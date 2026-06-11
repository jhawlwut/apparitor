#!/usr/bin/env python3
"""MCP authorization gateway: enforcing policy on a vendor server you cannot modify.

The vendor server (below) represents a third-party MCP server your enterprise receives
but does not control — you cannot add middleware to it, change its routing, or touch its
source.  The gateway is a thin FastMCP proxy YOUR team owns; all enforcement lives here.
The middleware on the gateway is the chokepoint: every tool call and listing flows through
it before anything reaches the upstream.

What this demo proves
---------------------
* ``tools/list`` through the gateway omits ``delete_records`` (filter_listings hides what
  the subject may not call).
* ``read_report`` through the gateway succeeds AND increments the vendor's invocation
  counter — the call genuinely reached the upstream.
* ``delete_records`` through the gateway raises a generic ``ToolError`` AND the vendor's
  invocation counter remains zero — the upstream was never reached.

What production adds (this demo intentionally omits)
----------------------------------------------------
* TLS to a real PDP (remove allow_insecure_pdp; pass a real URL).
* ``auth=`` on the proxy server with a real OAuth token verifier, so the validated
  token's ``sub`` becomes the subject — drop ``allow_static_subject=True``.
* Egress rules / DNS that block agents from calling the vendor server directly,
  forcing all traffic through the gateway.

Mock PDP honesty note
---------------------
The mock PDP is a scripted deny-list: everything is permitted unless a rule matches.
That is the inverse of production authorization semantics (deny-by-default /
permit-by-exception) and must not be copied into real deployments.
"""

from __future__ import annotations

import asyncio
import importlib.util
import re
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import fastmcp as _fmcp
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

from apparitor import ScannerConfig
from apparitor.fastmcp import FastMCPAuthorizationMiddleware

# ── Version-compatible proxy factory ────────────────────────────────────────────
# FastMCP.as_proxy is deprecated on 3.x (emits FastMCPDeprecationWarning); use the
# replacement create_proxy on 3.x and the class method on 2.x.
# Regex avoids int() on pre-release suffixes like "3.2rc1".
_ver_match = re.match(r"\d+", _fmcp.__version__)
assert _ver_match, "fastmcp.__version__ must start with a digit"
_major = int(_ver_match.group())
if _major >= 3:
    from fastmcp.server import create_proxy as _create_proxy
else:
    _create_proxy = _fmcp.FastMCP.as_proxy  # type: ignore[assignment]  # 2.x spelling (deprecated alias on 3.x)

# ── Load the mock PDP without making examples/ a package ────────────────────────
_MOCK_PDP_PATH = Path(__file__).resolve().parent.parent / "mock_pdp" / "mock_pdp.py"
_spec = importlib.util.spec_from_file_location("mock_pdp", _MOCK_PDP_PATH)
assert _spec and _spec.loader
_mock_pdp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mock_pdp)


class _Counter:
    """Mutable state shared between main() and the vendor server's tool functions."""

    def __init__(self) -> None:
        self.read_report = 0
        self.delete_records = 0


def _build_vendor_server(counter: _Counter) -> FastMCP:
    """The upstream vendor server — no apparitor wiring; treat it as unmodifiable."""
    vendor = FastMCP("vendor")

    @vendor.tool
    def read_report(report_id: str) -> str:
        counter.read_report += 1
        return f"report {report_id}: all clear"

    @vendor.tool
    def delete_records(table: str) -> str:
        counter.delete_records += 1
        return f"records in {table} deleted"

    return vendor


def _start_mock_pdp(deny: set[str]) -> tuple[int, ThreadingHTTPServer]:
    """Bind an ephemeral port, start the mock PDP in a daemon thread, return (port, server)."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _mock_pdp.make_handler(deny))
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return port, server


async def main() -> int:
    counter = _Counter()
    vendor = _build_vendor_server(counter)

    # The proxy is named "vendor-gateway" (stable, no "/").  The middleware's default
    # MCPResourceMapper server-scopes resource ids as "<server>/<tool>", so the deny key
    # for delete_records is exactly "tool_call.execute:vendor-gateway/delete_records".
    # Do NOT pass a mapper override here: DefaultToolCallMapper drops the server prefix
    # and would silently break the deny.
    proxy = _create_proxy(vendor, name="vendor-gateway")

    # Two-part deny key: any subject, specific resource.
    deny_keys: set[str] = {"tool_call.execute:vendor-gateway/delete_records"}
    port, pdp_server = _start_mock_pdp(deny_keys)

    mismatches = 0
    middleware: FastMCPAuthorizationMiddleware | None = None

    try:
        # allow_insecure_pdp is required: the SSRF guard blocks plain-HTTP loopback by default.
        config = ScannerConfig(
            pdp_url=f"http://127.0.0.1:{port}",
            allow_insecure_pdp=True,
            agent_id="demo-agent",
        )

        middleware = FastMCPAuthorizationMiddleware(
            config=config,
            # Local in-process demo with no OAuth server: explicitly opt in to the static
            # agent subject (never do this silently on a network transport).
            allow_static_subject=True,
            filter_listings=True,
        )
        proxy.add_middleware(middleware)

        async with Client(proxy) as client:
            # ── Assertion 1: tools/list hides delete_records ─────────────────────────
            tools = await client.list_tools()
            tool_names = {t.name for t in tools}
            if "read_report" in tool_names and "delete_records" not in tool_names:
                print("PASS: tools/list shows read_report, hides delete_records")
            else:
                print(f"MISMATCH: tools/list={sorted(tool_names)!r}; expected [read_report]")
                mismatches += 1

            # ── Assertion 2: read_report flows through to the upstream ────────────────
            try:
                await client.call_tool("read_report", {"report_id": "Q4"})
                if counter.read_report == 1:
                    print("PASS: read_report allowed and upstream invocation counter == 1")
                else:
                    n = counter.read_report
                    print(f"MISMATCH: read_report allowed but upstream counter == {n}")
                    mismatches += 1
            except ToolError as exc:
                print(f"MISMATCH: read_report unexpectedly denied ({exc})")
                mismatches += 1

            # ── Assertion 3: delete_records is denied and upstream never reached ──────
            try:
                await client.call_tool("delete_records", {"table": "prod"})
                n = counter.delete_records
                print(f"MISMATCH: delete_records should have been denied (counter={n})")
                mismatches += 1
            except ToolError as exc:
                if "not authorized" not in str(exc).lower():
                    # a not-found or upstream error must not impersonate the middleware's deny
                    print(f"MISMATCH: unexpected ToolError text: {exc}")
                    mismatches += 1
                elif counter.delete_records == 0:
                    # This line IS the security claim: the upstream was never reached.
                    print(
                        "PASS: upstream never reached"
                        " (delete_records invocations=0 after denied call)"
                    )
                else:
                    n = counter.delete_records
                    print(f"MISMATCH: delete_records denied but upstream called (n={n})")
                    mismatches += 1
    finally:
        if middleware is not None:
            await middleware.aclose()
        pdp_server.shutdown()
        pdp_server.server_close()

    print()
    if mismatches:
        print(f"FAIL: {mismatches} mismatch(es)")
        return 1
    print("All assertions passed.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
