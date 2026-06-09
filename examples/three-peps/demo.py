#!/usr/bin/env python3
"""One policy, one engine, three enforcement points.

Runs the SAME Cedar policy (vendored in ``examples/cedar/``) through every shipping
enforcement-point adapter — the LlamaFirewall scanner, the NeMo Guardrails rail, and the
FastMCP server middleware — using the in-process Cedar backend: no Docker, no network, no
gateway. Each lane submits the same two tool calls and must produce the same verdicts:

* ``read_file``        → ALLOW  (low sensitivity, non-destructive — permitted for the agent)
* ``delete_database``  → BLOCK  (``forbid`` on ``destructive == true`` overrides any permit)

Lanes whose optional dependency is not installed are skipped with a hint; set
``APPARITOR_DEMO_REQUIRE_ALL=1`` (as CI does) to fail unless all three lanes run. Run with::

    pip install -e ".[llamafirewall,nemo,fastmcp,cedar]"
    python examples/three-peps/demo.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from apparitor import ScannerConfig
from apparitor.errors import MissingDependencyError

_CEDAR_DIR = Path(__file__).resolve().parent.parent / "cedar"

#: The two calls every lane submits, with the verdict the shared policy must produce.
_CASES: list[tuple[str, dict[str, Any], str]] = [
    ("read_file", {"path": "/tmp/report.txt"}, "ALLOW"),
    ("delete_database", {"name": "prod"}, "BLOCK"),
]


def _config() -> ScannerConfig:
    """One config for all three lanes: the vendored Cedar policy, evaluated in-process."""
    return ScannerConfig(
        backend="cedar",
        cedar_policies_path=str(_CEDAR_DIR / "policies.cedar"),
        cedar_entities_path=str(_CEDAR_DIR / "entities.json"),
        agent_id="demo-agent",
    )


def _openai_call(name: str, args: dict[str, Any]) -> dict[str, Any]:
    return {"type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


async def lane_llamafirewall() -> dict[str, str] | None:
    try:
        from llamafirewall import AssistantMessage, ScanDecision

        from apparitor import AuthZENScanner
    except (ImportError, MissingDependencyError):
        return None

    results: dict[str, str] = {}
    async with AuthZENScanner(config=_config()) as scanner:
        for name, args, _ in _CASES:
            message = AssistantMessage(content="", tool_calls=[_openai_call(name, args)])
            scan = await scanner.scan(message)
            results[name] = "ALLOW" if scan.decision == ScanDecision.ALLOW else "BLOCK"
    return results


async def lane_nemo() -> dict[str, str] | None:
    try:
        from apparitor.nemo import NeMoAuthorizationRails
    except (ImportError, MissingDependencyError):
        return None

    results: dict[str, str] = {}
    async with NeMoAuthorizationRails(config=_config()) as rails:
        for name, args, _ in _CASES:
            action_result = await rails.action(tool_calls=[_openai_call(name, args)])
            results[name] = "ALLOW" if action_result.return_value is True else "BLOCK"
    return results


async def lane_fastmcp() -> dict[str, str] | None:
    try:
        from fastmcp import Client, FastMCP
        from fastmcp.exceptions import ToolError

        from apparitor.fastmcp import FastMCPAuthorizationMiddleware
    except (ImportError, MissingDependencyError):
        return None
    from apparitor.mapping import DefaultToolCallMapper

    cfg = _config()
    middleware = FastMCPAuthorizationMiddleware(
        config=cfg,
        # The default MCP mapper server-scopes resource ids ("<server>/<tool>"); the demo's
        # point is that ONE policy file governs all three lanes, so use the same mapper —
        # and therefore the same Cedar policy keys (Tool::"read_file") — as the others.
        mapper=DefaultToolCallMapper(cfg),
        # Local in-process demo with no OAuth server: explicitly opt in to the static
        # agent subject (never do this silently on a network transport).
        allow_static_subject=True,
    )
    server = FastMCP("demo")
    server.add_middleware(middleware)

    @server.tool
    def read_file(path: str) -> str:
        return f"contents of {path}"

    @server.tool
    def delete_database(name: str) -> str:
        return f"database {name} deleted"

    results: dict[str, str] = {}
    async with middleware, Client(server) as client:
        for name, args, _ in _CASES:
            try:
                await client.call_tool(name, args)
                results[name] = "ALLOW"
            except ToolError:
                results[name] = "BLOCK"
    return results


_LANES: list[tuple[str, str, Callable[[], Awaitable[dict[str, str] | None]]]] = [
    ("LlamaFirewall scanner", "apparitor[llamafirewall]", lane_llamafirewall),
    ("NeMo Guardrails rail", "apparitor[nemo]", lane_nemo),
    ("FastMCP middleware", "apparitor[fastmcp]", lane_fastmcp),
]


async def main() -> int:
    try:
        import cedarpy  # noqa: F401
    except ImportError:
        # Cedar is the demo's shared engine (every lane evaluates against it in-process),
        # not an optional lane — without it there is nothing to demonstrate.
        print("this demo needs the in-process Cedar engine: pip install 'apparitor[cedar]'")
        return 1

    print(f"policy: {_CEDAR_DIR / 'policies.cedar'} (in-process Cedar, no network)\n")

    ran = 0
    mismatches = 0
    for label, extra, lane in _LANES:
        results = await lane()
        if results is None:
            print(f"{label:24} skipped — install '{extra}' to run this lane")
            continue
        ran += 1
        for name, _, want in _CASES:
            got = results[name]
            marker = "ok" if got == want else "MISMATCH"
            if got != want:
                mismatches += 1
            print(f"{label:24} {name:18} -> {got:5}  (expected {want})  {marker}")

    print(
        f"\n{ran}/3 enforcement points ran; "
        f"{'all agree' if mismatches == 0 else f'{mismatches} MISMATCHED verdicts'}"
    )
    if mismatches or ran == 0:
        return 1
    if os.environ.get("APPARITOR_DEMO_REQUIRE_ALL") and ran < len(_LANES):
        print("APPARITOR_DEMO_REQUIRE_ALL is set and a lane was skipped — failing")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
