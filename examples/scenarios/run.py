#!/usr/bin/env python3
"""End-to-end scenario walk-through — core install only, no extras required.

Starts a dependency-free mock AuthZEN PDP (from examples/mock_pdp/) on an ephemeral
loopback port and drives ``AuthorizationEngine`` through seven scenarios (eight assertions
— the dual-principal finale checks both a block and an allow) that cover the client-side
contract: fail-closed verdict mapping, batch AND semantics, and dual-principal evaluation.
No Docker, no network egress, no optional extras.

The mock PDP is a scripted deny-list, so these scenarios prove the CLIENT-side contract —
that the engine maps verdicts correctly (fail-closed on errors, all-or-nothing on batches,
AND on dual principals) — not that any real policy engine is configured correctly. For real
policy engine examples see ``examples/three-peps/`` (three enforcement points, Cedar
in-process) and the ``examples/openfga/``, ``examples/cedar/``, and ``examples/opa/``
examples.

Run::

    pip install -e .
    python examples/scenarios/run.py
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import socket
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

from apparitor import (
    AuthorizationEngine,
    DualPrincipalMapper,
    ScannerConfig,
    Subject,
    Verdict,
    VerdictStatus,
    subject_scope,
)

# Load the mock PDP handler without making examples/ a package.
_MOCK_PDP_PATH = Path(__file__).resolve().parent.parent / "mock_pdp" / "mock_pdp.py"
_spec = importlib.util.spec_from_file_location("mock_pdp", _MOCK_PDP_PATH)
assert _spec and _spec.loader
_mock_pdp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mock_pdp)

# Deny-set for the walk-through.  Two forms exercised:
#   "tool_call.execute:delete_table"            — 2-part: any subject, specific resource
#   "travel-bot:tool_call.execute:book_flight"  — 3-part: agent-boundary deny for one tool
_DENY: set[str] = {
    "tool_call.execute:delete_table",
    "travel-bot:tool_call.execute:book_flight",
}


def _openai_call(name: str, args: dict | None = None) -> dict:
    return {"type": "function", "function": {"name": name, "arguments": json.dumps(args or {})}}


def _start_mock_pdp() -> tuple[int, ThreadingHTTPServer]:
    """Bind an ephemeral port, start the mock PDP in a daemon thread, return (port, server)."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _mock_pdp.make_handler(_DENY))
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return port, server


def _closed_port() -> int:
    """Bind an ephemeral port, record it, close it, return the port number.

    Binds port 0 to get an OS-assigned free port, then releases it.  There is a brief
    window before the engine connects in which another process could take the port —
    negligible on an isolated runner, and a hijacked port yields a non-AuthZEN response
    that still resolves fail-closed (BLOCK/ERROR), while any other outcome is caught as
    a MISMATCH.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _fmt(
    name: str,
    got_verdict: Verdict,
    got_status: VerdictStatus,
    want_verdict: Verdict,
    want_status: VerdictStatus,
) -> tuple[str, bool]:
    ok = got_verdict is want_verdict and got_status is want_status
    marker = "ok" if ok else "MISMATCH"
    line = (
        f"  {name:<40} -> {got_verdict.value:<14} {got_status.value:<8}"
        f" (expected {want_verdict.value}/{want_status.value})  {marker}"
    )
    return line, ok


async def main() -> int:
    port, server = _start_mock_pdp()
    try:
        # allow_insecure_pdp is required: the SSRF guard blocks plain-HTTP loopback by default.
        config = ScannerConfig(
            pdp_url=f"http://127.0.0.1:{port}",
            allow_insecure_pdp=True,
            agent_id="travel-bot",
        )

        mismatches = 0

        engine = AuthorizationEngine(config)
        try:
            # ── Scenario 1: allow ────────────────────────────────────────────────────────────
            r = await engine.evaluate_tool_calls([_openai_call("read_file")])
            line, ok = _fmt(
                "1. allow (read_file)", r.verdict, r.status, Verdict.ALLOW, VerdictStatus.SUCCESS
            )
            print(line)
            if not ok:
                mismatches += 1

            # ── Scenario 2: deny (2-part key) ────────────────────────────────────────────────
            r = await engine.evaluate_tool_calls([_openai_call("delete_table")])
            line, ok = _fmt(
                "2. deny (delete_table)", r.verdict, r.status, Verdict.BLOCK, VerdictStatus.SUCCESS
            )
            print(line)
            if not ok:
                mismatches += 1

            # ── Scenario 3: unparseable input fails closed ───────────────────────────────────
            # The adapter detection returns None for an unrecognised shape; the engine blocks
            # before the PDP is consulted (fail closed on malformed input).
            r = await engine.evaluate_tool_calls([{"weird": "shape"}])
            line, ok = _fmt(
                "3. unparseable fails closed",
                r.verdict,
                r.status,
                Verdict.BLOCK,
                VerdictStatus.ERROR,
            )
            print(line)
            if not ok:
                mismatches += 1
        finally:
            await engine.aclose()

        # ── Scenario 4: PDP unreachable, on_error=deny ──────────────────────────────────────
        dead_port = _closed_port()
        # Tight budget so the scenario completes quickly in CI.
        dead_config = ScannerConfig(
            pdp_url=f"http://127.0.0.1:{dead_port}",
            allow_insecure_pdp=True,
            agent_id="travel-bot",
            request_budget_s=0.5,
            connect_timeout_s=0.2,
            read_timeout_s=0.2,
            max_retries=0,
            on_error="deny",
        )
        engine4 = AuthorizationEngine(dead_config)
        try:
            r = await engine4.evaluate_tool_calls([_openai_call("read_file")])
            line, ok = _fmt(
                "4. unreachable on_error=deny",
                r.verdict,
                r.status,
                Verdict.BLOCK,
                VerdictStatus.ERROR,
            )
            print(line)
            if not ok:
                mismatches += 1
        finally:
            await engine4.aclose()

        # ── Scenario 5: PDP unreachable, on_error=human_review ──────────────────────────────
        # There is deliberately no fail-open option; the only choices are deny or human review.
        dead_config5 = ScannerConfig(
            pdp_url=f"http://127.0.0.1:{dead_port}",
            allow_insecure_pdp=True,
            agent_id="travel-bot",
            request_budget_s=0.5,
            connect_timeout_s=0.2,
            read_timeout_s=0.2,
            max_retries=0,
            on_error="human_review",
        )
        engine5 = AuthorizationEngine(dead_config5)
        try:
            r = await engine5.evaluate_tool_calls([_openai_call("read_file")])
            line, ok = _fmt(
                "5. unreachable on_error=human_review",
                r.verdict,
                r.status,
                Verdict.HUMAN_REVIEW,
                VerdictStatus.ERROR,
            )
            print(line)
            if not ok:
                mismatches += 1
        finally:
            await engine5.aclose()

        # ── Scenario 6: batch all-or-nothing ────────────────────────────────────────────────
        # read_file would allow; delete_table denies — the batch AND means the whole message blocks.
        engine6 = AuthorizationEngine(config)
        try:
            r = await engine6.evaluate_tool_calls(
                [
                    _openai_call("read_file"),
                    _openai_call("delete_table"),
                ]
            )
            line, ok = _fmt(
                "6. batch all-or-nothing", r.verdict, r.status, Verdict.BLOCK, VerdictStatus.SUCCESS
            )
            print(line)
            if not ok:
                mismatches += 1
        finally:
            await engine6.aclose()

        # ── Scenario 7: dual-principal finale ────────────────────────────────────────────────
        # DualPrincipalMapper emits two evaluation requests per call — user leg AND agent leg.
        # The agent boundary (travel-bot) has a 3-part deny for book_flight, so that call blocks
        # even though alice holds the permission.  read_file passes both legs.
        dual_engine = AuthorizationEngine(config, mapper=DualPrincipalMapper(config))
        try:
            with subject_scope(Subject(type="user", id="alice@acme.com")):
                r_book = await dual_engine.evaluate_tool_calls([_openai_call("book_flight")])
            line_7a, ok_7a = _fmt(
                "7a. dual book_flight (agent blocks)",
                r_book.verdict,
                r_book.status,
                Verdict.BLOCK,
                VerdictStatus.SUCCESS,
            )
            print(line_7a)
            if not ok_7a:
                mismatches += 1

            with subject_scope(Subject(type="user", id="alice@acme.com")):
                r_read = await dual_engine.evaluate_tool_calls([_openai_call("read_file")])
            line_7b, ok_7b = _fmt(
                "7b. dual read_file (both pass)",
                r_read.verdict,
                r_read.status,
                Verdict.ALLOW,
                VerdictStatus.SUCCESS,
            )
            print(line_7b)
            if not ok_7b:
                mismatches += 1

            # Narrative: the user holds the permission, but the agent's own boundary does not.
            # Only print when both assertions matched so the message is not misleading on failure.
            if ok_7a and ok_7b:
                print("     → alice may book_flight; travel-bot's agent boundary may not.")
        finally:
            await dual_engine.aclose()

        print()
        if mismatches:
            print(f"FAIL: {mismatches} mismatch(es)")
            return 1
        print("All scenarios ok. These results prove the CLIENT-side contract (fail-closed")
        print("verdict mapping, batch AND, dual-principal AND) against a scripted deny-list —")
        print("not the correctness of any real policy engine.")
        return 0
    finally:
        # shutdown stops serve_forever; server_close releases the listening socket.
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
