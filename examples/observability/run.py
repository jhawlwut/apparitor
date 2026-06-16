#!/usr/bin/env python3
"""Observability walk-through — the decision log and metrics, made runnable.

apparitor's audit log and metrics are its compliance surface (``docs/audit-log.md`` freezes
the log as a stability contract; ``docs/eu-ai-act.md`` maps it to the EU AI Act). They are
the most heavily *documented* part of the project and, until this example, the least
*shown*. This script closes that gap with core install only — no extras, no Docker:

1. **Configure the ``apparitor`` logger** with a UTC, ISO-8601 formatter. ``docs/audit-log.md``
   says you MUST do this: a sink that keeps only the message and no event time is not an
   audit trail.
2. **Drive every contract line** — C1 (per-decision audit record) for allow / block /
   human-review, C2 (batch ``denied_legs``) on a dual-principal deny, and C3 (per-item
   summary) on a ``tools/list``-style visibility filter.
3. **Parse them back** with ``ast.literal_eval``, exactly as the doc's parsing guidance
   prescribes — turning the frozen grammar into living, asserted code (a consumer-side
   companion to ``tests/unit/test_log_contract.py``).
4. **Forward metrics** through a custom :class:`~apparitor.MetricsSink` that renders the
   Prometheus exposition format ``metrics.py`` advertises but never demonstrates.

Run::

    pip install -e .
    python examples/observability/run.py
"""

from __future__ import annotations

import ast
import asyncio
import importlib.util
import json
import logging
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from apparitor import (
    AuthorizationEngine,
    DualPrincipalMapper,
    InMemoryMetrics,
    NormalizedToolCall,
    ScannerConfig,
    Subject,
    subject_scope,
)

# Reuse the shared mock PDP's decision logic rather than re-implementing a deny-list.
_MOCK_PDP_PATH = Path(__file__).resolve().parent.parent / "mock_pdp" / "mock_pdp.py"
_spec = importlib.util.spec_from_file_location("mock_pdp", _MOCK_PDP_PATH)
assert _spec and _spec.loader
mock_pdp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mock_pdp)

# A 2-part deny (any subject) for a destructive tool, plus a 3-part agent-boundary deny so
# the dual-principal leg blocks travel-bot even when the user holds the grant. The review-set
# is a "permit, but a human must confirm" outcome the PDP signals via the advisory response
# ``context`` — the Article 14 human-oversight case. All three are demo shortcuts; see
# mock_pdp.py on why a permit-by-default deny-list must never ship to production.
_DENY: set[str] = {
    "tool_call.execute:delete_table",
    "travel-bot:tool_call.execute:book_flight",
}
_REVIEW: set[str] = {"wire_transfer"}


def _decision(body: dict, item: dict | None = None) -> dict[str, Any]:
    """One AuthZEN decision, with an advisory ``context`` flag on review-required resources."""
    src = item or body
    action = src.get("action") or body.get("action") or {}
    resource = src.get("resource") or body.get("resource") or {}
    subject = src.get("subject") or body.get("subject") or {}
    allowed = mock_pdp.decide(_DENY, subject, action, resource)
    out: dict[str, Any] = {"decision": allowed}
    if allowed and resource.get("id", "") in _REVIEW:
        out["context"] = {"review": True}
    return out


def _make_handler() -> type[BaseHTTPRequestHandler]:
    """Mirror mock_pdp's handler but emit the advisory review ``context`` the engine reads."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:  # quiet by default
            pass

        def _read(self) -> dict:
            length = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(length) or b"{}")

        def _send(self, payload: dict, status: int = 200) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self) -> None:
            try:
                body = self._read()
            except (ValueError, json.JSONDecodeError):
                self._send({"error": "invalid json"}, status=400)
                return
            path = self.path.rstrip("/")
            if path == "/access/v1/evaluation":
                self._send(_decision(body))
            elif path == "/access/v1/evaluations":
                items = body.get("evaluations") or [None]
                self._send({"evaluations": [_decision(body, it) for it in items]})
            else:
                self._send({"error": "not found"}, status=404)

    return Handler


def _start_pdp() -> tuple[int, ThreadingHTTPServer]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler())
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return port, server


# ── Logging: the step docs/audit-log.md says you MUST do ─────────────────────────────────


class _Capture(logging.Handler):
    """Collects the rendered contract lines so the demo can parse them downstream.

    ``LogRecord.getMessage()`` (the formatted message) is the documented stable surface; the
    record's ``msg`` / ``args`` structure is internal and deliberately not relied on here.
    """

    def __init__(self) -> None:
        super().__init__(level=logging.INFO)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


def _configure_logging() -> _Capture:
    """Route the ``apparitor`` logger to a UTC, ISO-8601 sink (+ a parser-side capture).

    Subject ids are decision principals (often emails), so in production this logger goes to
    a restricted, access-controlled sink with a retention policy — see docs/audit-log.md.
    """
    logger = logging.getLogger("apparitor")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.propagate = False  # don't double-emit through the root logger

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    fmt.converter = time.gmtime  # UTC clock of record (docs/audit-log.md "Timestamps")

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(fmt)
    logger.addHandler(stream)

    capture = _Capture()
    logger.addHandler(capture)
    return capture


# ── Parsing: the contract grammar, as the doc prescribes (ast.literal_eval, not JSON) ───────

_C1 = re.compile(
    r"apparitor decision verdict=(?P<verdict>\S+) status=(?P<status>\S+) "
    r"subjects=(?P<subjects>\[.*?\]) correlation=(?P<correlation>\S+) "
    r"resources=(?P<resources>\[.*?\]) fingerprints=(?P<fingerprints>\[.*?\]) "
    r"latency_ms=(?P<latency>[0-9.]+)$"
)
_C2 = re.compile(r"apparitor batch denied_legs=(?P<legs>\[.*\])$")
_C3 = re.compile(
    r"apparitor per-item decisions verdicts=(?P<verdicts>\[.*?\]) latency_ms=(?P<latency>[0-9.]+)$"
)


def parse_c1(line: str) -> dict[str, Any] | None:
    m = _C1.match(line)
    if m is None:
        return None
    return {
        "verdict": m["verdict"],
        "status": m["status"],
        "subjects": ast.literal_eval(m["subjects"]),
        "correlation": None if m["correlation"] == "None" else m["correlation"],
        "resources": ast.literal_eval(m["resources"]),
        "fingerprints": ast.literal_eval(m["fingerprints"]),
        "latency_ms": float(m["latency"]),
    }


# ── Metrics: a custom MetricsSink that renders Prometheus exposition text ────────────────


class PrometheusMetrics(InMemoryMetrics):
    """The sink ``metrics.py`` describes: reuse the in-memory counters/histogram, add a scrape.

    Dependency-free on purpose (no ``prometheus_client``) so the example needs no extras; a
    real deployment would bridge the same counters into its Prometheus or OpenTelemetry SDK.
    """

    def render(self) -> str:
        out: list[str] = [
            "# HELP apparitor_decisions_total Authorization decisions by verdict and status.",
            "# TYPE apparitor_decisions_total counter",
        ]
        for (verdict, status), count in sorted(self.decisions.items()):
            labels = f'verdict="{verdict}",status="{status}"'
            out.append(f"apparitor_decisions_total{{{labels}}} {count}")
        out += [
            "# HELP apparitor_decision_latency_seconds Decision latency.",
            "# TYPE apparitor_decision_latency_seconds histogram",
        ]
        for le, cumulative in self.latency_histogram():
            bound = "+Inf" if le == float("inf") else repr(le)
            out.append(f'apparitor_decision_latency_seconds_bucket{{le="{bound}"}} {cumulative}')
        out += [
            f"apparitor_decision_latency_seconds_sum {self.latency_sum_s}",
            f"apparitor_decision_latency_seconds_count {self.latency_count}",
            "# HELP apparitor_decision_cache_total Decision-cache lookups by outcome.",
            "# TYPE apparitor_decision_cache_total counter",
            f'apparitor_decision_cache_total{{outcome="hit"}} {self.cache_hits}',
            f'apparitor_decision_cache_total{{outcome="miss"}} {self.cache_misses}',
        ]
        return "\n".join(out)


# ── Scenarios ────────────────────────────────────────────────────────────────────────────


def _call(name: str, args: dict | None = None) -> dict:
    return {"type": "function", "function": {"name": name, "arguments": json.dumps(args or {})}}


def _needs_review(context: dict[str, Any]) -> bool:
    return bool(context.get("review"))


_USER = Subject(type="user", id="alice@acme.com")


async def main() -> int:
    capture = _configure_logging()
    prom = PrometheusMetrics()
    port, server = _start_pdp()
    try:
        # allow_insecure_pdp is required: the SSRF guard blocks plain-HTTP loopback by default.
        config = ScannerConfig(
            pdp_url=f"http://127.0.0.1:{port}", allow_insecure_pdp=True, agent_id="travel-bot"
        )
        engine = AuthorizationEngine(config, review_predicate=_needs_review, metrics=prom)
        dual = AuthorizationEngine(config, mapper=DualPrincipalMapper(config), metrics=prom)

        print("== Contract lines (live, as emitted) ==")
        # C1 allow / block / human-review. correlation_id chains a decision to its session.
        with subject_scope(_USER):
            await engine.evaluate_tool_calls([_call("read_file")], {"correlation_id": "sess-allow"})
            await engine.evaluate_tool_calls(
                [_call("delete_table")], {"correlation_id": "sess-block"}
            )
            await engine.evaluate_tool_calls(
                [_call("wire_transfer")], {"correlation_id": "sess-review"}
            )
            # C1 (two principals) + C2: the user holds the grant, the agent boundary denies.
            await dual.evaluate_tool_calls([_call("book_flight")], {"correlation_id": "sess-dual"})
            # C3: per-item visibility filter (a tools/list shaping), one verdict per item.
            await engine.evaluate_each(
                [NormalizedToolCall(name="read_file"), NormalizedToolCall(name="delete_table")]
            )
    finally:
        await engine.aclose()
        await dual.aclose()
        server.shutdown()
        server.server_close()

    return _report(capture, prom)


def _report(capture: _Capture, prom: PrometheusMetrics) -> int:
    """Parse the captured lines, print the structured view + scrape, and assert the contract."""
    c1 = {rec["correlation"]: rec for line in capture.lines if (rec := parse_c1(line))}
    c2 = [m["legs"] for line in capture.lines if (m := _C2.match(line))]
    c3 = [m["verdicts"] for line in capture.lines if (m := _C3.match(line))]

    print("\n== Parsed audit records (ast.literal_eval, per the doc) ==")
    for corr, rec in c1.items():
        print(
            f"  {corr:<11} verdict={rec['verdict']:<12} status={rec['status']:<7}"
            f" subjects={rec['subjects']} resources={rec['resources']}"
        )
    if c2:
        print(f"  C2 denied_legs: {ast.literal_eval(c2[0])}")
    if c3:
        print(f"  C3 verdicts:    {ast.literal_eval(c3[0])}")

    print("\n== Prometheus /metrics scrape (custom MetricsSink) ==")
    print(prom.render())

    # Assertions: the audit log is the interface, so verify it from the consumer side.
    expected = {
        "sess-allow": ("allow", "success", 1),
        "sess-block": ("block", "success", 1),
        "sess-review": ("human_review", "success", 1),
        "sess-dual": ("block", "success", 2),  # two principals: alice (allows) AND travel-bot
    }
    mismatches: list[str] = []
    for corr, (verdict, status, n_subjects) in expected.items():
        rec = c1.get(corr)
        if rec is None:
            mismatches.append(f"{corr}: no C1 record")
            continue
        if (rec["verdict"], rec["status"]) != (verdict, status):
            mismatches.append(f"{corr}: {rec['verdict']}/{rec['status']} != {verdict}/{status}")
        if len(rec["subjects"]) != n_subjects:
            mismatches.append(f"{corr}: {len(rec['subjects'])} subjects != {n_subjects}")
    if c1.get("sess-dual", {}).get("subjects") != ["alice@acme.com", "travel-bot"]:
        mismatches.append("sess-dual: C1 must name both principals, sorted")
    if not (c2 and "agent:travel-bot tool_call.execute book_flight" in ast.literal_eval(c2[0])):
        mismatches.append("missing C2 denied_legs naming the agent boundary")
    if not c3 or ast.literal_eval(c3[0]) != ["allow", "block"]:
        mismatches.append("C3 per-item verdicts != ['allow', 'block']")

    print()
    if mismatches:
        for m in mismatches:
            print(f"FAIL: {m}")
        return 1
    print("All contract lines emitted, parsed, and verified from the consumer side.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
