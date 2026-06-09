"""A tiny AuthZEN -> OPA gateway.

OPA speaks its own Data API (``POST /v1/data/<path>`` returning ``{"result": ...}``), not
AuthZEN, so this stdlib HTTP service is the "local AuthZEN gateway": it accepts AuthZEN
``POST /access/v1/evaluation`` requests, feeds the ``subject``/``action``/``resource``/
``context`` tuple to OPA as the policy ``input``, and evaluates the vendored Rego policy +
data with the official ``opa`` CLI (``opa eval``).

This is example glue, not a hardened PDP — but it keeps the security posture the scanner
expects: any CLI failure or unrecognised outcome resolves to **deny** (fail closed), and
``decision`` is only ever ``true`` when the policy's ``allow`` rule evaluates to exactly
``true``.

It is not latency-tuned: each decision forks ``opa eval`` (recompiling the policy) and a
batch forks one process per entry **sequentially**. That serialisation is deliberate —
together with ``_MAX_BATCH`` it bounds fork amplification (see the batch-bounds note
below). See the README's *Performance* section before parallelising.

Run::

    python gateway.py --port 8080 --policy policy.rego --data data.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

# The Rego rule the gateway reads. `default allow := false` in the policy makes this always
# defined, so a missing/undefined result can only mean an OPA error -> fail closed.
_QUERY = "data.apparitor.authz.allow"

# Bound a single `opa eval`: a hung process (e.g. a pathological policy) fails closed rather
# than blocking the worker thread indefinitely. Generous — a healthy eval is sub-second.
_EVAL_TIMEOUT_S = 10

# Batch bounds: a multi-tool-call message is small, so cap the entry count and the request
# body. Each entry forks an `opa` process, so an unbounded array/body is a fork/memory
# amplification lever for an unauthenticated caller. Generous for the scanner's real use.
_MAX_BATCH = 100
_MAX_BODY_BYTES = 1 << 20  # 1 MiB


def _extract_decision(stdout: str) -> bool:
    """Pull the boolean ``allow`` out of ``opa eval --format=json`` output, fail closed.

    Anything other than an explicit ``true`` value — undefined result, malformed JSON, a
    non-boolean — is treated as deny: the gateway never invents an allow from a shape it
    does not recognise.
    """
    try:
        value = json.loads(stdout)["result"][0]["expressions"][0]["value"]
    except (ValueError, KeyError, IndexError, TypeError):
        return False
    return value is True


class OpaEvaluator:
    """Translates one AuthZEN tuple into an `opa eval` invocation over the vendored policy."""

    def __init__(self, policy: Path, data: Path) -> None:
        self._policy = policy
        self._data = data

    def decide(self, body: dict[str, Any]) -> bool:
        subject = body.get("subject") or {}
        action = body.get("action") or {}
        resource = body.get("resource") or {}
        if not (subject.get("id") and action.get("name") and resource.get("id")):
            raise ValueError("subject.id, action.name and resource.id are required")

        # The whole tuple becomes the policy `input`; the Rego decides what to read from it.
        input_doc: dict[str, Any] = {"subject": subject, "action": action, "resource": resource}
        context = body.get("context")
        if context is not None:
            input_doc["context"] = context

        cmd = [
            "opa",
            "eval",
            "--format=json",
            "--data",
            str(self._policy),
            "--data",
            str(self._data),
            "--stdin-input",
            _QUERY,
        ]
        try:
            result = subprocess.run(
                cmd,
                input=json.dumps(input_doc),
                capture_output=True,
                text=True,
                check=False,
                timeout=_EVAL_TIMEOUT_S,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False  # opa missing/unrunnable or a hung eval -> fail closed
        if result.returncode != 0:
            return False  # a policy/parse error is never an allow
        return _extract_decision(result.stdout)


def _merge_item(item: dict[str, Any], defaults: dict[str, Any]) -> dict[str, Any]:
    """Overlay one batch ``evaluations`` entry on the request-level defaults.

    Per AuthZEN, top-level ``subject``/``action``/``resource``/``context`` are defaults that
    each entry may override. Keyed on membership, not truthiness, so an explicit empty/null
    override (e.g. ``resource: {}``) is honored rather than silently replaced by the default
    — which would otherwise let a default ALLOW tuple stand in for a field the entry cleared.
    """
    return {
        key: item[key] if key in item else defaults.get(key)
        for key in ("subject", "action", "resource", "context")
    }


def make_handler(evaluator: OpaEvaluator) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:  # quiet by default
            pass

        def _send(self, payload: dict[str, Any], status: int = 200) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _read_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", 0))
            if length < 0:
                # A negative length would make read(-1) drain to EOF, bypassing the cap.
                raise ValueError("invalid Content-Length")
            if length > _MAX_BODY_BYTES:
                raise ValueError("request body too large")
            return json.loads(self.rfile.read(length) or b"{}")

        def do_GET(self) -> None:
            if self.path.rstrip("/") == "/healthz":
                self._send({"status": "ok"})
            else:
                self._send({"error": "not found"}, status=404)

        def do_POST(self) -> None:
            path = self.path.rstrip("/")
            if path == "/access/v1/evaluation":
                self._evaluate_one()
            elif path == "/access/v1/evaluations":
                self._evaluate_batch()
            else:
                self._send({"error": "not found"}, status=404)

        def _evaluate_one(self) -> None:
            try:
                decision = evaluator.decide(self._read_body())
            except ValueError as exc:
                self._send({"error": str(exc)}, status=400)
            except Exception:
                # Any other failure fails closed: a gateway error is never an allow.
                self._send({"decision": False})
            else:
                self._send({"decision": decision})

        def _evaluate_batch(self) -> None:
            try:
                body = self._read_body()
            except ValueError as exc:
                self._send({"error": str(exc)}, status=400)
                return
            if not isinstance(body, dict):
                self._send({"error": "request body must be a JSON object"}, status=400)
                return
            items = body.get("evaluations")
            if not isinstance(items, list):
                self._send({"error": "'evaluations' must be a list"}, status=400)
                return
            if len(items) > _MAX_BATCH:
                self._send({"error": "too many evaluations"}, status=413)
                return
            # Evaluate each entry independently and fail closed per entry, so one malformed
            # or denied call can never become an allow. A non-dict entry is malformed: it must
            # NOT inherit the request-level defaults (that could turn garbage into an allow),
            # so it denies outright. Order and length mirror the request, which is what the
            # scanner's execute_all aggregation expects.
            results = []
            for item in items:
                if not isinstance(item, dict):
                    results.append({"decision": False})
                    continue
                try:
                    decision = evaluator.decide(_merge_item(item, body))
                except Exception:
                    decision = False
                results.append({"decision": decision})
            self._send({"evaluations": results})

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description="AuthZEN -> OPA gateway")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--policy", type=Path, default=Path("policy.rego"))
    parser.add_argument("--data", type=Path, default=Path("data.json"))
    args = parser.parse_args()

    evaluator = OpaEvaluator(args.policy, args.data)
    server = ThreadingHTTPServer(("0.0.0.0", args.port), make_handler(evaluator))
    print(f"AuthZEN->OPA gateway on http://0.0.0.0:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
