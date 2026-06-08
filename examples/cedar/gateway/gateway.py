"""A tiny AuthZEN -> Cedar gateway.

Cedar has no native AuthZEN endpoint, so this stdlib HTTP service is the "local AuthZEN
gateway": it accepts AuthZEN ``POST /access/v1/evaluation`` requests, translates the
``subject``/``action``/``resource``/``context`` tuple into a Cedar authorization request,
and shells out to the official ``cedar`` CLI to evaluate vendored policies + entities.

This is example glue, not a hardened PDP — but it keeps the security posture the scanner
expects: any CLI failure or unrecognised outcome resolves to **deny** (fail closed), and
``decision`` is only ever ``true`` when Cedar explicitly returns Allow (exit code 0).

Run::

    python gateway.py --port 8080 --policies policies.cedar --entities entities.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

# AuthZEN subject/resource types are lowercase; Cedar entity types are PascalCase in the
# vendored schema. Unknown types pass through title-cased.
_TYPE_MAP = {"agent": "Agent", "tool": "Tool"}

# `cedar authorize` exits 0 on Allow and 2 (AuthorizeDeny) on Deny; treat anything else as
# an error and fail closed.
_ALLOW_EXIT = 0

# Batch bounds: a multi-tool-call message is small, so cap the entry count and the request
# body. Each entry forks a `cedar` process, so an unbounded array/body is a fork/memory
# amplification lever for an unauthenticated caller. Generous for the scanner's real use.
_MAX_BATCH = 100
_MAX_BODY_BYTES = 1 << 20  # 1 MiB


def _entity_uid(kind: str, identifier: str) -> str:
    # A double-quote would produce a malformed Cedar UID (Agent::"foo"bar"). Reject it
    # rather than emit something the CLI can't parse. Normalised tool names never contain
    # quotes, so this only guards against pathological input.
    if '"' in identifier:
        raise ValueError(f"identifier may not contain a double-quote: {identifier!r}")
    cedar_type = _TYPE_MAP.get(kind, kind.title())
    return f'{cedar_type}::"{identifier}"'


class CedarEvaluator:
    """Translates one AuthZEN tuple into a `cedar authorize` invocation."""

    def __init__(self, policies: Path, entities: Path) -> None:
        self._policies = policies
        self._entities = entities

    def decide(self, body: dict[str, Any]) -> bool:
        subject = body.get("subject") or {}
        action = body.get("action") or {}
        resource = body.get("resource") or {}
        if not (subject.get("id") and action.get("name") and resource.get("id")):
            raise ValueError("subject.id, action.name and resource.id are required")

        cmd = [
            "cedar",
            "authorize",
            "--policies",
            str(self._policies),
            "--entities",
            str(self._entities),
            "--principal",
            _entity_uid(subject.get("type", "agent"), subject["id"]),
            "--action",
            f'Action::"{action["name"]}"',
            "--resource",
            _entity_uid(resource.get("type", "tool"), resource["id"]),
        ]

        context = body.get("context")
        with tempfile.TemporaryDirectory() as tmp:
            if context:
                ctx_path = Path(tmp) / "context.json"
                ctx_path.write_text(json.dumps(context))
                cmd += ["--context", str(ctx_path)]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            except OSError:
                return False  # cedar missing/unrunnable -> fail closed
        return result.returncode == _ALLOW_EXIT


def _merge_item(item: dict[str, Any], defaults: dict[str, Any]) -> dict[str, Any]:
    """Overlay one batch ``evaluations`` entry on the request-level defaults.

    Per AuthZEN, top-level ``subject``/``action``/``resource``/``context`` are defaults that
    each entry may override; the entry's own field wins when present.
    """
    return {
        key: item.get(key) or defaults.get(key)
        for key in ("subject", "action", "resource", "context")
    }


def make_handler(evaluator: CedarEvaluator) -> type[BaseHTTPRequestHandler]:
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
    parser = argparse.ArgumentParser(description="AuthZEN -> Cedar gateway")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--policies", type=Path, default=Path("policies.cedar"))
    parser.add_argument("--entities", type=Path, default=Path("entities.json"))
    args = parser.parse_args()

    evaluator = CedarEvaluator(args.policies, args.entities)
    server = ThreadingHTTPServer(("0.0.0.0", args.port), make_handler(evaluator))
    print(f"AuthZEN->Cedar gateway on http://0.0.0.0:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
