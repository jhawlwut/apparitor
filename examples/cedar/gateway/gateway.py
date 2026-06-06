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


def _entity_uid(kind: str, identifier: str) -> str:
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

        def do_GET(self) -> None:
            if self.path.rstrip("/") == "/healthz":
                self._send({"status": "ok"})
            else:
                self._send({"error": "not found"}, status=404)

        def do_POST(self) -> None:
            if self.path.rstrip("/") != "/access/v1/evaluation":
                self._send({"error": "not found"}, status=404)
                return
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                decision = evaluator.decide(body)
            except ValueError as exc:
                self._send({"error": str(exc)}, status=400)
            else:
                self._send({"decision": decision})

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
