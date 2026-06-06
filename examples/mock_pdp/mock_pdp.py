"""A tiny, dependency-free AuthZEN PDP for tests and demos.

Implements ``POST /access/v1/evaluation`` and ``POST /access/v1/evaluations`` using only
the standard library. Decisions come from a simple deny-list of ``"<action>:<resource id>"``
rules; everything else is allowed. This is **not** a real authorization engine — it exists
to exercise the scanner end-to-end without standing up OPA/OpenFGA/Cedar.

Run::

    python examples/mock_pdp/mock_pdp.py --port 8080 --deny tool_call.execute:database.delete_table
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


def decide(deny: set[str], subject: dict, action: dict, resource: dict) -> bool:
    """Return the allow/deny decision for one AuthZEN tuple."""
    key = f"{action.get('name', '')}:{resource.get('id', '')}"
    return key not in deny


def _evaluate_one(deny: set[str], body: dict, item: dict | None = None) -> dict[str, Any]:
    src = item or body
    action = src.get("action") or body.get("action") or {}
    resource = src.get("resource") or body.get("resource") or {}
    subject = src.get("subject") or body.get("subject") or {}
    return {"decision": decide(deny, subject, action, resource)}


def make_handler(deny: set[str]) -> type[BaseHTTPRequestHandler]:
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
            if self.path.rstrip("/") == "/access/v1/evaluation":
                self._send(_evaluate_one(deny, body))
            elif self.path.rstrip("/") == "/access/v1/evaluations":
                items = body.get("evaluations") or [None]
                self._send({"evaluations": [_evaluate_one(deny, body, it) for it in items]})
            else:
                self._send({"error": "not found"}, status=404)

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock AuthZEN PDP")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--deny",
        action="append",
        default=[],
        help="deny rule '<action>:<resource_id>' (repeatable)",
    )
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(set(args.deny)))
    print(f"Mock AuthZEN PDP on http://127.0.0.1:{args.port} (deny={args.deny})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
