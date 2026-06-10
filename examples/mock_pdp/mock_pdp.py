"""A tiny, dependency-free AuthZEN PDP for tests and demos.

Implements ``POST /access/v1/evaluation`` and ``POST /access/v1/evaluations`` using only
the standard library. Decisions come from a deny-list; everything else is allowed.

Two deny-rule forms are supported:

* ``"<action>:<resource_id>"`` — action + resource match (any subject).
* ``"<subject_id>:<action>:<resource_id>"`` — subject + action + resource match.

Both are pure membership tests on composed keys (never split/parsed) so resource ids
containing ``:`` are safe.  Action names or subject ids containing ``:`` create key-space
overlap between the two rule forms (a 3-part rule can also match as a 2-part rule for a
colon-bearing action name) — fine for a demo, avoid ``:`` in action names when mixing
both forms.

This PDP is **permit-by-default** (deny-list): every request is allowed unless a deny
rule matches.  That is the **inverse** of production authorization semantics
(deny-by-default / permit-by-exception) and **must not be copied into real deployments**.

This is **not** a real authorization engine — it exists to exercise the scanner
end-to-end without standing up OPA/OpenFGA/Cedar.

Run::

    python examples/mock_pdp/mock_pdp.py --port 8080 --deny tool_call.execute:delete_table
    python examples/mock_pdp/mock_pdp.py --port 8080 --deny bot:tool_call.execute:delete_table
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


def decide(deny: set[str], subject: dict, action: dict, resource: dict) -> bool:
    """Return the allow/deny decision for one AuthZEN tuple.

    Checks both the 2-part ``"<action>:<resource_id>"`` key and the 3-part
    ``"<subject_id>:<action>:<resource_id>"`` key — pure membership tests, never
    split, so resource ids containing ``:`` are safe.
    """
    action_name = action.get("name", "")
    resource_id = resource.get("id", "")
    two_part = f"{action_name}:{resource_id}"
    three_part = f"{subject.get('id', '')}:{action_name}:{resource_id}"
    return two_part not in deny and three_part not in deny


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
        help=(
            "deny rule: '<action>:<resource_id>' (any subject) or "
            "'<subject_id>:<action>:<resource_id>' (subject-scoped); repeatable"
        ),
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
