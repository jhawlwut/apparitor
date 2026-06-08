"""Golden test: pin the exact AuthZEN request body the scanner puts on the wire.

Catches accidental wire-shape regressions (field renames, `exclude_none` changes,
redaction changes) that line coverage would miss.
"""

from __future__ import annotations

import json

import pytest

from apparitor.client import AuthZENClient
from apparitor.engine import AuthorizationEngine

pytestmark = pytest.mark.unit

_EVAL_URL = "http://pdp.test/access/v1/evaluation"

_EXPECTED_EVALUATION_BODY = {
    "subject": {"type": "agent", "id": "bot-123", "properties": {}},
    "action": {"name": "tool_call.execute", "properties": {}},
    "resource": {
        "type": "tool",
        "id": "read_file",
        "properties": {"arguments": {"path": "***redacted***"}},
    },
}


@pytest.mark.asyncio
async def test_single_evaluation_request_body_is_stable(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    engine = AuthorizationEngine(
        make_config(), client=AuthZENClient(make_config(), sleep=noop_sleep)
    )
    await engine.evaluate_tool_calls([make_openai_call("read_file", path="/etc/passwd")])
    sent = json.loads(route.calls.last.request.content)
    assert sent == _EXPECTED_EVALUATION_BODY
