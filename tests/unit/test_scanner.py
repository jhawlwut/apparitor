"""Scanner boundary tests — verdict → LlamaFirewall ScanResult mapping.

Requires LlamaFirewall (the scanner's only hard dependency). Skipped automatically when
it is not installed; the rest of the pipeline is covered by the LlamaFirewall-free engine
tests. A separate CI job installs ``[llamafirewall]`` to run these.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

pytest.importorskip("llamafirewall")

from llamafirewall import AssistantMessage, ScanDecision, ScanStatus  # noqa: E402

from authzen_llamafirewall import AuthZENScanner, Subject  # noqa: E402
from authzen_llamafirewall.decision import Verdict, VerdictResult, VerdictStatus  # noqa: E402
from authzen_llamafirewall.mapping import subject_scope  # noqa: E402

_EVAL_URL = "http://pdp.test/access/v1/evaluation"


@pytest.mark.parametrize(
    ("verdict", "status", "expected_decision", "expected_status", "expected_score"),
    [
        (Verdict.ALLOW, VerdictStatus.SUCCESS, ScanDecision.ALLOW, ScanStatus.SUCCESS, 0.0),
        (Verdict.BLOCK, VerdictStatus.ERROR, ScanDecision.BLOCK, ScanStatus.ERROR, 1.0),
        (Verdict.SKIP, VerdictStatus.SKIPPED, ScanDecision.ALLOW, ScanStatus.SKIPPED, 0.0),
        (
            Verdict.HUMAN_REVIEW,
            VerdictStatus.SUCCESS,
            ScanDecision.HUMAN_IN_THE_LOOP_REQUIRED,
            ScanStatus.SUCCESS,
            0.5,
        ),
    ],
)
def test_verdict_maps_to_scan_result(
    make_config, verdict, status, expected_decision, expected_status, expected_score
) -> None:
    scanner = AuthZENScanner(config=make_config())
    result = scanner._to_scan_result(VerdictResult(verdict, "reason", status))
    assert result.decision == expected_decision
    assert result.status == expected_status
    assert result.score == expected_score
    assert result.reason == "reason"


def test_constructor_requires_pdp_url_or_config() -> None:
    with pytest.raises(ValueError, match="pdp_url or config"):
        AuthZENScanner()


@pytest.mark.asyncio
async def test_scan_end_to_end_allows(make_config, noop_sleep, respx_mock) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    message = AssistantMessage(
        content="",
        tool_calls=[{"type": "function", "function": {"name": "read", "arguments": "{}"}}],
    )
    async with AuthZENScanner(config=make_config(agent_id="bot")) as scanner:
        result = await scanner.scan(message)
    assert result.decision == ScanDecision.ALLOW
    assert result.status == ScanStatus.SUCCESS


@pytest.mark.asyncio
async def test_scan_blocks_unauthorized_tool_call(make_config, noop_sleep, respx_mock) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": False})
    message = AssistantMessage(
        content="",
        tool_calls=[{"type": "function", "function": {"name": "delete", "arguments": "{}"}}],
    )
    async with AuthZENScanner(config=make_config(agent_id="bot")) as scanner:
        result = await scanner.scan(message)
    assert result.decision == ScanDecision.BLOCK


@pytest.mark.asyncio
async def test_scan_uses_request_scoped_subject(make_config, noop_sleep, respx_mock) -> None:
    import json

    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    message = AssistantMessage(
        content="",
        tool_calls=[{"type": "function", "function": {"name": "read", "arguments": "{}"}}],
    )
    async with AuthZENScanner(config=make_config(agent_id=None)) as scanner:
        with subject_scope(Subject(type="user", id="alice@acme.com")):
            await scanner.scan(message)
    sent = json.loads(route.calls.last.request.content)
    assert sent["subject"]["id"] == "alice@acme.com"


@pytest.mark.asyncio
async def test_scan_with_no_tool_calls_skips(make_config, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL)
    message = AssistantMessage(content="just text, no tools")
    async with AuthZENScanner(config=make_config(agent_id="bot")) as scanner:
        result = await scanner.scan(message)
    assert result.decision == ScanDecision.ALLOW
    assert result.status == ScanStatus.SKIPPED
    assert route.call_count == 0
