"""End-to-end engine pipeline tests (extract → map → evaluate → decide) via respx."""

from __future__ import annotations

import httpx
import pytest

from authzen_llamafirewall.client import AuthZENClient
from authzen_llamafirewall.config import OnError
from authzen_llamafirewall.decision import Verdict, VerdictStatus
from authzen_llamafirewall.engine import AuthorizationEngine

pytestmark = pytest.mark.unit

_EVAL_URL = "http://pdp.test/access/v1/evaluation"
_BATCH_URL = "http://pdp.test/access/v1/evaluations"


def _engine(cfg, noop_sleep, **kw):
    client = AuthZENClient(cfg, sleep=noop_sleep)
    return AuthorizationEngine(cfg, client=client, **kw)


@pytest.mark.asyncio
async def test_authorized_call_allows(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    engine = _engine(make_config(), noop_sleep)
    result = await engine.evaluate_tool_calls([make_openai_call("read_file", path="/tmp")])
    assert result.verdict is Verdict.ALLOW
    assert result.status is VerdictStatus.SUCCESS


@pytest.mark.asyncio
async def test_unauthorized_call_blocks(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": False})
    engine = _engine(make_config(), noop_sleep)
    result = await engine.evaluate_tool_calls([make_openai_call("delete_table")])
    assert result.verdict is Verdict.BLOCK
    assert result.status is VerdictStatus.SUCCESS


@pytest.mark.asyncio
async def test_no_tool_calls_skips(make_config, noop_sleep, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL)
    result = await _engine(make_config(), noop_sleep).evaluate_tool_calls(None)
    assert result.verdict is Verdict.SKIP
    assert result.status is VerdictStatus.SKIPPED
    assert route.call_count == 0  # PDP never consulted


@pytest.mark.asyncio
async def test_unparseable_tool_call_fails_closed(make_config, noop_sleep, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL)
    result = await _engine(make_config(), noop_sleep).evaluate_tool_calls([{"weird": "shape"}])
    assert result.verdict is Verdict.BLOCK
    assert result.status is VerdictStatus.ERROR
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_missing_subject_fails_closed(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    route = respx_mock.post(_EVAL_URL)
    engine = _engine(make_config(agent_id=None), noop_sleep)
    result = await engine.evaluate_tool_calls([make_openai_call("read")])
    assert result.verdict is Verdict.BLOCK
    assert result.status is VerdictStatus.ERROR
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_batch_all_allow(make_config, make_openai_call, noop_sleep, respx_mock) -> None:
    respx_mock.post(_BATCH_URL).respond(
        json={"evaluations": [{"decision": True}, {"decision": True}]}
    )
    engine = _engine(make_config(), noop_sleep)
    result = await engine.evaluate_tool_calls([make_openai_call("read"), make_openai_call("list")])
    assert result.verdict is Verdict.ALLOW


@pytest.mark.asyncio
async def test_batch_any_deny_blocks_whole_message(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_BATCH_URL).respond(
        json={"evaluations": [{"decision": True}, {"decision": False}]}
    )
    engine = _engine(make_config(), noop_sleep)
    result = await engine.evaluate_tool_calls(
        [make_openai_call("read"), make_openai_call("delete")]
    )
    assert result.verdict is Verdict.BLOCK


@pytest.mark.asyncio
async def test_pdp_down_denies_by_default(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_EVAL_URL).respond(status_code=503)
    engine = _engine(make_config(max_retries=0), noop_sleep)
    result = await engine.evaluate_tool_calls([make_openai_call("read")])
    assert result.verdict is Verdict.BLOCK
    assert result.status is VerdictStatus.ERROR


@pytest.mark.asyncio
async def test_pdp_down_human_review_when_configured(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_EVAL_URL).mock(side_effect=httpx.ConnectError("refused"))
    engine = _engine(make_config(on_error=OnError.HUMAN_REVIEW, max_retries=0), noop_sleep)
    result = await engine.evaluate_tool_calls([make_openai_call("read")])
    assert result.verdict is Verdict.HUMAN_REVIEW
    assert result.status is VerdictStatus.ERROR


@pytest.mark.asyncio
async def test_cache_hit_skips_second_pdp_call(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    engine = _engine(make_config(cache_enabled=True), noop_sleep)
    call = make_openai_call("read", path="/tmp")
    assert (await engine.evaluate_tool_calls([call])).verdict is Verdict.ALLOW
    assert (await engine.evaluate_tool_calls([call])).verdict is Verdict.ALLOW
    assert route.call_count == 1  # second served from cache


@pytest.mark.asyncio
async def test_deny_is_not_cached(make_config, make_openai_call, noop_sleep, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": False})
    engine = _engine(make_config(cache_enabled=True), noop_sleep)
    call = make_openai_call("delete")
    await engine.evaluate_tool_calls([call])
    await engine.evaluate_tool_calls([call])
    assert route.call_count == 2  # deny re-checked, never cached


@pytest.mark.asyncio
async def test_review_predicate_escalates_allow_to_human(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": True, "context": {"step_up": True}})
    engine = _engine(
        make_config(), noop_sleep, review_predicate=lambda ctx: bool(ctx.get("step_up"))
    )
    result = await engine.evaluate_tool_calls([make_openai_call("wire_transfer")])
    assert result.verdict is Verdict.HUMAN_REVIEW


@pytest.mark.asyncio
async def test_review_predicate_cannot_downgrade_deny(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": False, "context": {"step_up": True}})
    engine = _engine(make_config(), noop_sleep, review_predicate=lambda ctx: True)
    result = await engine.evaluate_tool_calls([make_openai_call("delete")])
    assert result.verdict is Verdict.BLOCK


@pytest.mark.asyncio
async def test_all_mappers_abstain_skips(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    route = respx_mock.post(_EVAL_URL)

    class _AbstainMapper:
        def map(self, tool_call, request_context):
            return None

    cfg = make_config()
    engine = AuthorizationEngine(
        cfg, client=AuthZENClient(cfg, sleep=noop_sleep), mapper=_AbstainMapper()
    )
    result = await engine.evaluate_tool_calls([make_openai_call("read")])
    assert result.verdict is Verdict.SKIP
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_client_error_blocks_loudly(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_EVAL_URL).respond(status_code=403, json={"error": "forbidden"})
    engine = _engine(make_config(max_retries=0), noop_sleep)
    result = await engine.evaluate_tool_calls([make_openai_call("read")])
    assert result.verdict is Verdict.BLOCK
    assert result.status is VerdictStatus.ERROR


@pytest.mark.asyncio
async def test_malformed_tool_call_arguments_fail_closed(
    make_config, noop_sleep, respx_mock
) -> None:
    route = respx_mock.post(_EVAL_URL)
    # Recognised OpenAI shape but the arguments are not valid JSON.
    bad = {"type": "function", "function": {"name": "f", "arguments": "{not json"}}
    result = await _engine(make_config(), noop_sleep).evaluate_tool_calls([bad])
    assert result.verdict is Verdict.BLOCK
    assert result.status is VerdictStatus.ERROR
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_engine_aclose_is_idempotent(make_config, noop_sleep) -> None:
    engine = _engine(make_config(), noop_sleep)
    await engine.aclose()


@pytest.mark.asyncio
async def test_malformed_response_resolves_via_on_error(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"context": {}})  # missing decision
    deny = await _engine(make_config(max_retries=0), noop_sleep).evaluate_tool_calls(
        [make_openai_call("read")]
    )
    assert deny.verdict is Verdict.BLOCK
    assert deny.status is VerdictStatus.ERROR

    respx_mock.post(_EVAL_URL).respond(json={"context": {}})
    review = await _engine(
        make_config(on_error=OnError.HUMAN_REVIEW, max_retries=0), noop_sleep
    ).evaluate_tool_calls([make_openai_call("read")])
    assert review.verdict is Verdict.HUMAN_REVIEW


@pytest.mark.asyncio
async def test_batch_review_predicate_escalates(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    # The HITL bypass regression: a 2nd tool call must not dodge human review.
    respx_mock.post(_BATCH_URL).respond(
        json={"evaluations": [{"decision": True}, {"decision": True, "context": {"step_up": True}}]}
    )
    engine = _engine(
        make_config(), noop_sleep, review_predicate=lambda ctx: bool(ctx.get("step_up"))
    )
    result = await engine.evaluate_tool_calls(
        [make_openai_call("read"), make_openai_call("wire_transfer")]
    )
    assert result.verdict is Verdict.HUMAN_REVIEW


@pytest.mark.asyncio
async def test_batch_short_array_blocks(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    # Two calls submitted, one decision returned → block the whole message.
    respx_mock.post(_BATCH_URL).respond(json={"evaluations": [{"decision": True}]})
    engine = _engine(make_config(), noop_sleep)
    result = await engine.evaluate_tool_calls([make_openai_call("a"), make_openai_call("b")])
    assert result.verdict is Verdict.BLOCK


@pytest.mark.asyncio
async def test_batch_pdp_error_resolves_on_error(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_BATCH_URL).respond(status_code=503)
    engine = _engine(make_config(max_retries=0), noop_sleep)
    result = await engine.evaluate_tool_calls([make_openai_call("a"), make_openai_call("b")])
    assert result.verdict is Verdict.BLOCK
    assert result.status is VerdictStatus.ERROR


@pytest.mark.asyncio
async def test_predicate_with_no_context_does_not_escalate(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": True})  # no context
    engine = _engine(make_config(), noop_sleep, review_predicate=lambda ctx: True)
    result = await engine.evaluate_tool_calls([make_openai_call("read")])
    assert result.verdict is Verdict.ALLOW


@pytest.mark.asyncio
async def test_predicate_that_raises_fails_closed(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    def _boom(_ctx: dict) -> bool:
        raise RuntimeError("predicate bug")

    respx_mock.post(_EVAL_URL).respond(json={"decision": True, "context": {"x": 1}})
    engine = _engine(make_config(), noop_sleep, review_predicate=_boom)
    result = await engine.evaluate_tool_calls([make_openai_call("read")])
    assert result.verdict is Verdict.BLOCK
    assert result.status is VerdictStatus.ERROR
