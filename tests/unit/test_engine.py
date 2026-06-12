"""End-to-end engine pipeline tests (extract → map → evaluate → decide) via respx."""

from __future__ import annotations

import httpx
import pytest

from apparitor.client import AuthZENClient
from apparitor.config import OnError
from apparitor.decision import Verdict, VerdictStatus
from apparitor.engine import AuthorizationEngine, build_engine
from apparitor.errors import AuthZENConfigError

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


# --- evaluate_normalized (the structured-call seam for MCP-boundary PEPs) -----------


@pytest.mark.asyncio
async def test_evaluate_normalized_allows(make_config, noop_sleep, respx_mock) -> None:
    from apparitor.adapters import NormalizedToolCall

    respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    engine = _engine(make_config(), noop_sleep)
    result = await engine.evaluate_normalized([NormalizedToolCall("read_file", {"path": "/t"})])
    assert result.verdict is Verdict.ALLOW
    assert result.status is VerdictStatus.SUCCESS


@pytest.mark.asyncio
async def test_evaluate_normalized_blocks(make_config, noop_sleep, respx_mock) -> None:
    from apparitor.adapters import NormalizedToolCall

    respx_mock.post(_EVAL_URL).respond(json={"decision": False})
    engine = _engine(make_config(), noop_sleep)
    result = await engine.evaluate_normalized([NormalizedToolCall("delete_table")])
    assert result.verdict is Verdict.BLOCK
    assert result.status is VerdictStatus.SUCCESS


@pytest.mark.asyncio
async def test_evaluate_normalized_empty_skips(make_config, noop_sleep, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL)
    engine = _engine(make_config(), noop_sleep)
    for calls in (None, []):
        result = await engine.evaluate_normalized(calls)
        assert result.verdict is Verdict.SKIP
        assert result.status is VerdictStatus.SKIPPED
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_evaluate_normalized_mapper_abstention_skips(
    make_config, noop_sleep, respx_mock
) -> None:
    # Engine semantics: every mapper abstaining is SKIP. A PEP where a present call must
    # never silently pass (e.g. the FastMCP middleware) refuses SKIP at its own boundary.
    from apparitor.adapters import NormalizedToolCall

    class AbstainingMapper:
        def map(self, tool_call, request_context):
            return None

    route = respx_mock.post(_EVAL_URL)
    engine = _engine(make_config(), noop_sleep, mapper=AbstainingMapper())
    result = await engine.evaluate_normalized([NormalizedToolCall("read")])
    assert result.verdict is Verdict.SKIP
    assert result.status is VerdictStatus.SKIPPED
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_evaluate_normalized_missing_subject_fails_closed(
    make_config, noop_sleep, respx_mock
) -> None:
    from apparitor.adapters import NormalizedToolCall

    route = respx_mock.post(_EVAL_URL)
    engine = _engine(make_config(agent_id=None), noop_sleep)
    result = await engine.evaluate_normalized([NormalizedToolCall("read")])
    assert result.verdict is Verdict.BLOCK
    assert result.status is VerdictStatus.ERROR
    assert route.call_count == 0


# --- evaluate_requests (pre-mapped requests, e.g. MCP resource/prompt gating) -------


def _shaped_request(resource_id: str = "resource://config"):
    from apparitor.models import Action, EvaluationRequest, Resource, Subject

    return EvaluationRequest(
        subject=Subject(type="user", id="alice@acme.com"),
        action=Action(name="resource.read"),
        resource=Resource(type="mcp_resource", id=resource_id),
    )


@pytest.mark.asyncio
async def test_evaluate_requests_allows(make_config, noop_sleep, respx_mock) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    result = await _engine(make_config(), noop_sleep).evaluate_requests([_shaped_request()])
    assert result.verdict is Verdict.ALLOW
    assert result.status is VerdictStatus.SUCCESS


@pytest.mark.asyncio
async def test_evaluate_requests_blocks(make_config, noop_sleep, respx_mock) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": False})
    result = await _engine(make_config(), noop_sleep).evaluate_requests([_shaped_request()])
    assert result.verdict is Verdict.BLOCK


@pytest.mark.asyncio
async def test_evaluate_requests_empty_skips(make_config, noop_sleep, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL)
    for requests in (None, []):
        result = await _engine(make_config(), noop_sleep).evaluate_requests(requests)
        assert result.verdict is Verdict.SKIP
        assert result.status is VerdictStatus.SKIPPED
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_evaluate_requests_pdp_error_fails_closed(
    make_config, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_EVAL_URL).respond(status_code=503)
    engine = _engine(make_config(max_retries=0), noop_sleep)
    result = await engine.evaluate_requests([_shaped_request()])
    assert result.verdict is Verdict.BLOCK
    assert result.status is VerdictStatus.ERROR


# --- evaluate_each (per-item verdicts for visibility filtering) ---------------------


def _normalized(*names: str):
    from apparitor.adapters import NormalizedToolCall

    return [NormalizedToolCall(name) for name in names]


@pytest.mark.asyncio
async def test_evaluate_each_returns_positional_verdicts(
    make_config, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_BATCH_URL).respond(
        json={"evaluations": [{"decision": True}, {"decision": False}]}
    )
    results = await _engine(make_config(), noop_sleep).evaluate_each(_normalized("read", "rm"))
    assert [r.verdict for r in results] == [Verdict.ALLOW, Verdict.BLOCK]
    assert all(r.status is VerdictStatus.SUCCESS for r in results)


@pytest.mark.asyncio
async def test_evaluate_each_empty_returns_empty(make_config, noop_sleep, respx_mock) -> None:
    route = respx_mock.post(_BATCH_URL)
    assert await _engine(make_config(), noop_sleep).evaluate_each([]) == []
    assert await _engine(make_config(), noop_sleep).evaluate_each(None) == []
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_evaluate_each_mapper_abstention_blocks_item(
    make_config, noop_sleep, respx_mock
) -> None:
    # The abstained item fails closed while its sibling is still evaluated — positions align.
    from apparitor.config import ScannerConfig
    from apparitor.mapping import DefaultToolCallMapper

    class SelectiveMapper(DefaultToolCallMapper):
        def map(self, tool_call, request_context):
            return None if tool_call.name == "hidden" else super().map(tool_call, request_context)

    cfg: ScannerConfig = make_config()
    respx_mock.post(_BATCH_URL).respond(json={"evaluations": [{"decision": True}]})
    engine = _engine(cfg, noop_sleep, mapper=SelectiveMapper(cfg))
    results = await engine.evaluate_each(_normalized("hidden", "read"))
    assert results[0].verdict is Verdict.BLOCK
    assert results[0].status is VerdictStatus.ERROR
    assert results[1].verdict is Verdict.ALLOW


@pytest.mark.asyncio
async def test_evaluate_each_count_mismatch_blocks_all(make_config, noop_sleep, respx_mock) -> None:
    # A non-conformant PDP (short array) must not let any item through.
    respx_mock.post(_BATCH_URL).respond(json={"evaluations": [{"decision": True}]})
    results = await _engine(make_config(), noop_sleep).evaluate_each(_normalized("a", "b"))
    assert all(r.verdict is Verdict.BLOCK and r.status is VerdictStatus.ERROR for r in results)


@pytest.mark.asyncio
async def test_evaluate_each_pdp_error_resolves_on_error(
    make_config, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_BATCH_URL).respond(status_code=503)
    engine = _engine(make_config(max_retries=0, on_error="human_review"), noop_sleep)
    results = await engine.evaluate_each(_normalized("a", "b"))
    assert all(
        r.verdict is Verdict.HUMAN_REVIEW and r.status is VerdictStatus.ERROR for r in results
    )


@pytest.mark.asyncio
async def test_evaluate_each_review_predicate_escalates_item(
    make_config, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_BATCH_URL).respond(
        json={"evaluations": [{"decision": True, "context": {"step_up": True}}, {"decision": True}]}
    )
    engine = _engine(make_config(), noop_sleep, review_predicate=lambda c: bool(c.get("step_up")))
    results = await engine.evaluate_each(_normalized("transfer", "read"))
    assert results[0].verdict is Verdict.HUMAN_REVIEW
    assert results[1].verdict is Verdict.ALLOW


@pytest.mark.asyncio
async def test_evaluate_each_missing_subject_blocks_all(
    make_config, noop_sleep, respx_mock
) -> None:
    route = respx_mock.post(_BATCH_URL)
    results = await _engine(make_config(agent_id=None), noop_sleep).evaluate_each(
        _normalized("a", "b")
    )
    assert all(r.verdict is Verdict.BLOCK and r.status is VerdictStatus.ERROR for r in results)
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_evaluate_each_client_error_blocks_all(make_config, noop_sleep, respx_mock) -> None:
    # A 4xx is OUR fault — hard BLOCK for every item, never resolved through on_error.
    respx_mock.post(_BATCH_URL).respond(status_code=400)
    engine = _engine(make_config(max_retries=0, on_error="human_review"), noop_sleep)
    results = await engine.evaluate_each(_normalized("a", "b"))
    assert all(r.verdict is Verdict.BLOCK and r.status is VerdictStatus.ERROR for r in results)


@pytest.mark.asyncio
async def test_evaluate_each_unexpected_error_blocks_all(
    make_config, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_BATCH_URL).mock(side_effect=RuntimeError("boom"))
    results = await _engine(make_config(max_retries=0), noop_sleep).evaluate_each(
        _normalized("a", "b")
    )
    assert all(r.verdict is Verdict.BLOCK and r.status is VerdictStatus.ERROR for r in results)


@pytest.mark.asyncio
async def test_evaluate_each_all_abstain_blocks_without_pdp(
    make_config, noop_sleep, respx_mock
) -> None:
    class AbstainAll:
        def map(self, tool_call, request_context):
            return None

    route = respx_mock.post(_BATCH_URL)
    engine = _engine(make_config(), noop_sleep, mapper=AbstainAll())
    results = await engine.evaluate_each(_normalized("a", "b"))
    assert all(r.verdict is Verdict.BLOCK and r.status is VerdictStatus.ERROR for r in results)
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_evaluate_each_raising_predicate_fails_closed(
    make_config, noop_sleep, respx_mock
) -> None:
    # The per-item path must swallow a faulty review predicate exactly like the aggregate
    # path does — never raise, never ALLOW.
    def boom(_ctx: dict) -> bool:
        raise RuntimeError("predicate bug")

    respx_mock.post(_BATCH_URL).respond(
        json={"evaluations": [{"decision": True, "context": {"x": 1}}, {"decision": True}]}
    )
    engine = _engine(make_config(), noop_sleep, review_predicate=boom)
    results = await engine.evaluate_each(_normalized("a", "b"))
    assert all(r.verdict is Verdict.BLOCK and r.status is VerdictStatus.ERROR for r in results)


@pytest.mark.asyncio
async def test_evaluate_each_raising_mapper_fails_closed(
    make_config, noop_sleep, respx_mock
) -> None:
    class BoomMapper:
        def map(self, tool_call, request_context):
            raise RuntimeError("mapper bug")

    route = respx_mock.post(_BATCH_URL)
    engine = _engine(make_config(), noop_sleep, mapper=BoomMapper())
    results = await engine.evaluate_each(_normalized("a", "b"))
    assert all(r.verdict is Verdict.BLOCK and r.status is VerdictStatus.ERROR for r in results)
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_raising_mapper_fails_closed_on_aggregate_path(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    # The aggregate path must block on ANY mapper fault (not just config errors),
    # mirroring evaluate_each — the engine never raises, never allows on error.
    class BoomMapper:
        def map(self, tool_call, request_context):
            raise RuntimeError("mapper bug")

    route = respx_mock.post(_EVAL_URL)
    engine = _engine(make_config(), noop_sleep, mapper=BoomMapper())
    result = await engine.evaluate_tool_calls([make_openai_call("read")])
    assert result.verdict is Verdict.BLOCK
    assert result.status is VerdictStatus.ERROR
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_evaluate_each_metrics_fault_does_not_alter_verdicts(
    make_config, noop_sleep, respx_mock
) -> None:
    class RaisingSink:
        def record_decision(self, *, verdict: str, status: str, latency_s: float) -> None:
            raise RuntimeError("sink bug")

        def record_cache(self, *, hit: bool) -> None:
            raise RuntimeError("sink bug")

    respx_mock.post(_BATCH_URL).respond(
        json={"evaluations": [{"decision": True}, {"decision": False}]}
    )
    engine = _engine(make_config(), noop_sleep, metrics=RaisingSink())
    results = await engine.evaluate_each(_normalized("read", "rm"))
    assert [r.verdict for r in results] == [Verdict.ALLOW, Verdict.BLOCK]


# --- dual-principal (user AND agent) evaluation --------------------------------------


def _dual_engine(make_config, noop_sleep, **cfg):
    from apparitor.mapping import DualPrincipalMapper

    config = make_config(agent_id="travel-bot", **cfg)
    return _engine(config, noop_sleep, mapper=DualPrincipalMapper(config))


def _alice():
    from apparitor.mapping import subject_scope
    from apparitor.models import Subject

    return subject_scope(Subject(type="user", id="alice@acme.com"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("user_ok", "agent_ok", "expected"),
    [
        (True, True, Verdict.ALLOW),
        (True, False, Verdict.BLOCK),
        (False, True, Verdict.BLOCK),
        (False, False, Verdict.BLOCK),
    ],
)
async def test_dual_principal_truth_table(
    make_config, make_openai_call, noop_sleep, respx_mock, user_ok, agent_ok, expected
) -> None:
    # One call → two legs → the engine's all-allow-or-block batch aggregation is the AND:
    # the agent's own boundary denies even when the user holds the permission, and vice
    # versa.
    respx_mock.post(_BATCH_URL).respond(
        json={"evaluations": [{"decision": user_ok}, {"decision": agent_ok}]}
    )
    engine = _dual_engine(make_config, noop_sleep)
    with _alice():
        result = await engine.evaluate_tool_calls([make_openai_call("delete_table")])
    assert result.verdict is expected


@pytest.mark.asyncio
async def test_dual_principal_sends_both_legs(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    import json as jsonlib

    route = respx_mock.post(_BATCH_URL).respond(
        json={"evaluations": [{"decision": True}, {"decision": True}]}
    )
    engine = _dual_engine(make_config, noop_sleep)
    with _alice():
        await engine.evaluate_tool_calls([make_openai_call("read")])
    sent = jsonlib.loads(route.calls.last.request.content)
    subjects = [item["subject"]["id"] for item in sent["evaluations"]]
    assert subjects == ["alice@acme.com", "travel-bot"]


@pytest.mark.asyncio
async def test_dual_principal_multi_call_blocks_on_any_leg(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    # Two calls → four legs; one denied agent leg blocks the whole message.
    respx_mock.post(_BATCH_URL).respond(
        json={
            "evaluations": [
                {"decision": True},
                {"decision": True},
                {"decision": True},
                {"decision": False},
            ]
        }
    )
    engine = _dual_engine(make_config, noop_sleep)
    with _alice():
        result = await engine.evaluate_tool_calls(
            [make_openai_call("read"), make_openai_call("delete")]
        )
    assert result.verdict is Verdict.BLOCK


@pytest.mark.asyncio
async def test_dual_principal_missing_user_fails_closed(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    route = respx_mock.post(_BATCH_URL)
    engine = _dual_engine(make_config, noop_sleep)
    result = await engine.evaluate_tool_calls([make_openai_call("read")])
    assert result.verdict is Verdict.BLOCK
    assert result.status is VerdictStatus.ERROR
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_dual_principal_review_escalation_on_agent_leg(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_BATCH_URL).respond(
        json={
            "evaluations": [
                {"decision": True},
                {"decision": True, "context": {"step_up": True}},
            ]
        }
    )
    config = make_config(agent_id="travel-bot")
    from apparitor.mapping import DualPrincipalMapper

    engine = _engine(
        config,
        noop_sleep,
        mapper=DualPrincipalMapper(config),
        review_predicate=lambda ctx: bool(ctx.get("step_up")),
    )
    with _alice():
        result = await engine.evaluate_tool_calls([make_openai_call("transfer")])
    assert result.verdict is Verdict.HUMAN_REVIEW


@pytest.mark.asyncio
async def test_empty_sequence_mapper_is_abstention_not_allow(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    # all([]) is vacuously true — an empty group must read as abstention (SKIP on the
    # aggregate path), never as an allow.
    class EmptyMapper:
        def map(self, tool_call, request_context):
            return []

    route = respx_mock.post(_EVAL_URL)
    engine = _engine(make_config(), noop_sleep, mapper=EmptyMapper())
    result = await engine.evaluate_tool_calls([make_openai_call("read")])
    assert result.verdict is Verdict.SKIP
    assert result.status is VerdictStatus.SKIPPED
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_evaluate_each_groups_dual_legs_positionally(
    make_config, noop_sleep, respx_mock
) -> None:
    # Two calls under a dual mapper → groups of two legs; verdicts stay positional and
    # AND within each group ([T,T] → ALLOW, [T,F] → BLOCK).
    respx_mock.post(_BATCH_URL).respond(
        json={
            "evaluations": [
                {"decision": True},
                {"decision": True},
                {"decision": True},
                {"decision": False},
            ]
        }
    )
    engine = _dual_engine(make_config, noop_sleep)
    with _alice():
        results = await engine.evaluate_each(_normalized("read", "delete"))
    assert [r.verdict for r in results] == [Verdict.ALLOW, Verdict.BLOCK]


@pytest.mark.asyncio
async def test_evaluate_each_group_denied_first_leg_blocks(
    make_config, noop_sleep, respx_mock
) -> None:
    # [F,T] must BLOCK: a denied first leg can never be overwritten by a later allow
    # (catches a "combined = last leg" regression that [T,F] alone would let pass).
    respx_mock.post(_BATCH_URL).respond(
        json={
            "evaluations": [
                {"decision": False},
                {"decision": True},
                {"decision": True},
                {"decision": True},
            ]
        }
    )
    engine = _dual_engine(make_config, noop_sleep)
    with _alice():
        results = await engine.evaluate_each(_normalized("delete", "read"))
    assert [r.verdict for r in results] == [Verdict.BLOCK, Verdict.ALLOW]


@pytest.mark.asyncio
async def test_evaluate_each_group_review_first_leg_escalates(
    make_config, noop_sleep, respx_mock
) -> None:
    # [review,T] must surface HUMAN_REVIEW for the group — escalation sticks even when a
    # later leg is a clean allow.
    respx_mock.post(_BATCH_URL).respond(
        json={
            "evaluations": [
                {"decision": True, "context": {"step_up": True}},
                {"decision": True},
            ]
        }
    )
    from apparitor.mapping import DualPrincipalMapper

    config = make_config(agent_id="travel-bot")
    engine = _engine(
        config,
        noop_sleep,
        mapper=DualPrincipalMapper(config),
        review_predicate=lambda ctx: bool(ctx.get("step_up")),
    )
    with _alice():
        results = await engine.evaluate_each(_normalized("transfer"))
    assert [r.verdict for r in results] == [Verdict.HUMAN_REVIEW]


@pytest.mark.asyncio
async def test_evaluate_each_long_batch_fails_closed(make_config, noop_sleep, respx_mock) -> None:
    # A non-conformant PDP returning MORE decisions than legs is just as untrustworthy as
    # one returning fewer — every item must fail closed, not consume the extras.
    respx_mock.post(_BATCH_URL).respond(
        json={
            "evaluations": [
                {"decision": True},
                {"decision": True},
                {"decision": True},
            ]
        }
    )
    engine = _dual_engine(make_config, noop_sleep)
    with _alice():
        results = await engine.evaluate_each(_normalized("read"))
    assert [r.verdict for r in results] == [Verdict.BLOCK]
    assert results[0].status is VerdictStatus.ERROR


@pytest.mark.asyncio
async def test_evaluate_each_empty_group_blocks_item(make_config, noop_sleep, respx_mock) -> None:
    # An empty group on the positional path must BLOCK its item (never vacuous-allow),
    # while siblings still evaluate.
    class SelectiveEmpty:
        def __init__(self, config):
            from apparitor.mapping import DefaultToolCallMapper

            self._inner = DefaultToolCallMapper(config)

        def map(self, tool_call, request_context):
            if tool_call.name == "hidden":
                return []
            return self._inner.map(tool_call, request_context)

    respx_mock.post(_BATCH_URL).respond(json={"evaluations": [{"decision": True}]})
    cfg = make_config()
    engine = _engine(cfg, noop_sleep, mapper=SelectiveEmpty(cfg))
    results = await engine.evaluate_each(_normalized("hidden", "read"))
    assert results[0].verdict is Verdict.BLOCK
    assert results[0].status is VerdictStatus.ERROR
    assert results[1].verdict is Verdict.ALLOW


@pytest.mark.asyncio
async def test_decision_log_records_all_principals(
    make_config, make_openai_call, noop_sleep, respx_mock, caplog
) -> None:
    # The audit trail must say WHO was denied — both principals under dual evaluation.
    import logging

    respx_mock.post(_BATCH_URL).respond(
        json={"evaluations": [{"decision": True}, {"decision": False}]}
    )
    engine = _dual_engine(make_config, noop_sleep)
    with _alice(), caplog.at_level(logging.INFO, logger="apparitor"):
        await engine.evaluate_tool_calls([make_openai_call("delete")])
    assert "subjects=['alice@acme.com', 'travel-bot']" in caplog.text


# --- build_engine factory -----------------------------------------------------------


def test_build_engine_both_none_raises() -> None:
    # Neither pdp_url nor config — adapter misconfiguration must be loud.
    with pytest.raises(AuthZENConfigError, match="pdp_url or config"):
        build_engine(None, None)


def test_build_engine_both_provided_raises(make_config) -> None:
    # Providing both is ambiguous; the docstring prohibits it and config silently winning
    # would be a surprise — reject explicitly.
    with pytest.raises(AuthZENConfigError, match="not both"):
        build_engine("http://pdp.test", make_config())


def test_build_engine_pdp_url_only_builds_config() -> None:
    # A bare URL must construct a ScannerConfig and return a live engine.
    cfg, engine = build_engine("https://pdp.example.com/access/v1/evaluation", None)
    assert str(cfg.pdp_url) == "https://pdp.example.com/access/v1/evaluation"
    assert isinstance(engine, AuthorizationEngine)


# --- generic reason (no exception text to callers) ----------------------------------


@pytest.mark.asyncio
async def test_transport_error_reason_is_generic(
    make_config, make_openai_call, noop_sleep, respx_mock, caplog
) -> None:
    # Requirements §3.10: returned reason must be generic; PDP URL/host stays in operator
    # logs only. A transport error must not embed the exception text in VerdictResult.reason.
    import logging

    respx_mock.post(_EVAL_URL).mock(
        side_effect=httpx.ConnectError("connection refused: pdp.secret.internal")
    )
    engine = _engine(make_config(max_retries=0), noop_sleep)
    with caplog.at_level(logging.WARNING, logger="apparitor"):
        result = await engine.evaluate_tool_calls([make_openai_call("read")])
    assert result.verdict is Verdict.BLOCK
    assert result.status is VerdictStatus.ERROR
    # The detailed exception message must not appear in the caller-visible reason.
    assert "pdp.secret.internal" not in result.reason
    assert "connection refused" not in result.reason
    # But it MUST appear in the operator log.
    assert "pdp.secret.internal" in caplog.text or "connection refused" in caplog.text


@pytest.mark.asyncio
async def test_malformed_response_reason_is_generic(
    make_config, make_openai_call, noop_sleep, respx_mock, caplog
) -> None:
    # A malformed PDP body must not expose internal detail in the caller-visible reason.
    import logging

    respx_mock.post(_EVAL_URL).respond(
        content=b'{"decision": false, "decision": true}',
        headers={"content-type": "application/json"},
    )
    engine = _engine(make_config(max_retries=0), noop_sleep)
    with caplog.at_level(logging.WARNING, logger="apparitor"):
        result = await engine.evaluate_tool_calls([make_openai_call("read")])
    assert result.verdict is Verdict.BLOCK
    assert result.status is VerdictStatus.ERROR
    assert "duplicate" not in result.reason
    assert "decision" not in result.reason.lower().replace("blocked", "")


# --- CancelledError must not silently become ALLOW ----------------------------------


@pytest.mark.asyncio
async def test_cancelled_error_propagates_and_records_metric(
    make_config, make_openai_call, noop_sleep
) -> None:
    import asyncio

    from apparitor.backends import DecisionBackend
    from apparitor.metrics import InMemoryMetrics
    from apparitor.models import (
        BatchEvaluationRequest,
        BatchEvaluationResponse,
        EvaluationRequest,
        EvaluationResponse,
    )

    # Mid-PDP cancellation must re-raise CancelledError (structured concurrency) and
    # must never silently return an ALLOW (a missing verdict is non-authorized).
    class CancellingBackend:
        async def evaluate(self, request: EvaluationRequest) -> EvaluationResponse:
            raise asyncio.CancelledError()

        async def evaluate_batch(self, request: BatchEvaluationRequest) -> BatchEvaluationResponse:
            raise asyncio.CancelledError()

        async def aclose(self) -> None:
            pass

    assert isinstance(CancellingBackend(), DecisionBackend)
    metrics = InMemoryMetrics()
    cfg = make_config(max_retries=0)
    engine = AuthorizationEngine(cfg, client=CancellingBackend(), metrics=metrics)
    with pytest.raises(asyncio.CancelledError):
        await engine.evaluate_tool_calls([make_openai_call("read")])
    # The block/error counter must have been incremented so ops can observe the interruption.
    block_count = sum(
        v for (verdict, _status), v in metrics.decisions.items() if verdict == "block"
    )
    assert block_count >= 1


@pytest.mark.asyncio
async def test_evaluate_each_cancelled_error_propagates_and_records_metric(
    make_config, noop_sleep
) -> None:
    import asyncio

    from apparitor.backends import DecisionBackend
    from apparitor.metrics import InMemoryMetrics
    from apparitor.models import (
        BatchEvaluationRequest,
        BatchEvaluationResponse,
        EvaluationRequest,
        EvaluationResponse,
    )

    # A mid-batch cancellation on the per-item path must re-raise CancelledError so
    # structured concurrency can cancel the task, and must record a block/error metric
    # so the interruption is observable to ops (matching the assurance doc guarantee).
    class CancellingBackend:
        async def evaluate(self, request: EvaluationRequest) -> EvaluationResponse:
            raise asyncio.CancelledError()

        async def evaluate_batch(self, request: BatchEvaluationRequest) -> BatchEvaluationResponse:
            raise asyncio.CancelledError()

        async def aclose(self) -> None:
            pass

    assert isinstance(CancellingBackend(), DecisionBackend)
    metrics = InMemoryMetrics()
    cfg = make_config(max_retries=0)
    engine = AuthorizationEngine(cfg, client=CancellingBackend(), metrics=metrics)
    with pytest.raises(asyncio.CancelledError):
        await engine.evaluate_each(_normalized("read", "write"))
    block_count = sum(
        v for (verdict, _status), v in metrics.decisions.items() if verdict == "block"
    )
    assert block_count >= 1
