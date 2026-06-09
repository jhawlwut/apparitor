"""NeMo Guardrails rail adapter tests — verdict → allow/block(refuse) mapping and action wiring.

Requires nemoguardrails (the adapter's only hard dependency); skipped automatically when it is
not installed (a dedicated CI job installs ``[nemo]`` to run these). The PDP is mocked with
respx, exactly like the scanner/engine tests — the firewall-free engine does the real work, so
these assert only the NeMo boundary: the ``allowed`` return value, the ``output_mapping``
fail-closed semantics, the surfaced verdict context, and the action/dispatcher wiring.
"""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.unit

pytest.importorskip("nemoguardrails")

from nemoguardrails.actions.action_dispatcher import ActionDispatcher  # noqa: E402
from nemoguardrails.actions.actions import ActionResult  # noqa: E402
from nemoguardrails.actions.output_mapping import is_output_blocked  # noqa: E402

from apparitor import Subject  # noqa: E402
from apparitor.mapping import subject_scope  # noqa: E402
from apparitor.nemo import NeMoAuthorizationRails, authorization_blocks  # noqa: E402

_EVAL_URL = "http://pdp.test/access/v1/evaluation"


# --- output_mapping (the allow/block boundary) --------------------------------------


@pytest.mark.parametrize(
    ("value", "blocked"),
    [(True, False), (False, True), (None, True), ("allow", True), (0, True), (1, True)],
)
def test_output_mapping_fails_closed(value: object, blocked: bool) -> None:
    # Only an explicit True (an allowed verdict) passes; anything else refuses.
    assert authorization_blocks(value) is blocked


def test_constructor_requires_pdp_url_or_config() -> None:
    with pytest.raises(ValueError, match="pdp_url or config"):
        NeMoAuthorizationRails()


# --- action end-to-end (engine driven via a mocked PDP) -----------------------------


@pytest.mark.asyncio
async def test_action_allows_authorized_call(make_config, make_openai_call, respx_mock) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    async with NeMoAuthorizationRails(config=make_config()) as guard:
        result = await guard.action(tool_calls=[make_openai_call("read_file", path="/tmp")])
    assert isinstance(result, ActionResult)
    assert result.return_value is True
    assert result.context_updates["tool_authorization_verdict"] == "allow"
    assert is_output_blocked(result.return_value, guard.action) is False


@pytest.mark.asyncio
async def test_action_refuses_unauthorized_call(make_config, make_openai_call, respx_mock) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": False})
    async with NeMoAuthorizationRails(config=make_config()) as guard:
        result = await guard.action(tool_calls=[make_openai_call("delete_table")])
    assert result.return_value is False
    assert result.context_updates["tool_authorization_verdict"] == "block"
    assert is_output_blocked(result.return_value, guard.action) is True


@pytest.mark.asyncio
async def test_action_fails_closed_on_pdp_error(make_config, make_openai_call, respx_mock) -> None:
    # PDP unreachable → on_error=DENY → BLOCK with status=ERROR → refuse (no silent allow).
    respx_mock.post(_EVAL_URL).respond(status_code=503)
    async with NeMoAuthorizationRails(config=make_config(max_retries=0)) as guard:
        result = await guard.action(tool_calls=[make_openai_call("read")])
    assert result.return_value is False
    assert result.context_updates["tool_authorization_status"] == "error"
    assert is_output_blocked(result.return_value, guard.action) is True


@pytest.mark.asyncio
async def test_action_refuses_on_human_review(make_config, make_openai_call, respx_mock) -> None:
    # on_error=HUMAN_REVIEW → PDP error yields HUMAN_REVIEW(status=ERROR) → must still refuse
    # (NeMo has no native HITL pause; HUMAN_REVIEW maps to block, surfaced for escalation).
    respx_mock.post(_EVAL_URL).respond(status_code=503)
    cfg = make_config(max_retries=0, on_error="human_review")
    async with NeMoAuthorizationRails(config=cfg) as guard:
        result = await guard.action(tool_calls=[make_openai_call("read")])
    assert result.return_value is False
    assert result.context_updates["tool_authorization_verdict"] == "human_review"
    assert is_output_blocked(result.return_value, guard.action) is True


@pytest.mark.asyncio
async def test_action_refuses_on_review_predicate_escalation(
    make_config, make_openai_call, respx_mock
) -> None:
    # A clean ALLOW escalated to HUMAN_REVIEW by a review_predicate still refuses
    # (verdict not in the allow-set, status=SUCCESS) — the non-error human-review path.
    respx_mock.post(_EVAL_URL).respond(json={"decision": True, "context": {"step_up": True}})
    guard = NeMoAuthorizationRails(
        config=make_config(), review_predicate=lambda ctx: bool(ctx.get("step_up"))
    )
    async with guard:
        result = await guard.action(tool_calls=[make_openai_call("transfer_funds")])
    assert result.return_value is False
    assert result.context_updates["tool_authorization_verdict"] == "human_review"
    assert result.context_updates["tool_authorization_status"] == "success"
    assert is_output_blocked(result.return_value, guard.action) is True


@pytest.mark.asyncio
async def test_action_skips_when_no_tool_calls(make_config, respx_mock) -> None:
    # Nothing to authorize → SKIP → allowed (pass-through), PDP never consulted.
    route = respx_mock.post(_EVAL_URL)
    async with NeMoAuthorizationRails(config=make_config()) as guard:
        result = await guard.action(tool_calls=None)
    assert result.return_value is True
    assert result.context_updates["tool_authorization_verdict"] == "skip"
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_action_reads_tool_calls_from_context(
    make_config, make_openai_call, respx_mock
) -> None:
    # When the flow does not pass tool_calls explicitly, fall back to the NeMo context.
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    async with NeMoAuthorizationRails(config=make_config()) as guard:
        result = await guard.action(context={"tool_calls": [make_openai_call("read")]})
    assert result.return_value is True
    # "allow" (not "skip") proves the call came from context and the PDP was consulted.
    assert result.context_updates["tool_authorization_verdict"] == "allow"
    assert route.call_count == 1


@pytest.mark.asyncio
async def test_action_uses_request_scoped_subject(
    make_config, make_openai_call, respx_mock
) -> None:
    # Subject resolution is identical to the scanner: read from current_subject, not the message.
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    async with NeMoAuthorizationRails(config=make_config(agent_id=None)) as guard:
        with subject_scope(Subject(type="user", id="alice@acme.com")):
            await guard.action(tool_calls=[make_openai_call("read")])
    sent = json.loads(route.calls.last.request.content)
    assert sent["subject"]["id"] == "alice@acme.com"


# --- NeMo action / rail wiring ------------------------------------------------------


@pytest.mark.asyncio
async def test_action_registers_and_executes_via_dispatcher(
    make_config, make_openai_call, respx_mock
) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": False})
    dispatcher = ActionDispatcher(load_all_actions=False)
    async with NeMoAuthorizationRails(config=make_config()) as guard:
        dispatcher.register_action(guard.action, name=guard.action_name)
        assert dispatcher.get_action(guard.action_name) is guard.action
        result, status = await dispatcher.execute_action(
            guard.action_name, {"tool_calls": [make_openai_call("delete_table")]}
        )
    assert status == "success"
    assert isinstance(result, ActionResult)
    assert is_output_blocked(result.return_value, guard.action) is True


@pytest.mark.asyncio
async def test_register_wires_action_onto_llmrails(make_config) -> None:
    from nemoguardrails import LLMRails, RailsConfig

    rails = LLMRails(RailsConfig.from_content(yaml_content="models: []"))
    async with NeMoAuthorizationRails(config=make_config()) as guard:
        assert guard.register(rails) is rails
        assert rails.runtime.action_dispatcher.get_action(guard.action_name) is guard.action
