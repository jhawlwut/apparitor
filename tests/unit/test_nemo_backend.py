"""NeMo Guardrails rail adapter tests — verdict → ``RailOutcome`` mapping and action wiring.

Requires nemoguardrails (the adapter's only hard dependency); skipped automatically when it is
not installed (a dedicated CI job installs ``[nemo]`` to run these). The PDP is mocked with
respx, exactly like the scanner/engine tests — the firewall-free engine does the real work, so
these assert only the NeMo boundary: the ``RailOutcome`` decision and its fail-closed mapping,
the surfaced verdict metadata, the action/dispatcher wiring, and the documented Colang flow.
"""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.unit

pytest.importorskip("nemoguardrails")

from nemoguardrails import LLMRails, RailsConfig  # noqa: E402
from nemoguardrails.actions.action_dispatcher import ActionDispatcher  # noqa: E402
from nemoguardrails.actions.rail_outcome import RailDecision, RailOutcome  # noqa: E402

from apparitor import Subject  # noqa: E402
from apparitor.mapping import subject_scope  # noqa: E402
from apparitor.nemo import NeMoAuthorizationRails  # noqa: E402

_EVAL_URL = "http://pdp.test/access/v1/evaluation"

# The wiring from the module docstring, plus a test-only confirmation on the allow path so
# the flow completes without an LLM.
_COLANG = """
define bot refuse to authorize tool call
  "I can't authorize that action."

define bot confirm tool call
  "Tool call authorized."

define flow authorize tool calls
  $result = execute authorize_tool_calls(tool_calls=$tool_calls)
  if $result.is_blocked
    bot refuse to authorize tool call
    stop
  bot confirm tool call
  stop
"""

_RAILS_YAML = """
models: []
rails:
  input:
    flows:
      - authorize tool calls
"""


def test_constructor_requires_pdp_url_or_config() -> None:
    with pytest.raises(ValueError, match="pdp_url or config"):
        NeMoAuthorizationRails()


# --- action end-to-end (engine driven via a mocked PDP) -----------------------------


@pytest.mark.asyncio
async def test_action_allows_authorized_call(make_config, make_openai_call, respx_mock) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    async with NeMoAuthorizationRails(config=make_config()) as guard:
        result = await guard.action(tool_calls=[make_openai_call("read_file", path="/tmp")])
    assert isinstance(result, RailOutcome)
    assert result.decision is RailDecision.ALLOW
    assert result.is_blocked is False
    assert result.metadata["tool_authorization_verdict"] == "allow"
    assert result.metadata["tool_authorization_status"] == "success"
    # Plain-typed evidence: a host can serialise it into a refusal message or a log line.
    json.dumps(result.metadata)


@pytest.mark.asyncio
async def test_action_refuses_unauthorized_call(make_config, make_openai_call, respx_mock) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": False})
    async with NeMoAuthorizationRails(config=make_config()) as guard:
        result = await guard.action(tool_calls=[make_openai_call("delete_table")])
    assert result.decision is RailDecision.BLOCK
    assert result.is_blocked is True
    # The rail's own decision, not a block NeMo synthesised because the action raised.
    assert result.failed is False
    assert result.metadata["tool_authorization_verdict"] == "block"


@pytest.mark.asyncio
async def test_action_fails_closed_on_pdp_error(make_config, make_openai_call, respx_mock) -> None:
    # PDP unreachable → on_error=DENY → BLOCK with status=ERROR → refuse (no silent allow).
    respx_mock.post(_EVAL_URL).respond(status_code=503)
    async with NeMoAuthorizationRails(config=make_config(max_retries=0)) as guard:
        result = await guard.action(tool_calls=[make_openai_call("read")])
    assert result.is_blocked is True
    assert result.metadata["tool_authorization_status"] == "error"


@pytest.mark.asyncio
async def test_action_refuses_on_human_review(make_config, make_openai_call, respx_mock) -> None:
    # on_error=HUMAN_REVIEW → PDP error yields HUMAN_REVIEW(status=ERROR) → must still refuse
    # (NeMo has no native HITL pause; HUMAN_REVIEW maps to block, surfaced for escalation).
    respx_mock.post(_EVAL_URL).respond(status_code=503)
    cfg = make_config(max_retries=0, on_error="human_review")
    async with NeMoAuthorizationRails(config=cfg) as guard:
        result = await guard.action(tool_calls=[make_openai_call("read")])
    assert result.is_blocked is True
    assert result.metadata["tool_authorization_verdict"] == "human_review"


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
    assert result.is_blocked is True
    assert result.metadata["tool_authorization_verdict"] == "human_review"
    assert result.metadata["tool_authorization_status"] == "success"


@pytest.mark.asyncio
async def test_action_skips_when_no_tool_calls(make_config, respx_mock) -> None:
    # Nothing to authorize → SKIP → allowed (pass-through), PDP never consulted.
    route = respx_mock.post(_EVAL_URL)
    async with NeMoAuthorizationRails(config=make_config()) as guard:
        result = await guard.action(tool_calls=None)
    assert result.is_blocked is False
    assert result.metadata["tool_authorization_verdict"] == "skip"
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_action_reads_tool_calls_from_context(
    make_config, make_openai_call, respx_mock
) -> None:
    # When the flow does not pass tool_calls explicitly, fall back to the NeMo context.
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    async with NeMoAuthorizationRails(config=make_config()) as guard:
        result = await guard.action(context={"tool_calls": [make_openai_call("read")]})
    assert result.is_blocked is False
    # "allow" (not "skip") proves the call came from context and the PDP was consulted.
    assert result.metadata["tool_authorization_verdict"] == "allow"
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
    assert isinstance(result, RailOutcome)
    assert result.is_blocked is True


@pytest.mark.asyncio
async def test_register_wires_action_onto_llmrails(make_config) -> None:
    rails = LLMRails(RailsConfig.from_content(yaml_content="models: []"))
    async with NeMoAuthorizationRails(config=make_config()) as guard:
        assert guard.register(rails) is rails
        assert rails.runtime.action_dispatcher.get_action(guard.action_name) is guard.action


def _rails_with_flow(guard: NeMoAuthorizationRails) -> LLMRails:
    rails = LLMRails(RailsConfig.from_content(colang_content=_COLANG, yaml_content=_RAILS_YAML))
    return guard.register(rails)


def _messages(tool_call: dict[str, object]) -> list[dict[str, object]]:
    # NeMo has no built-in tool-calls key: the host injects them via a context message.
    return [
        {"role": "context", "content": {"tool_calls": [tool_call]}},
        {"role": "user", "content": "run it"},
    ]


@pytest.mark.asyncio
async def test_documented_flow_refuses_denied_call(
    make_config, make_openai_call, respx_mock
) -> None:
    # The Colang flow from the module docstring, driven end-to-end through LLMRails: a denied
    # verdict must reach `$result.is_blocked` and stop the turn before any LLM is consulted.
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": False})
    async with NeMoAuthorizationRails(config=make_config()) as guard:
        rails = _rails_with_flow(guard)
        reply = await rails.generate_async(messages=_messages(make_openai_call("delete_table")))
    assert reply["content"] == "I can't authorize that action."
    assert route.call_count == 1


@pytest.mark.asyncio
async def test_documented_flow_passes_allowed_call(
    make_config, make_openai_call, respx_mock
) -> None:
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    async with NeMoAuthorizationRails(config=make_config()) as guard:
        rails = _rails_with_flow(guard)
        reply = await rails.generate_async(messages=_messages(make_openai_call("read_file")))
    assert reply["content"] == "Tool call authorized."
    assert route.call_count == 1
