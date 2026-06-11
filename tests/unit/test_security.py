"""Security-property tests — the invariants that make this a real authorization control."""

from __future__ import annotations

import json
import logging

import httpx
import pytest

from apparitor.client import AuthZENClient
from apparitor.config import OnError, ScannerConfig
from apparitor.decision import Verdict, VerdictStatus
from apparitor.engine import AuthorizationEngine
from apparitor.errors import AuthZENConfigError

pytestmark = pytest.mark.unit

_EVAL_URL = "http://pdp.test/access/v1/evaluation"


def _engine(cfg, noop_sleep, **kw):
    return AuthorizationEngine(cfg, client=AuthZENClient(cfg, sleep=noop_sleep), **kw)


def test_client_refuses_private_pdp_url() -> None:
    # SSRF guard fires at client construction, before any request is made.
    with pytest.raises(AuthZENConfigError):
        AuthZENClient(ScannerConfig(pdp_url="https://169.254.169.254"))  # cloud metadata


@pytest.mark.asyncio
async def test_subject_is_not_taken_from_tool_content(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    # A prompt-injected tool call tries to set itself as an admin subject.
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    engine = _engine(make_config(agent_id="bot-123"), noop_sleep)
    malicious = make_openai_call("read", subject="admin", role="superuser", id="root")
    await engine.evaluate_tool_calls([malicious])

    sent = json.loads(route.calls.last.request.content)
    assert sent["subject"]["id"] == "bot-123"  # trusted config, not the tool args
    assert sent["subject"]["type"] == "agent"


@pytest.mark.asyncio
async def test_auth_token_is_never_logged(
    make_config, make_openai_call, noop_sleep, respx_mock, caplog
) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    cfg = make_config(default_headers={"Authorization": "Bearer super-secret-token"})
    engine = _engine(cfg, noop_sleep)
    with caplog.at_level(logging.DEBUG, logger="apparitor"):
        await engine.evaluate_tool_calls([make_openai_call("read", api_key="leakme")])
    assert "super-secret-token" not in caplog.text
    assert "leakme" not in caplog.text  # redacted arguments aren't logged either


@pytest.mark.asyncio
async def test_arguments_are_redacted_in_the_pdp_request_by_default(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    engine = _engine(make_config(), noop_sleep)
    await engine.evaluate_tool_calls([make_openai_call("read", path="/etc/shadow")])
    sent = json.loads(route.calls.last.request.content)
    assert sent["resource"]["properties"]["arguments"] == {"path": "***redacted***"}


# --- ALLOW-only cache invariant -------------------------------------------------------


@pytest.mark.asyncio
async def test_block_decision_is_never_cached(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    # A BLOCK verdict must always be re-evaluated on every request: caching a deny would
    # risk promoting it to an allow if the PDP's decision later changes (e.g. policy
    # rollout between calls).  Only ALLOW decisions are stored in the cache.
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": False})
    engine = _engine(make_config(cache_enabled=True), noop_sleep)
    call = make_openai_call("delete_table")
    first = await engine.evaluate_tool_calls([call])
    second = await engine.evaluate_tool_calls([call])
    assert first.verdict is Verdict.BLOCK
    assert second.verdict is Verdict.BLOCK
    # Both calls hit the PDP — the deny was never placed in cache.
    assert route.call_count == 2


# --- on_error produces non-ALLOW outcomes on PDP failure ------------------------------


@pytest.mark.asyncio
async def test_pdp_failure_with_on_error_deny_blocks(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    # The default on_error=DENY path: a PDP outage must produce BLOCK(status=ERROR),
    # never a coerced allow.
    respx_mock.post(_EVAL_URL).mock(side_effect=httpx.ConnectError("refused"))
    engine = _engine(make_config(on_error=OnError.DENY, max_retries=0), noop_sleep)
    result = await engine.evaluate_tool_calls([make_openai_call("read")])
    assert result.verdict is Verdict.BLOCK
    assert result.status is VerdictStatus.ERROR


@pytest.mark.asyncio
async def test_pdp_failure_with_on_error_human_review_escalates(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    # on_error=HUMAN_REVIEW escalates to a HITL verdict on error — still non-ALLOW,
    # still fails closed.  HUMAN_REVIEW is never a silent allow.
    respx_mock.post(_EVAL_URL).mock(side_effect=httpx.ConnectError("refused"))
    engine = _engine(make_config(on_error=OnError.HUMAN_REVIEW, max_retries=0), noop_sleep)
    result = await engine.evaluate_tool_calls([make_openai_call("read")])
    assert result.verdict is Verdict.HUMAN_REVIEW
    assert result.status is VerdictStatus.ERROR
    # Confirm it is not an allow verdict — the is_allowed_* predicates must both refuse it.
    from apparitor.decision import is_allowed_gateway, is_allowed_inline

    assert is_allowed_inline(result) is False
    assert is_allowed_gateway(result) is False
