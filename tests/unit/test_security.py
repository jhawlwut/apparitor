"""Security-property tests — the invariants that make this a real authorization control."""

from __future__ import annotations

import json
import logging

import pytest

from apparitor.client import AuthZENClient
from apparitor.config import ScannerConfig
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
