"""AuthZEN client tests — transport, retries, error mapping, SSRF guard."""

from __future__ import annotations

import httpx
import pytest

from authzen_llamafirewall.client import AuthZENClient, validate_pdp_url
from authzen_llamafirewall.errors import (
    AuthZENClientError,
    AuthZENConfigError,
    MalformedPDPResponseError,
    PDPTimeoutError,
    PDPUnavailableError,
)
from authzen_llamafirewall.models import Action, EvaluationRequest, Resource, Subject

pytestmark = pytest.mark.unit

_EVAL_URL = "http://pdp.test/access/v1/evaluation"
_BATCH_URL = "http://pdp.test/access/v1/evaluations"


def _request() -> EvaluationRequest:
    return EvaluationRequest(
        subject=Subject(type="agent", id="bot"),
        action=Action(name="tool_call.execute"),
        resource=Resource(type="tool", id="database.delete_table"),
    )


async def _client(make_config, noop_sleep, **cfg):
    return AuthZENClient(make_config(**cfg), sleep=noop_sleep)


@pytest.mark.asyncio
async def test_evaluate_allow(make_config, noop_sleep, respx_mock) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    client = await _client(make_config, noop_sleep)
    resp = await client.evaluate(_request())
    assert resp.decision is True
    await client.aclose()


@pytest.mark.asyncio
async def test_evaluate_deny(make_config, noop_sleep, respx_mock) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": False})
    client = await _client(make_config, noop_sleep)
    assert (await client.evaluate(_request())).decision is False
    await client.aclose()


@pytest.mark.asyncio
async def test_batch(make_config, noop_sleep, respx_mock) -> None:
    from authzen_llamafirewall.models import BatchEvaluationRequest, EvaluationItem

    respx_mock.post(_BATCH_URL).respond(
        json={"evaluations": [{"decision": True}, {"decision": False}]}
    )
    client = await _client(make_config, noop_sleep)
    req = _request()
    batch = BatchEvaluationRequest(
        evaluations=[EvaluationItem(resource=req.resource, action=req.action, subject=req.subject)]
    )
    resp = await client.evaluate_batch(batch)
    assert [e.decision for e in resp.evaluations] == [True, False]
    await client.aclose()


@pytest.mark.asyncio
async def test_4xx_is_client_error_and_not_retried(make_config, noop_sleep, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL).respond(status_code=403, json={"error": "nope"})
    client = await _client(make_config, noop_sleep)
    with pytest.raises(AuthZENClientError) as exc:
        await client.evaluate(_request())
    assert exc.value.status_code == 403
    assert route.call_count == 1  # never retried
    await client.aclose()


@pytest.mark.asyncio
async def test_5xx_retries_then_fails(make_config, noop_sleep, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL).respond(status_code=503)
    client = await _client(make_config, noop_sleep, max_retries=2)
    with pytest.raises(PDPUnavailableError):
        await client.evaluate(_request())
    assert route.call_count == 3  # 1 + 2 retries
    await client.aclose()


@pytest.mark.asyncio
async def test_429_retry_then_success(make_config, noop_sleep, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL)
    route.side_effect = [
        httpx.Response(429),
        httpx.Response(200, json={"decision": True}),
    ]
    client = await _client(make_config, noop_sleep, max_retries=2)
    assert (await client.evaluate(_request())).decision is True
    assert route.call_count == 2
    await client.aclose()


@pytest.mark.asyncio
async def test_timeout_maps_to_pdp_timeout(make_config, noop_sleep, respx_mock) -> None:
    respx_mock.post(_EVAL_URL).mock(side_effect=httpx.ReadTimeout("slow"))
    client = await _client(make_config, noop_sleep, max_retries=0)
    with pytest.raises(PDPTimeoutError):
        await client.evaluate(_request())
    await client.aclose()


@pytest.mark.asyncio
async def test_connect_error_maps_to_unavailable(make_config, noop_sleep, respx_mock) -> None:
    respx_mock.post(_EVAL_URL).mock(side_effect=httpx.ConnectError("refused"))
    client = await _client(make_config, noop_sleep, max_retries=0)
    with pytest.raises(PDPUnavailableError):
        await client.evaluate(_request())
    await client.aclose()


@pytest.mark.asyncio
async def test_missing_decision_is_malformed(make_config, noop_sleep, respx_mock) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"context": {}})  # no decision
    client = await _client(make_config, noop_sleep)
    with pytest.raises(MalformedPDPResponseError):
        await client.evaluate(_request())
    await client.aclose()


@pytest.mark.asyncio
async def test_non_json_body_is_malformed(make_config, noop_sleep, respx_mock) -> None:
    respx_mock.post(_EVAL_URL).respond(content=b"not json", headers={"content-type": "text/plain"})
    client = await _client(make_config, noop_sleep)
    with pytest.raises(MalformedPDPResponseError):
        await client.evaluate(_request())
    await client.aclose()


@pytest.mark.asyncio
async def test_default_headers_are_sent(make_config, noop_sleep, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    client = await _client(
        make_config, noop_sleep, default_headers={"Authorization": "Bearer s3cret"}
    )
    await client.evaluate(_request())
    assert route.calls.last.request.headers["authorization"] == "Bearer s3cret"
    await client.aclose()


def test_ssrf_guard_rejects_http_and_private_and_localhost() -> None:
    with pytest.raises(AuthZENConfigError):
        validate_pdp_url("http://pdp.internal", allow_insecure=False)  # not https
    with pytest.raises(AuthZENConfigError):
        validate_pdp_url("https://10.0.0.5", allow_insecure=False)  # private
    with pytest.raises(AuthZENConfigError):
        validate_pdp_url("https://localhost", allow_insecure=False)
    # public https hostname is allowed; insecure flag bypasses the guard
    validate_pdp_url("https://pdp.example.com", allow_insecure=False)
    validate_pdp_url("http://127.0.0.1:8080", allow_insecure=True)
