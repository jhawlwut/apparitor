"""AuthZEN client tests — transport, retries, error mapping, SSRF guard."""

from __future__ import annotations

import httpx
import pytest

from apparitor.client import AuthZENClient, validate_pdp_url
from apparitor.errors import (
    AuthZENClientError,
    AuthZENConfigError,
    MalformedPDPResponseError,
    PDPTimeoutError,
    PDPUnavailableError,
)
from apparitor.models import Action, EvaluationRequest, Resource, Subject

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
    from apparitor.models import BatchEvaluationRequest, EvaluationItem

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
async def test_transport_error_retries_then_recovers(make_config, noop_sleep, respx_mock) -> None:
    # A transient transport fault is retried and the next attempt succeeds.
    route = respx_mock.post(_EVAL_URL)
    route.side_effect = [httpx.ConnectError("blip"), httpx.Response(200, json={"decision": True})]
    client = await _client(make_config, noop_sleep, max_retries=2)
    assert (await client.evaluate(_request())).decision is True
    assert route.call_count == 2
    await client.aclose()


@pytest.mark.asyncio
async def test_protocol_error_maps_to_unavailable(make_config, noop_sleep, respx_mock) -> None:
    # A non-timeout transport fault (e.g. protocol error) routes to a service error.
    respx_mock.post(_EVAL_URL).mock(side_effect=httpx.RemoteProtocolError("boom"))
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


@pytest.mark.asyncio
async def test_non_bool_decision_is_malformed(make_config, noop_sleep, respx_mock) -> None:
    # A truthy non-bool (e.g. 1) must NOT coerce to an ALLOW.
    respx_mock.post(_EVAL_URL).respond(json={"decision": 1})
    client = await _client(make_config, noop_sleep)
    with pytest.raises(MalformedPDPResponseError):
        await client.evaluate(_request())
    await client.aclose()


@pytest.mark.asyncio
async def test_unfollowed_redirect_fails_closed(make_config, noop_sleep, respx_mock) -> None:
    respx_mock.post(_EVAL_URL).respond(
        status_code=302, headers={"location": "http://169.254.169.254"}
    )
    client = await _client(make_config, noop_sleep, max_retries=0)
    with pytest.raises(PDPUnavailableError):
        await client.evaluate(_request())
    await client.aclose()


@pytest.mark.asyncio
async def test_budget_stops_retries_early(make_config, respx_mock) -> None:
    # A driven clock: each backoff "sleep" advances time past the budget, so retries stop
    # before max_retries is reached.
    now = [0.0]

    async def advancing_sleep(seconds: float) -> None:
        now[0] += max(seconds, 1.0)

    route = respx_mock.post(_EVAL_URL).respond(status_code=503)
    cfg = make_config(max_retries=10, request_budget_s=2.0, backoff_base_s=0.0)
    client = AuthZENClient(cfg, sleep=advancing_sleep, clock=lambda: now[0])
    # Budget exhaustion raises a timeout, well before max_retries (10) is reached.
    with pytest.raises(PDPTimeoutError):
        await client.evaluate(_request())
    assert route.call_count < 5
    await client.aclose()


@pytest.mark.asyncio
async def test_byo_client_is_not_closed_by_aclose(make_config, noop_sleep) -> None:
    byo = httpx.AsyncClient(base_url="http://pdp.test")
    client = AuthZENClient(make_config(), http_client=byo, sleep=noop_sleep)
    await client.aclose()
    assert not byo.is_closed  # caller owns the client's lifecycle
    await byo.aclose()


@pytest.mark.asyncio
async def test_duplicate_json_key_in_response_is_malformed(
    make_config, noop_sleep, respx_mock
) -> None:
    # A body like {"decision": false, "decision": true} must not be silently collapsed to
    # {"decision": true} (last-wins in json.loads) before pydantic's StrictBool sees it —
    # that would coerce a contradictory/malformed response into an ALLOW.  Requirements §3.6.
    respx_mock.post(_EVAL_URL).respond(
        content=b'{"decision": false, "decision": true}',
        headers={"content-type": "application/json"},
    )
    client = await _client(make_config, noop_sleep)
    with pytest.raises(MalformedPDPResponseError, match="duplicate"):
        await client.evaluate(_request())
    await client.aclose()


@pytest.mark.asyncio
async def test_batch_response_sibling_objects_with_same_key_are_valid(
    make_config, noop_sleep, respx_mock
) -> None:
    # Sibling JSON objects (e.g. two "decision" fields in distinct array entries) are NOT
    # duplicates — the duplicate-key check is per-object, not across the whole document.
    from apparitor.models import BatchEvaluationRequest, EvaluationItem

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


def test_ssrf_guard_rejects_http_and_private_and_localhost() -> None:
    for bad in (
        "http://pdp.internal",  # not https
        "https://10.0.0.5",  # private
        "https://localhost",
        "https://0.0.0.0",  # unspecified
        "https://[::1]",  # IPv6 loopback
        "https://[::ffff:169.254.169.254]",  # IPv4-mapped link-local (cloud metadata)
    ):
        with pytest.raises(AuthZENConfigError):
            validate_pdp_url(bad, allow_insecure=False)
    # public https hostname is allowed; insecure flag bypasses the guard
    validate_pdp_url("https://pdp.example.com", allow_insecure=False)
    validate_pdp_url("http://127.0.0.1:8080", allow_insecure=True)


def test_ssrf_guard_accepts_public_ip_literal() -> None:
    # The fall-through branch (a public IP literal that passes all is_private/is_loopback/
    # etc. checks) must not raise.  8.8.8.8 is a globally-routable address; Python's
    # ipaddress classifies it as neither private nor reserved.
    validate_pdp_url("https://8.8.8.8/access/v1/evaluation", allow_insecure=False)


def test_ssrf_guard_rejects_unparseable_url() -> None:
    # A string urlparse cannot split (e.g. an unterminated IPv6 literal) must surface as the
    # guard's typed AuthZENConfigError, not a raw ValueError leaking out — for both flag
    # states, since urlparse runs before the allow_insecure short-circuit. Regression for a
    # finding surfaced by the fuzz harness (fuzz/fuzz_url_guard.py).
    for bad in ("https://[", "https://[::1", "https://exa[mple"):
        for insecure in (False, True):
            with pytest.raises(AuthZENConfigError):
                validate_pdp_url(bad, allow_insecure=insecure)


@pytest.mark.asyncio
async def test_batch_nested_duplicate_key_in_evaluations_entry_is_malformed(
    make_config, noop_sleep, respx_mock
) -> None:
    # A duplicate key *inside* one of the evaluation-array objects (not at the top level)
    # must also trigger MalformedPDPResponseError — the object_pairs_hook fires recursively
    # per JSON object, so this is already handled; this test pins that it stays covered.
    from apparitor.models import BatchEvaluationRequest, EvaluationItem

    respx_mock.post(_BATCH_URL).respond(
        content=b'{"evaluations": [{"decision": false, "decision": true}]}',
        headers={"content-type": "application/json"},
    )
    client = await _client(make_config, noop_sleep)
    req = _request()
    batch = BatchEvaluationRequest(
        evaluations=[EvaluationItem(resource=req.resource, action=req.action, subject=req.subject)]
    )
    with pytest.raises(MalformedPDPResponseError, match="duplicate"):
        await client.evaluate_batch(batch)
    await client.aclose()
