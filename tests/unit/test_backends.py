"""Native OPA backend + backend-selection tests (transport reuse, fail-closed parsing)."""

from __future__ import annotations

import json

import httpx
import pytest

from apparitor.backends import DecisionBackend, OPABackend, build_backend
from apparitor.client import AuthZENClient
from apparitor.config import Backend
from apparitor.decision import Verdict, VerdictStatus
from apparitor.engine import AuthorizationEngine
from apparitor.errors import (
    AuthZENClientError,
    AuthZENConfigError,
    MalformedPDPResponseError,
    PDPUnavailableError,
)
from apparitor.models import (
    Action,
    BatchEvaluationRequest,
    EvaluationItem,
    EvaluationRequest,
    Resource,
    Subject,
)

pytestmark = pytest.mark.unit

# config.opa_decision_path defaults to "apparitor/authz/allow".
_OPA_URL = "http://pdp.test/v1/data/apparitor/authz/allow"


def _request() -> EvaluationRequest:
    return EvaluationRequest(
        subject=Subject(type="agent", id="bot"),
        action=Action(name="tool_call.execute"),
        resource=Resource(type="tool", id="send_email"),
    )


async def _backend(make_config, noop_sleep, **cfg) -> OPABackend:
    return OPABackend(make_config(backend="opa", **cfg), sleep=noop_sleep)


# --- backend selection --------------------------------------------------------------


def test_build_backend_selects_by_config(make_config) -> None:
    assert isinstance(build_backend(make_config()), AuthZENClient)
    assert isinstance(build_backend(make_config(backend="opa")), OPABackend)


def test_backends_satisfy_the_protocol(make_config) -> None:
    # runtime_checkable Protocol: both backends are structurally a DecisionBackend.
    assert isinstance(build_backend(make_config()), DecisionBackend)
    assert isinstance(build_backend(make_config(backend="opa")), DecisionBackend)


def test_backend_coerced_from_string(make_config) -> None:
    assert make_config(backend="opa").backend is Backend.OPA
    assert make_config().backend is Backend.AUTHZEN


# --- single evaluation --------------------------------------------------------------


@pytest.mark.asyncio
async def test_evaluate_allow(make_config, noop_sleep, respx_mock) -> None:
    route = respx_mock.post(_OPA_URL).respond(json={"result": True})
    backend = await _backend(make_config, noop_sleep)
    assert (await backend.evaluate(_request())).decision is True
    # The whole AuthZEN tuple is handed to OPA as `input`.
    sent = json.loads(route.calls.last.request.content)
    assert sent == {"input": _request().model_dump(mode="json", exclude_none=True)}
    await backend.aclose()


@pytest.mark.asyncio
async def test_evaluate_deny(make_config, noop_sleep, respx_mock) -> None:
    respx_mock.post(_OPA_URL).respond(json={"result": False})
    backend = await _backend(make_config, noop_sleep)
    assert (await backend.evaluate(_request())).decision is False
    await backend.aclose()


@pytest.mark.asyncio
async def test_custom_decision_path(make_config, noop_sleep, respx_mock) -> None:
    route = respx_mock.post("http://pdp.test/v1/data/my/pkg/allow").respond(json={"result": True})
    backend = await _backend(make_config, noop_sleep, opa_decision_path="/my/pkg/allow/")
    assert (await backend.evaluate(_request())).decision is True
    assert route.called
    await backend.aclose()


@pytest.mark.parametrize(
    "body",
    [
        {},  # undefined result (no default rule) -> error, never a falsy allow
        {"result": "true"},  # string, not a bool
        {"result": 1},  # truthy int, not a bool
        {"result": {"allow": True}},  # object, not a bare bool
        {"result": None},
    ],
)
@pytest.mark.asyncio
async def test_non_boolean_result_fails_closed(make_config, noop_sleep, respx_mock, body) -> None:
    respx_mock.post(_OPA_URL).respond(json=body)
    backend = await _backend(make_config, noop_sleep)
    with pytest.raises(MalformedPDPResponseError):
        await backend.evaluate(_request())
    await backend.aclose()


@pytest.mark.asyncio
async def test_non_json_body_fails_closed(make_config, noop_sleep, respx_mock) -> None:
    respx_mock.post(_OPA_URL).respond(content=b"not json")
    backend = await _backend(make_config, noop_sleep)
    with pytest.raises(MalformedPDPResponseError):
        await backend.evaluate(_request())
    await backend.aclose()


# --- batch ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_fans_out_and_preserves_decisions(make_config, noop_sleep, respx_mock) -> None:
    # OPA has no batch endpoint: each entry is its own Data API call. Decide by resource id.
    def by_resource(request: httpx.Request) -> httpx.Response:
        denied = b"delete_database" in request.read()
        return httpx.Response(200, json={"result": not denied})

    respx_mock.post(_OPA_URL).mock(side_effect=by_resource)
    backend = await _backend(make_config, noop_sleep)
    req = _request()
    batch = BatchEvaluationRequest(
        subject=req.subject,
        action=req.action,
        evaluations=[
            EvaluationItem(resource=Resource(type="tool", id="send_email")),
            EvaluationItem(resource=Resource(type="tool", id="delete_database")),
        ],
    )
    resp = await backend.evaluate_batch(batch)
    assert [e.decision for e in resp.evaluations] == [True, False]
    await backend.aclose()


@pytest.mark.asyncio
async def test_batch_entry_overrides_defaults_in_input(make_config, noop_sleep, respx_mock) -> None:
    # AuthZEN batch semantics: an entry's own fields override the request-level defaults in
    # the OPA `input`; omitted fields fall back. Matched by subject id (gather is concurrent,
    # so capture order is not guaranteed).
    seen: list[dict] = []

    def capture(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content)["input"])
        return httpx.Response(200, json={"result": True})

    respx_mock.post(_OPA_URL).mock(side_effect=capture)
    backend = await _backend(make_config, noop_sleep)
    req = _request()
    batch = BatchEvaluationRequest(
        subject=req.subject,
        action=req.action,
        resource=req.resource,
        context={"tenant": "default"},
        evaluations=[
            EvaluationItem(),  # inherits every default
            EvaluationItem(
                subject=Subject(type="agent", id="other"), context={"tenant": "override"}
            ),
        ],
    )
    resp = await backend.evaluate_batch(batch)
    assert [e.decision for e in resp.evaluations] == [True, True]
    by_id = {doc["subject"]["id"]: doc for doc in seen}
    assert by_id["bot"]["context"] == {"tenant": "default"}  # inherited
    assert by_id["other"]["context"] == {"tenant": "override"}  # entry wins
    assert by_id["other"]["resource"]["id"] == "send_email"  # resource still inherited
    await backend.aclose()


@pytest.mark.asyncio
async def test_batch_one_error_propagates_fail_closed(make_config, noop_sleep, respx_mock) -> None:
    # A malformed response on any entry must surface (engine then resolves via on_error),
    # never silently drop to a partial allow.
    respx_mock.post(_OPA_URL).respond(json={})
    backend = await _backend(make_config, noop_sleep)
    req = _request()
    batch = BatchEvaluationRequest(
        subject=req.subject,
        action=req.action,
        evaluations=[EvaluationItem(resource=req.resource)],
    )
    with pytest.raises(MalformedPDPResponseError):
        await backend.evaluate_batch(batch)
    await backend.aclose()


# --- transport reuse (inherited hardening) ------------------------------------------


@pytest.mark.asyncio
async def test_4xx_is_client_error_not_retried(make_config, noop_sleep, respx_mock) -> None:
    route = respx_mock.post(_OPA_URL).respond(status_code=400, json={"error": "bad path"})
    backend = await _backend(make_config, noop_sleep)
    with pytest.raises(AuthZENClientError):
        await backend.evaluate(_request())
    assert route.call_count == 1  # 4xx is our bug -> no retry
    await backend.aclose()


@pytest.mark.asyncio
async def test_transport_error_is_service_error(make_config, noop_sleep, respx_mock) -> None:
    respx_mock.post(_OPA_URL).mock(side_effect=httpx.ConnectError("refused"))
    backend = await _backend(make_config, noop_sleep)
    with pytest.raises(PDPUnavailableError):
        await backend.evaluate(_request())
    await backend.aclose()


# --- engine wiring (backend selected by config) -------------------------------------


@pytest.mark.asyncio
async def test_engine_uses_opa_backend_end_to_end(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_OPA_URL).respond(json={"result": True})
    cfg = make_config(backend="opa")
    engine = AuthorizationEngine(cfg, client=build_backend(cfg, sleep=noop_sleep))
    result = await engine.evaluate_tool_calls([make_openai_call("send_email")])
    assert result.verdict is Verdict.ALLOW
    await engine.aclose()


@pytest.mark.asyncio
async def test_engine_opa_backend_unreachable_fails_closed(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    # backend="opa" routes through the same on_error handling: an unreachable OPA is a
    # service error -> BLOCK with status=ERROR (never a coerced allow).
    respx_mock.post(_OPA_URL).mock(side_effect=httpx.ConnectError("refused"))
    cfg = make_config(backend="opa")
    engine = AuthorizationEngine(cfg, client=build_backend(cfg, sleep=noop_sleep))
    result = await engine.evaluate_tool_calls([make_openai_call("send_email")])
    assert result.verdict is Verdict.BLOCK
    assert result.status is VerdictStatus.ERROR
    await engine.aclose()


def test_opa_backend_inherits_ssrf_guard(make_config) -> None:
    # The SSRF guard lives in the shared transport, so the OPA backend gets it too.
    cfg = make_config(backend="opa", pdp_url="http://169.254.169.254", allow_insecure_pdp=False)
    with pytest.raises(AuthZENConfigError):
        OPABackend(cfg)
