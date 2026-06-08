"""AuthZEN 1.0 wire-conformance suite.

Drives the vendored canonical AuthZEN payloads (``cases.json``) through the real models
and client to prove we are wire-compatible with the spec: every request shape validates and
serialises with the spec field names, every response parses to the authoritative boolean
decision, the batch aggregation matches, and malformed responses fail closed (never a
coerced ALLOW). No policy engine is needed — this checks the AuthZEN interface, not a PDP's
decisions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from apparitor.client import AuthZENClient
from apparitor.decision import Verdict, aggregate, map_single
from apparitor.errors import MalformedPDPResponseError
from apparitor.models import (
    BatchEvaluationRequest,
    EvaluationRequest,
    EvaluationResponse,
)

pytestmark = pytest.mark.unit

_EVAL_URL = "http://pdp.test/access/v1/evaluation"
_BATCH_URL = "http://pdp.test/access/v1/evaluations"

_CASES = json.loads((Path(__file__).parent / "cases.json").read_text())


def _ids(cases: list[dict[str, Any]]) -> list[str]:
    return [c["name"] for c in cases]


@pytest.mark.parametrize("case", _CASES["single"], ids=_ids(_CASES["single"]))
@pytest.mark.asyncio
async def test_single_evaluation_conformance(
    case: dict[str, Any], make_config, noop_sleep, respx_mock
) -> None:
    request = case["request"]
    req = EvaluationRequest.model_validate(request)  # canonical shape is accepted
    assert req.subject.id == request["subject"]["id"]
    assert req.action.name == request["action"]["name"]
    assert req.resource.id == request["resource"]["id"]

    response = EvaluationResponse.model_validate(case["response"])
    assert response.decision is case["expected_decision"]

    # Full wire path: the client posts our request and parses the canonical response.
    respx_mock.post(_EVAL_URL).respond(json=case["response"])
    client = AuthZENClient(make_config(), sleep=noop_sleep)
    parsed = await client.evaluate(req)
    assert parsed.decision is case["expected_decision"]
    assert map_single(parsed.decision) is Verdict(case["expected_verdict"])


@pytest.mark.parametrize("case", _CASES["batch"], ids=_ids(_CASES["batch"]))
@pytest.mark.asyncio
async def test_batch_evaluation_conformance(
    case: dict[str, Any], make_config, noop_sleep, respx_mock
) -> None:
    req = BatchEvaluationRequest.model_validate(case["request"])

    respx_mock.post(_BATCH_URL).respond(json=case["response"])
    client = AuthZENClient(make_config(), sleep=noop_sleep)
    parsed = await client.evaluate_batch(req)

    decisions = [item.decision for item in parsed.evaluations]
    assert decisions == case["expected_decisions"]
    # Aggregate against the number of evaluations we REQUESTED (mirrors the engine), so a
    # PDP returning a short/long array is caught as a BLOCK rather than silently passing.
    assert aggregate(decisions, expected=len(req.evaluations)) is Verdict(case["expected_verdict"])


def test_batch_options_serialises_with_the_spec_field_name() -> None:
    # Regression guard: AuthZEN 1.0 uses `evaluations_semantic` (plural), not the singular.
    req = BatchEvaluationRequest.model_validate(_CASES["batch"][0]["request"])
    payload = req.model_dump(mode="json", exclude_none=True)
    assert payload["options"] == {"evaluations_semantic": "execute_all"}


@pytest.mark.parametrize("case", _CASES["invalid_responses"], ids=_ids(_CASES["invalid_responses"]))
@pytest.mark.asyncio
async def test_malformed_response_fails_closed(
    case: dict[str, Any], make_config, noop_sleep, respx_mock
) -> None:
    # A missing or non-bool `decision` is a malformed response, never a coerced ALLOW.
    with pytest.raises(ValidationError):
        EvaluationResponse.model_validate(case["response"])

    respx_mock.post(_EVAL_URL).respond(json=case["response"])
    client = AuthZENClient(make_config(), sleep=noop_sleep)
    req = EvaluationRequest.model_validate(_CASES["single"][0]["request"])
    with pytest.raises(MalformedPDPResponseError):
        await client.evaluate(req)


@pytest.mark.parametrize(
    "case", _CASES["invalid_batch_responses"], ids=_ids(_CASES["invalid_batch_responses"])
)
@pytest.mark.asyncio
async def test_malformed_batch_response_fails_closed(
    case: dict[str, Any], make_config, noop_sleep, respx_mock
) -> None:
    # A malformed nested decision in a batch response is malformed, never a coerced ALLOW.
    respx_mock.post(_BATCH_URL).respond(json=case["response"])
    client = AuthZENClient(make_config(), sleep=noop_sleep)
    req = BatchEvaluationRequest.model_validate(_CASES["batch"][0]["request"])
    with pytest.raises(MalformedPDPResponseError):
        await client.evaluate_batch(req)
