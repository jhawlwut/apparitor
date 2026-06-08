"""Model validation tests — the AuthZEN wire shapes and the StrictBool decision invariant."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from apparitor.models import (
    Action,
    BatchEvaluationRequest,
    EvaluationItem,
    EvaluationRequest,
    EvaluationResponse,
    Resource,
    Subject,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("bad", [1, 0, "true", "false", "yes", None])
def test_decision_must_be_strict_bool(bad: object) -> None:
    # Security invariant: a non-bool decision is malformed, never a coerced truthy ALLOW.
    with pytest.raises(ValidationError):
        EvaluationResponse.model_validate({"decision": bad})


@pytest.mark.parametrize("good", [True, False])
def test_decision_accepts_real_bools(good: bool) -> None:
    assert EvaluationResponse.model_validate({"decision": good}).decision is good


def test_request_excludes_none_context() -> None:
    req = EvaluationRequest(
        subject=Subject(type="agent", id="b"),
        action=Action(name="tool_call.execute"),
        resource=Resource(type="tool", id="x"),
    )
    assert "context" not in req.model_dump(exclude_none=True)


def test_request_models_forbid_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Subject.model_validate({"type": "agent", "id": "b", "bogus": 1})


def test_response_ignores_unknown_fields() -> None:
    resp = EvaluationResponse.model_validate({"decision": True, "surprise": 1, "context": {}})
    assert resp.decision is True


def test_batch_request_roundtrips() -> None:
    batch = BatchEvaluationRequest(
        evaluations=[
            EvaluationItem(
                subject=Subject(type="agent", id="b"),
                action=Action(name="a"),
                resource=Resource(type="tool", id="x"),
            )
        ]
    )
    dumped = batch.model_dump(mode="json", exclude_none=True)
    assert dumped["evaluations"][0]["resource"]["id"] == "x"
