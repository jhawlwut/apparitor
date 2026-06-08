"""OpenID AuthZEN interop "Todo" decision-matrix conformance.

Vendors the interop Todo scenario (the Rick & Morty role matrix) from ``interop_todo_cases.json``
and drives every ``(subject, action, resource)`` tuple through the real models and
``AuthZENClient`` (PDP mocked via ``respx``, no network) to prove:

* every canonical interop request validates and serialises with the AuthZEN 1.0 spec field
  names (``subject.type``, ``action.name``, ``resource.type``/``id``, ``ownerID`` properties);
* the documented decision maps to the right verdict — single (``map_single``) and batch
  (``aggregate``, all-allow-or-block), including a non-conformant short response array that
  must fail closed (BLOCK);
* the vendored matrix stays consistent with the scenario's role rules — a self-check
  re-derives every decision from the directory roles + rules, so a mislabeled
  ``expected_decision`` fails the suite rather than passing silently.

This checks the AuthZEN *interface* against the interop payloads, not a live PDP. Provenance
and the (documented) deviations from the live interop live in README.md and the dataset.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from authzen_llamafirewall.client import AuthZENClient
from authzen_llamafirewall.decision import Verdict, aggregate, map_single
from authzen_llamafirewall.models import BatchEvaluationRequest, EvaluationRequest

pytestmark = pytest.mark.unit

_EVAL_URL = "http://pdp.test/access/v1/evaluation"
_BATCH_URL = "http://pdp.test/access/v1/evaluations"

_DATA = json.loads((Path(__file__).parent / "interop_todo_cases.json").read_text())
_DIRECTORY: dict[str, list[str]] = _DATA["directory"]


def _ids(cases: list[dict[str, Any]]) -> list[str]:
    """Name each parametrized case by its ``name`` so a failure points to the case, not case0/1."""
    return [c["name"] for c in cases]


def _owner(resource: dict[str, Any]) -> str | None:
    """Return a todo's ``ownerID`` (the ABAC attribute the ownership rules key on), if any."""
    return resource.get("properties", {}).get("ownerID")


def _decide(action: str, subject_id: str, owner: str | None) -> bool:
    """The interop Todo policy, transcribed from the scenario's role rules (``_DATA["rules"]``).

    Roles are read from the vendored directory; ``owner`` is the todo's ``ownerID``. This
    re-derives each decision independently of the hand-authored ``expected_decision``, so a
    mislabeled cell fails the suite. It reads roles from the same directory it validates, so
    it guards the decision cells against the rules, not the directory itself.
    """
    roles = set(_DIRECTORY[subject_id])
    if action in ("can_read_user", "can_read_todos"):
        return True
    if action == "can_create_todo":
        return bool(roles & {"admin", "editor"})
    if action == "can_update_todo":
        return "evil_genius" in roles or ("editor" in roles and owner == subject_id)
    if action == "can_delete_todo":
        return "admin" in roles or ("editor" in roles and owner == subject_id)
    raise AssertionError(f"unknown interop action {action!r}")


@pytest.mark.parametrize("case", _DATA["single"], ids=_ids(_DATA["single"]))
def test_single_decision_matches_documented_rules(case: dict[str, Any]) -> None:
    """Re-derivation from the rules guards against a mislabeled ``expected_decision`` cell."""
    req = case["request"]
    derived = _decide(req["action"]["name"], req["subject"]["id"], _owner(req["resource"]))
    assert derived is case["expected_decision"]
    assert map_single(derived) is Verdict(case["expected_verdict"])


@pytest.mark.parametrize("case", _DATA["single"], ids=_ids(_DATA["single"]))
@pytest.mark.asyncio
async def test_single_wire_conformance(
    case: dict[str, Any], make_config, noop_sleep, respx_mock
) -> None:
    """The interop request serialises with spec field names and maps to the right verdict."""
    request = case["request"]
    req = EvaluationRequest.model_validate(request)  # canonical interop shape is accepted

    payload = req.model_dump(mode="json", exclude_none=True)
    assert payload["subject"] == {"type": "user", "id": request["subject"]["id"], "properties": {}}
    assert payload["action"]["name"] == request["action"]["name"]
    assert payload["resource"]["type"] == request["resource"]["type"]
    assert payload["resource"]["id"] == request["resource"]["id"]
    if _owner(request["resource"]) is not None:
        assert payload["resource"]["properties"]["ownerID"] == _owner(request["resource"])

    respx_mock.post(_EVAL_URL).respond(json={"decision": case["expected_decision"]})
    client = AuthZENClient(make_config(), sleep=noop_sleep)
    parsed = await client.evaluate(req)
    assert parsed.decision is case["expected_decision"]
    assert map_single(parsed.decision) is Verdict(case["expected_verdict"])


@pytest.mark.parametrize("case", _DATA["batch"], ids=_ids(_DATA["batch"]))
def test_batch_decisions_match_documented_rules(case: dict[str, Any]) -> None:
    """Both the per-evaluation decisions and the all-allow-or-block aggregate must hold."""
    request = case["request"]
    subject_id = request["subject"]["id"]
    action = request["action"]["name"]
    derived = [_decide(action, subject_id, _owner(ev["resource"])) for ev in request["evaluations"]]
    assert derived == case["expected_decisions"]
    assert aggregate(derived, expected=len(derived)) is Verdict(case["expected_verdict"])


@pytest.mark.parametrize("case", _DATA["batch"], ids=_ids(_DATA["batch"]))
@pytest.mark.asyncio
async def test_batch_wire_conformance(
    case: dict[str, Any], make_config, noop_sleep, respx_mock
) -> None:
    """A batch request serialises (incl. evaluations_semantic) and aggregates correctly."""
    request = case["request"]
    req = BatchEvaluationRequest.model_validate(request)

    payload = req.model_dump(mode="json", exclude_none=True)
    assert len(payload["evaluations"]) == len(request["evaluations"])
    if "options" in request:  # the spec field is plural: evaluations_semantic
        semantic = request["options"]["evaluations_semantic"]
        assert payload["options"]["evaluations_semantic"] == semantic

    respx_mock.post(_BATCH_URL).respond(json=case["response"])
    client = AuthZENClient(make_config(), sleep=noop_sleep)
    parsed = await client.evaluate_batch(req)

    decisions = [item.decision for item in parsed.evaluations]
    assert decisions == case["expected_decisions"]
    # Aggregate against the number REQUESTED so a short/long PDP array is caught as a BLOCK.
    assert aggregate(decisions, expected=len(req.evaluations)) is Verdict(case["expected_verdict"])


@pytest.mark.parametrize("case", _DATA["batch_defensive"], ids=_ids(_DATA["batch_defensive"]))
@pytest.mark.asyncio
async def test_batch_short_array_fails_closed(
    case: dict[str, Any], make_config, noop_sleep, respx_mock
) -> None:
    """A short PDP response array fails closed — the plan BLOCKs, never a partial allow."""
    req = BatchEvaluationRequest.model_validate(case["request"])

    respx_mock.post(_BATCH_URL).respond(json=case["response"])
    client = AuthZENClient(make_config(), sleep=noop_sleep)
    parsed = await client.evaluate_batch(req)

    decisions = [item.decision for item in parsed.evaluations]
    assert decisions == case["expected_decisions"]
    assert len(decisions) < len(req.evaluations)  # PDP returned fewer decisions than requested
    # The plan BLOCKS even though the returned decision is ALLOW — a short array is never a
    # partial-allow (the `aggregate(expected=...)` count-mismatch guard).
    assert aggregate(decisions, expected=len(req.evaluations)) is Verdict(case["expected_verdict"])
