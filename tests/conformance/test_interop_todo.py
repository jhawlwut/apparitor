"""OpenID AuthZEN interop "Todo" decision-matrix conformance.

Vendors the interop Todo scenario (the Rick & Morty role matrix) from ``interop_todo_cases.json``
and drives every ``(subject, action, resource)`` tuple through the real models and
``AuthZENClient`` (PDP mocked via ``respx``, no network) to prove:

* every canonical interop request validates and serialises with the AuthZEN 1.0 spec field
  names (``subject.type``, ``action.name``, ``resource.type``/``id``, ``ownerID`` properties);
* the documented decision maps to the right verdict — single (``map_single``) and batch
  (``aggregate``, all-allow-or-block);
* the vendored matrix stays consistent with the scenario's role rules — a self-check
  re-derives every decision from the directory + rules, so a stray edit to the data can't
  pass silently.

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
    return [c["name"] for c in cases]


def _owner(resource: dict[str, Any]) -> str | None:
    return resource.get("properties", {}).get("ownerID")


def _decide(action: str, subject_id: str, owner: str | None) -> bool:
    """The interop Todo policy, transcribed from the scenario's role rules.

    Roles are read from the vendored directory; ``owner`` is the todo's ``ownerID``. This
    re-derives decisions independently of the wire path so the matrix can't drift from the
    documented rules (``_DATA["rules"]``).
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
    req = case["request"]
    derived = _decide(req["action"]["name"], req["subject"]["id"], _owner(req["resource"]))
    assert derived is case["expected_decision"]
    assert map_single(case["expected_decision"]) is Verdict(case["expected_verdict"])


@pytest.mark.parametrize("case", _DATA["single"], ids=_ids(_DATA["single"]))
@pytest.mark.asyncio
async def test_single_wire_conformance(
    case: dict[str, Any], make_config, noop_sleep, respx_mock
) -> None:
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
    req = BatchEvaluationRequest.model_validate(case["request"])

    respx_mock.post(_BATCH_URL).respond(json=case["response"])
    client = AuthZENClient(make_config(), sleep=noop_sleep)
    parsed = await client.evaluate_batch(req)

    decisions = [item.decision for item in parsed.evaluations]
    assert decisions == case["expected_decisions"]
    # Aggregate against the number REQUESTED so a short/long PDP array is caught as a BLOCK.
    assert aggregate(decisions, expected=len(req.evaluations)) is Verdict(case["expected_verdict"])
