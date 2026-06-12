"""Native Cedar backend tests — in-process evaluation via cedarpy (no network).

Requires the optional ``cedarpy`` dependency; skipped automatically when it is not installed
(a dedicated CI job installs ``[cedar]`` to run these). Uses the vendored Cedar policy +
entities from ``examples/cedar`` so the test exercises the real engine end to end.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

pytestmark = pytest.mark.unit

pytest.importorskip("cedarpy")

from apparitor import AuthorizationEngine, ScannerConfig, Verdict  # noqa: E402
from apparitor.backends import DecisionBackend, build_backend  # noqa: E402
from apparitor.cedar import CedarBackend  # noqa: E402
from apparitor.config import Backend  # noqa: E402
from apparitor.decision import VerdictStatus  # noqa: E402
from apparitor.errors import AuthZENConfigError, MalformedPDPResponseError  # noqa: E402
from apparitor.models import (  # noqa: E402
    Action,
    BatchEvaluationRequest,
    EvaluationItem,
    EvaluationRequest,
    Resource,
    Subject,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_EXAMPLE = Path(__file__).parents[2] / "examples" / "cedar"

# A Cedar schema (JSON form) matching the vendored Agent/Action/Tool entities. Used to exercise
# the optional cedar_schema_path branch: with it set, policies are validated against the schema
# at construction and the schema is passed to every evaluation.
_VALID_SCHEMA = {
    "": {
        "entityTypes": {
            "Agent": {"shape": {"type": "Record", "attributes": {}}},
            "Tool": {
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "sensitivity": {"type": "String"},
                        "destructive": {"type": "Boolean"},
                    },
                }
            },
        },
        "actions": {
            "tool_call.execute": {
                "appliesTo": {"principalTypes": ["Agent"], "resourceTypes": ["Tool"]}
            }
        },
    }
}


def _config(**overrides: object) -> ScannerConfig:
    params: dict[str, object] = {
        "backend": "cedar",
        "agent_id": "demo-agent",
        "cedar_policies_path": str(_EXAMPLE / "policies.cedar"),
        "cedar_entities_path": str(_EXAMPLE / "entities.json"),
    }
    params.update(overrides)
    return ScannerConfig(**params)


def _request(tool: str, subject: str = "demo-agent") -> EvaluationRequest:
    return EvaluationRequest(
        subject=Subject(type="agent", id=subject),
        action=Action(name="tool_call.execute"),
        resource=Resource(type="tool", id=tool),
    )


# --- backend selection / config -----------------------------------------------------


def test_build_backend_selects_cedar() -> None:
    backend = build_backend(_config())
    assert isinstance(backend, CedarBackend)
    assert isinstance(backend, DecisionBackend)


def test_backend_coerced_from_string() -> None:
    assert _config().backend is Backend.CEDAR


def test_missing_policy_paths_fail_closed() -> None:
    with pytest.raises(AuthZENConfigError, match="cedar_policies_path"):
        CedarBackend(ScannerConfig(backend="cedar", agent_id="demo-agent"))


def test_unreadable_policy_path_fails_closed() -> None:
    with pytest.raises(AuthZENConfigError, match="cannot load"):
        CedarBackend(_config(cedar_policies_path="/nonexistent/policies.cedar"))


def test_malformed_policy_rejected_at_construction(tmp_path: Path) -> None:
    # A policy typo parses fine as text but makes Cedar return NoDecision at runtime (a silent
    # total deny). It must instead fail loudly at construction, never at request time.
    bad = tmp_path / "broken.cedar"
    bad.write_text("permit (this is not valid cedar", encoding="utf-8")
    with pytest.raises(AuthZENConfigError, match="invalid Cedar policy set"):
        CedarBackend(_config(cedar_policies_path=str(bad)))


def test_non_validating_schema_rejected_at_construction(tmp_path: Path) -> None:
    # A schema that does not validate the policy set is a config error, caught at construction.
    schema = tmp_path / "schema.json"
    schema.write_text(json.dumps({"": {"entityTypes": "nonsense"}}), encoding="utf-8")
    with pytest.raises(AuthZENConfigError, match="validation failed"):
        CedarBackend(_config(cedar_schema_path=str(schema)))


# --- optional schema ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_schema_path_validates_and_evaluates(tmp_path: Path) -> None:
    # With a valid schema, policies are validated against it at construction and the schema is
    # threaded through evaluation; decisions are unchanged from the schema-less path.
    schema = tmp_path / "schema.json"
    schema.write_text(json.dumps(_VALID_SCHEMA), encoding="utf-8")
    backend = CedarBackend(_config(cedar_schema_path=str(schema)))
    try:
        assert (await backend.evaluate(_request("send_email"))).decision is True
        assert (await backend.evaluate(_request("delete_database"))).decision is False
    finally:
        await backend.aclose()


# --- single evaluation --------------------------------------------------------------


@pytest.mark.asyncio
async def test_permit_low_sensitivity_tool() -> None:
    backend = CedarBackend(_config())
    try:
        assert (await backend.evaluate(_request("send_email"))).decision is True
    finally:
        await backend.aclose()


@pytest.mark.asyncio
async def test_deny_destructive_tool() -> None:
    backend = CedarBackend(_config())
    try:
        assert (await backend.evaluate(_request("delete_database"))).decision is False
    finally:
        await backend.aclose()


@pytest.mark.asyncio
async def test_unknown_tool_denies() -> None:
    # No entity / no matching permit -> Cedar's default deny.
    backend = CedarBackend(_config())
    try:
        assert (await backend.evaluate(_request("nope"))).decision is False
    finally:
        await backend.aclose()


@pytest.mark.asyncio
async def test_wrong_subject_denies() -> None:
    backend = CedarBackend(_config())
    try:
        assert (
            await backend.evaluate(_request("send_email", subject="intruder"))
        ).decision is False
    finally:
        await backend.aclose()


@pytest.mark.asyncio
async def test_quote_in_id_fails_closed() -> None:
    # A double-quote would produce a malformed Cedar UID; reject -> deny (never an allow).
    backend = CedarBackend(_config())
    try:
        with pytest.raises(MalformedPDPResponseError):
            await backend.evaluate(_request('send"_email'))
    finally:
        await backend.aclose()


@pytest.mark.asyncio
async def test_backslash_in_id_fails_closed() -> None:
    # A backslash inside a Cedar string literal produces a malformed UID; reject -> deny.
    backend = CedarBackend(_config())
    try:
        with pytest.raises(MalformedPDPResponseError):
            await backend.evaluate(_request("send\\_email"))
    finally:
        await backend.aclose()


@pytest.mark.asyncio
async def test_control_char_in_id_fails_closed() -> None:
    # A control char (U+0000-U+001F) would embed an invisible byte in the Cedar literal;
    # reject -> deny rather than pass a malformed UID to the engine.
    backend = CedarBackend(_config())
    try:
        with pytest.raises(MalformedPDPResponseError):
            await backend.evaluate(_request("send\x01email"))
        with pytest.raises(MalformedPDPResponseError):
            await backend.evaluate(_request("send\x1femail"))
    finally:
        await backend.aclose()


# --- _entity_uid unit tests (no backend construction needed) -----------------------


def test_entity_uid_rejects_double_quote() -> None:
    from apparitor.cedar import _entity_uid

    with pytest.raises(ValueError, match="disallowed"):
        _entity_uid("tool", 'foo"bar')


def test_entity_uid_rejects_backslash() -> None:
    from apparitor.cedar import _entity_uid

    with pytest.raises(ValueError, match="disallowed"):
        _entity_uid("tool", "foo\\bar")


def test_entity_uid_rejects_control_chars() -> None:
    from apparitor.cedar import _entity_uid

    for c in ("\x00", "\x1f", "\n", "\r", "\t"):
        with pytest.raises(ValueError, match="disallowed"):
            _entity_uid("tool", f"foo{c}bar")


def test_entity_uid_accepts_normal_identifier() -> None:
    from apparitor.cedar import _entity_uid

    uid = _entity_uid("tool", "send_email")
    assert uid == 'Tool::"send_email"'


# --- batch --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_preserves_order_and_decisions() -> None:
    backend = CedarBackend(_config())
    req = _request("send_email")
    batch = BatchEvaluationRequest(
        subject=req.subject,
        action=req.action,
        evaluations=[
            EvaluationItem(resource=Resource(type="tool", id="send_email")),
            EvaluationItem(resource=Resource(type="tool", id="delete_database")),
            EvaluationItem(resource=Resource(type="tool", id="read_file")),
        ],
    )
    try:
        resp = await backend.evaluate_batch(batch)
    finally:
        await backend.aclose()
    assert [e.decision for e in resp.evaluations] == [True, False, True]


@pytest.mark.asyncio
async def test_batch_entry_overrides_default_subject() -> None:
    # AuthZEN batch semantics: an entry's own field overrides the request-level default. Here a
    # default subject that permits send_email is overridden per-entry by a subject that does not,
    # so the two entries decide differently from the same resource.
    backend = CedarBackend(_config())
    batch = BatchEvaluationRequest(
        subject=Subject(type="agent", id="demo-agent"),
        action=Action(name="tool_call.execute"),
        resource=Resource(type="tool", id="send_email"),
        evaluations=[
            EvaluationItem(),  # inherits the permitted default subject
            EvaluationItem(subject=Subject(type="agent", id="intruder")),  # overrides -> deny
        ],
    )
    try:
        resp = await backend.evaluate_batch(batch)
    finally:
        await backend.aclose()
    assert [e.decision for e in resp.evaluations] == [True, False]


# --- engine wiring ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_engine_end_to_end(make_openai_call: Callable[..., dict[str, object]]) -> None:
    engine = AuthorizationEngine(_config())
    try:
        allowed = await engine.evaluate_tool_calls([make_openai_call("send_email")])
        blocked = await engine.evaluate_tool_calls([make_openai_call("delete_database")])
        batch_mixed = await engine.evaluate_tool_calls(
            [make_openai_call("send_email"), make_openai_call("delete_database")]
        )
    finally:
        await engine.aclose()
    assert allowed.verdict is Verdict.ALLOW
    assert allowed.status is VerdictStatus.SUCCESS
    assert blocked.verdict is Verdict.BLOCK
    assert batch_mixed.verdict is Verdict.BLOCK
