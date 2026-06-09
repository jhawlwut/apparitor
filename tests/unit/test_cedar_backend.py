"""Native Cedar backend tests — in-process evaluation via cedarpy (no network).

Requires the optional ``cedarpy`` dependency; skipped automatically when it is not installed
(a dedicated CI job installs ``[cedar]`` to run these). Uses the vendored Cedar policy +
entities from ``examples/cedar`` so the test exercises the real engine end to end.
"""

from __future__ import annotations

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
