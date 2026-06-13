"""Pure decision-logic tests (no I/O)."""

from __future__ import annotations

import pytest

from apparitor.config import OnError
from apparitor.decision import (
    Verdict,
    VerdictResult,
    VerdictStatus,
    aggregate,
    escalate,
    is_allowed_gateway,
    is_allowed_inline,
    map_single,
    refusal_message,
    resolve_error,
    validate_gateway_subject_config,
)
from apparitor.errors import AuthZENConfigError
from apparitor.models import Subject

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("decision", "wants_review", "expected"),
    [
        (True, False, Verdict.ALLOW),
        (False, False, Verdict.BLOCK),
        (True, True, Verdict.HUMAN_REVIEW),
        # A deny can never be downgraded by a review escalation.
        (False, True, Verdict.BLOCK),
    ],
)
def test_map_single(decision: bool, wants_review: bool, expected: Verdict) -> None:
    assert map_single(decision, wants_review=wants_review) is expected


def test_escalate_never_downgrades() -> None:
    assert escalate(Verdict.BLOCK, Verdict.HUMAN_REVIEW) is Verdict.BLOCK
    assert escalate(Verdict.ALLOW, Verdict.HUMAN_REVIEW) is Verdict.HUMAN_REVIEW
    assert escalate(Verdict.ALLOW, Verdict.BLOCK) is Verdict.BLOCK


@pytest.mark.parametrize(
    ("decisions", "expected_n", "expected"),
    [
        ([True, True], 2, Verdict.ALLOW),
        ([True, False], 2, Verdict.BLOCK),
        ([False, False], 2, Verdict.BLOCK),
        # short / missing entry blocks the whole message
        ([True], 2, Verdict.BLOCK),
        ([], 1, Verdict.BLOCK),
        # a non-conformant PDP returning MORE decisions than expected is also blocked
        ([True, True, True], 2, Verdict.BLOCK),
    ],
)
def test_aggregate(decisions: list[bool], expected_n: int, expected: Verdict) -> None:
    assert aggregate(decisions, expected=expected_n) is expected


@pytest.mark.parametrize(
    ("on_error", "expected"),
    [(OnError.DENY, Verdict.BLOCK), (OnError.HUMAN_REVIEW, Verdict.HUMAN_REVIEW)],
)
def test_resolve_error(on_error: OnError, expected: Verdict) -> None:
    result = resolve_error(on_error, "pdp down")
    assert result.verdict is expected
    assert result.status is VerdictStatus.ERROR
    assert "pdp down" in result.reason


def test_scores() -> None:
    assert VerdictResult(Verdict.ALLOW, "x").score == 0.0
    assert VerdictResult(Verdict.BLOCK, "x").score == 1.0
    assert 0.0 < VerdictResult(Verdict.HUMAN_REVIEW, "x").score < 1.0


# --- is_allowed_inline (in-runtime adapters: scanner, NeMo) -------------------------


@pytest.mark.parametrize(
    ("verdict", "status", "expected"),
    [
        # Clean ALLOW and SKIP both authorize on in-runtime adapters: SKIP means
        # "nothing to gate" (no tool calls in the message), not "mapper abstained".
        (Verdict.ALLOW, VerdictStatus.SUCCESS, True),
        (Verdict.SKIP, VerdictStatus.SKIPPED, True),
        # All blocking and error verdicts must not authorize.
        (Verdict.BLOCK, VerdictStatus.SUCCESS, False),
        (Verdict.HUMAN_REVIEW, VerdictStatus.SUCCESS, False),
        # ERROR status overrides the verdict — ALLOW/SKIP with ERROR must not authorize,
        # because the authorization check itself was compromised.
        (Verdict.ALLOW, VerdictStatus.ERROR, False),
        (Verdict.SKIP, VerdictStatus.ERROR, False),
        (Verdict.BLOCK, VerdictStatus.ERROR, False),
        (Verdict.HUMAN_REVIEW, VerdictStatus.ERROR, False),
    ],
)
def test_is_allowed_inline(verdict: Verdict, status: VerdictStatus, expected: bool) -> None:
    result = VerdictResult(verdict=verdict, reason="test", status=status)
    assert is_allowed_inline(result) is expected


# --- is_allowed_gateway (boundary adapters: FastMCP middleware, A2A executor) --------


@pytest.mark.parametrize(
    ("verdict", "status", "expected"),
    [
        # Only a clean ALLOW authorizes at a network boundary.  A SKIP at a gateway
        # means the mapper abstained on a submitted call — executing anyway is a bypass.
        (Verdict.ALLOW, VerdictStatus.SUCCESS, True),
        (Verdict.SKIP, VerdictStatus.SKIPPED, False),
        (Verdict.BLOCK, VerdictStatus.SUCCESS, False),
        (Verdict.HUMAN_REVIEW, VerdictStatus.SUCCESS, False),
        # ERROR status overrides the verdict.
        (Verdict.ALLOW, VerdictStatus.ERROR, False),
        (Verdict.SKIP, VerdictStatus.ERROR, False),
        (Verdict.BLOCK, VerdictStatus.ERROR, False),
        (Verdict.HUMAN_REVIEW, VerdictStatus.ERROR, False),
    ],
)
def test_is_allowed_gateway(verdict: Verdict, status: VerdictStatus, expected: bool) -> None:
    result = VerdictResult(verdict=verdict, reason="test", status=status)
    assert is_allowed_gateway(result) is expected


def test_inline_and_gateway_diverge_only_on_skip() -> None:
    """SKIP is the sole divergence point: inline passes it, gateway refuses it.

    This test pins the contract so a future edit cannot silently unify the two helpers
    and introduce a bypass (gateway) or an unwarranted refusal (inline).
    """
    skip_result = VerdictResult(
        verdict=Verdict.SKIP, reason="no calls", status=VerdictStatus.SKIPPED
    )
    assert is_allowed_inline(skip_result) is True  # pass-through: nothing to gate
    assert is_allowed_gateway(skip_result) is False  # refuse: mapper abstained on submitted call


# --- refusal_message (text that crosses the trust boundary to the client) ------------


@pytest.mark.parametrize(
    ("verdict", "expected"),
    [
        # Generic and fixed: never the engine's reason (it may embed PDP/config detail).
        (None, "tool call not authorized"),
        (VerdictResult(Verdict.BLOCK, "internal detail"), "tool call not authorized"),
        (VerdictResult(Verdict.BLOCK, "x", VerdictStatus.ERROR), "tool call not authorized"),
        # HUMAN_REVIEW stays distinguishable so a host can escalate instead of retrying.
        (
            VerdictResult(Verdict.HUMAN_REVIEW, "x"),
            "tool call requires human approval; do not retry",
        ),
    ],
)
def test_refusal_message(verdict: VerdictResult | None, expected: str) -> None:
    assert refusal_message("tool call", verdict) == expected


# --- validate_gateway_subject_config (gateway-adapter constructor guards) ------------


def test_workload_subject_type_is_reserved(make_config) -> None:
    with pytest.raises(AuthZENConfigError, match="reserved"):
        validate_gateway_subject_config(
            make_config(),
            subject_type="workload",
            allow_static_subject=False,
            boundary_subject=None,
        )


def test_workload_reservation_covers_static_fallback(make_config) -> None:
    with pytest.raises(AuthZENConfigError, match="reserved"):
        validate_gateway_subject_config(
            make_config(subject_type="workload"),
            subject_type="user",
            allow_static_subject=True,
            boundary_subject=None,
        )


def test_workload_boundary_subject_is_reserved(make_config) -> None:
    with pytest.raises(AuthZENConfigError, match="reserved"):
        validate_gateway_subject_config(
            make_config(),
            subject_type="user",
            allow_static_subject=False,
            boundary_subject=Subject(type="workload", id="svc-1"),
        )


def test_boundary_with_cache_enabled_warns(make_config, caplog) -> None:
    # Boundary evaluation always batches, so the ALLOW cache is dead weight — warn once.
    import logging

    with caplog.at_level(logging.WARNING, logger="apparitor"):
        validate_gateway_subject_config(
            make_config(cache_enabled=True),
            subject_type="user",
            allow_static_subject=False,
            boundary_subject=Subject(type="agent", id="svc-1"),
        )
    assert "never be consulted" in caplog.text
