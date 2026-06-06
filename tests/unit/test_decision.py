"""Pure decision-logic tests (no I/O)."""

from __future__ import annotations

import pytest

from authzen_llamafirewall.config import OnError
from authzen_llamafirewall.decision import (
    Verdict,
    VerdictStatus,
    aggregate,
    escalate,
    map_single,
    resolve_error,
)

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
    from authzen_llamafirewall.decision import VerdictResult

    assert VerdictResult(Verdict.ALLOW, "x").score == 0.0
    assert VerdictResult(Verdict.BLOCK, "x").score == 1.0
    assert 0.0 < VerdictResult(Verdict.HUMAN_REVIEW, "x").score < 1.0
