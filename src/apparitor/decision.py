"""Pure, LlamaFirewall-free decision logic.

Defines the internal verdict vocabulary and the functions that turn AuthZEN responses
(and error conditions) into a verdict. Keeping this free of LlamaFirewall means the whole
decision/aggregation/error surface is unit-testable without the ML stack; the scanner maps
:class:`VerdictResult` onto LlamaFirewall's ``ScanResult`` at the boundary.

Also hosts the shared adapter helpers that all four adapters import:
:func:`is_allowed_inline` / :func:`is_allowed_gateway` (SKIP semantics differ between
in-runtime firewall and gateway adapters), :func:`refusal_message`,
:func:`record_pre_engine_refusal`, :func:`validate_gateway_subject_config`,
:data:`WORKLOAD_RESERVED_MSG`, and
:data:`DUAL_PRINCIPAL_CACHE_WARNING`. They live here — rather than in ``engine`` — because
this is the lowest-common import that is both engine-free and host-SDK-free; placing them
higher would create circular imports between the adapter modules and the engine.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from .config import OnError
from .errors import AuthZENConfigError

if TYPE_CHECKING:
    from .config import ScannerConfig
    from .metrics import MetricsSink
    from .models import Subject

_log = logging.getLogger("apparitor")


class Verdict(str, Enum):
    """Internal authorization outcome (maps to ``ScanDecision`` at the boundary)."""

    ALLOW = "allow"
    HUMAN_REVIEW = "human_review"
    BLOCK = "block"
    SKIP = "skip"


class VerdictStatus(str, Enum):
    """Whether the verdict came from a clean evaluation or an error/skip path."""

    SUCCESS = "success"
    ERROR = "error"
    SKIPPED = "skipped"


# Severity lattice: a higher value may never be downgraded by an escalation.
# SKIP < ALLOW < HUMAN_REVIEW < BLOCK
_SEVERITY: dict[Verdict, int] = {
    Verdict.SKIP: -1,
    Verdict.ALLOW: 0,
    Verdict.HUMAN_REVIEW: 1,
    Verdict.BLOCK: 2,
}

_SCORE: dict[Verdict, float] = {
    Verdict.SKIP: 0.0,
    Verdict.ALLOW: 0.0,
    Verdict.HUMAN_REVIEW: 0.5,
    Verdict.BLOCK: 1.0,
}


@dataclass(frozen=True)
class VerdictResult:
    """A verdict plus the human-readable reason, score, and status."""

    verdict: Verdict
    reason: str
    status: VerdictStatus = VerdictStatus.SUCCESS

    @property
    def score(self) -> float:
        return _SCORE[self.verdict]


def escalate(base: Verdict, target: Verdict) -> Verdict:
    """Return the more severe of two verdicts (escalation can never downgrade)."""
    return base if _SEVERITY[base] >= _SEVERITY[target] else target


def map_single(base_decision: bool, *, wants_review: bool = False) -> Verdict:
    """Map an AuthZEN boolean decision to a verdict (``True``→ALLOW, ``False``→BLOCK)."""
    base = Verdict.ALLOW if base_decision else Verdict.BLOCK
    return escalate(base, Verdict.HUMAN_REVIEW) if wants_review else base


def aggregate(decisions: list[bool], *, expected: int) -> Verdict:
    """Aggregate a batch: ALLOW iff every expected entry is allowed, else BLOCK.

    Any count mismatch (``len(decisions) != expected``) or any ``False`` blocks the whole
    message — a benign call smuggled beside a denied one, or a non-conformant PDP returning
    a short/long array, must not pass.
    """
    if len(decisions) != expected or not all(decisions):
        return Verdict.BLOCK
    return Verdict.ALLOW


def resolve_error(on_error: OnError, reason: str) -> VerdictResult:
    """Resolve a PDP error per policy. There is no fail-open: deny or human review only."""
    verdict = Verdict.BLOCK if on_error is OnError.DENY else Verdict.HUMAN_REVIEW
    return VerdictResult(verdict=verdict, reason=reason, status=VerdictStatus.ERROR)


def is_allowed_inline(verdict: VerdictResult) -> bool:
    """Return True when the verdict authorizes execution on an in-runtime adapter.

    ALLOW and SKIP both pass here because SKIP means "the message contained no tool
    calls to authorize" — there is nothing to gate, so pass-through is correct.  This
    is the right predicate for the LlamaFirewall scanner and the NeMo rail, where the
    engine's SKIP path is reached only when ``tool_calls`` is None or empty.

    Do NOT use this at a network boundary (see :func:`is_allowed_gateway`): a SKIP at
    that layer would mean the mapper abstained on an actually-submitted call, and
    executing anyway would be an authorization bypass.
    """
    return verdict.status is not VerdictStatus.ERROR and verdict.verdict in (
        Verdict.ALLOW,
        Verdict.SKIP,
    )


def is_allowed_gateway(verdict: VerdictResult) -> bool:
    """Return True only when the verdict is a clean ALLOW — for boundary/network adapters.

    At a network boundary (FastMCP middleware, A2A executor) exactly one request is
    always submitted, so a SKIP verdict can only mean the mapper abstained on the
    submitted call.  Executing on a SKIP would silently bypass authorization.  Only
    ALLOW — with status SUCCESS, not ERROR — reaches the downstream handler.

    For in-runtime adapters where SKIP legitimately means "nothing to authorize", use
    :func:`is_allowed_inline` instead.
    """
    return verdict.status is not VerdictStatus.ERROR and verdict.verdict is Verdict.ALLOW


def refusal_message(noun: str, verdict: VerdictResult | None) -> str:
    """Generic, per-surface refusal text for the network-boundary adapters.

    This text crosses the trust boundary to the client/calling agent verbatim, so it is
    fixed and generic — never the engine's reason, which may embed PDP/config detail
    (requirements §3.10). HUMAN_REVIEW stays distinguishable so a host can escalate.
    """
    if verdict is not None and verdict.verdict is Verdict.HUMAN_REVIEW:
        return f"{noun} requires human approval; do not retry"
    return f"{noun} not authorized"


#: Warning emitted once at construction when dual-principal evaluation is combined with the
#: ALLOW cache; shared by both emission sites (:func:`validate_gateway_subject_config`
#: below, for the gateway adapters' ``boundary_subject``, and ``mapping``'s
#: ``DualPrincipalMapper``) so the text is pinned in one place and the test-suite can
#: assert the exact string.
DUAL_PRINCIPAL_CACHE_WARNING = (
    "apparitor: dual-principal evaluation always batches, so the ALLOW cache"
    " (cache_enabled=True) will never be consulted"
)

#: Error message for the workload namespace guard (shared by the gateway adapters and
#: ``DualPrincipalMapper``). The "workload" type is reserved for verified
#: client-credentials tokens (FastMCP) — minting claim-derived, static, or boundary
#: principals in that namespace would alias machine policies on a shared PDP.
WORKLOAD_RESERVED_MSG = 'subject type "workload" is reserved for verified client-credentials tokens'


def validate_gateway_subject_config(
    config: ScannerConfig,
    *,
    subject_type: str,
    allow_static_subject: bool,
    boundary_subject: Subject | None,
) -> None:
    """Shared constructor guards for the network-boundary adapters (FastMCP, A2A).

    Enforces the ``workload`` namespace reservation (see :data:`WORKLOAD_RESERVED_MSG`)
    across the claim-derived, static-fallback, and boundary principals, and warns once
    when a boundary subject is combined with the ALLOW cache (boundary evaluation always
    batches, so the cache is never consulted).
    """
    if subject_type == "workload" or (allow_static_subject and config.subject_type == "workload"):
        raise AuthZENConfigError(WORKLOAD_RESERVED_MSG)
    if boundary_subject is not None:
        if boundary_subject.type == "workload":
            raise AuthZENConfigError(WORKLOAD_RESERVED_MSG)
        if config.cache_enabled:
            _log.warning(DUAL_PRINCIPAL_CACHE_WARNING)


def record_pre_engine_refusal(metrics: MetricsSink) -> None:
    """Count a pre-engine refusal (no subject / adapter fault) as a BLOCK+ERROR metric.

    Best-effort and isolated: a faulty sink must never convert a refusal into an
    execution, so the exception is swallowed after logging.
    """
    try:
        metrics.record_decision(verdict="block", status="error", latency_s=0.0)
    except Exception:
        _log.exception("apparitor: refusal metric emission failed (verdict unaffected)")
