"""The authorization engine — LlamaFirewall-free orchestration of the scan pipeline.

This holds all the logic (extract → map → evaluate → decide), operating only on plain
``list[dict]`` tool calls and producing an internal :class:`VerdictResult`. Keeping it
free of LlamaFirewall makes the entire pipeline unit-testable with ``respx`` and no ML
stack; :class:`~authzen_llamafirewall.scanner.AuthZENScanner` is a thin adapter that
converts the verdict into a LlamaFirewall ``ScanResult`` at the boundary.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from .adapters import NormalizedToolCall, detect_adapter
from .cache import DecisionCache, decision_cache_key
from .client import AuthZENClient
from .decision import (
    Verdict,
    VerdictResult,
    VerdictStatus,
    aggregate,
    escalate,
    map_single,
    resolve_error,
)
from .errors import AuthZENClientError, AuthZENConfigError, AuthZENServiceError
from .mapping import DefaultToolCallMapper
from .metrics import InMemoryMetrics, MetricsSink
from .models import BatchEvaluationRequest, EvaluationItem, EvaluationsOptions

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .config import ScannerConfig
    from .mapping import ToolCallMapper
    from .models import EvaluationRequest

#: Predicate over a PDP response ``context`` that may escalate (never downgrade) a verdict.
ReviewPredicate = Callable[[dict[str, Any]], bool]

_ALLOW_REASON = "authorized by policy"
_DENY_REASON = "blocked by authorization policy"
_SKIP_REASON = "no tool call to authorize"

logger = logging.getLogger("authzen_llamafirewall")


class AuthorizationEngine:
    """Coordinates adapters, mapper, client and cache to produce a verdict."""

    def __init__(
        self,
        config: ScannerConfig,
        *,
        client: AuthZENClient | None = None,
        mapper: ToolCallMapper | None = None,
        review_predicate: ReviewPredicate | None = None,
        metrics: MetricsSink | None = None,
    ) -> None:
        self._config = config
        self._client = client or AuthZENClient(config)
        self._mapper = mapper or DefaultToolCallMapper(config)
        self._review = review_predicate
        #: Decision-latency histogram + cache-hit counter. Defaults to an in-memory sink;
        #: pass ``NoopMetrics()`` to disable or your own sink to forward elsewhere.
        self.metrics: MetricsSink = metrics or InMemoryMetrics()
        self._cache = (
            DecisionCache(ttl_s=config.cache_ttl_s, max_ttl_s=config.cache_max_ttl_s)
            if config.cache_enabled
            else None
        )

    async def evaluate_tool_calls(
        self,
        tool_calls: list[dict[str, Any]] | None,
        request_context: Mapping[str, Any] | None = None,
    ) -> VerdictResult:
        """Authorize every tool call in ``tool_calls`` and return a single verdict."""
        if not tool_calls:  # nothing to authorize — no decision to time or count
            return VerdictResult(Verdict.SKIP, _SKIP_REASON, VerdictStatus.SKIPPED)

        started = time.perf_counter()
        result, requests = await self._decide(tool_calls, request_context or {})
        latency_s = time.perf_counter() - started
        self._emit(result, requests, latency_s)
        return result

    def _emit(
        self, result: VerdictResult, requests: list[EvaluationRequest], latency_s: float
    ) -> None:
        """Record metrics and the structured decision log.

        Isolated behind a catch-all so a faulty/blocking custom :class:`MetricsSink` (or a
        logging failure) can never break or alter a decision — observability is best-effort,
        the verdict is not.
        """
        try:
            self.metrics.record_decision(
                verdict=result.verdict.value, status=result.status.value, latency_s=latency_s
            )
            if requests:
                self._log(result, requests, latency_s)
        except Exception:
            logger.exception("authzen: metrics/log emission failed (verdict unaffected)")

    async def _decide(
        self, tool_calls: list[dict[str, Any]], ctx: Mapping[str, Any]
    ) -> tuple[VerdictResult, list[EvaluationRequest]]:
        try:
            requests = self._build_requests(tool_calls, ctx)
        except _UnparseableToolCall as exc:
            return VerdictResult(Verdict.BLOCK, str(exc), VerdictStatus.ERROR), []
        except AuthZENConfigError as exc:
            # Our misconfiguration (e.g. no subject) — fail closed, loudly.
            return VerdictResult(Verdict.BLOCK, str(exc), VerdictStatus.ERROR), []

        if not requests:  # every mapper abstained
            return VerdictResult(Verdict.SKIP, _SKIP_REASON, VerdictStatus.SKIPPED), []

        try:
            return await self._evaluate(requests), requests
        except AuthZENClientError as exc:
            verdict = VerdictResult(Verdict.BLOCK, f"{_DENY_REASON} ({exc})", VerdictStatus.ERROR)
        except AuthZENServiceError as exc:
            verdict = resolve_error(self._config.on_error, f"PDP unavailable: {exc}")
            logger.warning("authzen: PDP error, resolved as %s", verdict.verdict.value)
        except Exception:
            # Defense in depth: any unexpected internal error fails closed, never ALLOW.
            logger.exception("authzen: unexpected internal error during evaluation")
            verdict = VerdictResult(
                Verdict.BLOCK, f"{_DENY_REASON} (internal error)", VerdictStatus.ERROR
            )
        return verdict, requests

    def _build_requests(
        self, tool_calls: list[dict[str, Any]], ctx: Mapping[str, Any]
    ) -> list[EvaluationRequest]:
        requests: list[EvaluationRequest] = []
        for raw in tool_calls:
            normalized = _normalize(raw)
            mapped = self._mapper.map(normalized, ctx)
            if mapped is not None:
                requests.append(mapped)
        return requests

    async def _evaluate(self, requests: list[EvaluationRequest]) -> VerdictResult:
        if len(requests) == 1:
            return await self._evaluate_single(requests[0])
        return await self._evaluate_batch(requests)

    async def _evaluate_single(self, request: EvaluationRequest) -> VerdictResult:
        key = decision_cache_key(request) if self._cache is not None else None
        if self._cache is not None and key is not None:
            hit = self._cache.get(key)
            self.metrics.record_cache(hit=bool(hit))
            if hit:
                return VerdictResult(Verdict.ALLOW, f"{_ALLOW_REASON} (cached)")

        response = await self._client.evaluate(request)
        wants_review = self._wants_review(response.context)
        verdict = map_single(response.decision, wants_review=wants_review)

        if verdict is Verdict.ALLOW and self._cache is not None and key is not None:
            self._cache.set_allow(key)  # reuse the digest computed above (hot path)
        return VerdictResult(verdict, _reason_for(verdict))

    async def _evaluate_batch(self, requests: list[EvaluationRequest]) -> VerdictResult:
        batch = BatchEvaluationRequest(
            evaluations=[
                EvaluationItem(
                    subject=r.subject, action=r.action, resource=r.resource, context=r.context
                )
                for r in requests
            ],
            # Our model authorizes EVERY tool call, so we always need every decision:
            # execute_all. The short-circuit semantics don't fit "all calls must pass".
            options=EvaluationsOptions(),
        )
        response = await self._client.evaluate_batch(batch)
        decisions = [item.decision for item in response.evaluations]
        verdict = aggregate(decisions, expected=len(requests))
        # Apply the review predicate per item and escalate the aggregate (escalation can
        # never downgrade a BLOCK), so HUMAN_REVIEW is reachable on multi-call messages too.
        if any(self._wants_review(item.context) for item in response.evaluations):
            verdict = escalate(verdict, Verdict.HUMAN_REVIEW)
        return VerdictResult(verdict, _reason_for(verdict))

    def _wants_review(self, context: dict[str, Any] | None) -> bool:
        return bool(self._review and context is not None and self._review(context))

    def _log(
        self, result: VerdictResult, requests: list[EvaluationRequest], latency_s: float
    ) -> None:
        """Structured decision log: ids + an argument *fingerprint*, never raw args/PII."""
        first = requests[0]
        correlation = (first.context or {}).get("correlation_id")
        logger.info(
            "authzen decision verdict=%s status=%s subject=%s correlation=%s "
            "tools=%s fingerprints=%s latency_ms=%.1f",
            result.verdict.value,
            result.status.value,
            first.subject.id,
            correlation,
            [r.resource.id for r in requests],
            [_fingerprint(r) for r in requests],
            latency_s * 1000,
        )

    async def aclose(self) -> None:
        await self._client.aclose()


class _UnparseableToolCall(Exception):
    """Raised internally when a tool call cannot be normalised (→ fail closed)."""


def _normalize(raw: dict[str, Any]) -> NormalizedToolCall:
    adapter = detect_adapter(raw)
    if adapter is None:
        raise _UnparseableToolCall("unrecognised tool-call shape; refusing (fail closed)")
    try:
        return adapter.normalize(raw)
    except ValueError as exc:
        raise _UnparseableToolCall(f"malformed tool call: {exc}") from exc


def _fingerprint(request: EvaluationRequest) -> str:
    """Short, stable digest over the full request tuple — identifies a call without logging
    its (possibly sensitive) arguments. Recomputes the cache-key digest (same
    canonicalisation); cheap and only on the INFO log path."""
    return decision_cache_key(request)[:12]


def _reason_for(verdict: Verdict) -> str:
    if verdict is Verdict.ALLOW:
        return _ALLOW_REASON
    if verdict is Verdict.HUMAN_REVIEW:
        return "authorization requires human review"
    return _DENY_REASON
