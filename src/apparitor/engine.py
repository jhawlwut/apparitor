"""The authorization engine — LlamaFirewall-free orchestration of the scan pipeline.

This holds all the logic (extract → map → evaluate → decide), operating only on plain
``list[dict]`` tool calls and producing an internal :class:`VerdictResult`. Keeping it
free of LlamaFirewall makes the entire pipeline unit-testable with ``respx`` and no ML
stack; :class:`~apparitor.scanner.AuthZENScanner` is a thin adapter that
converts the verdict into a LlamaFirewall ``ScanResult`` at the boundary.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from .adapters import NormalizedToolCall, detect_adapter
from .backends import build_backend
from .cache import DecisionCache, decision_cache_key
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
from .models import (
    BatchEvaluationRequest,
    EvaluationItem,
    EvaluationRequest,
    EvaluationsOptions,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    import httpx

    from .backends import DecisionBackend
    from .config import ScannerConfig
    from .mapping import ToolCallMapper
    from .metrics import MetricsSink

#: Predicate over a PDP response ``context`` that may escalate (never downgrade) a verdict.
ReviewPredicate = Callable[[dict[str, Any]], bool]

_ALLOW_REASON = "authorized by policy"
_DENY_REASON = "blocked by authorization policy"
_SKIP_REASON = "no tool call to authorize"

logger = logging.getLogger("apparitor")


class AuthorizationEngine:
    """Coordinates adapters, mapper, client and cache to produce a verdict."""

    def __init__(
        self,
        config: ScannerConfig,
        *,
        client: DecisionBackend | None = None,
        mapper: ToolCallMapper | None = None,
        review_predicate: ReviewPredicate | None = None,
        metrics: MetricsSink | None = None,
    ) -> None:
        self._config = config
        self._client = client or build_backend(config)
        self._mapper = mapper or DefaultToolCallMapper(config)
        self._review = review_predicate
        #: Decision-latency histogram + cache-hit counter. Defaults to an in-memory sink;
        #: pass ``NoopMetrics()`` to disable or your own sink to forward elsewhere.
        self.metrics: MetricsSink = metrics if metrics is not None else InMemoryMetrics()
        self._cache = (
            DecisionCache(
                ttl_s=config.cache_ttl_s,
                max_ttl_s=config.cache_max_ttl_s,
                max_entries=config.cache_max_entries,
            )
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
        try:
            normalized = [_normalize(raw) for raw in tool_calls]
        except _UnparseableToolCall as exc:
            logger.warning("apparitor: unparseable tool call, blocking (%s)", exc)
            result = VerdictResult(Verdict.BLOCK, _DENY_REASON, VerdictStatus.ERROR)
            self._emit(result, [], 0.0)  # fail closed, still counted in metrics
            return result
        return await self.evaluate_normalized(normalized, request_context)

    async def evaluate_normalized(
        self,
        calls: list[NormalizedToolCall] | None,
        request_context: Mapping[str, Any] | None = None,
    ) -> VerdictResult:
        """Authorize already-normalised tool calls and return a single verdict.

        The seam for enforcement points that receive tool calls in structured form (e.g.
        an MCP ``tools/call`` request): they construct :class:`NormalizedToolCall` directly
        instead of round-tripping a provider-shaped dict through adapter detection.

        ``asyncio.CancelledError`` propagates — an unfinished scan is non-authorized
        (fail-closed at the caller's boundary).
        """
        if not calls:  # nothing to authorize — no decision to time or count
            return VerdictResult(Verdict.SKIP, _SKIP_REASON, VerdictStatus.SKIPPED)

        started = time.perf_counter()
        result, requests = await self._decide(calls, request_context or {})
        latency_s = time.perf_counter() - started
        self._emit(result, requests, latency_s)
        return result

    async def evaluate_requests(self, requests: list[EvaluationRequest] | None) -> VerdictResult:
        """Authorize pre-mapped evaluation requests and return a single verdict.

        The seam for enforcement points whose actions are not tool calls (e.g. MCP
        resource reads and prompt gets): the adapter shapes the AuthZEN tuple itself —
        including the trusted subject — and still gets the engine's fail-closed error
        tables, ALLOW-only cache, metrics and decision log.

        ``asyncio.CancelledError`` propagates — an unfinished scan is non-authorized
        (fail-closed at the caller's boundary).
        """
        if not requests:  # nothing to authorize — no decision to time or count
            return VerdictResult(Verdict.SKIP, _SKIP_REASON, VerdictStatus.SKIPPED)

        started = time.perf_counter()
        result = await self._evaluate_guarded(requests)
        latency_s = time.perf_counter() - started
        self._emit(result, requests, latency_s)
        return result

    async def evaluate_each(
        self,
        calls: list[NormalizedToolCall] | None,
        request_context: Mapping[str, Any] | None = None,
    ) -> list[VerdictResult]:
        """Authorize each call independently and return one verdict per call, positionally.

        For visibility filtering (e.g. shaping an MCP ``tools/list``), where a deny for one
        item must not block its siblings. Fail-closed per item: a mapper abstention or any
        evaluation fault yields a non-ALLOW verdict (BLOCK, or ``on_error``'s resolution)
        for the affected items — callers hide, never widen. One batch PDP round trip; the
        ALLOW-only cache is not consulted (the aggregate enforcement entrypoints own that
        hot path), and there is no per-subject decision log — just a summary INFO line and
        one ``record_decision`` per item (sharing the batch latency, and indistinguishable
        from enforcement decisions in the counters — account for that when alerting on
        block rates).
        """
        if not calls:
            return []
        started = time.perf_counter()
        results = await self._decide_each(calls, request_context or {})
        latency_s = time.perf_counter() - started
        self._emit_each(results, latency_s)
        return results

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
            logger.exception("apparitor: metrics/log emission failed (verdict unaffected)")

    def _record_cache(self, *, hit: bool) -> None:
        """Record a cache outcome, isolated so a faulty sink can't alter the verdict.

        This runs inside the decision path (unlike :meth:`_emit`), so it must swallow its
        own errors — otherwise a raising custom sink would flip an ALLOW into an error BLOCK.
        """
        try:
            self.metrics.record_cache(hit=hit)
        except Exception:
            logger.exception("apparitor: cache metric emission failed (verdict unaffected)")

    def _record_cancelled(self) -> None:
        """Record the block/error metric for a mid-evaluation cancellation, isolated.

        Must not raise — a faulty sink must never replace the original CancelledError with a
        metrics exception, which would violate the observability-isolation invariant.
        """
        try:
            self.metrics.record_decision(
                verdict=Verdict.BLOCK.value, status=VerdictStatus.ERROR.value, latency_s=0.0
            )
        except Exception:
            logger.exception("apparitor: cancellation metric emission failed")

    async def _decide(
        self, tool_calls: list[NormalizedToolCall], ctx: Mapping[str, Any]
    ) -> tuple[VerdictResult, list[EvaluationRequest]]:
        try:
            requests = self._build_requests(tool_calls, ctx)
        except AuthZENConfigError as exc:
            # Our misconfiguration (e.g. no subject) — fail closed, loudly. The warning is
            # the operator's only signal: no request was built, so no decision log follows.
            logger.warning("apparitor: mapping failed, blocking (%s)", exc)
            return VerdictResult(Verdict.BLOCK, _DENY_REASON, VerdictStatus.ERROR), []
        except Exception as exc:
            # A buggy custom mapper must fail closed here exactly as it does on the
            # per-item path — the engine never raises, never allows on error.
            return self._fault_verdict(exc), []

        if not requests:  # every mapper abstained
            return VerdictResult(Verdict.SKIP, _SKIP_REASON, VerdictStatus.SKIPPED), []

        return await self._evaluate_guarded(requests), requests

    async def _evaluate_guarded(self, requests: list[EvaluationRequest]) -> VerdictResult:
        """Evaluate with the fail-closed error tables (never raises, never ALLOW on error)."""
        try:
            return await self._evaluate(requests)
        except asyncio.CancelledError:
            # CancelledError is a BaseException, so the `except Exception` below would not
            # catch it — a mid-PDP cancellation would produce no verdict at all, which is
            # indistinguishable from ALLOW at the caller.  Record the fault metric so ops
            # can observe the interruption, then re-raise: structured concurrency requires
            # CancelledError to propagate (callers must treat an unfinished scan as denied).
            self._record_cancelled()
            raise
        except Exception as exc:
            return self._fault_verdict(exc)

    def _fault_verdict(self, exc: Exception) -> VerdictResult:
        """The one fail-closed error table, shared by every evaluation path."""
        if isinstance(exc, AuthZENClientError):
            # Log the detail (status code, PDP rejection reason) for operator diagnostics;
            # the returned reason stays generic — exc text can embed the PDP URL or host.
            logger.warning("apparitor: PDP client error, blocking (%s)", exc)
            return VerdictResult(Verdict.BLOCK, _DENY_REASON, VerdictStatus.ERROR)
        if isinstance(exc, AuthZENServiceError):
            # exc carries transport/timeout/malformed detail — operator log only (§3.10).
            logger.warning("apparitor: PDP error, resolved as on_error (%s)", exc)
            return resolve_error(self._config.on_error, _DENY_REASON)
        # Defense in depth: any unexpected internal error fails closed, never ALLOW.
        logger.exception("apparitor: unexpected internal error during evaluation")
        return VerdictResult(Verdict.BLOCK, _DENY_REASON, VerdictStatus.ERROR)

    async def _decide_each(
        self, calls: list[NormalizedToolCall], ctx: Mapping[str, Any]
    ) -> list[VerdictResult]:
        try:
            mapped = [_as_requests(self._mapper.map(call, ctx)) for call in calls]
        except Exception as exc:  # incl. AuthZENConfigError — a mapper fault blocks every item
            if isinstance(exc, AuthZENConfigError):
                # No requests were built, so no decision log follows — warn or it's invisible.
                logger.warning("apparitor: mapping failed, blocking all items (%s)", exc)
                failed = VerdictResult(Verdict.BLOCK, _DENY_REASON, VerdictStatus.ERROR)
            else:
                failed = self._fault_verdict(exc)
            return [failed] * len(calls)

        # Abstained items (None or an EMPTY group — all([]) must never read as allow)
        # stay BLOCK so positions align and abstention can never reveal.
        results = [
            VerdictResult(Verdict.BLOCK, "mapper abstained (fail closed)", VerdictStatus.ERROR)
        ] * len(calls)
        indexed = [(i, group) for i, group in enumerate(mapped) if group]
        if not indexed:
            return results

        try:
            flat = [request for _, group in indexed for request in group]
            response = await self._client.evaluate_batch(
                BatchEvaluationRequest(
                    evaluations=[
                        EvaluationItem(
                            subject=r.subject,
                            action=r.action,
                            resource=r.resource,
                            context=r.context,
                        )
                        for r in flat
                    ],
                    options=EvaluationsOptions(),
                )
            )
            if len(response.evaluations) != len(flat):
                # Non-conformant PDP (short/long array): nothing in the batch is trustworthy.
                raise AuthZENClientError("mismatched batch")
            # AND within each call's group (a multi-request mapper, e.g. dual-principal):
            # the combined verdict is the most severe leg — escalation can never widen.
            items = iter(response.evaluations)
            for i, group in indexed:
                combined = Verdict.ALLOW
                for _ in group:
                    item = next(items)
                    leg = map_single(item.decision, wants_review=self._wants_review(item.context))
                    combined = escalate(combined, leg)
                results[i] = VerdictResult(combined, _reason_for(combined))
            return results
        except asyncio.CancelledError:
            # CancelledError is a BaseException; the `except Exception` below does not catch
            # it — without this clause a mid-batch cancellation would record no metric, making
            # the interruption invisible to ops.  Record the fault metric (same convention as
            # _evaluate_guarded), then re-raise: a cancelled scan is non-authorized.
            self._record_cancelled()
            raise
        except Exception as exc:
            # Covers the PDP round trip AND per-item mapping (a raising review predicate
            # must fail closed here exactly as it does on the aggregate path).
            verdict = self._fault_verdict(exc)
        for i, _ in indexed:
            results[i] = verdict
        return results

    def _emit_each(self, results: list[VerdictResult], latency_s: float) -> None:
        """Best-effort metrics for per-item decisions; one counter per item, batch latency.

        Same isolation as :meth:`_emit` — observability can never alter a verdict.
        """
        try:
            for result in results:
                self.metrics.record_decision(
                    verdict=result.verdict.value, status=result.status.value, latency_s=latency_s
                )
            logger.info(
                "apparitor per-item decisions verdicts=%s latency_ms=%.1f",
                [r.verdict.value for r in results],
                latency_s * 1000,
            )
        except Exception:
            logger.exception("apparitor: metrics/log emission failed (verdict unaffected)")

    def _build_requests(
        self, tool_calls: list[NormalizedToolCall], ctx: Mapping[str, Any]
    ) -> list[EvaluationRequest]:
        requests: list[EvaluationRequest] = []
        for call in tool_calls:
            requests.extend(_as_requests(self._mapper.map(call, ctx)))
        return requests

    async def _evaluate(self, requests: list[EvaluationRequest]) -> VerdictResult:
        if len(requests) == 1:
            return await self._evaluate_single(requests[0])
        return await self._evaluate_batch(requests)

    async def _evaluate_single(self, request: EvaluationRequest) -> VerdictResult:
        key = decision_cache_key(request) if self._cache is not None else None
        if self._cache is not None and key is not None:
            hit = self._cache.get(key)
            self._record_cache(hit=bool(hit))
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
        if verdict is not Verdict.ALLOW:
            # The aggregate hides which leg denied — name them (principal/action/resource
            # ids only, never arguments) so an operator can tell a user-grant deny from an
            # agent-boundary deny without replaying the batch against the PDP.
            denied = [
                f"{r.subject.type}:{r.subject.id} {r.action.name} {r.resource.id}"
                for r, item in zip(requests, response.evaluations, strict=True)
                if not item.decision
            ]
            logger.info("apparitor batch denied_legs=%s", denied)
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
        """Operator/audit decision log.

        Records every distinct **decision principal**, resource ids, correlation id, and an
        argument *fingerprint* — deliberately, per requirements §3.10, since an authorization
        audit trail must say *who* was allowed/denied (under dual-principal evaluation that
        is both the user and the agent, never just the first leg). Raw tool arguments and
        tokens are never logged (arguments are fingerprinted). Subject ids are the
        principals themselves, so they may be emails or other identifiers; treat this
        logger as sensitive and route it accordingly.
        """
        correlation = (requests[0].context or {}).get("correlation_id")
        logger.info(
            "apparitor decision verdict=%s status=%s subjects=%s correlation=%s "
            "resources=%s fingerprints=%s latency_ms=%.1f",
            result.verdict.value,
            result.status.value,
            sorted({r.subject.id for r in requests}),
            correlation,
            [r.resource.id for r in requests],
            [_fingerprint(r) for r in requests],
            latency_s * 1000,
        )

    async def aclose(self) -> None:
        await self._client.aclose()


def _as_requests(
    mapped: EvaluationRequest | Sequence[EvaluationRequest] | None,
) -> list[EvaluationRequest]:
    """Normalise a mapper's return — single request, sequence, or abstention — to a list.

    The contract is ``Sequence`` (re-iterable); the return is materialised to a fresh list
    here, in one place, so even a non-conforming one-shot iterator gets consumed exactly
    once up front rather than silently half-read somewhere downstream.
    """
    if mapped is None:
        return []
    if isinstance(mapped, EvaluationRequest):
        return [mapped]
    return list(mapped)


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


#: Error message for the workload namespace guard (shared by all adapters).
#: The "workload" type is reserved for verified client-credentials tokens (FastMCP) so
#: minting claim-derived, static, or boundary principals in that namespace would alias
#: machine policies on a shared PDP.
WORKLOAD_RESERVED_MSG = 'subject type "workload" is reserved for verified client-credentials tokens'


def build_engine(
    pdp_url: str | None,
    config: ScannerConfig | None,
    *,
    http_client: httpx.AsyncClient | None = None,
    mapper: ToolCallMapper | None = None,
    review_predicate: ReviewPredicate | None = None,
    metrics: MetricsSink | None = None,
) -> tuple[ScannerConfig, AuthorizationEngine]:
    """Shared constructor prologue for every adapter.

    Resolves the (pdp_url, config) mutual-exclusion and constructs the backend and engine
    in one place so the four adapters stay DRY. Returns both the resolved config (adapters
    need it for their own settings) and the constructed engine.

    Raises :class:`~apparitor.errors.AuthZENConfigError` when neither ``pdp_url`` nor
    ``config`` is provided (previously ``ValueError``; changed pre-1.0 for consistency with
    the rest of the package's error hierarchy).
    """
    if pdp_url is not None and config is not None:
        raise AuthZENConfigError("provide pdp_url or config, not both")
    if config is None:
        if pdp_url is None:
            raise AuthZENConfigError("provide either pdp_url or config")
        from .config import ScannerConfig as _SC

        config = _SC(pdp_url=pdp_url)
    backend = build_backend(config, http_client=http_client)
    engine = AuthorizationEngine(
        config,
        client=backend,
        mapper=mapper,
        review_predicate=review_predicate,
        metrics=metrics,
    )
    return config, engine
