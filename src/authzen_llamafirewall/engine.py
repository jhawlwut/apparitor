"""The authorization engine — LlamaFirewall-free orchestration of the scan pipeline.

This holds all the logic (extract → map → evaluate → decide), operating only on plain
``list[dict]`` tool calls and producing an internal :class:`VerdictResult`. Keeping it
free of LlamaFirewall makes the entire pipeline unit-testable with ``respx`` and no ML
stack; :class:`~authzen_llamafirewall.scanner.AuthZENScanner` is a thin adapter that
converts the verdict into a LlamaFirewall ``ScanResult`` at the boundary.
"""

from __future__ import annotations

import logging
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
    ) -> None:
        self._config = config
        self._client = client or AuthZENClient(config)
        self._mapper = mapper or DefaultToolCallMapper(config)
        self._review = review_predicate
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
        if not tool_calls:
            return VerdictResult(Verdict.SKIP, _SKIP_REASON, VerdictStatus.SKIPPED)

        ctx: Mapping[str, Any] = request_context or {}
        try:
            requests = self._build_requests(tool_calls, ctx)
        except _UnparseableToolCall as exc:
            return VerdictResult(Verdict.BLOCK, str(exc), VerdictStatus.ERROR)
        except AuthZENConfigError as exc:
            # Our misconfiguration (e.g. no subject) — fail closed, loudly.
            return VerdictResult(Verdict.BLOCK, str(exc), VerdictStatus.ERROR)

        if not requests:  # every mapper abstained
            return VerdictResult(Verdict.SKIP, _SKIP_REASON, VerdictStatus.SKIPPED)

        try:
            verdict = await self._evaluate(requests)
        except AuthZENClientError as exc:
            return VerdictResult(Verdict.BLOCK, f"{_DENY_REASON} ({exc})", VerdictStatus.ERROR)
        except AuthZENServiceError as exc:
            result = resolve_error(self._config.on_error, f"PDP unavailable: {exc}")
            logger.warning("authzen: PDP error, resolved as %s", result.verdict.value)
            return result
        except Exception:
            # Defense in depth: any unexpected internal error fails closed, never ALLOW.
            logger.exception("authzen: unexpected internal error during evaluation")
            return VerdictResult(
                Verdict.BLOCK, f"{_DENY_REASON} (internal error)", VerdictStatus.ERROR
            )

        self._log(verdict, requests)
        return verdict

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
        if self._cache is not None:
            key = decision_cache_key(request)
            if self._cache.get(key):
                return VerdictResult(Verdict.ALLOW, f"{_ALLOW_REASON} (cached)")

        response = await self._client.evaluate(request)
        wants_review = self._wants_review(response.context)
        verdict = map_single(response.decision, wants_review=wants_review)

        if verdict is Verdict.ALLOW and self._cache is not None:
            self._cache.set_allow(decision_cache_key(request))
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

    def _log(self, verdict: VerdictResult, requests: list[EvaluationRequest]) -> None:
        logger.info(
            "authzen: verdict=%s tools=%s",
            verdict.verdict.value,
            [r.resource.id for r in requests],
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


def _reason_for(verdict: Verdict) -> str:
    if verdict is Verdict.ALLOW:
        return _ALLOW_REASON
    if verdict is Verdict.HUMAN_REVIEW:
        return "authorization requires human review"
    return _DENY_REASON
