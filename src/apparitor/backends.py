"""Pluggable decision backends.

The engine talks to a :class:`DecisionBackend` — anything that can evaluate a single tuple
or a batch and be closed. Two ship today:

* :class:`~apparitor.client.AuthZENClient` (default) — the AuthZEN Access Evaluation API.
* :class:`OPABackend` — Open Policy Agent's native Data API (``POST /v1/data/<path>``),
  for deployments that run OPA but don't front it with an AuthZEN endpoint.

:func:`build_backend` selects one from ``config.backend``. Both reuse the hardened
:class:`~apparitor.client.HTTPDecisionTransport` (SSRF guard, TLS, bounded retries, request
budget), so the security controls live in one place; a backend only shapes the request and
parses the response.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from .client import AuthZENClient, HTTPDecisionTransport
from .config import Backend
from .errors import MalformedPDPResponseError
from .models import (
    BatchEvaluationRequest,
    BatchEvaluationResponse,
    EvaluationRequest,
    EvaluationResponse,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    import httpx

    from .config import ScannerConfig


@runtime_checkable
class DecisionBackend(Protocol):
    """What the engine needs from a decision backend (AuthZEN client, OPA, …)."""

    async def evaluate(self, request: EvaluationRequest) -> EvaluationResponse: ...

    async def evaluate_batch(self, request: BatchEvaluationRequest) -> BatchEvaluationResponse: ...

    async def aclose(self) -> None: ...


class OPABackend(HTTPDecisionTransport):
    """Native Open Policy Agent backend: queries OPA's Data API directly (no AuthZEN hop).

    The AuthZEN tuple becomes the policy ``input``; the configured ``opa_decision_path`` must
    resolve to a **boolean** rule (give it a ``default ... := false`` so it is always defined,
    making a missing result an error rather than a falsy allow). Any non-boolean or absent
    ``result`` is a :class:`MalformedPDPResponseError` — fail closed, never a coerced allow.

    OPA has no batch endpoint, so a batch fans out to one Data API call per entry; the engine
    aggregates the per-entry decisions (all-allow-or-block under ``execute_all``). The native
    backend returns boolean decisions only — there is no advisory ``context``, so the
    ``review_predicate`` HITL path does not apply here.
    """

    def __init__(
        self,
        config: ScannerConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        super().__init__(config, http_client=http_client, sleep=sleep, clock=clock)
        self._path = "/v1/data/" + config.opa_decision_path.strip("/")

    async def evaluate(self, request: EvaluationRequest) -> EvaluationResponse:
        decision = await self._query(request.model_dump(mode="json", exclude_none=True))
        return EvaluationResponse(decision=decision)

    async def evaluate_batch(self, request: BatchEvaluationRequest) -> BatchEvaluationResponse:
        # Fan out concurrently over the shared pooled client; order is preserved by gather.
        # gather (no return_exceptions) propagates the first per-entry error and cancels the
        # in-flight siblings — intentional and security-critical: any transport/timeout/
        # malformed error must surface so the engine resolves it through on_error (fail
        # closed). Do NOT add return_exceptions=True; a partial batch must never become an allow.
        decisions = await asyncio.gather(*(self._query(doc) for doc in _batch_inputs(request)))
        return BatchEvaluationResponse(
            evaluations=[EvaluationResponse(decision=d) for d in decisions]
        )

    async def _query(self, input_doc: dict[str, Any]) -> bool:
        data = await self._post(self._path, {"input": input_doc})
        return _extract_decision(data)


def build_backend(
    config: ScannerConfig,
    *,
    http_client: httpx.AsyncClient | None = None,
    sleep: Callable[[float], Awaitable[None]] | None = None,
    clock: Callable[[], float] | None = None,
) -> DecisionBackend:
    """Construct the decision backend selected by ``config.backend``."""
    if config.backend is Backend.CEDAR:
        # In-process backend: no HTTP transport (no http_client/sleep/clock). Imported lazily
        # so the optional cedarpy dependency is only required when this backend is selected.
        from .cedar import CedarBackend

        return CedarBackend(config)
    kwargs: dict[str, Any] = {"http_client": http_client, "sleep": sleep, "clock": clock}
    if config.backend is Backend.OPA:
        return OPABackend(config, **kwargs)
    return AuthZENClient(config, **kwargs)


def _extract_decision(data: object) -> bool:
    """Pull OPA's boolean ``result`` out of a Data API response, fail closed.

    ``isinstance(x, bool)`` is intentional and strict: a JSON ``1``/``"true"`` (or a rule
    that returns an object) is a malformed decision, never a coerced truthy allow — the same
    security invariant the AuthZEN response model enforces via ``StrictBool``.
    """
    if isinstance(data, dict) and isinstance(data.get("result"), bool):
        return bool(data["result"])
    raise MalformedPDPResponseError(
        "OPA response missing a boolean 'result' "
        "(opa_decision_path must resolve to a boolean rule with a default)"
    )


def _batch_inputs(request: BatchEvaluationRequest) -> list[dict[str, Any]]:
    """One OPA ``input`` document per batch entry, overlaying request-level defaults.

    Mirrors AuthZEN batch semantics: top-level subject/action/resource/context are defaults
    each entry may override. Override is wholesale, not a merge — an entry with ``context={}``
    deliberately clears the request-level context (it is not the same as "unset", which falls
    back to the default). The engine fills every entry fully, so this is also a correctness
    guard for direct callers.
    """
    inputs: list[dict[str, Any]] = []
    for item in request.evaluations:
        merged = EvaluationRequest(
            subject=item.subject or request.subject,
            action=item.action or request.action,
            resource=item.resource or request.resource,
            context=item.context if item.context is not None else request.context,
        )
        inputs.append(merged.model_dump(mode="json", exclude_none=True))
    return inputs
