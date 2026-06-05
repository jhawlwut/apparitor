"""AuthZEN PDP client (LlamaFirewall-free, async-first).

Owns transport and the AuthZEN wire shape only — decision-to-verdict mapping lives in
the scanner. Designed so the scanner can hold **one long-lived, pooled**
``httpx.AsyncClient`` across calls (keep-alive in the hot path) and close it via
:meth:`AuthZENClient.aclose`.

Key contracts (implementation deferred):

* **Async is primary.** No ``asyncio.run`` anywhere — that would crash when invoked
  inside an already-running event loop (the common agent case). A synchronous variant,
  if provided, uses a real ``httpx.Client``.
* **Bring-your-own client.** Callers may pass a pre-configured ``httpx.AsyncClient``
  to own auth (bearer/mTLS), TLS roots, proxies and timeouts themselves; otherwise the
  client builds one from :class:`~authzen_llamafirewall.config.ScannerConfig`.
* **Retries** are bounded and hand-rolled (exponential backoff + jitter) over
  ``429``/``502``/``503``/``504`` and transport errors only — never ``4xx`` or a valid
  deny — and stay within the total request budget. (httpx transport-level retries only
  cover connection failures, not ``5xx``/``429``.)
* **SSRF guard.** ``pdp_url`` is operator config only; HTTPS is required and
  private/link-local hosts are rejected unless ``allow_insecure_pdp`` is set.
* httpx exceptions are mapped onto :mod:`authzen_llamafirewall.errors` at this boundary.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .models import (
    BatchEvaluationRequest,
    BatchEvaluationResponse,
    EvaluationRequest,
    EvaluationResponse,
)

if TYPE_CHECKING:
    import httpx

    from .config import ScannerConfig


class AuthZENClient:
    """Async client for the AuthZEN Access Evaluation API."""

    def __init__(
        self,
        config: ScannerConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._config = config
        self._http = http_client
        self._owns_http = http_client is None

    async def evaluate(self, request: EvaluationRequest) -> EvaluationResponse:
        """``POST /access/v1/evaluation`` — evaluate a single tuple."""
        raise NotImplementedError("deferred: see docs/requirements.md §7 (transport)")

    async def evaluate_batch(self, request: BatchEvaluationRequest) -> BatchEvaluationResponse:
        """``POST /access/v1/evaluations`` — evaluate a batch (multi-step plan)."""
        raise NotImplementedError("deferred: see docs/requirements.md §7-8")

    async def aclose(self) -> None:
        """Close the underlying client if this instance created it."""
        raise NotImplementedError("deferred")

    async def __aenter__(self) -> AuthZENClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
