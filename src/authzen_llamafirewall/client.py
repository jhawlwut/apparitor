"""AuthZEN PDP client (LlamaFirewall-free, async-first).

Owns transport and the AuthZEN wire shape only — decision-to-verdict mapping lives in the
engine. The scanner holds one long-lived, pooled ``httpx.AsyncClient`` across calls and
closes it via :meth:`AuthZENClient.aclose`.

* **Async only.** No ``asyncio.run`` — it would crash inside a running event loop.
* **Bring-your-own client.** Pass a pre-configured ``httpx.AsyncClient`` to own
  auth/TLS/proxies; otherwise one is built from :class:`ScannerConfig`.
* **Bounded retries within the budget.** Exponential backoff + jitter over ``429`` and
  ``502/503/504`` and transport errors only — never ``4xx`` or a valid deny. (httpx's
  transport retries cover connection failures only, not ``5xx``/``429``.)
* **SSRF guard.** ``pdp_url`` must be HTTPS and not a private/loopback/link-local host
  unless ``allow_insecure_pdp`` is set.
* httpx exceptions are mapped onto :mod:`authzen_llamafirewall.errors` here.
"""

from __future__ import annotations

import asyncio
import ipaddress
import random
from typing import TYPE_CHECKING, Any, TypeVar
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel

from .errors import (
    AuthZENClientError,
    AuthZENConfigError,
    MalformedPDPResponseError,
    PDPTimeoutError,
    PDPUnavailableError,
)
from .models import (
    BatchEvaluationRequest,
    BatchEvaluationResponse,
    EvaluationRequest,
    EvaluationResponse,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from .config import ScannerConfig

_RETRY_STATUS = frozenset({429, 502, 503, 504})

_ModelT = TypeVar("_ModelT", bound=BaseModel)


def validate_pdp_url(url: str, *, allow_insecure: bool) -> None:
    """Reject non-HTTPS or private/loopback/link-local PDP URLs (SSRF guard).

    Hostnames that are not literal IPs are allowed without DNS resolution (avoiding a
    network call and a TOCTOU window); operators should pair this with network egress
    controls. ``allow_insecure`` disables the guard for local development.
    """
    parsed = urlparse(url)
    if allow_insecure:
        return
    if parsed.scheme != "https":
        raise AuthZENConfigError(
            "pdp_url must be https; set allow_insecure_pdp=True for local development"
        )
    host = parsed.hostname or ""
    if host in ("localhost", "localhost.localdomain"):
        raise AuthZENConfigError("pdp_url resolves to localhost; set allow_insecure_pdp for dev")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return  # a hostname — cannot classify without DNS; permitted
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        raise AuthZENConfigError(f"pdp_url host {host} is private/link-local; refusing (SSRF)")


class AuthZENClient:
    """Async client for the AuthZEN Access Evaluation API."""

    def __init__(
        self,
        config: ScannerConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self._config = config
        validate_pdp_url(str(config.pdp_url), allow_insecure=config.allow_insecure_pdp)
        self._owns_http = http_client is None
        self._http = http_client or self._build_client()
        self._sleep = sleep or asyncio.sleep

    def _build_client(self) -> httpx.AsyncClient:
        cfg = self._config
        timeout = httpx.Timeout(
            connect=cfg.connect_timeout_s,
            read=cfg.read_timeout_s,
            write=cfg.read_timeout_s,
            pool=cfg.connect_timeout_s,
        )
        return httpx.AsyncClient(
            base_url=str(cfg.pdp_url).rstrip("/"),
            timeout=timeout,
            verify=cfg.verify_tls,
            headers=dict(cfg.default_headers),
        )

    async def evaluate(self, request: EvaluationRequest) -> EvaluationResponse:
        """``POST /access/v1/evaluation`` — evaluate a single tuple."""
        payload = request.model_dump(mode="json", exclude_none=True)
        data = await self._post(self._config.evaluation_path, payload)
        return _parse(data, EvaluationResponse)

    async def evaluate_batch(self, request: BatchEvaluationRequest) -> BatchEvaluationResponse:
        """``POST /access/v1/evaluations`` — evaluate a batch (multi-step plan)."""
        payload = request.model_dump(mode="json", exclude_none=True)
        data = await self._post(self._config.batch_path, payload)
        return _parse(data, BatchEvaluationResponse)

    async def _post(self, path: str, payload: dict[str, Any]) -> object:
        cfg = self._config
        deadline = asyncio.get_running_loop().time() + cfg.request_budget_s
        attempt = 0
        while True:
            try:
                response = await self._http.post(path, json=payload)
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                if not self._should_retry(attempt, deadline):
                    raise PDPUnavailableError(f"PDP unreachable: {exc}") from exc
            except httpx.TimeoutException as exc:
                if not self._should_retry(attempt, deadline):
                    raise PDPTimeoutError(f"PDP timed out: {exc}") from exc
            else:
                if response.status_code in _RETRY_STATUS and self._should_retry(attempt, deadline):
                    await self._backoff(attempt)
                    attempt += 1
                    continue
                return _handle_status(response)
            await self._backoff(attempt)
            attempt += 1

    def _should_retry(self, attempt: int, deadline: float) -> bool:
        return attempt < self._config.max_retries and asyncio.get_running_loop().time() < deadline

    async def _backoff(self, attempt: int) -> None:
        cfg = self._config
        delay = min(cfg.backoff_base_s * (2**attempt), cfg.backoff_max_s)
        await self._sleep(delay + random.uniform(0, cfg.backoff_base_s))

    async def aclose(self) -> None:
        """Close the underlying client if this instance created it."""
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> AuthZENClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()


def _handle_status(response: httpx.Response) -> object:
    """Return parsed JSON for ``2xx``; map ``4xx``/``5xx`` to typed errors."""
    code = response.status_code
    if 200 <= code < 300:
        try:
            return response.json()
        except ValueError as exc:
            raise MalformedPDPResponseError(f"PDP returned non-JSON body: {exc}") from exc
    if 400 <= code < 500:
        raise AuthZENClientError(f"PDP rejected the request (HTTP {code})", status_code=code)
    raise PDPUnavailableError(f"PDP returned HTTP {code}")


def _parse(data: object, model: type[_ModelT]) -> _ModelT:
    try:
        return model.model_validate(data)
    except Exception as exc:  # pydantic ValidationError or worse
        raise MalformedPDPResponseError(f"PDP response failed validation: {exc}") from exc
