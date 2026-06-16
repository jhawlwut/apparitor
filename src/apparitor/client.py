"""HTTP transport + AuthZEN PDP client (LlamaFirewall-free, async-first).

:class:`HTTPDecisionTransport` owns the hardened transport shared by every HTTP decision
backend: a pooled ``httpx.AsyncClient``, the SSRF guard, bounded retries within the request
budget, and httpx-exception mapping. :class:`AuthZENClient` builds the AuthZEN wire shape on
top of it; the native :class:`~apparitor.backends.OPABackend` reuses the same transport so
the security controls are defined once, never duplicated.

* **Async only.** No ``asyncio.run`` — it would crash inside a running event loop.
* **Bring-your-own client.** Pass a pre-configured ``httpx.AsyncClient`` to own
  auth/TLS/proxies; otherwise one is built from :class:`ScannerConfig`.
* **Bounded retries within the budget.** Exponential backoff + jitter over ``429`` and
  ``502/503/504`` and transport errors only — never ``4xx`` or a valid deny. (httpx's
  transport retries cover connection failures only, not ``5xx``/``429``.)
* **SSRF guard.** ``pdp_url`` must be HTTPS and not a private/loopback/link-local host
  unless ``allow_insecure_pdp`` is set.
* httpx exceptions are mapped onto :mod:`apparitor.errors` here.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
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
_TransportT = TypeVar("_TransportT", bound="HTTPDecisionTransport")


def validate_pdp_url(url: str, *, allow_insecure: bool) -> None:
    """Reject non-HTTPS or private/loopback/link-local PDP URLs (SSRF guard).

    Hostnames that are not literal IPs are allowed without DNS resolution (avoiding a
    network call and a TOCTOU window); operators should pair this with network egress
    controls. ``allow_insecure`` disables the guard for local development.
    """
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        # A string urlparse cannot even split (e.g. a malformed IPv6 literal like
        # "https://[") is not a usable PDP URL: reject it as a config error rather than
        # letting a raw ValueError escape the guard.
        raise AuthZENConfigError(f"pdp_url is not a parseable URL: {exc}") from exc
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
        return  # a hostname — cannot classify without DNS; permitted (pair with egress policy)
    # IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) is unwrapped so the checks below catch it.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_unspecified
        or ip.is_multicast
    ):
        raise AuthZENConfigError(f"pdp_url host {host} is private/link-local; refusing (SSRF)")


class HTTPDecisionTransport:
    """Pooled, SSRF-guarded HTTP transport with bounded retries — the base for every
    HTTP decision backend. Subclasses add the engine-specific request/response shaping."""

    def __init__(
        self,
        config: ScannerConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._config = config
        if config.pdp_url is None:
            raise AuthZENConfigError(f"pdp_url is required for the {config.backend.value} backend")
        validate_pdp_url(str(config.pdp_url), allow_insecure=config.allow_insecure_pdp)
        # Compose request URLs from the *validated* pdp_url, not from an injected client's
        # base_url, so the SSRF-checked origin (and the path prefix) always governs the
        # destination — even with a bring-your-own http_client.
        self._base_url = str(config.pdp_url).rstrip("/")
        self._owns_http = http_client is None
        self._http = http_client or self._build_client()
        self._sleep = sleep or asyncio.sleep
        self._clock = clock or (lambda: asyncio.get_running_loop().time())

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
            # Never follow redirects: a PDP 3xx to an internal host would defeat the SSRF
            # guard, which only validates the configured pdp_url.
            follow_redirects=False,
        )

    async def _post(self, path: str, payload: dict[str, Any]) -> object:
        cfg = self._config
        deadline = self._clock() + cfg.request_budget_s
        attempt = 0
        last_exc: Exception | None = None
        while True:
            remaining = deadline - self._clock()
            if remaining <= 0:
                raise PDPTimeoutError("PDP request budget exhausted") from last_exc
            # Cap every per-attempt timeout — including the pool-acquire wait — to the
            # remaining budget so a single slow call (or a saturated pool) can never run past
            # it (the budget bounds total wall-clock, not just retries).
            timeout = httpx.Timeout(
                connect=min(cfg.connect_timeout_s, remaining),
                read=min(cfg.read_timeout_s, remaining),
                write=min(cfg.read_timeout_s, remaining),
                pool=min(cfg.connect_timeout_s, remaining),
            )
            try:
                # Absolute URL from the validated pdp_url + per-request no-redirect: a bring-
                # your-own client cannot redirect the request off the SSRF-checked origin.
                response = await self._http.post(
                    self._base_url + path, json=payload, timeout=timeout, follow_redirects=False
                )
            except httpx.TimeoutException as exc:
                last_exc = exc
                if not self._should_retry(attempt, deadline):
                    raise PDPTimeoutError(f"PDP timed out: {exc}") from exc
            except httpx.TransportError as exc:
                # Base of connection/protocol/read/write transport faults. Mapped to a
                # service error so it routes through on_error (not the generic catch-all).
                last_exc = exc
                if not self._should_retry(attempt, deadline):
                    raise PDPUnavailableError(f"PDP unreachable: {exc}") from exc
            else:
                if response.status_code in _RETRY_STATUS and self._should_retry(attempt, deadline):
                    await self._backoff(attempt, deadline)
                    attempt += 1
                    continue
                return _handle_status(response)
            await self._backoff(attempt, deadline)
            attempt += 1

    def _should_retry(self, attempt: int, deadline: float) -> bool:
        return attempt < self._config.max_retries and self._clock() < deadline

    async def _backoff(self, attempt: int, deadline: float) -> None:
        cfg = self._config
        delay = min(cfg.backoff_base_s * (2**attempt), cfg.backoff_max_s)
        delay += random.uniform(0, cfg.backoff_base_s)
        # Never sleep past the budget — the loop checks remaining only after the sleep, so an
        # unclamped backoff would let total wall-clock exceed request_budget_s.
        remaining = deadline - self._clock()
        if remaining <= 0:
            return
        await self._sleep(min(delay, remaining))

    async def aclose(self) -> None:
        """Close the underlying client if this instance created it."""
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self: _TransportT) -> _TransportT:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()


class AuthZENClient(HTTPDecisionTransport):
    """Async client for the AuthZEN Access Evaluation API."""

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


def _strict_json(raw: bytes) -> object:
    """Parse JSON, raising ``MalformedPDPResponseError`` on duplicate keys.

    ``json.loads`` uses last-wins for duplicate keys, so a body such as
    ``{"decision": false, "decision": true}`` silently collapses to
    ``{"decision": true}`` before pydantic's ``StrictBool`` validator runs —
    coercing a contradictory/malformed response into an ALLOW.  An
    ``object_pairs_hook`` that detects duplicate keys within each JSON object
    closes that window.  Requirements §3.6: malformed 2xx → BLOCK.
    """

    def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        # A fresh dict tracks keys for THIS object only — sibling objects in a batch
        # response legitimately reuse the same key names (e.g. multiple "decision" fields
        # in the evaluations array are not duplicates — each is in its own JSON object).
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise MalformedPDPResponseError(
                    f"PDP response contains duplicate JSON key: {key!r}"
                )
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=_reject_duplicates)
    except MalformedPDPResponseError:
        raise
    except ValueError as exc:
        raise MalformedPDPResponseError(f"PDP returned non-JSON body: {exc}") from exc


def _handle_status(response: httpx.Response) -> object:
    """Return parsed JSON for ``2xx``; map ``4xx``/``5xx`` to typed errors."""
    code = response.status_code
    if 200 <= code < 300:
        return _strict_json(response.content)
    if 300 <= code < 400:
        # Redirects are disabled; an unfollowed 3xx is treated as unavailable (fail closed),
        # never as a decision.
        raise PDPUnavailableError(f"PDP returned an unexpected redirect (HTTP {code})")
    if 400 <= code < 500:
        raise AuthZENClientError(f"PDP rejected the request (HTTP {code})", status_code=code)
    raise PDPUnavailableError(f"PDP returned HTTP {code}")


def _parse(data: object, model: type[_ModelT]) -> _ModelT:
    try:
        return model.model_validate(data)
    except Exception as exc:  # pydantic ValidationError or worse
        raise MalformedPDPResponseError(f"PDP response failed validation: {exc}") from exc
