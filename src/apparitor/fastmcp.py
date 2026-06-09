"""FastMCP server-middleware adapter (thin adapter over :class:`AuthorizationEngine`).

This is the **only** module that imports FastMCP. The import is guarded so that importing
it without ``fastmcp`` installed yields a clear
:class:`~apparitor.errors.MissingDependencyError` rather than an opaque ``ImportError``.

It binds the firewall-free :class:`AuthorizationEngine` behind a FastMCP **middleware** so
every MCP ``tools/call`` is authorized server-side, *before* the tool executes — the same
engine, mapper, fail-closed semantics and metrics as the LlamaFirewall scanner and the NeMo
rail; only the boundary differs. Unlike the in-runtime firewall adapters, the subject here
can come from a **validated** identity: the OAuth access token FastMCP's auth layer
verified for the request — never from anything the model produced.

Subject resolution (first match wins; no match refuses the call):

1. The verified access token's ``sub`` claim → ``Subject(type="user", id=<sub>)``
   (``subject_claim`` / ``subject_type`` are constructor knobs). A token *without* a
   usable claim refuses — a workload (client-credentials) token is never silently
   downgraded to a fallback subject.
2. A host-injected trusted subject: ``current_request_context["subject"]`` or
   :func:`~apparitor.mapping.subject_scope` — out-of-band, as with the other adapters.
3. ``config.agent_id``, **only** when ``allow_static_subject=True``. Off by default: on a
   network transport a static fallback would authorize every anonymous caller as that one
   subject (a confused deputy). Opt in only for local/stdio servers.

The default mapper is :class:`~apparitor.mapping.MCPResourceMapper`, so the resource id is
server-scoped (``"<server>/<tool>"``): ``server_label`` if given, else the name of the
FastMCP server the call arrived on. Renaming the server therefore changes resource ids
(and ALLOW-cache keys) — pin ``server_label`` where policies must outlive a rename.

Verdict mapping is fail-closed: only a clean ``ALLOW`` reaches the tool. ``BLOCK``,
``HUMAN_REVIEW`` (MCP has no human-in-the-loop pause; refusal is surfaced distinctly so a
host can escalate), mapper abstention (``SKIP`` — here always exactly one call is
submitted, so abstention would otherwise silently execute) and any error refuse by raising
``ToolError``. Refusal messages are deliberately generic: ``ToolError`` text reaches the
(untrusted) client and model, so the rich verdict/reason stays in the operator decision
log and metrics. Note the decision log records the subject id — with token-derived
subjects that is the OAuth ``sub``; route the ``apparitor`` logger accordingly.

Enforcement scope (deployment requirements): register the middleware on every server whose
tools must be gated (a mounted sub-server is covered only when calls flow through the
parent), order it after any custom auth middleware so the token is populated, and note
that v1 gates ``tools/call`` only — resource reads and prompts are not yet authorized.
FastMCP never tears middleware down, so closing is the host's job (``aclose()``).

Wiring::

    from fastmcp import FastMCP
    from apparitor.fastmcp import FastMCPAuthorizationMiddleware

    server = FastMCP("files", auth=...)  # auth yields the validated token identity
    server.add_middleware(FastMCPAuthorizationMiddleware(pdp_url="https://pdp.internal"))
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from .adapters import NormalizedToolCall
from .config import ScannerConfig
from .decision import Verdict, VerdictResult, VerdictStatus
from .engine import AuthorizationEngine, ReviewPredicate
from .errors import MissingDependencyError
from .mapping import (
    MCP_SERVER_LABEL_KEY,
    MCPResourceMapper,
    current_request_context,
    current_subject,
)
from .models import Subject

try:  # pragma: no cover - exercised via import-guard tests
    from fastmcp.exceptions import ToolError
    from fastmcp.server.dependencies import get_access_token
    from fastmcp.server.middleware import Middleware
except ImportError as exc:  # pragma: no cover
    raise MissingDependencyError(
        "apparitor.fastmcp requires FastMCP. Install it with:\n    pip install 'apparitor[fastmcp]'"
    ) from exc

if TYPE_CHECKING:
    import httpx
    import mcp.types as mt
    from fastmcp.server.middleware import CallNext, MiddlewareContext
    from fastmcp.tools.tool import ToolResult

    from .mapping import ToolCallMapper
    from .metrics import MetricsSink

logger = logging.getLogger("apparitor")

# Refusal text crosses the trust boundary to the client/model, so it is fixed and generic —
# never the engine's reason, which may embed PDP/config detail (requirements §3.10).
_DENY_MESSAGE = "tool call not authorized"
_REVIEW_MESSAGE = "tool call requires human approval; do not retry"


def _is_allowed(verdict: VerdictResult) -> bool:
    """Only a clean ALLOW executes. SKIP refuses here: exactly one call is always
    submitted, so SKIP can only mean a mapper abstained — executing it would be a bypass
    (unlike the scanner/NeMo adapters, where SKIP means "no tool calls in the message")."""
    return verdict.status is not VerdictStatus.ERROR and verdict.verdict is Verdict.ALLOW


class FastMCPAuthorizationMiddleware(Middleware):  # type: ignore[misc]  # fastmcp may be absent in the lint env (base is Any)
    """Authorizes MCP tool calls against an AuthZEN PDP from inside a FastMCP server.

    Construct it like the other adapters — a ``pdp_url`` or a full :class:`ScannerConfig` —
    then ``server.add_middleware(...)``. A subject must be resolvable (validated token,
    host-injected subject, or the opt-in static fallback) or the call is refused.
    """

    def __init__(
        self,
        pdp_url: str | None = None,
        *,
        config: ScannerConfig | None = None,
        server_label: str | None = None,
        subject_type: str = "user",
        subject_claim: str = "sub",
        allow_static_subject: bool = False,
        mapper: ToolCallMapper | None = None,
        http_client: httpx.AsyncClient | None = None,
        review_predicate: ReviewPredicate | None = None,
        metrics: MetricsSink | None = None,
    ) -> None:
        super().__init__()
        if config is None:
            if pdp_url is None:
                raise ValueError("provide either pdp_url or config")
            config = ScannerConfig(pdp_url=pdp_url)
        self._config = config
        self._server_label = server_label
        self._subject_type = subject_type
        self._subject_claim = subject_claim
        self._allow_static_subject = allow_static_subject
        from .backends import build_backend

        backend = build_backend(config, http_client=http_client)
        self._engine = AuthorizationEngine(
            config,
            client=backend,
            mapper=mapper or MCPResourceMapper(config),
            review_predicate=review_predicate,
            metrics=metrics,
        )

    @property
    def metrics(self) -> MetricsSink:
        """The engine's metrics sink (latency histogram + cache-hit counter)."""
        return self._engine.metrics

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        """Authorize the tool call; only a clean ALLOW reaches ``call_next``."""
        try:
            verdict = await self._authorize(context)
        except Exception:
            # Defense in depth: an adapter-level fault must refuse, never execute. The
            # generic message is deliberate — exception text must not reach the client.
            logger.exception("apparitor: FastMCP authorization middleware error (refusing)")
            raise ToolError(_DENY_MESSAGE) from None
        if verdict is not None and _is_allowed(verdict):
            return await call_next(context)
        if verdict is not None and verdict.verdict is Verdict.HUMAN_REVIEW:
            raise ToolError(_REVIEW_MESSAGE)
        raise ToolError(_DENY_MESSAGE)

    async def _authorize(
        self, context: MiddlewareContext[mt.CallToolRequestParams]
    ) -> VerdictResult | None:
        """Evaluate the call; ``None`` means no resolvable subject (refuse, no PDP trip)."""
        ctx: dict[str, Any] = dict(current_request_context.get() or {})
        subject = self._resolve_subject(ctx)
        if subject is None:
            return None
        # The resolved subject is injected explicitly (the mapper consults
        # request_context["subject"] first), so a validated token always wins over any
        # ambient or host-provided value.
        ctx["subject"] = subject
        if self._server_label is not None:
            ctx[MCP_SERVER_LABEL_KEY] = self._server_label
        elif MCP_SERVER_LABEL_KEY not in ctx:
            name = _server_name(context)
            if name is not None:
                ctx[MCP_SERVER_LABEL_KEY] = name
        call = NormalizedToolCall(
            name=context.message.name, arguments=dict(context.message.arguments or {})
        )
        return await self._engine.evaluate_normalized([call], request_context=ctx)

    def _resolve_subject(self, request_context: dict[str, Any]) -> Subject | None:
        token = get_access_token()
        if token is not None:
            sub = (token.claims or {}).get(self._subject_claim)
            if isinstance(sub, str) and sub.strip():
                return Subject(
                    type=self._subject_type,
                    id=sub,
                    properties={"client_id": token.client_id, "scopes": list(token.scopes)},
                )
            # A verified token without a usable subject claim (e.g. a client-credentials
            # workload token) refuses rather than silently downgrading to a fallback.
            logger.warning(
                "apparitor: access token has no usable %r claim; refusing (workload"
                " identities are not yet supported)",
                self._subject_claim,
            )
            return None
        injected = request_context.get("subject")
        if isinstance(injected, Subject):
            return injected
        ambient = current_subject.get()
        if ambient is not None:
            return ambient
        if self._allow_static_subject and self._config.agent_id is not None:
            return Subject(type=self._config.subject_type, id=self._config.agent_id)
        logger.warning(
            "apparitor: no authenticated subject for MCP tool call; refusing (configure"
            " server auth, or opt in to allow_static_subject for local/stdio use)"
        )
        return None

    async def aclose(self) -> None:
        """Release the underlying PDP client (FastMCP never closes middleware itself).

        Only closes a client this adapter created; a bring-your-own ``http_client`` is left
        for the caller to manage.
        """
        await self._engine.aclose()

    async def __aenter__(self) -> FastMCPAuthorizationMiddleware:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()


def _server_name(context: MiddlewareContext[Any]) -> str | None:
    """The name of the FastMCP server handling the call, or ``None`` if unresolvable."""
    fastmcp_ctx = context.fastmcp_context
    server = getattr(fastmcp_ctx, "fastmcp", None) if fastmcp_ctx is not None else None
    name = getattr(server, "name", None)
    if isinstance(name, str) and name.strip():
        return name
    return None


__all__ = ["FastMCPAuthorizationMiddleware"]
