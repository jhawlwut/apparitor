"""Mapping from a normalised tool call to an AuthZEN evaluation request.

A single extensibility seam — :class:`ToolCallMapper` — turns a tool call plus
request-scoped context into an :class:`~apparitor.models.EvaluationRequest`
(or ``None`` to abstain). Subject resolution, resource shaping and context enrichment all
live behind this one protocol because in practice they read the same request context.

Subject identity is **request-scoped**, not static: the principal that matters for
authorization is usually the end user the agent acts for, which arrives via the host
framework's run context — not via the ``Message``. The default mapper reads it from the
:data:`current_subject` context variable, falling back to a configured static agent
subject, and fails closed if neither is available rather than authorizing an unknown
principal.
"""

from __future__ import annotations

import contextvars
import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from .errors import AuthZENConfigError
from .models import Action, EvaluationRequest, Resource, Subject

if TYPE_CHECKING:
    from .adapters import NormalizedToolCall
    from .config import ScannerConfig

#: Request-scoped subject. Hosts set this (per request / per agent run) before the scanner
#: is invoked; the default mapper reads it here. Prefer :func:`subject_scope` over calling
#: ``.set()`` directly so the value can never leak across requests on a reused task/loop.
current_subject: contextvars.ContextVar[Subject | None] = contextvars.ContextVar(
    "authzen_current_subject", default=None
)

#: Request-scoped enrichment context (``conversation_id`` / ``user_id`` / ``correlation_id``
#: and, optionally, a trusted ``subject``). MUST contain only host-trusted, out-of-band data
#: — never anything derived from model/tool output (that would be a confused-deputy).
current_request_context: contextvars.ContextVar[Mapping[str, Any] | None] = contextvars.ContextVar(
    "authzen_current_request_context", default=None
)

_REDACTED = "***redacted***"

#: Request-context key carrying the MCP server label when it is resolved per call (e.g. by
#: the FastMCP middleware, from the server it is mounted on) rather than fixed at mapper
#: construction. Host-trusted, like everything else in the request context.
MCP_SERVER_LABEL_KEY = "mcp_server_label"


def request_context_attrs(request_context: Mapping[str, Any]) -> dict[str, Any] | None:
    """The host-trusted enrichment keys forwarded as AuthZEN ``context``.

    Shared by the mappers and by adapters that shape evaluation requests directly (e.g.
    MCP resource/prompt gating), so every surface forwards the same attribute set.
    """
    keys = ("conversation_id", "user_id", "correlation_id")
    ctx = {k: request_context[k] for k in keys if k in request_context}
    if not ctx:
        return None
    # Host-trusted but not necessarily JSON-typed (a UUID correlation id, say); coerce so
    # downstream serialisation (the PDP body and the cache key) can never raise and crash
    # the fail-closed path — same guarantee _json_safe gives tool arguments.
    return _json_safe(ctx)


@contextmanager
def subject_scope(subject: Subject) -> Iterator[None]:
    """Bind :data:`current_subject` for the duration of the ``with`` block, then reset it.

    Use this instead of ``current_subject.set(...)`` so the subject is always cleared and
    can never leak to a later request that reuses the same task/event loop.
    """
    token = current_subject.set(subject)
    try:
        yield
    finally:
        current_subject.reset(token)


def _json_safe(value: dict[str, Any]) -> dict[str, Any]:
    """Return a JSON-serialisable copy of ``value`` (stringifying exotic leaf types).

    Guarantees that downstream serialisation (the PDP request body and the cache key)
    can never raise on a non-JSON argument value and crash the fail-closed path.
    """
    safe: dict[str, Any] = json.loads(json.dumps(value, default=str))
    return safe


def mcp_resource_id(server: str, tool: str) -> str:
    """Build a stable resource id for an MCP tool call.

    Bare MCP tool names (``search``, ``read``, ``query`` …) collide across servers, so a
    faithful authorization key is server-scoped: ``"<server>/<tool>"``. Any ``/`` in a
    segment is rejected (fail closed) rather than stripped: ``a/b`` + ``read`` and ``a`` +
    ``b/read`` would otherwise collide, and aliasing ``read`` / ``/read`` onto one policy key
    would silently widen an ALLOW.
    """
    server = server.strip()
    tool = tool.strip()
    if not server or not tool:
        raise AuthZENConfigError("mcp_resource_id requires non-empty server and tool")
    if "/" in server or "/" in tool:
        raise AuthZENConfigError("mcp_resource_id segments may not contain '/'")
    return f"{server}/{tool}"


@runtime_checkable
class ToolCallMapper(Protocol):
    """Maps a tool call + request context to an AuthZEN request, or ``None``."""

    def map(
        self,
        tool_call: NormalizedToolCall,
        request_context: Mapping[str, Any],
    ) -> EvaluationRequest | None:
        """Return an :class:`EvaluationRequest`, or ``None`` to abstain."""
        ...


class DefaultToolCallMapper:
    """Default mapper: ``{type:"tool", id:<tool name>}`` with arguments in resource props."""

    def __init__(self, config: ScannerConfig) -> None:
        self._config = config

    def _resolve_subject(self, request_context: Mapping[str, Any]) -> Subject:
        injected = request_context.get("subject")
        if isinstance(injected, Subject):
            return injected
        subject = current_subject.get()
        if subject is not None:
            return subject
        if self._config.agent_id is not None:
            return Subject(type=self._config.subject_type, id=self._config.agent_id)
        raise AuthZENConfigError(
            "no subject available: set current_subject for the request or config.agent_id"
        )

    def _arguments(self, tool_call: NormalizedToolCall) -> dict[str, Any]:
        cfg = self._config
        if not cfg.forward_arguments:
            return {}
        if cfg.redact_arguments:
            args: dict[str, Any] = dict.fromkeys(tool_call.arguments, _REDACTED)
        else:
            args = _json_safe(tool_call.arguments)
        # Size cap applies to both paths: even redacted keys are caller-influenced.
        if len(json.dumps(args, sort_keys=True).encode("utf-8")) > cfg.max_argument_bytes:
            return {"_truncated": True}
        return args

    def _resource(
        self, tool_call: NormalizedToolCall, request_context: Mapping[str, Any]
    ) -> Resource:
        return Resource(
            type=self._config.resource_type,
            id=_normalize_tool_name(tool_call.name),
            properties={"arguments": self._arguments(tool_call)},
        )

    def _context(self, request_context: Mapping[str, Any]) -> dict[str, Any] | None:
        return request_context_attrs(request_context)

    def map(
        self,
        tool_call: NormalizedToolCall,
        request_context: Mapping[str, Any],
    ) -> EvaluationRequest | None:
        return EvaluationRequest(
            subject=self._resolve_subject(request_context),
            action=Action(name=self._config.action_name),
            resource=self._resource(tool_call, request_context),
            context=self._context(request_context),
        )


class MCPResourceMapper(DefaultToolCallMapper):
    """Mapper for genuine MCP deployments: ``resource.id = "<server>/<tool>"``.

    Not the default, because tool calls extracted at the LLM API layer rarely carry MCP
    server provenance. Use when a server label is resolvable: fixed at construction, or —
    when ``server_label`` is ``None`` — read per call from
    ``request_context[MCP_SERVER_LABEL_KEY]`` (set by an MCP-boundary PEP such as the
    FastMCP middleware). Fails closed when neither is available. The tool segment gets the
    same case/whitespace normalisation as the default mapper (anti-evasion).
    """

    def __init__(self, config: ScannerConfig, *, server_label: str | None = None) -> None:
        super().__init__(config)
        self._server_label = server_label

    def _resource(
        self, tool_call: NormalizedToolCall, request_context: Mapping[str, Any]
    ) -> Resource:
        label = (
            self._server_label
            if self._server_label is not None
            else request_context.get(MCP_SERVER_LABEL_KEY)
        )
        if not isinstance(label, str):
            raise AuthZENConfigError(
                "MCPResourceMapper requires a server label (constructor or "
                f"request_context[{MCP_SERVER_LABEL_KEY!r}])"
            )
        return Resource(
            type="mcp_tool",
            id=mcp_resource_id(label, _normalize_tool_name(tool_call.name)),
            properties={"arguments": self._arguments(tool_call)},
        )


def _normalize_tool_name(name: str) -> str:
    """Normalise a tool name for use as a resource id (case/whitespace)."""
    return name.strip().lower()
