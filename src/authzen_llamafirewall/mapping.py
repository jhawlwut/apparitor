"""Mapping from a normalised tool call to an AuthZEN evaluation request.

A single extensibility seam — :class:`ToolCallMapper` — turns a tool call plus
request-scoped context into an :class:`~authzen_llamafirewall.models.EvaluationRequest`
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
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from .errors import AuthZENConfigError
from .models import Action, EvaluationRequest, Resource, Subject

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .adapters import NormalizedToolCall
    from .config import ScannerConfig

#: Request-scoped subject. Hosts set this (per request / per agent run) before the scanner
#: is invoked; the default mapper reads it here.
current_subject: contextvars.ContextVar[Subject | None] = contextvars.ContextVar(
    "authzen_current_subject", default=None
)

_REDACTED = "***redacted***"


def mcp_resource_id(server: str, tool: str) -> str:
    """Build a stable resource id for an MCP tool call.

    Bare MCP tool names (``search``, ``read``, ``query`` …) collide across servers, so a
    faithful authorization key is server-scoped: ``"<server>/<tool>"``.
    """
    server = server.strip().strip("/")
    tool = tool.strip().strip("/")
    if not server or not tool:
        raise AuthZENConfigError("mcp_resource_id requires non-empty server and tool")
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
            return dict.fromkeys(tool_call.arguments, _REDACTED)
        encoded = json.dumps(tool_call.arguments, sort_keys=True)
        if len(encoded.encode("utf-8")) > cfg.max_argument_bytes:
            return {"_truncated": True}
        return dict(tool_call.arguments)

    def _resource(self, tool_call: NormalizedToolCall) -> Resource:
        return Resource(
            type=self._config.resource_type,
            id=_normalize_tool_name(tool_call.name),
            properties={"arguments": self._arguments(tool_call)},
        )

    def _context(self, request_context: Mapping[str, Any]) -> dict[str, Any] | None:
        keys = ("conversation_id", "user_id", "correlation_id")
        ctx = {k: request_context[k] for k in keys if k in request_context}
        return ctx or None

    def map(
        self,
        tool_call: NormalizedToolCall,
        request_context: Mapping[str, Any],
    ) -> EvaluationRequest | None:
        return EvaluationRequest(
            subject=self._resolve_subject(request_context),
            action=Action(name=self._config.action_name),
            resource=self._resource(tool_call),
            context=self._context(request_context),
        )


class MCPResourceMapper(DefaultToolCallMapper):
    """Mapper for genuine MCP deployments: ``resource.id = "<server>/<tool>"``.

    Not the default, because tool calls extracted at the LLM API layer rarely carry MCP
    server provenance. Use when a server label is resolvable.
    """

    def __init__(self, config: ScannerConfig, *, server_label: str) -> None:
        super().__init__(config)
        self._server_label = server_label

    def _resource(self, tool_call: NormalizedToolCall) -> Resource:
        return Resource(
            type="mcp_tool",
            id=mcp_resource_id(self._server_label, tool_call.name),
            properties={"arguments": self._arguments(tool_call)},
        )


def _normalize_tool_name(name: str) -> str:
    """Normalise a tool name for use as a resource id (case/whitespace)."""
    return name.strip().lower()
