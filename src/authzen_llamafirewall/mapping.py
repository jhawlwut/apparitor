"""Mapping from a normalised tool call to an AuthZEN evaluation request.

A single extensibility seam — :class:`ToolCallMapper` — turns a tool call plus
request-scoped context into an :class:`~authzen_llamafirewall.models.EvaluationRequest`
(or ``None`` to abstain). Subject resolution, resource shaping and context enrichment
all live behind this one protocol rather than three, because in practice they read
from the same shared request context.

Subject identity is **request-scoped**, not static: the principal that matters for
authorization is usually the end user the agent is acting for, which arrives via the
host framework's run context — not via the ``Message``. The default mapper reads it
from the :data:`current_subject` context variable.

The default mapper's ``map`` body is intentionally deferred (this session ships the
contract, not the policy logic).
"""

from __future__ import annotations

import contextvars
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from .errors import AuthZENConfigError
from .models import EvaluationRequest, Subject

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .adapters import NormalizedToolCall
    from .config import ScannerConfig

#: Request-scoped subject. Hosts set this (per request / per agent run) before the
#: scanner is invoked; the default mapper reads it here.
current_subject: contextvars.ContextVar[Subject | None] = contextvars.ContextVar(
    "authzen_current_subject", default=None
)


def mcp_resource_id(server: str, tool: str) -> str:
    """Build a stable resource id for an MCP tool call.

    Bare MCP tool names (``search``, ``read``, ``query`` …) collide across servers, so
    a faithful authorization key is server-scoped: ``"<server>/<tool>"``.
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
    """Default mapper: ``{type:"tool", id:<tool name>}`` with args in resource props.

    Resolves the subject from :data:`current_subject` (falling back to the configured
    static agent subject), the action from ``config.action_name``, and forwards
    (optionally redacted, size-capped) arguments into ``resource.properties``.
    """

    def __init__(self, config: ScannerConfig) -> None:
        self._config = config

    def map(
        self,
        tool_call: NormalizedToolCall,
        request_context: Mapping[str, Any],
    ) -> EvaluationRequest | None:
        raise NotImplementedError("deferred: see docs/requirements.md §3 (mapping)")


class MCPResourceMapper(DefaultToolCallMapper):
    """Mapper for genuine MCP deployments: ``resource.id = "<server>/<tool>"``.

    Not the default, because tool calls extracted at the LLM API layer rarely carry
    MCP server provenance. Use when a server label is resolvable.
    """

    def __init__(self, config: ScannerConfig, *, server_label: str) -> None:
        super().__init__(config)
        self._server_label = server_label

    def map(
        self,
        tool_call: NormalizedToolCall,
        request_context: Mapping[str, Any],
    ) -> EvaluationRequest | None:
        raise NotImplementedError("deferred: see docs/requirements.md §3 (mapping)")
