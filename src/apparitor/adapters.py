"""Provider-aware extraction of tool calls from LlamaFirewall messages.

``Message.tool_calls`` is typed ``list[dict] | None`` and is **not** normalised by
LlamaFirewall — its shape depends entirely on the integrating framework:

* **OpenAI**     ``{"id", "type": "function", "function": {"name", "arguments": "<JSON str>"}}``
  (note: ``arguments`` is a JSON-encoded *string*).
* **Anthropic**  ``{"type": "tool_use", "id", "name", "input": {...}}``
* **LangChain**  ``{"name", "args": {...}, "id"}``

A naive ``tc["name"]`` silently fails on OpenAI. These adapters detect the shape and
normalise to :class:`NormalizedToolCall`. This module is pure (no I/O, no
LlamaFirewall import) and is implemented now because mis-extraction is an
authorization-bypass risk, not merely a bug.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class NormalizedToolCall:
    """A tool call reduced to the fields authorization cares about."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    id: str | None = None


@runtime_checkable
class ToolCallAdapter(Protocol):
    """Detects and normalises one provider's tool-call dict shape."""

    def matches(self, raw: dict[str, Any]) -> bool:
        """Return ``True`` if ``raw`` looks like this provider's shape."""
        ...

    def normalize(self, raw: dict[str, Any]) -> NormalizedToolCall:
        """Convert ``raw`` to a :class:`NormalizedToolCall`. May raise ``ValueError``."""
        ...


def _coerce_args(value: Any) -> dict[str, Any]:
    """Coerce a tool-call argument payload into a dict.

    OpenAI encodes arguments as a JSON string; everything else uses a dict. A
    non-dict / unparseable payload raises ``ValueError`` so the caller can fail
    closed rather than guess.
    """
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"tool-call arguments are not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValueError("decoded tool-call arguments are not a JSON object")
        return parsed
    raise ValueError(f"unsupported tool-call arguments type: {type(value).__name__}")


class OpenAIToolCallAdapter:
    """OpenAI / Azure OpenAI function-calling shape."""

    def matches(self, raw: dict[str, Any]) -> bool:
        return isinstance(raw.get("function"), dict) or raw.get("type") == "function"

    def normalize(self, raw: dict[str, Any]) -> NormalizedToolCall:
        fn = raw.get("function")
        if not isinstance(fn, dict) or not fn.get("name"):
            raise ValueError("OpenAI tool call missing function.name")
        return NormalizedToolCall(
            name=str(fn["name"]),
            arguments=_coerce_args(fn.get("arguments")),
            id=raw.get("id"),
        )


class AnthropicToolCallAdapter:
    """Anthropic raw ``tool_use`` block shape."""

    def matches(self, raw: dict[str, Any]) -> bool:
        return raw.get("type") == "tool_use"

    def normalize(self, raw: dict[str, Any]) -> NormalizedToolCall:
        if not raw.get("name"):
            raise ValueError("Anthropic tool_use missing name")
        return NormalizedToolCall(
            name=str(raw["name"]),
            arguments=_coerce_args(raw.get("input")),
            id=raw.get("id"),
        )


class LangChainToolCallAdapter:
    """LangChain-normalised tool-call shape (``{name, args, id}``)."""

    def matches(self, raw: dict[str, Any]) -> bool:
        return "args" in raw and "name" in raw

    def normalize(self, raw: dict[str, Any]) -> NormalizedToolCall:
        if not raw.get("name"):
            raise ValueError("LangChain tool call missing name")
        return NormalizedToolCall(
            name=str(raw["name"]),
            arguments=_coerce_args(raw.get("args")),
            id=raw.get("id"),
        )


# Detection order matters: most specific shapes first.
_DEFAULT_ADAPTERS: tuple[ToolCallAdapter, ...] = (
    AnthropicToolCallAdapter(),
    OpenAIToolCallAdapter(),
    LangChainToolCallAdapter(),
)


def detect_adapter(
    raw: dict[str, Any],
    adapters: tuple[ToolCallAdapter, ...] = _DEFAULT_ADAPTERS,
) -> ToolCallAdapter | None:
    """Return the first adapter whose ``matches`` accepts ``raw``, or ``None``.

    A ``None`` result means the shape is unrecognised; per the threat model the
    caller must fail closed (BLOCK), never skip.
    """
    for adapter in adapters:
        if adapter.matches(raw):
            return adapter
    return None
