"""Tool-call adapter tests — shape detection and normalisation per provider."""

from __future__ import annotations

import pytest

from apparitor.adapters import (
    AnthropicToolCallAdapter,
    LangChainToolCallAdapter,
    OpenAIToolCallAdapter,
    detect_adapter,
)

pytestmark = pytest.mark.unit


def test_openai_parses_json_string_arguments() -> None:
    adapter = OpenAIToolCallAdapter()
    raw = {"id": "1", "type": "function", "function": {"name": "f", "arguments": '{"a": 1}'}}
    assert adapter.matches(raw)
    norm = adapter.normalize(raw)
    assert norm.name == "f"
    assert norm.arguments == {"a": 1}
    assert norm.id == "1"


def test_openai_missing_name_raises() -> None:
    with pytest.raises(ValueError, match=r"function\.name"):
        OpenAIToolCallAdapter().normalize({"function": {"arguments": "{}"}})


def test_openai_invalid_json_arguments_raise() -> None:
    with pytest.raises(ValueError, match="not valid JSON"):
        OpenAIToolCallAdapter().normalize({"function": {"name": "f", "arguments": "{bad"}})


def test_openai_non_object_arguments_raise() -> None:
    with pytest.raises(ValueError, match="not a JSON object"):
        OpenAIToolCallAdapter().normalize({"function": {"name": "f", "arguments": "[1, 2]"}})


def test_anthropic_uses_input_dict() -> None:
    adapter = AnthropicToolCallAdapter()
    raw = {"type": "tool_use", "id": "t", "name": "read", "input": {"path": "/x"}}
    assert adapter.matches(raw)
    assert adapter.normalize(raw).arguments == {"path": "/x"}


def test_anthropic_missing_name_raises() -> None:
    with pytest.raises(ValueError, match="tool_use missing name"):
        AnthropicToolCallAdapter().normalize({"type": "tool_use", "input": {}})


def test_langchain_uses_args_dict() -> None:
    adapter = LangChainToolCallAdapter()
    raw = {"name": "search", "args": {"q": "x"}, "id": "l"}
    assert adapter.matches(raw)
    assert adapter.normalize(raw).arguments == {"q": "x"}


def test_langchain_missing_name_raises() -> None:
    with pytest.raises(ValueError, match="LangChain tool call missing name"):
        LangChainToolCallAdapter().normalize({"args": {}, "name": ""})


def test_unsupported_argument_type_raises() -> None:
    # An int payload is neither a JSON string nor a dict.
    with pytest.raises(ValueError, match="unsupported tool-call arguments type"):
        AnthropicToolCallAdapter().normalize({"type": "tool_use", "name": "x", "input": 5})


def test_none_arguments_default_to_empty() -> None:
    norm = AnthropicToolCallAdapter().normalize({"type": "tool_use", "name": "x"})
    assert norm.arguments == {}


@pytest.mark.parametrize(
    ("raw", "adapter_type"),
    [
        ({"function": {"name": "f"}}, OpenAIToolCallAdapter),
        ({"type": "tool_use", "name": "n"}, AnthropicToolCallAdapter),
        ({"name": "n", "args": {}}, LangChainToolCallAdapter),
    ],
)
def test_detect_adapter_picks_right_provider(raw: dict, adapter_type: type) -> None:
    assert isinstance(detect_adapter(raw), adapter_type)


def test_detect_adapter_none_for_unknown() -> None:
    assert detect_adapter({"nope": True}) is None
