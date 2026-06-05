"""Mapper tests — subject resolution, resource shaping, argument handling."""

from __future__ import annotations

import pytest

from authzen_llamafirewall.adapters import NormalizedToolCall
from authzen_llamafirewall.errors import AuthZENConfigError
from authzen_llamafirewall.mapping import (
    DefaultToolCallMapper,
    MCPResourceMapper,
    current_subject,
)
from authzen_llamafirewall.models import Subject

pytestmark = pytest.mark.unit


def _call(name: str = "Delete_Table", **args: object) -> NormalizedToolCall:
    return NormalizedToolCall(name=name, arguments=dict(args), id="c1")


def test_subject_from_context_var(make_config) -> None:
    cfg = make_config(agent_id=None)
    mapper = DefaultToolCallMapper(cfg)
    token = current_subject.set(Subject(type="user", id="alice"))
    try:
        req = mapper.map(_call(), {})
    finally:
        current_subject.reset(token)
    assert req is not None
    assert req.subject.id == "alice"


def test_subject_from_config_agent_id(make_config) -> None:
    req = DefaultToolCallMapper(make_config(agent_id="bot-9")).map(_call(), {})
    assert req is not None
    assert req.subject == Subject(type="agent", id="bot-9")


def test_subject_from_request_context(make_config) -> None:
    req = DefaultToolCallMapper(make_config(agent_id=None)).map(
        _call(), {"subject": Subject(type="svc", id="s1")}
    )
    assert req is not None
    assert req.subject.id == "s1"


def test_missing_subject_fails_closed(make_config) -> None:
    mapper = DefaultToolCallMapper(make_config(agent_id=None))
    with pytest.raises(AuthZENConfigError):
        mapper.map(_call(), {})


def test_resource_id_is_normalized(make_config) -> None:
    req = DefaultToolCallMapper(make_config()).map(_call("  Delete_Table  "), {})
    assert req is not None
    assert req.resource.id == "delete_table"
    assert req.resource.type == "tool"


def test_arguments_redacted_by_default(make_config) -> None:
    req = DefaultToolCallMapper(make_config()).map(_call(path="/etc/passwd"), {})
    assert req is not None
    assert req.resource.properties["arguments"] == {"path": "***redacted***"}


def test_arguments_passthrough_when_not_redacted(make_config) -> None:
    cfg = make_config(redact_arguments=False)
    req = DefaultToolCallMapper(cfg).map(_call(path="/tmp/x"), {})
    assert req is not None
    assert req.resource.properties["arguments"] == {"path": "/tmp/x"}


def test_arguments_truncated_when_oversized(make_config) -> None:
    cfg = make_config(redact_arguments=False, max_argument_bytes=8)
    req = DefaultToolCallMapper(cfg).map(_call(blob="x" * 1000), {})
    assert req is not None
    assert req.resource.properties["arguments"] == {"_truncated": True}


def test_arguments_dropped_when_forwarding_disabled(make_config) -> None:
    cfg = make_config(forward_arguments=False)
    req = DefaultToolCallMapper(cfg).map(_call(path="/x"), {})
    assert req is not None
    assert req.resource.properties["arguments"] == {}


def test_context_only_includes_known_keys(make_config) -> None:
    req = DefaultToolCallMapper(make_config()).map(
        _call(), {"conversation_id": "c", "secret": "nope"}
    )
    assert req is not None
    assert req.context == {"conversation_id": "c"}


def test_mcp_mapper_server_scopes_resource_id(make_config) -> None:
    req = MCPResourceMapper(make_config(), server_label="files").map(_call("read"), {})
    assert req is not None
    assert req.resource.type == "mcp_tool"
    assert req.resource.id == "files/read"


def test_mcp_resource_id_rejects_empty_parts() -> None:
    from authzen_llamafirewall.mapping import mcp_resource_id

    with pytest.raises(AuthZENConfigError):
        mcp_resource_id("", "read")
    with pytest.raises(AuthZENConfigError):
        mcp_resource_id("files", "  ")


def test_subject_scope_sets_and_resets() -> None:
    from authzen_llamafirewall.mapping import subject_scope

    assert current_subject.get() is None
    with subject_scope(Subject(type="user", id="alice")):
        assert current_subject.get() == Subject(type="user", id="alice")
    assert current_subject.get() is None  # always reset, even though no token juggling


def test_non_json_arguments_are_made_safe(make_config) -> None:
    # A non-JSON value (a set) must not crash serialisation; it is stringified.
    cfg = make_config(redact_arguments=False)
    req = DefaultToolCallMapper(cfg).map(_call(tags={"a", "b"}), {})
    assert req is not None
    args = req.resource.properties["arguments"]
    assert isinstance(args["tags"], str)  # stringified, JSON-serialisable
