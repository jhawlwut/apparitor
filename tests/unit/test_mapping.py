"""Mapper tests — subject resolution, resource shaping, argument handling."""

from __future__ import annotations

import pytest

from apparitor.adapters import NormalizedToolCall
from apparitor.errors import AuthZENConfigError
from apparitor.mapping import (
    DefaultToolCallMapper,
    MCPResourceMapper,
    current_subject,
)
from apparitor.models import Subject

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


def test_redacted_arguments_are_also_size_capped(make_config) -> None:
    cfg = make_config(redact_arguments=True, max_argument_bytes=4)
    req = DefaultToolCallMapper(cfg).map(_call(aaa=1, bbb=2, ccc=3), {})
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
    from apparitor.mapping import mcp_resource_id

    with pytest.raises(AuthZENConfigError):
        mcp_resource_id("", "read")
    with pytest.raises(AuthZENConfigError):
        mcp_resource_id("files", "  ")


def test_mcp_resource_id_rejects_embedded_separator() -> None:
    # "a/b" + "read" and "a" + "b/read" would collide on the same ambiguous policy key.
    from apparitor.mapping import mcp_resource_id

    with pytest.raises(AuthZENConfigError):
        mcp_resource_id("a/b", "read")
    with pytest.raises(AuthZENConfigError):
        mcp_resource_id("files", "b/read")


def test_mcp_mapper_reads_label_from_request_context(make_config) -> None:
    from apparitor.mapping import MCP_SERVER_LABEL_KEY

    mapper = MCPResourceMapper(make_config())
    req = mapper.map(_call("read"), {MCP_SERVER_LABEL_KEY: "files"})
    assert req is not None
    assert req.resource.id == "files/read"


def test_mcp_mapper_constructor_label_wins_over_context(make_config) -> None:
    from apparitor.mapping import MCP_SERVER_LABEL_KEY

    mapper = MCPResourceMapper(make_config(), server_label="vault")
    req = mapper.map(_call("read"), {MCP_SERVER_LABEL_KEY: "files"})
    assert req is not None
    assert req.resource.id == "vault/read"


def test_mcp_mapper_without_label_fails_closed(make_config) -> None:
    with pytest.raises(AuthZENConfigError):
        MCPResourceMapper(make_config()).map(_call("read"), {})


def test_mcp_mapper_empty_constructor_label_fails_closed_not_context(make_config) -> None:
    # An explicit "" label is a misconfiguration: it must fail closed, not silently fall
    # through to the request-context label (constructor precedence is `is not None`).
    from apparitor.mapping import MCP_SERVER_LABEL_KEY

    mapper = MCPResourceMapper(make_config(), server_label="")
    with pytest.raises(AuthZENConfigError):
        mapper.map(_call("read"), {MCP_SERVER_LABEL_KEY: "files"})


def test_mcp_mapper_normalizes_tool_segment(make_config) -> None:
    # Same case/whitespace anti-evasion as the default mapper's resource id.
    req = MCPResourceMapper(make_config(), server_label="files").map(_call("  Read  "), {})
    assert req is not None
    assert req.resource.id == "files/read"


def test_subject_scope_sets_and_resets() -> None:
    from apparitor.mapping import subject_scope

    assert current_subject.get() is None
    with subject_scope(Subject(type="user", id="alice")):
        assert current_subject.get() == Subject(type="user", id="alice")
    assert current_subject.get() is None  # always reset, even though no token juggling


def test_request_context_scope_sets_clears_and_is_exception_safe() -> None:
    from apparitor.mapping import current_request_context, request_context_scope

    assert current_request_context.get() is None

    ctx = {"conversation_id": "c-42", "user_id": "alice@acme.com"}
    with request_context_scope(ctx):
        assert current_request_context.get() == ctx

    # Cleared after normal exit.
    assert current_request_context.get() is None

    # Also cleared when the block raises.
    try:
        with request_context_scope({"x": "y"}):
            assert current_request_context.get() == {"x": "y"}
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    assert current_request_context.get() is None


def test_non_json_arguments_are_made_safe(make_config) -> None:
    # A non-JSON value (a set) must not crash serialisation; it is stringified.
    cfg = make_config(redact_arguments=False)
    req = DefaultToolCallMapper(cfg).map(_call(tags={"a", "b"}), {})
    assert req is not None
    args = req.resource.properties["arguments"]
    assert isinstance(args["tags"], str)  # stringified, JSON-serialisable


def test_request_context_attrs_are_made_json_safe(make_config) -> None:
    # A host-supplied non-JSON attr (e.g. a UUID correlation id) must not crash request
    # serialisation downstream; it is stringified, like exotic tool-argument values.
    import uuid

    correlation = uuid.uuid4()
    req = DefaultToolCallMapper(make_config()).map(_call(), {"correlation_id": correlation})
    assert req is not None
    assert req.context == {"correlation_id": str(correlation)}


# --- dual-principal (user AND agent) mapping ------------------------------------------


def test_dual_principal_emits_one_request_per_principal(make_config) -> None:
    from apparitor.mapping import DualPrincipalMapper, subject_scope

    mapper = DualPrincipalMapper(make_config(agent_id="travel-bot"))
    with subject_scope(Subject(type="user", id="alice@acme.com")):
        requests = mapper.map(_call("read"), {})
    assert isinstance(requests, list) and len(requests) == 2
    assert [r.subject.id for r in requests] == ["alice@acme.com", "travel-bot"]
    assert requests[0].subject.type == "user"
    assert requests[1].subject.type == "agent"
    # Both legs evaluate the SAME action/resource — only the principal differs.
    assert requests[0].resource == requests[1].resource
    assert requests[0].action == requests[1].action


def test_dual_principal_accepts_explicit_agent_subject(make_config) -> None:
    from apparitor.mapping import DualPrincipalMapper

    mapper = DualPrincipalMapper(
        make_config(agent_id=None), agent_subject=Subject(type="agent", id="ops-bot")
    )
    requests = mapper.map(_call("read"), {"subject": Subject(type="user", id="bo@acme.com")})
    assert [r.subject.id for r in requests] == ["bo@acme.com", "ops-bot"]


def test_dual_principal_requires_agent_principal(make_config) -> None:
    from apparitor.mapping import DualPrincipalMapper

    with pytest.raises(AuthZENConfigError, match="agent principal"):
        DualPrincipalMapper(make_config(agent_id=None))


def test_dual_principal_rejects_workload_agent_subject(make_config) -> None:
    from apparitor.mapping import DualPrincipalMapper

    with pytest.raises(AuthZENConfigError, match="reserved"):
        DualPrincipalMapper(make_config(), agent_subject=Subject(type="workload", id="svc-1"))


def test_dual_principal_requires_request_scoped_user(make_config) -> None:
    # The agent_id fallback must NOT apply to the user leg: that would collapse the
    # AND into a single principal.
    from apparitor.mapping import DualPrincipalMapper

    mapper = DualPrincipalMapper(make_config(agent_id="travel-bot"))
    with pytest.raises(AuthZENConfigError, match="request-scoped user subject"):
        mapper.map(_call("read"), {})


def test_dual_principal_rejects_user_equal_to_agent(make_config) -> None:
    # A "user" leg that IS the agent (e.g. an upstream static-subject fallback injecting
    # the agent as the request subject) collapses the AND into one principal — refuse.
    from apparitor.mapping import DualPrincipalMapper

    mapper = DualPrincipalMapper(make_config(agent_id="travel-bot"))
    with pytest.raises(AuthZENConfigError, match="distinct principals"):
        mapper.map(_call("read"), {"subject": Subject(type="agent", id="travel-bot")})


def test_dual_principal_warns_once_about_bypassed_cache(make_config, caplog) -> None:
    # The opt-in ALLOW cache is a single-request fast path; dual evaluation always
    # batches, so enabling both deserves a loud construction-time warning.
    import logging

    from apparitor.mapping import DualPrincipalMapper

    with caplog.at_level(logging.WARNING, logger="apparitor"):
        DualPrincipalMapper(make_config(agent_id="travel-bot", cache_enabled=True))
    assert "never be consulted" in caplog.text


# --- build_boundary_leg ---------------------------------------------------------------


def test_build_boundary_leg_returns_boundary_subject_with_same_action_and_context() -> None:
    from apparitor.mapping import build_boundary_leg
    from apparitor.models import Action, EvaluationRequest, Resource

    caller = Subject(type="agent", id="planner")
    boundary = Subject(type="agent", id="travel-bot")
    primary = EvaluationRequest(
        subject=caller,
        action=Action(name="agent.invoke"),
        resource=Resource(type="a2a_agent", id="demo"),
        context={"tenant": "acme"},
    )
    leg = build_boundary_leg(primary, boundary, caller_subject=caller)
    assert leg.subject == boundary
    assert leg.action == primary.action
    # Both legs carry the same context VALUE (equal dicts at the PDP; pydantic copies on
    # construction) — the A2A tenant context must reach both the caller and boundary leg.
    assert leg.context == primary.context


def test_build_boundary_leg_deep_copies_resource() -> None:
    # Mutating the boundary leg's resource must not affect the primary leg (and vice versa).
    from apparitor.mapping import build_boundary_leg
    from apparitor.models import Action, EvaluationRequest, Resource

    caller = Subject(type="user", id="alice")
    boundary = Subject(type="agent", id="travel-bot")
    primary = EvaluationRequest(
        subject=caller,
        action=Action(name="resource.read"),
        resource=Resource(type="mcp_resource", id="resource://config", properties={"k": "v"}),
        context=None,
    )
    leg = build_boundary_leg(primary, boundary, caller_subject=caller)
    assert leg.resource is not primary.resource
    leg.resource.properties["k"] = "mutated"
    assert primary.resource.properties["k"] == "v"


def test_build_boundary_leg_collapse_guard_raises() -> None:
    # The AND would silently collapse to a single-principal check when both legs have
    # the same subject — refuse rather than let a misconfiguration go unnoticed.
    from apparitor.mapping import build_boundary_leg
    from apparitor.models import Action, EvaluationRequest, Resource

    same = Subject(type="agent", id="travel-bot")
    primary = EvaluationRequest(
        subject=same,
        action=Action(name="agent.invoke"),
        resource=Resource(type="a2a_agent", id="demo"),
        context=None,
    )
    with pytest.raises(AuthZENConfigError, match="distinct"):
        build_boundary_leg(primary, same, caller_subject=same)
