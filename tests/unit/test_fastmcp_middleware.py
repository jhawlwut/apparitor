"""FastMCP middleware adapter tests — verdict → execute/refuse mapping over a real server.

Requires fastmcp (the adapter's only hard dependency); skipped automatically when it is not
installed (a dedicated CI job installs ``[fastmcp]`` to run these). The server is driven
end-to-end through FastMCP's in-memory transport; the PDP is mocked with respx, exactly like
the scanner/nemo tests. Token identity is bound through the MCP SDK's auth contextvar — the
seam FastMCP's HTTP auth middleware populates for a verified request — so per-request and
concurrent identity behave as they do over a real transport.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

pytestmark = pytest.mark.unit

pytest.importorskip("fastmcp")

from fastmcp import Client, FastMCP  # noqa: E402
from fastmcp.exceptions import ToolError  # noqa: E402
from fastmcp.server.auth.auth import AccessToken  # noqa: E402
from mcp.server.auth.middleware.auth_context import auth_context_var  # noqa: E402
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser  # noqa: E402

from apparitor import Subject  # noqa: E402
from apparitor.fastmcp import FastMCPAuthorizationMiddleware  # noqa: E402
from apparitor.mapping import subject_scope  # noqa: E402

_EVAL_URL = "http://pdp.test/access/v1/evaluation"
_ALICE = Subject(type="user", id="alice@acme.com")


def _server(guard: FastMCPAuthorizationMiddleware) -> FastMCP:
    server = FastMCP("files")
    server.add_middleware(guard)

    @server.tool
    def read_file(path: str) -> str:
        return f"contents of {path}"

    return server


@contextmanager
def _token(claims: dict[str, object], client_id: str = "client-1") -> Iterator[None]:
    """Bind a verified access token the way FastMCP's auth middleware does per request."""
    user = AuthenticatedUser(
        AccessToken(token="opaque", client_id=client_id, scopes=["files:read"], claims=claims)
    )
    reset = auth_context_var.set(user)
    try:
        yield
    finally:
        auth_context_var.reset(reset)


def test_constructor_requires_pdp_url_or_config() -> None:
    with pytest.raises(ValueError, match="pdp_url or config"):
        FastMCPAuthorizationMiddleware()


@pytest.mark.asyncio
async def test_allowed_call_executes(make_config, respx_mock) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    async with FastMCPAuthorizationMiddleware(config=make_config()) as guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                result = await client.call_tool("read_file", {"path": "/tmp/a"})
    assert result.data == "contents of /tmp/a"


@pytest.mark.asyncio
async def test_denied_call_refused_with_generic_reason(make_config, respx_mock) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": False})
    async with FastMCPAuthorizationMiddleware(config=make_config()) as guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                with pytest.raises(ToolError, match="not authorized"):
                    await client.call_tool("read_file", {"path": "/etc/passwd"})


@pytest.mark.asyncio
async def test_pdp_error_fails_closed_without_leaking_detail(make_config, respx_mock) -> None:
    # PDP unreachable → BLOCK(status=ERROR) → refuse. The client-visible message must not
    # carry the engine's reason (PDP host, exception text, config hints).
    respx_mock.post(_EVAL_URL).respond(status_code=503)
    guard = FastMCPAuthorizationMiddleware(config=make_config(max_retries=0))
    async with guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                with pytest.raises(ToolError) as excinfo:
                    await client.call_tool("read_file", {"path": "/tmp/a"})
    message = str(excinfo.value)
    assert "not authorized" in message
    for fragment in ("pdp", "503", "http", "subject", "config"):
        assert fragment not in message.lower()


@pytest.mark.asyncio
async def test_no_subject_refuses_without_consulting_pdp(make_config, respx_mock) -> None:
    # agent_id is configured but allow_static_subject defaults to False: an anonymous
    # caller must NOT be authorized as the static agent (confused deputy).
    route = respx_mock.post(_EVAL_URL)
    guard = FastMCPAuthorizationMiddleware(config=make_config(agent_id="bot-123"))
    async with guard, Client(_server(guard)) as client:
        with pytest.raises(ToolError, match="not authorized"):
            await client.call_tool("read_file", {"path": "/tmp/a"})
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_static_subject_requires_opt_in(make_config, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    guard = FastMCPAuthorizationMiddleware(
        config=make_config(agent_id="bot-123"), allow_static_subject=True
    )
    async with guard, Client(_server(guard)) as client:
        await client.call_tool("read_file", {"path": "/tmp/a"})
    sent = json.loads(route.calls.last.request.content)
    assert sent["subject"]["type"] == "agent"
    assert sent["subject"]["id"] == "bot-123"


@pytest.mark.asyncio
async def test_token_subject_wins_over_ambient_subject(make_config, respx_mock) -> None:
    # A validated token outranks a host-bound subject_scope; client_id/scopes ride along
    # as subject properties for ABAC policies.
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    async with FastMCPAuthorizationMiddleware(config=make_config()) as guard:
        with (
            subject_scope(Subject(type="user", id="mallory@acme.com")),
            _token({"sub": "alice@acme.com"}),
        ):
            async with Client(_server(guard)) as client:
                await client.call_tool("read_file", {"path": "/tmp/a"})
    sent = json.loads(route.calls.last.request.content)
    assert sent["subject"]["type"] == "user"
    assert sent["subject"]["id"] == "alice@acme.com"
    assert sent["subject"]["properties"] == {"client_id": "client-1", "scopes": ["files:read"]}


@pytest.mark.asyncio
async def test_token_without_sub_claim_refuses_with_no_fallback(make_config, respx_mock) -> None:
    # A client-credentials (workload) token must never be downgraded to the static
    # subject, even when the static fallback is opted in.
    route = respx_mock.post(_EVAL_URL)
    guard = FastMCPAuthorizationMiddleware(
        config=make_config(agent_id="bot-123"), allow_static_subject=True
    )
    async with guard:
        with _token({"azp": "machine-client"}):
            async with Client(_server(guard)) as client:
                with pytest.raises(ToolError, match="not authorized"):
                    await client.call_tool("read_file", {"path": "/tmp/a"})
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_resource_id_is_server_scoped(make_config, respx_mock) -> None:
    # Default mapper is MCPResourceMapper with the label derived from the server name.
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    async with FastMCPAuthorizationMiddleware(config=make_config()) as guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                await client.call_tool("read_file", {"path": "/tmp/a"})
    sent = json.loads(route.calls.last.request.content)
    assert sent["resource"]["type"] == "mcp_tool"
    assert sent["resource"]["id"] == "files/read_file"


@pytest.mark.asyncio
async def test_server_label_overrides_server_name(make_config, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    guard = FastMCPAuthorizationMiddleware(config=make_config(), server_label="vault")
    async with guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                await client.call_tool("read_file", {"path": "/tmp/a"})
    sent = json.loads(route.calls.last.request.content)
    assert sent["resource"]["id"] == "vault/read_file"


@pytest.mark.asyncio
async def test_human_review_refuses_distinctly(make_config, respx_mock) -> None:
    # A clean ALLOW escalated by a review predicate refuses with the human-approval
    # message (distinct from a deny, so hosts can build escalation), still generic.
    respx_mock.post(_EVAL_URL).respond(json={"decision": True, "context": {"step_up": True}})
    guard = FastMCPAuthorizationMiddleware(
        config=make_config(), review_predicate=lambda ctx: bool(ctx.get("step_up"))
    )
    async with guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                with pytest.raises(ToolError, match="human approval"):
                    await client.call_tool("read_file", {"path": "/tmp/a"})


@pytest.mark.asyncio
async def test_mapper_abstention_refuses(make_config, respx_mock) -> None:
    # SKIP can only mean the mapper abstained (exactly one call is always submitted);
    # executing the tool anyway would be an authorization bypass.
    route = respx_mock.post(_EVAL_URL)
    guard = FastMCPAuthorizationMiddleware(
        config=make_config(), mapper=type("Abstain", (), {"map": lambda self, tc, ctx: None})()
    )
    async with guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                with pytest.raises(ToolError, match="not authorized"):
                    await client.call_tool("read_file", {"path": "/tmp/a"})
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_list_tools_passes_ungated(make_config, respx_mock) -> None:
    # v1 gates tools/call only; listings pass through without a subject or a PDP trip.
    route = respx_mock.post(_EVAL_URL)
    guard = FastMCPAuthorizationMiddleware(config=make_config())
    async with guard, Client(_server(guard)) as client:
        tools = await client.list_tools()
    assert [t.name for t in tools] == ["read_file"]
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_concurrent_requests_use_their_own_token_subject(make_config, respx_mock) -> None:
    # Two interleaved sessions with distinct tokens must never cross-contaminate the
    # subject sent to the PDP (contextvar isolation under asyncio concurrency).
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    guard = FastMCPAuthorizationMiddleware(config=make_config())

    async def call_as(sub: str) -> None:
        with _token({"sub": sub}, client_id=f"client-{sub}"):
            async with Client(_server(guard)) as client:
                await client.call_tool("read_file", {"path": f"/home/{sub}"})

    async with guard:
        await asyncio.gather(call_as("bob@acme.com"), call_as("carol@acme.com"))
    subjects = {json.loads(call.request.content)["subject"]["id"] for call in route.calls}
    assert subjects == {"bob@acme.com", "carol@acme.com"}
