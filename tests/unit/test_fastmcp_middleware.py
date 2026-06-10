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

import httpx  # noqa: E402
from fastmcp import Client, FastMCP  # noqa: E402
from fastmcp.exceptions import McpError, ToolError  # noqa: E402
from fastmcp.server.auth.auth import AccessToken  # noqa: E402
from mcp.server.auth.middleware.auth_context import auth_context_var  # noqa: E402
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser  # noqa: E402

from apparitor import Subject  # noqa: E402
from apparitor.fastmcp import FastMCPAuthorizationMiddleware  # noqa: E402
from apparitor.mapping import subject_scope  # noqa: E402

_EVAL_URL = "http://pdp.test/access/v1/evaluation"
_BATCH_URL = "http://pdp.test/access/v1/evaluations"
_ALICE = Subject(type="user", id="alice@acme.com")


def _server(guard: FastMCPAuthorizationMiddleware) -> FastMCP:
    server = FastMCP("files")
    server.add_middleware(guard)

    @server.tool
    def read_file(path: str) -> str:
        return f"contents of {path}"

    @server.resource("resource://config")
    def config_resource() -> str:
        return "secret-config"

    @server.prompt
    def greet(name: str) -> str:
        return f"Hello {name}"

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
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": False})
    async with FastMCPAuthorizationMiddleware(config=make_config()) as guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                with pytest.raises(ToolError, match="not authorized"):
                    await client.call_tool("read_file", {"path": "/etc/passwd"})
    # The PDP was actually consulted — proving this is a genuine deny, not a subject-
    # resolution refusal that raises the same generic message without a round trip.
    assert route.call_count == 1


@pytest.mark.asyncio
async def test_pdp_error_fails_closed_without_leaking_detail(make_config, respx_mock) -> None:
    # PDP unreachable → BLOCK(status=ERROR) → refuse. The client-visible message must not
    # carry the engine's reason (PDP host, exception text, config hints).
    route = respx_mock.post(_EVAL_URL).respond(status_code=503)
    guard = FastMCPAuthorizationMiddleware(config=make_config(max_retries=0))
    async with guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                with pytest.raises(ToolError) as excinfo:
                    await client.call_tool("read_file", {"path": "/tmp/a"})
    assert route.call_count == 1  # reached the PDP, not a pre-engine refusal
    message = str(excinfo.value).lower()
    assert "not authorized" in message
    # None of the engine's reason text ("PDP unavailable: ...503...", "retr"y hints) leaks.
    for fragment in ("pdp", "unavailable", "503", "http", "retr", "subject", "config"):
        assert fragment not in message


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
    # Listing filter is opt-in (default off): listings pass through, no subject, no PDP.
    route = respx_mock.post(_EVAL_URL)
    guard = FastMCPAuthorizationMiddleware(config=make_config())
    async with guard, Client(_server(guard)) as client:
        tools = await client.list_tools()
    assert [t.name for t in tools] == ["read_file"]
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_concurrent_requests_use_their_own_token_subject(make_config, respx_mock) -> None:
    # Two interleaved sessions against ONE shared server/guard with distinct tokens must
    # never cross-contaminate the subject sent to the PDP — contextvar isolation under
    # asyncio concurrency, exercised on a single long-lived server instance.
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    guard = FastMCPAuthorizationMiddleware(config=make_config())
    server = _server(guard)

    async def call_as(sub: str) -> None:
        with _token({"sub": sub}, client_id=f"client-{sub}"):
            async with Client(server) as client:
                await client.call_tool("read_file", {"path": f"/home/{sub}"})

    async with guard:
        await asyncio.gather(call_as("bob@acme.com"), call_as("carol@acme.com"))
    subjects = {json.loads(call.request.content)["subject"]["id"] for call in route.calls}
    assert subjects == {"bob@acme.com", "carol@acme.com"}


@pytest.mark.asyncio
async def test_adapter_fault_refuses_without_leaking_or_executing(make_config, respx_mock) -> None:
    # The defense-in-depth catch-all: a fault the engine doesn't map (here a mapper raising
    # a non-AuthZENConfigError) must refuse with the generic message — never execute the
    # tool, never let the exception text reach the client.
    route = respx_mock.post(_EVAL_URL)

    class BoomMapper:
        def map(self, tool_call, request_context):
            raise RuntimeError("secret-internal-detail")

    guard = FastMCPAuthorizationMiddleware(config=make_config(), mapper=BoomMapper())
    async with guard, Client(_server(guard)) as client:
        with subject_scope(_ALICE), pytest.raises(ToolError) as excinfo:
            await client.call_tool("read_file", {"path": "/tmp/a"})
    assert route.call_count == 0
    assert "secret-internal-detail" not in str(excinfo.value)
    assert "not authorized" in str(excinfo.value).lower()


@pytest.mark.asyncio
async def test_subject_from_request_context_when_no_token(make_config, respx_mock) -> None:
    # Resolution step 2: a host-injected trusted subject (no token, no ambient scope).
    from apparitor.mapping import current_request_context

    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    async with FastMCPAuthorizationMiddleware(config=make_config(agent_id=None)) as guard:
        reset = current_request_context.set({"subject": Subject(type="svc", id="s-1")})
        try:
            async with Client(_server(guard)) as client:
                await client.call_tool("read_file", {"path": "/tmp/a"})
        finally:
            current_request_context.reset(reset)
    sent = json.loads(route.calls.last.request.content)
    assert sent["subject"]["id"] == "s-1"


@pytest.mark.asyncio
async def test_configurable_subject_claim_and_type(make_config, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    guard = FastMCPAuthorizationMiddleware(
        config=make_config(), subject_claim="email", subject_type="person"
    )
    async with guard:
        with _token({"email": "dana@acme.com"}):
            async with Client(_server(guard)) as client:
                await client.call_tool("read_file", {"path": "/tmp/a"})
    sent = json.loads(route.calls.last.request.content)
    assert sent["subject"]["type"] == "person"
    assert sent["subject"]["id"] == "dana@acme.com"


@pytest.mark.asyncio
async def test_mounted_server_uses_pinned_label_for_stable_key(make_config, respx_mock) -> None:
    # Under composition the server name the middleware sees differs across FastMCP versions,
    # so a pinned server_label is the documented way to keep policy keys stable. The mounted
    # tool is exposed under the prefix; the resource id must be "<label>/<prefixed tool>".
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    guard = FastMCPAuthorizationMiddleware(config=make_config(), server_label="gateway")
    parent = FastMCP("parent")
    parent.add_middleware(guard)
    child = FastMCP("child")

    @child.tool
    def read_file(path: str) -> str:
        return path

    parent.mount(child, prefix="files")
    async with guard:
        with subject_scope(_ALICE):
            async with Client(parent) as client:
                await client.call_tool("files_read_file", {"path": "/tmp/a"})
    sent = json.loads(route.calls.last.request.content)
    assert sent["resource"]["id"] == "gateway/files_read_file"


# --- workload (client-credentials) identities ----------------------------------------


@pytest.mark.asyncio
async def test_workload_token_authorized_with_opt_in(make_config, respx_mock) -> None:
    # A verified token without a sub claim maps to a DISTINCT subject type, so policies
    # written for users can never match a machine principal.
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    guard = FastMCPAuthorizationMiddleware(config=make_config(), allow_workload_subject=True)
    async with guard:
        with _token({"azp": "machine"}, client_id="svc-42"):
            async with Client(_server(guard)) as client:
                await client.call_tool("read_file", {"path": "/tmp/a"})
    sent = json.loads(route.calls.last.request.content)
    assert sent["subject"]["type"] == "workload"
    assert sent["subject"]["id"] == "svc-42"


@pytest.mark.asyncio
async def test_sub_claim_wins_over_workload_opt_in(make_config, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    guard = FastMCPAuthorizationMiddleware(config=make_config(), allow_workload_subject=True)
    async with guard:
        with _token({"sub": "alice@acme.com"}, client_id="svc-42"):
            async with Client(_server(guard)) as client:
                await client.call_tool("read_file", {"path": "/tmp/a"})
    sent = json.loads(route.calls.last.request.content)
    assert sent["subject"]["type"] == "user"
    assert sent["subject"]["id"] == "alice@acme.com"


# --- listing filter (opt-in, advisory) ------------------------------------------------


def _decide_by_resource_id(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    evaluations = [
        {"decision": "delete" not in item["resource"]["id"]} for item in body["evaluations"]
    ]
    return httpx.Response(200, json={"evaluations": evaluations})


@pytest.mark.asyncio
async def test_filter_listings_hides_denied_tools(make_config, respx_mock) -> None:
    route = respx_mock.post(_BATCH_URL).mock(side_effect=_decide_by_resource_id)
    guard = FastMCPAuthorizationMiddleware(config=make_config(), filter_listings=True)
    server = _server(guard)

    @server.tool
    def delete_database(name: str) -> str:
        return name

    async with guard:
        with subject_scope(_ALICE):
            async with Client(server) as client:
                tools = await client.list_tools()
    assert [tool.name for tool in tools] == ["read_file"]
    assert route.call_count == 1  # one batch round trip, not N singles


@pytest.mark.asyncio
async def test_filter_listings_hides_all_without_subject(make_config, respx_mock) -> None:
    route = respx_mock.post(_BATCH_URL)
    guard = FastMCPAuthorizationMiddleware(config=make_config(), filter_listings=True)
    async with guard, Client(_server(guard)) as client:
        tools = await client.list_tools()
    assert tools == []
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_filter_listings_hides_all_on_pdp_error(make_config, respx_mock) -> None:
    respx_mock.post(_BATCH_URL).respond(status_code=503)
    guard = FastMCPAuthorizationMiddleware(config=make_config(max_retries=0), filter_listings=True)
    async with guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                tools = await client.list_tools()
    assert tools == []


# --- resource gating (on by default) --------------------------------------------------


@pytest.mark.asyncio
async def test_resource_read_gated_and_allowed(make_config, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    async with FastMCPAuthorizationMiddleware(config=make_config()) as guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                contents = await client.read_resource("resource://config")
    assert "secret-config" in str(contents)
    sent = json.loads(route.calls.last.request.content)
    assert sent["action"]["name"] == "resource.read"
    assert sent["resource"]["type"] == "mcp_resource"
    assert sent["resource"]["id"] == "resource://config"
    assert sent["resource"]["properties"]["server"] == "files"


@pytest.mark.asyncio
async def test_resource_read_denied_with_generic_reason(make_config, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": False})
    async with FastMCPAuthorizationMiddleware(config=make_config()) as guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                with pytest.raises(McpError, match="not authorized"):
                    await client.read_resource("resource://config")
    assert route.call_count == 1  # a genuine PDP deny, not a subject-resolution refusal


@pytest.mark.asyncio
async def test_resource_pdp_error_fails_closed_without_leaking_detail(
    make_config, respx_mock
) -> None:
    route = respx_mock.post(_EVAL_URL).respond(status_code=503)
    guard = FastMCPAuthorizationMiddleware(config=make_config(max_retries=0))
    async with guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                with pytest.raises(McpError) as excinfo:
                    await client.read_resource("resource://config")
    assert route.call_count == 1
    message = str(excinfo.value).lower()
    assert "not authorized" in message
    for fragment in ("pdp", "unavailable", "503", "http", "retr", "config "):
        assert fragment not in message


@pytest.mark.asyncio
async def test_resource_gate_opt_out_passes_ungated(make_config, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL)
    guard = FastMCPAuthorizationMiddleware(config=make_config(), gate_resources=False)
    async with guard, Client(_server(guard)) as client:
        contents = await client.read_resource("resource://config")
    assert "secret-config" in str(contents)
    assert route.call_count == 0


# --- prompt gating (on by default) ----------------------------------------------------


@pytest.mark.asyncio
async def test_prompt_gated_and_allowed_with_server_scoped_key(make_config, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    async with FastMCPAuthorizationMiddleware(config=make_config()) as guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                result = await client.get_prompt("greet", {"name": "Bo"})
    assert "Hello Bo" in str(result)
    sent = json.loads(route.calls.last.request.content)
    assert sent["action"]["name"] == "prompt.get"
    assert sent["resource"]["type"] == "mcp_prompt"
    assert sent["resource"]["id"] == "files/greet"


@pytest.mark.asyncio
async def test_prompt_denied_with_generic_reason(make_config, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": False})
    async with FastMCPAuthorizationMiddleware(config=make_config()) as guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                with pytest.raises(McpError, match="not authorized"):
                    await client.get_prompt("greet", {"name": "Bo"})
    assert route.call_count == 1  # a genuine PDP deny, not a subject-resolution refusal


@pytest.mark.asyncio
async def test_prompt_gate_opt_out_passes_ungated(make_config, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL)
    guard = FastMCPAuthorizationMiddleware(config=make_config(), gate_prompts=False)
    async with guard, Client(_server(guard)) as client:
        result = await client.get_prompt("greet", {"name": "Bo"})
    assert "Hello Bo" in str(result)
    assert route.call_count == 0


# --- panel-review hardening cases -----------------------------------------------------


def test_workload_subject_type_is_reserved(make_config) -> None:
    with pytest.raises(ValueError, match="reserved"):
        FastMCPAuthorizationMiddleware(config=make_config(), subject_type="workload")
    with pytest.raises(ValueError, match="reserved"):
        FastMCPAuthorizationMiddleware(
            config=make_config(subject_type="workload"), allow_static_subject=True
        )


@pytest.mark.asyncio
async def test_workload_with_empty_client_id_refuses(make_config, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL)
    guard = FastMCPAuthorizationMiddleware(config=make_config(), allow_workload_subject=True)
    async with guard:
        with _token({"azp": "machine"}, client_id="  "):
            async with Client(_server(guard)) as client:
                with pytest.raises(ToolError, match="not authorized"):
                    await client.call_tool("read_file", {"path": "/tmp/a"})
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_prompt_pdp_error_fails_closed_without_leaking_detail(
    make_config, respx_mock
) -> None:
    route = respx_mock.post(_EVAL_URL).respond(status_code=503)
    guard = FastMCPAuthorizationMiddleware(config=make_config(max_retries=0))
    async with guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                with pytest.raises(McpError) as excinfo:
                    await client.get_prompt("greet", {"name": "Bo"})
    assert route.call_count == 1
    message = str(excinfo.value).lower()
    assert "not authorized" in message
    for fragment in ("pdp", "unavailable", "503", "http", "retr"):
        assert fragment not in message


@pytest.mark.asyncio
async def test_resource_human_review_refuses_distinctly(make_config, respx_mock) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": True, "context": {"step_up": True}})
    guard = FastMCPAuthorizationMiddleware(
        config=make_config(), review_predicate=lambda ctx: bool(ctx.get("step_up"))
    )
    async with guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                with pytest.raises(McpError, match="human approval"):
                    await client.read_resource("resource://config")


@pytest.mark.asyncio
async def test_prompt_name_with_separator_refuses(make_config, respx_mock) -> None:
    # An embedded "/" would make an ambiguous policy key; _prompt_request refuses it
    # before any PDP trip.
    route = respx_mock.post(_EVAL_URL)
    async with FastMCPAuthorizationMiddleware(config=make_config()) as guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                with pytest.raises(McpError, match="not authorized"):
                    await client.get_prompt("weird/name", {})
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_filter_listings_uses_call_time_keys_under_mount(make_config, respx_mock) -> None:
    # The listing filter must evaluate the SAME policy key the call gate will: the
    # client-visible (mount-prefixed) tool name — on both supported FastMCP lines, which
    # disagree about where that name lives on the listed Tool object.
    seen_ids: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen_ids.extend(item["resource"]["id"] for item in body["evaluations"])
        return httpx.Response(
            200, json={"evaluations": [{"decision": True}] * len(body["evaluations"])}
        )

    respx_mock.post(_BATCH_URL).mock(side_effect=respond)
    guard = FastMCPAuthorizationMiddleware(
        config=make_config(), server_label="gateway", filter_listings=True
    )
    parent = FastMCP("parent")
    parent.add_middleware(guard)
    child = FastMCP("child")

    @child.tool
    def read_file(path: str) -> str:
        return path

    parent.mount(child, prefix="files")
    async with guard:
        with subject_scope(_ALICE):
            async with Client(parent) as client:
                tools = await client.list_tools()
    assert [tool.name for tool in tools] == ["files_read_file"]
    # Identical to the resource id the mounted-call test pins for on_call_tool.
    assert seen_ids == ["gateway/files_read_file"]


@pytest.mark.asyncio
async def test_prompt_name_whitespace_is_kept_verbatim(make_config, respx_mock) -> None:
    # " greet " and "greet" are distinct FastMCP components; their policy keys must not
    # collapse onto each other (an ALLOW for one would silently cover the other), so the
    # name is consulted at the PDP verbatim rather than refused or trimmed.
    route = respx_mock.post(_EVAL_URL).respond(json={"decision": False})
    async with FastMCPAuthorizationMiddleware(config=make_config()) as guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                with pytest.raises(McpError, match="not authorized"):
                    await client.get_prompt(" greet ", {})
    assert route.call_count == 1
    sent = json.loads(route.calls.last.request.content)
    assert sent["resource"]["id"] == "files/ greet "


@pytest.mark.asyncio
async def test_whitespace_only_prompt_name_refuses(make_config, respx_mock) -> None:
    route = respx_mock.post(_EVAL_URL)
    async with FastMCPAuthorizationMiddleware(config=make_config()) as guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                with pytest.raises(McpError, match="not authorized"):
                    await client.get_prompt("   ", {})
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_unusable_server_label_refuses_prompt(make_config, respx_mock) -> None:
    # A label with an embedded "/" cannot form an unambiguous "<server>/<prompt>" key.
    route = respx_mock.post(_EVAL_URL)
    guard = FastMCPAuthorizationMiddleware(config=make_config(), server_label="bad/label")
    async with guard:
        with subject_scope(_ALICE):
            async with Client(_server(guard)) as client:
                with pytest.raises(McpError, match="not authorized"):
                    await client.get_prompt("greet", {})
    assert route.call_count == 0
