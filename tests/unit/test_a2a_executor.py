"""A2A executor adapter tests — verdict → execute/refuse mapping over a real A2A server.

Requires a2a-sdk with its [http-server] extra (the in-process JSON-RPC harness); skipped
automatically when it is not installed (a dedicated CI job installs it). The server is
driven end-to-end: Starlette routes over ``httpx.ASGITransport``, the official A2A client
on top. The PDP is mocked with ``httpx.MockTransport`` on a bring-your-own client — NOT
respx, which would also intercept the in-process A2A client's httpx traffic. Caller
identity is injected through a custom ``ServerCallContextBuilder`` — the exact seam a
deployment's authentication middleware populates.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

pytestmark = pytest.mark.unit

pytest.importorskip("a2a")
pytest.importorskip("sse_starlette")  # the SDK's [http-server] extra

import a2a.types as t  # noqa: E402
from a2a.auth.user import User  # noqa: E402
from a2a.client import ClientConfig, ClientFactory  # noqa: E402
from a2a.server.agent_execution import AgentExecutor, RequestContext  # noqa: E402
from a2a.server.context import ServerCallContext  # noqa: E402
from a2a.server.events import EventQueue  # noqa: E402
from a2a.server.request_handlers import DefaultRequestHandler  # noqa: E402
from a2a.server.routes import (  # noqa: E402
    DefaultServerCallContextBuilder,
    ServerCallContextBuilder,
    create_jsonrpc_routes,
)
from a2a.server.tasks import InMemoryTaskStore  # noqa: E402
from starlette.applications import Starlette  # noqa: E402

from apparitor import Subject  # noqa: E402
from apparitor.a2a import A2AAuthorizationExecutor  # noqa: E402
from apparitor.mapping import subject_scope  # noqa: E402

_ALICE = Subject(type="user", id="alice@acme.com")

_CARD = t.AgentCard(
    name="travel-agent",
    description="demo",
    version="1",
    supported_interfaces=[t.AgentInterface(url="http://test/a2a", protocol_binding="JSONRPC")],
    capabilities=t.AgentCapabilities(streaming=False),
    default_input_modes=["text"],
    default_output_modes=["text"],
    skills=[t.AgentSkill(id="book_flight", name="book_flight", description="b", tags=[])],
)


class _Peer(User):
    """An authenticated A2A peer, as a deployment's authn middleware would establish."""

    def __init__(self, name: str) -> None:
        self._name = name

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def user_name(self) -> str:
        return self._name


class _ContextBuilder(DefaultServerCallContextBuilder):
    """Injects a fixed user/tenant — the seam real authn middleware populates — while
    keeping the default builder's header/version handling intact."""

    def __init__(self, user: User | None = None, tenant: str = "") -> None:
        self._user = user
        self._tenant = tenant

    def build(self, request: Any) -> ServerCallContext:
        context = super().build(request)
        if self._user is not None:
            context.user = self._user
        if self._tenant:
            context.tenant = self._tenant
        return context


class _EchoExecutor(AgentExecutor):
    """The guarded delegate; records whether it actually ran."""

    def __init__(self) -> None:
        self.executed = 0
        self.cancelled = 0

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        self.executed += 1
        reply = t.Message(
            message_id="r1",
            role=t.Role.ROLE_AGENT,
            parts=[t.Part(text="booked")],
            context_id=context.context_id or "",
            task_id=context.task_id or "",
        )
        await event_queue.enqueue_event(reply)

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        self.cancelled += 1


class _PDP:
    """An httpx.MockTransport PDP capturing every evaluation request."""

    def __init__(self, decision: bool = True, status_code: int = 200) -> None:
        self.requests: list[dict[str, Any]] = []
        self._decision = decision
        self._status = status_code

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(json.loads(request.content))
        if self._status != 200:
            return httpx.Response(self._status)
        return httpx.Response(200, json={"decision": self._decision})

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


def _guarded(
    delegate: AgentExecutor, pdp: _PDP, make_config: Any, **kwargs: Any
) -> A2AAuthorizationExecutor:
    return A2AAuthorizationExecutor(
        delegate,
        config=make_config(agent_id=None, max_retries=0),
        agent_label="travel-agent",
        http_client=pdp.client(),
        **kwargs,
    )


def _a2a_client(executor: AgentExecutor, builder: ServerCallContextBuilder | None = None) -> Any:
    handler = DefaultRequestHandler(
        agent_executor=executor, task_store=InMemoryTaskStore(), agent_card=_CARD
    )
    routes = create_jsonrpc_routes(handler, rpc_url="/a2a", context_builder=builder)
    app = Starlette(routes=routes)
    hc = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    return ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(_CARD)


def _request(tenant: str = "") -> t.SendMessageRequest:
    return t.SendMessageRequest(
        tenant=tenant,
        message=t.Message(message_id="m1", role=t.Role.ROLE_USER, parts=[t.Part(text="book it")]),
    )


async def _send(client: Any, tenant: str = "") -> list[Any]:
    return [event async for event in client.send_message(_request(tenant))]


def test_constructor_validates(make_config) -> None:
    delegate = _EchoExecutor()
    with pytest.raises(ValueError, match="pdp_url or config"):
        A2AAuthorizationExecutor(delegate, agent_label="x")
    with pytest.raises(ValueError, match="agent_label"):
        A2AAuthorizationExecutor(delegate, config=make_config(), agent_label="a/b")
    with pytest.raises(ValueError, match="reserved"):
        A2AAuthorizationExecutor(
            delegate, config=make_config(), agent_label="x", subject_type="workload"
        )


@pytest.mark.asyncio
async def test_authenticated_peer_allowed(make_config) -> None:
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config)
    # tenant arrives on the REQUEST (the SDK's dispatcher copies it onto the call
    # context) — it is protocol routing data, not a host assertion.
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        events = await _send(client, tenant="acme")
    assert delegate.executed == 1
    assert any("booked" in str(event) for event in events)
    sent = pdp.requests[0]
    assert sent["subject"]["type"] == "agent"
    assert sent["subject"]["id"] == "planner-agent"
    assert sent["action"]["name"] == "agent.invoke"
    assert sent["resource"]["type"] == "a2a_agent"
    assert sent["resource"]["id"] == "travel-agent"
    assert sent["context"]["tenant"] == "acme"


@pytest.mark.asyncio
async def test_denied_invocation_refused_with_generic_reason(make_config) -> None:
    pdp = _PDP(decision=False)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config)
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        with pytest.raises(Exception, match="not authorized") as excinfo:
            await _send(client)
    assert delegate.executed == 0
    assert len(pdp.requests) == 1  # a genuine PDP deny, not a pre-engine refusal
    message = str(excinfo.value).lower()
    for fragment in ("pdp", "unavailable", "http", "subject", "config"):
        assert fragment not in message


@pytest.mark.asyncio
async def test_unauthenticated_caller_refused_without_pdp_trip(make_config) -> None:
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    # agent_id configured but allow_static_subject defaults to False: an anonymous
    # network caller must never be authorized as the static subject.
    guard = A2AAuthorizationExecutor(
        delegate,
        config=make_config(agent_id="bot-123", max_retries=0),
        agent_label="travel-agent",
        http_client=pdp.client(),
    )
    client = _a2a_client(guard)  # default builder: UnauthenticatedUser
    async with guard:
        with pytest.raises(Exception, match="not authorized"):
            await _send(client)
    assert delegate.executed == 0
    assert pdp.requests == []


@pytest.mark.asyncio
async def test_static_subject_requires_opt_in(make_config) -> None:
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = A2AAuthorizationExecutor(
        delegate,
        config=make_config(agent_id="bot-123", max_retries=0),
        agent_label="travel-agent",
        allow_static_subject=True,
        http_client=pdp.client(),
    )
    client = _a2a_client(guard)
    async with guard:
        await _send(client)
    assert delegate.executed == 1
    assert pdp.requests[0]["subject"]["id"] == "bot-123"


@pytest.mark.asyncio
async def test_host_injected_subject_when_unauthenticated(make_config) -> None:
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config)
    client = _a2a_client(guard)
    async with guard:
        with subject_scope(_ALICE):
            await _send(client)
    assert pdp.requests[0]["subject"]["id"] == "alice@acme.com"


@pytest.mark.asyncio
async def test_authenticated_peer_wins_over_ambient_subject(make_config) -> None:
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config)
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        with subject_scope(_ALICE):
            await _send(client)
    assert pdp.requests[0]["subject"]["id"] == "planner-agent"


@pytest.mark.asyncio
async def test_skill_resolver_scopes_resource(make_config) -> None:
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config, skill_resolver=lambda context: "book_flight")
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        await _send(client)
    assert pdp.requests[0]["resource"]["type"] == "a2a_skill"
    assert pdp.requests[0]["resource"]["id"] == "travel-agent/book_flight"


@pytest.mark.asyncio
async def test_unusable_skill_refuses_without_pdp_trip(make_config) -> None:
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config, skill_resolver=lambda context: "a/b")
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        with pytest.raises(Exception, match="not authorized"):
            await _send(client)
    assert delegate.executed == 0
    assert pdp.requests == []


@pytest.mark.asyncio
async def test_raising_skill_resolver_refuses(make_config) -> None:
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()

    def boom(context: RequestContext) -> str:
        raise RuntimeError("secret-resolver-detail")

    guard = _guarded(delegate, pdp, make_config, skill_resolver=boom)
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        with pytest.raises(Exception, match="not authorized") as excinfo:
            await _send(client)
    assert delegate.executed == 0
    assert "secret-resolver-detail" not in str(excinfo.value)


@pytest.mark.asyncio
async def test_pdp_error_fails_closed_without_leaking_detail(make_config) -> None:
    pdp = _PDP(status_code=503)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config)
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        with pytest.raises(Exception, match="not authorized") as excinfo:
            await _send(client)
    assert delegate.executed == 0
    assert len(pdp.requests) == 1
    message = str(excinfo.value).lower()
    for fragment in ("pdp", "unavailable", "503", "retr"):
        assert fragment not in message


@pytest.mark.asyncio
async def test_human_review_refuses_distinctly(make_config) -> None:
    delegate = _EchoExecutor()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"decision": True, "context": {"step_up": True}})

    guard = A2AAuthorizationExecutor(
        delegate,
        config=make_config(agent_id=None, max_retries=0),
        agent_label="travel-agent",
        review_predicate=lambda ctx: bool(ctx.get("step_up")),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        with pytest.raises(Exception, match="human approval"):
            await _send(client)
    assert delegate.executed == 0


@pytest.mark.asyncio
async def test_cancel_passes_through_to_delegate(make_config) -> None:
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config)
    async with guard:
        await guard.cancel(None, None)  # type: ignore[arg-type]  # delegate ignores both
    assert delegate.cancelled == 1
