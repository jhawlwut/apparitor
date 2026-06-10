"""A2A agent-executor adapter (thin adapter over :class:`AuthorizationEngine`).

This is the **only** module that imports the A2A SDK. The import is guarded so that
importing it without ``a2a-sdk`` installed yields a clear
:class:`~apparitor.errors.MissingDependencyError` rather than an opaque ``ImportError``.

It binds the firewall-free :class:`AuthorizationEngine` in front of an A2A
``AgentExecutor`` so every agent-to-agent invocation (``message/send`` and streaming
variants) is authorized server-side, *before* the wrapped executor runs — the same engine,
fail-closed semantics and metrics as the LlamaFirewall scanner, the NeMo rail and the
FastMCP middleware; only the boundary differs. Like the FastMCP middleware (and unlike the
in-runtime firewall adapters), the subject can come from a **validated** identity: the
authenticated peer the A2A server's authentication layer established for the request —
never from anything inside the message.

Subject resolution (first match wins; no match refuses the invocation):

1. The authenticated caller from ``RequestContext.call_context.user`` →
   ``Subject(type="agent", id=<user_name>)`` — the A2A peer is typically itself an agent;
   ``subject_type`` is a constructor knob for deployments that authenticate end users.
2. A trusted subject placed in ``ServerCallContext.state["subject"]`` by the
   deployment's ``ServerCallContextBuilder`` — per-request and threaded through the SDK.
   The ambient contextvar seam the other adapters offer is deliberately **not** consulted
   here: the executor runs inside the SDK's detached, long-lived producer task, where
   contextvars are snapshotted at task creation and go stale across turns — a
   cross-request identity leak waiting to happen.
3. ``config.agent_id``, **only** when ``allow_static_subject=True``. Off by default: an
   unauthenticated network caller must never be silently authorized as a static subject
   (a confused deputy). Opt in only where the transport itself is trusted.

Host enrichment attributes (``conversation_id`` / ``user_id`` / ``correlation_id``) are
likewise read from ``ServerCallContext.state``, never from ambient context.

The AuthZEN tuple: action ``agent.invoke``; resource ``{type: "a2a_agent",
id: <agent_label>}``, or — when ``skill_resolver`` resolves a skill for the request —
``{type: "a2a_skill", id: "<agent_label>/<skill>"}`` (segments validated like every other
policy key: non-empty, no embedded ``/``; the skill is kept verbatim). The A2A ``tenant``
rides along in the AuthZEN ``context`` for multi-tenant policies, beside the standard
host-context attributes — note it is the *request's* tenant as resolved by the SDK
(protocol routing data), so policies should treat it as a claim to check against the
subject, not as proof by itself.

Verdict mapping is fail-closed: only a clean ``ALLOW`` reaches the wrapped executor.
``BLOCK``, ``HUMAN_REVIEW``, abstention and any error refuse by raising an A2A
``InvalidRequestError`` whose text the client receives **verbatim** — so refusals are
deliberately generic and the rich verdict/reason stays in the operator decision log and
metrics. (``InvalidRequestError`` maps to JSON-RPC -32600 — semantically "invalid
request" rather than "forbidden"; it is the stateless choice. The protocol-native
alternative, a ``TASK_STATE_REJECTED`` task event, persists a task per denied request —
unauthenticated write amplification on the task store — so it is deferred as a possible
opt-in.) ``cancel`` is passed through: the SDK cancels the producer task *before*
``executor.cancel`` runs, so gating at this seam could not actually prevent
cancellation — authorize cancels in HTTP/authn middleware if needed.

Wiring::

    from a2a.server.request_handlers import DefaultRequestHandler
    from apparitor.a2a import A2AAuthorizationExecutor

    guarded = A2AAuthorizationExecutor(
        MyExecutor(), pdp_url="https://pdp.internal", agent_label="travel-agent"
    )
    handler = DefaultRequestHandler(agent_executor=guarded, task_store=..., agent_card=...)

The adapter needs only the base ``a2a-sdk``; serving over HTTP additionally needs the
SDK's ``[http-server]`` extra, as in any A2A deployment.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from .config import ScannerConfig
from .decision import Verdict, VerdictResult, VerdictStatus
from .engine import AuthorizationEngine, ReviewPredicate
from .errors import MissingDependencyError
from .mapping import request_context_attrs
from .models import Action, EvaluationRequest, Resource, Subject

try:  # pragma: no cover - exercised via import-guard tests
    from a2a.server.agent_execution import AgentExecutor, RequestContext
    from a2a.utils.errors import InvalidRequestError
except ImportError as exc:  # pragma: no cover
    raise MissingDependencyError(
        "apparitor.a2a requires the A2A SDK. Install it with:\n    pip install 'apparitor[a2a]'"
    ) from exc

if TYPE_CHECKING:
    from collections.abc import Callable

    import httpx
    from a2a.server.events import EventQueue

    from .metrics import MetricsSink

logger = logging.getLogger("apparitor")


def _refusal(verdict: VerdictResult | None) -> str:
    """Generic refusal text; HUMAN_REVIEW stays distinguishable for calling agents.

    This text crosses the trust boundary to the calling agent verbatim, so it is fixed
    and generic — never the engine's reason, which may embed PDP/config detail.
    """
    if verdict is not None and verdict.verdict is Verdict.HUMAN_REVIEW:
        return "agent invocation requires human approval; do not retry"
    return "agent invocation not authorized"


def _is_allowed(verdict: VerdictResult) -> bool:
    """Only a clean ALLOW executes; exactly one request is always submitted, so SKIP
    could only mean nothing was evaluated — executing on it would be a bypass."""
    return verdict.status is not VerdictStatus.ERROR and verdict.verdict is Verdict.ALLOW


class A2AAuthorizationExecutor(AgentExecutor):  # type: ignore[misc]  # a2a-sdk may be absent in the lint env (base is Any)
    """Authorizes A2A invocations against an AuthZEN PDP before the wrapped executor runs.

    Construct it like the other adapters — a ``pdp_url`` or a full :class:`ScannerConfig` —
    plus the executor to guard and the agent's stable policy label, then hand it to the
    request handler in the executor's place. A subject must be resolvable (authenticated
    peer, host-injected subject, or the opt-in static fallback) or the invocation is
    refused.
    """

    def __init__(
        self,
        delegate: AgentExecutor,
        pdp_url: str | None = None,
        *,
        config: ScannerConfig | None = None,
        agent_label: str,
        skill_resolver: Callable[[RequestContext], str | None] | None = None,
        subject_type: str = "agent",
        allow_static_subject: bool = False,
        http_client: httpx.AsyncClient | None = None,
        review_predicate: ReviewPredicate | None = None,
        metrics: MetricsSink | None = None,
    ) -> None:
        if config is None:
            if pdp_url is None:
                raise ValueError("provide either pdp_url or config")
            config = ScannerConfig(pdp_url=pdp_url)
        if subject_type == "workload":
            # Reserved by the FastMCP adapter for verified client-credentials tokens;
            # minting other principals in that namespace would alias machine policies.
            raise ValueError('subject type "workload" is reserved')
        label = agent_label.strip()
        if not label or "/" in label:
            raise ValueError("agent_label must be non-empty and contain no '/'")
        self._delegate = delegate
        self._config = config
        self._agent_label = label
        self._skill_resolver = skill_resolver
        self._subject_type = subject_type
        self._allow_static_subject = allow_static_subject
        from .backends import build_backend

        backend = build_backend(config, http_client=http_client)
        self._engine = AuthorizationEngine(
            config, client=backend, review_predicate=review_predicate, metrics=metrics
        )
        logger.info("apparitor: A2A executor gating agent.invoke for %r", label)

    @property
    def metrics(self) -> MetricsSink:
        """The engine's metrics sink (latency histogram + cache-hit counter)."""
        return self._engine.metrics

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Authorize the invocation; only a clean ALLOW reaches the wrapped executor."""
        try:
            verdict = await self._authorize(context)
        except Exception:
            # Defense in depth: an adapter-level fault must refuse, never execute. The
            # generic message is deliberate — exception text reaches the calling agent.
            logger.exception("apparitor: A2A authorization executor error (refusing)")
            self._record_refusal()
            raise InvalidRequestError(message=_refusal(None)) from None
        if verdict is not None and _is_allowed(verdict):
            await self._delegate.execute(context, event_queue)
            return
        if verdict is None:
            # No resolvable subject: the engine never ran; count the refusal so an
            # all-misconfigured fleet doesn't show zero decisions.
            self._record_refusal()
        raise InvalidRequestError(message=_refusal(verdict))

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Pass task cancellation through ungated (v1 — see module docstring)."""
        await self._delegate.cancel(context, event_queue)

    async def _authorize(self, context: RequestContext) -> VerdictResult | None:
        """Evaluate the invocation; ``None`` refuses without a PDP trip (no subject or
        no sound policy key)."""
        # Per-request data only: ServerCallContext.state is threaded through the SDK for
        # this request; ambient contextvars would be stale here (see module docstring).
        state: dict[str, Any] = dict(context.call_context.state) if context.call_context else {}
        subject = self._resolve_subject(context, state)
        if subject is None:
            return None
        resource = self._resource(context)
        if resource is None:
            return None
        request = EvaluationRequest(
            subject=subject,
            action=Action(name="agent.invoke"),
            resource=resource,
            context=self._context_attrs(context, state),
        )
        return await self._engine.evaluate_requests([request])

    def _resolve_subject(self, context: RequestContext, state: dict[str, Any]) -> Subject | None:
        user = context.call_context.user if context.call_context else None
        if user is not None and user.is_authenticated:
            name = user.user_name
            if isinstance(name, str) and name.strip():
                return Subject(type=self._subject_type, id=name)
            # Authenticated but nameless is a broken authn integration — refuse rather
            # than guess; never fall through to a weaker subject.
            logger.warning("apparitor: authenticated A2A user has no user_name; refusing")
            return None
        injected = state.get("subject")
        if isinstance(injected, Subject):
            return injected
        if self._allow_static_subject and self._config.agent_id is not None:
            return Subject(type=self._config.subject_type, id=self._config.agent_id)
        logger.warning(
            "apparitor: no authenticated subject for A2A invocation; refusing (configure"
            " server authentication, inject one via ServerCallContext.state['subject'],"
            " or opt in to allow_static_subject)"
        )
        return None

    def _resource(self, context: RequestContext) -> Resource | None:
        if self._skill_resolver is None:
            return Resource(type="a2a_agent", id=self._agent_label)
        skill = self._skill_resolver(context)
        if skill is None:
            return Resource(type="a2a_agent", id=self._agent_label)
        # The skill is kept verbatim (distinct skills must not alias one policy key);
        # an empty or "/"-bearing skill cannot form an unambiguous key — refuse.
        if not isinstance(skill, str) or not skill.strip() or "/" in skill:
            logger.warning("apparitor: unusable skill id from skill_resolver; refusing")
            return None
        return Resource(type="a2a_skill", id=f"{self._agent_label}/{skill}")

    def _context_attrs(
        self, context: RequestContext, state: dict[str, Any]
    ) -> dict[str, Any] | None:
        attrs = request_context_attrs(state) or {}
        tenant = context.call_context.tenant if context.call_context else ""
        if tenant:
            attrs["tenant"] = tenant
        return attrs or None

    def _record_refusal(self) -> None:
        """Count a pre-engine refusal as a BLOCK+ERROR decision (best-effort, isolated)."""
        try:
            self._engine.metrics.record_decision(verdict="block", status="error", latency_s=0.0)
        except Exception:
            logger.exception("apparitor: refusal metric emission failed (verdict unaffected)")

    async def aclose(self) -> None:
        """Release the underlying PDP client (the host owns executor teardown).

        Only closes a client this adapter created; a bring-your-own ``http_client`` is
        left for the caller to manage.
        """
        await self._engine.aclose()

    async def __aenter__(self) -> A2AAuthorizationExecutor:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()


__all__ = ["A2AAuthorizationExecutor"]
