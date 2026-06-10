# apparitor

[![CI](https://github.com/jhawlwut/apparitor/actions/workflows/ci.yml/badge.svg)](https://github.com/jhawlwut/apparitor/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/jhawlwut/apparitor/badge)](https://scorecard.dev/viewer/?uri=github.com/jhawlwut/apparitor)
[![CodeQL](https://github.com/jhawlwut/apparitor/actions/workflows/codeql.yml/badge.svg)](https://github.com/jhawlwut/apparitor/actions/workflows/codeql.yml)
[![pip-audit](https://github.com/jhawlwut/apparitor/actions/workflows/pip-audit.yml/badge.svg)](https://github.com/jhawlwut/apparitor/actions/workflows/pip-audit.yml)
[![Aikido Security](https://img.shields.io/badge/Aikido%20Security-scanned%20daily-4c1?logo=aikido&logoColor=white)](https://app.aikido.dev/repositories/2253820/checks)
[![Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen.svg)](pyproject.toml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

**A vendor-neutral authorization layer for AI agents.** apparitor connects the agentic
firewalls teams already run to the authorization policy engines they already trust, so
every agent action is checked against policy before it executes.

Agentic firewalls — [Meta's LlamaFirewall](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall),
[NVIDIA's NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) — ask *"is this input
or output safe?"* They do **not** ask *"is this agent **allowed** to do this?"* apparitor
adds that missing axis. It routes each agent tool call to a policy decision point and maps
the verdict back onto the firewall's `ALLOW` / `BLOCK` / `HUMAN_IN_THE_LOOP` model.

One integration, many policy engines: apparitor speaks the
[AuthZEN 1.0](https://openid.net/specs/authorization-interop-spec-1_0.html) interop
standard, so the same wiring reaches the engines you already author policy in —
**OpenFGA** (Zanzibar / ReBAC), **Cedar** (policy-as-code), and **OPA / Rego** — with no
policy rewrite. Apache-2.0, built entirely on public standards.

> **Status: `0.0.1a0` — pre-alpha.** **Shipping today:** four enforcement points — the
> LlamaFirewall scanner, the NeMo Guardrails rail, the FastMCP server middleware, and the
> A2A executor — and the AuthZEN evaluation pipeline, working end-to-end against any
> AuthZEN 1.0 PDP (OpenFGA, Cedar, OPA, Cerbos, Topaz) plus native OPA and in-process
> Cedar backends, with 98% test coverage on the adapter-free core (see
> [`CHANGELOG`](CHANGELOG.md)). **On the roadmap:** a native OpenFGA backend and the
> code-exec enforcement point. APIs may change — see
> [`docs/requirements.md`](docs/requirements.md) for the design and [`ROADMAP`](ROADMAP.md).

## The gap

```
Agent: "Delete the production database"
         │
         ▼
   Agentic firewall   → "Is this prompt malicious?"            → PASS (it's not a jailbreak)
         │
         ▼
   ??? nothing ???    → "Is this agent authorized to do this?" → NO CHECK
         │
         ▼
   Tool executes.  Production database deleted.
```

With apparitor in the loop:

```
Agent: "Delete the production database"
         │
         ▼
   Firewall safety scanners (PromptGuard, AlignmentCheck, CodeShield, …)   → PASS
         │
         ▼
   apparitor ──────────POST /access/v1/evaluation──────▶  Policy engine (OpenFGA / Cedar / OPA / …)
         │                                                    │
         │  ◀────────────────── { "decision": false } ────────┘
         ▼
   BLOCK — "agent travel-bot-123 is not authorized for tool_call.execute on database.delete_table"
```

## Quickstart (target API — wiring is ≤10 lines)

apparitor ships today as a LlamaFirewall scanner and a NeMo Guardrails rail
(`NeMoAuthorizationRails`). The LlamaFirewall path: point the scanner at any
AuthZEN-compliant policy decision point (PDP) and bind it to the assistant role:

```python
from llamafirewall import LlamaFirewall, Role
from apparitor import AuthZENScanner, ScannerConfig

# Point at any AuthZEN-compliant PDP. Secure defaults: fail-closed, TLS-verified.
# A subject must be resolvable — set config.agent_id, or current_subject per request.
scanner = AuthZENScanner(config=ScannerConfig(pdp_url="https://pdp.internal", agent_id="travel-bot"))

firewall = LlamaFirewall(scanners={Role.ASSISTANT: [scanner]})
result = await firewall.scan_async(assistant_message)   # ALLOW / BLOCK / HUMAN_IN_THE_LOOP
```

Per request, supply the real end user the agent acts for (recommended over a static
`agent_id`) — see [Identity: who the agent acts for](#identity-who-the-agent-acts-for).

At the **MCP boundary** the same engine runs server-side, before any tool executes —
and the subject is the *validated* OAuth identity of the caller (the token's `sub`),
not a host-asserted value (`pip install "apparitor[fastmcp]"`):

```python
from fastmcp import FastMCP
from apparitor.fastmcp import FastMCPAuthorizationMiddleware

server = FastMCP("files", auth=my_token_verifier)   # auth supplies the validated identity
server.add_middleware(FastMCPAuthorizationMiddleware(pdp_url="https://pdp.internal"))
```

Register the middleware **after** any custom auth middleware (so the token is populated).
It gates `tools/call`, `resources/read` (action `resource.read`), and `prompts/get`
(action `prompt.get`) by default — `gate_resources`/`gate_prompts` opt a hook out — and
can additionally hide unauthorized tools from `tools/list` with `filter_listings=True`
(advisory; `tools/call` remains the enforcement invariant). Client-credentials tokens can
be authorized as distinct `workload` subjects via `allow_workload_subject=True`. Under
server composition pin `server_label` for stable policy keys. FastMCP never tears
middleware down, so call `await middleware.aclose()` on shutdown to release the PDP client.

At the **A2A boundary** the same engine guards agent-to-agent invocations — the subject
is the authenticated peer the A2A server established, and the request's `tenant` is
forwarded to policies as a claim to cross-check (`pip install "apparitor[a2a]"`):

```python
from apparitor.a2a import A2AAuthorizationExecutor

guarded = A2AAuthorizationExecutor(
    my_executor, pdp_url="https://pdp.internal", agent_label="travel-agent"
)
# hand `guarded` to DefaultRequestHandler in your executor's place
```

The AuthZEN client and models are **adapter-free** and usable on their own:

```python
from apparitor.models import EvaluationRequest   # no firewall dependency needed
```

## Identity: who the agent acts for

Every decision needs a **subject** — the principal your policy is written against. apparitor
never infers it from model or tool output (that would be a [confused
deputy](https://en.wikipedia.org/wiki/Confused_deputy_problem)); the **host** supplies it,
request-scoped, because the firewall layer sees messages, not an authenticated principal.
There is a maturity ladder of three levels, and the same seam feeds every mapper-driven
adapter (the LlamaFirewall scanner, the NeMo rail, the FastMCP middleware). At the MCP
boundary the middleware fills this seam itself from the validated OAuth token — see the
note below.

**Level 0 — a static agent identity.** Set `agent_id`; every call is authorized as that
agent. Enough for policies that don't depend on the end user — *"no agent may call a
destructive tool"*:

```python
scanner = AuthZENScanner(config=ScannerConfig(pdp_url="https://pdp.internal", agent_id="travel-bot"))
```

**Level 1 — the real end user, per request (recommended).** Where your host already
authenticated the user, bind it for the agent run with `subject_scope`. It resets the value
on exit, so a subject can never leak to a later request that reuses the same task/event loop:

```python
from apparitor import Subject, subject_scope

with subject_scope(Subject(type="user", id="alice@acme.com")):
    result = await firewall.scan_async(assistant_message)
```

**Level 2 — the agentic permission boundary (user ∧ agent).** Level 1 is the production
floor; Level 2 is the recommended hardening when agent and user privileges differ. The
`DualPrincipalMapper` evaluates **two** decisions per call — the end user's grant *and*
the agent's own boundary — and the call proceeds only when both allow. That is the
evaluation semantics of a permission boundary: the agent can never exercise a permission
its boundary denies, even when the human holds it — at every mapper-gated call (MCP
resource reads/prompt gets and the A2A executor shape their own tuples and stay
single-principal for now — [#39](https://github.com/jhawlwut/apparitor/issues/39)):

```python
from apparitor import DualPrincipalMapper, ScannerConfig

config = ScannerConfig(pdp_url="https://pdp.internal", agent_id="travel-bot")
scanner = AuthZENScanner(config=config, mapper=DualPrincipalMapper(config))
# per request: subject_scope(user) supplies the user leg; "travel-bot" is the boundary
```

Unlike an in-policy `forbid` (the [three-peps demo](examples/three-peps/)'s deny-override,
which works when one PDP holds all your policy), the dual mapper makes the boundary a
**separate, separately-audited decision** that works across engines and policy stores.
Cost: two decisions per call, sent as one batched PDP round trip.

With neither a request-context `subject` nor `current_subject` set and no `agent_id`, the
scan fails **closed**. Request-scoped attributes (`user_id`, `conversation_id`, …) can ride
along as AuthZEN `context` for policy conditions — see
[docs/setup.md](docs/setup.md#identity-resolving-the-subject) for the full resolution order
and a request-context example.

> Enforcement points that carry a *validated* identity of their own populate this same
> subject seam: the FastMCP middleware reads the verified OAuth token's `sub` claim and
> it outranks any host-asserted subject. A token is never silently downgraded — a token
> without a usable claim refuses the call, and the static `agent_id` fallback requires an
> explicit `allow_static_subject=True` opt-in (local/stdio only).

## Observability

Every decision is timed and counted. The scanner (and the standalone `AuthorizationEngine`)
exposes a `metrics` sink — by default an in-process `InMemoryMetrics` with a latency
histogram and decision/cache counters:

```python
m = scanner.metrics                         # InMemoryMetrics by default
m.latency_histogram()                       # [(le_seconds, cumulative_count), …, (+Inf, n)]
m.decisions                                 # {("allow", "success"): 12, ("block", "error"): 1}
m.cache_hits, m.cache_misses                # cache effectiveness (single-call decisions)
```

To export, pass your own `MetricsSink` (forward to Prometheus/OpenTelemetry) or
`NoopMetrics()` to disable. The default `InMemoryMetrics` is lock-free and meant for
single-event-loop use; a long-lived server scraping it from another thread (or a sink shared
across threads) must provide its own synchronisation — pass a thread-safe `MetricsSink`.
Each decision also emits one structured audit log line (verdict,
status, subject id, correlation id, tool names, and an argument *fingerprint*). Raw tool
arguments and tokens are never logged — arguments are fingerprinted. The subject id is the
decision principal (with the FastMCP middleware that is the OAuth `sub`, which may be an
email), so treat the `apparitor` logger as sensitive and route it accordingly.

## What apparitor connects

**Enforcement points** (the agent-side hooks apparitor plugs into):

| Enforcement point | Vendor | Status |
| --- | --- | --- |
| [**LlamaFirewall**](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall) | Meta | shipping (`AuthZENScanner`) |
| [**NeMo Guardrails**](https://github.com/NVIDIA/NeMo-Guardrails) | NVIDIA | shipping (`NeMoAuthorizationRails`) |
| [**FastMCP**](https://github.com/PrefectHQ/fastmcp) server middleware | Prefect | shipping (`FastMCPAuthorizationMiddleware`) |
| [**A2A**](https://a2a-protocol.org/) agent executor | Linux Foundation | shipping (`A2AAuthorizationExecutor`) |

**Policy engines** (where the authorization decision is made). apparitor reaches these over
AuthZEN; OPA and Cedar also have native backends that skip the AuthZEN hop, selected by
config (`backend="opa"` / `backend="cedar"`):

| Engine | Paradigm | How apparitor reaches it | Example |
| --- | --- | --- | --- |
| **Mock PDP** (testing/demo) | — | AuthZEN | [`examples/mock_pdp/`](examples/mock_pdp/) |
| **OpenFGA** | Zanzibar / ReBAC | native AuthZEN (experimental) | [`examples/openfga/`](examples/openfga/) |
| **Cedar** | policy-as-code (ABAC) | AuthZEN gateway · native in-process (`backend="cedar"`) | [`examples/cedar/`](examples/cedar/) |
| **OPA / Rego** | policy-as-code | AuthZEN gateway · native Data API (`backend="opa"`) | [`examples/opa/`](examples/opa/) |
| **Amazon Verified Permissions** | managed Cedar | [AWS AuthZEN interface](https://github.com/aws-samples/sample-authzen-interface-verified-permissions) | [`examples/avp/`](examples/avp/) |
| Any AuthZEN 1.0 PDP (Cerbos, Topaz, …) | varies | AuthZEN | [`docs/setup.md`](docs/setup.md) |

## Documentation

- [Technical requirements & design decisions](docs/requirements.md)
- [Architecture](docs/architecture.md)
- [Setup: connecting to a policy engine](docs/setup.md)
- [Roadmap](ROADMAP.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)

## License

[Apache License 2.0](LICENSE).
