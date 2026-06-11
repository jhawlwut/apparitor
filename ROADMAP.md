# Roadmap

apparitor is a vendor-neutral authorization layer for AI agents: it authorizes an agent's
tool calls against a policy engine and maps the verdict onto an agentic firewall's
allow / block / human-review model. The plan below takes it from a single firewall + the
AuthZEN interop standard to an aggregator across the popular agentic firewalls and policy
engines. Each milestone is a self-contained, reviewable body of work; the design it
implements is specified in [`docs/requirements.md`](docs/requirements.md).

Status legend: ✅ done · 🔜 next · 📋 planned.

## ✅ M0 — Architecture & scaffold

- Technical requirements, architecture, and setup docs.
- Typed package skeleton; AuthZEN 1.0 pydantic models; provider-aware tool-call
  adapters (OpenAI / Anthropic / LangChain); configuration and error hierarchy.
- Project governance: contributing guide, security policy, contributor/agent
  conventions, issue & PR templates, CI (lint, types, tests, build).

## ✅ M1 — Core evaluation pipeline

- `AuthZENClient.evaluate` (single `POST /access/v1/evaluation`): timeouts, request
  budget, bounded retries with backoff, httpx-exception mapping.
- Default `ToolCallMapper`: subject from request context, resource shaping, argument
  forwarding with redaction/size caps.
- `AuthZENScanner.scan` (the LlamaFirewall integration): extract → map → evaluate →
  decide, with the full decision/error tables (fail-closed; `status=ERROR` on the error
  path).
- A mock PDP and the first unit suite (mapping, models, decision mapping, on-error).

## ✅ M2 — Batch, caching & observability

- Batch evaluation (`/access/v1/evaluations`) with `execute_all` aggregation
  (all-allow-or-block) for multi-step plan pre-authorization.
- Opt-in, ALLOW-only TTL decision cache with the full-tuple key and hard TTL ceiling.
- Structured decision logging (argument fingerprints, token redaction), a latency
  histogram, and cache-hit/miss counters.

## ✅ M3 — Policy-engine integrations & conformance

- Worked examples over AuthZEN: **OpenFGA** (native, experimental AuthZEN; ReBAC),
  **Cedar** (policy-as-code, via a local AuthZEN gateway), and **OPA / Rego** (policy-as-code,
  via a local AuthZEN gateway) — digest-pinned images, vendored models/policies, smoke
  scripts. Together they exercise both ReBAC and ABAC over the same AuthZEN API.
- Integration tests via testcontainers (Docker-gated; skip when absent).
- Conformance against the vendored OpenID AuthZEN interop decisions dataset.

**Remaining:** the **Amazon Verified Permissions** (managed Cedar) cloud example.

## 📋 M4 — Hardening & first release

- ✅ **Internal adversarial security review** ([`docs/security-review.md`](docs/security-review.md)):
  three attacker-focused slices (core engine + transport; mapping layer + four enforcement
  adapters; configuration + supply chain), static analysis plus concrete repro probes,
  reviewed against the full threat model. Six findings — one HIGH, three MEDIUM, two LOW —
  all fixed on the `fix/security-hardening` branch. Positive properties (fail-closed on
  every error path, subject isolation, cache safety, SSRF guard, dual-principal AND
  semantics) verified sound. No open P0/P1 findings in the documented review.
- 🔜 **Independent third-party security review** (post-public, adoption-gated): the
  internal review is the current assurance baseline; an independent external review is a
  goal for after the project has public users. Pursued through the free avenues available
  to open source: a **GitHub Security Lab** review request and a **Sentry open-source
  sponsorship** application. Both are tracked as TODOs, not release-gating items.
- Documentation site. ✅ Example scenarios as runnable demos (`examples/scenarios/`).
- ✅ Audit-log schema frozen as a stability contract (`docs/audit-log.md`): logger,
  levels, C1/C2/C3 field grammar, parsing guidance, stability policy, pinned by
  `tests/unit/test_log_contract.py`.
- `0.1.0` release to PyPI via OIDC trusted publishing; SHA-pinned CI actions; SBOM /
  dependency audit.
- ✅ **EU AI Act / CADA compliance reference** ([`docs/eu-ai-act.md`](docs/eu-ai-act.md)):
  field-by-field mapping of the decision log to Article 12 categories, the Article 14
  human-oversight mechanism (`HUMAN_IN_THE_LOOP_REQUIRED`), and the deployer obligations
  (tamper-evidence, 6-month retention) that are infrastructure concerns outside this
  library's scope. High-risk obligations apply from **2 August 2026**.

**Acceptance:** a tagged `0.1.0` on PyPI, green release pipeline, no open P0/P1
findings in the documented internal review. An independent third-party audit is a
post-adoption goal, not a `0.1.0` blocker.

**Project status & resourcing:** this is a solo-maintained open-source project; cadence
is best-effort. Security-review depth and external audits scale with adoption and
sponsorship. The current assurance baseline is the documented threat model
([`docs/requirements.md`](docs/requirements.md)), the tested invariants in the unit
suite, and the internal adversarial review linked above.

## Beyond v0.1 — the aggregator

This is where apparitor broadens from "an AuthZEN scanner for LlamaFirewall" into an
aggregator across the popular agentic firewalls and policy engines.

### More enforcement points (firewalls, MCP, A2A)

- ✅ **NeMo Guardrails** (NVIDIA) rail — binds the same `AuthorizationEngine` behind a NeMo
  custom action so a NeMo-guarded agent gets the identical authorization check; the verdict
  maps onto NeMo's allow / block(refuse) model via `output_mapping` (fail-closed). Adapter,
  not a re-implementation (`apparitor.nemo`, optional `[nemo]` extra).
- ✅ **FastMCP server middleware** — the first MCP-boundary PEP: every `tools/call` is
  authorized server-side before the tool executes, with the subject taken from the
  **validated** OAuth token (`sub`) rather than a host assertion (`apparitor.fastmcp`,
  optional `[fastmcp]` extra). Follow-ups, all shipped: ✅ list filtering via
  `filter_listings` ([#32](https://github.com/jhawlwut/apparitor/issues/32)), ✅ workload
  (client-credentials) identities as a distinct `workload` subject type via
  `allow_workload_subject` ([#33](https://github.com/jhawlwut/apparitor/issues/33)), ✅
  resource reads and prompts gated by default (actions `resource.read` / `prompt.get`,
  per-hook opt-outs) ([#34](https://github.com/jhawlwut/apparitor/issues/34)).
- ✅ **A2A executor** — the first non-firewall, non-MCP surface: every agent-to-agent
  invocation is authorized before the wrapped `AgentExecutor` runs (`action =
  agent.invoke`, `resource = <agent>` or `<agent>/<skill>` via `skill_resolver`), with the
  subject taken from the server's **authenticated peer** (`apparitor.a2a`, optional
  `[a2a]` extra). Task reads and `cancel` are HTTP/authn-middleware territory — the SDK
  cancels the producer before `executor.cancel` runs, so the executor seam cannot gate
  them; a task-status (`TASK_STATE_REJECTED`) refusal mode remains possible follow-up.
- ✅ A three-PEP portability demo: one Cedar policy enforced identically at the scanner,
  the rail, and the MCP middleware (in-process Cedar backend, no Docker) —
  [`examples/three-peps/`](examples/three-peps/), gated by the `three-pep-demo` CI job.
- ✅ A **dual-principal (user ∧ agent) mapper** — `DualPrincipalMapper` evaluates the
  end user's grant AND the agent's own permission boundary as one all-allow-or-block
  batch, at every mapper-gated call (scanner, rail, FastMCP tools/listing). The A2A
  executor and FastMCP resource/prompt paths are also covered via `boundary_subject`
  (closes [#39](https://github.com/jhawlwut/apparitor/issues/39)).
- Keep the host-specific surface thin: only the adapter module may import a host SDK; the
  core stays standalone.

### ✅ / 🔜 Native policy-engine adapters (skip the AuthZEN hop)

- A pluggable **decision-backend** interface so a deployment selects its engine by config
  (`ScannerConfig(backend=...)`), reusing one hardened transport (SSRF guard, TLS, bounded
  retries) and the same mapping + fail-closed semantics. ✅ done.
- **OPA / Rego** native backend — talks OPA's Data API (`/v1/data/<rule>`) directly, no
  AuthZEN gateway. ✅ done (`backend="opa"`).
- **Cedar** native backend — evaluates Cedar policies in-process via the optional `cedarpy`
  binding, no gateway; the decision never leaves the host. ✅ done (`backend="cedar"`).
- Direct **OpenFGA** backend (its own Check API) for deployments that don't front it with an
  AuthZEN endpoint — next, plugging into the same seam. A managed **Amazon Verified
  Permissions** backend (boto3) is tracked separately as the cloud/AVP variant.

## Out of scope (tracked, deferred)

Intentionally excluded for now and tracked separately: control-plane decision-log emission,
OPA bundle distribution, a Microsoft Agent Governance capability check, and natural-language
policy authoring. Structured log persistence, cross-session aggregation, retention, and
compliance export — post-`v0.1`.
