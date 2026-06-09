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

**Remaining:** the **Amazon Verified Permissions** (managed Cedar) cloud example and the
end-to-end scenario walk-through (deny / out-of-scope / allow / PDP-unreachable / batch).

## 📋 M4 — Hardening & first release

- Independent security review against the threat model.
- Documentation site; example scenarios as runnable demos.
- `0.1.0` release to PyPI via OIDC trusted publishing; SHA-pinned CI actions; SBOM /
  dependency audit.

**Acceptance:** a tagged `0.1.0` on PyPI, green release pipeline, no open P0/P1
security findings.

## Beyond v0.1 — the aggregator

This is where apparitor broadens from "an AuthZEN scanner for LlamaFirewall" into an
aggregator across the popular agentic firewalls and policy engines.

### 📋 More agentic firewalls

- **NeMo Guardrails** (NVIDIA) rail — bind the same `AuthorizationEngine` behind a NeMo
  action/rail so a NeMo-guarded agent gets the identical authorization check. The engine is
  already firewall-free, so this is an adapter, not a re-implementation.
- Keep the firewall-specific surface thin: only the firewall adapter module may import a
  firewall SDK; the core stays standalone.

### 📋 Native policy-engine adapters (skip the AuthZEN hop)

- Direct **Cedar**, **OpenFGA**, and **OPA / Rego** adapters for deployments that don't
  front their engine with an AuthZEN endpoint — talk each engine's own API while keeping the
  same mapping seam and fail-closed semantics.
- A pluggable decision-backend interface so a deployment selects its engine by config.

## Out of scope (tracked, deferred)

Intentionally excluded for now and tracked separately: control-plane decision-log emission,
OPA bundle distribution, a Microsoft Agent Governance capability check, and natural-language
policy authoring.
