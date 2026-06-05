# Roadmap

Milestone-based plan for the AuthZEN authorization scanner. Each milestone is a
self-contained, reviewable body of work with explicit deliverables and acceptance
criteria. The design these milestones implement is specified in
[`docs/requirements.md`](docs/requirements.md).

Status legend: ✅ done · 🔜 next · 📋 planned.

## ✅ M0 — Architecture & scaffold

- Technical requirements, architecture, and setup docs.
- Typed package skeleton; AuthZEN 1.0 pydantic models; provider-aware tool-call
  adapters (OpenAI / Anthropic / LangChain); configuration and error hierarchy.
- Project governance: contributing guide, security policy, contributor/agent
  conventions, issue & PR templates, CI (lint, types, tests, build).

**Acceptance:** `ruff`, `mypy --strict`, `pytest`, and `build`/`twine check` all pass;
package imports without the LlamaFirewall stack; PDP-name availability confirmed.

## 🔜 M1 — Core evaluation pipeline

- `AuthZENClient.evaluate` (single `POST /access/v1/evaluation`): timeouts, the
  request budget, bounded retries with backoff, httpx-exception mapping.
- Default `ToolCallMapper`: subject from request context, resource shaping, argument
  forwarding with redaction/size caps.
- `AuthZENScanner.scan`: extract → map → evaluate → decide, with the full
  decision/error tables (fail-closed; `status=ERROR` on the error path).
- A mock PDP and the first unit suite (mapping, models, decision mapping, on-error).

**Acceptance:** an unauthorized tool call returns `BLOCK`, an authorized one `ALLOW`,
and a PDP outage resolves per `on_error`; ≥90% line+branch coverage on the
LlamaFirewall-free modules.

## 📋 M2 — Batch, caching & observability

- Batch evaluation (`/access/v1/evaluations`) with the `execute_all` aggregation
  (all-allow-or-block) for multi-step plan pre-authorization.
- Opt-in, ALLOW-only TTL decision cache with the full-tuple key and hard TTL ceiling.
- Structured decision logging (argument fingerprints, token redaction), a latency
  histogram, and a cache-hit counter.

**Acceptance:** batch and cache behaviour covered by tests, including the security
cases (no stale ALLOW past TTL, errors never cached, tokens never logged).

## 📋 M3 — PDP integrations & conformance

- Worked examples: OPA via [`kanywst/opa-authzen`](https://github.com/kanywst/opa-authzen)
  and Cerbos (digest-pinned images, vendored policy bundles, smoke scripts).
- Integration tests via testcontainers (Docker-gated; skip when absent).
- Conformance against the vendored OpenID AuthZEN interop decisions dataset.

**Acceptance:** the demo scenarios (deny / out-of-scope / allow / PDP-unreachable /
batch) run end-to-end against real OPA and Cerbos.

## 📋 M4 — Hardening & first release

- Independent security review against the threat model.
- Documentation site; example scenarios as runnable demos.
- `0.1.0` release to PyPI via OIDC trusted publishing; SHA-pinned CI actions; SBOM /
  dependency audit.

**Acceptance:** a tagged `0.1.0` on PyPI, green release pipeline, no open P0/P1
security findings.

## Out of scope (tracked, deferred)

These are intentionally excluded from the milestones above and would be tracked
separately: control-plane decision-log emission, OPA bundle distribution, a NeMo
Guardrails rail, a Microsoft Agent Governance capability check, and natural-language
policy authoring.
