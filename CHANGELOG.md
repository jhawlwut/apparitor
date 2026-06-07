# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Working scan pipeline (M1).** `AuthZENScanner.scan()` authorizes an agent's tool
  calls end-to-end: extract → map → evaluate → decide.
- LlamaFirewall-free `AuthorizationEngine` holding all logic, so the pipeline is fully
  unit-testable without the ML stack; the scanner is a thin adapter that converts the
  verdict to a `ScanResult`.
- `AuthZENClient`: async httpx transport with explicit timeouts, a request budget,
  bounded retries (429/5xx/transport only) with jittered backoff, an SSRF/TLS guard on
  `pdp_url`, bring-your-own-client support, and httpx→typed-error mapping.
- `DefaultToolCallMapper` / `MCPResourceMapper`: request-scoped subject resolution
  (never from model output), argument redaction/size-caps, MCP server-scoped resource ids.
- Opt-in, ALLOW-only TTL `DecisionCache` with a full-tuple SHA-256 key.
- Batch evaluation with all-allow-or-block aggregation; `review_predicate` escalation
  (never downgrade); fail-closed `on_error` (deny / human_review).
- AuthZEN 1.0 pydantic models; provider-aware tool-call adapters (OpenAI / Anthropic /
  LangChain); `ScannerConfig` with secure defaults; exception hierarchy.
- A dependency-free mock AuthZEN PDP for demos/tests.
- Test suite: 90+ unit tests, 98% line+branch coverage on the LlamaFirewall-free
  modules (90% gate enforced), including the security invariants.

- **Real PDP examples (M3).** Runnable OpenFGA example (native, experimental AuthZEN API;
  vendored model + relationship tuples) and Cedar example (policy-as-code behind a local
  AuthZEN → Cedar gateway running the official Cedar CLI), each with a `smoke.sh` and a
  Docker-gated `testcontainers` integration test that skips when no daemon is present.
- `integration` optional-dependency group (`testcontainers`) and a `workflow_dispatch`
  CI job that runs the integration suite.

### Not yet implemented

- Amazon Verified Permissions (cloud) example and the end-to-end scenario walk-through.
- Structured decision-log metrics (latency histogram, cache-hit counter) and the
  AuthZEN interop conformance dataset.

## [0.0.1a0]
- Initial pre-alpha scaffold.
