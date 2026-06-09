# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Three-PEP portability demo (`examples/three-peps/`).** The same vendored Cedar policy
  (`examples/cedar/policies.cedar`, deny-override on `destructive == true`) enforced
  identically at the LlamaFirewall scanner, the NeMo Guardrails rail, and the FastMCP
  middleware over the in-process Cedar backend — no Docker, no network. Self-asserting
  (exits non-zero on any verdict mismatch) and gated in CI by the `three-pep-demo` job,
  which installs all three enforcement-point extras and requires every lane to run.
- **FastMCP server-middleware enforcement point (`apparitor.fastmcp`, optional `[fastmcp]`
  extra).** `FastMCPAuthorizationMiddleware` authorizes every MCP `tools/call` server-side,
  before the tool executes, over the same `AuthorizationEngine` as the LlamaFirewall scanner
  and the NeMo rail. The subject comes from the **validated** OAuth access token
  (`claims["sub"]`, configurable) and outranks host-asserted subjects; a token without a
  usable claim refuses, and the static `agent_id` fallback is gated behind an explicit
  `allow_static_subject=True` opt-in (local/stdio only). Verdicts map fail-closed onto MCP:
  only a clean `ALLOW` executes; `BLOCK` / `HUMAN_REVIEW` / mapper abstention / errors raise
  a deliberately generic `ToolError` (the rich reason stays in the operator log). Supports
  fastmcp 2.14 and 3.x (both exercised in CI).
- `AuthorizationEngine.evaluate_normalized()` — a public seam for enforcement points that
  receive tool calls in structured form (no provider-shape adapter detection).
- `MCPResourceMapper` can now resolve its server label per call from
  `request_context[MCP_SERVER_LABEL_KEY]`; the tool segment gets the same case/whitespace
  normalisation as the default mapper, and `mcp_resource_id` rejects embedded `/` (an
  ambiguous policy key) — fail-closed.
- `DecisionCache` is bounded: new `cache_max_entries` config (default 10 000, FIFO
  eviction) so per-token subject cardinality cannot grow the ALLOW cache without limit.
- **Docker-free OpenFGA integration backend (linux/amd64).** Set `APPARITOR_OPENFGA_NATIVE=1` to run the
  OpenFGA E2E against a pinned, **SHA-256-verified** OpenFGA release binary launched directly
  (only `github.com` egress needed) instead of a container, so the real-PDP test works where
  the Docker registry is unreachable. Same vendored model + tuples and assertions; a
  `workflow_dispatch` `integration-native` CI job exercises it.
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
- **Observability (M2).** A dependency-free metrics sink (`MetricsSink` protocol with a
  default `InMemoryMetrics` and a `NoopMetrics` opt-out): a decision-latency histogram and
  a cache-hit/miss counter, surfaced on the engine and scanner. Structured audit logs now
  carry the verdict, status, subject (decision principal), correlation id, and an argument
  *fingerprint*; raw arguments and tokens are never logged (arguments are fingerprinted).
- **AuthZEN 1.0 wire-conformance suite** (`tests/conformance/`): vendored canonical
  request/response payloads driven through the models and client to prove wire
  compatibility (request shapes, response decisions, batch aggregation, and malformed
  responses failing closed).

### Changed

- **Renamed to `apparitor` and repositioned.** The project is now a vendor-neutral
  authorization layer that aggregates policy engines (AuthZEN, Cedar, OpenFGA, Rego) across
  agentic firewalls (LlamaFirewall today; NeMo Guardrails planned), rather than an
  AuthZEN-scanner-for-LlamaFirewall only. The Python import package and PyPI distribution
  are now **`apparitor`** (was `authzen_llamafirewall` / `authzen-llamafirewall-scanner`):
  `from apparitor import AuthZENScanner`. Breaking import change — acceptable pre-alpha, no
  published release affected. Public API names (`AuthZENScanner`, `AuthorizationEngine`, …)
  are unchanged.
- **Spec fix:** the batch options field is now `evaluations_semantic` (plural), matching
  AuthZEN 1.0; it was previously serialised as `evaluation_semantic`. Renames
  `EvaluationsOptions.evaluation_semantic` → `evaluations_semantic` (pre-alpha, breaking).
- `DefaultToolCallMapper._resource` takes the request context (so `MCPResourceMapper` can
  resolve a per-call server label). A custom mapper subclass overriding the protected
  `_resource` must adopt the new signature; the public `ToolCallMapper.map` contract is
  unchanged.

### Not yet implemented

- Amazon Verified Permissions (cloud) example and the end-to-end scenario walk-through.

## [0.0.1a0]
- Initial pre-alpha scaffold.
