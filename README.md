<p align="center">
  <a href="https://app.aikido.dev/repositories/2253820/checks"><img src="https://img.shields.io/badge/Aikido%20Security-scanned%20daily-4c1?logo=aikido&logoColor=white" alt="Aikido Security Status"></a>
</p>

# authzen-llamafirewall-scanner

[![CI](https://github.com/jhawlwut/authzen-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/jhawlwut/authzen-scanner/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen.svg)](pyproject.toml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

**An AuthZEN authorization scanner for [Meta's LlamaFirewall](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall).**

Content-safety guardrails ask *"is this prompt malicious?"* They do **not** ask
*"is this agent **allowed** to do this?"* This plugin fills that gap: it evaluates an
agent's tool calls against any [AuthZEN 1.0](https://openid.net/specs/authorization-interop-spec-1_0.html)
Policy Decision Point (PDP) — OpenFGA, Cedar/AVP, OPA, Cerbos, Topaz — and maps the authorization
decision back onto LlamaFirewall's `ALLOW` / `BLOCK` / `HUMAN_IN_THE_LOOP` model.

Apache-2.0 licensed. Built entirely on public standards.

> **Status: `0.0.1a0` — pre-alpha.** The scan pipeline works end-to-end against any
> AuthZEN PDP (see [`CHANGELOG`](CHANGELOG.md)), with 98% test coverage on the
> LlamaFirewall-free core. Still pre-alpha: real OpenFGA/Cedar example wiring and
> conformance tests are pending, and APIs may change. See
> [`docs/requirements.md`](docs/requirements.md) for the design and [`ROADMAP`](ROADMAP.md).

## The gap

```
Agent: "Delete the production database"
         │
         ▼
   LlamaFirewall      → "Is this prompt malicious?"            → PASS (it's not a jailbreak)
         │
         ▼
   ??? nothing ???    → "Is this agent authorized to do this?" → NO CHECK
         │
         ▼
   Tool executes.  Production database deleted.
```

With this scanner in the loop:

```
Agent: "Delete the production database"
         │
         ▼
   LlamaFirewall scanners (PromptGuard, AlignmentCheck, CodeShield, …)   → PASS
         │
         ▼
   AuthZENAuthorizationScanner ──POST /access/v1/evaluation──▶  AuthZEN PDP (OpenFGA / Cedar / …)
         │                                                         │
         │  ◀────────────────── { "decision": false } ────────────┘
         ▼
   BLOCK — "agent travel-bot-123 is not authorized for tool_call.execute on database.delete_table"
```

## Quickstart (target API — wiring is ≤10 lines)

```python
from llamafirewall import LlamaFirewall, Role
from authzen_llamafirewall import AuthZENScanner, ScannerConfig

# Point at any AuthZEN-compliant PDP. Secure defaults: fail-closed, TLS-verified.
# A subject must be resolvable — set config.agent_id, or current_subject per request.
scanner = AuthZENScanner(config=ScannerConfig(pdp_url="https://pdp.internal", agent_id="travel-bot"))

firewall = LlamaFirewall(scanners={Role.ASSISTANT: [scanner]})
result = await firewall.scan_async(assistant_message)   # ALLOW / BLOCK / HUMAN_IN_THE_LOOP
```

Per request, resolve the real end user the agent acts for (recommended over a static
`agent_id`). Use `subject_scope` so the identity is always reset and can never leak to a
later request that reuses the same task/event loop:

```python
from authzen_llamafirewall import Subject, subject_scope

with subject_scope(Subject(type="user", id="alice@acme.com")):
    result = await firewall.scan_async(assistant_message)
```

The AuthZEN client and models are **LlamaFirewall-free** and usable on their own:

```python
from authzen_llamafirewall.models import EvaluationRequest   # no LlamaFirewall needed
```

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
`NoopMetrics()` to disable. Each decision also emits one structured audit log line (verdict,
status, subject id, correlation id, tool names, and an argument *fingerprint*). Raw tool
arguments and tokens are never logged — arguments are fingerprinted. The subject id is the
decision principal (it may itself be an identifier such as an email), so treat the
`authzen_llamafirewall` logger as sensitive and route it accordingly.

## PDP support matrix

| PDP | AuthZEN support | Example |
| --- | --- | --- |
| **Mock PDP** (testing/demo) | n/a | [`examples/mock_pdp/`](examples/mock_pdp/) |
| **OpenFGA** (Zanzibar / ReBAC) | native (experimental) | [`examples/openfga/`](examples/openfga/) |
| **Cedar** (policy-as-code) | via AuthZEN gateway | [`examples/cedar/`](examples/cedar/) |
| **Amazon Verified Permissions** (managed Cedar) | via [AWS AuthZEN interface](https://github.com/aws-samples/sample-authzen-interface-verified-permissions) | [`examples/avp/`](examples/avp/) |
| Any AuthZEN 1.0 PDP (OPA, Cerbos, Topaz, …) | by spec | [`docs/setup.md`](docs/setup.md) |

## Documentation

- [Technical requirements & design decisions](docs/requirements.md)
- [Architecture](docs/architecture.md)
- [Setup: connecting to a PDP](docs/setup.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)

## License

[Apache License 2.0](LICENSE).
