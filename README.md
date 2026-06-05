# authzen-llamafirewall-scanner

**An AuthZEN authorization scanner for [Meta's LlamaFirewall](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall).**

Content-safety guardrails ask *"is this prompt malicious?"* They do **not** ask
*"is this agent **allowed** to do this?"* This plugin fills that gap: it evaluates an
agent's tool calls against any [AuthZEN 1.0](https://openid.net/specs/authorization-interop-spec-1_0.html)
Policy Decision Point (PDP) — OpenFGA, Cedar/AVP, OPA, Cerbos, Topaz — and maps the authorization
decision back onto LlamaFirewall's `ALLOW` / `BLOCK` / `HUMAN_IN_THE_LOOP` model.

Apache-2.0 licensed. Built entirely on public standards.

> **Status: `0.0.1a0` — pre-alpha scaffold.** This repository currently contains the
> architecture, the technical requirements, and the typed project skeleton. The scanner
> logic is **not yet implemented** (`scan()` raises `NotImplementedError`). Do not use in
> production. See [`docs/requirements.md`](docs/requirements.md) for the design.

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
from authzen_llamafirewall import AuthZENScanner

# Point at any AuthZEN-compliant PDP. Secure defaults: fail-closed, TLS-verified.
scanner = AuthZENScanner(pdp_url="https://pdp.internal")

firewall = LlamaFirewall(scanners={Role.ASSISTANT: [scanner]})
result = await firewall.scan_async(assistant_message)   # ALLOW / BLOCK / HUMAN_IN_THE_LOOP
```

The AuthZEN client and models are **LlamaFirewall-free** and usable on their own:

```python
from authzen_llamafirewall.models import EvaluationRequest   # no LlamaFirewall needed
```

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
