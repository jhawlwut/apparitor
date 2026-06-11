# EU AI Act — Compliance Reference

This document maps apparitor's decision log and verdict model onto the EU AI Act
obligations relevant to agentic AI deployments. It is not legal advice and does not
substitute for an assessment against the full Act text or Annex III.

**Enforcement deadline:** high-risk AI system obligations under Articles 8–17, 26, and
73 apply from **2 August 2026**.

## Which articles apply

| Article | Obligation | Who bears it |
|---------|-----------|-------------|
| Art. 12 | Automatic logging of events relevant to risk identification; tamper-evident; ≥ 6-month retention | Provider (technical capability) + Deployer (retention and tamper-evidence infrastructure) |
| Art. 14 | Human-oversight mechanism must be technically built into the system | Provider |
| Art. 26 | Deployer must maintain logs, ensure human oversight operates, document use-case risk | Deployer |

## What apparitor provides

### Automatic decision logging (Article 12)

Every authorization decision emits one structured line to `logging.getLogger("apparitor")`
at `INFO` level. The line is machine-parseable and maps onto Article 12 as follows:

| Log field | Example | Article 12 relevance |
|-----------|---------|---------------------|
| `verdict` | `allow` / `block` / `human_review` | Risk event — every denial and every escalation to human review |
| `status` | `success` / `error` | Risk event — `error` means the PDP was unreachable; the agent was still blocked (fail-closed) |
| `subjects` | `["user:alice@acme.com", "agent:travel-bot"]` | Identity of every principal at the moment of decision; under dual-principal evaluation both the end-user and the agent boundary appear |
| `resources` | `["database.delete_table"]` | The tool, resource URI, or A2A agent the action targeted |
| `fingerprints` | `["a3f8c1d2b5e4"]` | Short SHA-256 digest of the full request tuple — identifies the exact call without logging raw arguments |
| `correlation` | `"conv-abc-123"` | Ties the decision to the wider agent session for cross-event traceability |
| `latency_ms` | `12.4` | Operational monitoring |

Two event classes that the policy engine never records are present here:

- **Error-path blocks** (`status=error`): when the PDP is unreachable and the call is
  blocked fail-closed, the event appears in the apparitor log. The PDP has no record of it.
- **Dual-principal denials**: the batch leg that triggered a deny is identified by name in
  `subjects` and `resources`, so the audit trail distinguishes a user-grant denial from an
  agent-boundary denial without replaying the batch against the PDP.

### Human oversight (Article 14)

`HUMAN_IN_THE_LOOP_REQUIRED` is a first-class verdict in apparitor's decision model,
not an add-on. Two ways to reach it:

- `on_error=human_review` — PDP-unavailable events escalate to human review rather than
  hard-blocking (default is `on_error=deny`; there is no fail-open option).
- `review_predicate` — a caller-supplied function over the PDP response `context` that
  can escalate specific policy responses to human review; it can only escalate, never
  downgrade a deny.

Only a clean `ALLOW` proceeds to tool execution. Both `HUMAN_IN_THE_LOOP_REQUIRED` and
`BLOCK` halt the agent action before it runs.

### Fail-closed default

`on_error=deny` is the default. When authorization cannot be completed — PDP
unreachable, timeout, malformed response — the call is blocked and the event is logged
with `status=error`. There is no global fail-open configuration option.

## What the deployer must provide

apparitor emits the right events. **Tamper-evidence and retention are infrastructure
obligations the deployer must satisfy under Article 26.**

**Tamper-evidence:** route the `apparitor` logger to an append-only, write-protected log
store — AWS CloudWatch with tamper protection, Azure Monitor Logs, an immutable S3 bucket
with Object Lock, a SIEM, or equivalent. Python's `logging` module alone is not
tamper-evident.

**Retention:** Article 12 requires logs be retained for at least **6 months** from the
date of each event (24 months for biometric and law-enforcement systems). Configure your
log store accordingly.

**Log routing (minimal example):**

```python
import logging
import logging.handlers

# Replace with your SIEM forwarder, CloudWatch handler, or equivalent.
handler = logging.handlers.WatchedFileHandler("/var/log/apparitor/decisions.jsonl")
handler.setFormatter(logging.Formatter("%(message)s"))

log = logging.getLogger("apparitor")
log.addHandler(handler)
log.setLevel(logging.INFO)
```

Treat the `apparitor` logger as sensitive: `subjects` may contain email addresses or
other personal identifiers. Route it to an access-controlled store and apply any
applicable GDPR pseudonymisation before long-term retention.

## EU Cloud and AI Development Act (CADA)

CADA's sovereignty assurance requirements are met structurally:

- **Data residency:** the PDP is operator-chosen. An EU-hosted OpenFGA, Cerbos, OPA, or
  Topaz instance means no authorization request leaves the EU sovereign envelope.
- **Supply-chain transparency:** a CycloneDX SBOM of the runtime dependency tree is
  generated at every release and attached to the GitHub Release as `apparitor.cdx.json`.
- **No proprietary lock-in:** Apache-2.0 license, no closed components, no telemetry,
  no vendor-controlled PDP required.

## Is my AI system high-risk?

Annex III of the Act lists the high-risk categories. Agentic AI systems making autonomous
decisions in employment, essential services, education, law enforcement, border control,
or critical infrastructure are most likely in scope. Review Annex III and Article 6
against your use case; this document assumes high-risk classification applies.
