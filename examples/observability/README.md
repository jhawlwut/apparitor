# Observability: the decision log and metrics, made runnable

apparitor's audit log is its compliance surface — [`docs/audit-log.md`](../../docs/audit-log.md)
freezes it as a stability contract and [`docs/eu-ai-act.md`](../../docs/eu-ai-act.md) maps it to
the EU AI Act. This is the most heavily *documented* part of the project and, until this
example, the least *shown*. [`run.py`](run.py) closes that gap with **core install only — no
extras, no Docker**.

It does the four things the docs describe but never demonstrate:

1. **Configures the `apparitor` logger** with a UTC, ISO-8601 formatter. `docs/audit-log.md`
   says you MUST: a sink that keeps only the message and no event time is not an audit trail.
2. **Emits every contract line**, then prints them as they are logged:

   | Line | When | Carries |
   | --- | --- | --- |
   | **C1** decision record | every enforcement decision | verdict, status, every principal, resources, fingerprints, correlation, latency |
   | **C2** `denied_legs` | a multi-request (e.g. dual-principal) batch that denies | which `type:id` leg blocked, per resource |
   | **C3** per-item summary | a `tools/list`-style visibility filter (`evaluate_each`) | one advisory verdict per item (not an audit record) |

3. **Parses them back** with `ast.literal_eval`, exactly as the doc's parsing guidance
   prescribes — turning the frozen grammar into living, asserted code (a consumer-side
   companion to `tests/unit/test_log_contract.py`).
4. **Forwards metrics** through a custom `MetricsSink` that renders the Prometheus exposition
   format `metrics.py` advertises: decision counters, a latency histogram, and cache outcomes.

## Run

From the repo root:

```bash
pip install -e .
python examples/observability/run.py
```

The script drives five decisions — `allow`, a policy `block`, a policy-driven `human_review`
(the Article 14 case: the PDP permits but flags the call for a human via the advisory response
`context`), a dual-principal deny (the user holds the grant, the agent boundary does not → C1
naming both principals + C2), and a per-item filter (C3). It prints the live log lines, the
parsed records, and a `/metrics` scrape, then asserts the contract from the consumer side and
exits non-zero on any mismatch. The `observability` CI job runs it on every PR and push to
`main`.

## EU AI Act mapping

- **C1 is the Article 12 record** for the authorization function: per-decision outcome, every
  principal, the resource, and a per-call fingerprint. Set `correlation_id` on every request
  (the example does) so decisions chain to sessions.
- **`verdict=human_review` is the Article 14** human-oversight signal — a decision escalated to
  a person. Who reviewed it and the outcome happen outside apparitor and join on `correlation`.

See [`docs/eu-ai-act.md`](../../docs/eu-ai-act.md) for the full field-by-field mapping.

## Notes that keep the demo honest

- The PDP is a permit-by-default deny-list (it reuses [`../mock_pdp/`](../mock_pdp/)'s decision
  logic and adds the advisory review `context`). That is the **inverse** of production semantics
  and must not be copied — it exists to exercise the log end-to-end without standing up a real
  engine.
- The logger is **sensitive**: subject ids are decision principals and may be emails. In
  production route it to a restricted, access-controlled sink with a retention policy that meets
  your obligation (six months under AI Act Arts. 19/26(6)); the example prints to stdout only to
  be readable.
- C1 fingerprints cover argument **key names** only under the default `redact_arguments=True`.
  Deployments that must reconstruct *what* was attempted set `redact_arguments=False` (weigh the
  GDPR cost) or keep input records in an adjacent system joined on `correlation`. See
  `docs/audit-log.md` for the full grammar and stability policy.
