# Scenario walk-through

A self-asserting, dependency-free script that drives `AuthorizationEngine` through seven
scenarios (eight assertions — the dual-principal finale checks both a block and an allow)
using the [mock PDP](../mock_pdp/) on an ephemeral loopback port. No Docker, no optional
extras, no network egress.

## How to run

```bash
pip install -e .
python examples/scenarios/run.py
```

Exit 0 means all scenarios matched their expected verdicts; exit 1 means at least one
mismatch (the output names it).

## Scenarios

| # | Name | Tool call | Expected verdict | Expected status | What it exercises |
|---|------|-----------|-----------------|-----------------|-------------------|
| 1 | allow | `read_file` | ALLOW | success | Happy path |
| 2 | deny | `delete_table` | BLOCK | success | 2-part deny key (`action:resource`) |
| 3 | unparseable fails closed | `{"weird": "shape"}` | BLOCK | error | Malformed input never reaches the PDP |
| 4 | PDP unreachable, `on_error=deny` | `read_file` | BLOCK | error | Fail-closed on connection error |
| 5 | PDP unreachable, `on_error=human_review` | `read_file` | HUMAN_REVIEW | error | No fail-open; only deny or human review |
| 6 | batch all-or-nothing | `read_file` + `delete_table` | BLOCK | success | AND aggregation: one deny blocks the batch |
| 7a | dual-principal — agent blocks | `book_flight` (alice) | BLOCK | success | 3-part deny key (`subject:action:resource`) on the agent leg |
| 7b | dual-principal — both pass | `read_file` (alice) | ALLOW | success | Both user and agent legs allowed |

The deny-set used is:

```python
{"tool_call.execute:delete_table", "travel-bot:tool_call.execute:book_flight"}
```

See [../mock_pdp/README.md](../mock_pdp/README.md) for the two deny-rule forms
(`<action>:<resource_id>` and `<subject_id>:<action>:<resource_id>`).

## Honesty note

The mock PDP is a scripted deny-list, so these scenarios prove the **client-side contract**
— that the engine maps verdicts correctly (fail-closed on errors, all-or-nothing on batches,
AND on dual principals) — not that any real policy engine is configured correctly. For real
policy-engine examples see [`examples/three-peps/`](../three-peps/) (three enforcement points, Cedar in-process),
[`examples/openfga/`](../openfga/), [`examples/cedar/`](../cedar/), and
[`examples/opa/`](../opa/).
