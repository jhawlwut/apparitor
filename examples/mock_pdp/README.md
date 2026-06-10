# Mock PDP

A tiny, dependency-free AuthZEN PDP for tests and demos — implemented in
[`mock_pdp.py`](mock_pdp.py) using only the standard library. It serves
`POST /access/v1/evaluation` and `/access/v1/evaluations`, allowing everything except a
configurable deny-list.

Two deny-rule forms are supported:

| Form | Matches |
| --- | --- |
| `<action>:<resource_id>` | Any subject performing that action on that resource |
| `<subject_id>:<action>:<resource_id>` | A specific subject performing that action on that resource |

Both are pure membership tests on the composed key — never split or parsed — so resource
ids containing `:` are safe.

```bash
# Deny any subject from executing delete_table
python examples/mock_pdp/mock_pdp.py --port 8080 --deny tool_call.execute:delete_table

# Deny only "travel-bot" from executing book_flight (other subjects may still call it)
python examples/mock_pdp/mock_pdp.py --port 8080 --deny travel-bot:tool_call.execute:book_flight
```

Then point the scanner at it (local dev → `allow_insecure_pdp=True` since it's plain HTTP):

```python
from apparitor import AuthZENScanner, ScannerConfig

scanner = AuthZENScanner(config=ScannerConfig(
    pdp_url="http://127.0.0.1:8080", allow_insecure_pdp=True, agent_id="demo-agent",
))
```

This is not a real authorization engine — it exists to exercise the scanner end-to-end
without standing up OpenFGA/Cedar. See [../README.md](../README.md).
