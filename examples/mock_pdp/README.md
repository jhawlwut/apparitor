# Mock PDP

A tiny, dependency-free AuthZEN PDP for tests and demos — implemented in
[`mock_pdp.py`](mock_pdp.py) using only the standard library. It serves
`POST /access/v1/evaluation` and `/access/v1/evaluations`, allowing everything except a
configurable deny-list of `"<action>:<resource id>"` rules.

```bash
python examples/mock_pdp/mock_pdp.py --port 8080 --deny tool_call.execute:database.delete_table
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
