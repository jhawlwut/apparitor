# OpenFGA example

Wires the scanner to [OpenFGA](https://openfga.dev), a Zanzibar-style,
**relationship-based (ReBAC)** engine, through its native, experimental **AuthZEN**
API. OpenFGA implements AuthZEN single and batch evaluation by mapping each request onto
its `Check` endpoint, so the scanner talks to it with no OpenFGA-specific code.

## What it shows

`agent:demo-agent` is granted `can_execute` on a small allow-list of tools. The scanner
sends an AuthZEN evaluation per tool call; OpenFGA returns `decision: true` for a granted
tool and `decision: false` for anything ungranted, which the scanner maps to `ALLOW` /
`BLOCK`.

The vendored model (`model.json`, shown below as DSL) and tuples (`tuples.json`) are
loaded at bring-up; nothing is fetched at runtime.

```fga
model
  schema 1.1

type agent

type tool
  relations
    define can_execute: [agent]
```

## AuthZEN → OpenFGA mapping

| AuthZEN field | OpenFGA | Demo value |
| --- | --- | --- |
| `subject.type` + `subject.id` | user | `agent:demo-agent` |
| `action.name` | relation | `can_execute` |
| `resource.type` + `resource.id` | object | `tool:send_email` |

`action.name` **must** equal a relation defined on the resource type, so point the scanner
at `can_execute` rather than the default `tool_call.execute`. The endpoints are
store-scoped (`/stores/{store_id}/access/v1/evaluation`).

## Run

Requires Docker, `curl`, and `jq`.

```bash
./smoke.sh
```

This brings up OpenFGA (`docker-compose.yml`), creates a store, loads the model + tuples,
and asserts a granted tool is allowed and an ungranted one is denied. It tears the stack
down on exit.

### Without Docker

Where the Docker registry is unreachable but `github.com` is not (restricted-egress CI,
sandboxes), the integration test can run OpenFGA from its pinned release binary
(**linux/amd64 only**) instead of a container. It is downloaded once and **SHA-256-verified**
before it runs:

```bash
APPARITOR_OPENFGA_NATIVE=1 pytest tests/integration/test_openfga.py -m integration --no-cov
```

Same vendored model + tuples, same assertions; no Docker or `testcontainers` needed.

## Point the scanner at it

The store id is created at runtime, so it goes into the evaluation path:

```python
from apparitor import AuthZENScanner, ScannerConfig

scanner = AuthZENScanner(config=ScannerConfig(
    pdp_url="http://127.0.0.1:8080",
    allow_insecure_pdp=True,           # local dev, plain HTTP
    agent_id="demo-agent",
    action_name="can_execute",         # the OpenFGA relation
    evaluation_path=f"/stores/{store_id}/access/v1/evaluation",
    batch_path=f"/stores/{store_id}/access/v1/evaluations",
))
```

The Docker-gated integration test in
[`tests/integration/test_openfga.py`](../../tests/integration/test_openfga.py) drives the
real engine against this deployment end-to-end. See [../README.md](../README.md).
