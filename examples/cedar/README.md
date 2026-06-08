# Cedar example

Wires the scanner to [Cedar](https://www.cedarpolicy.com/) — AWS's open-source,
**policy-as-code (ABAC)** language. Unlike OpenFGA, Cedar has no native AuthZEN endpoint,
so this example runs the official `cedar` CLI behind a small **AuthZEN gateway** we own
([`gateway/gateway.py`](gateway/gateway.py)). The scanner speaks plain AuthZEN; the
gateway translates each request into a `cedar authorize` call over vendored policies and
entities.

Together with the [OpenFGA example](../openfga/), this shows the scanner works unchanged
across both major authorization paradigms — relationship-based and policy-based — over the
same AuthZEN API.

## What it shows

[`policies.cedar`](policies.cedar) permits the demo agent to execute low-sensitivity,
non-destructive tools and **forbids** any destructive tool outright (`forbid` overrides
`permit`). Tool attributes live in [`entities.json`](entities.json):

| Tool | `sensitivity` | `destructive` | Decision |
| --- | --- | --- | --- |
| `send_email`, `read_file` | low | false | Allow |
| `delete_database` | high | true | Deny |

## AuthZEN → Cedar mapping (in the gateway)

| AuthZEN field | Cedar |
| --- | --- |
| `subject.type` + `subject.id` | principal `Agent::"demo-agent"` |
| `action.name` | action `Action::"tool_call.execute"` |
| `resource.type` + `resource.id` | resource `Tool::"send_email"` |
| `context` | Cedar request `context` |

The gateway fails **closed**: any `cedar` error or non-Allow exit code becomes
`decision: false`. Cedar's default `action.name` (`tool_call.execute`) is used as-is — no
relation wiring is needed, unlike OpenFGA.

It serves both AuthZEN endpoints: single `POST /access/v1/evaluation` and batch
`POST /access/v1/evaluations`. The scanner uses the batch endpoint to pre-authorize a
multi-tool-call message in one request; each entry is evaluated independently and fails
closed, so under `execute_all` the message is allowed only if every call is permitted.

## Performance (and why it isn't tuned)

The gateway forks the `cedar` CLI once per decision and evaluates batch entries
**sequentially**, re-reading the vendored policies and entities each time — so an
N-tool-call batch costs roughly N serial `cedar` invocations. This is deliberate, not an
oversight: sequential forks plus the `_MAX_BATCH` cap bound how many `cedar` processes an
unauthenticated caller can spawn at once, so the shim can't become a fork-amplification
lever. Don't "optimise" it into a thread pool without first adding a **global** concurrency
cap and container CPU/memory limits, or you reopen that denial-of-service surface.

It's example glue to show the scanner speaks AuthZEN to Cedar — not a latency-tuned PDP.
The scanner protects itself regardless: a slow PDP trips its `request_budget_s` and
fails closed rather than stalling the agent. For real throughput, run Cedar behind a
long-lived service (e.g. in-process bindings) that owns its own concurrency and limits.

## Run

Requires Docker, `curl`, and `jq`. The first run builds the Cedar CLI from source
(`cargo install`), so it needs network egress and takes a few minutes.

```bash
./smoke.sh
```

This builds + starts the gateway ([`docker-compose.yml`](docker-compose.yml)) and asserts
a permitted tool is allowed, a destructive one is denied, and a batch is allowed only when
every entry is permitted — then tears down.

## Point the scanner at it

```python
from apparitor import AuthZENScanner, ScannerConfig

scanner = AuthZENScanner(config=ScannerConfig(
    pdp_url="http://127.0.0.1:8080",
    allow_insecure_pdp=True,   # local dev, plain HTTP
    agent_id="demo-agent",
))
```

The Docker-gated integration test in
[`tests/integration/test_cedar.py`](../../tests/integration/test_cedar.py) builds the
gateway image and drives the real engine against it. The managed AWS variant — Amazon
Verified Permissions — lives in [`../avp/`](../avp/). See [../README.md](../README.md).
