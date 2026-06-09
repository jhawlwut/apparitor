# OPA / Rego example

Wires the scanner to [OPA](https://www.openpolicyagent.org/) (Open Policy Agent) — the
CNCF **policy-as-code** engine and its **Rego** language. OPA exposes its own Data API
(`POST /v1/data/...` returning `{"result": ...}`), not AuthZEN, so this example runs the
official `opa` binary behind a small **AuthZEN gateway** we own
([`gateway/gateway.py`](gateway/gateway.py)). The scanner speaks plain AuthZEN; the gateway
feeds each request to OPA as the policy `input` and evaluates the vendored Rego policy.

Together with the [OpenFGA example](../openfga/) (relationship-based) and the
[Cedar example](../cedar/) (policy-as-code via a gateway), this shows the scanner works
unchanged across the popular authorization engines over the same AuthZEN API. OPA and Cedar
are both policy-as-code; this example evaluates general-purpose Rego, exercised through the
gateway over the same AuthZEN API.

## What it shows

[`policy.rego`](policy.rego) permits the demo agent to execute low-sensitivity,
non-destructive tools and denies everything else — `default allow := false` is the
fail-closed pivot. Tool attributes live in [`data.json`](data.json):

| Tool | `sensitivity` | `destructive` | Decision |
| --- | --- | --- | --- |
| `send_email`, `read_file` | low | false | Allow |
| `delete_database` | high | true | Deny |

## AuthZEN → OPA mapping (in the gateway)

| AuthZEN field | OPA policy `input` |
| --- | --- |
| `subject` | `input.subject` (`input.subject.id == "demo-agent"`) |
| `action.name` | `input.action.name` (`"tool_call.execute"`) |
| `resource` | `input.resource` (`data.tools[input.resource.id]`) |
| `context` | `input.context` (forwarded when present) |

The gateway runs `opa eval --format=json … data.apparitor.authz.allow`, reading the policy's
boolean `allow` rule. It fails **closed**: any `opa` error, non-zero exit, or non-`true`
result becomes `decision: false`. Because `allow` has a `default` of `false`, an unknown
tool or a missing attribute is a deny, not an error.

It serves both AuthZEN endpoints: single `POST /access/v1/evaluation` and batch
`POST /access/v1/evaluations`. The scanner uses the batch endpoint to pre-authorize a
multi-tool-call message in one request; each entry is evaluated independently and fails
closed, so under `execute_all` the message is allowed only if every call is permitted.

## Performance (and why it isn't tuned)

The gateway forks `opa eval` once per decision — recompiling the policy each time — and
evaluates batch entries **sequentially**, so an N-tool-call batch costs roughly N serial
`opa` invocations. This is deliberate, not an oversight: sequential forks plus the
`_MAX_BATCH` cap bound how many `opa` processes an unauthenticated caller can spawn at once,
so the shim can't become a fork-amplification lever. Don't "optimise" it into a thread pool
without first adding a **global** concurrency cap and container CPU/memory limits, or you
reopen that denial-of-service surface.

It's example glue to show the scanner speaks AuthZEN to OPA — not a latency-tuned PDP. For
real throughput, run OPA as a long-lived server (`opa run --server`) and translate AuthZEN
onto its Data API, or front it with a service that owns its own concurrency and limits. The
scanner protects itself regardless: a slow PDP trips its `request_budget_s` and fails closed
rather than stalling the agent.

## Run

Requires Docker, `curl`, and `jq`. The OPA binary comes from the digest-pinned official
image ([`gateway/Dockerfile`](gateway/Dockerfile)), so the build is offline and quick.

```bash
./smoke.sh
```

This builds + starts the gateway ([`docker-compose.yml`](docker-compose.yml)) and asserts a
permitted tool is allowed, a destructive one is denied, and a batch is allowed only when
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
[`tests/integration/test_opa.py`](../../tests/integration/test_opa.py) builds the gateway
image and drives the real engine against it. See [../README.md](../README.md).
