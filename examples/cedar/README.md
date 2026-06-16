# Cedar example

Wires the scanner to [Cedar](https://www.cedarpolicy.com/), AWS's open-source,
**policy-as-code (ABAC)** language. Unlike OpenFGA, Cedar has no native AuthZEN endpoint,
so this example runs the official `cedar` CLI behind a small **AuthZEN gateway** we own
([`gateway/gateway.py`](gateway/gateway.py)). The scanner speaks plain AuthZEN; the
gateway translates each request into a `cedar authorize` call over vendored policies and
entities.

Together with the [OpenFGA example](../openfga/), this shows the scanner works unchanged
across both major authorization paradigms (relationship-based and policy-based) over the
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
`decision: false`. Cedar's default `action.name` (`tool_call.execute`) is used as-is. No
relation wiring is needed, unlike OpenFGA.

It serves both AuthZEN endpoints: single `POST /access/v1/evaluation` and batch
`POST /access/v1/evaluations`. The scanner uses the batch endpoint to pre-authorize a
multi-tool-call message in one request; each entry is evaluated independently and fails
closed, so under `execute_all` the message is allowed only if every call is permitted.

## Performance (and why it isn't tuned)

The gateway forks the `cedar` CLI once per decision and evaluates batch entries
**sequentially**, re-reading the vendored policies and entities each time, so an
N-tool-call batch costs roughly N serial `cedar` invocations. This is deliberate: sequential
forks plus the `_MAX_BATCH` cap bound how many `cedar` processes an
unauthenticated caller can spawn at once, so the shim can't become a fork-amplification
lever. Don't "optimise" it into a thread pool without first adding a **global** concurrency
cap and container CPU/memory limits, or you reopen that denial-of-service surface.

It's example glue to show the scanner speaks AuthZEN to Cedar, not a latency-tuned PDP.
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
every entry is permitted, then tears down.

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
gateway image and drives the real engine against it. The managed AWS variant, Amazon
Verified Permissions, lives in [`../avp/`](../avp/). See [../README.md](../README.md).

## Native backend (no gateway)

The gateway above lets the scanner speak plain AuthZEN to the `cedar` CLI. If you'd rather
skip the gateway entirely, the scanner has a **native Cedar backend** that evaluates the
policy **in-process** via the optional [`cedarpy`](https://pypi.org/project/cedarpy/) binding
(no server, no subprocess, no network; decisions never leave the host). Install the extra
and point at the vendored policy + entities:

```bash
pip install 'apparitor[cedar]'
```

```python
from apparitor import AuthZENScanner, ScannerConfig

scanner = AuthZENScanner(config=ScannerConfig(
    backend="cedar",                          # evaluate Cedar in-process via cedarpy
    agent_id="demo-agent",
    cedar_policies_path="policies.cedar",     # your Cedar policy set
    cedar_entities_path="entities.json",      # your entities
    # cedar_schema_path="schema.json",        # optional; enables schema validation
))
```

Paths are resolved against the process working directory, so this snippet only finds the files
if you run it from `examples/cedar/`; use absolute paths in production.

The backend maps the AuthZEN tuple onto a Cedar request (`Agent::"…"` / `Action::"…"` /
`Tool::"…"`) and is fail-closed: only an explicit Cedar `Allow` is ALLOW; `Deny` and
`NoDecision` deny, never a coerced allow. The policy set is parsed (and, if you pass
`cedar_schema_path`, validated) **at construction**, so a policy typo raises an
`AuthZENConfigError` at startup rather than silently denying every request. Cedar treats a
parse error as `NoDecision`, not an exception. A multi-tool-call message uses Cedar's
`is_authorized_batch` and is allowed only if every call is permitted. Cedar returns boolean
decisions only, so the advisory `context` / `review_predicate` HITL path does not apply to this
backend (as with native OPA).

When to use which:

| | Gateway (AuthZEN) | Native backend (`backend="cedar"`) |
| --- | --- | --- |
| Extra process | the `cedar` CLI behind the gateway | none, evaluated in-process |
| Dependency | Docker / the `cedar` CLI | the `cedarpy` wheel (`apparitor[cedar]`) |
| Data residency | request crosses the gateway hop | decision stays in your process |
| Best for | standardising on AuthZEN across engines | embedding Cedar with the least moving parts |

`cedarpy` wraps the Apache-2.0 Cedar engine but is a third-party binding (not AWS-official),
so it is pinned in the optional `[cedar]` extra and bumped deliberately. The native Cedar
backend is covered by [`tests/unit/test_cedar_backend.py`](../../tests/unit/test_cedar_backend.py),
which drives the real engine against this vendored policy.
