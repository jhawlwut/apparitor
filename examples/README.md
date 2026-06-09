# Examples

Worked examples wiring the scanner to PDPs. The **mock PDP, OpenFGA, Cedar, and OPA
examples are runnable** (each with a `smoke.sh` and a Docker-gated integration test); AVP
and the scenario walk-through are still placeholders (see [`ROADMAP.md`](../ROADMAP.md) M3).

| Directory | What it shows | Status |
| --- | --- | --- |
| [`mock_pdp/`](mock_pdp/) | A tiny in-process AuthZEN PDP for tests/demos | runnable |
| [`openfga/`](openfga/) | OpenFGA (Zanzibar/ReBAC) with the native, experimental AuthZEN API | runnable |
| [`cedar/`](cedar/) | Cedar (ABAC) behind a local AuthZEN gateway | runnable |
| [`opa/`](opa/) | OPA / Rego (policy-as-code) behind a local AuthZEN gateway | runnable |
| [`avp/`](avp/) | Amazon Verified Permissions (managed Cedar) — later, cloud example | placeholder |
| [`scenarios/`](scenarios/) | Deny / out-of-scope / allow / PDP-unreachable / batch pre-authorization | placeholder |

The lead backends are **OpenFGA** (relationship-based) and **Cedar** (policy-as-code) —
together they show the scanner works across both major authorization paradigms over the
same AuthZEN API. The **OPA / Rego** example adds the CNCF general-purpose policy engine;
any other AuthZEN 1.0 PDP (Cerbos, Topaz, …) works the same way.

## Reproducibility notes

- Container images are pinned **by digest** with healthchecks; a `justfile`/`smoke.sh`
  drives bring-up and a smoke check.
- Policy bundles / models are **vendored and pinned** — no fetching at runtime (works
  under restricted egress).
- Anything requiring Docker is excluded from the default CI run and auto-skips when no
  daemon is present.
