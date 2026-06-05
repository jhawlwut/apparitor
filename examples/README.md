# Examples

Worked examples wiring the scanner to real PDPs. **These are placeholders** — the
implementations land alongside the scanner logic (see the tracking issue and
[`docs/requirements.md`](../docs/requirements.md)).

| Directory | What it will show |
| --- | --- |
| [`mock_pdp/`](mock_pdp/) | A tiny in-process AuthZEN PDP for tests/demos |
| [`openfga/`](openfga/) | OpenFGA (Zanzibar/ReBAC) with the native, experimental AuthZEN API |
| [`cedar/`](cedar/) | Cedar (ABAC) behind a local AuthZEN gateway |
| [`avp/`](avp/) | Amazon Verified Permissions (managed Cedar) — later, cloud example |
| [`scenarios/`](scenarios/) | Deny / out-of-scope / allow / PDP-unreachable / batch pre-authorization |

The lead backends are **OpenFGA** (relationship-based) and **Cedar** (policy-as-code) —
together they show the scanner works across both major authorization paradigms over the
same AuthZEN API. Any AuthZEN 1.0 PDP (OPA, Cerbos, Topaz, …) works the same way.

## Reproducibility notes

- Container images are pinned **by digest** with healthchecks; a `justfile`/`smoke.sh`
  drives bring-up and a smoke check.
- Policy bundles / models are **vendored and pinned** — no fetching at runtime (works
  under restricted egress).
- Anything requiring Docker is excluded from the default CI run and auto-skips when no
  daemon is present.
