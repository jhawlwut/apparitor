# Examples

Worked examples wiring the scanner to real PDPs. **These are placeholders** — the
implementations land alongside the scanner logic (see the tracking issue and
[`docs/requirements.md`](../docs/requirements.md)).

| Directory | What it will show |
| --- | --- |
| [`opa/`](opa/) | OPA via `kanywst/opa-authzen` (image pinned by digest; vendored bundle) |
| [`cerbos/`](cerbos/) | Cerbos with native AuthZEN |
| [`mock_pdp/`](mock_pdp/) | A tiny in-process AuthZEN PDP for tests/demos |
| [`scenarios/`](scenarios/) | Deny / out-of-scope / allow / PDP-unreachable / batch pre-authorization |

## Reproducibility notes

- Container images are pinned **by digest** with healthchecks; a `justfile`/`smoke.sh`
  drives bring-up and a smoke check.
- The `kanywst/opa-authzen` policy bundle is **vendored and pinned** — no fetching at
  runtime (works under restricted egress).
- Anything requiring Docker is excluded from the default CI run and auto-skips when no
  daemon is present.
