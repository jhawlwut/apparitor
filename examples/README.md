# Examples

Worked examples wiring the scanner to PDPs. The **mock PDP, OpenFGA, Cedar, OPA,
and scenarios examples are runnable**; **three-peps** runs fully in-process. **three-peps**, **gateway**, and **scenarios** are CI-gated with no Docker required. AVP remains a
placeholder (see [`ROADMAP.md`](../ROADMAP.md) M4).

| Directory | What it shows | Status |
| --- | --- | --- |
| [`mock_pdp/`](mock_pdp/) | A tiny in-process AuthZEN PDP for tests/demos | runnable |
| [`openfga/`](openfga/) | OpenFGA (Zanzibar/ReBAC) with the native, experimental AuthZEN API | runnable |
| [`cedar/`](cedar/) | Cedar (ABAC) behind a local AuthZEN gateway | runnable |
| [`opa/`](opa/) | OPA / Rego (policy-as-code) behind a local AuthZEN gateway | runnable |
| [`three-peps/`](three-peps/) | One Cedar policy enforced at the scanner, the NeMo rail, and the FastMCP middleware (in-process, no Docker) | runnable |
| [`avp/`](avp/) | Amazon Verified Permissions (managed Cedar) — later, cloud example | placeholder |
| [`gateway/`](gateway/) | An authorization gateway in front of an MCP server you can't modify (proxy + middleware) | runnable |
| [`scenarios/`](scenarios/) | Allow / deny / unparseable / PDP-unreachable (both on_error modes) / batch / dual-principal walk-through | runnable |

The lead backends are **OpenFGA** (relationship-based) and **Cedar** (policy-as-code) —
together they show the scanner works across both major authorization paradigms over the
same AuthZEN API. The **OPA / Rego** example adds the CNCF general-purpose policy engine;
any other AuthZEN 1.0 PDP (Cerbos, Topaz, …) works the same way.

## Reproducibility notes

- Container images are pinned **by digest** with healthchecks; a `smoke.sh` drives
  bring-up and a smoke check.
- Policy bundles / models are **vendored and pinned** — no fetching at runtime (works
  under restricted egress).
- Anything requiring Docker is excluded from the default CI run and auto-skips when no
  daemon is present.
