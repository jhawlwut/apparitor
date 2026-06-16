# Examples

Worked examples for apparitor, in two groups: **policy engines** (where the authorization
decision is made) and **patterns & operations** (cross-cutting concerns shown end-to-end).
Everything marked *runnable* runs as-is; the **three-peps**, **gateway**, **scenarios**, and
**observability** examples are **CI-gated and need no Docker** (core install or in-process
only). AVP is a placeholder (see [`ROADMAP.md`](../ROADMAP.md) M4).

## Policy engines

| Directory | What it shows | Status |
| --- | --- | --- |
| [`mock_pdp/`](mock_pdp/) | A tiny in-process AuthZEN PDP for tests/demos | runnable |
| [`openfga/`](openfga/) | OpenFGA (Zanzibar/ReBAC) with the native, experimental AuthZEN API | runnable |
| [`cedar/`](cedar/) | Cedar (ABAC) behind a local AuthZEN gateway | runnable |
| [`opa/`](opa/) | OPA / Rego (policy-as-code) behind a local AuthZEN gateway | runnable |
| [`avp/`](avp/) | Amazon Verified Permissions (managed Cedar), a later cloud example | placeholder |

The lead backends are **OpenFGA** (relationship-based) and **Cedar** (policy-as-code).
Together they show the scanner works across both major authorization paradigms over the
same AuthZEN API. The **OPA / Rego** example adds the CNCF general-purpose policy engine;
any other AuthZEN 1.0 PDP (Cerbos, Topaz, …) works the same way.

## Patterns & operations

| Directory | What it shows | Status |
| --- | --- | --- |
| [`three-peps/`](three-peps/) | One Cedar policy enforced at the scanner, the NeMo rail, and the FastMCP middleware (in-process, no Docker) | runnable |
| [`gateway/`](gateway/) | An authorization gateway in front of an MCP server you can't modify (proxy + middleware) | runnable |
| [`scenarios/`](scenarios/) | Allow / deny / unparseable / PDP-unreachable (both on_error modes) / batch / dual-principal walk-through | runnable |
| [`observability/`](observability/) | The decision log (C1/C2/C3) and metrics: configure the logger, emit + parse every contract line, scrape Prometheus | runnable |

## Reproducibility notes

- Container images are pinned **by digest** with healthchecks; a `smoke.sh` drives
  bring-up and a smoke check.
- Policy bundles / models are **vendored and pinned**: no fetching at runtime (works
  under restricted egress).
- Anything requiring Docker is excluded from the default CI run and auto-skips when no
  daemon is present.
