# AuthZEN conformance suite

Wire-conformance for the AuthZEN 1.0 Access Evaluation API. [`cases.json`](cases.json)
vendors canonical request/response payloads; [`test_conformance.py`](test_conformance.py)
drives them through the real models and `AuthZENClient` (via `respx`, no network) to prove:

- every canonical **request** shape validates and serialises with the spec field names
  (including `options.evaluations_semantic`, plural, per AuthZEN 1.0);
- every **response** parses to the authoritative boolean `decision`, mapping to the right
  verdict (single) or aggregate (batch);
- **malformed** responses (missing / non-bool `decision`) fail closed — never a coerced
  ALLOW (the `StrictBool` invariant).

## Provenance

Cases are seeded from the normative examples in the finalized
[AuthZEN Authorization API 1.0 spec](https://openid.net/specs/authorization-interop-spec-1_0.html)
plus derived deny / ABAC-properties / malformed edge cases. This checks the **interface**,
not a PDP's policy decisions, so no policy engine is required.

## Interop "Todo" decision matrix

[`interop_todo_cases.json`](interop_todo_cases.json) vendors the OpenID AuthZEN interop
**Todo** scenario (the Rick & Morty role matrix); [`test_interop_todo.py`](test_interop_todo.py)
drives every `(subject, action, resource)` tuple through the same models + client (mocked
PDP, no network) and, in addition, **re-derives every decision from the directory + role
rules** so the vendored matrix cannot silently drift from the documented policy.

- **Directory** (users → roles): from `openid/authzen`
  [`interop/authzen-todo-backend/src/directory.ts`](https://github.com/openid/authzen/blob/main/interop/authzen-todo-backend/src/directory.ts).
- **Rules + request shapes**: the `todo-1.1` payload spec,
  [`interop/authzen-interop-website/docs/scenarios/todo-1.1/index.md`](https://github.com/openid/authzen/blob/main/interop/authzen-interop-website/docs/scenarios/todo-1.1/index.md)
  (rendered at <https://authzen-interop.net/docs/scenarios/todo-1.1/>). Reads are universal;
  `can_create_todo` needs `admin`/`editor`; `can_update_todo` needs `evil_genius` or an
  `editor` who owns the todo; `can_delete_todo` needs `admin` or an `editor` who owns it.

Documented deviations from the live interop (see `_deviations` in the dataset): subjects use
the directory's **email** identity rather than the OIDC-encoded `sub` the interop resolves
through the same directory; `can_create_todo` requests carry a `resource.id` because AuthZEN
1.0 marks it REQUIRED (the draft payload omits it, and the decision is role-based regardless);
and the optional empty `context: {}` is omitted.

These run in the default unit suite (no Docker, no real network).
