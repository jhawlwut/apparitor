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
not a PDP's policy decisions, so no policy engine is required; it can be extended with the
full interop todo decision matrix where a reproducing PDP is available.

These run in the default unit suite (no Docker, no real network).
