# Security Review — 2026-06-11

An adversarial security review was conducted on 2026-06-11 against the threat model in
[`docs/requirements.md`](requirements.md) and [`SECURITY.md`](../SECURITY.md). It found
six issues (one HIGH, three MEDIUM, two LOW/hardening), all of which were fixed before
this document was written. The review also probed the properties the system is designed to
hold and found them all sound — those positive findings are documented in
[Properties verified](#properties-verified), which is the more important result. See
[Known limitations](#known-limitations--accepted-risks) for what is explicitly out of
scope or deferred.

## Scope & methodology

**Reviewed against:** [`docs/requirements.md`](requirements.md) (full threat model,
§§3.1–3.10) and [`SECURITY.md`](../SECURITY.md) (secure-by-default posture).

**Attacker-focused slices:**

1. Core evaluation engine + AuthZEN/OPA transport (`engine.py`, `client.py`, `opa.py`).
2. Mapping layer + all four enforcement adapters (`mapping.py`, `scanner.py`, `nemo.py`,
   `fastmcp.py`, `a2a.py`).
3. Configuration, operational security, and supply chain (`config.py`, `cedar.py`,
   `.gitignore`, `pyproject.toml`).

**Method:** static analysis of each slice against requirements, followed by concrete
repro probes for each candidate finding — confirming exploitability before recording a
finding and confirming the fix before closing it. Date: **2026-06-11**.

## Independence

This is an **internal, AI-assisted adversarial review**. It is not an independent
third-party audit. An independent review is a planned post-public goal — see
[ROADMAP.md](../ROADMAP.md) for how it will be pursued.

## Findings

| ID | Severity | Area | Description | Status | Resolution |
|----|----------|------|-------------|--------|-----------|
| SR-01 | HIGH | Transport (client.py) | Duplicate JSON key in PDP response coerced last-wins by `json.loads` before `StrictBool` validation — `{"decision": false, "decision": true}` reached pydantic as `{"decision": true}` (ALLOW). Violated §3.6: malformed 2xx must BLOCK. | Fixed | `_strict_json` / `object_pairs_hook` in `0b4ce97` |
| SR-02 | MEDIUM | Engine (engine.py) | Transport/exception text, including the internal PDP URL, flowed into `VerdictResult.reason` and was exposed to callers via `ScanResult.reason`. Violated §3.10: returned reason must be generic. | Fixed | `_DENY_REASON` constant on all error paths in `159d2af` |
| SR-03 | MEDIUM | Engine (engine.py) | `asyncio.CancelledError` is a `BaseException`; the `except Exception` guard was transparent to it. A task cancelled mid-PDP-call produced no verdict and no metric — indistinguishable from ALLOW at the caller. | Fixed | Dedicated `except asyncio.CancelledError` clause records metric and re-raises in `159d2af` |
| SR-04 | MEDIUM | Mapping (mapping.py) | No `request_context_scope()` helper mirrored `subject_scope()`. A reused asyncio task that forgot to reset the context variable could leak a prior request's injected context into a later request. | Fixed | `request_context_scope` context manager added and exported in `9deb6aa` |
| SR-05 | LOW | Cedar backend (cedar.py) | `_entity_uid` rejected only double-quotes; a backslash or control character in an identifier also breaks the Cedar string literal. The engine already failed closed on a parse error, but the rejection was implicit. | Hardened | Explicit check extended to backslash and control chars in `c8d55a8` |
| SR-06 | LOW | Config / supply chain | `.env` absent from `.gitignore`; `llamafirewall` extra had no upper-bound ceiling (a major bump could silently replace the audited version); `default_headers` docstring falsely claimed log redaction. | Fixed | `1674c99` |

## Properties verified

These were probed and held. No action was required; they are recorded because a future
change that inadvertently breaks one of these would not be caught by the fix list above.

### Subject identity isolation

- No path lets attacker-controlled model output reach an authorization decision or the
  subject identity in any of the four adapters. The subject comes from one of: the
  host's request-context `ContextVar` (scanner, NeMo rail), a validated OAuth `sub`
  claim (FastMCP), or the server's authenticated peer identity (A2A).
- The `workload` subject type is reserved; constructor validation rejects it for
  claim-derived and static subjects.

### Fail-closed on every error path

- `OnError` has only `DENY` and `HUMAN_REVIEW` — there is no fail-open option.
- No exception in the evaluation path yields `ALLOW`. `_fault_verdict` always resolves
  to `BLOCK` or `on_error` (which is `BLOCK` by default).
- Batch length-mismatch → `BLOCK`.
- The vacuous `all([])` gap is closed: an empty group cannot read as an allow on either
  the aggregate or per-item path.

### Decision validation

- `StrictBool` rejects non-bool decisions (`1`, `"true"`, `0`, `null`, absent field).
- `MalformedPDPResponseError` on any duplicate key within a JSON object; sibling objects
  in a batch response (multiple `"decision"` fields in distinct array entries) are
  correctly not flagged.

### Cache safety

- ALLOW-only; off by default.
- Full-tuple SHA-256 key (subject, action, resource including argument hash, context) —
  cross-user and cross-argument isolation enforced.
- Hard TTL ceiling; PDP-suggested TTL clamped down.
- Dual-principal evaluation always bypasses the cache (logged as a warning if
  `cache_enabled=True`).
- Auth headers never appear in fingerprints or cache keys.

### SSRF guard

- Enforces HTTPS; rejects private/RFC1918/loopback/link-local addresses including
  IPv4-mapped IPv6 (`::ffff:10.x.x.x` etc.).
- Redirects disabled on the httpx client.
- `pdp_url` is operator config only — never derived from a message.

### Argument and credential hygiene

- Argument values are never in logs or metrics; they appear only as a 12-character
  SHA-256 fingerprint.
- Auth headers (`Authorization`, `X-Api-Key`, etc.) are never logged or cached.

### Observability isolation

- Metrics/log-sink failures are caught and logged at `ERROR` but do not affect the
  verdict. The decision is returned before the sink call where possible.

### Dual-principal AND semantics

- Cannot collapse: a boundary subject equal to the caller subject is rejected before any
  PDP call.
- Cannot lose a deny: both legs of a dual-principal batch must be `ALLOW`; one BLOCK on
  either leg → BLOCK.

### SKIP / inline-ALLOW semantics

- SKIP-gateway semantics cannot be abused to force the inline `ALLOW` path — the SKIP
  and ALLOW paths are distinct; SKIP abstains, it does not grant.

## Known limitations & accepted risks

- **DNS rebinding.** An operator-configured non-literal PDP hostname is not rebound-
  resistant at the httpx layer. This is out of scope by design — pair with network egress
  controls at the deployment level. Documented in `client.py`.
- **LlamaFirewall ML stack internals.** Only apparitor's use of LlamaFirewall was
  reviewed; the ML model internals were not audited.
- **Trusted PDP.** A compromised PDP that returns a well-formed `{"decision": true}` is
  outside the threat model. The PDP is trusted to render correct policy decisions;
  apparitor defends the transport and the malformed/contradictory cases.
- **Response-body-size DoS.** A compromised PDP returning a very large body could cause
  memory pressure before validation runs. This is a noted hardening follow-up, not fixed
  here.
- **This is not a third-party audit.** The review is internal and AI-assisted. Its
  findings are honest but it should not be treated as equivalent to an independent
  external assessment.

## Re-review triggers

Re-run this review when any of the following change:

- The threat model (`docs/requirements.md` §§3.5–3.10) or `SECURITY.md`.
- The AuthZEN transport or OPA/Cedar backend response parsing (`client.py`, `opa.py`,
  `cedar.py`).
- The mapping layer or any enforcement adapter (`mapping.py`, `scanner.py`, `nemo.py`,
  `fastmcp.py`, `a2a.py`).
- A new backend or enforcement adapter is added.
- A dependency carrying a CVE is updated (check against the relevant section above).

See [`docs/audit-log.md`](audit-log.md) for the decision-log stability contract and its
own re-review/stability policy.
