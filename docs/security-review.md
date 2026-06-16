# Security Posture & Continuous Assurance

This document states the standing security invariants of the `apparitor` authorization
layer, the threat-model coverage they address, the assurance basis, and the triggers for
re-review. It is intended to be read alongside the threat model in
[`docs/requirements.md`](requirements.md) and the secure-by-default posture in
[`SECURITY.md`](../SECURITY.md).

The posture below was established by an internal adversarial review against the threat
model; issues identified during that review were fixed and are reflected in the test suite
and the changelog.

## Scope & coverage

**Reviewed against:** [`docs/requirements.md`](requirements.md) (full threat model,
§§3.1–3.10) and [`SECURITY.md`](../SECURITY.md) (secure-by-default posture).

**Attacker-focused slices:**

1. Core evaluation engine + AuthZEN/OPA transport (`engine.py`, `client.py`, `backends.py`).
2. Mapping layer + all four enforcement adapters (`mapping.py`, `scanner.py`, `nemo.py`,
   `fastmcp.py`, `a2a.py`).
3. Configuration, operational security, and supply chain (`config.py`, `cedar.py`,
   `.gitignore`, `pyproject.toml`).

## Assurance basis / independence

The posture below is established by an internal adversarial review plus the tested
invariants documented in each section. This is **not** an independent third-party audit;
it should not be treated as equivalent to an independent external assessment. An
independent review is a planned post-public goal — see [ROADMAP.md](../ROADMAP.md) for
how it will be pursued.

## Security properties & invariants

Each property is stated as a standing guarantee, with the test(s) that enforce it cited
inline. The cited tests exist in `tests/unit/` on this branch.

### Subject identity isolation

The system guarantees that no attacker-controlled content — model output, tool arguments,
or message text — can reach an authorization decision or influence the subject identity
used in any of the four enforcement adapters.

- Subject is read from one of: the request-scoped `current_subject` `ContextVar`
  (scanner, NeMo rail), a validated OAuth `sub` claim (FastMCP), or the server's
  authenticated peer identity (A2A). Never from message content or arguments.
- The `"workload"` subject type is reserved; constructor validation rejects it for
  claim-derived and static subjects.
- `request_context_scope()` ensures a reused asyncio task cannot leak a prior request's
  injected context into a later request.

Enforcing tests:
`tests/unit/test_security.py::test_subject_is_not_taken_from_tool_content`,
`tests/unit/test_mapping.py::test_subject_from_context_var`,
`tests/unit/test_mapping.py::test_request_context_scope_sets_clears_and_is_exception_safe`,
`tests/unit/test_fastmcp_middleware.py::test_workload_subject_type_is_reserved`,
`tests/unit/test_a2a_executor.py::test_ambient_contextvar_subject_is_ignored`,
`tests/unit/test_a2a_executor.py::test_caller_headers_cannot_mint_subject_or_context`.

### Fail-closed on every error path

The system guarantees that no failure, exception, or edge case in the evaluation path
yields an ALLOW. `OnError` has only `DENY` and `HUMAN_REVIEW`; there is no fail-open
option.

- `_fault_verdict` always resolves to `BLOCK` or `on_error` (which defaults to `BLOCK`).
- A batch length-mismatch produces `BLOCK`, not a partial ALLOW.
- An empty mapper group (a mapper returning an empty sequence) blocks the item; it cannot
  read as an allow on either the aggregate or per-item path.
- An unparseable tool call always produces `BLOCK`, never `SKIPPED`.
- `asyncio.CancelledError` is caught, a `block/error` metric is recorded, and the error
  re-propagates — a cancelled call is never silently indistinguishable from ALLOW.

Enforcing tests:
`tests/unit/test_security.py::test_pdp_failure_with_on_error_deny_blocks`,
`tests/unit/test_security.py::test_pdp_failure_with_on_error_human_review_escalates`,
`tests/unit/test_engine.py::test_unparseable_tool_call_fails_closed`,
`tests/unit/test_engine.py::test_empty_sequence_mapper_is_abstention_not_allow`,
`tests/unit/test_engine.py::test_evaluate_each_empty_group_blocks_item`,
`tests/unit/test_engine.py::test_cancelled_error_propagates_and_records_metric`,
`tests/unit/test_engine.py::test_batch_short_array_blocks`.

### Decision validation

The system guarantees that any malformed PDP response fails closed with
`MalformedPDPResponseError`; a non-boolean, absent, or ambiguous decision field never
reaches the verdict logic.

- `StrictBool` rejects non-bool decisions (`1`, `"true"`, `0`, `null`, absent field).
- A duplicate JSON key within a PDP response object raises `MalformedPDPResponseError`.
  Sibling objects in a batch response (multiple `"decision"` fields in distinct array
  entries) are correctly not flagged — the check is per-object.
- The fix applies to both the AuthZEN transport and the OPA backend.

Enforcing tests:
`tests/unit/test_client.py::test_duplicate_json_key_in_response_is_malformed`,
`tests/unit/test_client.py::test_non_bool_decision_is_malformed`,
`tests/unit/test_client.py::test_missing_decision_is_malformed`,
`tests/unit/test_backends.py::test_duplicate_json_key_in_opa_response_fails_closed`.

### Cache safety

The system guarantees that the opt-in decision cache (off by default) cannot expand the
ALLOW surface or leak decisions across subjects or argument values.

- ALLOW-only: DENY, error, and HUMAN_REVIEW verdicts are never cached.
- Full-tuple SHA-256 key over subject, action, resource (including argument hash), and
  context — cross-user and cross-argument isolation enforced at the key level.
- Hard TTL ceiling; any PDP-suggested TTL is clamped down.
- Dual-principal evaluation always bypasses the cache (logged as a warning when
  `cache_enabled=True`).
- Auth headers never appear in fingerprints or cache keys.

Enforcing tests:
`tests/unit/test_security.py::test_block_decision_is_never_cached`,
`tests/unit/test_engine.py::test_deny_is_not_cached`,
`tests/unit/test_cache.py::test_key_is_stable_and_argument_sensitive`,
`tests/unit/test_mapping.py::test_dual_principal_warns_once_about_bypassed_cache`.

### SSRF guard

The system guarantees that the PDP URL, which is operator configuration only and never
derived from a message, is validated before any outbound HTTP request.

- Enforces HTTPS; rejects private/RFC1918/loopback/link-local addresses including
  IPv4-mapped IPv6 (`::ffff:10.x.x.x` etc.).
- Redirects are disabled on the httpx client.
- `pdp_url` is operator config only — never derived from a message.

Enforcing tests:
`tests/unit/test_security.py::test_client_refuses_private_pdp_url`,
`tests/unit/test_client.py::test_ssrf_guard_rejects_http_and_private_and_localhost`,
`tests/unit/test_client.py::test_unfollowed_redirect_fails_closed`,
`tests/unit/test_backends.py::test_opa_backend_inherits_ssrf_guard`.

### Argument and credential hygiene

The system guarantees that tool argument values and authentication credentials never
appear in logs, metrics, or cache keys.

- Argument values appear only as a 12-character SHA-256 fingerprint in logs.
- Auth headers (`Authorization`, `X-Api-Key`, etc.) are never logged or cached.

Enforcing tests:
`tests/unit/test_security.py::test_auth_token_is_never_logged`,
`tests/unit/test_security.py::test_arguments_are_redacted_in_the_pdp_request_by_default`,
`tests/unit/test_metrics.py::test_structured_decision_log_carries_ids_and_fingerprint`.

### Observability isolation

The system guarantees that metrics and log-sink failures cannot affect verdict delivery.

- Sink failures are caught and logged at `ERROR` but do not alter or delay the verdict.
- The decision is returned before the sink call where possible.
- A raising sink on the `asyncio.CancelledError` path cannot replace `CancelledError` with
  a metrics exception — `_record_cancelled` isolates the write so structured concurrency
  propagation is never masked.

Enforcing tests:
`tests/unit/test_metrics.py::test_faulty_sink_never_breaks_or_alters_the_decision`,
`tests/unit/test_metrics.py::test_faulty_cache_metric_sink_does_not_flip_the_verdict`,
`tests/unit/test_engine.py::test_cancelled_error_propagates_even_when_sink_raises`,
`tests/unit/test_engine.py::test_evaluate_each_cancelled_error_propagates_even_when_sink_raises`.

### Dual-principal AND semantics

The system guarantees that dual-principal evaluation cannot collapse to a single-principal
check or lose a deny from either leg.

- A boundary subject equal to the caller subject is rejected before any PDP call.
- Both legs of a dual-principal batch must be ALLOW; one BLOCK on either leg → BLOCK.

Enforcing tests:
`tests/unit/test_engine.py::test_dual_principal_truth_table`,
`tests/unit/test_engine.py::test_dual_principal_missing_user_fails_closed`,
`tests/unit/test_mapping.py::test_dual_principal_rejects_user_equal_to_agent`,
`tests/unit/test_mapping.py::test_dual_principal_requires_request_scoped_user`.

### Reason isolation (generic caller-facing messages)

The system guarantees that the caller-visible `reason` field on error paths never
contains internal detail (PDP URL, exception text, transport state).

- All error-path `VerdictResult.reason` values use the fixed `_DENY_REASON` constant.
- Exception detail appears only in operator logs.

Enforcing tests:
`tests/unit/test_engine.py::test_transport_error_reason_is_generic`,
`tests/unit/test_engine.py::test_malformed_response_reason_is_generic`,
`tests/unit/test_fastmcp_middleware.py::test_pdp_error_fails_closed_without_leaking_detail`.

### SKIP / inline-ALLOW semantics

The system guarantees that SKIP-gateway semantics cannot be abused to force an inline
ALLOW. SKIP and ALLOW are distinct paths; SKIP abstains, it does not grant.

## Known limitations & accepted risks

- **DNS rebinding.** An operator-configured non-literal PDP hostname is not
  rebinding-resistant at the httpx layer. This is out of scope by design — pair with
  network egress controls at the deployment level. Documented in `client.py`.
- **LlamaFirewall ML stack internals.** Only apparitor's use of LlamaFirewall was
  reviewed; the ML model internals were not audited.
- **Trusted PDP.** A compromised PDP that returns a well-formed `{"decision": true}` is
  outside the threat model. The PDP is trusted to render correct policy decisions;
  apparitor defends the transport and the malformed/contradictory cases.
- **Response-body-size DoS.** A compromised PDP returning a very large body could cause
  memory pressure before validation runs. This is a noted hardening follow-up, not yet
  addressed.

## Re-review triggers

Re-run this review when any of the following change:

- The threat model (`docs/requirements.md` §§3.5–3.10) or `SECURITY.md`.
- The AuthZEN transport or OPA/Cedar backend response parsing (`client.py`, `backends.py`,
  `cedar.py`).
- The mapping layer or any enforcement adapter (`mapping.py`, `scanner.py`, `nemo.py`,
  `fastmcp.py`, `a2a.py`).
- A new backend or enforcement adapter is added.
- A dependency carrying a CVE is updated (check the affected section above).

See [`docs/audit-log.md`](audit-log.md) for the decision-log stability contract and its
own re-review and stability policy.
