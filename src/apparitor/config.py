"""Scanner configuration.

A single pydantic model (consistent with :mod:`apparitor.models`) gives
validation, sane secure defaults, and enum coercion for free. The happy path is a
single kwarg::

    AuthZENScanner(pdp_url="https://pdp.internal")

which constructs a :class:`ScannerConfig` under the hood.
"""

from __future__ import annotations

from enum import Enum

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field


class Backend(str, Enum):
    """Which decision backend the engine talks to.

    ``authzen`` (default) speaks the AuthZEN Access Evaluation API to any compliant PDP.
    ``opa`` talks Open Policy Agent's native Data API directly (no AuthZEN gateway), for
    deployments that run OPA but don't front it with an AuthZEN endpoint. ``cedar`` evaluates
    Cedar policies in-process via the optional ``cedarpy`` dependency (no server, no network) —
    the decision never leaves the host.
    """

    AUTHZEN = "authzen"
    OPA = "opa"
    CEDAR = "cedar"


class OnError(str, Enum):
    """How to resolve a verdict when the PDP cannot return a usable decision.

    There is deliberately **no** global fail-open option: an authorization gate that
    can be configured to allow-on-failure is not a gate. The only choices are a hard
    deny or routing to a human. The choice may additionally be specialised per error
    class in the implementation (see ``docs/requirements.md`` §6).
    """

    DENY = "deny"
    HUMAN_REVIEW = "human_review"


class ScannerConfig(BaseModel):
    """Validated configuration for :class:`~apparitor.AuthZENScanner`."""

    model_config = ConfigDict(extra="forbid")

    # --- decision backend ---
    backend: Backend = Backend.AUTHZEN

    # --- PDP endpoint ---
    # Required for the HTTP backends (authzen, opa); unused by the in-process cedar backend,
    # so it is optional here and enforced at backend construction.
    pdp_url: AnyHttpUrl | None = None
    # AuthZEN backend paths (ignored when backend="opa").
    evaluation_path: str = "/access/v1/evaluation"
    batch_path: str = "/access/v1/evaluations"
    # OPA backend (backend="opa"): the Rego decision path under OPA's Data API
    # (``/v1/data/<path>``) — your policy's package plus a boolean rule. **Set this to match
    # your own Rego package**; the default matches this repo's example policy
    # (examples/opa/policy.rego). A path that doesn't resolve to a boolean rule fails closed
    # (deny), so a mismatch is safe but will deny every call until corrected.
    opa_decision_path: str = "apparitor/authz/allow"
    # Cedar backend (backend="cedar"): paths to the vendored Cedar policy set, entities, and
    # an optional schema. policies + entities are required for the cedar backend (enforced at
    # construction). Policies/entities are loaded once and evaluated in-process.
    cedar_policies_path: str | None = None
    cedar_entities_path: str | None = None
    cedar_schema_path: str | None = None

    # --- AuthZEN tuple defaults (mappers may override per call) ---
    subject_type: str = "agent"
    # Static fallback subject id, used when no request-scoped subject is set. If neither
    # is available the mapper fails closed rather than authorizing an unknown principal.
    agent_id: str | None = None
    action_name: str = "tool_call.execute"
    resource_type: str = "tool"

    # Static headers sent on every PDP request. Prefer a bring-your-own httpx client for
    # secrets; anything here is also redacted from logs.
    default_headers: dict[str, str] = Field(default_factory=dict)

    # --- failure handling ---
    on_error: OnError = OnError.DENY

    # --- latency budget / transport ---
    # Total wall-clock budget for a single scan; retries happen *within* it.
    request_budget_s: float = Field(default=2.0, gt=0)
    connect_timeout_s: float = Field(default=1.0, gt=0)
    read_timeout_s: float = Field(default=2.0, gt=0)
    max_retries: int = Field(default=2, ge=0)
    backoff_base_s: float = Field(default=0.05, ge=0)
    backoff_max_s: float = Field(default=0.5, ge=0)

    # --- security ---
    verify_tls: bool = True
    # Allow non-HTTPS / RFC1918 / link-local PDP URLs. Off by default to blunt SSRF;
    # intended only for local development against a mock PDP.
    allow_insecure_pdp: bool = False

    # --- caching (off by default; ALLOW-only when on) ---
    cache_enabled: bool = False
    cache_ttl_s: float = Field(default=60.0, ge=0)
    cache_max_ttl_s: float = Field(default=300.0, ge=0)

    # --- argument handling / logging ---
    forward_arguments: bool = True
    redact_arguments: bool = True
    max_argument_bytes: int = Field(default=4096, ge=0)
