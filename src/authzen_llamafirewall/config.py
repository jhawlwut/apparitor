"""Scanner configuration.

A single pydantic model (consistent with :mod:`authzen_llamafirewall.models`) gives
validation, sane secure defaults, and enum coercion for free. The happy path is a
single kwarg::

    AuthZENScanner(pdp_url="https://pdp.internal")

which constructs a :class:`ScannerConfig` under the hood.
"""

from __future__ import annotations

from enum import Enum

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field

from .models import EvaluationSemantic


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
    """Validated configuration for :class:`~authzen_llamafirewall.AuthZENScanner`."""

    model_config = ConfigDict(extra="forbid")

    # --- PDP endpoint ---
    pdp_url: AnyHttpUrl
    evaluation_path: str = "/access/v1/evaluation"
    batch_path: str = "/access/v1/evaluations"

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
    evaluation_semantic: EvaluationSemantic = EvaluationSemantic.EXECUTE_ALL

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
