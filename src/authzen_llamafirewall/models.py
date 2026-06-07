"""Pydantic v2 models for the AuthZEN 1.0 Access Evaluation API.

Spec: https://openid.net/specs/authorization-interop-spec-1_0.html

These models are deliberately free of any LlamaFirewall import so the AuthZEN
client/models can be used and tested standalone.

Conventions:

* **Request** models forbid unknown fields (they are *our* payloads — typos should
  fail fast) and are serialised with ``exclude_none=True`` so optional members such
  as ``context`` are simply omitted rather than sent as ``null`` (some PDPs reject
  explicit nulls).
* **Response** models ignore unknown fields — the PDP owns its response shape and may
  add members (e.g. richer ``context`` reasons) we must tolerate.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictBool

# --- shared config -----------------------------------------------------------------

_REQUEST_CONFIG = ConfigDict(extra="forbid")
_RESPONSE_CONFIG = ConfigDict(extra="ignore")


# --- request tuple components ------------------------------------------------------


class Subject(BaseModel):
    """The principal the decision is *about* (who).

    Per the threat model, ``id``/``type`` must originate from trusted, out-of-band
    request context — never from model-generated message content. In agentic
    deployments this is typically the **end user** the agent acts on behalf of; the
    agent itself is modelled as an actor inside ``context``.
    """

    model_config = _REQUEST_CONFIG

    type: str
    id: str
    properties: dict[str, Any] = Field(default_factory=dict)


class Action(BaseModel):
    """The operation being attempted (verb). Defaults to ``tool_call.execute``."""

    model_config = _REQUEST_CONFIG

    name: str
    properties: dict[str, Any] = Field(default_factory=dict)


class Resource(BaseModel):
    """The thing being acted upon.

    For a tool call the default ``type`` is ``"tool"`` and ``id`` is the normalised
    tool name. Tool arguments belong in ``properties`` (so PDPs can write ABAC rules
    over them) and must be treated by policy as **untrusted** model output.
    """

    model_config = _REQUEST_CONFIG

    type: str
    id: str
    properties: dict[str, Any] = Field(default_factory=dict)


class EvaluationSemantic(str, Enum):
    """Batch evaluation semantics (AuthZEN ``options.evaluations_semantic``)."""

    EXECUTE_ALL = "execute_all"
    DENY_ON_FIRST_DENY = "deny_on_first_deny"
    PERMIT_ON_FIRST_PERMIT = "permit_on_first_permit"


# --- single evaluation -------------------------------------------------------------


class EvaluationRequest(BaseModel):
    """Body for ``POST /access/v1/evaluation``."""

    model_config = _REQUEST_CONFIG

    subject: Subject
    action: Action
    resource: Resource
    context: dict[str, Any] | None = None


class EvaluationResponse(BaseModel):
    """Response for a single evaluation.

    ``decision`` is REQUIRED and authoritative; ``context`` is advisory (it may carry
    reasons). Strict validation means a missing/non-bool ``decision`` raises rather
    than coercing to a falsy allow.
    """

    model_config = _RESPONSE_CONFIG

    # StrictBool: a non-bool ``decision`` (e.g. 1 / "true") is a malformed response, never
    # a coerced truthy ALLOW. This is a security invariant — do not relax it.
    decision: StrictBool
    context: dict[str, Any] | None = None


# --- batch evaluation --------------------------------------------------------------


class EvaluationItem(BaseModel):
    """One entry in a batch ``evaluations`` array.

    Each member is optional; omitted members inherit the request-level defaults.
    """

    model_config = _REQUEST_CONFIG

    subject: Subject | None = None
    action: Action | None = None
    resource: Resource | None = None
    context: dict[str, Any] | None = None


class EvaluationsOptions(BaseModel):
    """``options`` for a batch request.

    The wire field is ``evaluations_semantic`` (plural) per AuthZEN 1.0 — see the
    conformance suite in ``tests/conformance``.
    """

    model_config = _REQUEST_CONFIG

    evaluations_semantic: EvaluationSemantic = EvaluationSemantic.EXECUTE_ALL


class BatchEvaluationRequest(BaseModel):
    """Body for ``POST /access/v1/evaluations``.

    Top-level ``subject``/``action``/``resource``/``context`` act as defaults for any
    member omitted from the individual ``evaluations`` entries.
    """

    model_config = _REQUEST_CONFIG

    subject: Subject | None = None
    action: Action | None = None
    resource: Resource | None = None
    context: dict[str, Any] | None = None
    evaluations: list[EvaluationItem] = Field(default_factory=list)
    options: EvaluationsOptions | None = None


class BatchEvaluationResponse(BaseModel):
    """Response for a batch evaluation."""

    model_config = _RESPONSE_CONFIG

    evaluations: list[EvaluationResponse] = Field(default_factory=list)
