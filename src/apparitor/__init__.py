"""AuthZEN 1.0 authorization scanner plugin for Meta's LlamaFirewall.

This package answers the question content-safety scanners do not: *"is this agent
**allowed** to do this?"* It evaluates agent tool calls against any AuthZEN-compliant
Policy Decision Point (PDP) and maps the decision onto LlamaFirewall's
ALLOW / BLOCK / HUMAN_IN_THE_LOOP model.

Import layout (deliberate):

* :mod:`apparitor.models`, ``client``, ``adapters``, ``mapping``,
  ``cache``, ``config`` and ``errors`` are **LlamaFirewall-free** — importable and
  unit-testable without the (heavy) LlamaFirewall ML stack installed.
* :class:`apparitor.AuthZENScanner` lives in
  :mod:`apparitor.scanner`, which **requires** ``llamafirewall``. It is
  exposed lazily (PEP 562 ``__getattr__``) so that ``import apparitor``
  succeeds even when LlamaFirewall is not installed; accessing the scanner without it
  raises :class:`~apparitor.errors.MissingDependencyError`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .adapters import (
    AnthropicToolCallAdapter,
    LangChainToolCallAdapter,
    NormalizedToolCall,
    OpenAIToolCallAdapter,
    ToolCallAdapter,
    detect_adapter,
)
from .backends import DecisionBackend, OPABackend, build_backend
from .config import Backend, OnError, ScannerConfig
from .decision import Verdict, VerdictResult, VerdictStatus
from .engine import AuthorizationEngine, ReviewPredicate
from .errors import (
    AuthZENClientError,
    AuthZENConfigError,
    AuthZENError,
    AuthZENServiceError,
    MalformedPDPResponseError,
    MissingDependencyError,
    PDPTimeoutError,
    PDPUnavailableError,
)
from .mapping import (
    MCP_SERVER_LABEL_KEY,
    DefaultToolCallMapper,
    DualPrincipalMapper,
    MCPResourceMapper,
    ToolCallMapper,
    current_request_context,
    current_subject,
    mcp_resource_id,
    subject_scope,
)
from .metrics import DEFAULT_BUCKETS, InMemoryMetrics, MetricsSink, NoopMetrics
from .models import (
    Action,
    BatchEvaluationRequest,
    BatchEvaluationResponse,
    EvaluationItem,
    EvaluationRequest,
    EvaluationResponse,
    EvaluationSemantic,
    EvaluationsOptions,
    Resource,
    Subject,
)

__version__ = "0.0.1a0"

if TYPE_CHECKING:
    # For type-checkers only; these runtime exports are lazy (see __getattr__ below) because
    # each pulls an optional dependency (llamafirewall / cedarpy / nemoguardrails / fastmcp /
    # a2a-sdk).
    from .a2a import A2AAuthorizationExecutor
    from .cedar import CedarBackend
    from .fastmcp import FastMCPAuthorizationMiddleware
    from .nemo import NeMoAuthorizationRails
    from .scanner import AuthZENScanner

__all__ = [  # noqa: RUF022 - grouped by concern, not alphabetised, for readability
    "__version__",
    # enforcement-point adapters (lazy; each needs an optional host SDK)
    "AuthZENScanner",
    "NeMoAuthorizationRails",
    "FastMCPAuthorizationMiddleware",
    "A2AAuthorizationExecutor",
    # config
    "ScannerConfig",
    "OnError",
    "Backend",
    # decision backends (AuthZEN client by default; native OPA; native Cedar via cedarpy, lazy)
    "DecisionBackend",
    "OPABackend",
    "CedarBackend",
    "build_backend",
    # engine / decision (LlamaFirewall-free orchestration)
    "AuthorizationEngine",
    "ReviewPredicate",
    "Verdict",
    "VerdictResult",
    "VerdictStatus",
    # metrics
    "MetricsSink",
    "InMemoryMetrics",
    "NoopMetrics",
    "DEFAULT_BUCKETS",
    # models
    "Subject",
    "Action",
    "Resource",
    "EvaluationRequest",
    "EvaluationResponse",
    "EvaluationItem",
    "EvaluationsOptions",
    "EvaluationSemantic",
    "BatchEvaluationRequest",
    "BatchEvaluationResponse",
    # adapters
    "NormalizedToolCall",
    "ToolCallAdapter",
    "OpenAIToolCallAdapter",
    "AnthropicToolCallAdapter",
    "LangChainToolCallAdapter",
    "detect_adapter",
    # mapping
    "ToolCallMapper",
    "DefaultToolCallMapper",
    "DualPrincipalMapper",
    "MCPResourceMapper",
    "MCP_SERVER_LABEL_KEY",
    "current_subject",
    "current_request_context",
    "subject_scope",
    "mcp_resource_id",
    # errors
    "AuthZENError",
    "AuthZENConfigError",
    "AuthZENClientError",
    "AuthZENServiceError",
    "PDPUnavailableError",
    "PDPTimeoutError",
    "MalformedPDPResponseError",
    "MissingDependencyError",
]


def __getattr__(name: str) -> object:
    """Lazily expose the optional-dependency exports (PEP 562).

    Each branch below pulls an optional host/engine SDK; importing them lazily keeps a
    plain ``import apparitor`` working without any extras installed.
    """
    if name == "AuthZENScanner":
        from .scanner import AuthZENScanner

        return AuthZENScanner
    if name == "CedarBackend":
        from .cedar import CedarBackend

        return CedarBackend
    if name == "NeMoAuthorizationRails":
        from .nemo import NeMoAuthorizationRails

        return NeMoAuthorizationRails
    if name == "FastMCPAuthorizationMiddleware":
        from .fastmcp import FastMCPAuthorizationMiddleware

        return FastMCPAuthorizationMiddleware
    if name == "A2AAuthorizationExecutor":
        from .a2a import A2AAuthorizationExecutor

        return A2AAuthorizationExecutor
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
