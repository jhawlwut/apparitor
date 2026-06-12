"""In-process Cedar decision backend (requires the optional ``cedarpy`` dependency).

Evaluates the AuthZEN tuple against Cedar policies + entities **in-process** via the
``cedarpy`` binding over the Apache-2.0 Cedar engine — no server, no gateway, no network. The
decision is computed inside the caller's own process, so request data (including a
potentially PII subject id) never leaves the host: the sovereignty- and ops-lightest way to
run Cedar.

Isolated in its own module (like :mod:`apparitor.scanner`) so ``cedarpy`` stays an optional
extra and the rest of the package imports without it; importing this module without it raises
:class:`~apparitor.errors.MissingDependencyError`.

Fail-closed: only an explicit Cedar ``Allow`` is ALLOW; ``Deny`` and ``NoDecision`` are
denies. A malformed policy set (or a schema that does not validate) is caught at construction
and raised as :class:`~apparitor.errors.AuthZENConfigError` — cedarpy treats a policy parse
error as ``NoDecision`` rather than an exception, so without this check a single policy typo
would silently deny *every* request at runtime instead of failing loudly at startup. At
request time a Python-level fault (a malformed entity UID, or a Rust panic surfaced as a
Python exception) is raised as :class:`MalformedPDPResponseError` and resolved through
``on_error`` — never a coerced allow. This mirrors the strict ``StrictBool`` invariant the
AuthZEN/OPA backends use.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .backends import merge_batch_item
from .errors import AuthZENConfigError, MalformedPDPResponseError, MissingDependencyError
from .models import (
    BatchEvaluationRequest,
    BatchEvaluationResponse,
    EvaluationRequest,
    EvaluationResponse,
)

try:
    import cedarpy
except ImportError as exc:  # pragma: no cover - exercised via the import-guard test
    raise MissingDependencyError(
        "the Cedar backend requires cedarpy. Install it with:\n    pip install 'apparitor[cedar]'"
    ) from exc

if TYPE_CHECKING:
    from .config import ScannerConfig

# AuthZEN subject/resource types are lowercase; Cedar entity types are PascalCase in the
# conventional schema. "action".title() == "Action", so this maps the action verb too.
_TYPE_MAP = {"agent": "Agent", "tool": "Tool"}


def _entity_uid(kind: str, identifier: str) -> str:
    # A double-quote, backslash, or control char in an identifier would break the Cedar string
    # literal (e.g. Agent::"foo"bar", Agent::"foo\nbar").  The engine already fails closed on a
    # parse error (NoDecision → BLOCK), but rejecting here makes the refusal explicit and cheap.
    if any(c == '"' or c == "\\" or ord(c) <= 0x1F for c in identifier):
        raise ValueError(
            f"identifier contains a disallowed character (double-quote, backslash, or"
            f" control char): {identifier!r}"
        )
    return f'{_TYPE_MAP.get(kind, kind.title())}::"{identifier}"'


class CedarBackend:
    """In-process Cedar evaluator implementing :class:`~apparitor.backends.DecisionBackend`.

    Policies/entities (and an optional schema) are loaded once at construction from the
    configured paths. There is no network, so this does NOT inherit ``HTTPDecisionTransport``
    (``pdp_url``, SSRF, TLS, retries don't apply). Cedar returns boolean decisions only, so the
    advisory ``context`` / ``review_predicate`` HITL path doesn't apply here (as with OPA).
    """

    def __init__(self, config: ScannerConfig) -> None:
        if not config.cedar_policies_path or not config.cedar_entities_path:
            raise AuthZENConfigError(
                'backend="cedar" requires cedar_policies_path and cedar_entities_path'
            )
        try:
            self._policies = Path(config.cedar_policies_path).read_text(encoding="utf-8")
            self._entities = json.loads(
                Path(config.cedar_entities_path).read_text(encoding="utf-8")
            )
            self._schema: Any | None = (
                json.loads(Path(config.cedar_schema_path).read_text(encoding="utf-8"))
                if config.cedar_schema_path
                else None
            )
        except (OSError, ValueError) as exc:
            raise AuthZENConfigError(f"cannot load Cedar policies/entities: {exc}") from exc
        self._validate_policies()

    def _validate_policies(self) -> None:
        # Fail fast at construction. A policy typo parses fine as text and then makes Cedar
        # return NoDecision (a silent deny of *everything*), not raise — so without this a
        # misconfigured customer would see a hard deny at runtime, bypassing on_error, with the
        # parse error only on stderr. format_policies parses without needing a schema; with a
        # schema, validate the policies against it too.
        try:
            if self._schema is not None:
                result = cedarpy.validate_policies(self._policies, self._schema)
            else:
                cedarpy.format_policies(self._policies)  # parse-only; raises on a syntax error
                return
        except (ValueError, RuntimeError) as exc:
            raise AuthZENConfigError(f"invalid Cedar policy set: {exc}") from exc
        if not result.validation_passed:
            raise AuthZENConfigError(f"Cedar policy/schema validation failed: {result.errors}")

    async def evaluate(self, request: EvaluationRequest) -> EvaluationResponse:
        # cedarpy is synchronous; run it off the event loop so a slow eval can't block it.
        decision = await asyncio.to_thread(self._decide, request)
        return EvaluationResponse(decision=decision)

    async def evaluate_batch(self, request: BatchEvaluationRequest) -> BatchEvaluationResponse:
        decisions = await asyncio.to_thread(self._decide_batch, request)
        return BatchEvaluationResponse(
            evaluations=[EvaluationResponse(decision=d) for d in decisions]
        )

    async def aclose(self) -> None:  # in-process: nothing to release
        return None

    def _cedar_request(self, req: EvaluationRequest) -> dict[str, Any]:
        return {
            "principal": _entity_uid(req.subject.type, req.subject.id),
            "action": _entity_uid("action", req.action.name),
            "resource": _entity_uid(req.resource.type, req.resource.id),
            "context": req.context or {},
        }

    def _decide(self, request: EvaluationRequest) -> bool:
        try:
            result = cedarpy.is_authorized(
                self._cedar_request(request), self._policies, self._entities, self._schema
            )
            # Kept inside the try so a malformed result (e.g. no ``.decision``) maps to
            # MalformedPDPResponseError, not an escaping AttributeError. bool(): cedarpy is
            # untyped in the type-check env (Any), so coerce to a concrete bool.
            return bool(result.decision == cedarpy.Decision.Allow)
        except Exception as exc:  # malformed uid/result or a surfaced Rust panic
            raise MalformedPDPResponseError(f"Cedar evaluation failed: {exc}") from exc

    def _decide_batch(self, request: BatchEvaluationRequest) -> list[bool]:
        try:
            requests = [
                self._cedar_request(merge_batch_item(item, request)) for item in request.evaluations
            ]
            results = cedarpy.is_authorized_batch(
                requests, self._policies, self._entities, self._schema
            )
            # Order is preserved by cedarpy; a count mismatch is caught by the engine's
            # aggregate. Kept inside the try so a malformed result maps to a fail-closed error.
            return [bool(r.decision == cedarpy.Decision.Allow) for r in results]
        except Exception as exc:
            raise MalformedPDPResponseError(f"Cedar batch evaluation failed: {exc}") from exc
