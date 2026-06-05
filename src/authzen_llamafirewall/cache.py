"""Decision cache (opt-in, OFF by default).

Caching authorization decisions is a classic footgun: a stale ALLOW after a policy or
role revocation is a privilege-escalation window. The contract this module enforces
when enabled:

* **ALLOW decisions only** are cached (caching a deny is fail-safe but pointless;
  caching an *error*-derived verdict would poison the cache and is forbidden).
* The TTL is short with a hard ceiling; any PDP-suggested TTL is clamped **down**.
* The key is a SHA-256 over canonical, type-tagged JSON of the **full** request tuple
  (subject + action + resource incl. an args hash + context) — never string
  concatenation, never a hand-picked "context subset" (collision / poisoning risk).
* A flush hook and the ``cache_enabled=False`` kill switch support incident response.

Implementation is deferred; this module pins the interface and the key derivation
contract.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import EvaluationRequest


def decision_cache_key(request: EvaluationRequest) -> str:
    """Derive a stable, collision-resistant cache key for an evaluation request.

    Canonicalises the request to sorted, type-tagged JSON and returns a SHA-256 hex
    digest. Arguments under ``resource.properties`` are included via their own hash so
    that ``delete_file(/tmp/x)`` never serves a cached ALLOW for
    ``delete_file(/etc/passwd)``.
    """
    raise NotImplementedError("deferred: see docs/requirements.md §9 (caching)")


class DecisionCache:
    """In-memory TTL cache for ALLOW decisions.

    The concurrency model (async-only vs thread-shared) and in-flight coalescing are
    pinned in ``docs/architecture.md`` before implementation.
    """

    def __init__(self, *, ttl_s: float, max_ttl_s: float) -> None:
        self._ttl_s = min(ttl_s, max_ttl_s)
        self._max_ttl_s = max_ttl_s

    def get(self, key: str) -> bool | None:
        """Return a cached ALLOW (``True``) if present and unexpired, else ``None``."""
        raise NotImplementedError("deferred: see docs/requirements.md §9 (caching)")

    def set_allow(self, key: str, *, pdp_ttl_s: float | None = None) -> None:
        """Cache an ALLOW. ``pdp_ttl_s`` (if any) is clamped to the configured ceiling."""
        raise NotImplementedError("deferred: see docs/requirements.md §9 (caching)")

    def clear(self) -> None:
        """Flush the cache (incident-response hook)."""
        raise NotImplementedError("deferred: see docs/requirements.md §9 (caching)")
