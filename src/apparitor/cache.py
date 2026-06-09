"""Decision cache (opt-in, OFF by default).

Caching authorization decisions is a classic footgun: a stale ALLOW after a policy or
role revocation is a privilege-escalation window. The contract enforced here:

* **ALLOW decisions only** are cached. A deny or any error-derived verdict is never
  cached (caching an error would poison the cache).
* The TTL is short with a hard ceiling; any PDP-suggested TTL is clamped **down**.
* The key is a SHA-256 over canonical, sorted JSON of the **full** request tuple
  (subject + action + resource incl. arguments + context) — never string concatenation,
  never a hand-picked "context subset", so two policy-distinct requests cannot collide.

The cache is intended for single-loop async use within one scanner instance.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable

from .models import EvaluationRequest


def decision_cache_key(request: EvaluationRequest) -> str:
    """Derive a stable, collision-resistant cache key for an evaluation request.

    Canonicalises the request to sorted JSON (so dict ordering is irrelevant) and returns
    a SHA-256 hex digest. Arguments under ``resource.properties`` are part of the digest,
    so ``delete_file(/tmp/x)`` never serves a cached ALLOW for ``delete_file(/etc/passwd)``.
    """
    canonical = json.dumps(
        request.model_dump(mode="json", exclude_none=True),
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class DecisionCache:
    """In-memory TTL cache for ALLOW decisions (single-loop async use)."""

    def __init__(
        self,
        *,
        ttl_s: float,
        max_ttl_s: float,
        max_entries: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl_s = min(ttl_s, max_ttl_s)
        self._max_ttl_s = max_ttl_s
        self._max_entries = max(1, max_entries)
        self._clock = clock
        self._entries: dict[str, float] = {}

    def get(self, key: str) -> bool | None:
        """Return ``True`` for a present, unexpired ALLOW; otherwise ``None``."""
        expiry = self._entries.get(key)
        if expiry is None:
            return None
        if self._clock() >= expiry:
            del self._entries[key]
            return None
        return True

    def set_allow(self, key: str, *, pdp_ttl_s: float | None = None) -> None:
        """Cache an ALLOW. ``pdp_ttl_s`` (if any) is clamped to the configured ceiling."""
        ttl = self._ttl_s if pdp_ttl_s is None else min(pdp_ttl_s, self._max_ttl_s)
        if ttl <= 0:
            return
        if key not in self._entries and len(self._entries) >= self._max_entries:
            # Bound memory on long-lived hosts: per-subject keys (e.g. per-token MCP
            # subjects) multiply cardinality. FIFO eviction is enough for a short-TTL
            # ALLOW-only cache — an evicted entry just costs one PDP round trip.
            del self._entries[next(iter(self._entries))]
        self._entries[key] = self._clock() + ttl

    def clear(self) -> None:
        """Flush the cache (incident-response hook)."""
        self._entries.clear()
