"""Decision metrics — a latency histogram and a cache-hit counter, dependency-free.

Observability is a day-one requirement (``docs/requirements.md`` §3.10), but the core must
stay free of any metrics dependency (only ``httpx`` + ``pydantic``). So the engine records
into a small :class:`MetricsSink` protocol. The default :class:`InMemoryMetrics` keeps
Prometheus-shaped counters and a histogram you can scrape or bridge; pass
:class:`NoopMetrics` to disable, or your own sink to forward to Prometheus/OpenTelemetry.

Like :class:`~apparitor.cache.DecisionCache`, :class:`InMemoryMetrics` targets
single-loop async use within one engine instance and is intentionally lock-free: the record
methods are synchronous and do no ``await``, so they run to completion atomically on the
loop. A sink shared across OS threads must provide its own synchronisation.
"""

from __future__ import annotations

from bisect import bisect_left
from typing import Protocol, runtime_checkable

#: Cumulative upper bounds (seconds) for the latency histogram. PDP calls sit in the agent
#: hot path, so the buckets focus on the sub-second-to-a-few-seconds range.
DEFAULT_BUCKETS: tuple[float, ...] = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0)


@runtime_checkable
class MetricsSink(Protocol):
    """The engine's emit-only contract for decision latency and cache outcomes.

    This is a *write* seam (the engine only records); reading/exporting is the concern of
    the concrete sink — see :class:`InMemoryMetrics` for the in-process reader API.
    """

    def record_decision(self, *, verdict: str, status: str, latency_s: float) -> None:
        """Record one completed decision: its verdict, status, and wall-clock latency."""
        ...

    def record_cache(self, *, hit: bool) -> None:
        """Record a decision-cache lookup outcome. Only single-call decisions consult the
        cache (the batch path is never cached), so this covers single-call decisions only."""
        ...


class NoopMetrics:
    """A sink that discards everything (opt out of metrics)."""

    def record_decision(self, *, verdict: str, status: str, latency_s: float) -> None: ...

    def record_cache(self, *, hit: bool) -> None: ...


class InMemoryMetrics:
    """In-memory metrics: a latency histogram + decision/cache counters (single-loop use)."""

    def __init__(self, buckets: tuple[float, ...] = DEFAULT_BUCKETS) -> None:
        self._buckets = tuple(sorted(buckets))
        #: Count of decisions keyed by ``(verdict, status)``.
        self.decisions: dict[tuple[str, str], int] = {}
        # Deliberately NOT delegated to reset(): calling an overridable method from
        # __init__ would run a subclass override before its own state exists.
        self._bucket_counts = [0] * (len(self._buckets) + 1)
        self.latency_sum_s = 0.0
        self.latency_count = 0
        self.cache_hits = 0
        self.cache_misses = 0

    def record_decision(self, *, verdict: str, status: str, latency_s: float) -> None:
        key = (verdict, status)
        self.decisions[key] = self.decisions.get(key, 0) + 1
        # First bucket bound ``b`` with ``latency_s <= b`` (Prometheus ``le`` semantics);
        # anything past the last bound lands in the +Inf overflow slot.
        self._bucket_counts[bisect_left(self._buckets, latency_s)] += 1
        self.latency_sum_s += latency_s
        self.latency_count += 1

    def record_cache(self, *, hit: bool) -> None:
        if hit:
            self.cache_hits += 1
        else:
            self.cache_misses += 1

    def latency_histogram(self) -> list[tuple[float, int]]:
        """Cumulative ``(le, count)`` pairs, including a final ``+Inf`` bucket."""
        bounds = (*self._buckets, float("inf"))
        cumulative = 0
        out: list[tuple[float, int]] = []
        for bound, count in zip(bounds, self._bucket_counts, strict=True):
            cumulative += count
            out.append((bound, cumulative))
        return out

    def reset(self) -> None:
        """Zero all counters (tests / incident response)."""
        self.decisions.clear()
        # One slot per bucket plus a trailing +Inf overflow slot (non-cumulative).
        self._bucket_counts = [0] * (len(self._buckets) + 1)
        self.latency_sum_s = 0.0
        self.latency_count = 0
        self.cache_hits = 0
        self.cache_misses = 0
