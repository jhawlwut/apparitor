"""Tests for the metrics sink and its wiring into the engine."""

from __future__ import annotations

import logging

import httpx
import pytest

from apparitor.client import AuthZENClient
from apparitor.config import OnError
from apparitor.decision import Verdict
from apparitor.engine import AuthorizationEngine
from apparitor.metrics import InMemoryMetrics, MetricsSink, NoopMetrics

pytestmark = pytest.mark.unit

_EVAL_URL = "http://pdp.test/access/v1/evaluation"
_BATCH_URL = "http://pdp.test/access/v1/evaluations"


def _engine(cfg, noop_sleep, **kw):
    return AuthorizationEngine(cfg, client=AuthZENClient(cfg, sleep=noop_sleep), **kw)


class _AbstainMapper:
    """A mapper that abstains on every call (returns no EvaluationRequest)."""

    def map(self, _tool_call, _request_context):
        return None


class _RaisingMetrics:
    """A sink that raises — stands in for a buggy/blocking custom MetricsSink."""

    def record_decision(self, *, verdict, status, latency_s):
        raise RuntimeError("sink boom")

    def record_cache(self, *, hit):
        raise RuntimeError("sink boom")


# --- InMemoryMetrics (pure) --------------------------------------------------------


def test_histogram_buckets_are_cumulative_with_overflow() -> None:
    metrics = InMemoryMetrics(buckets=(0.1, 1.0))
    for latency in (0.05, 0.5, 5.0):  # bucket0, bucket1, +Inf overflow
        metrics.record_decision(verdict="allow", status="success", latency_s=latency)

    assert metrics.latency_histogram() == [(0.1, 1), (1.0, 2), (float("inf"), 3)]
    assert metrics.latency_count == 3
    assert metrics.latency_sum_s == pytest.approx(5.55)


def test_boundary_observation_counts_in_its_le_bucket() -> None:
    metrics = InMemoryMetrics(buckets=(0.1, 1.0))
    metrics.record_decision(verdict="allow", status="success", latency_s=0.1)  # le=0.1
    assert metrics.latency_histogram() == [(0.1, 1), (1.0, 1), (float("inf"), 1)]


def test_decision_and_cache_counters() -> None:
    metrics = InMemoryMetrics()
    metrics.record_decision(verdict="allow", status="success", latency_s=0.01)
    metrics.record_decision(verdict="allow", status="success", latency_s=0.02)
    metrics.record_decision(verdict="block", status="error", latency_s=0.03)
    metrics.record_cache(hit=True)
    metrics.record_cache(hit=False)

    assert metrics.decisions == {("allow", "success"): 2, ("block", "error"): 1}
    assert (metrics.cache_hits, metrics.cache_misses) == (1, 1)


def test_reset_zeroes_everything() -> None:
    metrics = InMemoryMetrics(buckets=(0.1,))
    metrics.record_decision(verdict="allow", status="success", latency_s=0.05)
    metrics.record_cache(hit=True)
    metrics.reset()

    assert metrics.decisions == {}
    assert metrics.latency_count == 0
    assert metrics.latency_sum_s == 0.0
    assert metrics.cache_hits == 0
    assert metrics.latency_histogram() == [(0.1, 0), (float("inf"), 0)]


def test_sinks_satisfy_the_protocol() -> None:
    assert isinstance(InMemoryMetrics(), MetricsSink)
    assert isinstance(NoopMetrics(), MetricsSink)
    noop = NoopMetrics()  # calling it does nothing and never raises
    noop.record_decision(verdict="allow", status="success", latency_s=0.0)
    noop.record_cache(hit=True)


# --- engine wiring -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_engine_records_decision_latency(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    metrics = InMemoryMetrics()
    engine = _engine(make_config(), noop_sleep, metrics=metrics)
    await engine.evaluate_tool_calls([make_openai_call("read")])

    assert metrics.decisions == {("allow", "success"): 1}
    assert metrics.latency_count == 1


@pytest.mark.asyncio
async def test_engine_records_cache_hit_and_miss(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    metrics = InMemoryMetrics()
    engine = _engine(make_config(cache_enabled=True), noop_sleep, metrics=metrics)
    call = make_openai_call("read", path="/tmp")
    await engine.evaluate_tool_calls([call])
    await engine.evaluate_tool_calls([call])

    assert metrics.cache_misses == 1
    assert metrics.cache_hits == 1


@pytest.mark.asyncio
async def test_engine_records_error_path_decision(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_EVAL_URL).mock(side_effect=httpx.ConnectError("refused"))
    metrics = InMemoryMetrics()
    engine = _engine(make_config(on_error=OnError.DENY, max_retries=0), noop_sleep, metrics=metrics)
    await engine.evaluate_tool_calls([make_openai_call("read")])

    assert metrics.decisions == {("block", "error"): 1}


@pytest.mark.asyncio
async def test_empty_tool_calls_records_nothing(make_config, noop_sleep) -> None:
    metrics = InMemoryMetrics()
    engine = _engine(make_config(), noop_sleep, metrics=metrics)
    await engine.evaluate_tool_calls(None)

    assert metrics.latency_count == 0
    assert metrics.decisions == {}


@pytest.mark.asyncio
async def test_all_abstain_records_a_skip_decision_but_no_log(
    make_config, make_openai_call, noop_sleep, caplog
) -> None:
    # A present-but-abstained tool call is a timed SKIP decision (unlike empty tool_calls),
    # but there are no requests to log.
    metrics = InMemoryMetrics()
    engine = _engine(make_config(), noop_sleep, metrics=metrics, mapper=_AbstainMapper())
    with caplog.at_level(logging.INFO, logger="apparitor"):
        await engine.evaluate_tool_calls([make_openai_call("read")])

    assert metrics.decisions == {("skip", "skipped"): 1}
    assert metrics.latency_count == 1
    assert "authzen decision" not in caplog.text


@pytest.mark.asyncio
async def test_batch_records_one_decision_and_logs_each_call(
    make_config, make_openai_call, noop_sleep, respx_mock, caplog
) -> None:
    respx_mock.post(_BATCH_URL).respond(
        json={"evaluations": [{"decision": True}, {"decision": True}]}
    )
    metrics = InMemoryMetrics()
    engine = _engine(make_config(), noop_sleep, metrics=metrics)
    with caplog.at_level(logging.INFO, logger="apparitor"):
        await engine.evaluate_tool_calls([make_openai_call("read"), make_openai_call("write")])

    assert metrics.decisions == {("allow", "success"): 1}  # one decision for the message
    assert metrics.latency_count == 1
    assert "resources=['read', 'write']" in caplog.text  # both calls in one structured line


@pytest.mark.asyncio
async def test_faulty_sink_never_breaks_or_alters_the_decision(
    make_config, make_openai_call, noop_sleep, respx_mock, caplog
) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    engine = _engine(make_config(), noop_sleep, metrics=_RaisingMetrics())
    with caplog.at_level(logging.ERROR, logger="apparitor"):
        result = await engine.evaluate_tool_calls([make_openai_call("read")])

    assert result.verdict is Verdict.ALLOW  # observability failure must not change the verdict
    assert "emission failed" in caplog.text


@pytest.mark.asyncio
async def test_faulty_cache_metric_sink_does_not_flip_the_verdict(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    # record_cache runs inside the decision path; a raising sink there must not turn an
    # ALLOW (or a cache hit) into an error BLOCK.
    respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    engine = _engine(make_config(cache_enabled=True), noop_sleep, metrics=_RaisingMetrics())
    call = make_openai_call("read", path="/tmp")
    first = await engine.evaluate_tool_calls([call])  # miss → record_cache(False) raises
    second = await engine.evaluate_tool_calls([call])  # hit → record_cache(True) raises

    assert first.verdict is Verdict.ALLOW
    assert second.verdict is Verdict.ALLOW


@pytest.mark.asyncio
async def test_noop_metrics_does_not_break_evaluation(
    make_config, make_openai_call, noop_sleep, respx_mock
) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    engine = _engine(make_config(), noop_sleep, metrics=NoopMetrics())
    result = await engine.evaluate_tool_calls([make_openai_call("read")])
    assert result.reason


@pytest.mark.asyncio
async def test_structured_decision_log_carries_ids_and_fingerprint(
    make_config, make_openai_call, noop_sleep, respx_mock, caplog
) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    engine = _engine(make_config(agent_id="bot-123"), noop_sleep)
    with caplog.at_level(logging.INFO, logger="apparitor"):
        await engine.evaluate_tool_calls(
            [make_openai_call("read", path="/tmp")],
            request_context={"correlation_id": "corr-9"},
        )

    text = caplog.text
    assert "verdict=allow" in text
    assert "status=success" in text
    assert "subjects=['bot-123']" in text
    assert "correlation=corr-9" in text
    assert "fingerprints=" in text
    assert "latency_ms=" in text
    assert "/tmp" not in text  # raw arguments never logged
