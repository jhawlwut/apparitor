"""Pins the audit-log schema documented in docs/audit-log.md.

A failure here means a breaking log-schema change is in flight — add a CHANGELOG
entry under Changed with "Update log parsers" and bump the version.
"""

from __future__ import annotations

import ast
import logging
import re

import pytest

from apparitor.client import AuthZENClient
from apparitor.engine import AuthorizationEngine

pytestmark = pytest.mark.unit

_EVAL_URL = "http://pdp.test/access/v1/evaluation"
_BATCH_URL = "http://pdp.test/access/v1/evaluations"

# Field-order and prefix anchored, deliberately search()-based so future APPENDED
# key=value tokens (allowed by the stability policy) still pass.
_C1 = re.compile(
    r"apparitor decision "
    r"verdict=(?P<verdict>\S+) "
    r"status=(?P<status>\S+) "
    r"subjects=(?P<subjects>\[.*?\]) "
    r"correlation=(?P<correlation>\S+) "
    r"resources=(?P<resources>\[.*?\]) "
    r"fingerprints=(?P<fingerprints>\[.*?\]) "
    r"latency_ms=(?P<latency>\d+\.\d)(?!\d)"
)

# C2 — denied-legs companion.
_C2 = re.compile(r"apparitor batch denied_legs=(?P<legs>\[.*\])")

# C3 — evaluate_each summary.
_C3 = re.compile(
    r"apparitor per-item decisions verdicts=(?P<verdicts>\[.*?\]) "
    r"latency_ms=(?P<latency>\d+\.\d)(?!\d)"
)


def _engine(cfg, noop_sleep, **kw):
    return AuthorizationEngine(cfg, client=AuthZENClient(cfg, sleep=noop_sleep), **kw)


def _c1_record(caplog):
    """Return the first caplog record whose message matches the C1 grammar."""
    for r in caplog.records:
        if r.name == "apparitor" and _C1.search(r.getMessage()):
            return r.getMessage()
    return None


# ---------------------------------------------------------------------------
# C1 — single-principal, single call
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_c1_single_principal_grammar(
    make_config, make_openai_call, noop_sleep, respx_mock, caplog
) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    engine = _engine(make_config(agent_id="bot-123"), noop_sleep)
    with caplog.at_level(logging.INFO, logger="apparitor"):
        await engine.evaluate_tool_calls(
            [make_openai_call("read_file", path="/tmp")],
            request_context={"correlation_id": "corr-1"},
        )

    line = _c1_record(caplog)
    assert line is not None, "no C1 line emitted"

    m = _C1.search(line)
    assert m is not None, f"C1 grammar mismatch: {line!r}"

    assert m.group("verdict") == "allow"
    assert m.group("status") == "success"

    # Pins the Python-repr single-quote list format (not JSON) for list-valued fields.
    assert m.group("subjects").startswith("['")
    assert m.group("resources").startswith("['")
    assert m.group("fingerprints").startswith("['")

    subjects = ast.literal_eval(m.group("subjects"))
    assert subjects == ["bot-123"]

    assert m.group("correlation") == "corr-1"

    fps = ast.literal_eval(m.group("fingerprints"))
    assert len(fps) == 1
    assert re.fullmatch(r"[0-9a-f]{12}", fps[0]), f"fingerprint format: {fps[0]!r}"
    # latency precision is guarded by the (?!\d) lookahead in _C1; no separate check needed


# ---------------------------------------------------------------------------
# C1 — dual-principal (two subjects, two resources, two fingerprints)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_c1_dual_principal_grammar(
    make_config, make_openai_call, noop_sleep, respx_mock, caplog
) -> None:
    from apparitor.mapping import DualPrincipalMapper, subject_scope
    from apparitor.models import Subject

    respx_mock.post(_BATCH_URL).respond(
        json={"evaluations": [{"decision": True}, {"decision": True}]}
    )
    config = make_config(agent_id="travel-bot")
    engine = _engine(config, noop_sleep, mapper=DualPrincipalMapper(config))
    ctx = caplog.at_level(logging.INFO, logger="apparitor")
    with subject_scope(Subject(type="user", id="alice@acme.com")), ctx:
        await engine.evaluate_tool_calls([make_openai_call("files_read")])

    line = _c1_record(caplog)
    assert line is not None, "no C1 line emitted"

    m = _C1.search(line)
    assert m is not None, f"C1 grammar mismatch: {line!r}"

    # subjects= is sorted and deduplicated
    subjects = ast.literal_eval(m.group("subjects"))
    assert subjects == sorted(subjects), "subjects not sorted"
    assert len(subjects) == len(set(subjects)), "subjects not deduplicated"
    assert set(subjects) == {"alice@acme.com", "travel-bot"}

    # dual-principal → two resources and two fingerprints
    resources = ast.literal_eval(m.group("resources"))
    fingerprints = ast.literal_eval(m.group("fingerprints"))
    assert len(resources) == 2
    assert len(fingerprints) == 2
    for fp in fingerprints:
        assert re.fullmatch(r"[0-9a-f]{12}", fp), f"fingerprint format: {fp!r}"


# ---------------------------------------------------------------------------
# C1 — correlation present vs absent
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_c1_correlation_present(
    make_config, make_openai_call, noop_sleep, respx_mock, caplog
) -> None:
    respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    engine = _engine(make_config(), noop_sleep)
    with caplog.at_level(logging.INFO, logger="apparitor"):
        await engine.evaluate_tool_calls(
            [make_openai_call("read")],
            request_context={"correlation_id": "my-corr-id"},
        )

    line = _c1_record(caplog)
    assert line is not None
    m = _C1.search(line)
    assert m is not None
    assert m.group("correlation") == "my-corr-id"


@pytest.mark.asyncio
async def test_c1_correlation_absent_renders_none(
    make_config, make_openai_call, noop_sleep, respx_mock, caplog
) -> None:
    # When no correlation_id is in the request context the field renders as the
    # literal string "None" — it is never omitted from the line.
    respx_mock.post(_EVAL_URL).respond(json={"decision": True})
    engine = _engine(make_config(), noop_sleep)
    with caplog.at_level(logging.INFO, logger="apparitor"):
        await engine.evaluate_tool_calls([make_openai_call("read")])

    line = _c1_record(caplog)
    assert line is not None
    m = _C1.search(line)
    assert m is not None
    assert m.group("correlation") == "None"


# ---------------------------------------------------------------------------
# C2 — denied-legs companion
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_c2_denied_legs_grammar(
    make_config, make_openai_call, noop_sleep, respx_mock, caplog
) -> None:
    from apparitor.mapping import DualPrincipalMapper, subject_scope
    from apparitor.models import Subject

    # Deny the agent leg so the batch fires the C2 line.
    respx_mock.post(_BATCH_URL).respond(
        json={"evaluations": [{"decision": True}, {"decision": False}]}
    )
    config = make_config(agent_id="travel-bot")
    engine = _engine(config, noop_sleep, mapper=DualPrincipalMapper(config))
    ctx = caplog.at_level(logging.INFO, logger="apparitor")
    with subject_scope(Subject(type="user", id="alice@acme.com")), ctx:
        await engine.evaluate_tool_calls([make_openai_call("delete_table")])

    # Find C2
    c2_line = None
    for r in caplog.records:
        if r.name == "apparitor":
            msg = r.getMessage()
            if _C2.search(msg):
                c2_line = msg
                break
    assert c2_line is not None, "no C2 line emitted"

    m = _C2.search(c2_line)
    assert m is not None
    legs = ast.literal_eval(m.group("legs"))
    assert len(legs) >= 1

    # Each entry has the grammar: <type>:<id> <action> <resource>
    for entry in legs:
        assert re.fullmatch(r"\S+:\S+ \S+ \S+", entry), f"C2 entry grammar mismatch: {entry!r}"


# ---------------------------------------------------------------------------
# C3 — evaluate_each summary
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_c3_evaluate_each_grammar(make_config, noop_sleep, respx_mock, caplog) -> None:
    from apparitor.adapters import NormalizedToolCall

    respx_mock.post(_BATCH_URL).respond(
        json={"evaluations": [{"decision": True}, {"decision": False}]}
    )
    engine = _engine(make_config(), noop_sleep)
    with caplog.at_level(logging.INFO, logger="apparitor"):
        await engine.evaluate_each([NormalizedToolCall("read"), NormalizedToolCall("delete")])

    c3_line = None
    for r in caplog.records:
        if r.name == "apparitor":
            msg = r.getMessage()
            if _C3.search(msg):
                c3_line = msg
                break
    assert c3_line is not None, "no C3 line emitted"

    m = _C3.search(c3_line)
    assert m is not None, f"C3 grammar mismatch: {c3_line!r}"

    # Pins the Python-repr single-quote list format; latency precision is guarded by
    # the (?!\d) lookahead in _C3.
    assert m.group("verdicts").startswith("['")
    verdicts = ast.literal_eval(m.group("verdicts"))
    assert verdicts == ["allow", "block"]


# ---------------------------------------------------------------------------
# SKIP paths emit no C1
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_skip_none_emits_no_c1(make_config, noop_sleep, caplog) -> None:
    engine = _engine(make_config(), noop_sleep)
    with caplog.at_level(logging.INFO, logger="apparitor"):
        await engine.evaluate_tool_calls(None)

    for r in caplog.records:
        if r.name == "apparitor":
            assert "apparitor decision" not in r.getMessage()


@pytest.mark.asyncio
async def test_skip_empty_emits_no_c1(make_config, noop_sleep, caplog) -> None:
    engine = _engine(make_config(), noop_sleep)
    with caplog.at_level(logging.INFO, logger="apparitor"):
        await engine.evaluate_tool_calls([])

    for r in caplog.records:
        if r.name == "apparitor":
            assert "apparitor decision" not in r.getMessage()
