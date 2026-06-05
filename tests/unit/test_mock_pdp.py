"""Tests for the example mock PDP's pure decision functions (no server)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_PATH = Path(__file__).parents[2] / "examples" / "mock_pdp" / "mock_pdp.py"
_spec = importlib.util.spec_from_file_location("mock_pdp", _PATH)
assert _spec and _spec.loader
mock_pdp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mock_pdp)


def test_decide_denylist() -> None:
    deny = {"tool_call.execute:database.delete_table"}
    blocked = mock_pdp.decide(
        deny, {}, {"name": "tool_call.execute"}, {"id": "database.delete_table"}
    )
    allowed = mock_pdp.decide(deny, {}, {"name": "tool_call.execute"}, {"id": "database.read"})
    assert blocked is False
    assert allowed is True


def test_evaluate_one_falls_back_to_top_level_defaults() -> None:
    body = {"action": {"name": "tool_call.execute"}, "resource": {"id": "x"}}
    assert mock_pdp._evaluate_one(set(), body) == {"decision": True}
    assert mock_pdp._evaluate_one({"tool_call.execute:x"}, body) == {"decision": False}
