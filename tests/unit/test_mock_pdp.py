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


def test_decide_subject_scoped_deny() -> None:
    # 3-part key blocks only the named subject; other subjects still pass.
    deny = {"alice:tool_call.execute:book_flight"}
    alice = {"id": "alice"}
    bob = {"id": "bob"}
    action = {"name": "tool_call.execute"}
    resource = {"id": "book_flight"}
    assert mock_pdp.decide(deny, alice, action, resource) is False
    assert mock_pdp.decide(deny, bob, action, resource) is True


def test_decide_two_and_three_part_are_independent() -> None:
    # A 2-part rule blocks every subject; a 3-part rule for a different subject
    # does not unblock what the 2-part rule already covers.
    deny = {"tool_call.execute:nuke", "carol:tool_call.execute:safe"}
    action = {"name": "tool_call.execute"}
    assert mock_pdp.decide(deny, {"id": "carol"}, action, {"id": "nuke"}) is False
    assert mock_pdp.decide(deny, {"id": "dave"}, action, {"id": "nuke"}) is False
    assert mock_pdp.decide(deny, {"id": "carol"}, action, {"id": "safe"}) is False
    assert mock_pdp.decide(deny, {"id": "dave"}, action, {"id": "safe"}) is True


def test_decide_colon_overlap() -> None:
    # A deny entry "a:b:c" is a pure membership test — it matches both the 3-part
    # form (subject=a, action=b, resource=c) AND the 2-part form when the action name
    # contains a colon (action="a:b", resource="c").  This is a key-space overlap, not
    # a parsing ambiguity; the demo avoids ':' in action names to sidestep it.
    deny = {"a:b:c"}
    assert mock_pdp.decide(deny, {"id": "a"}, {"name": "b"}, {"id": "c"}) is False  # 3-part
    # 2-part overlap: action name contains ':', so "a:b" + "c" composes the same key
    assert mock_pdp.decide(deny, {"id": "x"}, {"name": "a:b"}, {"id": "c"}) is False
    # unrelated subject, action "b" — not in the deny set
    assert mock_pdp.decide(deny, {"id": "x"}, {"name": "b"}, {"id": "c"}) is True
