"""Tests for the example Cedar gateway's pure translation/decision logic (no cedar binary).

The subprocess call to ``cedar`` is stubbed, so these run without Docker or the CLI.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytestmark = pytest.mark.unit

_PATH = Path(__file__).parents[2] / "examples" / "cedar" / "gateway" / "gateway.py"
_spec = importlib.util.spec_from_file_location("cedar_gateway", _PATH)
assert _spec and _spec.loader
gateway = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gateway)

_BODY = {
    "subject": {"type": "agent", "id": "demo-agent"},
    "action": {"name": "tool_call.execute"},
    "resource": {"type": "tool", "id": "send_email"},
}


def test_entity_uid_maps_known_and_unknown_types() -> None:
    assert gateway._entity_uid("agent", "demo-agent") == 'Agent::"demo-agent"'
    assert gateway._entity_uid("tool", "send_email") == 'Tool::"send_email"'
    assert gateway._entity_uid("widget", "w1") == 'Widget::"w1"'


def test_entity_uid_rejects_embedded_double_quote() -> None:
    with pytest.raises(ValueError, match="double-quote"):
        gateway._entity_uid("tool", 'send"_email')


def test_decide_requires_core_fields() -> None:
    evaluator = gateway.CedarEvaluator(Path("policies.cedar"), Path("entities.json"))
    with pytest.raises(ValueError, match="required"):
        evaluator.decide({"subject": {"id": "a"}, "action": {"name": "x"}})


@pytest.mark.parametrize(("returncode", "expected"), [(0, True), (2, False), (1, False)])
def test_decide_maps_cedar_exit_code(
    monkeypatch: pytest.MonkeyPatch, returncode: int, expected: bool
) -> None:
    def fake_run(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(returncode=returncode, stdout="", stderr="")

    monkeypatch.setattr(gateway.subprocess, "run", fake_run)
    evaluator = gateway.CedarEvaluator(Path("policies.cedar"), Path("entities.json"))
    assert evaluator.decide(_BODY) is expected


def test_decide_fails_closed_when_cedar_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        raise FileNotFoundError("cedar")

    monkeypatch.setattr(gateway.subprocess, "run", boom)
    evaluator = gateway.CedarEvaluator(Path("policies.cedar"), Path("entities.json"))
    assert evaluator.decide(_BODY) is False
