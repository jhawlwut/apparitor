"""Tests for the example Cedar gateway's pure translation/decision logic (no cedar binary).

The subprocess call to ``cedar`` is stubbed, so these run without Docker or the CLI.
"""

from __future__ import annotations

import importlib.util
import io
import json
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


# --- batch endpoint -----------------------------------------------------------------


def test_merge_item_entry_overrides_defaults() -> None:
    defaults = {
        "subject": {"type": "agent", "id": "demo-agent"},
        "action": {"name": "tool_call.execute"},
        "resource": {"type": "tool", "id": "default"},
    }
    merged = gateway._merge_item({"resource": {"type": "tool", "id": "entry"}}, defaults)
    assert merged == {
        "subject": {"type": "agent", "id": "demo-agent"},
        "action": {"name": "tool_call.execute"},
        "resource": {"type": "tool", "id": "entry"},  # entry wins
        "context": None,  # absent on both -> None
    }


def _drive_batch(
    body: dict[str, Any], *, content_length: int | None = None
) -> tuple[int, dict[str, Any]]:
    """Invoke the batch handler in-process (no socket) and capture the response."""
    evaluator = gateway.CedarEvaluator(Path("policies.cedar"), Path("entities.json"))
    handler_cls = gateway.make_handler(evaluator)
    handler = handler_cls.__new__(handler_cls)
    raw = json.dumps(body).encode()
    length = len(raw) if content_length is None else content_length
    handler.headers = {"Content-Length": str(length)}
    handler.rfile = io.BytesIO(raw)
    captured: list[tuple[int, dict[str, Any]]] = []

    def capture(payload: dict[str, Any], status: int = 200) -> None:
        captured.append((status, payload))

    handler._send = capture  # type: ignore[method-assign]
    handler._evaluate_batch()
    return captured[0]


def _allow_all(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
    return SimpleNamespace(returncode=0, stdout="", stderr="")


def test_batch_preserves_order_and_per_entry_decisions(monkeypatch: pytest.MonkeyPatch) -> None:
    def by_resource(argv: list[str], *_a: Any, **_k: Any) -> SimpleNamespace:
        rc = 2 if any("delete_database" in a for a in argv) else 0
        return SimpleNamespace(returncode=rc, stdout="", stderr="")

    monkeypatch.setattr(gateway.subprocess, "run", by_resource)
    status, payload = _drive_batch(
        {
            "subject": {"type": "agent", "id": "demo-agent"},
            "action": {"name": "tool_call.execute"},
            "evaluations": [
                {"resource": {"type": "tool", "id": "send_email"}},
                {"resource": {"type": "tool", "id": "delete_database"}},
            ],
        }
    )
    assert status == 200
    assert payload == {"evaluations": [{"decision": True}, {"decision": False}]}


def test_batch_non_dict_entry_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # Even when cedar would allow everything, a non-dict (malformed) entry must deny and must
    # NOT inherit the request-level default tuple — the security-critical fail-closed case.
    monkeypatch.setattr(gateway.subprocess, "run", _allow_all)
    status, payload = _drive_batch(
        {
            "subject": {"type": "agent", "id": "demo-agent"},
            "action": {"name": "tool_call.execute"},
            "resource": {"type": "tool", "id": "send_email"},  # a valid Allow default
            "evaluations": [12345, "garbage", None, True],
        }
    )
    assert status == 200
    assert payload == {"evaluations": [{"decision": False}] * 4}


def test_batch_entry_missing_fields_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # A dict entry with no resolvable resource makes decide() raise; the batch loop catches it
    # per entry and denies rather than failing the whole request.
    monkeypatch.setattr(gateway.subprocess, "run", _allow_all)
    status, payload = _drive_batch(
        {
            "subject": {"type": "agent", "id": "demo-agent"},
            "action": {"name": "tool_call.execute"},
            "evaluations": [{"subject": {"type": "agent", "id": "demo-agent"}}],
        }
    )
    assert (status, payload) == (200, {"evaluations": [{"decision": False}]})


def test_batch_non_list_evaluations_is_400(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway.subprocess, "run", _allow_all)
    status, _ = _drive_batch({"evaluations": "nope"})
    assert status == 400


def test_batch_too_many_evaluations_is_413(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway.subprocess, "run", _allow_all)
    entry = {"resource": {"type": "tool", "id": "send_email"}}
    status, _ = _drive_batch(
        {
            "subject": {"type": "agent", "id": "demo-agent"},
            "action": {"name": "tool_call.execute"},
            "evaluations": [entry] * (gateway._MAX_BATCH + 1),
        }
    )
    assert status == 413


def test_batch_oversized_body_is_400(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway.subprocess, "run", _allow_all)
    status, _ = _drive_batch({"evaluations": []}, content_length=gateway._MAX_BODY_BYTES + 1)
    assert status == 400


def test_batch_empty_list_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway.subprocess, "run", _allow_all)
    status, payload = _drive_batch({"evaluations": []})
    assert (status, payload) == (200, {"evaluations": []})
