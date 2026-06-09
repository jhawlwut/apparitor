"""Tests for the example OPA gateway's pure translation/decision logic (no opa binary).

The subprocess call to ``opa eval`` is stubbed, so these run without Docker or the CLI.
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

_PATH = Path(__file__).parents[2] / "examples" / "opa" / "gateway" / "gateway.py"
_spec = importlib.util.spec_from_file_location("opa_gateway", _PATH)
assert _spec and _spec.loader
gateway = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gateway)

_BODY = {
    "subject": {"type": "agent", "id": "demo-agent"},
    "action": {"name": "tool_call.execute"},
    "resource": {"type": "tool", "id": "send_email"},
}


def _eval_output(value: object) -> str:
    """The JSON shape `opa eval --format=json` emits for a single-expression query."""
    return json.dumps({"result": [{"expressions": [{"value": value, "text": gateway._QUERY}]}]})


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        (_eval_output(True), True),
        (_eval_output(False), False),
        (_eval_output("true"), False),  # a string, not a bool -> deny
        (_eval_output(1), False),  # truthy but not True -> deny
        ('{"result": []}', False),  # undefined result -> deny
        ("", False),  # no output -> deny
        ("not json", False),  # malformed -> deny
    ],
)
def test_extract_decision_only_true_is_allow(stdout: str, expected: bool) -> None:
    assert gateway._extract_decision(stdout) is expected


def test_decide_requires_core_fields() -> None:
    evaluator = gateway.OpaEvaluator(Path("policy.rego"), Path("data.json"))
    with pytest.raises(ValueError, match="required"):
        evaluator.decide({"subject": {"id": "a"}, "action": {"name": "x"}})


@pytest.mark.parametrize(
    ("returncode", "value", "expected"),
    [(0, True, True), (0, False, False), (1, True, False)],
)
def test_decide_maps_opa_result(
    monkeypatch: pytest.MonkeyPatch, returncode: int, value: bool, expected: bool
) -> None:
    def fake_run(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(returncode=returncode, stdout=_eval_output(value), stderr="")

    monkeypatch.setattr(gateway.subprocess, "run", fake_run)
    evaluator = gateway.OpaEvaluator(Path("policy.rego"), Path("data.json"))
    assert evaluator.decide(_BODY) is expected


def test_decide_forwards_input_to_opa(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def capture_run(cmd: list[str], *, input: str, **_kwargs: Any) -> SimpleNamespace:
        captured["cmd"] = cmd
        captured["input"] = json.loads(input)
        return SimpleNamespace(returncode=0, stdout=_eval_output(True), stderr="")

    monkeypatch.setattr(gateway.subprocess, "run", capture_run)
    evaluator = gateway.OpaEvaluator(Path("policy.rego"), Path("data.json"))
    body = {**_BODY, "context": {"conversation_id": "c1"}}
    assert evaluator.decide(body) is True
    # The whole tuple is handed to OPA as `input`, and the query targets the allow rule.
    assert captured["input"] == body
    assert captured["cmd"][-1] == gateway._QUERY
    assert "--stdin-input" in captured["cmd"]


def test_decide_fails_closed_when_opa_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        raise FileNotFoundError("opa")

    monkeypatch.setattr(gateway.subprocess, "run", boom)
    evaluator = gateway.OpaEvaluator(Path("policy.rego"), Path("data.json"))
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


def _drive_batch(body: Any, *, content_length: int | None = None) -> tuple[int, dict[str, Any]]:
    """Invoke the batch handler in-process (no socket) and capture the response."""
    evaluator = gateway.OpaEvaluator(Path("policy.rego"), Path("data.json"))
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
    return SimpleNamespace(returncode=0, stdout=_eval_output(True), stderr="")


def test_batch_preserves_order_and_per_entry_decisions(monkeypatch: pytest.MonkeyPatch) -> None:
    def by_resource(_cmd: list[str], *, input: str, **_k: Any) -> SimpleNamespace:
        denied = json.loads(input)["resource"]["id"] == "delete_database"
        return SimpleNamespace(returncode=0, stdout=_eval_output(not denied), stderr="")

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
    # Even when opa would allow everything, a non-dict (malformed) entry must deny and must
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


def test_batch_non_dict_body_is_400(monkeypatch: pytest.MonkeyPatch) -> None:
    # A non-object JSON root (array/string/number) must be a clean 400, not an AttributeError.
    monkeypatch.setattr(gateway.subprocess, "run", _allow_all)
    status, _ = _drive_batch([{"resource": {"type": "tool", "id": "send_email"}}])
    assert status == 400


def test_batch_negative_content_length_is_400(monkeypatch: pytest.MonkeyPatch) -> None:
    # A negative Content-Length must not reach read(-1) (which would drain to EOF).
    monkeypatch.setattr(gateway.subprocess, "run", _allow_all)
    status, _ = _drive_batch({"evaluations": []}, content_length=-1)
    assert status == 400


def test_merge_item_honors_explicit_falsey_override() -> None:
    defaults = {"resource": {"type": "tool", "id": "default"}, "context": {"k": "v"}}
    # An entry that explicitly clears a field keeps the empty value (no default inheritance);
    # a field the entry omits still falls back to the default.
    merged = gateway._merge_item({"resource": {}, "context": None}, defaults)
    assert merged["resource"] == {}
    assert merged["context"] is None
    assert gateway._merge_item({}, defaults)["resource"] == {"type": "tool", "id": "default"}
