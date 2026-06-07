"""Smoke tests: package imports, LlamaFirewall-free standalone use, and the
LlamaFirewall import guard. Behavioural coverage lives in the dedicated test modules
(``test_engine``, ``test_client``, ``test_mapping``, ``test_decision``, ``test_cache``,
``test_security``, ``test_scanner``)."""

from __future__ import annotations

import importlib

import pytest

pytestmark = pytest.mark.unit


def test_package_imports_without_llamafirewall() -> None:
    pkg = importlib.import_module("authzen_llamafirewall")
    assert pkg.__version__
    # Unknown attributes still raise (PEP 562 __getattr__ is well-behaved).
    with pytest.raises(AttributeError):
        _ = pkg.DoesNotExist  # type: ignore[attr-defined]


def test_lf_free_submodules_import_standalone() -> None:
    for name in ("models", "client", "adapters", "mapping", "cache", "config", "errors"):
        importlib.import_module(f"authzen_llamafirewall.{name}")


def test_scanner_without_llamafirewall_raises_missing_dependency() -> None:
    from authzen_llamafirewall.errors import MissingDependencyError

    try:
        import llamafirewall  # noqa: F401
    except ImportError:
        with pytest.raises(MissingDependencyError):
            importlib.import_module("authzen_llamafirewall.scanner")
    else:
        # LlamaFirewall is installed; the scanner must import and subclass Scanner.
        from llamafirewall import Scanner

        from authzen_llamafirewall.scanner import AuthZENScanner

        assert issubclass(AuthZENScanner, Scanner)


def test_single_evaluation_request_roundtrips_spec_json() -> None:
    from authzen_llamafirewall.models import EvaluationRequest

    body = {
        "subject": {"type": "user", "id": "alice@acme.com"},
        "action": {"name": "can_read"},
        "resource": {"type": "document", "id": "123"},
    }
    req = EvaluationRequest.model_validate(body)
    assert req.subject.id == "alice@acme.com"
    # exclude_none keeps optional members (context) off the wire.
    assert "context" not in req.model_dump(exclude_none=True)


def test_response_tolerates_unknown_fields_and_requires_decision() -> None:
    from pydantic import ValidationError

    from authzen_llamafirewall.models import EvaluationResponse

    resp = EvaluationResponse.model_validate(
        {"decision": True, "context": {"id": "0", "reason_user": {"en": "ok"}}, "extra": 1}
    )
    assert resp.decision is True
    with pytest.raises(ValidationError):
        EvaluationResponse.model_validate({"context": {}})  # missing decision


def test_batch_uses_spec_literal_semantics() -> None:
    from authzen_llamafirewall.models import EvaluationSemantic, EvaluationsOptions

    assert EvaluationSemantic.DENY_ON_FIRST_DENY.value == "deny_on_first_deny"
    dumped = EvaluationsOptions(
        evaluations_semantic=EvaluationSemantic.PERMIT_ON_FIRST_PERMIT
    ).model_dump()
    assert dumped["evaluations_semantic"] == "permit_on_first_permit"


@pytest.mark.parametrize(
    ("raw", "expected_name", "expected_args"),
    [
        (
            {
                "id": "c1",
                "type": "function",
                "function": {"name": "delete_table", "arguments": '{"table": "prod"}'},
            },
            "delete_table",
            {"table": "prod"},
        ),
        (
            {"type": "tool_use", "id": "t1", "name": "read_file", "input": {"path": "/etc"}},
            "read_file",
            {"path": "/etc"},
        ),
        (
            {"name": "search", "args": {"q": "x"}, "id": "l1"},
            "search",
            {"q": "x"},
        ),
    ],
)
def test_adapters_normalize_provider_shapes(
    raw: dict, expected_name: str, expected_args: dict
) -> None:
    from authzen_llamafirewall.adapters import detect_adapter

    adapter = detect_adapter(raw)
    assert adapter is not None
    norm = adapter.normalize(raw)
    assert norm.name == expected_name
    assert norm.arguments == expected_args


def test_detect_adapter_returns_none_for_unknown_shape() -> None:
    from authzen_llamafirewall.adapters import detect_adapter

    assert detect_adapter({"weird": "shape"}) is None


def test_mcp_resource_id_is_server_scoped() -> None:
    from authzen_llamafirewall.mapping import mcp_resource_id

    assert mcp_resource_id("files", "read") == "files/read"


def test_config_rejects_unknown_fields_and_defaults_fail_closed() -> None:
    from pydantic import ValidationError

    from authzen_llamafirewall.config import OnError, ScannerConfig

    cfg = ScannerConfig(pdp_url="https://pdp.internal")  # type: ignore[arg-type]
    assert cfg.on_error is OnError.DENY
    assert cfg.verify_tls is True
    assert cfg.cache_enabled is False
    with pytest.raises(ValidationError):
        ScannerConfig(pdp_url="https://pdp.internal", bogus=1)  # type: ignore[call-arg]
