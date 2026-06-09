"""Integration test: the native OPA backend against a real ``opa run --server``.

Drives the engine with ``backend="opa"`` straight at OPA's Data API — no AuthZEN gateway.
Runs the pinned OPA release binary directly (Docker-free, linux/amd64 only); integration-
marked, so excluded from the default run, and skips cleanly off linux/amd64. Reuses the
vendored policy + data from ``examples/opa``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from apparitor import AuthorizationEngine, ScannerConfig, Verdict

from ._helpers import native_opa, wait_healthy

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

# Native binary, no Docker daemon needed — so no `docker` marker (which would skip it).
pytestmark = [pytest.mark.integration]

_EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "opa"


@pytest.fixture(scope="module")
def opa_base_url() -> Iterator[str]:
    with native_opa(_EXAMPLE / "policy.rego", _EXAMPLE / "data.json") as base:
        wait_healthy(base, path="/health")
        yield base


def _config(base: str) -> ScannerConfig:
    return ScannerConfig(
        backend="opa",
        pdp_url=base,
        allow_insecure_pdp=True,
        agent_id="demo-agent",
        opa_decision_path="apparitor/authz/allow",
    )


@pytest.mark.asyncio
async def test_permit_and_deny(
    opa_base_url: str, make_openai_call: Callable[..., dict[str, object]]
) -> None:
    engine = AuthorizationEngine(_config(opa_base_url))
    try:
        allowed = await engine.evaluate_tool_calls([make_openai_call("send_email")])
        blocked = await engine.evaluate_tool_calls([make_openai_call("delete_database")])
    finally:
        await engine.aclose()
    assert allowed.verdict is Verdict.ALLOW
    assert blocked.verdict is Verdict.BLOCK


@pytest.mark.asyncio
async def test_batch_all_or_nothing(
    opa_base_url: str, make_openai_call: Callable[..., dict[str, object]]
) -> None:
    # backend="opa" fans the batch out to one Data API call per entry; execute_all means the
    # message is allowed only if every call is permitted.
    engine = AuthorizationEngine(_config(opa_base_url))
    try:
        all_granted = await engine.evaluate_tool_calls(
            [make_openai_call("send_email"), make_openai_call("read_file")]
        )
        one_denied = await engine.evaluate_tool_calls(
            [make_openai_call("send_email"), make_openai_call("delete_database")]
        )
    finally:
        await engine.aclose()
    assert all_granted.verdict is Verdict.ALLOW
    assert one_denied.verdict is Verdict.BLOCK
