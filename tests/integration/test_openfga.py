"""Integration test: the engine against a real OpenFGA via its native AuthZEN API.

Docker-gated and integration-marked, so it is excluded from the default run and skips
cleanly when Docker or testcontainers are unavailable. Mirrors ``examples/openfga``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
import pytest

from authzen_llamafirewall import AuthorizationEngine, ScannerConfig, Verdict

from ._helpers import wait_healthy

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

pytestmark = [pytest.mark.integration, pytest.mark.docker]

DockerContainer = pytest.importorskip("testcontainers.core.container").DockerContainer

_IMAGE = "openfga/openfga:v1.15.0"
_EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "openfga"


@pytest.fixture(scope="module")
def openfga_store(docker_available: bool) -> Iterator[tuple[str, str]]:
    """Start OpenFGA, load the vendored model + tuples, yield ``(base_url, store_id)``."""
    if not docker_available:
        pytest.skip("Docker daemon not available")
    container = (
        DockerContainer(_IMAGE)
        .with_command("run --experimentals=authzen --authzen-base-url=http://localhost:8080")
        .with_exposed_ports(8080)
    )
    container.start()
    try:
        base = f"http://{container.get_container_host_ip()}:{container.get_exposed_port(8080)}"
        wait_healthy(base)
        model = json.loads((_EXAMPLE / "model.json").read_text())
        tuples = json.loads((_EXAMPLE / "tuples.json").read_text())
        with httpx.Client(base_url=base, timeout=10.0) as client:
            store_id = client.post("/stores", json={"name": "authzen-it"}).json()["id"]
            client.post(f"/stores/{store_id}/authorization-models", json=model).raise_for_status()
            client.post(
                f"/stores/{store_id}/write", json={"writes": {"tuple_keys": tuples}}
            ).raise_for_status()
        yield base, store_id
    finally:
        container.stop()


def _config(base: str, store_id: str) -> ScannerConfig:
    return ScannerConfig(
        pdp_url=base,
        allow_insecure_pdp=True,
        agent_id="demo-agent",
        action_name="can_execute",  # the OpenFGA relation
        evaluation_path=f"/stores/{store_id}/access/v1/evaluation",
        batch_path=f"/stores/{store_id}/access/v1/evaluations",
    )


@pytest.mark.asyncio
async def test_single_tool_call(
    openfga_store: tuple[str, str], make_openai_call: Callable[..., dict[str, object]]
) -> None:
    base, store_id = openfga_store
    engine = AuthorizationEngine(_config(base, store_id))
    try:
        allowed = await engine.evaluate_tool_calls([make_openai_call("send_email")])
        blocked = await engine.evaluate_tool_calls([make_openai_call("delete_database")])
    finally:
        await engine.aclose()
    assert allowed.verdict is Verdict.ALLOW
    assert blocked.verdict is Verdict.BLOCK


@pytest.mark.asyncio
async def test_batch_all_or_nothing(
    openfga_store: tuple[str, str], make_openai_call: Callable[..., dict[str, object]]
) -> None:
    base, store_id = openfga_store
    engine = AuthorizationEngine(_config(base, store_id))
    try:
        all_granted = await engine.evaluate_tool_calls(
            [make_openai_call("send_email"), make_openai_call("read_file")]
        )
        one_ungranted = await engine.evaluate_tool_calls(
            [make_openai_call("send_email"), make_openai_call("delete_database")]
        )
    finally:
        await engine.aclose()
    assert all_granted.verdict is Verdict.ALLOW
    assert one_ungranted.verdict is Verdict.BLOCK
