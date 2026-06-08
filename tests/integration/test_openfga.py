"""Integration test: the engine against a real OpenFGA via its native AuthZEN API.

Integration-marked, so it is excluded from the default run. Two interchangeable backends
serve the same vendored model + tuples through the same assertions:

* **Docker** (default) — a digest-pinned OpenFGA image via testcontainers; skips cleanly
  when Docker or testcontainers are unavailable.
* **Native** — set ``APPARITOR_OPENFGA_NATIVE=1`` to run a pinned OpenFGA release binary
  directly (no Docker registry needed), for restricted-egress CI and sandboxes.

Mirrors ``examples/openfga``.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
import pytest

from apparitor import AuthorizationEngine, ScannerConfig, Verdict

from ._helpers import native_openfga, wait_healthy

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

_NATIVE = os.getenv("APPARITOR_OPENFGA_NATIVE", "").strip().lower() in {"1", "true", "yes", "on"}

# The native backend needs no Docker daemon, so it must not carry the `docker` marker
# (which would otherwise skip it when no daemon is present — see tests/conftest.py).
pytestmark = [pytest.mark.integration] if _NATIVE else [pytest.mark.integration, pytest.mark.docker]

# Docker backend image, pinned by digest (tag v1.15.0) for reproducibility. The bare
# name@sha256 form is what the testcontainers/docker-py pull path resolves cleanly (a
# tag+digest ref confuses it).
_IMAGE = "openfga/openfga@sha256:5cd70f1f71e17124e8213c0e35c4a453e39e25f6365a0baf700f06584a04e7e8"
_EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "openfga"


@contextmanager
def _openfga_server(docker_available: bool) -> Iterator[str]:
    """Yield the base URL of a running OpenFGA — native binary or Docker container."""
    if _NATIVE:
        with native_openfga() as base:
            yield base
        return
    if not docker_available:
        pytest.skip("Docker daemon not available")
    testcontainers = pytest.importorskip("testcontainers.core.container")
    container = (
        testcontainers.DockerContainer(_IMAGE)
        .with_command("run --experimentals=authzen --authzen-base-url=http://localhost:8080")
        .with_exposed_ports(8080)
    )
    container.start()
    try:
        yield f"http://{container.get_container_host_ip()}:{container.get_exposed_port(8080)}"
    finally:
        container.stop()


@pytest.fixture(scope="module")
def openfga_store(docker_available: bool) -> Iterator[tuple[str, str]]:
    """Start OpenFGA, load the vendored model + tuples, yield ``(base_url, store_id)``."""
    with _openfga_server(docker_available) as base:
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
