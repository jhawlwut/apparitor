"""Integration test: the engine against the local AuthZEN -> Cedar gateway.

Builds the gateway image (official Cedar CLI + stdlib gateway) and drives the real engine
against it. Docker-gated and integration-marked; skips cleanly without Docker or
testcontainers. Mirrors ``examples/cedar``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from authzen_llamafirewall import AuthorizationEngine, ScannerConfig, Verdict

from ._helpers import wait_healthy

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

pytestmark = [pytest.mark.integration, pytest.mark.docker]

DockerContainer = pytest.importorskip("testcontainers.core.container").DockerContainer
DockerImage = pytest.importorskip("testcontainers.core.image").DockerImage

_EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "cedar"


@pytest.fixture(scope="module")
def cedar_base_url(docker_available: bool) -> Iterator[str]:
    """Build + run the Cedar gateway image, yielding its base URL."""
    if not docker_available:
        pytest.skip("Docker daemon not available")
    with DockerImage(
        path=str(_EXAMPLE),
        dockerfile_path="gateway/Dockerfile",
        tag="authzen-cedar-it:latest",
    ) as image:
        container = DockerContainer(str(image)).with_exposed_ports(8080)
        container.start()
        try:
            base = f"http://{container.get_container_host_ip()}:{container.get_exposed_port(8080)}"
            wait_healthy(base)
            yield base
        finally:
            container.stop()


@pytest.mark.asyncio
async def test_permit_and_forbid(
    cedar_base_url: str, make_openai_call: Callable[..., dict[str, object]]
) -> None:
    engine = AuthorizationEngine(
        ScannerConfig(pdp_url=cedar_base_url, allow_insecure_pdp=True, agent_id="demo-agent")
    )
    try:
        allowed = await engine.evaluate_tool_calls([make_openai_call("send_email")])
        blocked = await engine.evaluate_tool_calls([make_openai_call("delete_database")])
    finally:
        await engine.aclose()
    assert allowed.verdict is Verdict.ALLOW
    assert blocked.verdict is Verdict.BLOCK


@pytest.mark.asyncio
async def test_batch_all_or_nothing(
    cedar_base_url: str, make_openai_call: Callable[..., dict[str, object]]
) -> None:
    # Multi-tool-call messages take the batch path (POST /access/v1/evaluations); execute_all
    # means the message is allowed only if every call is permitted.
    engine = AuthorizationEngine(
        ScannerConfig(pdp_url=cedar_base_url, allow_insecure_pdp=True, agent_id="demo-agent")
    )
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
