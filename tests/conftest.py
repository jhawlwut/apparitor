"""Shared pytest fixtures and guards.

* ``no_real_network`` — autouse for ``unit``-marked tests: blocks outbound TCP so a
  unit test can never accidentally hit a real PDP.
* ``docker_available`` — session probe; ``docker``-marked tests *skip* (never fail)
  when no daemon is reachable, keeping the default/unit run green without Docker.
* ``make_config`` / ``make_openai_call`` / ``noop_sleep`` — factories used by the suite.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture(autouse=True)
def no_real_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Block real outbound TCP connections for unit-marked tests."""
    if request.node.get_closest_marker("unit") is None:
        return

    real_connect = socket.socket.connect

    def guarded_connect(self: socket.socket, address: Any) -> None:
        host = address[0] if isinstance(address, tuple) else address
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise RuntimeError(
                f"unit test attempted a real network connection to {address!r}; "
                "mock the PDP with respx instead"
            )
        real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)


@pytest.fixture(scope="session")
def docker_available() -> bool:
    """Best-effort probe for a reachable Docker daemon."""
    return any(Path(p).exists() for p in ("/var/run/docker.sock", "/run/docker.sock"))


@pytest.fixture(autouse=True)
def _skip_docker_without_daemon(request: pytest.FixtureRequest, docker_available: bool) -> None:
    if request.node.get_closest_marker("docker") and not docker_available:
        pytest.skip("Docker daemon not available")


@pytest.fixture
def make_config():
    """Factory for a test ScannerConfig (mockable http PDP, no real backoff sleeps)."""
    from authzen_llamafirewall.config import ScannerConfig

    def _make(**overrides: Any) -> Any:
        params: dict[str, Any] = {
            "pdp_url": "http://pdp.test",
            "allow_insecure_pdp": True,
            "agent_id": "bot-123",
            "max_retries": 2,
            "backoff_base_s": 0.0,
            "backoff_max_s": 0.0,
        }
        params.update(overrides)
        return ScannerConfig(**params)

    return _make


async def _noop_sleep(_seconds: float) -> None:
    """A non-sleeping replacement for asyncio.sleep in retry tests."""
    return None


@pytest.fixture
def noop_sleep():
    return _noop_sleep


@pytest.fixture
def make_openai_call():
    """Factory for an OpenAI-shaped tool_call dict."""

    def _make(name: str, **args: Any) -> dict[str, Any]:
        return {
            "id": f"call_{name}",
            "type": "function",
            "function": {"name": name, "arguments": json.dumps(args)},
        }

    return _make
