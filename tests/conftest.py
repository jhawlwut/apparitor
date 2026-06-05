"""Shared pytest fixtures and guards.

The behavioural suite is deferred, but the scaffold pins the fixtures and markers the
suite will rely on so it has nowhere to drift:

* ``no_real_network`` — autouse for ``unit``-marked tests: blocks outbound TCP so a
  unit test can never accidentally hit a real PDP.
* ``docker_available`` — session probe; ``docker``-marked tests *skip* (never fail)
  when no daemon is reachable, keeping the default/unit run green without Docker.
* ``frozen_clock`` — deterministic time for cache TTL tests (no ``sleep``).
* ``authzen_interop_cases`` — the vendored OpenID AuthZEN interop decisions, used as a
  conformance oracle and for golden request-body tests.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def pdp_base_url() -> str:
    return "https://pdp.test"


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
def frozen_clock():
    freezegun = pytest.importorskip("freezegun")
    with freezegun.freeze_time("2026-06-05T00:00:00Z") as frozen:
        yield frozen


@pytest.fixture
def authzen_interop_cases() -> list[dict[str, Any]]:
    """Load vendored AuthZEN interop request/expected-decision pairs."""
    path = FIXTURES / "authzen_interop" / "decisions.json"
    if not path.exists():
        pytest.skip("interop decisions fixture not yet vendored")
    return json.loads(path.read_text())
