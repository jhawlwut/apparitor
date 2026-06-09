"""Shared helpers for the Docker-gated integration tests."""

from __future__ import annotations

import contextlib
import hashlib
import platform
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator


def wait_healthy(base_url: str, path: str = "/healthz", timeout_s: float = 60.0) -> None:
    """Poll ``base_url + path`` until it returns HTTP 200 or the timeout elapses."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}{path}", timeout=2) as resp:
                if resp.status == 200:
                    return
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(1)
    raise TimeoutError(f"{base_url}{path} did not become healthy within {timeout_s}s")


# OpenFGA serves the AuthZEN Access Evaluation API natively (experimental). Running its
# release binary directly gives the OpenFGA integration test a real PDP where the Docker
# registry is unreachable (restricted-egress CI, sandboxes) but github.com is not. The
# version and SHA-256 are pinned and the archive is verified before it is ever opened or
# executed — the same pinned-and-verified posture as the digest-pinned image the Docker
# path uses. This version is pinned independently of that image (v1.15.0): both expose the
# same experimental AuthZEN API the test exercises; bump deliberately, keeping the checksum
# below in lockstep.
_OPENFGA_VERSION = "1.17.1"
_OPENFGA_SHA256 = "54fa82228ada006e72d0566bf12a4831045561c0a367f92fc7352a7063b0b786"
_OPENFGA_URL = (
    f"https://github.com/openfga/openfga/releases/download/"
    f"v{_OPENFGA_VERSION}/openfga_{_OPENFGA_VERSION}_linux_amd64.tar.gz"
)


# OPA's native backend (apparitor backend="opa") talks OPA's own Data API, so the native
# integration test runs OPA's release binary directly — no Docker, no AuthZEN gateway. The
# version and SHA-256 are pinned and the binary is verified before it is ever executed,
# matching the digest-pinned posture of the gateway image. Bump deliberately, keeping the
# checksum in lockstep (the official per-asset checksum is published at <asset>.sha256).
_OPA_VERSION = "1.17.1"
_OPA_SHA256 = "3d4bb88482958d990351ec5d2f7558509992776bc473bc1b78d86d76cb993ca3"
_OPA_URL = (
    f"https://github.com/open-policy-agent/opa/releases/download/"
    f"v{_OPA_VERSION}/opa_linux_amd64_static"
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _ensure_openfga_binary() -> str:
    """Download (cached) and verify the pinned OpenFGA archive; extract and return the path.

    The archive SHA-256 is checked on *every* call — including against a cached archive —
    before it is opened, and the binary is re-extracted from the verified archive each time.
    So a tampered cache in the world-writable temp dir can never be opened or executed: the
    bad archive is rejected, and a swapped-in loose binary is overwritten by the verified
    extraction.
    """
    cache = Path(tempfile.gettempdir()) / f"apparitor-openfga-{_OPENFGA_VERSION}"
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / "openfga.tar.gz"
    if not archive.exists():
        with urllib.request.urlopen(_OPENFGA_URL, timeout=30) as resp:
            archive.write_bytes(resp.read())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != _OPENFGA_SHA256:
        archive.unlink(missing_ok=True)
        raise RuntimeError(
            f"OpenFGA {_OPENFGA_VERSION} checksum mismatch: "
            f"got {digest}, expected {_OPENFGA_SHA256}"
        )
    binary = cache / "openfga"
    with tarfile.open(archive) as tar:
        member = next(m for m in tar.getmembers() if m.isfile() and Path(m.name).name == "openfga")
        member.name = "openfga"  # flatten to the bare binary; never honour archived paths
        tar.extract(member, cache)
    binary.chmod(0o755)
    return str(binary)


def _ensure_opa_binary() -> str:
    """Download (cached) and verify the pinned OPA binary; return its path.

    OPA ships a single static binary (not an archive), so the download *is* the executable.
    Its SHA-256 is checked on every call — including against the cache — before it is made
    executable or run, so a tampered cache in the world-writable temp dir is rejected.
    """
    cache = Path(tempfile.gettempdir()) / f"apparitor-opa-{_OPA_VERSION}"
    cache.mkdir(parents=True, exist_ok=True)
    binary = cache / "opa"
    if not binary.exists():
        with urllib.request.urlopen(_OPA_URL, timeout=30) as resp:
            binary.write_bytes(resp.read())
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if digest != _OPA_SHA256:
        binary.unlink(missing_ok=True)
        raise RuntimeError(
            f"OPA {_OPA_VERSION} checksum mismatch: got {digest}, expected {_OPA_SHA256}"
        )
    binary.chmod(0o755)
    return str(binary)


@contextlib.contextmanager
def native_opa(policy: Path, data: Path) -> Iterator[str]:
    """Run the pinned OPA binary in server mode over the vendored policy + data; yield base URL.

    A Docker-free backend for the native OPA integration test (linux/amd64 only); skips
    cleanly on other platforms rather than failing.
    """
    if sys.platform != "linux" or platform.machine() not in ("x86_64", "amd64"):
        pytest.skip("native OPA backend supports linux/amd64 only")
    binary = _ensure_opa_binary()
    port = _free_port()
    proc = subprocess.Popen(
        [binary, "run", "--server", f"--addr=localhost:{port}", str(policy), str(data)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield f"http://localhost:{port}"
    finally:
        proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=10)
        if proc.poll() is None:
            proc.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=5)


@contextlib.contextmanager
def native_openfga() -> Iterator[str]:
    """Run the pinned OpenFGA release binary with the AuthZEN API; yield its base URL.

    A Docker-free backend for the OpenFGA integration test (linux/amd64 only); skips
    cleanly on other platforms rather than failing.
    """
    if sys.platform != "linux" or platform.machine() not in ("x86_64", "amd64"):
        pytest.skip("native OpenFGA backend supports linux/amd64 only")
    binary = _ensure_openfga_binary()
    http_port, grpc_port = _free_port(), _free_port()
    proc = subprocess.Popen(
        [
            binary,
            "run",
            "--experimentals=authzen",
            f"--authzen-base-url=http://localhost:{http_port}",
            f"--http-addr=localhost:{http_port}",
            f"--grpc-addr=localhost:{grpc_port}",
            "--playground-enabled=false",
            "--metrics-enabled=false",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield f"http://localhost:{http_port}"
    finally:
        proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=10)
        if proc.poll() is None:
            proc.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=5)
