"""Shared helpers for the Docker-gated integration tests."""

from __future__ import annotations

import time
import urllib.error
import urllib.request


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
