"""Decision cache tests — TTL behaviour, key derivation, ALLOW-only contract."""

from __future__ import annotations

import pytest

from authzen_llamafirewall.cache import DecisionCache, decision_cache_key
from authzen_llamafirewall.models import Action, EvaluationRequest, Resource, Subject

pytestmark = pytest.mark.unit


def _request(tool_id: str = "x", **args: object) -> EvaluationRequest:
    return EvaluationRequest(
        subject=Subject(type="agent", id="bot"),
        action=Action(name="tool_call.execute"),
        resource=Resource(type="tool", id=tool_id, properties={"arguments": dict(args)}),
    )


def test_key_is_stable_and_argument_sensitive() -> None:
    assert decision_cache_key(_request("t", a=1)) == decision_cache_key(_request("t", a=1))
    # Different arguments must not collide onto the same cached decision.
    assert decision_cache_key(_request("t", path="/tmp")) != decision_cache_key(
        _request("t", path="/etc/passwd")
    )
    assert decision_cache_key(_request("a")) != decision_cache_key(_request("b"))


def test_get_miss_then_hit_then_expiry() -> None:
    now = [1000.0]
    cache = DecisionCache(ttl_s=10, max_ttl_s=300, clock=lambda: now[0])
    assert cache.get("k") is None
    cache.set_allow("k")
    assert cache.get("k") is True
    now[0] += 9
    assert cache.get("k") is True
    now[0] += 2  # past the 10s TTL
    assert cache.get("k") is None


def test_pdp_ttl_clamped_to_ceiling() -> None:
    now = [0.0]
    cache = DecisionCache(ttl_s=10, max_ttl_s=60, clock=lambda: now[0])
    cache.set_allow("k", pdp_ttl_s=9999)
    now[0] = 61  # beyond the 60s ceiling
    assert cache.get("k") is None


def test_zero_ttl_does_not_store() -> None:
    cache = DecisionCache(ttl_s=0, max_ttl_s=300, clock=lambda: 0.0)
    cache.set_allow("k")
    assert cache.get("k") is None


def test_clear() -> None:
    cache = DecisionCache(ttl_s=10, max_ttl_s=300, clock=lambda: 0.0)
    cache.set_allow("k")
    cache.clear()
    assert cache.get("k") is None
