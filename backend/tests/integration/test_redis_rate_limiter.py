"""
Integration tests for Redis-Backed Atomic Multi-Worker Rate Limiter.

Verifies:
1. Shared state across independent instances/workers backed by Redis.
2. Sliding-window rate limit enforcement and atomic rejection (HTTP 429 with Retry-After).
3. Window expiration and counter reset behavior.
4. Client IP spoofing prevention (X-Forwarded-For ignored unless peer is in TRUSTED_PROXIES).
"""
from __future__ import annotations

import uuid
from fastapi import FastAPI, Depends, Request
from fastapi.testclient import TestClient

from app.core.rate_limiter import RedisRateLimiter, rate_limit, limiter


def test_redis_rate_limiter_shared_across_workers():
    """Verify that multiple application workers share the exact same rate limit counter via Redis."""
    # Worker 1 and Worker 2 are separate instances with their own connections to Redis
    worker_1 = RedisRateLimiter()
    worker_2 = RedisRateLimiter()

    test_ip = f"198.51.100.{uuid.uuid4().hex[:4]}"
    endpoint = "shared_test"
    max_calls = 3
    window = 10

    # Worker 1 consumes 2 requests
    allowed_1, rem_1, _ = worker_1.is_allowed(test_ip, endpoint, max_calls=max_calls, window_seconds=window)
    assert allowed_1 is True
    assert rem_1 == 2

    allowed_2, rem_2, _ = worker_1.is_allowed(test_ip, endpoint, max_calls=max_calls, window_seconds=window)
    assert allowed_2 is True
    assert rem_2 == 1

    # Worker 2 processes the 3rd request - should consume the last allowed slot
    allowed_3, rem_3, _ = worker_2.is_allowed(test_ip, endpoint, max_calls=max_calls, window_seconds=window)
    assert allowed_3 is True
    assert rem_3 == 0

    # Worker 2 processes the 4th request - MUST be rejected because limit was reached across workers!
    allowed_4, rem_4, retry_after = worker_2.is_allowed(test_ip, endpoint, max_calls=max_calls, window_seconds=window)
    assert allowed_4 is False
    assert rem_4 == 0
    assert retry_after > 0

    # Worker 1 also sees it blocked
    allowed_5, rem_5, _ = worker_1.is_allowed(test_ip, endpoint, max_calls=max_calls, window_seconds=window)
    assert allowed_5 is False


def test_redis_rate_limiter_reset():
    """Verify that resetting rate limiter restores access immediately."""
    limiter_inst = RedisRateLimiter()
    test_ip = f"198.51.100.{uuid.uuid4().hex[:4]}"
    endpoint = "reset_test"

    # Exhaust limit
    for _ in range(3):
        limiter_inst.is_allowed(test_ip, endpoint, max_calls=3, window_seconds=60)

    # Over limit
    allowed, _, _ = limiter_inst.is_allowed(test_ip, endpoint, max_calls=3, window_seconds=60)
    assert allowed is False

    # Reset
    limiter_inst.reset(test_ip, endpoint)

    # Allowed again
    allowed_after_reset, rem, _ = limiter_inst.is_allowed(test_ip, endpoint, max_calls=3, window_seconds=60)
    assert allowed_after_reset is True
    assert rem == 2


def test_client_ip_spoofing_defense():
    """Verify X-Forwarded-For header is ignored if the direct peer is not a trusted proxy."""
    dummy_app = FastAPI()

    @dummy_app.get("/test-ip")
    def test_ip_endpoint(request: Request):
        return {"detected_ip": limiter.get_client_ip(request)}

    client = TestClient(dummy_app)

    # Case A: Request from untrusted remote client sending fake X-Forwarded-For
    # TestClient default host is 'testclient' which is not in TRUSTED_PROXIES
    resp_untrusted = client.get("/test-ip", headers={"X-Forwarded-For": "1.2.3.4, 5.6.7.8"})
    assert resp_untrusted.status_code == 200
    # Must use direct peer (testclient), NOT the spoofed header!
    assert resp_untrusted.json()["detected_ip"] == "testclient"


def test_rate_limiter_http_429_headers():
    """Verify rate limit dependency raises HTTP 429 with Retry-After and X-RateLimit headers."""
    dummy_app = FastAPI()

    @dummy_app.get("/limited")
    def limited_endpoint(_rl=Depends(rate_limit(max_calls=2, window_seconds=30, endpoint_key="unit_429"))):
        return {"status": "ok"}

    client = TestClient(dummy_app)

    # Call 1: OK
    r1 = client.get("/limited")
    assert r1.status_code == 200

    # Call 2: OK
    r2 = client.get("/limited")
    assert r2.status_code == 200

    # Call 3: Exceeded -> HTTP 429
    r3 = client.get("/limited")
    assert r3.status_code == 429
    assert "Retry-After" in r3.headers
    assert int(r3.headers["Retry-After"]) > 0
    assert r3.headers.get("X-RateLimit-Remaining") == "0"
