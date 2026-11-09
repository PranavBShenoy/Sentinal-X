"""
SENTINEL-X Shared Redis-Backed Rate Limiter.

Provides atomic, multi-worker sliding-window rate limiting for FastAPI.
Enforces shared state across independent worker processes, threads, and container instances.

Key Security Properties:
1. Multi-worker state: Backed by Redis Sorted Sets (ZSET).
2. Atomicity: Evaluated via Lua script to prevent race conditions during high concurrent load.
3. Memory bounding: Every key has an automatic sliding TTL expiration to prevent memory leaks.
4. Client IP verification: Validates direct peer IP against TRUSTED_PROXIES before trusting X-Forwarded-For.
5. Account-based & IP-based rate limiting: Supports rate limiting by IP, user ID, or combined identifier.
6. Fail-safe policy: Degraded state is tracked and surfaced through operational /health reporting.
"""
from __future__ import annotations

import collections
import time
import uuid
from typing import Callable, Dict, List, Optional, Tuple

import redis
from fastapi import HTTPException, Request, status

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

# Atomic Sliding-Window Lua Script for Redis
SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local max_calls = tonumber(ARGV[3])
local member_id = ARGV[4]

-- Remove timestamps outside the sliding window
local clear_before = now - window
redis.call('ZREMRANGEBYSCORE', key, 0, clear_before)

-- Count requests currently in window
local current_count = redis.call('ZCARD', key)

if current_count < max_calls then
    -- Under limit: add current timestamp and refresh expiration
    redis.call('ZADD', key, now, member_id)
    redis.call('EXPIRE', key, math.ceil(window + 15))
    local remaining = max_calls - current_count - 1
    return {1, remaining, math.ceil(window)}
else
    -- Over limit: find oldest timestamp in window to compute precise retry_after
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_after = math.ceil(window)
    if #oldest >= 2 then
        local oldest_ts = tonumber(oldest[2])
        retry_after = math.max(1, math.ceil(oldest_ts + window - now))
    end
    return {0, 0, retry_after}
end
"""


class RedisRateLimiter:
    """
    Atomic multi-worker rate limiter backed by Redis.
    """

    def __init__(self, redis_url: Optional[str] = None) -> None:
        self.raw_url = redis_url or settings.REDIS_URL
        self._redis_client: Optional[redis.Redis] = None
        self._lua_sha: Optional[str] = None
        self._degraded_mode: bool = False
        self._degraded_reason: Optional[str] = None
        # Emergency in-memory fallback for development resilience
        self._memory_fallback: Dict[str, List[float]] = collections.defaultdict(list)
        self._init_client()

    def _init_client(self) -> None:
        """Initialize Redis connection with URL scheme normalization."""
        try:
            url = self.raw_url
            if url.startswith("redis+socket://"):
                # Convert kombu/celery socket scheme to redis-py unix:// format
                path = url.replace("redis+socket://", "").split("?")[0]
                url = f"unix://{path}"

            self._redis_client = redis.Redis.from_url(
                url,
                socket_timeout=1.5,
                socket_connect_timeout=1.5,
                decode_responses=False,
            )
            # Ping to verify connectivity
            self._redis_client.ping()
            self._degraded_mode = False
            self._degraded_reason = None
            logger.info("Connected to shared Redis rate-limiting backend", url=url)
        except Exception as e:
            self._degraded_mode = True
            self._degraded_reason = f"Cannot connect to Redis at {self.raw_url}: {str(e)}"
            if settings.APP_ENV == "production":
                logger.critical("PRODUCTION ALERT: Redis rate limiter unavailable", error=str(e))
            else:
                logger.warning("Redis unavailable for rate limiting, running in degraded mode", error=str(e))

    @property
    def is_healthy(self) -> bool:
        """Check if Redis connection is live."""
        if self._degraded_mode or self._redis_client is None:
            return False
        try:
            return bool(self._redis_client.ping())
        except Exception:
            self._degraded_mode = True
            return False

    def get_status(self) -> Dict[str, Any]:
        """Report operational state for /health endpoint."""
        healthy = self.is_healthy
        return {
            "status": "healthy" if healthy else "degraded",
            "backend": "redis" if healthy else "emergency_memory",
            "degraded": not healthy,
            "reason": None if healthy else self._degraded_reason,
        }

    def get_client_ip(self, request: Request) -> str:
        """
        Extract authenticated client IP address.

        Security enforcement:
        - NEVER blindly trust X-Forwarded-For unless the direct peer IP
          is explicitly present in TRUSTED_PROXIES.
        """
        direct_peer = request.client.host if request.client else "127.0.0.1"

        trusted_proxies = set(settings.trusted_proxies_list)

        # If direct peer is not in trusted proxies, ignore X-Forwarded-For to prevent spoofing
        if direct_peer not in trusted_proxies:
            return direct_peer

        # Peer is a trusted reverse proxy (e.g. local Nginx). Parse X-Forwarded-For
        xff = request.headers.get("X-Forwarded-For")
        if not xff:
            return direct_peer

        # Pick the client IP (first entry in comma-separated list)
        client_candidate = xff.split(",")[0].strip()
        return client_candidate or direct_peer

    def is_allowed(
        self,
        identifier: str,
        endpoint_key: str,
        max_calls: int,
        window_seconds: int = 60,
    ) -> Tuple[bool, int, int]:
        """
        Check whether request is allowed under the sliding window.

        Returns:
            (allowed: bool, remaining_calls: int, retry_after_seconds: int)
        """
        if not settings.RATE_LIMIT_ENABLED:
            return True, max_calls, 0

        redis_key = f"sentinelx:ratelimit:{endpoint_key}:{identifier}"
        now = time.time()
        member_id = f"{now}:{uuid.uuid4().hex[:8]}"

        # Attempt Redis atomic execution first
        if not self._degraded_mode and self._redis_client is not None:
            try:
                res = self._redis_client.eval(
                    SLIDING_WINDOW_LUA,
                    1,
                    redis_key,
                    now,
                    window_seconds,
                    max_calls,
                    member_id,
                )
                allowed = bool(res[0])
                remaining = int(res[1])
                retry_after = int(res[2])
                return allowed, remaining, retry_after
            except (redis.ConnectionError, redis.TimeoutError) as e:
                self._degraded_mode = True
                self._degraded_reason = f"Redis connection lost during rate limit eval: {str(e)}"
                logger.error("Redis rate limit eval failed, activating fail-safe", error=str(e))

        # FAIL-SAFE POLICY:
        # In production: Fail-closed on auth endpoints to prevent credential stuffing
        if settings.APP_ENV == "production" and endpoint_key in ("login", "register"):
            logger.critical("Production auth request blocked due to rate limiter unavailability")
            return False, 0, window_seconds

        # In non-production or general endpoints: use local memory sliding window
        return self._evaluate_memory_fallback(redis_key, now, window_seconds, max_calls)

    def _evaluate_memory_fallback(
        self,
        key: str,
        now: float,
        window_seconds: int,
        max_calls: int,
    ) -> Tuple[bool, int, int]:
        """Sliding-window fallback for local development or degraded status."""
        cutoff = now - window_seconds
        calls = self._memory_fallback[key]
        calls[:] = [t for t in calls if t > cutoff]

        if len(calls) < max_calls:
            calls.append(now)
            remaining = max_calls - len(calls)
            return True, remaining, window_seconds

        oldest = calls[0] if calls else now
        retry_after = max(1, int(oldest + window_seconds - now))
        return False, 0, retry_after

    def reset(self, identifier: str, endpoint_key: str) -> None:
        """Reset rate limit counter for a specific identifier."""
        redis_key = f"sentinelx:ratelimit:{endpoint_key}:{identifier}"
        if not self._degraded_mode and self._redis_client is not None:
            try:
                self._redis_client.delete(redis_key)
            except Exception:
                pass
        self._memory_fallback.pop(redis_key, None)


# Singleton rate limiter instance
limiter = RedisRateLimiter()


def rate_limit(
    max_calls: int = 10,
    window_seconds: int = 60,
    endpoint_key: str = "default",
    use_account: bool = False,
) -> Callable[[Request], None]:
    """
    FastAPI dependency enforcing shared Redis rate limiting.

    Usage:
        @router.post("/login")
        def login(..., _rl=Depends(rate_limit(max_calls=10, endpoint_key="login"))):
    """
    def _dependency(request: Request) -> None:
        ip = limiter.get_client_ip(request)
        identifier = ip

        if use_account:
            # If user is authenticated, attach user ID to identifier
            user_id = getattr(request.state, "user_id", None)
            if user_id:
                identifier = f"{user_id}:{ip}"

        allowed, remaining, retry_after = limiter.is_allowed(
            identifier=identifier,
            endpoint_key=endpoint_key,
            max_calls=max_calls,
            window_seconds=window_seconds,
        )

        if not allowed:
            logger.warning(
                "Rate limit exceeded",
                endpoint=endpoint_key,
                identifier=identifier,
                retry_after=retry_after,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many requests for endpoint '{endpoint_key}'. Please slow down.",
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(max_calls),
                    "X-RateLimit-Remaining": str(remaining),
                    "X-RateLimit-Reset": str(retry_after),
                },
            )

    return _dependency
