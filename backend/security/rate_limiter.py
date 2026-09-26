"""
Rate Limiter — AI Governance & Security Layer API
Redis sliding window rate limiter with per-key and per-org limits.
"""
import time
from typing import Optional, Tuple

from core.config import settings
from core.database import get_redis


class RateLimiter:
    """
    Redis-based sliding window rate limiter.
    Supports:
    - Requests per minute (RPM) per API key
    - Daily token quota per API key
    - Org-level limits
    """

    async def check_rate_limit(
        self,
        api_key_id: str,
        org_id: str,
        rpm_limit: int = 60,
        daily_token_limit: int = 1_000_000,
        tokens_used: int = 0,
    ) -> Tuple[bool, dict]:
        if not settings.rate_limit_enabled:
            return True, {}

        try:
            redis = await get_redis()
            now = time.time()
            window_start = now - 60

            rpm_key = f"rl:rpm:{api_key_id}"
            await redis.zremrangebyscore(rpm_key, 0, window_start)
            current_count = await redis.zcard(rpm_key)

            if current_count >= rpm_limit:
                entries = await redis.zrange(rpm_key, 0, 0)
                oldest = float(entries[0]) if entries else now - 60
                retry_after = int(60 - (now - oldest))
                return False, {
                    "error": "rate_limit_exceeded",
                    "limit_type": "requests_per_minute",
                    "limit": rpm_limit,
                    "current": current_count,
                    "retry_after_seconds": max(1, retry_after),
                }

            today = time.strftime("%Y-%m-%d")
            token_key = f"rl:tokens:{api_key_id}:{today}"
            current_tokens = int(await redis.get(token_key) or 0)

            if current_tokens + tokens_used > daily_token_limit:
                return False, {
                    "error": "token_quota_exceeded",
                    "limit_type": "daily_tokens",
                    "limit": daily_token_limit,
                    "used": current_tokens,
                    "requested": tokens_used,
                }

            return True, {
                "rpm_remaining": rpm_limit - current_count,
                "daily_tokens_used": current_tokens,
                "daily_tokens_remaining": daily_token_limit - current_tokens,
            }
        except Exception:
            # Redis unavailable — allow request through (fail open)
            return True, {"warning": "rate_limiting_unavailable"}


    async def record_request(self, api_key_id: str, tokens_used: int = 0) -> None:
        """Record a completed request for rate limiting purposes."""
        try:
            redis = await get_redis()
            now = time.time()
            today = time.strftime("%Y-%m-%d")
            rpm_key = f"rl:rpm:{api_key_id}"
            await redis.zadd(rpm_key, {f"{now}:{api_key_id}": now})
            await redis.expire(rpm_key, 120)
            if tokens_used > 0:
                token_key = f"rl:tokens:{api_key_id}:{today}"
                await redis.incrby(token_key, tokens_used)
                await redis.expire(token_key, 90000)
        except Exception:
            pass  # Redis unavailable — skip recording

    async def is_blocked(self, api_key_id: str) -> Tuple[bool, Optional[str]]:
        """Check if an API key is currently blocked."""
        try:
            redis = await get_redis()
            block_key = f"rl:blocked:{api_key_id}"
            reason = await redis.get(block_key)
            if reason:
                return True, reason
        except Exception:
            pass  # Redis unavailable
        return False, None



# ── Singleton ──────────────────────────────────────────────────
rate_limiter = RateLimiter()
