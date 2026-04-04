"""
app/core/cache.py
Redis client wrapper with JSON serialization helpers.
"""
import json
import redis.asyncio as aioredis
from app.core.config import get_settings

settings = get_settings()

_redis: aioredis.Redis | None = None


def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            decode_responses=True,
        )
    return _redis


async def cache_get(key: str) -> dict | list | None:
    try:
        r = get_redis()
        raw = await r.get(key)
        if raw is None:
            return None
        return json.loads(raw)
    except Exception as e:
        # Fallback cleanly if Redis is down
        return None


async def cache_set(key: str, value: dict | list, ttl: int | None = None) -> None:
    try:
        r = get_redis()
        ttl = ttl or settings.CACHE_TTL_SECONDS
        await r.setex(key, ttl, json.dumps(value))
    except Exception:
        pass


async def cache_delete(key: str) -> None:
    try:
        r = get_redis()
        await r.delete(key)
    except Exception:
        pass


# Cache key constants
CACHE_CITY_MAP = "aegis:city_map"
CACHE_HEATMAP = "aegis:heatmap"
CACHE_ANOMALIES = "aegis:anomalies"
CACHE_SCHEMA_ACTIVE = "aegis:schema_active"
CACHE_THREAT_SCORE = "aegis:threat_score"