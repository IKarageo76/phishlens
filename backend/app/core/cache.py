"""Per-indicator result cache: Redis when REDIS_URL is set, otherwise in-process memory.

Caching is what keeps free-tier quotas usable: the same domain checked twice in a
day costs one API call, not two.
"""

import json
import time
from typing import Any, Protocol


class Cache(Protocol):
    async def get(self, key: str) -> Any | None: ...
    async def set(self, key: str, value: Any, ttl: int) -> None: ...


class MemoryCache:
    def __init__(self, max_items: int = 5000) -> None:
        self._data: dict[str, tuple[float, str]] = {}
        self._max = max_items

    async def get(self, key: str) -> Any | None:
        item = self._data.get(key)
        if not item:
            return None
        expires, payload = item
        if expires < time.time():
            self._data.pop(key, None)
            return None
        return json.loads(payload)

    async def set(self, key: str, value: Any, ttl: int) -> None:
        if len(self._data) >= self._max:
            oldest = min(self._data, key=lambda k: self._data[k][0])
            self._data.pop(oldest, None)
        self._data[key] = (time.time() + ttl, json.dumps(value, default=str))


class RedisCache:
    def __init__(self, url: str) -> None:
        import redis.asyncio as redis  # imported lazily so Redis stays optional

        self._redis = redis.from_url(url, decode_responses=True)

    async def get(self, key: str) -> Any | None:
        try:
            payload = await self._redis.get(f"phishlens:{key}")
        except Exception:  # noqa: BLE001 - a cache outage must not break analysis
            return None
        return json.loads(payload) if payload else None

    async def set(self, key: str, value: Any, ttl: int) -> None:
        try:
            await self._redis.set(f"phishlens:{key}", json.dumps(value, default=str), ex=ttl)
        except Exception:  # noqa: BLE001
            pass


_cache: Cache | None = None


def get_cache(redis_url: str = "") -> Cache:
    global _cache
    if _cache is None:
        _cache = RedisCache(redis_url) if redis_url else MemoryCache()
    return _cache


def reset_cache() -> None:
    """Used by tests."""
    global _cache
    _cache = None
