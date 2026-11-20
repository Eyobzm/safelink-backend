import json
import time

TTL = {"SAFE": 600, "SUSPICIOUS": 120, "DANGEROUS": 1800}


class VerdictCache:
    """Memory cache for one worker. Uses Redis when REDIS_URL is set (multi-worker).

    Keys are URL hashes, never raw URLs (NFR-PRIV-02).
    """

    def __init__(self, redis_url: str = ""):
        self._d: dict[str, tuple[float, dict]] = {}
        self._redis = None
        self._redis_url = redis_url

    async def connect(self) -> None:
        if not self._redis_url:
            return
        import redis.asyncio as aioredis

        self._redis = aioredis.from_url(self._redis_url, decode_responses=True)

    async def aclose(self) -> None:
        if self._redis is not None:
            await self._redis.aclose()

    async def get(self, key: str) -> dict | None:
        if self._redis is not None:
            raw = await self._redis.get(self._rk(key))
            return json.loads(raw) if raw else None
        item = self._d.get(key)
        if not item or item[0] < time.monotonic():
            self._d.pop(key, None)
            return None
        return item[1]

    async def set(self, key: str, value: dict, verdict: str, degraded: bool) -> None:
        ttl = 60 if degraded else TTL.get(verdict, 120)
        if self._redis is not None:
            await self._redis.set(self._rk(key), json.dumps(value), ex=ttl)
            return
        self._d[key] = (time.monotonic() + ttl, value)

    @staticmethod
    def _rk(key: str) -> str:
        return f"safelink:verdict:{key}"
