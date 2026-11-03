import time

TTL = {"SAFE": 600, "SUSPICIOUS": 120, "DANGEROUS": 1800}


class VerdictCache:
    """In-memory for the pilot. Swap for Redis when running >1 worker. Keys are hashes (NFR-PRIV-02)."""

    def __init__(self):
        self._d: dict[str, tuple[float, dict]] = {}

    def get(self, key: str) -> dict | None:
        item = self._d.get(key)
        if not item or item[0] < time.monotonic():
            self._d.pop(key, None)
            return None
        return item[1]

    def set(self, key: str, value: dict, verdict: str, degraded: bool) -> None:
        ttl = 60 if degraded else TTL.get(verdict, 120)
        self._d[key] = (time.monotonic() + ttl, value)
