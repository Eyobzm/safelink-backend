import base64

import httpx

from .base import EngineResult


class PhishTankProvider:
    """Behind the Provider interface so another feed can replace it (SRS 13.2 #5)."""

    name = "phishtank"

    def __init__(self, client: httpx.AsyncClient, api_key: str):
        self._client, self._key = client, api_key

    async def lookup(self, url: str) -> EngineResult:
        r = await self._client.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": base64.b64encode(url.encode()).decode(), "format": "json", "app_key": self._key},
            headers={"User-Agent": "phishtank/safelink"},
            timeout=1.4,
        )
        r.raise_for_status()
        res = r.json().get("results", {})
        if not res.get("in_database"):
            return EngineResult(self.name, "clean")
        if res.get("verified") and res.get("valid"):
            return EngineResult(self.name, "flagged")
        return EngineResult(self.name, "unverified")
