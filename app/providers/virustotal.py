import base64

import httpx

from .base import EngineResult


class VirusTotalProvider:
    """Looks up an EXISTING report only. Never submits (too slow, burns quota)."""

    name = "vt"

    def __init__(self, client: httpx.AsyncClient, api_key: str):
        self._client, self._key = client, api_key

    async def lookup(self, url: str) -> EngineResult:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = await self._client.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": self._key},
            timeout=1.4,
        )
        if r.status_code == 404:
            return EngineResult(self.name, "unknown")
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        n = int(stats.get("malicious", 0))
        return EngineResult(self.name, "flagged" if n else "clean", detections=n, detail=stats)
