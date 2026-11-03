import httpx

from .base import EngineResult


class URLScanProvider:
    """All URLScan traffic goes through _post(): visibility must be 'private' (C-02, FR-SCAN-05)."""

    name = "urlscan"
    URL = "https://urlscan.io/api/v1/scan/"

    def __init__(self, client: httpx.AsyncClient, api_key: str):
        self._client, self._key = client, api_key

    @staticmethod
    def build_payload(url: str) -> dict:
        return {"url": url, "visibility": "private"}

    async def _post(self, payload: dict) -> httpx.Response:
        if payload.get("visibility") != "private":
            raise RuntimeError("URLScan submission must be private")
        return await self._client.post(self.URL, headers={"API-Key": self._key}, json=payload, timeout=5)

    async def submit(self, url: str) -> None:
        """Run as a background task, outside the verdict deadline."""
        await self._post(self.build_payload(url))

    async def lookup(self, url: str) -> EngineResult:
        # First-pass verdict does not wait for URLScan (SRS 13.2 #4).
        return EngineResult(self.name, "unknown")
