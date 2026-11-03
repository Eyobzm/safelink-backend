import httpx

from .base import EngineResult


class GSBProvider:
    name = "gsb"
    URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(self, client: httpx.AsyncClient, api_key: str):
        self._client, self._key = client, api_key

    async def lookup(self, url: str) -> EngineResult:
        body = {
            "client": {"clientId": "safelink", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANDROID", "ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        r = await self._client.post(self.URL, params={"key": self._key}, json=body, timeout=1.4)
        r.raise_for_status()
        matches = r.json().get("matches")
        return EngineResult(self.name, "flagged" if matches else "clean")
