import asyncio

from app.pipeline import run_scan
from app.providers.base import EngineResult


class Fast:
    def __init__(self, name, status="clean", detections=0):
        self.name, self._s, self._d = name, status, detections

    async def lookup(self, url):
        return EngineResult(self.name, self._s, self._d)


class Slow:
    name = "slow"

    async def lookup(self, url):
        await asyncio.sleep(5)
        return EngineResult("slow", "clean")


class Broken:
    name = "broken"

    async def lookup(self, url):
        raise RuntimeError("boom")


class NoRedirect:
    async def resolve(self, url):
        from app.providers.redirects import RedirectResult
        return RedirectResult(0, url)


async def test_timeout_and_error_do_not_fail_scan():
    out = await run_scan("https://a.com", [Fast("gsb"), Slow(), Broken()], NoRedirect(), deadline=0.2)
    assert out["results"]["gsb"].status == "clean"
    assert out["results"]["slow"].status == "timeout"
    assert out["results"]["broken"].status == "error"
    assert out["latency_ms"] < 1000
