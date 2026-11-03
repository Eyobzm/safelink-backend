"""Evidence for AC-05: URLScan submissions are always private."""
import httpx
import pytest
import respx

from app.providers.urlscan import URLScanProvider


def test_payload_is_private():
    assert URLScanProvider.build_payload("https://a.com")["visibility"] == "private"


@pytest.mark.asyncio
async def test_non_private_payload_is_rejected():
    async with httpx.AsyncClient() as c:
        p = URLScanProvider(c, "k")
        with pytest.raises(RuntimeError):
            await p._post({"url": "https://a.com", "visibility": "public"})
        with pytest.raises(RuntimeError):
            await p._post({"url": "https://a.com"})


@pytest.mark.asyncio
@respx.mock
async def test_submit_sends_private():
    route = respx.post(URLScanProvider.URL).mock(return_value=httpx.Response(200, json={}))
    async with httpx.AsyncClient() as c:
        await URLScanProvider(c, "k").submit("https://a.com/x")
    assert b'"visibility":"private"' in route.calls[0].request.content.replace(b" ", b"")
