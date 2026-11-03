import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx


@dataclass
class RedirectResult:
    hops: int
    final_url: str


async def _is_public_host(host: str) -> bool:
    """SSRF guard: reject private/loopback/link-local targets on EVERY hop.
    Note: DNS rebinding is not fully covered; pin resolved IPs for production."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return True


class RedirectResolver:
    MAX_HOPS = 5

    def __init__(self, client: httpx.AsyncClient):
        self._client = client

    async def resolve(self, url: str) -> RedirectResult:
        hops, current = 0, url
        while hops < self.MAX_HOPS:
            host = urlsplit(current).hostname or ""
            if not await _is_public_host(host):
                break
            r = await self._client.head(current, follow_redirects=False, timeout=0.6)
            loc = r.headers.get("location")
            if r.status_code in (301, 302, 303, 307, 308) and loc:
                current = urljoin(current, loc)
                hops += 1
            else:
                break
        return RedirectResult(hops, current)
