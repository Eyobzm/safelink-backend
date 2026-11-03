import hmac
import time
from collections import defaultdict, deque

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..config import settings

_bearer = HTTPBearer(auto_error=False)
_hits: dict[str, deque] = defaultdict(deque)


async def require_client(
    request: Request, cred: HTTPAuthorizationCredentials | None = Depends(_bearer)
) -> str:
    """App-token auth (NFR-SEC-03) + simple per-client rate limit (FR-SCAN-09).
    Upgrade to Play Integrity attestation later."""
    if not cred or not settings.app_token or not hmac.compare_digest(cred.credentials, settings.app_token):
        raise HTTPException(status_code=401, detail={"error": "unauthorized"})
    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    q = _hits[client]
    while q and q[0] < now - 60:
        q.popleft()
    if len(q) >= settings.rate_limit_per_minute:
        raise HTTPException(status_code=429, detail={"error": "rate_limited"})
    q.append(now)
    return client
