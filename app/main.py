import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .api import admin, report, rules, scan
from .config import settings
from .db.session import init_db
from .logging_filter import RedactQueryFilter
from .providers.gsb import GSBProvider
from .providers.phishtank import PhishTankProvider
from .providers.redirects import RedirectResolver
from .providers.urlscan import URLScanProvider
from .providers.virustotal import VirusTotalProvider
from .services.cache import VerdictCache


@asynccontextmanager
async def lifespan(app: FastAPI):
    for name in ("", "httpx", "uvicorn.access"):
        logging.getLogger(name).addFilter(RedactQueryFilter())
    logging.getLogger("httpx").setLevel(logging.WARNING)  # API keys can appear in URLs

    await init_db()
    client = httpx.AsyncClient()  # one shared client (connection pooling)
    app.state.settings = settings
    app.state.cache = VerdictCache(settings.redis_url)
    await app.state.cache.connect()
    app.state.urlscan = URLScanProvider(client, settings.urlscan_api_key)
    app.state.providers = [
        GSBProvider(client, settings.gsb_api_key),
        VirusTotalProvider(client, settings.vt_api_key),
        PhishTankProvider(client, settings.phishtank_api_key),
        app.state.urlscan,
    ]
    app.state.redirects = RedirectResolver(client)
    yield
    await app.state.cache.aclose()
    await client.aclose()


app = FastAPI(title="SafeLink Backend", version="0.1.0", lifespan=lifespan)
app.include_router(scan.router)
app.include_router(report.router)
app.include_router(rules.router)
app.include_router(admin.router)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.exception_handler(HTTPException)
async def http_error(_: Request, exc: HTTPException):
    detail = exc.detail if isinstance(exc.detail, dict) else {"error": str(exc.detail)}
    return JSONResponse(status_code=exc.status_code, content=detail)  # structured errors (SRS 6.4)
