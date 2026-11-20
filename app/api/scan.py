import asyncio

from fastapi import APIRouter, Depends, Request

from ..db.models import ScanEnrichment
from ..db.session import SessionLocal
from ..models import ScanRequest, ScanResponse
from ..normalize import normalize_url, outbound_url, url_hash
from ..pipeline import run_scan
from ..scoring import ScanInput, decide, message_key
from .deps import require_client

router = APIRouter(prefix="/v1")


@router.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest, request: Request, _: str = Depends(require_client)):
    st = request.app.state
    normalized = normalize_url(req.url)
    key = url_hash(normalized)

    cached = await st.cache.get(key)
    if cached:
        return cached

    out = outbound_url(normalized)  # query/fragment never leave our server
    data = await run_scan(out, st.providers, st.redirects, st.settings.internal_deadline_s)
    r = data["results"]

    decision = decide(
        ScanInput(
            local_flags=req.local_flags,
            gsb=r["gsb"].status,
            vt_status=r["vt"].status,
            vt_detections=r["vt"].detections,
            phishtank=r["phishtank"].status,
            urlscan=r["urlscan"].status,
            redirect_hops=data["redirect_hops"],
        )
    )

    # URLScan runs as async enrichment, outside the deadline (private only).
    asyncio.create_task(_safe_submit(st.urlscan, out))

    resp = ScanResponse(
        verdict=decision.verdict,
        score=decision.score,
        reasons=decision.reasons,
        message_key=message_key(decision),
        engines={n: x.status for n, x in r.items()},
        degraded=decision.degraded,
        latency_ms=data["latency_ms"],
    )
    await st.cache.set(key, resp.model_dump(), decision.verdict, decision.degraded)
    return resp


async def _safe_submit(urlscan, url: str) -> None:
    try:
        uuid = await urlscan.submit(url)
        if not uuid:
            return
        async with SessionLocal() as s:
            await s.merge(ScanEnrichment(url_hash=url_hash(url), urlscan_uuid=uuid))
            await s.commit()
    except Exception:
        pass  # enrichment is best-effort
