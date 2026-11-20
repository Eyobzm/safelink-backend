from sqlalchemy import select

from ..db.models import Report
from ..db.session import SessionLocal
from ..models import ReportRequest
from ..normalize import normalize_url, redact


async def save_report(req: ReportRequest, client_version: str | None = None) -> None:
    async with SessionLocal() as s:
        s.add(
            Report(
                url_redacted=redact(normalize_url(req.url)),
                report_type=req.report_type,
                note=req.note,
                client_version=client_version,
            )
        )
        await s.commit()


def _row(r: Report) -> dict:
    return {
        "id": r.id,
        "url_redacted": r.url_redacted,
        "report_type": r.report_type,
        "note": r.note,
        "status": r.status,
        "created_at": r.created_at.isoformat(),
    }


async def list_reports(status: str | None = None, limit: int = 100) -> list[dict]:
    async with SessionLocal() as s:
        q = select(Report).order_by(Report.created_at.desc()).limit(limit)
        if status:
            q = q.where(Report.status == status)
        rows = (await s.execute(q)).scalars().all()
    return [_row(r) for r in rows]


async def triage_report(report_id: str, status: str) -> dict | None:
    async with SessionLocal() as s:
        row = await s.get(Report, report_id)
        if row is None:
            return None
        row.status = status
        await s.commit()
        await s.refresh(row)
        return _row(row)
