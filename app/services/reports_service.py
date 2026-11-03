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
