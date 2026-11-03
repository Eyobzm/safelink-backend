import base64

from sqlalchemy import select

from ..db.models import RuleVersion
from ..db.session import SessionLocal


async def get_delta(since: int) -> dict:
    """Return the latest signed package if newer than the client's version.
    Pilot simplification: one full package per version."""
    async with SessionLocal() as s:
        row = (
            await s.execute(select(RuleVersion).order_by(RuleVersion.version.desc()).limit(1))
        ).scalar_one_or_none()
    if row is None or row.version <= since:
        return {"version": since, "package": None, "signature": None}
    return {
        "version": row.version,
        "package": base64.b64encode(row.package).decode(),
        "signature": base64.b64encode(row.signature).decode(),
    }
