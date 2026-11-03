from fastapi import APIRouter, Depends

from ..models import ReportRequest
from ..services.reports_service import save_report
from .deps import require_client

router = APIRouter(prefix="/v1")


@router.post("/report", status_code=202)
async def report(req: ReportRequest, _: str = Depends(require_client)):
    await save_report(req)
    return {"status": "accepted"}
