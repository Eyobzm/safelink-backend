from fastapi import APIRouter, Depends

from ..services.rules_service import get_delta
from .deps import require_client

router = APIRouter(prefix="/v1")


@router.get("/rules/delta")
async def rules_delta(since: int = 0, _: str = Depends(require_client)):
    return await get_delta(since)
