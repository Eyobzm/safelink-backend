from dataclasses import dataclass
from typing import Literal, Protocol

Status = Literal["clean", "flagged", "unverified", "unknown", "timeout", "error"]


@dataclass
class EngineResult:
    name: str
    status: Status
    detections: int = 0
    detail: dict | None = None


class Provider(Protocol):
    name: str

    async def lookup(self, url: str) -> EngineResult: ...
