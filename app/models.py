from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["SAFE", "SUSPICIOUS", "DANGEROUS"]


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    source_app: str | None = None
    client_version: str = "1.0.0"
    local_flags: list[str] = []


class ScanResponse(BaseModel):
    verdict: Verdict
    score: int
    reasons: list[str]
    message_key: str
    engines: dict[str, str]
    degraded: bool
    latency_ms: int


class ReportRequest(BaseModel):
    url: str = Field(max_length=4096)
    report_type: Literal["false_positive", "missed_threat"]
    note: str | None = Field(default=None, max_length=1000)
