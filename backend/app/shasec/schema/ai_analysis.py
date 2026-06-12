from typing import Any

from pydantic import ConfigDict

from backend.common.schema import SchemaBase


class CreateAIAnalysisParam(SchemaBase):
    scan_id: int
    score: int = 0
    summary: str | None = None
    impacts: str | None = None
    recommendations: str | None = None
    provider: str | None = None
    raw: dict[str, Any] | None = None


class GetAIAnalysisDetails(SchemaBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    x_id: str
    scan_id: int
    score: int
    summary: str | None = None
    impacts: str | None = None
    recommendations: str | None = None
    provider: str | None = None
