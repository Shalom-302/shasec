from datetime import datetime

from pydantic import ConfigDict, Field

from backend.common.enums import FindingSeverity
from backend.common.schema import SchemaBase


class FindingSchemaBase(SchemaBase):
    plugin: str
    title: str
    severity: FindingSeverity = Field(default=FindingSeverity.info)
    description: str | None = None
    evidence: str | None = None
    recommendation: str | None = None


class CreateFindingParam(FindingSchemaBase):
    """Used by plugins/aggregator to persist a normalized finding."""

    scan_id: int


class GetFindingDetails(FindingSchemaBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    x_id: str
    scan_id: int
    fingerprint: str | None = None
    created_time: datetime
