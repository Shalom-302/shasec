from datetime import datetime

from pydantic import ConfigDict, Field

from backend.common.enums import ReportFormat
from backend.common.schema import SchemaBase


class CreateReportParam(SchemaBase):
    scan_id: int
    format: ReportFormat = Field(default=ReportFormat.pdf)


class GetReportDetails(SchemaBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    x_id: str
    scan_id: int
    format: ReportFormat
    location: str | None = None
    created_time: datetime
