from datetime import datetime

from pydantic import ConfigDict

from backend.common.enums import ScanStatus, TargetType
from backend.common.schema import SchemaBase


class CreateScanParam(SchemaBase):
    target_id: int
    # Explicit consent to run the active-exploitation stage (default OFF).
    allow_active_exploitation: bool = False


class QuickScanParam(SchemaBase):
    """One-shot scan straight from a URL (target is created/reused behind it)."""

    url: str
    type: TargetType = TargetType.api
    name: str | None = None
    allow_active_exploitation: bool = False
    # Optional bearer token (without the "Bearer " prefix) to drive authenticated
    # exploit modules (JWT tampering, BFLA). Never stored — used transiently.
    auth_token: str | None = None


class GetScanDetails(SchemaBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    x_id: str
    target_id: int
    status: ScanStatus
    allow_active_exploitation: bool = False
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    created_time: datetime
    updated_time: datetime | None = None
