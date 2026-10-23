"""Schemas for the admin user-management console (SaaS governance):
account listing with per-user aggregates, risk signals, and the suspend /
reactivate / credit-adjust actions."""
from datetime import datetime

from pydantic import ConfigDict, Field

from backend.common.schema import SchemaBase


class RiskSignal(SchemaBase):
    """One flagged behaviour on an account, with a human explanation."""
    code: str
    label: str
    detail: str
    severity: str = 'low'  # low / medium / high


class AdminUserListItem(SchemaBase):
    id: int
    x_id: str
    email: str
    firstname: str | None = None
    lastname: str | None = None
    status: bool
    is_admin: bool = False
    roles: list[str] = []
    join_time: datetime | None = None
    last_login_time: datetime | None = None
    # Aggregates
    credits: int = 0
    free_scans: int = 0
    scan_count: int = 0
    active_scans: int = 0
    failed_scans: int = 0
    pending_requests: int = 0
    targets_count: int = 0
    # Coarse risk summary (detail via GET /admin/users/{id})
    risk_level: str = 'none'  # none / low / medium / high
    risk_count: int = 0


class AdminUserDetail(AdminUserListItem):
    authorized_targets: int = 0
    active_requests_total: int = 0
    distinct_active_domains: int = 0
    next_expiry: datetime | None = None
    signals: list[RiskSignal] = []


class AdminAuditItem(SchemaBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    admin_id: int | None = None
    target_user_id: int | None = None
    action: str
    note: str | None = None
    created_time: datetime


class SuspendParam(SchemaBase):
    reason: str = Field(min_length=3, max_length=500, description='Why the account is being suspended (shown to the client)')


class ReactivateParam(SchemaBase):
    note: str | None = Field(default=None, max_length=500)


class AdminCreditParam(SchemaBase):
    amount: int = Field(ge=1, le=100000)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)
    note: str | None = Field(default=None, max_length=255)
