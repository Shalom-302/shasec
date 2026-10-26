from datetime import datetime

from pydantic import ConfigDict, EmailStr, Field

from backend.common.schema import SchemaBase


class ScanPricing(SchemaBase):
    fast: int
    standard: int
    deep: int
    free_profiles: list[str]


class GetCreditBalance(SchemaBase):
    credits: int
    free_scans: int
    next_expiry: datetime | None = None
    is_admin: bool = False
    pricing: ScanPricing


class GetCreditGrant(SchemaBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    amount: int
    remaining: int
    kind: str
    source: str
    expires_at: datetime | None = None
    note: str | None = None
    created_time: datetime


class GetCreditTransaction(SchemaBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    delta: int
    kind: str
    reason: str
    scan_id: int | None = None
    note: str | None = None
    created_time: datetime


class RedeemCodeParam(SchemaBase):
    code: str = Field(min_length=4, max_length=40)


class CreateVouchersParam(SchemaBase):
    count: int = Field(default=1, ge=1, le=500, description='How many distinct codes to generate')
    credits: int = Field(ge=1, le=100000, description='Credits granted per redemption')
    max_redemptions: int = Field(default=1, ge=1, le=100000, description='Total uses allowed per code')
    valid_until: datetime | None = Field(default=None, description='Code unusable after this date')
    credit_validity_days: int | None = Field(
        default=None, ge=1, le=3650, description='Granted credits expire N days after redemption'
    )
    note: str | None = Field(default=None, max_length=255)


class DisableVouchersParam(SchemaBase):
    ids: list[int] = Field(min_length=1, max_length=500, description='Credit codes to disable')


class GetVoucher(SchemaBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    code: str
    credits: int
    max_redemptions: int
    redemption_count: int
    valid_until: datetime | None = None
    credit_validity_days: int | None = None
    is_active: bool
    note: str | None = None
    created_time: datetime


class AdminGrantParam(SchemaBase):
    email: EmailStr
    credits: int = Field(ge=1, le=100000)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)
    note: str | None = Field(default=None, max_length=255)
