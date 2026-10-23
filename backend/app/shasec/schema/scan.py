from datetime import datetime

from pydantic import ConfigDict

from backend.common.enums import ExploitAggression, ScanBilling, ScanProfile, ScanStatus, TargetType
from backend.common.schema import SchemaBase


class CreateScanParam(SchemaBase):
    target_id: int
    # Explicit consent to run the active-exploitation stage (default OFF).
    allow_active_exploitation: bool = False
    # Depth/speed profile — controls which plugin tiers run (default standard).
    profile: ScanProfile = ScanProfile.standard


class QuickScanParam(SchemaBase):
    """One-shot scan straight from a URL (target is created/reused behind it)."""

    url: str
    type: TargetType = TargetType.api
    name: str | None = None
    allow_active_exploitation: bool = False
    # fast = quick recon only, standard = default, deep = full heavy tooling.
    profile: ScanProfile = ScanProfile.standard
    # How hard the exploit stage probes (only applies when active exploitation is
    # consented). 'aggressive' widens bounded coverage; never destructive.
    aggression: ExploitAggression = ExploitAggression.safe
    # Optional bearer token (without the "Bearer " prefix) to drive authenticated
    # exploit modules (JWT tampering, BFLA). Never stored — used transiently.
    auth_token: str | None = None
    # BOLA/IDOR object-id iteration range, e.g. "1-10". Transient, never stored.
    id_range: str | None = None
    # Explicit opt-in to actually send write verbs (PUT/PATCH/DELETE) in verb
    # tampering. OFF by default (OPTIONS-first). PROD DANGER — leave false on
    # production. Transient, never stored.
    allow_destructive: bool = False


class GetScanDetails(SchemaBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    x_id: str
    target_id: int
    status: ScanStatus
    profile: ScanProfile = ScanProfile.standard
    allow_active_exploitation: bool = False
    owner_id: int | None = None
    billing: ScanBilling = ScanBilling.admin
    credits_charged: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    created_time: datetime
    updated_time: datetime | None = None
