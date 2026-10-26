from datetime import datetime
from typing import List

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.common.enums import ScanBilling, ScanMode, ScanProfile, ScanStatus
from backend.common.model import Base, get_id, id_key


class Scan(Base):
    """A security audit run against a single target.

    ``status`` is the single source of truth for the scan lifecycle
    (pending -> running -> completed | failed). Every transition is owned by the
    orchestrator (shasec-core) and broadcast over WebSocket.
    """

    __tablename__ = 'scan'

    id: Mapped[id_key] = mapped_column(init=False)
    x_id: Mapped[str] = mapped_column(sa.String(32), init=False, unique=True, default=get_id)
    target_id: Mapped[int] = mapped_column(
        sa.ForeignKey('target.id', ondelete='CASCADE'), index=True, comment='Audited target'
    )
    status: Mapped[str] = mapped_column(
        sa.String(32), default=ScanStatus.pending.value, comment='pending / awaiting_approval / awaiting_scope / queued / running / completed / failed'
    )
    # Depth/speed profile (methodology §3 staged hunt). Controls which plugin
    # tiers run and the scanner-stage wall-clock budget.
    profile: Mapped[str] = mapped_column(
        sa.String(16), default=ScanProfile.standard.value, comment='fast / standard / deep'
    )
    # single URL, or a whole-domain audit run in the five-step hunt (ScanMode).
    mode: Mapped[str] = mapped_column(
        sa.String(16), default=ScanMode.single.value, server_default=ScanMode.single.value, comment='single / audit'
    )
    # Explicit consent to run the active-exploitation stage (sends attack
    # payloads, not just reads). OFF by default — scanning never implies it.
    allow_active_exploitation: Mapped[bool] = mapped_column(
        sa.Boolean, default=False, comment='Consent to run the exploit stage'
    )
    owner_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey('user.id', ondelete='CASCADE'), index=True, default=None, comment='Owner account'
    )
    # How the scan was paid for (free discovery / credits / admin). Free scans
    # show results but do not unlock detailed reports.
    billing: Mapped[str] = mapped_column(
        sa.String(16), default=ScanBilling.admin.value, comment='free / credits / admin'
    )
    credits_charged: Mapped[int] = mapped_column(
        sa.Integer, default=0, comment='Credits debited for this scan'
    )
    # Advanced (active) audit approval trail. A client submits a request with a
    # scope note; an admin approves (-> queued) or rejects (-> failed + refund).
    scope_note: Mapped[str | None] = mapped_column(
        sa.String(2000), init=False, default=None, comment='Client scope/justification for an advanced audit'
    )
    reviewed_by: Mapped[int | None] = mapped_column(
        sa.ForeignKey('user.id', ondelete='SET NULL'), init=False, default=None, comment='Admin who reviewed the request'
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), init=False, default=None
    )
    review_note: Mapped[str | None] = mapped_column(
        sa.String(1000), init=False, default=None, comment='Admin decision note (e.g. rejection reason)'
    )
    started_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), init=False, default=None
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), init=False, default=None
    )
    error: Mapped[str | None] = mapped_column(
        sa.Text, init=False, default=None, comment='Failure reason when status=failed'
    )

    target: Mapped['Target'] = relationship(init=False, back_populates='scans', lazy='noload')
    findings: Mapped[List['Finding']] = relationship(
        init=False, back_populates='scan', lazy='noload', cascade='all, delete-orphan'
    )
    analysis: Mapped['AIAnalysis | None'] = relationship(
        init=False, back_populates='scan', lazy='noload', uselist=False, cascade='all, delete-orphan'
    )
    reports: Mapped[List['Report']] = relationship(
        init=False, back_populates='scan', lazy='noload', cascade='all, delete-orphan'
    )
    exploits: Mapped[List['Exploit']] = relationship(
        init=False, back_populates='scan', lazy='noload', cascade='all, delete-orphan'
    )
