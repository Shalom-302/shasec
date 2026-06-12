from datetime import datetime
from typing import List

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.common.enums import ScanStatus
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
        sa.String(16), default=ScanStatus.pending.value, comment='pending / running / completed / failed'
    )
    # Explicit consent to run the active-exploitation stage (sends attack
    # payloads, not just reads). OFF by default — scanning never implies it.
    allow_active_exploitation: Mapped[bool] = mapped_column(
        sa.Boolean, default=False, comment='Consent to run the exploit stage'
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
