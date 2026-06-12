import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.common.model import Base, get_id, id_key


class AIAnalysis(Base):
    """The AI verdict over a scan's correlated findings.

    Produced by shasec-ai from the normalized findings only — the AI never runs
    a scan. One analysis per scan.
    """

    __tablename__ = 'ai_analysis'

    id: Mapped[id_key] = mapped_column(init=False)
    x_id: Mapped[str] = mapped_column(sa.String(32), init=False, unique=True, default=get_id)
    scan_id: Mapped[int] = mapped_column(
        sa.ForeignKey('scan.id', ondelete='CASCADE'), index=True, unique=True, comment='Analyzed scan'
    )
    score: Mapped[int] = mapped_column(sa.Integer, default=0, comment='Security score 0-100 (higher is safer)')
    summary: Mapped[str | None] = mapped_column(sa.Text, default=None, comment='Executive summary')
    impacts: Mapped[str | None] = mapped_column(sa.Text, default=None)
    recommendations: Mapped[str | None] = mapped_column(sa.Text, default=None)
    provider: Mapped[str | None] = mapped_column(
        sa.String(64), default=None, comment='AI provider that produced this (e.g. ollama)'
    )
    raw: Mapped[dict | None] = mapped_column(sa.JSON, default=None, comment='Raw provider output for audit')

    scan: Mapped['Scan'] = relationship(init=False, back_populates='analysis', lazy='noload')
