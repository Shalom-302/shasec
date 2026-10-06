import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.common.enums import FindingConfidence, FindingSeverity, FindingStatus
from backend.common.model import Base, get_id, id_key


class Finding(Base):
    """A normalized vulnerability.

    Every plugin (nmap, nuclei, zap, ...) translates its native output into this
    single shape, so the aggregator, the AI and the report engine never need to
    know which scanner produced a finding.
    """

    __tablename__ = 'finding'

    id: Mapped[id_key] = mapped_column(init=False)
    x_id: Mapped[str] = mapped_column(sa.String(32), init=False, unique=True, default=get_id)
    scan_id: Mapped[int] = mapped_column(
        sa.ForeignKey('scan.id', ondelete='CASCADE'), index=True, comment='Owning scan'
    )
    plugin: Mapped[str] = mapped_column(sa.String(64), comment='Source plugin (nmap, nuclei, ...)')
    title: Mapped[str] = mapped_column(sa.String(512))
    severity: Mapped[str] = mapped_column(
        sa.String(16), default=FindingSeverity.info.value, comment='critical / high / medium / low / info'
    )
    # Methodology §14 — a finding is an *observation* until proven. It enters
    # ``suspected`` with ``low`` confidence; a proof (Exploit row) promotes it.
    # Forcing an agent to set these keeps "observed" distinct from "potential".
    confidence: Mapped[str] = mapped_column(
        sa.String(16), default=FindingConfidence.low.value, comment='low / medium / high'
    )
    status: Mapped[str] = mapped_column(
        sa.String(32),
        default=FindingStatus.suspected.value,
        comment='suspected / confirmed / false_positive / stopped / fixed / retest_required',
    )
    description: Mapped[str | None] = mapped_column(sa.Text, default=None)
    evidence: Mapped[str | None] = mapped_column(sa.Text, default=None)
    recommendation: Mapped[str | None] = mapped_column(sa.Text, default=None)
    # Deterministic, scanner-agnostic correlation key. Two plugins reporting the
    # same vulnerability share a fingerprint, so the aggregator can dedupe them
    # into a single finding (criticality = max). Computed by the aggregator.
    fingerprint: Mapped[str | None] = mapped_column(sa.String(64), init=False, default=None, index=True)

    scan: Mapped['Scan'] = relationship(init=False, back_populates='findings', lazy='noload')
