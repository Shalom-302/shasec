import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.common.enums import ReportFormat
from backend.common.model import Base, get_id, id_key


class Report(Base):
    """A generated audit document (findings + AI analysis), stored in object storage."""

    __tablename__ = 'report'

    id: Mapped[id_key] = mapped_column(init=False)
    x_id: Mapped[str] = mapped_column(sa.String(32), init=False, unique=True, default=get_id)
    scan_id: Mapped[int] = mapped_column(
        sa.ForeignKey('scan.id', ondelete='CASCADE'), index=True, comment='Reported scan'
    )
    format: Mapped[str] = mapped_column(
        sa.String(16), default=ReportFormat.pdf.value, comment='pdf / html / markdown / json'
    )
    location: Mapped[str | None] = mapped_column(
        sa.String(1024), init=False, default=None, comment='Storage object key / path'
    )

    scan: Mapped['Scan'] = relationship(init=False, back_populates='reports', lazy='noload')
