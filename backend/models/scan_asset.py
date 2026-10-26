import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from backend.common.model import Base, id_key


class ScanAsset(Base):
    """A host discovered by a domain audit's cartography step (step 1).

    The cartography only *maps* (passive sources + DNS + one light HTTP probe).
    Nothing is attacked until the operator ticks ``selected`` on the hosts that
    are really in scope — a sub-domain CNAME'd to a third-party SaaS is flagged
    and never pre-selected, because it belongs to someone else.
    """

    __tablename__ = 'scan_asset'

    id: Mapped[id_key] = mapped_column(init=False)
    scan_id: Mapped[int] = mapped_column(
        sa.ForeignKey('scan.id', ondelete='CASCADE'), index=True, comment='Owning audit'
    )
    host: Mapped[str] = mapped_column(sa.String(255), comment='FQDN')
    source: Mapped[str] = mapped_column(sa.String(32), default='root', comment='root / subfinder / crt.sh / wordlist')
    url: Mapped[str | None] = mapped_column(sa.String(512), default=None, comment='Base URL that answered')
    ips: Mapped[str | None] = mapped_column(sa.String(255), default=None, comment='Resolved addresses, comma-separated')
    cname: Mapped[str | None] = mapped_column(sa.String(255), default=None)
    third_party: Mapped[str | None] = mapped_column(
        sa.String(64), default=None, comment='SaaS provider the host is delegated to (not ours to attack)'
    )
    alive: Mapped[bool] = mapped_column(sa.Boolean, default=False, comment='Answered over HTTP(S)')
    http_status: Mapped[int | None] = mapped_column(sa.Integer, default=None)
    title: Mapped[str | None] = mapped_column(sa.String(255), default=None)
    server: Mapped[str | None] = mapped_column(sa.String(255), default=None)
    kind: Mapped[str] = mapped_column(sa.String(16), default='website', comment='website / api')
    selected: Mapped[bool] = mapped_column(sa.Boolean, default=False, comment='In scope for steps 2-4')
