from datetime import datetime
from typing import List

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.common.enums import TargetType
from backend.common.model import Base, get_id, id_key


class Target(Base):
    """An audit target: a website, API, GraphQL endpoint or host."""

    __tablename__ = 'target'

    id: Mapped[id_key] = mapped_column(init=False)
    x_id: Mapped[str] = mapped_column(sa.String(32), init=False, unique=True, default=get_id)
    name: Mapped[str] = mapped_column(sa.String(255), comment='Human-readable target name')
    url: Mapped[str] = mapped_column(sa.String(2048), comment='Target URL or host')
    type: Mapped[str] = mapped_column(
        sa.String(32), default=TargetType.website.value, comment='website / api / graphql / host'
    )
    # Security guardrail: no scan may start against a target until its owner has
    # explicitly authorized it. This is the seed of the "authorized scope" rule —
    # an audit platform that scans un-vetted targets is a weapon, not a tool.
    is_authorized: Mapped[bool] = mapped_column(
        sa.Boolean, default=False, comment='Owner authorized this target for scanning'
    )

    # Tenant: the account that registered this target. NULL = legacy/admin row,
    # visible to admins only.
    owner_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey('user.id', ondelete='CASCADE'), index=True, default=None, comment='Owner account'
    )
    # Scope attestation: who declared (under the accepted terms of use) that they
    # own the target or hold written permission to test it, when, from where.
    # This is the accountability trail behind is_authorized for self-service accounts.
    authorized_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), init=False, default=None, comment='When scanning was attested'
    )
    authorized_by: Mapped[int | None] = mapped_column(
        sa.ForeignKey('user.id', ondelete='SET NULL'), init=False, default=None, comment='Account that attested'
    )
    authorized_ip: Mapped[str | None] = mapped_column(
        sa.String(64), init=False, default=None, comment='Client IP at attestation'
    )
    terms_version: Mapped[str | None] = mapped_column(
        sa.String(32), init=False, default=None, comment='Terms of use version accepted'
    )

    scans: Mapped[List['Scan']] = relationship(
        init=False, back_populates='target', lazy='noload', cascade='all, delete-orphan'
    )
