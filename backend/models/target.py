from typing import List

import secrets
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.common.enums import TargetType
from backend.common.model import Base, get_id, id_key


def new_verify_token() -> str:
    return f'kortex-verify={secrets.token_urlsafe(24)}'


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
    # Ownership proof: the owner serves this token at settings.TARGET_VERIFY_PATH
    # on the target host. A successful check is what flips is_authorized for a
    # non-admin — owning the account is not owning the domain.
    verify_token: Mapped[str] = mapped_column(
        sa.String(64), init=False, default_factory=new_verify_token, comment='Ownership proof token'
    )
    verified_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), init=False, default=None, comment='Last successful ownership proof'
    )

    scans: Mapped[List['Scan']] = relationship(
        init=False, back_populates='target', lazy='noload', cascade='all, delete-orphan'
    )
