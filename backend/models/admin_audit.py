import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from backend.common.model import Base, id_key


class AdminAudit(Base):
    """An append-only trail of privileged admin actions on an account.

    Written explicitly by the admin user-management handlers (the request-level
    opera-log middleware does not fire for the mounted ``/api/v1`` routes). Keeps
    who did what to whom, with a free-text reason — for accountability when an
    account is suspended, reactivated or credited by hand.
    """

    __tablename__ = 'admin_audit'

    id: Mapped[id_key] = mapped_column(init=False)
    # Non-default columns first (MappedAsDataclass dataclass ordering).
    admin_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey('user.id', ondelete='SET NULL'), index=True,
        comment='Acting admin (kept even if the admin is later deleted)',
    )
    target_user_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey('user.id', ondelete='CASCADE'), index=True,
        comment='Account the action was performed on',
    )
    action: Mapped[str] = mapped_column(sa.String(32), comment='suspend / reactivate / credit_grant')
    note: Mapped[str | None] = mapped_column(sa.String(500), default=None)
