import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from backend.common.model import Base, id_key


class Notification(Base):
    """An in-app notification for one account.

    Used for the advanced-audit workflow: admins are notified when a client
    requests an active audit; the client is notified of the approve/reject
    decision. ``link`` is a relative app path the UI can open.
    """

    __tablename__ = 'notification'

    id: Mapped[id_key] = mapped_column(init=False)
    # Non-default columns first (MappedAsDataclass dataclass ordering).
    user_id: Mapped[int] = mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'), index=True)
    title: Mapped[str] = mapped_column(sa.String(255))
    kind: Mapped[str] = mapped_column(sa.String(32), default='info', comment='info / audit_request / audit_decision')
    body: Mapped[str | None] = mapped_column(sa.String(1000), default=None)
    link: Mapped[str | None] = mapped_column(sa.String(255), default=None, comment='Relative app path to open')
    is_read: Mapped[bool] = mapped_column(sa.Boolean, default=False, index=True)
