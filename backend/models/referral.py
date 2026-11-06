import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from backend.common.model import Base, id_key


class ReferralCode(Base):
    """A user's personal referral code (created on first visit of the page)."""

    __tablename__ = 'referral_code'

    id: Mapped[id_key] = mapped_column(init=False)
    user_id: Mapped[int] = mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'), unique=True)
    code: Mapped[str] = mapped_column(sa.String(16), unique=True, index=True)


class Referral(Base):
    """Who referred whom. One referrer per account, set once (sign-up link or
    code typed at first checkout), never changed afterwards."""

    __tablename__ = 'referral'

    id: Mapped[id_key] = mapped_column(init=False)
    referee_id: Mapped[int] = mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'), unique=True)
    referrer_id: Mapped[int] = mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'), index=True)
    code: Mapped[str] = mapped_column(sa.String(16))
