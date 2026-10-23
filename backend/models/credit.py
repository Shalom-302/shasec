from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from backend.common.enums import CreditKind, CreditSource
from backend.common.model import Base, get_id, id_key


class CreditGrant(Base):
    """A bucket of credits (or free scans) given to an account.

    The balance is the sum of ``remaining`` over unexpired grants: debits drain
    the bucket that expires first, so monthly subscription credits are used
    before purchased credits that never expire.
    """

    __tablename__ = 'credit_grant'

    id: Mapped[id_key] = mapped_column(init=False)
    x_id: Mapped[str] = mapped_column(sa.String(32), init=False, unique=True, default=get_id)
    user_id: Mapped[int] = mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'), index=True)
    amount: Mapped[int] = mapped_column(sa.Integer, comment='Units granted')
    remaining: Mapped[int] = mapped_column(sa.Integer, comment='Units still available')
    kind: Mapped[str] = mapped_column(
        sa.String(16), default=CreditKind.credit.value, comment='free_scan / credit'
    )
    source: Mapped[str] = mapped_column(
        sa.String(16), default=CreditSource.admin.value, comment='signup / voucher / purchase / subscription / admin'
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), default=None, comment='NULL = never expires'
    )
    voucher_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey('credit_voucher.id', ondelete='SET NULL'), default=None, index=True
    )
    # External payment reference (e.g. payment orchestrator transaction id), so a
    # webhook replay can never credit twice.
    external_ref: Mapped[str | None] = mapped_column(sa.String(128), default=None, unique=True)
    note: Mapped[str | None] = mapped_column(sa.String(255), default=None)


class CreditTransaction(Base):
    """Append-only ledger: every balance movement, for history and support."""

    __tablename__ = 'credit_transaction'

    id: Mapped[id_key] = mapped_column(init=False)
    user_id: Mapped[int] = mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'), index=True)
    delta: Mapped[int] = mapped_column(sa.Integer, comment='+grant / -debit')
    kind: Mapped[str] = mapped_column(sa.String(16), comment='free_scan / credit')
    reason: Mapped[str] = mapped_column(sa.String(16), comment='grant / scan_debit / scan_refund')
    grant_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey('credit_grant.id', ondelete='SET NULL'), default=None, index=True
    )
    scan_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey('scan.id', ondelete='SET NULL'), default=None, index=True
    )
    note: Mapped[str | None] = mapped_column(sa.String(255), default=None)


class CreditVoucher(Base):
    """An admin-generated code redeemable for credits.

    The code itself stops working after ``max_redemptions`` uses or past
    ``valid_until``; the credits it grants expire ``credit_validity_days`` after
    redemption (NULL = never).
    """

    __tablename__ = 'credit_voucher'

    id: Mapped[id_key] = mapped_column(init=False)
    code: Mapped[str] = mapped_column(sa.String(32), unique=True, index=True)
    credits: Mapped[int] = mapped_column(sa.Integer, comment='Credits granted per redemption')
    max_redemptions: Mapped[int] = mapped_column(sa.Integer, default=1, comment='Total uses allowed')
    redemption_count: Mapped[int] = mapped_column(sa.Integer, init=False, default=0)
    valid_until: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), default=None, comment='Code unusable after this date'
    )
    credit_validity_days: Mapped[int | None] = mapped_column(
        sa.Integer, default=None, comment='Granted credits expire N days after redemption'
    )
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True)
    note: Mapped[str | None] = mapped_column(sa.String(255), default=None)
    created_by: Mapped[int | None] = mapped_column(
        sa.ForeignKey('user.id', ondelete='SET NULL'), default=None
    )


class CreditVoucherRedemption(Base):
    """One account can redeem a given voucher at most once."""

    __tablename__ = 'credit_voucher_redemption'
    __table_args__ = (sa.UniqueConstraint('voucher_id', 'user_id', name='uq_voucher_user'),)

    id: Mapped[id_key] = mapped_column(init=False)
    voucher_id: Mapped[int] = mapped_column(sa.ForeignKey('credit_voucher.id', ondelete='CASCADE'), index=True)
    user_id: Mapped[int] = mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'), index=True)
