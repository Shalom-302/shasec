"""Affiliate (promo-code) program with admin-controlled cash commissions.

- Affiliate: a user who applied, accepted the program terms and gave a payout
  identity (name + Mobile Money number). Only an admin can approve it and set
  its rates. Its ``code`` is the promo code buyers type at checkout.
- AffiliateCommission: one per confirmed payment made with the code. It is never
  paid automatically: pending (hold period + real usage) -> available -> the
  admin marks it paid with the transfer reference, or rejects it.

Attribution (who brought whom) reuses the ``referral`` table: one affiliate per
buyer, set once.
"""
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from backend.common.model import Base, id_key


class Affiliate(Base):
    __tablename__ = 'affiliate'

    id: Mapped[id_key] = mapped_column(init=False)
    user_id: Mapped[int] = mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'), unique=True)
    code: Mapped[str] = mapped_column(sa.String(16), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(sa.String(120))
    payout_phone: Mapped[str] = mapped_column(sa.String(20), index=True)
    payout_method: Mapped[str] = mapped_column(sa.String(16), comment='wave / orange / mtn / moov')
    status: Mapped[str] = mapped_column(sa.String(16), default='pending', index=True,
                                        comment='pending / approved / suspended / rejected')
    discount_pct: Mapped[int] = mapped_column(sa.Integer, default=30, comment='Buyer discount, % of list price')
    commission_pct: Mapped[int] = mapped_column(sa.Integer, default=20, comment='Commission, % of list price')
    terms_accepted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), default=None)
    reviewed_by: Mapped[int | None] = mapped_column(sa.ForeignKey('user.id', ondelete='SET NULL'), default=None)
    reviewed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), default=None)
    note: Mapped[str | None] = mapped_column(sa.String(500), default=None)


class AffiliateCommission(Base):
    __tablename__ = 'affiliate_commission'

    id: Mapped[id_key] = mapped_column(init=False)
    affiliate_id: Mapped[int] = mapped_column(sa.ForeignKey('affiliate.id', ondelete='CASCADE'), index=True)
    payment_id: Mapped[int] = mapped_column(sa.ForeignKey('payment.id', ondelete='CASCADE'), unique=True)
    referee_id: Mapped[int] = mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'), index=True)
    amount: Mapped[int] = mapped_column(sa.Integer, comment='FCFA owed to the affiliate')
    status: Mapped[str] = mapped_column(sa.String(16), default='pending', index=True,
                                        comment='pending / available / paid / rejected')
    available_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), default=None)
    flags: Mapped[str | None] = mapped_column(sa.String(500), default=None, comment='Fraud signals for the admin')
    paid_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), default=None)
    paid_ref: Mapped[str | None] = mapped_column(sa.String(120), default=None, comment='Wave/OM transfer reference')
    reviewed_by: Mapped[int | None] = mapped_column(sa.ForeignKey('user.id', ondelete='SET NULL'), default=None)
    note: Mapped[str | None] = mapped_column(sa.String(500), default=None)
