from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from backend.common.model import Base, get_id, id_key


class Payment(Base):
    """One online purchase of credits (MoneyFusion checkout).

    Written BEFORE the user pays: it freezes the price and the credits for this
    pack at the moment we decided them. When the payment is confirmed nothing is
    recomputed from the notification. ``status`` moves pending -> paid exactly
    once through a conditional UPDATE, and the credit grant carries
    ``external_ref = provider:reference`` (unique) as a second, independent guard.
    """

    __tablename__ = 'payment'

    id: Mapped[id_key] = mapped_column(init=False)
    user_id: Mapped[int] = mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'), index=True)
    pack: Mapped[str] = mapped_column(sa.String(32))
    amount: Mapped[int] = mapped_column(sa.Integer, comment='Price asked, FCFA')
    credits: Mapped[int] = mapped_column(sa.Integer, comment='Credits granted once paid')
    x_id: Mapped[str] = mapped_column(sa.String(32), init=False, unique=True, default=get_id)
    validity_days: Mapped[int | None] = mapped_column(sa.Integer, default=None, comment='NULL = never expires')
    provider: Mapped[str] = mapped_column(sa.String(32), default='moneyfusion')
    # Aggregator token: our idempotency key. NULL only between insert and the
    # aggregator's answer (same DB transaction).
    reference: Mapped[str | None] = mapped_column(sa.String(128), default=None, unique=True, index=True)
    status: Mapped[str] = mapped_column(
        sa.String(16), default='pending', index=True, comment='pending / paid / failed / mismatch / expired'
    )
    amount_paid: Mapped[float | None] = mapped_column(sa.Float, default=None)
    checkout_url: Mapped[str | None] = mapped_column(sa.String(1024), default=None)
    paid_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), default=None)
    note: Mapped[str | None] = mapped_column(sa.String(255), default=None)
    # Promo code (affiliate program): amount above is what the buyer pays;
    # list_price is the pack's normal price the commission is computed on.
    list_price: Mapped[int | None] = mapped_column(sa.Integer, default=None)
    promo_code: Mapped[str | None] = mapped_column(sa.String(16), default=None)
    affiliate_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey('affiliate.id', ondelete='SET NULL'), default=None, index=True)
    # Mobile Money number that paid (anti self-referral, fraud review).
    payer_phone: Mapped[str | None] = mapped_column(sa.String(20), default=None, index=True)
