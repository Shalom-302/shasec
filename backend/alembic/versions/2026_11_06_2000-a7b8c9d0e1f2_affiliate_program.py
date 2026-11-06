"""affiliate program: promo codes, admin-approved cash commissions

Revision ID: a7b8c9d0e1f2
Revises: f2c3d4e5a6b7
Create Date: 2026-11-06 20:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a7b8c9d0e1f2'
down_revision: Union[str, None] = 'f2c3d4e5a6b7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _ts():
    return (sa.Column('created_time', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_time', sa.DateTime(timezone=True), nullable=True))


def upgrade() -> None:
    op.create_table(
        'affiliate',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key id'),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('user.id', ondelete='CASCADE'), nullable=False),
        sa.Column('code', sa.String(16), nullable=False),
        sa.Column('full_name', sa.String(120), nullable=False),
        sa.Column('payout_phone', sa.String(20), nullable=False),
        sa.Column('payout_method', sa.String(16), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('discount_pct', sa.Integer(), nullable=False),
        sa.Column('commission_pct', sa.Integer(), nullable=False),
        sa.Column('terms_accepted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('reviewed_by', sa.Integer(), sa.ForeignKey('user.id', ondelete='SET NULL'), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('note', sa.String(500), nullable=True),
        *_ts(),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id'),
    )
    op.create_index('ix_affiliate_id', 'affiliate', ['id'])
    op.create_index('ix_affiliate_code', 'affiliate', ['code'], unique=True)
    op.create_index('ix_affiliate_status', 'affiliate', ['status'])
    op.create_index('ix_affiliate_payout_phone', 'affiliate', ['payout_phone'])

    op.create_table(
        'affiliate_commission',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key id'),
        sa.Column('affiliate_id', sa.Integer(), sa.ForeignKey('affiliate.id', ondelete='CASCADE'), nullable=False),
        sa.Column('payment_id', sa.Integer(), sa.ForeignKey('payment.id', ondelete='CASCADE'), nullable=False),
        sa.Column('referee_id', sa.Integer(), sa.ForeignKey('user.id', ondelete='CASCADE'), nullable=False),
        sa.Column('amount', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('available_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('flags', sa.String(500), nullable=True),
        sa.Column('paid_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('paid_ref', sa.String(120), nullable=True),
        sa.Column('reviewed_by', sa.Integer(), sa.ForeignKey('user.id', ondelete='SET NULL'), nullable=True),
        sa.Column('note', sa.String(500), nullable=True),
        *_ts(),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('payment_id'),
    )
    op.create_index('ix_affiliate_commission_id', 'affiliate_commission', ['id'])
    op.create_index('ix_affiliate_commission_affiliate_id', 'affiliate_commission', ['affiliate_id'])
    op.create_index('ix_affiliate_commission_referee_id', 'affiliate_commission', ['referee_id'])
    op.create_index('ix_affiliate_commission_status', 'affiliate_commission', ['status'])

    op.add_column('payment', sa.Column('list_price', sa.Integer(), nullable=True))
    op.add_column('payment', sa.Column('promo_code', sa.String(16), nullable=True))
    op.add_column('payment', sa.Column('affiliate_id', sa.Integer(), nullable=True))
    op.add_column('payment', sa.Column('payer_phone', sa.String(20), nullable=True))
    op.create_foreign_key('fk_payment_affiliate_id', 'payment', 'affiliate', ['affiliate_id'], ['id'], ondelete='SET NULL')
    op.create_index('ix_payment_affiliate_id', 'payment', ['affiliate_id'])
    op.create_index('ix_payment_payer_phone', 'payment', ['payer_phone'])


def downgrade() -> None:
    op.drop_index('ix_payment_payer_phone', table_name='payment')
    op.drop_index('ix_payment_affiliate_id', table_name='payment')
    op.drop_constraint('fk_payment_affiliate_id', 'payment', type_='foreignkey')
    for col in ('payer_phone', 'affiliate_id', 'promo_code', 'list_price'):
        op.drop_column('payment', col)
    op.drop_table('affiliate_commission')
    op.drop_table('affiliate')
