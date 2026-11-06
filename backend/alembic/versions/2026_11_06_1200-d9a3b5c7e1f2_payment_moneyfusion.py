"""payment table for online credit purchases (MoneyFusion)

Revision ID: d9a3b5c7e1f2
Revises: c8f1a2b3d4e5
Create Date: 2026-11-06 12:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd9a3b5c7e1f2'
down_revision: Union[str, None] = 'c8f1a2b3d4e5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'payment',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key id'),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('pack', sa.String(length=32), nullable=False),
        sa.Column('amount', sa.Integer(), nullable=False, comment='Price asked, FCFA'),
        sa.Column('credits', sa.Integer(), nullable=False, comment='Credits granted once paid'),
        sa.Column('x_id', sa.String(length=32), nullable=False),
        sa.Column('validity_days', sa.Integer(), nullable=True, comment='NULL = never expires'),
        sa.Column('provider', sa.String(length=32), nullable=False),
        sa.Column('reference', sa.String(length=128), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=False,
                  comment='pending / paid / failed / mismatch / expired'),
        sa.Column('amount_paid', sa.Float(), nullable=True),
        sa.Column('checkout_url', sa.String(length=1024), nullable=True),
        sa.Column('paid_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('note', sa.String(length=255), nullable=True),
        sa.Column('created_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_time', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('x_id'),
    )
    op.create_index(op.f('ix_payment_id'), 'payment', ['id'], unique=False)
    op.create_index(op.f('ix_payment_user_id'), 'payment', ['user_id'], unique=False)
    op.create_index(op.f('ix_payment_reference'), 'payment', ['reference'], unique=True)
    op.create_index(op.f('ix_payment_status'), 'payment', ['status'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_payment_status'), table_name='payment')
    op.drop_index(op.f('ix_payment_reference'), table_name='payment')
    op.drop_index(op.f('ix_payment_user_id'), table_name='payment')
    op.drop_index(op.f('ix_payment_id'), table_name='payment')
    op.drop_table('payment')
