"""referral program: personal codes + referrer attribution

Revision ID: e1b2c3d4f5a6
Revises: d9a3b5c7e1f2
Create Date: 2026-11-06 15:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e1b2c3d4f5a6'
down_revision: Union[str, None] = 'd9a3b5c7e1f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _timestamps():
    return (
        sa.Column('created_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_time', sa.DateTime(timezone=True), nullable=True),
    )


def upgrade() -> None:
    op.create_table(
        'referral_code',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key id'),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('code', sa.String(length=16), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id'),
    )
    op.create_index(op.f('ix_referral_code_id'), 'referral_code', ['id'], unique=False)
    op.create_index(op.f('ix_referral_code_code'), 'referral_code', ['code'], unique=True)

    op.create_table(
        'referral',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key id'),
        sa.Column('referee_id', sa.Integer(), nullable=False),
        sa.Column('referrer_id', sa.Integer(), nullable=False),
        sa.Column('code', sa.String(length=16), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(['referee_id'], ['user.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['referrer_id'], ['user.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('referee_id'),
    )
    op.create_index(op.f('ix_referral_id'), 'referral', ['id'], unique=False)
    op.create_index(op.f('ix_referral_referrer_id'), 'referral', ['referrer_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_referral_referrer_id'), table_name='referral')
    op.drop_index(op.f('ix_referral_id'), table_name='referral')
    op.drop_table('referral')
    op.drop_index(op.f('ix_referral_code_code'), table_name='referral_code')
    op.drop_index(op.f('ix_referral_code_id'), table_name='referral_code')
    op.drop_table('referral_code')
