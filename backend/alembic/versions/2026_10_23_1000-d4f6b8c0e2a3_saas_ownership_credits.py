"""saas: tenant ownership, target ownership proof, credits & vouchers

- target/scan get an ``owner_id`` (NULL for pre-existing rows = admin-only).
- target gets a ``verify_token`` (ownership proof) and ``verified_at``.
- scan gets ``billing`` / ``credits_charged`` (existing scans = admin).
- credit ledger: credit_voucher, credit_grant, credit_transaction,
  credit_voucher_redemption.

Revision ID: d4f6b8c0e2a3
Revises: c3e5a7b9d2f1
Create Date: 2026-10-23 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd4f6b8c0e2a3'
down_revision: Union[str, None] = 'c3e5a7b9d2f1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column('created_time', sa.DateTime(timezone=True), nullable=False, comment='Creation time'),
        sa.Column('updated_time', sa.DateTime(timezone=True), nullable=True, comment='update time'),
    ]


def upgrade() -> None:
    # --- ownership -----------------------------------------------------------
    for table in ('target', 'scan'):
        op.add_column(table, sa.Column('owner_id', sa.Integer(), nullable=True, comment='Owner account'))
        op.create_foreign_key(f'fk_{table}_owner', table, 'user', ['owner_id'], ['id'], ondelete='CASCADE')
        op.create_index(f'ix_{table}_owner_id', table, ['owner_id'])

    op.add_column('target', sa.Column('verify_token', sa.String(length=64), nullable=True, comment='Ownership proof token'))
    op.execute("UPDATE target SET verify_token = 'kortex-verify=' || md5(random()::text || id::text)")
    op.alter_column('target', 'verify_token', nullable=False)
    op.add_column('target', sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True,
                                      comment='Last successful ownership proof'))

    op.add_column('scan', sa.Column('billing', sa.String(length=16), nullable=False,
                                    server_default=sa.text("'admin'"), comment='free / credits / admin'))
    op.add_column('scan', sa.Column('credits_charged', sa.Integer(), nullable=False,
                                    server_default=sa.text('0'), comment='Credits debited for this scan'))

    # --- credits -------------------------------------------------------------
    op.create_table(
        'credit_voucher',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key id'),
        sa.Column('code', sa.String(length=32), nullable=False),
        sa.Column('credits', sa.Integer(), nullable=False, comment='Credits granted per redemption'),
        sa.Column('max_redemptions', sa.Integer(), nullable=False, comment='Total uses allowed'),
        sa.Column('redemption_count', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('valid_until', sa.DateTime(timezone=True), nullable=True, comment='Code unusable after this date'),
        sa.Column('credit_validity_days', sa.Integer(), nullable=True,
                  comment='Granted credits expire N days after redemption'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('note', sa.String(length=255), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(['created_by'], ['user.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_credit_voucher_id', 'credit_voucher', ['id'])
    op.create_index('ix_credit_voucher_code', 'credit_voucher', ['code'], unique=True)

    op.create_table(
        'credit_grant',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key id'),
        sa.Column('x_id', sa.String(length=32), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('amount', sa.Integer(), nullable=False, comment='Units granted'),
        sa.Column('remaining', sa.Integer(), nullable=False, comment='Units still available'),
        sa.Column('kind', sa.String(length=16), nullable=False, comment='free_scan / credit'),
        sa.Column('source', sa.String(length=16), nullable=False,
                  comment='signup / voucher / purchase / subscription / admin'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True, comment='NULL = never expires'),
        sa.Column('voucher_id', sa.Integer(), nullable=True),
        sa.Column('external_ref', sa.String(length=128), nullable=True),
        sa.Column('note', sa.String(length=255), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['voucher_id'], ['credit_voucher.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('x_id'),
        sa.UniqueConstraint('external_ref'),
    )
    op.create_index('ix_credit_grant_id', 'credit_grant', ['id'])
    op.create_index('ix_credit_grant_user_id', 'credit_grant', ['user_id'])
    op.create_index('ix_credit_grant_voucher_id', 'credit_grant', ['voucher_id'])

    op.create_table(
        'credit_transaction',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key id'),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('delta', sa.Integer(), nullable=False, comment='+grant / -debit'),
        sa.Column('kind', sa.String(length=16), nullable=False, comment='free_scan / credit'),
        sa.Column('reason', sa.String(length=16), nullable=False, comment='grant / scan_debit / scan_refund'),
        sa.Column('grant_id', sa.Integer(), nullable=True),
        sa.Column('scan_id', sa.Integer(), nullable=True),
        sa.Column('note', sa.String(length=255), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['grant_id'], ['credit_grant.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['scan_id'], ['scan.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_credit_transaction_id', 'credit_transaction', ['id'])
    op.create_index('ix_credit_transaction_user_id', 'credit_transaction', ['user_id'])
    op.create_index('ix_credit_transaction_grant_id', 'credit_transaction', ['grant_id'])
    op.create_index('ix_credit_transaction_scan_id', 'credit_transaction', ['scan_id'])

    op.create_table(
        'credit_voucher_redemption',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key id'),
        sa.Column('voucher_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(['voucher_id'], ['credit_voucher.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('voucher_id', 'user_id', name='uq_voucher_user'),
    )
    op.create_index('ix_credit_voucher_redemption_id', 'credit_voucher_redemption', ['id'])
    op.create_index('ix_credit_voucher_redemption_voucher_id', 'credit_voucher_redemption', ['voucher_id'])
    op.create_index('ix_credit_voucher_redemption_user_id', 'credit_voucher_redemption', ['user_id'])


def downgrade() -> None:
    op.drop_table('credit_voucher_redemption')
    op.drop_table('credit_transaction')
    op.drop_table('credit_grant')
    op.drop_table('credit_voucher')
    op.drop_column('scan', 'credits_charged')
    op.drop_column('scan', 'billing')
    op.drop_column('target', 'verified_at')
    op.drop_column('target', 'verify_token')
    for table in ('scan', 'target'):
        op.drop_index(f'ix_{table}_owner_id', table_name=table)
        op.drop_constraint(f'fk_{table}_owner', table, type_='foreignkey')
        op.drop_column(table, 'owner_id')
