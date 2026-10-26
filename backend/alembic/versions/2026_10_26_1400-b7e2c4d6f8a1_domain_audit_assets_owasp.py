"""domain audit: scan mode, discovered assets, OWASP class on results

Revision ID: b7e2c4d6f8a1
Revises: afdd18a237a9
Create Date: 2026-10-26 14:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b7e2c4d6f8a1'
down_revision: Union[str, None] = 'afdd18a237a9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Existing scans are single-URL scans: server_default fills the column.
    op.add_column('scan', sa.Column('mode', sa.String(length=16), server_default='single', nullable=False,
                                    comment='single / audit'))

    op.create_table('scan_asset',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key id'),
    sa.Column('scan_id', sa.Integer(), nullable=False, comment='Owning audit'),
    sa.Column('host', sa.String(length=255), nullable=False, comment='FQDN'),
    sa.Column('source', sa.String(length=32), nullable=False, comment='root / subfinder / crt.sh / wordlist'),
    sa.Column('url', sa.String(length=512), nullable=True, comment='Base URL that answered'),
    sa.Column('ips', sa.String(length=255), nullable=True, comment='Resolved addresses, comma-separated'),
    sa.Column('cname', sa.String(length=255), nullable=True),
    sa.Column('third_party', sa.String(length=64), nullable=True,
              comment='SaaS provider the host is delegated to (not ours to attack)'),
    sa.Column('alive', sa.Boolean(), nullable=False, comment='Answered over HTTP(S)'),
    sa.Column('http_status', sa.Integer(), nullable=True),
    sa.Column('title', sa.String(length=255), nullable=True),
    sa.Column('server', sa.String(length=255), nullable=True),
    sa.Column('kind', sa.String(length=16), nullable=False, comment='website / api'),
    sa.Column('selected', sa.Boolean(), nullable=False, comment='In scope for steps 2-4'),
    sa.Column('created_time', sa.DateTime(timezone=True), nullable=False, comment='Creation time'),
    sa.Column('updated_time', sa.DateTime(timezone=True), nullable=True, comment='update time'),
    sa.ForeignKeyConstraint(['scan_id'], ['scan.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scan_asset_id'), 'scan_asset', ['id'], unique=False)
    op.create_index(op.f('ix_scan_asset_scan_id'), 'scan_asset', ['scan_id'], unique=False)

    for table in ('finding', 'exploit'):
        op.add_column(table, sa.Column('asset_id', sa.Integer(), nullable=True))
        op.add_column(table, sa.Column('owasp', sa.String(length=8), nullable=True))
        op.create_index(op.f(f'ix_{table}_asset_id'), table, ['asset_id'], unique=False)
        op.create_index(op.f(f'ix_{table}_owasp'), table, ['owasp'], unique=False)
        op.create_foreign_key(f'{table}_asset_id_fkey', table, 'scan_asset', ['asset_id'], ['id'], ondelete='SET NULL')


def downgrade() -> None:
    for table in ('exploit', 'finding'):
        op.drop_constraint(f'{table}_asset_id_fkey', table, type_='foreignkey')
        op.drop_index(op.f(f'ix_{table}_owasp'), table_name=table)
        op.drop_index(op.f(f'ix_{table}_asset_id'), table_name=table)
        op.drop_column(table, 'owasp')
        op.drop_column(table, 'asset_id')
    op.drop_index(op.f('ix_scan_asset_scan_id'), table_name='scan_asset')
    op.drop_index(op.f('ix_scan_asset_id'), table_name='scan_asset')
    op.drop_table('scan_asset')
    op.drop_column('scan', 'mode')
