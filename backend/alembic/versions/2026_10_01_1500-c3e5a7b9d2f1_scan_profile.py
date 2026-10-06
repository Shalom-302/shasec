"""scan profile (fast / standard / deep)

Adds a depth/speed profile to each scan so the scanner stage can run only the
plugin tiers that profile allows (methodology §3 staged hunt), which is what
keeps scans from running the heavy long tail (nmap/testssl/ffuf/zap) every time.

Revision ID: c3e5a7b9d2f1
Revises: b2d4f6a8c1e0
Create Date: 2026-10-01 15:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3e5a7b9d2f1'
down_revision: Union[str, None] = 'b2d4f6a8c1e0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'scan',
        sa.Column(
            'profile', sa.String(length=16), nullable=False,
            server_default=sa.text("'standard'"), comment='fast / standard / deep',
        ),
    )


def downgrade() -> None:
    op.drop_column('scan', 'profile')
