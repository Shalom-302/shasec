"""user.email_verified for WhatsApp-OTP sign-up gate

Revision ID: c8f1a2b3d4e5
Revises: b7e2c4d6f8a1
Create Date: 2026-10-26 17:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c8f1a2b3d4e5'
down_revision: Union[str, None] = 'b7e2c4d6f8a1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # server_default '1' (true) => existing rows (admins, current clients) stay
    # verified and are never locked out; only new sign-ups are created False.
    op.add_column('user', sa.Column('email_verified', sa.Boolean(), nullable=False, server_default='1'))


def downgrade() -> None:
    op.drop_column('user', 'email_verified')
