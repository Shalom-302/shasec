"""finding confidence + status lifecycle (methodology §14)

Adds the Kaanari "Chasse aux Sorcières" finding discipline to the schema so an
AI agent (Hermes) must declare confidence and separate observed from potential:
    - finding.confidence  (low / medium / high)
    - finding.status      (suspected / confirmed / false_positive / stopped / fixed / retest_required)
    - exploit.status      (same lifecycle, mirroring Finding)

Revision ID: b2d4f6a8c1e0
Revises: 1bc196249524
Create Date: 2026-10-01 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2d4f6a8c1e0'
down_revision: Union[str, None] = '1bc196249524'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # server_default backfills existing rows for the NOT NULL columns; the ORM
    # supplies the value for new rows, so the defaults are harmless going forward.
    op.add_column(
        'finding',
        sa.Column(
            'confidence', sa.String(length=16), nullable=False,
            server_default=sa.text("'low'"), comment='low / medium / high',
        ),
    )
    op.add_column(
        'finding',
        sa.Column(
            'status', sa.String(length=32), nullable=False,
            server_default=sa.text("'suspected'"),
            comment='suspected / confirmed / false_positive / stopped / fixed / retest_required',
        ),
    )
    op.add_column(
        'exploit',
        sa.Column(
            'status', sa.String(length=32), nullable=False,
            server_default=sa.text("'suspected'"),
            comment='suspected / confirmed / false_positive / stopped / fixed / retest_required',
        ),
    )
    # A proof that was already recorded as confirmed should read as such.
    op.execute("UPDATE exploit SET status = 'confirmed' WHERE confirmed = true")


def downgrade() -> None:
    op.drop_column('exploit', 'status')
    op.drop_column('finding', 'status')
    op.drop_column('finding', 'confidence')
