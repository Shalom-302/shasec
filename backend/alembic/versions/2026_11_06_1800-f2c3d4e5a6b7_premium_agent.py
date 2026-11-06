"""premium LangGraph agent: messages, memory, approval-gated actions, profile

Revision ID: f2c3d4e5a6b7
Revises: e1b2c3d4f5a6
Create Date: 2026-11-06 18:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f2c3d4e5a6b7'
down_revision: Union[str, None] = 'e1b2c3d4f5a6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _base(name: str, *cols):
    op.create_table(
        name,
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key id'),
        sa.Column('user_id', sa.Integer(), nullable=False),
        *cols,
        sa.Column('created_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_time', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f(f'ix_{name}_id'), name, ['id'], unique=False)


def upgrade() -> None:
    _base('agent_message',
          sa.Column('role', sa.String(16), nullable=False),
          sa.Column('content', sa.Text(), nullable=False),
          sa.Column('origin', sa.String(16), nullable=False))
    op.create_index(op.f('ix_agent_message_user_id'), 'agent_message', ['user_id'])

    _base('agent_memory',
          sa.Column('kind', sa.String(16), nullable=False),
          sa.Column('content', sa.String(500), nullable=False))
    op.create_index(op.f('ix_agent_memory_user_id'), 'agent_memory', ['user_id'])

    _base('agent_action',
          sa.Column('kind', sa.String(32), nullable=False),
          sa.Column('target_id', sa.Integer(), sa.ForeignKey('target.id', ondelete='CASCADE'), nullable=False),
          sa.Column('reason', sa.String(1000), nullable=False),
          sa.Column('profile', sa.String(16), nullable=False),
          sa.Column('scope_note', sa.String(2000), nullable=True),
          sa.Column('status', sa.String(16), nullable=False),
          sa.Column('scan_id', sa.Integer(), sa.ForeignKey('scan.id', ondelete='SET NULL'), nullable=True),
          sa.Column('review_note', sa.String(1000), nullable=True),
          sa.Column('reviewed_by', sa.Integer(), sa.ForeignKey('user.id', ondelete='SET NULL'), nullable=True),
          sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
          sa.Column('origin', sa.String(16), nullable=False))
    op.create_index(op.f('ix_agent_action_user_id'), 'agent_action', ['user_id'])
    op.create_index(op.f('ix_agent_action_status'), 'agent_action', ['status'])

    _base('agent_profile',
          sa.Column('autopilot', sa.Boolean(), nullable=False),
          sa.Column('last_autopilot_at', sa.DateTime(timezone=True), nullable=True))
    op.create_unique_constraint('uq_agent_profile_user_id', 'agent_profile', ['user_id'])


def downgrade() -> None:
    op.drop_table('agent_profile')
    op.drop_table('agent_action')
    op.drop_table('agent_memory')
    op.drop_table('agent_message')
