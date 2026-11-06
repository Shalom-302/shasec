"""Kortex Defender premium agent (LangGraph + DeepSeek).

- AgentMessage: the conversation, replayed into the graph each turn.
- AgentMemory: what the agent has learned about the account (stack, priorities,
  and *lessons* from the admin's approvals/rejections). Injected into its
  system prompt, so its behaviour adapts to past outcomes.
- AgentAction: anything that costs credits or touches a target. The agent only
  PROPOSES; nothing runs until an admin approves.
"""
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from backend.common.model import Base, id_key


class AgentMessage(Base):
    __tablename__ = 'agent_message'

    id: Mapped[id_key] = mapped_column(init=False)
    user_id: Mapped[int] = mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'), index=True)
    role: Mapped[str] = mapped_column(sa.String(16), comment='user / assistant / system_event')
    content: Mapped[str] = mapped_column(sa.Text)
    # 'chat' (user typed) or 'autopilot' (daily autonomous review).
    origin: Mapped[str] = mapped_column(sa.String(16), default='chat')


class AgentMemory(Base):
    __tablename__ = 'agent_memory'

    id: Mapped[id_key] = mapped_column(init=False)
    user_id: Mapped[int] = mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'), index=True)
    kind: Mapped[str] = mapped_column(sa.String(16), comment='fact / preference / lesson')
    content: Mapped[str] = mapped_column(sa.String(500))


class AgentAction(Base):
    __tablename__ = 'agent_action'

    id: Mapped[id_key] = mapped_column(init=False)
    user_id: Mapped[int] = mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'), index=True)
    kind: Mapped[str] = mapped_column(sa.String(32), comment='scan / advanced_audit')
    target_id: Mapped[int] = mapped_column(sa.ForeignKey('target.id', ondelete='CASCADE'))
    reason: Mapped[str] = mapped_column(sa.String(1000))
    profile: Mapped[str] = mapped_column(sa.String(16), default='standard')
    scope_note: Mapped[str | None] = mapped_column(sa.String(2000), default=None)
    status: Mapped[str] = mapped_column(
        sa.String(16), default='pending', index=True, comment='pending / executed / rejected / failed')
    scan_id: Mapped[int | None] = mapped_column(sa.ForeignKey('scan.id', ondelete='SET NULL'), default=None)
    review_note: Mapped[str | None] = mapped_column(sa.String(1000), default=None)
    reviewed_by: Mapped[int | None] = mapped_column(sa.ForeignKey('user.id', ondelete='SET NULL'), default=None)
    reviewed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), default=None)
    origin: Mapped[str] = mapped_column(sa.String(16), default='chat')


class AgentProfile(Base):
    """Per-account agent settings (autopilot on/off, last autonomous run)."""

    __tablename__ = 'agent_profile'

    id: Mapped[id_key] = mapped_column(init=False)
    user_id: Mapped[int] = mapped_column(sa.ForeignKey('user.id', ondelete='CASCADE'), unique=True)
    autopilot: Mapped[bool] = mapped_column(sa.Boolean, default=True)
    last_autopilot_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), default=None)
