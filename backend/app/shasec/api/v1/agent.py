"""Premium agent (LangGraph + DeepSeek). Client chat + admin approval of actions."""
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi_limiter.depends import RateLimiter
from pydantic import ConfigDict, Field
from sqlalchemy import delete, select

from backend.app.shasec.service.access import actor_from, require_admin
from backend.app.shasec.service.agent_service import agent_service, is_premium, messages_left
from backend.common.exception import errors
from backend.common.response.response_schema import ResponseModel, response_base
from backend.common.schema import SchemaBase
from backend.common.security.jwt import DependsJwtAuth
from backend.core.conf import settings
from backend.database.db_postgres import async_db_session
from backend.models import Target
from backend.models.agent import AgentAction, AgentMemory, AgentMessage, AgentProfile
from backend.models.user import User

router = APIRouter(prefix='/agent', tags=['Agent'])


class ChatParam(SchemaBase):
    message: Annotated[str, Field(min_length=1, max_length=4000)]


class AutopilotParam(SchemaBase):
    enabled: bool


class DecisionParam(SchemaBase):
    note: str | None = Field(default=None, max_length=1000)


class GetMessage(SchemaBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    role: str
    content: str
    origin: str
    created_time: datetime


class GetMemory(SchemaBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    kind: str
    content: str
    created_time: datetime


class GetAction(SchemaBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    kind: str
    target_id: int
    target_url: str | None = None
    user_email: str | None = None
    reason: str
    profile: str
    scope_note: str | None = None
    status: str
    scan_id: int | None = None
    review_note: str | None = None
    origin: str
    created_time: datetime


async def _actions(where, limit: int = 50) -> list[GetAction]:
    async with async_db_session() as db:
        rows = (await db.execute(
            select(AgentAction, Target.url, User.email)
            .join(Target, Target.id == AgentAction.target_id).join(User, User.id == AgentAction.user_id)
            .where(*where).order_by(AgentAction.id.desc()).limit(limit))).all()
    out = []
    for a, url, email in rows:
        g = GetAction.model_validate(a)
        g.target_url, g.user_email = url, email
        out.append(g)
    return out


@router.get('/status', summary='Agent availability for me', dependencies=[DependsJwtAuth])
async def status(request: Request) -> ResponseModel:
    uid = actor_from(request).id
    async with async_db_session() as db:
        prof = await db.scalar(select(AgentProfile).where(AgentProfile.user_id == uid))
    return response_base.success(request=request, data={
        'premium': await is_premium(uid), 'enabled': bool(settings.DEEPSEEK_API_KEY),
        'messages_left': await messages_left(uid), 'autopilot': prof.autopilot if prof else True,
        'autopilot_available': settings.AGENT_AUTOPILOT_ENABLED,
    })


@router.get('/messages', summary='My conversation with the agent', dependencies=[DependsJwtAuth])
async def messages(request: Request) -> ResponseModel:
    uid = actor_from(request).id
    async with async_db_session() as db:
        rows = (await db.scalars(select(AgentMessage).where(AgentMessage.user_id == uid)
                                 .order_by(AgentMessage.id.desc()).limit(100))).all()
    return response_base.success(request=request, data=[GetMessage.model_validate(m) for m in reversed(rows)])


@router.post('/chat', summary='Talk to the agent',
             dependencies=[DependsJwtAuth, Depends(RateLimiter(times=10, minutes=1))])
async def chat(request: Request, obj: ChatParam) -> ResponseModel:
    data = await agent_service.run_turn(actor_from(request).id, obj.message.strip(), origin='chat')
    return response_base.success(request=request, data=data)


@router.get('/memory', summary='What the agent remembers about me', dependencies=[DependsJwtAuth])
async def memory(request: Request) -> ResponseModel:
    uid = actor_from(request).id
    async with async_db_session() as db:
        rows = (await db.scalars(select(AgentMemory).where(AgentMemory.user_id == uid)
                                 .order_by(AgentMemory.id.desc()))).all()
    return response_base.success(request=request, data=[GetMemory.model_validate(m) for m in rows])


@router.delete('/memory/{pk}', summary='Forget one memory', dependencies=[DependsJwtAuth])
async def forget(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    uid = actor_from(request).id
    async with async_db_session.begin() as db:
        res = await db.execute(delete(AgentMemory).where(AgentMemory.id == pk, AgentMemory.user_id == uid))
    return response_base.success(request=request, data={'deleted': res.rowcount})


@router.get('/actions', summary='My agent proposals', dependencies=[DependsJwtAuth])
async def my_actions(request: Request) -> ResponseModel:
    data = await _actions([AgentAction.user_id == actor_from(request).id], 30)
    return response_base.success(request=request, data=data)


@router.put('/autopilot', summary='Turn the daily autonomous review on/off', dependencies=[DependsJwtAuth])
async def autopilot(request: Request, obj: AutopilotParam) -> ResponseModel:
    uid = actor_from(request).id
    async with async_db_session.begin() as db:
        prof = await db.scalar(select(AgentProfile).where(AgentProfile.user_id == uid))
        if prof is None:
            prof = AgentProfile(user_id=uid)
            db.add(prof)
        prof.autopilot = obj.enabled
    return response_base.success(request=request, data={'autopilot': obj.enabled})


# ---- admin approval ------------------------------------------------------------
@router.get('/admin/actions', summary='[admin] Agent proposals', dependencies=[DependsJwtAuth])
async def admin_actions(request: Request, status: Annotated[str | None, Query(max_length=16)] = 'pending') -> ResponseModel:
    require_admin(actor_from(request))
    where = [AgentAction.status == status] if status else []
    return response_base.success(request=request, data=await _actions(where, 100))


@router.post('/admin/actions/{pk}/approve', summary='[admin] Approve and execute', dependencies=[DependsJwtAuth])
async def approve(request: Request, pk: Annotated[int, Path(...)], obj: DecisionParam) -> ResponseModel:
    actor = actor_from(request)
    require_admin(actor)
    a = await agent_service.decide(admin=actor, action_id=pk, approve=True, note=obj.note)
    return response_base.success(request=request, data={'id': a.id, 'status': a.status, 'scan_id': a.scan_id,
                                                        'note': a.review_note})


@router.post('/admin/actions/{pk}/reject', summary='[admin] Reject', dependencies=[DependsJwtAuth])
async def reject(request: Request, pk: Annotated[int, Path(...)], obj: DecisionParam) -> ResponseModel:
    actor = actor_from(request)
    require_admin(actor)
    if not (obj.note or '').strip():
        raise errors.RequestError(msg='Indiquez un motif : l’agent s’en sert pour apprendre.')
    a = await agent_service.decide(admin=actor, action_id=pk, approve=False, note=obj.note)
    return response_base.success(request=request, data={'id': a.id, 'status': a.status})
