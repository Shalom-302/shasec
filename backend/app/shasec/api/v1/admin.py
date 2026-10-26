"""Admin user-management console (SaaS governance).

All routes are admin-only (``require_admin``) and live under ``/admin/users``.
They let an operator list client accounts with per-account aggregates and risk
signals, drill into one account's scans / credit history / action trail, and
suspend, reactivate or credit an account. Suspension takes effect immediately
(it evicts the account's live sessions from Redis)."""
from typing import Annotated

from fastapi import APIRouter, Path, Query, Request

from backend.app.shasec.schema.admin_user import (
    AdminAuditItem,
    AdminCreditParam,
    AdminOverview,
    AdminUserDetail,
    AdminUserListItem,
    ReactivateParam,
    SuspendParam,
)
from backend.app.shasec.schema.credit import GetCreditTransaction
from backend.app.shasec.schema.scan import GetScanDetails
from backend.app.shasec.service.access import actor_from, require_admin
from backend.app.shasec.service.admin_user_service import admin_user_service
from backend.app.shasec.service.credit_service import credit_service
from backend.common.pagination import DependsPagination, paging_data
from backend.common.response.response_schema import ResponseModel, response_base
from backend.common.security.jwt import DependsJwtAuth
from backend.crud.crud_scan import scan_dao
from backend.database.db_postgres import CurrentSession

router = APIRouter(prefix='/admin', tags=['Admin · Users'])


@router.get('/overview', summary='[admin] Platform counters and recent activity', dependencies=[DependsJwtAuth])
async def get_overview(request: Request) -> ResponseModel:
    require_admin(actor_from(request))
    data = AdminOverview(**await admin_user_service.overview())
    return response_base.success(request=request, data=data)


@router.get('/users', summary='[admin] List client accounts with aggregates & risk', dependencies=[DependsJwtAuth])
async def list_users(
    request: Request,
    query: Annotated[str | None, Query(description='Filter by email')] = None,
    status: Annotated[bool | None, Query()] = None,
    role: Annotated[str | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> ResponseModel:
    require_admin(actor_from(request))
    result = await admin_user_service.list_users(page=page, size=size, q=query, status=status, role=role)
    result['items'] = [AdminUserListItem(**it) for it in result['items']]
    return response_base.success(request=request, data=result)


@router.get('/users/{pk}', summary='[admin] Account detail with risk signals', dependencies=[DependsJwtAuth])
async def get_user_detail(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    require_admin(actor_from(request))
    data = AdminUserDetail(**await admin_user_service.get_detail(pk))
    return response_base.success(request=request, data=data)


@router.get('/users/{pk}/scans', summary='[admin] An account’s scans (paginated)',
            dependencies=[DependsJwtAuth, DependsPagination])
async def get_user_scans(request: Request, db: CurrentSession, pk: Annotated[int, Path(...)]) -> ResponseModel:
    require_admin(actor_from(request))
    stmt = await scan_dao.get_list(owner_id=pk)
    page_data = await paging_data(db, stmt, GetScanDetails)
    return response_base.success(request=request, data=page_data)


@router.get('/users/{pk}/transactions', summary='[admin] An account’s credit history (paginated)',
            dependencies=[DependsJwtAuth, DependsPagination])
async def get_user_transactions(request: Request, db: CurrentSession, pk: Annotated[int, Path(...)]) -> ResponseModel:
    require_admin(actor_from(request))
    stmt = credit_service.transactions_select(pk)
    page_data = await paging_data(db, stmt, GetCreditTransaction)
    return response_base.success(request=request, data=page_data)


@router.get('/users/{pk}/audit', summary='[admin] Admin actions on an account (paginated)',
            dependencies=[DependsJwtAuth, DependsPagination])
async def get_user_audit(request: Request, db: CurrentSession, pk: Annotated[int, Path(...)]) -> ResponseModel:
    require_admin(actor_from(request))
    stmt = admin_user_service.audit_select(pk)
    page_data = await paging_data(db, stmt, AdminAuditItem)
    return response_base.success(request=request, data=page_data)


@router.post('/users/{pk}/suspend', summary='[admin] Suspend an account (blocks login, kills sessions)',
             dependencies=[DependsJwtAuth])
async def suspend_user(request: Request, pk: Annotated[int, Path(...)], obj: SuspendParam) -> ResponseModel:
    actor = actor_from(request)
    require_admin(actor)
    await admin_user_service.suspend(actor_id=actor.id, user_id=pk, reason=obj.reason)
    return response_base.success(request=request)


@router.post('/users/{pk}/reactivate', summary='[admin] Reactivate a suspended account',
             dependencies=[DependsJwtAuth])
async def reactivate_user(request: Request, pk: Annotated[int, Path(...)], obj: ReactivateParam) -> ResponseModel:
    actor = actor_from(request)
    require_admin(actor)
    await admin_user_service.reactivate(actor_id=actor.id, user_id=pk, note=obj.note)
    return response_base.success(request=request)


@router.post('/users/{pk}/credits', summary='[admin] Grant credits to an account', dependencies=[DependsJwtAuth])
async def grant_user_credits(request: Request, pk: Annotated[int, Path(...)], obj: AdminCreditParam) -> ResponseModel:
    actor = actor_from(request)
    require_admin(actor)
    await admin_user_service.grant_credits(
        actor_id=actor.id, user_id=pk, amount=obj.amount,
        expires_in_days=obj.expires_in_days, note=obj.note,
    )
    return response_base.success(request=request)
