"""Kortex credits: balance, history, voucher redemption, and admin tooling
(voucher generation, manual grants). Payments (e.g. MoneyFusion) will plug into
``credit_service.grant(..., source='purchase', external_ref=<payment id>)``."""
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Path, Request
from sqlalchemy import select, update

from backend.app.shasec.schema.credit import (
    AdminGrantParam,
    CreateVouchersParam,
    DisableVouchersParam,
    GetCreditBalance,
    GetCreditGrant,
    GetCreditTransaction,
    GetVoucher,
    RedeemCodeParam,
    ScanPricing,
)
from backend.app.shasec.service.access import actor_from, require_admin
from backend.app.shasec.service.credit_service import credit_service, format_code
from backend.common.enums import CreditSource
from backend.common.exception import errors
from backend.common.pagination import DependsPagination, paging_data
from backend.common.response.response_schema import ResponseModel, response_base
from backend.common.security.jwt import DependsJwtAuth
from backend.core.conf import settings
from backend.database.db_postgres import CurrentSession, async_db_session
from backend.models.admin_audit import AdminAudit
from backend.models.credit import CreditVoucher
from backend.utils.timezone import timezone

router = APIRouter(prefix='/credits', tags=['Credits'])


def _voucher(v: CreditVoucher) -> GetVoucher:
    data = GetVoucher.model_validate(v)
    data.code = format_code(v.code)
    return data


@router.get('/me', summary='My balance, free scans and scan pricing', dependencies=[DependsJwtAuth])
async def get_my_balance(request: Request) -> ResponseModel:
    actor = actor_from(request)
    async with async_db_session() as db:
        bal = await credit_service.balance(db, actor.id)
    data = GetCreditBalance(
        **bal,
        is_admin=actor.is_admin,
        pricing=ScanPricing(
            fast=settings.CREDITS_COST_FAST,
            standard=settings.CREDITS_COST_STANDARD,
            deep=settings.CREDITS_COST_DEEP,
            free_profiles=settings.CREDITS_FREE_PROFILES,
        ),
    )
    return response_base.success(request=request, data=data)


@router.get('/me/grants', summary='My active credit buckets', dependencies=[DependsJwtAuth])
async def get_my_grants(request: Request) -> ResponseModel:
    async with async_db_session() as db:
        grants = await credit_service.active_grants(db, actor_from(request).id)
    data = [GetCreditGrant.model_validate(g) for g in grants]
    return response_base.success(request=request, data=data)


@router.get('/me/transactions', summary='My credit history (paginated)',
            dependencies=[DependsJwtAuth, DependsPagination])
async def get_my_transactions(request: Request, db: CurrentSession) -> ResponseModel:
    stmt = credit_service.transactions_select(actor_from(request).id)
    page_data = await paging_data(db, stmt, GetCreditTransaction)
    return response_base.success(request=request, data=page_data)


@router.post('/redeem', summary='Redeem a credit code', dependencies=[DependsJwtAuth])
async def redeem_code(request: Request, obj: RedeemCodeParam) -> ResponseModel:
    async with async_db_session.begin() as db:
        grant = await credit_service.redeem(db, user_id=actor_from(request).id, code=obj.code)
        data = GetCreditGrant.model_validate(grant)
    return response_base.success(request=request, data=data)


# ---- admin -------------------------------------------------------------------
@router.post('/vouchers', summary='[admin] Generate credit codes', dependencies=[DependsJwtAuth])
async def create_vouchers(request: Request, obj: CreateVouchersParam) -> ResponseModel:
    actor = actor_from(request)
    require_admin(actor)
    async with async_db_session.begin() as db:
        vouchers = await credit_service.create_vouchers(db, actor=actor, **obj.model_dump())
        data = [_voucher(v) for v in vouchers]
    return response_base.success(request=request, data=data)


@router.get('/vouchers', summary='[admin] List credit codes', dependencies=[DependsJwtAuth])
async def list_vouchers(request: Request) -> ResponseModel:
    require_admin(actor_from(request))
    async with async_db_session() as db:
        rows = (await db.execute(select(CreditVoucher).order_by(CreditVoucher.id.desc()).limit(500))).scalars()
        data = [_voucher(v) for v in rows]
    return response_base.success(request=request, data=data)


@router.post('/vouchers/disable', summary='[admin] Disable several credit codes', dependencies=[DependsJwtAuth])
async def disable_vouchers(request: Request, obj: DisableVouchersParam) -> ResponseModel:
    require_admin(actor_from(request))
    async with async_db_session.begin() as db:
        res = await db.execute(
            update(CreditVoucher)
            .where(CreditVoucher.id.in_(obj.ids), CreditVoucher.is_active.is_(True))
            .values(is_active=False)
        )
    return response_base.success(request=request, data={'disabled': res.rowcount})


@router.post('/vouchers/{pk}/disable', summary='[admin] Disable a credit code', dependencies=[DependsJwtAuth])
async def disable_voucher(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    require_admin(actor_from(request))
    async with async_db_session.begin() as db:
        voucher = await db.get(CreditVoucher, pk)
        if not voucher:
            raise errors.NotFoundError(msg='Voucher not found')
        voucher.is_active = False
    return response_base.success(request=request)


@router.post('/grant', summary='[admin] Grant credits to an account', dependencies=[DependsJwtAuth])
async def admin_grant(request: Request, obj: AdminGrantParam) -> ResponseModel:
    actor = actor_from(request)
    require_admin(actor)
    async with async_db_session.begin() as db:
        user_id = await credit_service.user_id_by_email(db, obj.email)
        expires_at = timezone.now() + timedelta(days=obj.expires_in_days) if obj.expires_in_days else None
        grant = await credit_service.grant(
            db, user_id=user_id, amount=obj.credits, source=CreditSource.admin.value,
            expires_at=expires_at, note=obj.note,
        )
        # Same audit trail + client notification as POST /admin/users/{pk}/credits.
        db.add(AdminAudit(admin_id=actor.id, target_user_id=user_id, action='credit_grant',
                          note=f'+{obj.credits} crédits' + (f' · {obj.note}' if obj.note else '')))
        data = GetCreditGrant.model_validate(grant)
    from backend.app.shasec.service.notification_service import notification_service
    await notification_service.notify_user(
        user_id, kind='account', title=f'{obj.credits} crédits ont été ajoutés à votre compte',
        body=obj.note, link='/credits',
    )
    return response_base.success(request=request, data=data)
