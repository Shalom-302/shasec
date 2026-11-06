"""Affiliate program routes: apply / my dashboard (client), review + payouts (admin)."""
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi_limiter.depends import RateLimiter
from pydantic import Field
from sqlalchemy import func, select

from backend.app.shasec.service.access import actor_from, require_admin
from backend.app.shasec.service.affiliate_service import METHODS, affiliate_service
from backend.common.exception import errors
from backend.common.response.response_schema import ResponseModel, response_base
from backend.common.schema import SchemaBase
from backend.common.security.jwt import DependsJwtAuth
from backend.core.conf import settings
from backend.database.db_postgres import async_db_session
from backend.models.affiliate import Affiliate, AffiliateCommission
from backend.models.payment import Payment
from backend.models.referral import Referral
from backend.models.user import User

router = APIRouter(prefix='/affiliates', tags=['Affiliates'])


class ApplyParam(SchemaBase):
    code: Annotated[str, Field(min_length=4, max_length=16)]
    full_name: Annotated[str, Field(min_length=3, max_length=120)]
    payout_phone: Annotated[str, Field(min_length=8, max_length=20)]
    payout_method: str
    accept_terms: bool


class ReviewParam(SchemaBase):
    status: str
    discount_pct: int | None = Field(default=None, ge=0, le=90)
    commission_pct: int | None = Field(default=None, ge=0, le=90)
    note: str | None = Field(default=None, max_length=500)


class CommissionDecisionParam(SchemaBase):
    action: str  # paid / rejected / available
    paid_ref: str | None = Field(default=None, max_length=120)
    note: str | None = Field(default=None, max_length=500)


@router.get('/me', summary='My affiliate status, code and commissions', dependencies=[DependsJwtAuth])
async def me(request: Request) -> ResponseModel:
    return response_base.success(request=request, data=await affiliate_service.summary(actor_from(request).id))


@router.post('/apply', summary='Apply to the affiliate program',
             dependencies=[DependsJwtAuth, Depends(RateLimiter(times=5, minutes=60))])
async def apply(request: Request, obj: ApplyParam) -> ResponseModel:
    if not obj.accept_terms:
        raise errors.RequestError(msg='Acceptez les conditions du programme de parrainage.')
    if obj.payout_method not in METHODS:
        raise errors.RequestError(msg='Moyen de versement invalide.')
    aff = await affiliate_service.apply(user_id=actor_from(request).id, code=obj.code, full_name=obj.full_name,
                                        payout_phone=obj.payout_phone, payout_method=obj.payout_method)
    return response_base.success(request=request, data={'code': aff.code, 'status': aff.status})


# ---- admin ---------------------------------------------------------------------
def _dt(v: datetime | None):
    return v.isoformat() if v else None


@router.get('/admin/list', summary='[admin] Affiliates with their totals', dependencies=[DependsJwtAuth])
async def admin_list(request: Request, status: Annotated[str | None, Query(max_length=16)] = None) -> ResponseModel:
    require_admin(actor_from(request))
    async with async_db_session() as db:
        q = select(Affiliate, User.email).join(User, User.id == Affiliate.user_id).order_by(Affiliate.id.desc())
        if status:
            q = q.where(Affiliate.status == status)
        rows = (await db.execute(q.limit(200))).all()
        totals = {}
        for aid, st, amt in (await db.execute(
                select(AffiliateCommission.affiliate_id, AffiliateCommission.status, func.sum(AffiliateCommission.amount))
                .group_by(AffiliateCommission.affiliate_id, AffiliateCommission.status))).all():
            totals.setdefault(aid, {})[st] = int(amt or 0)
        referees = dict((await db.execute(select(Referral.referrer_id, func.count(Referral.id))
                                          .group_by(Referral.referrer_id))).all())
    data = [{'id': a.id, 'code': a.code, 'email': email, 'full_name': a.full_name, 'payout_phone': a.payout_phone,
             'payout_method': a.payout_method, 'status': a.status, 'discount_pct': a.discount_pct,
             'commission_pct': a.commission_pct, 'created_time': _dt(a.created_time), 'note': a.note,
             'referees': int(referees.get(a.user_id, 0)),
             'totals': {k: totals.get(a.id, {}).get(k, 0) for k in ('pending', 'available', 'paid', 'rejected')}}
            for a, email in rows]
    return response_base.success(request=request, data={'items': data, 'min_payout': settings.AFFILIATE_MIN_PAYOUT})


@router.post('/admin/{pk}/review', summary='[admin] Approve / suspend / reject an affiliate, set rates',
             dependencies=[DependsJwtAuth])
async def admin_review(request: Request, pk: Annotated[int, Path(...)], obj: ReviewParam) -> ResponseModel:
    actor = actor_from(request)
    require_admin(actor)
    a = await affiliate_service.review(admin_id=actor.id, affiliate_id=pk, status=obj.status,
                                       discount_pct=obj.discount_pct, commission_pct=obj.commission_pct, note=obj.note)
    return response_base.success(request=request, data={'id': a.id, 'status': a.status,
                                                        'discount_pct': a.discount_pct, 'commission_pct': a.commission_pct})


@router.get('/admin/commissions', summary='[admin] Commissions (to pay, pending, history)', dependencies=[DependsJwtAuth])
async def admin_commissions(request: Request, status: Annotated[str | None, Query(max_length=16)] = 'available',
                            affiliate_id: int | None = None) -> ResponseModel:
    require_admin(actor_from(request))
    async with async_db_session() as db:
        q = (select(AffiliateCommission, Affiliate.code, Affiliate.full_name, Affiliate.payout_method,
                    Affiliate.payout_phone, User.email, Payment.amount, Payment.list_price, Payment.payer_phone,
                    Payment.paid_at)
             .join(Affiliate, Affiliate.id == AffiliateCommission.affiliate_id)
             .join(User, User.id == AffiliateCommission.referee_id)
             .join(Payment, Payment.id == AffiliateCommission.payment_id)
             .order_by(AffiliateCommission.id.desc()))
        if status:
            q = q.where(AffiliateCommission.status == status)
        if affiliate_id:
            q = q.where(AffiliateCommission.affiliate_id == affiliate_id)
        rows = (await db.execute(q.limit(300))).all()
    data = [{'id': c.id, 'amount': c.amount, 'status': c.status, 'flags': c.flags, 'note': c.note,
             'available_at': _dt(c.available_at), 'paid_at': _dt(c.paid_at), 'paid_ref': c.paid_ref,
             'created_time': _dt(c.created_time), 'affiliate_id': c.affiliate_id, 'code': code, 'full_name': name,
             'payout_method': method, 'payout_phone': phone, 'referee_email': email, 'paid_amount': amount,
             'list_price': list_price, 'payer_phone': payer, 'payment_date': _dt(paid_at)}
            for c, code, name, method, phone, email, amount, list_price, payer, paid_at in rows]
    return response_base.success(request=request, data=data)


@router.post('/admin/commissions/{pk}', summary='[admin] Mark a commission paid / rejected / available',
             dependencies=[DependsJwtAuth])
async def admin_commission_decide(request: Request, pk: Annotated[int, Path(...)],
                                  obj: CommissionDecisionParam) -> ResponseModel:
    actor = actor_from(request)
    require_admin(actor)
    c = await affiliate_service.decide_commission(admin_id=actor.id, commission_id=pk, action=obj.action,
                                                  paid_ref=obj.paid_ref, note=obj.note)
    return response_base.success(request=request, data={'id': c.id, 'status': c.status})
