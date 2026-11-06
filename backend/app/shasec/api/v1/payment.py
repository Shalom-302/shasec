"""Online credit purchases (MoneyFusion Mobile Money checkout).

Flow: POST /payments/checkout -> browser goes to the aggregator page -> the
aggregator calls the webhook AND sends the user back to /credits/paiement, which
polls GET /payments/{x_id}. Every path ends in ``verify_and_credit``, which asks
MoneyFusion itself before crediting, exactly once. A cron in the arq worker
(``reconcile_payments``) catches payments whose webhook was lost.
"""
import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Request
from fastapi_limiter.depends import RateLimiter
from sqlalchemy import select
from starlette.background import BackgroundTasks

from backend.app.shasec.schema.payment import CheckoutParam, GetCheckout, GetPayment
from backend.app.shasec.service.access import actor_from
from backend.app.shasec.service.payment_service import enabled, packs, payment_service
from backend.common.exception import errors
from backend.common.log import log
from backend.common.response.response_schema import ResponseModel, response_base
from backend.common.security.jwt import DependsJwtAuth
from backend.core.conf import settings
from backend.database.db_postgres import async_db_session
from backend.models.payment import Payment

router = APIRouter(prefix='/payments', tags=['Payments'])


@router.get('/packs', summary='Packs for sale and whether online payment is on', dependencies=[DependsJwtAuth])
async def get_packs(request: Request) -> ResponseModel:
    return response_base.success(request=request, data={'enabled': enabled(), 'packs': packs()})


@router.post('/checkout', summary='Start a Mobile Money payment for a pack',
             dependencies=[DependsJwtAuth, Depends(RateLimiter(times=10, minutes=10))])
async def checkout(request: Request, obj: CheckoutParam) -> ResponseModel:
    p = await payment_service.create_checkout(user_id=actor_from(request).id, pack_id=obj.pack, phone=obj.phone,
                                             referral_code=obj.referral_code)
    return response_base.success(request=request, data=GetCheckout.model_validate(p))


@router.get('/me', summary='My payments', dependencies=[DependsJwtAuth])
async def my_payments(request: Request) -> ResponseModel:
    async with async_db_session() as db:
        rows = (await db.scalars(
            select(Payment).where(Payment.user_id == actor_from(request).id).order_by(Payment.id.desc()).limit(50)
        )).all()
    return response_base.success(request=request, data=[GetPayment.model_validate(p) for p in rows])


@router.get('/{x_id}', summary='Status of one of my payments (verifies it if still pending)',
            dependencies=[DependsJwtAuth, Depends(RateLimiter(times=60, minutes=5))])
async def payment_status(request: Request, x_id: Annotated[str, Path(max_length=32)]) -> ResponseModel:
    user_id = actor_from(request).id
    async with async_db_session() as db:
        p = await db.scalar(select(Payment).where(Payment.x_id == x_id, Payment.user_id == user_id))
    if not p:
        raise errors.NotFoundError(msg='Paiement introuvable.')
    if p.status == 'pending' and p.reference:
        await payment_service.verify_and_credit(p.reference)
        async with async_db_session() as db:
            p = await db.get(Payment, p.id)
    return response_base.success(request=request, data=GetPayment.model_validate(p))


@router.post('/webhook/{secret}', summary='MoneyFusion notification (public, verified server-side)',
             include_in_schema=False)
async def webhook(request: Request, secret: str, background_tasks: BackgroundTasks) -> dict:
    """Believes NOTHING it receives: only the token is read, then the payment is
    verified with MoneyFusion. Always 200 — an error would trigger useless retries."""
    expected = settings.PAYMENT_WEBHOOK_SECRET or '_'
    if not secrets.compare_digest(secret, expected):
        log.warning('[PAY WEBHOOK] bad URL secret, ignored')
        raise errors.NotFoundError(msg='Not Found')
    try:
        data = await request.json()
    except Exception:  # noqa: BLE001
        return {'status': 'ignored'}
    token = (data or {}).get('tokenPay') or (data or {}).get('token')
    if not token:
        return {'status': 'ignored'}
    background_tasks.add_task(payment_service.verify_and_credit, str(token))
    return {'status': 'received'}
