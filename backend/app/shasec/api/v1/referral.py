from fastapi import APIRouter, Request

from backend.app.shasec.service.access import actor_from
from backend.app.shasec.service.referral_service import referral_service
from backend.common.response.response_schema import ResponseModel, response_base
from backend.common.security.jwt import DependsJwtAuth
from backend.database.db_postgres import async_db_session

router = APIRouter(prefix='/referrals', tags=['Referrals'])


@router.get('/me', summary='My referral code, link and earnings', dependencies=[DependsJwtAuth])
async def my_referral(request: Request) -> ResponseModel:
    async with async_db_session.begin() as db:
        data = await referral_service.summary(db, actor_from(request).id)
    return response_base.success(request=request, data=data)
