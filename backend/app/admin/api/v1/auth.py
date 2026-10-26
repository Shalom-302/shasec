from fastapi import APIRouter, Depends, Request, Response
from fastapi_limiter.depends import RateLimiter
from starlette.background import BackgroundTasks

from backend.app.admin.schema.user import (
    GetCurrentUserInfoDetail,
    ResendOtpParam,
    # UpdatePasswordParam,
    UserLoginSchema,
    UserRegister,
    VerifyOtpParam,
)
from backend.app.admin.service.auth_service import auth_service
# from backend.app.user.service.user_service import user_service
from backend.common.response.response_schema import ResponseModel, response_base
from backend.common.security.jwt import DependsJwtAuth

router = APIRouter(prefix="/auth", tags=["User Auth"])


@router.post(
    '/register',
    summary='registered user',
    # Per-IP guard, kept loose (CI mobile carriers share IPs); the real anti-spam
    # limit is per phone number in otp_service.
    dependencies=[Depends(RateLimiter(times=10, minutes=10))],
)
async def register_user(request: Request, response: Response, obj: UserRegister, background_tasks: BackgroundTasks) -> ResponseModel:
    data = await auth_service.register(request=request, response=response, obj=obj, background_tasks=background_tasks)
    
    return response_base.success(request=request, data=data)


@router.post(
    '/login',
    summary='user login',
    description='json format, only supports debugging in third-party api tools, e.g. postman.',
    dependencies=[Depends(RateLimiter(times=5, minutes=1))],  # brute-force guard
)
async def user_login(
    request: Request, response: Response, obj: UserLoginSchema, background_tasks: BackgroundTasks
) -> ResponseModel:
    data = await auth_service.login(request=request, response=response, obj=obj, background_tasks=background_tasks)
    return response_base.success(request=request, data=data)


@router.post(
    '/verify-otp',
    summary='Verify the WhatsApp sign-up code and activate the account',
    dependencies=[Depends(RateLimiter(times=10, minutes=10))],
)
async def verify_otp(request: Request, response: Response, obj: VerifyOtpParam) -> ResponseModel:
    data = await auth_service.verify_otp(request=request, response=response, obj=obj)
    return response_base.success(request=request, data=data)


@router.post(
    '/resend-otp',
    summary='Resend the WhatsApp sign-up code',
    dependencies=[Depends(RateLimiter(times=3, minutes=10))],
)
async def resend_otp(request: Request, obj: ResendOtpParam) -> ResponseModel:
    data = await auth_service.resend_otp(request=request, obj=obj)
    return response_base.success(request=request, data=data)


@router.post('/token/new', summary='Create a new token', dependencies=[DependsJwtAuth])
async def create_new_token(request: Request, response: Response) -> ResponseModel:
    data = await auth_service.new_token(request=request, response=response)
    return response_base.success(request=request, data=data)


@router.post('/logout', summary='user logout', dependencies=[DependsJwtAuth])
async def user_logout(request: Request, response: Response) -> ResponseModel:
    await auth_service.logout(request=request, response=response)
    return response_base.success(request=request)


@router.get('/me', summary='Get connected user profile', dependencies=[DependsJwtAuth], response_model_exclude={'password'})
async def get_current_user(request: Request) -> ResponseModel:
    data = GetCurrentUserInfoDetail(**request.user.model_dump())
    return response_base.success(request=request, data=data)






