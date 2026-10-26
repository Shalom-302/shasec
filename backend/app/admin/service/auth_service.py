from fastapi import Request, Response
from fastapi.security import HTTPBasicCredentials
from datetime import datetime
from starlette.background import BackgroundTask, BackgroundTasks

from backend.app.shasec.service.credit_service import credit_service
from backend.app.shasec.service.otp_service import otp_service
from backend.crud.crud_user import user_dao
from backend.models.user import User
from backend.app.admin.schema.token import GetLoginToken, GetNewToken
from backend.app.admin.schema.user import ResendOtpParam, UserLoginSchema, UserRegister, VerifyOtpParam
from backend.app.admin.service.login_log_service import LoginLogService
from backend.common.enums import LoginLogStatusType
from backend.common.exception import errors
from backend.common.security.jwt import (
    create_access_token,
    create_new_token,
    create_refresh_token,
    get_token,
    jwt_decode,
    password_verify,
)
from backend.core.conf import settings
from backend.database.db_postgres import async_db_session
from backend.database.db_redis import redis_client
from backend.utils.timezone import timezone
from backend.utils.translator import Translator


class AuthService:
    @staticmethod
    async def swagger_login(*, obj: HTTPBasicCredentials) -> tuple[str, User]:
        async with async_db_session.begin() as db:
            current_user = await user_dao.get_by_email(db, obj.username)
            if not current_user:
                raise errors.NotFoundError(msg='Incorrect email or password')
            elif not password_verify(f'{obj.password}{current_user.salt}', current_user.password):
                raise errors.AuthorizationError(msg='Incorrect email or password')
            elif not current_user.status:
                raise errors.AuthorizationError(msg='The user has been locked out. Please contact the system useristrator.')
            access_token = await create_access_token(str(current_user.x_id), False)
            await user_dao.update_login_time(db, obj.username)
            return access_token.access_token, current_user

    @staticmethod
    async def register(
        *, request: Request, response: Response, obj: UserRegister, background_tasks: BackgroundTasks
        ) -> GetLoginToken:
        translator = Translator(request.state.locale)

        async with async_db_session.begin() as db:
            if not obj.password:
                raise errors.ForbiddenError(msg=translator.t('auth.enpty_password'))
            
            email = await user_dao.get_by_email(db, obj.email)
            if email:
                raise errors.ForbiddenError(msg=translator.t('auth.exist'))
            
            new_user = await user_dao.add(db, obj, role_name=settings.REGISTER_DEFAULT_ROLE)
            # Kortex free tier: one-shot discovery scans, granted once per account.
            await credit_service.grant_signup(db, new_user.id)

            # WhatsApp OTP gate: create the account UNVERIFIED, send the code, and
            # return without tokens — the user logs in only after /auth/verify-otp.
            # A gowa failure raises here, rolling back the whole registration so no
            # orphan unverified account is left behind.
            if settings.OTP_ENABLED:
                if not new_user.phone:
                    raise errors.ForbiddenError(msg='Numéro de téléphone requis pour la vérification WhatsApp.')
                new_user.email_verified = False
                await db.flush()
                await otp_service.start(email=new_user.email, phone=new_user.phone)
                return {'otp_required': True, 'email': new_user.email}

            # current_user_id = new_user.x_id
            # is_multi_login = new_user.is_multi_login
            user_x_id = new_user.x_id
            email = new_user.email
            
            access_token = await create_access_token(str(user_x_id), False)
            refresh_token = await create_refresh_token(str(user_x_id), False)

            n_user = await user_dao.get_with_relation(db, x_id=user_x_id, populates=['roles'])
        
            background_tasks.add_task(
                LoginLogService.create,
                **dict(
                    db=db,
                    request=request,
                    user_x_id=user_x_id,
                    email=email,
                    login_time=datetime.now(),
                    status=LoginLogStatusType.success.value,
                    msg=translator.t('auth.successful'),
                )
            )

            # await user_dao.update_login_time(db, obj.email)
            response.set_cookie(
                key=settings.COOKIE_REFRESH_TOKEN_KEY,
                value=refresh_token.refresh_token,
                max_age=settings.COOKIE_REFRESH_TOKEN_EXPIRE_SECONDS,
                expires=timezone.f_utc(refresh_token.refresh_token_expire_time),
                httponly=True,
                samesite=settings.COOKIE_SAMESITE,
                secure=settings.COOKIE_SECURE or settings.ENVIRONMENT != 'dev',
            )
            
            data = GetLoginToken(
                access_token=access_token.access_token,
                access_token_expire_time=access_token.access_token_expire_time,
                user=n_user,  # type: ignore
            )
            return data


    @staticmethod
    async def login(
        *, request: Request, response: Response, obj: UserLoginSchema, background_tasks: BackgroundTasks
    ) -> GetLoginToken:
        translator = Translator(request.state.locale)

        async with async_db_session.begin() as db:
            try:
                current_user = await user_dao.get_by_email(db, email=obj.email, populates=['roles'])
                if not current_user:
                    raise errors.NotFoundError(msg=translator.t('auth.incorrect_credential'))

                user_x_id = current_user.x_id
                email = current_user.email

                if not password_verify(obj.password + current_user.salt, current_user.password):
                    raise errors.AuthorizationError(msg=translator.t('auth.incorrect_credential'))
                elif not current_user.status:
                    raise errors.AuthorizationError(msg=translator.t('auth.account_locked'))
                elif settings.OTP_ENABLED and not current_user.email_verified:
                    # Recognisable message so the web can route to the OTP screen.
                    raise errors.AuthorizationError(msg='OTP_REQUIRED: compte non vérifié, entrez le code reçu par WhatsApp.')

                access_token = await create_access_token(str(user_x_id), settings.TOKEN_MULTI_LOGIN)
                refresh_token = await create_refresh_token(str(user_x_id), settings.TOKEN_MULTI_LOGIN)

            except errors.NotFoundError as e:
                raise errors.NotFoundError(msg=e.msg)
            except (errors.AuthorizationError, errors.CustomError) as e:
                task = BackgroundTask(
                    LoginLogService.create,
                    **dict(
                        db=db,
                        request=request,
                        user_x_id=user_x_id,
                        email=email,
                        login_time=datetime.now(),
                        status=LoginLogStatusType.fail.value,
                        msg=e.msg,
                    ),
                )
                raise errors.AuthorizationError(msg=e.msg, background=task)
            except Exception as e:
                raise e
            else:
                background_tasks.add_task(
                    LoginLogService.create,
                    **dict(
                        db=db,
                        request=request,
                        user_x_id=user_x_id,
                        email=email,
                        login_time=datetime.now(),
                        status=LoginLogStatusType.success.value,
                        msg=translator.t('auth.successful'),
                    ),
                )
                # await redis_client.delete(f'{user_settings.CAPTCHA_LOGIN_REDIS_PREFIX}:{request.state.ip}')

                await user_dao.update_login_time(db, obj.email)
                response.set_cookie(
                    key=settings.COOKIE_REFRESH_TOKEN_KEY,
                    value=refresh_token.refresh_token,
                    max_age=settings.COOKIE_REFRESH_TOKEN_EXPIRE_SECONDS,
                    expires=timezone.f_utc(refresh_token.refresh_token_expire_time),
                    httponly=True,
                    samesite='none'
                )
                await db.refresh(current_user)
                data = GetLoginToken(
                    access_token=access_token.access_token,
                    access_token_expire_time=access_token.access_token_expire_time,
                    user=current_user,  # type: ignore
                )
                return data


    @staticmethod
    @staticmethod
    async def verify_otp(*, request: Request, response: Response, obj: VerifyOtpParam) -> GetLoginToken:
        translator = Translator(request.state.locale)
        async with async_db_session.begin() as db:
            user = await user_dao.get_with_relation(db, email=obj.email, populates=['roles'])
            if not user:
                raise errors.NotFoundError(msg=translator.t('auth.incorrect_credential'))
            if not user.email_verified:
                await otp_service.verify(obj.email, obj.code)  # raises on bad/expired code
                user.email_verified = True
                await db.flush()
            x_id = user.x_id
            access_token = await create_access_token(str(x_id), settings.TOKEN_MULTI_LOGIN)
            refresh_token = await create_refresh_token(str(x_id), settings.TOKEN_MULTI_LOGIN)
            n_user = await user_dao.get_with_relation(db, x_id=x_id, populates=['roles'])
        response.set_cookie(
            key=settings.COOKIE_REFRESH_TOKEN_KEY,
            value=refresh_token.refresh_token,
            max_age=settings.COOKIE_REFRESH_TOKEN_EXPIRE_SECONDS,
            expires=timezone.f_utc(refresh_token.refresh_token_expire_time),
            httponly=True,
            samesite=settings.COOKIE_SAMESITE,
            secure=settings.COOKIE_SECURE or settings.ENVIRONMENT != 'dev',
        )
        return GetLoginToken(
            access_token=access_token.access_token,
            access_token_expire_time=access_token.access_token_expire_time,
            user=n_user,  # type: ignore
        )

    @staticmethod
    async def resend_otp(*, request: Request, obj: ResendOtpParam) -> dict:
        translator = Translator(request.state.locale)
        async with async_db_session() as db:
            user = await user_dao.get_by_email(db, obj.email)
        if not user:
            raise errors.NotFoundError(msg=translator.t('auth.incorrect_credential'))
        if user.email_verified:
            raise errors.ForbiddenError(msg='Ce compte est déjà vérifié.')
        if not user.phone:
            raise errors.ForbiddenError(msg='Aucun numéro associé à ce compte.')
        if not await otp_service.can_resend(obj.email):
            raise errors.ForbiddenError(msg='Patientez un instant avant de redemander un code.')
        await otp_service.start(email=obj.email, phone=user.phone)
        await otp_service.mark_resent(obj.email)
        return {'sent': True}

    @staticmethod
    async def new_token(*, request: Request, response: Response) -> GetNewToken:
        translator = Translator(request.state.locale)
        refresh_token = request.cookies.get(settings.COOKIE_REFRESH_TOKEN_KEY)

        if not refresh_token:
            raise errors.TokenError(msg=translator.t('auth.refresh_token_not_found'))
        try:
            user_x_id = jwt_decode(refresh_token)
        except Exception:
            raise errors.TokenError(msg=translator.t('auth.invalid_refresh_token'))
        # if request.user.id != user_id:
        #     raise errors.TokenError(msg='Refresh Token is invalid')
        async with async_db_session() as db:
            current_user = await user_dao.get_by_x_id(db, user_x_id)
            if not current_user:
                raise errors.NotFoundError(msg=translator.t('auth.incorrect_credential'))
            elif not current_user.status:
                raise errors.AuthorizationError(msg=translator.t('auth.account_locked'))
            current_token = get_token(request)
            new_token = await create_new_token(
                sub=str(current_user.x_id),
                token=current_token,
                refresh_token=refresh_token,
                multi_login=settings.TOKEN_MULTI_LOGIN,
            )
            response.set_cookie(
                key=settings.COOKIE_REFRESH_TOKEN_KEY,
                value=new_token.new_refresh_token,
                max_age=settings.COOKIE_REFRESH_TOKEN_EXPIRE_SECONDS,
                expires=timezone.f_utc(new_token.new_refresh_token_expire_time),
                httponly=True,
                samesite=settings.COOKIE_SAMESITE,
                secure=settings.COOKIE_SECURE or settings.ENVIRONMENT != 'dev',
            )
            data = GetNewToken(
                access_token=new_token.new_access_token,
                access_token_expire_time=new_token.new_access_token_expire_time,
            )
            return data


    @staticmethod
    async def logout(*, request: Request, response: Response) -> None:
        token = get_token(request)
        refresh_token = request.cookies.get(settings.COOKIE_REFRESH_TOKEN_KEY)
        response.delete_cookie(settings.COOKIE_REFRESH_TOKEN_KEY)
        # if request.user.is_multi_login:
        #     key = f'{settings.TOKEN_REDIS_PREFIX}:{request.user.id}:{token}'
        #     await redis_client.delete(key)
        #     if refresh_token:
        #         key = f'{settings.TOKEN_REFRESH_REDIS_PREFIX}:{request.user.id}:{refresh_token}'
        #         await redis_client.delete(key)
        # else:
        if settings.TOKEN_MULTI_LOGIN:
            # Multi-session: log out ONLY this session, leave the user's other
            # tabs/devices signed in.
            await redis_client.delete(f'{settings.TOKEN_REDIS_PREFIX}:{request.user.x_id}:{token}')
            if refresh_token:
                await redis_client.delete(f'{settings.TOKEN_REFRESH_REDIS_PREFIX}:{request.user.x_id}:{refresh_token}')
        else:
            key_prefix = f'{settings.TOKEN_REDIS_PREFIX}:{request.user.x_id}:'
            await redis_client.delete_prefix(key_prefix)
            key_prefix = f'{settings.TOKEN_REFRESH_REDIS_PREFIX}:{request.user.x_id}:'
            await redis_client.delete_prefix(key_prefix)


auth_service = AuthService()
