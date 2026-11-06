from math import ceil

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from pydantic.errors import PydanticUserError
from starlette.exceptions import HTTPException
from starlette.middleware.cors import CORSMiddleware
from uvicorn.protocols.http.h11_impl import STATUS_PHRASES

from backend.common.exception.errors import BaseExceptionMixin
from backend.common.response.response_code import CustomResponseCode, StandardResponseCode
from backend.common.response.response_schema import response_base
from backend.common.schema import (
    CUSTOM_USAGE_ERROR_MESSAGES,
    CUSTOM_VALIDATION_ERROR_MESSAGES,
)
from backend.core.conf import settings
from backend.utils.serializers import MsgSpecJSONResponse
from backend.utils.trace_id import get_request_trace_id
from backend.utils.translator import Translator


def _get_exception_code(status_code: int):
    """
    Get return status code, OpenAPI, Uvicorn... The available status codes are based on the RFC definitions, see the link below for detailed code.

    `python Status Code Standard Support <https://github.com/python/cpython/blob/6e3cc72afeaee2532b4327776501eb8234ac787b/Lib/http
    /__init__.py#L7>`__

    `IANA status code registry <https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml>`__

    :param status_code:
    :return:
    """
    try:
        STATUS_PHRASES[status_code]
    except Exception:
        code = StandardResponseCode.HTTP_400
    else:
        code = status_code
    return code


_FIELD_FR = {
    'url': 'URL', 'email': 'Email', 'password': 'Mot de passe', 'new_password': 'Nouveau mot de passe',
    'phone': 'Téléphone', 'name': 'Nom', 'code': 'Code', 'profile': 'Profil', 'type': 'Type',
    'message': 'Message', 'pack': 'Offre', 'target_id': 'Application',
}
_TYPE_FR = {
    'missing': 'ce champ est obligatoire.',
    'string_too_short': 'trop court.',
    'string_too_long': 'trop long.',
    'string_type': 'doit être un texte.',
    'int_parsing': 'doit être un nombre entier.',
    'int_type': 'doit être un nombre entier.',
    'bool_parsing': 'doit être vrai ou faux.',
    'enum': 'valeur non autorisée.',
    'literal_error': 'valeur non autorisée.',
    'greater_than_equal': 'valeur trop petite.',
    'less_than_equal': 'valeur trop grande.',
    'too_long': 'trop d’éléments.',
}


def _field_of(error: dict) -> str:
    loc = [str(x) for x in (error.get('loc') or ()) if str(x) not in ('body', 'query', 'path')]
    return loc[-1] if loc else ''


def _public_validation_message(error: dict) -> str:
    """One clear French sentence for a validation error.

    Our own validators raise ValueError with a message written for the user:
    keep it as is (pydantic prefixes it with "Value error, "). Built-in errors
    get a French wording naming the field. A model-level validator (e.g. the
    target URL check) reports an empty loc — handled without crashing."""
    field = _field_of(error)
    ctx_error = (error.get('ctx') or {}).get('error')
    if error.get('type') in ('value_error', 'assertion_error') and ctx_error:
        text = str(ctx_error)
        for prefix in ('Value error, ', 'Assertion failed, '):
            if text.startswith(prefix):
                text = text[len(prefix):]
        return text
    if error.get('type') == 'value_error' and error.get('msg', '').startswith('Value error, '):
        return error['msg'][len('Value error, '):]
    label = _FIELD_FR.get(field, field)
    detail = _TYPE_FR.get(error.get('type', ''))
    if field == 'email' or error.get('type') == 'value_error' and 'email' in str(error.get('msg', '')).lower():
        return 'Adresse email invalide.'
    if detail:
        return f'{label} : {detail}' if label else detail.capitalize()
    return f'{label} : valeur invalide.' if label else 'Données invalides.'


async def _validation_exception_handler(request: Request, e: RequestValidationError | ValidationError):
    """
    Data Validation Exception Handling

    :param e:
    :return:
    """
    errors = []
    for error in e.errors():
        custom_message = CUSTOM_VALIDATION_ERROR_MESSAGES.get(error['type'])
        if custom_message:
            ctx = error.get('ctx')
            if not ctx:
                error['msg'] = custom_message
            else:
                error['msg'] = custom_message.format(**ctx)
                ctx_error = ctx.get('error')
                if ctx_error:
                    error['ctx']['error'] = (
                        ctx_error.__str__().replace("'", '"') if isinstance(ctx_error, Exception) else None
                    )
        errors.append(error)
    error = errors[0]
    if error.get('type') == 'json_invalid':
        message = 'Requête invalide (JSON mal formé).'
    else:
        message = _public_validation_message(error)
    # User-facing: a clear French sentence, never "Illegal request parameters" nor
    # the submitted value. `data.errors` carries {field, msg} so the UI can point
    # at the right input (no input echo, safe in prod).
    msg = message
    data = {'errors': [{'field': _field_of(err), 'msg': _public_validation_message(err)} for err in errors]}
    if settings.ENVIRONMENT == 'dev':
        data['raw'] = errors
    content = {
        'code': StandardResponseCode.HTTP_422,
        'msg': msg,
        'data': data,
    }
    request.state.__request_validation_exception__ = content  # 用于在中间件中获取异常信息
    content.update(trace_id=get_request_trace_id(request))
    return MsgSpecJSONResponse(status_code=422, content=content)


def register_exception(app: FastAPI):
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """
        Global HTTP Exception Handling

        :param request:
        :param exc:
        :return:
        """
        if settings.ENVIRONMENT == 'dev':
            content = {
                'code': exc.status_code,
                'msg': exc.detail,
                'data': None,
            }
        elif exc.status_code == 429:
            # Rate limits are expected user-facing errors: say so, and when to retry.
            retry_after = int((exc.headers or {}).get('Retry-After', 60))
            content = {
                'code': 429,
                'msg': Translator(getattr(request.state, 'locale', 'fr')).t('app.too_many_attempts', minutes=max(1, ceil(retry_after / 60))),
                'data': None,
            }
        else:
            res = response_base.fail(request=request, res=CustomResponseCode.HTTP_400)
            content = res.model_dump()
        request.state.__request_http_exception__ = content
        content.update(trace_id=get_request_trace_id(request))
        return MsgSpecJSONResponse(
            status_code=_get_exception_code(exc.status_code),
            content=content,
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def fastapi_validation_exception_handler(request: Request, exc: RequestValidationError):
        """
        fastapi Data Validation Exception Handling

        :param request:
        :param exc:
        :return:
        """
        return await _validation_exception_handler(request, exc)

    @app.exception_handler(ValidationError)
    async def pydantic_validation_exception_handler(request: Request, exc: ValidationError):
        """
        pydantic Data Validation Exception Handling

        :param request:
        :param exc:
        :return:
        """
        return await _validation_exception_handler(request, exc)

    @app.exception_handler(PydanticUserError)
    async def pydantic_user_error_handler(request: Request, exc: PydanticUserError):
        """
        Pydantic User Exception Handling

        :param request:
        :param exc:
        :return:
        """
        content = {
            'code': StandardResponseCode.HTTP_500,
            'msg': CUSTOM_USAGE_ERROR_MESSAGES.get(exc.code),
            'data': None,
        }
        request.state.__request_pydantic_user_error__ = content
        content.update(trace_id=get_request_trace_id(request))
        return MsgSpecJSONResponse(
            status_code=StandardResponseCode.HTTP_500,
            content=content,
        )

    @app.exception_handler(AssertionError)
    async def assertion_error_handler(request: Request, exc: AssertionError):
        """
        assertion error handling

        :param request:
        :param exc:
        :return:
        """
        if settings.ENVIRONMENT == 'dev':
            content = {
                'code': StandardResponseCode.HTTP_500,
                'msg': str(''.join(exc.args) if exc.args else exc.__doc__),
                'data': None,
            }
        else:
            res = response_base.fail(request=request, res=CustomResponseCode.HTTP_500)
            content = res.model_dump()
        request.state.__request_assertion_error__ = content
        content.update(trace_id=get_request_trace_id(request))
        return MsgSpecJSONResponse(
            status_code=StandardResponseCode.HTTP_500,
            content=content,
        )

    @app.exception_handler(BaseExceptionMixin)
    async def custom_exception_handler(request: Request, exc: BaseExceptionMixin):
        """
        Global custom exception handling

        :param request:
        :param exc:
        :return:
        """
        content = {
            'code': exc.code,
            'msg': str(exc.msg),
            'data': exc.data if exc.data else None,
        }
        request.state.__request_custom_exception__ = content
        content.update(trace_id=get_request_trace_id(request))
        return MsgSpecJSONResponse(
            status_code=_get_exception_code(exc.code),
            content=content,
            background=exc.background,
        )

    @app.exception_handler(Exception)
    async def all_unknown_exception_handler(request: Request, exc: Exception):
        """
        global unknown exception handling (GUE)

        :param request:
        :param exc:
        :return:
        """
        if settings.ENVIRONMENT == 'dev':
            content = {
                'code': StandardResponseCode.HTTP_500,
                'msg': str(exc),
                'data': None,
            }
        else:
            res = response_base.fail(request=request, res=CustomResponseCode.HTTP_500)
            content = res.model_dump()
        request.state.__request_all_unknown_exception__ = content
        content.update(trace_id=get_request_trace_id(request))
        return MsgSpecJSONResponse(
            status_code=StandardResponseCode.HTTP_500,
            content=content,
        )

    if settings.MIDDLEWARE_CORS:

        @app.exception_handler(StandardResponseCode.HTTP_500)
        async def cors_custom_code_500_exception_handler(request, exc):
            """
            Cross Domain Customization 500 Exception Handling

            `Related issue <https://github.com/encode/starlette/issues/1175>`_
            `Solution <https://github.com/fastapi/fastapi/discussions/7847#discussioncomment-5144709>`_

            :param request:
            :param exc:
            :return:
            """
            if isinstance(exc, BaseExceptionMixin):
                content = {
                    'code': exc.code,
                    'msg': exc.msg,
                    'data': exc.data,
                }
            else:
                if settings.ENVIRONMENT == 'dev':
                    content = {
                        'code': StandardResponseCode.HTTP_500,
                        'msg': str(exc),
                        'data': None,
                    }
                else:
                    res = response_base.fail(request=request, res=CustomResponseCode.HTTP_500)
                    content = res.model_dump()
            request.state.__request_cors_500_exception__ = content
            content.update(trace_id=get_request_trace_id(request))
            response = MsgSpecJSONResponse(
                status_code=exc.code if isinstance(exc, BaseExceptionMixin) else StandardResponseCode.HTTP_500,
                content=content,
                background=exc.background if isinstance(exc, BaseExceptionMixin) else None,
            )
            origin = request.headers.get('origin')
            if origin:
                cors = CORSMiddleware(
                    app=app,
                    allow_origins=settings.CORS_ALLOWED_ORIGINS,
                    allow_credentials=True,
                    allow_methods=['*'],
                    allow_headers=['*'],
                    expose_headers=settings.CORS_EXPOSE_HEADERS,
                )
                response.headers.update(cors.simple_headers)
                has_cookie = 'cookie' in request.headers
                if cors.allow_all_origins and has_cookie:
                    response.headers['Access-Control-Allow-Origin'] = origin
                elif not cors.allow_all_origins and cors.is_allowed_origin(origin=origin):
                    response.headers['Access-Control-Allow-Origin'] = origin
                    response.headers.add_vary_header('Origin')
            return response
