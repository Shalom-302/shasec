from functools import lru_cache
import os
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from backend.core.path_conf import ApiV2Path


class Settings(BaseSettings):
    """Global settings.

    Every field has a sane development default so the app boots out of the box
    (e.g. ``docker-run.sh up`` with the bundled docker-compose). Override via the
    ``.env`` file for your own setup, and ALWAYS set real secrets in production.
    """

    model_config = SettingsConfigDict(
        env_file=f'{ApiV2Path}/.env', env_file_encoding='utf-8', extra='ignore'
    )

    APP_NAME: str = 'monshaapi'

    # Env Config
    ENVIRONMENT: Literal['dev', 'preprod', 'prod'] = 'dev'

    # Database schema bootstrap: in dev, tables are auto-created on startup for a
    # zero-friction first run. In production set DB_AUTO_CREATE=false and rely on
    # Alembic migrations (`shaapi db generate` / `shaapi db apply`).
    DB_AUTO_CREATE: bool = True

    # Observability (opt-in). When disabled, the OpenTelemetry/Prometheus stack
    # is never imported, keeping the lean core lightweight.
    OBSERVABILITY_ENABLED: bool = False
    OTLP_GRPC_ENDPOINT: str | None = None

    # Postgres
    POSTGRES_HOST: str = 'localhost'
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = 'postgres'
    POSTGRES_PASSWORD: str = 'postgres'
    POSTGRES_ECHO: bool = False
    POSTGRES_DATABASE: str = 'monshaapi'

    CLIENT_URL: str = 'http://localhost:3000'

    # Redis
    REDIS_HOST: str = 'localhost'
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str | None = None
    REDIS_DATABASE: int = 0
    REDIS_TIMEOUT: int = 5

    # Object storage (MinIO / S3-compatible)
    MINIO_ENDPOINT: str = 'localhost:9000'
    MINIO_PORT: int = 9000
    MINIO_ACCESS_KEY: str = 'minioadmin'
    MINIO_SECRET_KEY: str = 'minioadmin'
    MINIO_BUCKET_NAME: str = 'monshaapi'
    MINIO_CLOUD_URL: str = 'http://localhost:9000'

    # shasec AI analysis — DeepSeek (OpenAI-compatible /chat/completions API).
    # Set DEEPSEEK_API_KEY in .env to enable; left empty the analysis stage skips
    # cleanly and the scan still completes. The AI never scans — it interprets the
    # normalized findings + exploit proofs into a score, summary and remediations.
    AI_ANALYSIS_ENABLED: bool = True
    DEEPSEEK_API_KEY: str = ''
    DEEPSEEK_BASE_URL: str = 'https://api.deepseek.com'
    DEEPSEEK_MODEL: str = 'deepseek-chat'
    DEEPSEEK_TIMEOUT: int = 120

    # shasec durability — when true, the scan pipeline is enqueued to an arq worker
    # (Redis) instead of running in-process, so a scan survives an API restart. The
    # worker container and the API must share this flag. Falls back to in-process if
    # the queue can't be reached. Requires a running `arq ...worker.WorkerSettings`.
    SHASEC_USE_ARQ: bool = False

    # SMTP / email (optional: leave blank to disable outgoing mail)
    SMTP_TLS: str = 'True'
    SMTP_PORT: str = '587'
    SMTP_HOST: str = ''
    SMTP_USER: str = ''
    EMAILS_FROM_EMAIL: str = ''
    EMAILS_FROM_NAME: str = ''
    SMTP_PASSWORD: str = ''
    EMAIL_TEMPLATES_DIR: str = os.getcwd() + '/templates/build'

    # Token / crypto secrets — CHANGE THESE IN PRODUCTION
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
    TOKEN_SECRET_KEY: str = 'dev-insecure-change-me-token-secret-key'
    # Generate with: python -c "import os; print(os.urandom(32).hex())"
    OPERA_LOG_ENCRYPT_SECRET_KEY: str = 'dev-insecure-change-me-opera-log-key'

    # Google SSO (optional)
    GOOGLE_CLIENT_ID: str = ''
    GOOGLE_SECRET_KEY: str = ''
    GOOGLE_WEBHOOK_OAUTH_REDIRECT_URI: str = ''

    # FastAPI
    FASTAPI_API_V1_PATH: str = '/api/v1'
    FASTAPI_TITLE: str = 'monshaapi'
    FASTAPI_VERSION: str = '0.0.1'
    FASTAPI_DESCRIPTION: str = 'A lean, batteries-included FastAPI backend.'
    FASTAPI_DOCS_URL: str | None = f'{FASTAPI_API_V1_PATH}/docs'
    FASTAPI_REDOCS_URL: str | None = f'{FASTAPI_API_V1_PATH}/redocs'
    FASTAPI_OPENAPI_URL: str | None = f'{FASTAPI_API_V1_PATH}/openapi'
    FASTAPI_STATIC_FILES: bool = False
    # Interactive docs (Swagger/ReDoc/OpenAPI) are off in prod by default; set true
    # to expose them at /api/v1/docs even in prod (e.g. during bring-up).
    FASTAPI_EXPOSE_DOCS: bool = False

    # Token
    TOKEN_ALGORITHM: str = 'HS256'
    TOKEN_EXPIRE_SECONDS: int = 60 * 60 * 24 * 1  # access token lifetime
    TOKEN_REFRESH_EXPIRE_SECONDS: int = 60 * 60 * 24 * 7  # refresh token lifetime
    TOKEN_REDIS_PREFIX: str = 'monshaapi:token'
    USER_SECURE_TOKEN_REDIS_PREFIX: str = 'monshaapi:user:token'
    ADMIN_SECURE_TOKEN_REDIS_PREFIX: str = 'monshaapi:admin:token'
    TOKEN_REFRESH_REDIS_PREFIX: str = 'monshaapi:refresh_token'
    CAPTCHA_LOGIN_REDIS_PREFIX: str = 'monshaapi:captcha:login'
    TOKEN_REQUEST_PATH_EXCLUDE: list[str] = [  # JWT / RBAC whitelist
        f'{FASTAPI_API_V1_PATH}/auth/login',
        f'{FASTAPI_API_V1_PATH}/auth/token/new',
    ]

    # JWT
    JWT_USER_REDIS_PREFIX: str = 'monshaapi:user'
    JWT_ADMIN_REDIS_PREFIX: str = 'monshaapi:admin'
    JWT_USER_REDIS_EXPIRE_SECONDS: int = 60 * 60 * 24 * 7

    # Permission (RBAC)
    PERMISSION_MODE: Literal['casbin', 'role-menu'] = 'casbin'
    PERMISSION_REDIS_PREFIX: str = 'monshaapi:permission'

    # Casbin RBAC whitelist
    RBAC_CASBIN_EXCLUDE: set[tuple[str, str]] = {
        ('POST', f'{FASTAPI_API_V1_PATH}/auth/logout'),
        ('POST', f'{FASTAPI_API_V1_PATH}/auth/token/new'),
    }

    # Role-Menu
    RBAC_ROLE_MENU_EXCLUDE: list[str] = [
        'sys:monitor:redis',
        'sys:monitor:server',
    ]

    # Cookies
    COOKIE_REFRESH_TOKEN_KEY: str = 'monshaapi_refresh_token'
    COOKIE_REFRESH_TOKEN_EXPIRE_SECONDS: int = TOKEN_REFRESH_EXPIRE_SECONDS
    # Secure cookie flags. 'lax' works for a same-site front/back (e.g.
    # localhost:3000 -> localhost:8000); use 'none' + secure for cross-domain.
    # COOKIE_SECURE is forced on outside dev (see auth_service), so the refresh
    # token is never sent over plain HTTP in production.
    COOKIE_SECURE: bool = False
    COOKIE_SAMESITE: Literal['lax', 'strict', 'none'] = 'lax'

    # Log
    LOG_ROOT_LEVEL: str = 'NOTSET'
    LOG_STD_FORMAT: str = (
        '<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</> | <lvl>{level: <8}</> | '
        '<cyan> {correlation_id} </> | <lvl>{message}</>'
    )
    LOG_LOGURU_FORMAT: str = (
        '<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</> | <lvl>{level: <8}</> | '
        '<cyan> {correlation_id} </> | <lvl>{message}</>'
    )
    LOG_CID_DEFAULT_VALUE: str = '-'
    LOG_CID_UUID_LENGTH: int = 32  # must <= 32
    LOG_STDOUT_LEVEL: str = 'INFO'
    LOG_STDERR_LEVEL: str = 'ERROR'
    LOG_STDOUT_FILENAME: str = 'monshaapi_access.log'
    LOG_STDERR_FILENAME: str = 'monshaapi_error.log'

    # Middleware
    MIDDLEWARE_CORS: bool = True
    MIDDLEWARE_ACCESS: bool = True

    # Trace ID
    TRACE_ID_REQUEST_HEADER_KEY: str = 'X-Request-ID'

    # CORS
    CORS_ALLOWED_ORIGINS: list[str] = [
        'http://localhost:3000',  # Front-end address, no trailing '/'
    ]
    CORS_EXPOSE_HEADERS: list[str] = [
        TRACE_ID_REQUEST_HEADER_KEY,
    ]

    # DateTime
    DATETIME_TIMEZONE: str = 'Africa/Abidjan'
    DATETIME_FORMAT: str = '%Y-%m-%d %H:%M:%S'

    # Request limiter
    REQUEST_LIMITER_REDIS_PREFIX: str = 'monshaapi:limiter'

    # Demo mode (only GET, OPTIONS requests are allowed)
    DEMO_MODE: bool = False
    DEMO_MODE_EXCLUDE: set[tuple[str, str]] = {
        ('POST', f'{FASTAPI_API_V1_PATH}/auth/login'),
        ('POST', f'{FASTAPI_API_V1_PATH}/auth/logout'),
        ('GET', f'{FASTAPI_API_V1_PATH}/auth/captcha'),
    }

    # IP geolocation of requests. Default 'false' (no external call). 'online'
    # sends each client IP to ip-api.com over HTTP (privacy + latency — opt in
    # explicitly). 'offline' needs ip2region.xdb in backend/static/ (~11MB, not
    # shipped): download from https://github.com/lionsoul2014/ip2region
    IP_LOCATION_PARSE: Literal['online', 'offline', 'false'] = 'false'
    IP_LOCATION_REDIS_PREFIX: str = 'monshaapi:ip:location'
    IP_LOCATION_EXPIRE_SECONDS: int = 60 * 60 * 24 * 1

    # Opera log
    OPERA_LOG_PATH_EXCLUDE: list[str] = [
        '/favicon.ico',
        FASTAPI_DOCS_URL,
        FASTAPI_REDOCS_URL,
        FASTAPI_OPENAPI_URL,
        f'{FASTAPI_API_V1_PATH}/auth/login/swagger',
    ]
    OPERA_LOG_ENCRYPT_TYPE: int = 1  # 0: AES; 1: md5; 2: ItsDangerous; 3: plain; other: ******
    OPERA_LOG_ENCRYPT_KEY_INCLUDE: list[str] = [  # values to encrypt in request bodies
        'password',
        'old_password',
        'new_password',
        'confirm_password',
    ]

    @model_validator(mode='after')
    def _enforce_production_safety(self) -> 'Settings':
        """Refuse to boot in a non-dev environment with insecure defaults.

        In ``dev`` everything boots out of the box for a zero-friction first
        run. In ``preprod``/``prod``, leaving a development secret or a default
        infra credential in place is a critical vulnerability (forgeable JWTs,
        world-readable storage), so fail fast with an actionable message instead
        of starting a compromised server.
        """
        if self.ENVIRONMENT == 'dev':
            return self

        insecure: list[str] = []
        if self.TOKEN_SECRET_KEY == 'dev-insecure-change-me-token-secret-key':
            insecure.append(
                'TOKEN_SECRET_KEY  '
                '(generate: python -c "import secrets; print(secrets.token_urlsafe(32))")'
            )
        if self.OPERA_LOG_ENCRYPT_SECRET_KEY == 'dev-insecure-change-me-opera-log-key':
            insecure.append(
                'OPERA_LOG_ENCRYPT_SECRET_KEY  '
                '(generate: python -c "import os; print(os.urandom(32).hex())")'
            )
        if self.POSTGRES_PASSWORD == 'postgres':
            insecure.append('POSTGRES_PASSWORD  (still the default "postgres")')
        if self.MINIO_SECRET_KEY == 'minioadmin':
            insecure.append('MINIO_SECRET_KEY  (still the default "minioadmin")')

        if insecure:
            raise ValueError(
                f'ENVIRONMENT={self.ENVIRONMENT!r} but insecure development defaults '
                'are still in use:\n'
                + '\n'.join(f'  - {item}' for item in insecure)
                + '\nSet real values in your .env before deploying. '
                '(This check only runs outside dev.)'
            )
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the cached global settings instance."""
    return Settings()


# Configuration instance
settings = get_settings()
