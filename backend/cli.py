"""Project management commands that run *inside* the api container.

The host ``shaapi`` wrapper invokes these over ``docker compose exec``. For
example ``shaapi auth init`` runs, inside the container::

    python -m backend.cli create-admin --email you@example.com --password ...
    python -m backend.cli create-user  --email client@example.com --password ...

Kept on argparse + asyncio (stdlib only) so it has no extra dependency beyond
the backend itself.
"""
from __future__ import annotations

import argparse
import asyncio


async def create_admin(email: str, password: str) -> int:
    """Create an admin user (idempotent) so you can log into Swagger."""
    from backend.app.admin.schema.user import UserRegister
    from backend.common.enums import Role as RoleEnum
    from backend.crud.crud_role import role_dao
    from backend.crud.crud_user import user_dao
    from backend.database.db_postgres import async_db_session
    from backend.models import Role

    async with async_db_session() as db:
        if await user_dao.get_by_email(db, email) is not None:
            print(f"[skip] A user with email {email} already exists.")
            return 0

        # user_dao.add() attaches the admin role *by name*, so make sure it
        # exists first. The Role model has no data_scope column, so we build it
        # directly rather than through CreateRoleParam.
        if await role_dao.get_by_name(db, RoleEnum.ADMIN.value) is None:
            db.add(Role(name=RoleEnum.ADMIN.value))
            await db.flush()

        await user_dao.add(db, UserRegister(email=email, password=password))
        await db.commit()

    print(f"[ok] Admin user created: {email}")
    print("     Log in at /admin/api/v1/docs with this email and password.")
    return 0


async def create_user(email: str, password: str) -> int:
    """Create a regular client account (idempotent), as self-registration does
    — same default role and signup credits — but without the public rate limit."""
    from backend.app.admin.schema.user import UserRegister
    from backend.app.shasec.service.credit_service import credit_service
    from backend.core.conf import settings
    from backend.crud.crud_user import user_dao
    from backend.database.db_postgres import async_db_session

    async with async_db_session() as db:
        if await user_dao.get_by_email(db, email) is not None:
            print(f"[skip] A user with email {email} already exists.")
            return 0

        user = await user_dao.add(db, UserRegister(email=email, password=password), role_name=settings.REGISTER_DEFAULT_ROLE)
        await credit_service.grant_signup(db, user.id)
        await db.commit()

    print(f"[ok] User created: {email} (role: {settings.REGISTER_DEFAULT_ROLE})")
    return 0


async def set_password(email: str, password: str) -> int:
    """Recovery path for a forgotten password (e.g. the admin account, which has
    no phone so it can't use the WhatsApp reset): set a new password, re-enable
    the account, mark it verified and kill every open session."""
    from backend.common.security.jwt import get_hash_password
    from backend.core.conf import settings
    from backend.crud.crud_user import user_dao
    from backend.database.db_postgres import async_db_session
    from backend.database.db_redis import redis_client

    if len(password) < 8:
        print('[error] Password must be at least 8 characters.')
        return 1
    async with async_db_session.begin() as db:
        user = await user_dao.get_by_email(db, email)
        if user is None:
            print(f'[error] No user with email {email}.')
            return 1
        await user_dao.reset_password(db, user.id, get_hash_password(f'{password}{user.salt}'))
        user.status = True
        user.email_verified = True
        x_id = user.x_id
    # Sessions are keyed by x_id (see common/security/jwt.py).
    await redis_client.delete_prefix(f'{settings.TOKEN_REDIS_PREFIX}:{x_id}:')
    await redis_client.delete_prefix(f'{settings.TOKEN_REFRESH_REDIS_PREFIX}:{x_id}:')
    await redis_client.delete_prefix(f'{settings.JWT_USER_REDIS_PREFIX}:{x_id}')
    print(f'[ok] Password updated for {email}. Existing sessions were closed.')
    return 0


async def list_admins() -> int:
    """Print admin accounts (to find the email you forgot)."""
    from sqlalchemy import select

    from backend.common.enums import Role as RoleEnum
    from backend.database.db_postgres import async_db_session
    from backend.models import Role, User

    async with async_db_session() as db:
        rows = await db.execute(
            select(User.email, User.status, User.last_login_time)
            .join(User.roles).where(Role.name == RoleEnum.ADMIN.value)
        )
        for email, status, last_login in rows:
            print(f'{email}\tactive={bool(status)}\tlast_login={last_login}')
    return 0


def storage_init() -> int:
    """Ensure the configured object-storage bucket exists."""
    # Importing the singleton constructs the client, which creates the bucket
    # if it is missing (see MinioStorage.__init__).
    from backend.common.cloud_storage import mstorage
    from backend.core.conf import settings

    bucket = settings.MINIO_BUCKET_NAME
    if not mstorage.client.bucket_exists(bucket):
        mstorage.create_bucket()
        print(f"[ok] Created bucket: {bucket}")
    else:
        print(f"[skip] Bucket already exists: {bucket}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="backend.cli", description="monshaapi project management commands"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    ca = sub.add_parser("create-admin", help="Create an admin user")
    ca.add_argument("--email", required=True, help="Admin email (login).")
    ca.add_argument("--password", required=True, help="Admin password.")

    cu = sub.add_parser("create-user", help="Create a regular client user")
    cu.add_argument("--email", required=True, help="User email (login).")
    cu.add_argument("--password", required=True, help="User password.")

    sp = sub.add_parser("set-password", help="Reset a user's password (forgotten admin password)")
    sp.add_argument("--email", required=True, help="Account email.")
    sp.add_argument("--password", required=True, help="New password (>= 8 chars).")

    sub.add_parser("list-admins", help="List admin accounts")
    sub.add_parser("storage-init", help="Ensure the object-storage bucket exists")

    args = parser.parse_args()
    if args.command == "set-password":
        return asyncio.run(set_password(args.email, args.password))
    if args.command == "list-admins":
        return asyncio.run(list_admins())
    if args.command == "create-admin":
        return asyncio.run(create_admin(args.email, args.password))
    if args.command == "create-user":
        return asyncio.run(create_user(args.email, args.password))
    if args.command == "storage-init":
        return storage_init()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
