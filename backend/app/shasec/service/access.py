"""Tenant scoping for the SaaS: who is calling, and may they touch this row.

Every shasec route resolves an :class:`Actor` from ``request.user`` and passes it
down. Admins see every tenant (and legacy rows with ``owner_id IS NULL``);
everyone else only sees rows they own. A row that exists but belongs to someone
else is reported as *not found*, so ids cannot be probed across tenants.
"""
from dataclasses import dataclass

from fastapi import Request

from backend.common.enums import Role as RoleEnum
from backend.common.exception import errors


@dataclass(frozen=True)
class Actor:
    id: int
    is_admin: bool


def actor_from(request: Request) -> Actor:
    user = request.user
    roles = getattr(user, 'roles', None) or []
    is_admin = any(getattr(r, 'name', None) == RoleEnum.ADMIN.value for r in roles)
    return Actor(id=user.id, is_admin=is_admin)


def require_admin(actor: Actor) -> None:
    if not actor.is_admin:
        raise errors.ForbiddenError(msg='Administrator access required')


def can_access(actor: Actor, owner_id: int | None) -> bool:
    return actor.is_admin or (owner_id is not None and owner_id == actor.id)


def ensure_access(actor: Actor, row, *, not_found: str) -> None:
    if row is None or not can_access(actor, getattr(row, 'owner_id', None)):
        raise errors.NotFoundError(msg=not_found)
