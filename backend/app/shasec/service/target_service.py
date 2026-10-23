import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

import httpx
from sqlalchemy import Select

from backend.app.shasec.schema.target import CreateTargetParam, UpdateTargetParam
from backend.app.shasec.service.access import Actor, ensure_access
from backend.common.enums import TargetType
from backend.common.exception import errors
from backend.core.conf import settings
from backend.crud.crud_target import target_dao
from backend.database.db_postgres import async_db_session
from backend.models import Target
from backend.utils.timezone import timezone

_VERIFY_MAX_BYTES = 4096


def verify_url(target: Target) -> str:
    """Where the owner must serve the verify token: origin of the target URL."""
    raw = target.url.strip()
    parsed = urlparse(raw if '://' in raw else f'https://{raw}')
    scheme = parsed.scheme if parsed.scheme in ('http', 'https') else 'https'
    return f'{scheme}://{parsed.netloc}{settings.TARGET_VERIFY_PATH}'


async def _resolves_public(host: str) -> bool:
    # Re-check at fetch time (not only at creation): the backend must never be
    # steered into fetching an internal address through DNS.
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, None)
    except OSError:
        return False
    for *_, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return bool(infos)


class TargetService:
    @staticmethod
    async def get_by_id(*, actor: Actor, pk: int) -> Target:
        async with async_db_session() as db:
            target = await target_dao.get(db, pk)
            ensure_access(actor, target, not_found='Target not found')
            return target

    @staticmethod
    async def get_select(*, actor: Actor, name: str = None, type: str = None) -> Select:
        owner_id = None if actor.is_admin else actor.id
        return await target_dao.get_list(name=name, type=type, owner_id=owner_id)

    @staticmethod
    async def create(*, actor: Actor, obj: CreateTargetParam) -> Target:
        async with async_db_session.begin() as db:
            existing = await target_dao.select_model_by_column(db, url=obj.url, owner_id=actor.id)
            if existing:
                raise errors.ConflictError(msg='This target is already registered on your account')
            target = await target_dao.create(db, obj, owner_id=actor.id)
            await db.flush()
            return target

    @staticmethod
    async def update(*, actor: Actor, pk: int, obj: UpdateTargetParam) -> int:
        async with async_db_session.begin() as db:
            target = await target_dao.get(db, pk)
            ensure_access(actor, target, not_found='Target not found')
            data = obj.model_dump(exclude_unset=True)
            if not actor.is_admin:
                # Scope approval is earned through the ownership proof, never set.
                data.pop('is_authorized', None)
                if data.get('url') and data['url'] != target.url:
                    data.update(is_authorized=False, verified_at=None)
            return await target_dao.update(db, pk, data)

    @staticmethod
    async def set_authorization(*, actor: Actor, pk: int, is_authorized: bool) -> int:
        async with async_db_session.begin() as db:
            target = await target_dao.get(db, pk)
            ensure_access(actor, target, not_found='Target not found')
            if is_authorized and not actor.is_admin:
                raise errors.ForbiddenError(
                    msg='Prove ownership of the target (POST /targets/{id}/verify) to authorize it.'
                )
            return await target_dao.update(db, pk, {'is_authorized': is_authorized})

    @staticmethod
    async def verify(*, actor: Actor, pk: int) -> Target:
        """Ownership proof: fetch ``TARGET_VERIFY_PATH`` on the target origin and
        authorize the target when it serves this target's verify token."""
        async with async_db_session() as db:
            target = await target_dao.get(db, pk)
            ensure_access(actor, target, not_found='Target not found')
            token, url = target.verify_token, verify_url(target)

        host = urlparse(url).hostname or ''
        if target.type == TargetType.host.value and not host:
            raise errors.RequestError(msg='Target host is invalid')
        if not await _resolves_public(host):
            raise errors.RequestError(msg='Target host does not resolve to a public address')

        body = ''
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=False, verify=True) as client:
                async with client.stream('GET', url, headers={'User-Agent': 'KortexSecurity-Verify/1.0'}) as resp:
                    if resp.status_code == 200:
                        chunks = []
                        size = 0
                        async for chunk in resp.aiter_bytes():
                            chunks.append(chunk)
                            size += len(chunk)
                            if size >= _VERIFY_MAX_BYTES:
                                break
                        body = b''.join(chunks)[:_VERIFY_MAX_BYTES].decode('utf-8', 'replace')
                    else:
                        raise errors.RequestError(
                            msg=f'Verification file not found ({resp.status_code}) at {url}'
                        )
        except httpx.HTTPError:
            raise errors.RequestError(msg=f'Could not reach {url} to verify ownership')

        if token not in body:
            raise errors.RequestError(msg=f'Verification token not found in {url}')

        async with async_db_session.begin() as db:
            await target_dao.update(db, pk, {'is_authorized': True, 'verified_at': timezone.now()})
        async with async_db_session() as db:
            return await target_dao.get(db, pk)

    @staticmethod
    async def delete(*, actor: Actor, pk: list[int]) -> int:
        async with async_db_session.begin() as db:
            for target_id in pk:
                ensure_access(actor, await target_dao.get(db, target_id), not_found='Target not found')
            return await target_dao.delete(db, pk)


target_service: TargetService = TargetService()
