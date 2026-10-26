from sqlalchemy import Select

from backend.app.shasec.schema.target import CreateTargetParam, UpdateTargetParam
from backend.app.shasec.service.access import Actor, ensure_access
from backend.common.exception import errors
from backend.core.conf import settings
from backend.crud.crud_scan import scan_dao
from backend.crud.crud_target import target_dao
from backend.database.db_postgres import async_db_session
from backend.models import Target
from backend.utils.timezone import timezone

_ATTESTATION_CLEARED = {'authorized_at': None, 'authorized_by': None, 'authorized_ip': None, 'terms_version': None}


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
                    data.update(is_authorized=False, **_ATTESTATION_CLEARED)
            return await target_dao.update(db, pk, data)

    @staticmethod
    async def set_authorization(
        *, actor: Actor, pk: int, is_authorized: bool, accept_terms: bool = False,
        terms_version: str | None = None, ip: str | None = None,
    ) -> Target:
        """Authorize a target for scanning, or revoke it.

        Self-service accounts authorize by attesting, under the current terms of
        use, that they own the target or hold written permission to test it. The
        attestation (who / when / IP / terms version) is stored as the audit trail.
        Admins (operators) may authorize without it.
        """
        async with async_db_session.begin() as db:
            target = await target_dao.get(db, pk)
            ensure_access(actor, target, not_found='Target not found')
            if not is_authorized:
                await target_dao.update(db, pk, {'is_authorized': False, **_ATTESTATION_CLEARED})
            else:
                accepted = accept_terms and terms_version == settings.TERMS_VERSION
                if not accepted and not actor.is_admin:
                    raise errors.RequestError(
                        msg="Acceptez les conditions d'utilisation et attestez votre autorisation pour scanner cette cible.",
                        data={'terms_version': settings.TERMS_VERSION},
                    )
                await target_dao.update(db, pk, {
                    'is_authorized': True,
                    'authorized_at': timezone.now(),
                    'authorized_by': actor.id,
                    'authorized_ip': (ip or '')[:64] or None,
                    'terms_version': terms_version if accepted else None,
                })
        async with async_db_session() as db:
            return await target_dao.get(db, pk)

    @staticmethod
    async def delete(*, actor: Actor, pk: list[int]) -> int:
        async with async_db_session.begin() as db:
            for target_id in pk:
                ensure_access(actor, await target_dao.get(db, target_id), not_found='Target not found')
            # Deleting a target cascades to its scans; a live one holds credits.
            if await scan_dao.count_busy_for_targets(db, pk):
                raise errors.ForbiddenError(msg='Un scan est en cours sur cette application : annulez-le avant de la supprimer.')
            return await target_dao.delete(db, pk)


target_service: TargetService = TargetService()
