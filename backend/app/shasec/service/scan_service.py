import asyncio
import json

from sqlalchemy import Select

from backend.app.shasec.schema.scan import CreateScanParam
from backend.app.shasec.schema.target import CreateTargetParam
from backend.app.shasec.service.access import Actor, ensure_access, require_admin
from backend.app.shasec.service.credit_service import credit_service
from backend.app.shasec.service.notification_service import notification_service
from backend.app.shasec.service.orchestrator import run_pipeline
from backend.app.shasec.service.progress import publish as publish_progress
from backend.common.enums import ScanStatus
from backend.common.exception import errors
from backend.common.log import log
from backend.core.conf import settings
from backend.crud.crud_scan import scan_dao
from backend.crud.crud_scan_asset import scan_asset_dao
from backend.crud.crud_target import target_dao
from backend.database.db_postgres import async_db_session
from backend.database.db_redis import redis_client
from backend.utils.timezone import timezone
from backend.models import Scan

# Strong refs to in-flight in-process tasks (the fallback path) so the event loop
# does not garbage-collect them mid-run.
_RUNNING: set = set()
_arq_pool = None
# In-process fallback honours the same concurrency cap as the arq worker.
_SLOTS: asyncio.Semaphore | None = None
# Scans that must not be deleted (directly or with their target) until they end.
_BUSY = (ScanStatus.awaiting_approval.value, ScanStatus.awaiting_scope.value, ScanStatus.queued.value, ScanStatus.running.value)


# Audit exploit knobs (auth_token / aggression / id_range / allow_destructive) must
# survive the human awaiting_scope pause WITHOUT being persisted on the scan row
# (a destructive opt-in must never linger in the DB). We stash them in Redis with a
# short TTL, keyed by scan id, and pop+delete them when the audit resumes.
_XOPTS_TTL = 6 * 3600


def _xopts_key(scan_id: int) -> str:
    return f'shasec:scan:{scan_id}:xopts'


async def _stash_audit_opts(scan_id: int, auth_token: str | None, options: dict | None) -> None:
    try:
        await redis_client.set(
            _xopts_key(scan_id), json.dumps({'auth_token': auth_token, 'options': options or {}}),
            ex=_XOPTS_TTL,
        )
    except Exception as exc:  # noqa: BLE001 — resume will just use safe defaults
        log.warning(f'could not stash audit opts for scan {scan_id}: {exc}')


async def _pop_audit_opts(scan_id: int) -> tuple[str | None, dict | None]:
    try:
        raw = await redis_client.get(_xopts_key(scan_id))
        await redis_client.delete(_xopts_key(scan_id))
        if raw:
            data = json.loads(raw)
            return data.get('auth_token'), data.get('options')
    except Exception as exc:  # noqa: BLE001
        log.warning(f'could not read audit opts for scan {scan_id}: {exc}')
    return None, None


async def _run_limited(scan_id: int, auth_token: str | None, options: dict | None) -> None:
    global _SLOTS
    if _SLOTS is None:
        _SLOTS = asyncio.Semaphore(max(1, settings.SHASEC_MAX_CONCURRENT_SCANS))
    async with _SLOTS:
        await run_pipeline(scan_id, auth_token=auth_token, options=options)


async def _get_arq_pool():
    # Lazy import so the API boots even when arq isn't installed; only touched
    # when SHASEC_USE_ARQ is on and a scan is dispatched.
    global _arq_pool
    if _arq_pool is None:
        from arq import create_pool

        from backend.app.shasec.worker import redis_settings
        _arq_pool = await create_pool(redis_settings())
    return _arq_pool


def _run_in_process(scan_id: int, auth_token: str | None = None, options: dict | None = None) -> None:
    task = asyncio.create_task(_run_limited(scan_id, auth_token, options))
    _RUNNING.add(task)
    task.add_done_callback(_RUNNING.discard)


async def _dispatch(scan_id: int, auth_token: str | None = None, options: dict | None = None) -> None:
    """Durable execution via the arq worker when enabled; otherwise (or if the
    queue is unreachable) run in-process. auth_token and options are passed
    transiently and never persisted, so authenticated exploit modules (JWT, BFLA)
    and per-scan knobs (id_range, allow_destructive) can use them."""
    await publish_progress(scan_id, 'queued', message='En file d’attente')
    if settings.SHASEC_USE_ARQ:
        try:
            pool = await _get_arq_pool()
            await pool.enqueue_job('run_scan_job', scan_id, auth_token, options)
            return
        except Exception as exc:  # noqa: BLE001 — never block scan creation on the queue
            log.warning(f'arq enqueue failed for scan {scan_id} ({exc}); running in-process')
    _run_in_process(scan_id, auth_token=auth_token, options=options)


async def _guard_active_limit(db, actor: Actor) -> None:
    """One account can't flood the scanners: cap its queued + running scans."""
    if actor.is_admin:
        return
    await scan_dao.lock_owner(db, actor.id)
    limit = settings.SHASEC_MAX_ACTIVE_SCANS_PER_USER
    if await scan_dao.count_active(db, actor.id) >= limit:
        raise errors.ConflictError(
            msg=(f'Vous avez déjà {limit} scan(s) en cours. '
                 'Attendez la fin du scan en cours avant d’en lancer un autre.')
        )


def _guard_options(actor: Actor, *, allow_active_exploitation: bool = False,
                   aggression: str = 'safe', allow_destructive: bool = False) -> None:
    """Self-service accounts get passive/bounded scanning only: active
    exploitation, aggressive probing and write verbs stay admin-only."""
    if actor.is_admin:
        return
    if allow_active_exploitation or allow_destructive or getattr(aggression, 'value', aggression) != 'safe':
        raise errors.ForbiddenError(
            msg='Active exploitation, aggressive and destructive options are not available on this plan.'
        )


class ScanService:
    @staticmethod
    async def get_by_id(*, actor: Actor, pk: int) -> Scan:
        async with async_db_session() as db:
            scan = await scan_dao.get(db, pk)
            ensure_access(actor, scan, not_found='Scan not found')
            return scan

    @staticmethod
    async def get_select(*, actor: Actor, target_id: int = None, status: str = None) -> Select:
        owner_id = None if actor.is_admin else actor.id
        return await scan_dao.get_list(target_id=target_id, status=status, owner_id=owner_id)

    @staticmethod
    async def create(*, actor: Actor, obj: CreateScanParam) -> Scan:
        _guard_options(actor, allow_active_exploitation=obj.allow_active_exploitation)
        async with async_db_session.begin() as db:
            target = await target_dao.get(db, obj.target_id)
            ensure_access(actor, target, not_found='Target not found')
            scan = await scan_dao.create(db, obj, owner_id=target.owner_id or actor.id)
            await db.flush()
            return scan

    @staticmethod
    async def start(*, actor: Actor, pk: int) -> Scan:
        """Validate preconditions, enforce the authorized-scope guardrail, bill
        the account, then hand the scan to the orchestrator.
        """
        async with async_db_session.begin() as db:
            scan = await scan_dao.get(db, pk)
            ensure_access(actor, scan, not_found='Scan not found')
            if scan.status != ScanStatus.pending.value:
                # Already started/finished: idempotent guard, surfaced as 409 so a
                # retried start is a clear conflict, never a second run.
                raise errors.ConflictError(msg=f'Scan already started (status={scan.status})')
            target = await target_dao.get(db, scan.target_id)
            if not target:
                raise errors.NotFoundError(msg='Target not found')
            if not target.is_authorized:
                raise errors.ForbiddenError(
                    msg="Cette cible n'est pas autorisée au scan. Acceptez d'abord les conditions d'utilisation pour cette cible."
                )
            # Atomically claim the scan (pending -> running) BEFORE dispatch. The
            # read above gives clear errors on the common path; this conditional
            # update closes the race between two concurrent starts — only the
            # caller that flips the row proceeds, the loser's rowcount is 0.
            await _guard_active_limit(db, actor)
            claimed = await scan_dao.claim_for_start(db, pk)
            if claimed == 0:
                raise errors.ConflictError(msg='Scan already started (concurrent start)')
            # Same transaction as the claim: a 402 rolls the claim back.
            await credit_service.charge_scan(db, actor, scan)

        await _dispatch(pk)

        async with async_db_session() as db:
            return await scan_dao.get(db, pk)

    @staticmethod
    async def request_advanced(*, actor: Actor, target_id: int, profile: str = 'deep',
                               scope_note: str | None = None) -> Scan:
        """Submit an advanced (active-exploitation) audit for admin approval.

        Credits are reserved now; the scan waits in ``awaiting_approval`` until an
        admin approves (-> queued) or rejects (-> refund). Active audits run the
        XSS/CSRF/BOLA/BFLA/injection probes, so they never auto-run for a
        self-service account.
        """
        if actor.is_admin:
            return await ScanService.quick_by_target(
                actor=actor, target_id=target_id, profile=profile, allow_active_exploitation=True)
        async with async_db_session.begin() as db:
            target = await target_dao.get(db, target_id)
            ensure_access(actor, target, not_found='Target not found')
            if not target.is_authorized:
                raise errors.ForbiddenError(
                    msg="Autorisez d'abord cette cible (acceptation des conditions d'utilisation).")
            pending = await scan_dao.count_awaiting(db, actor.id)
            if pending >= settings.SHASEC_MAX_PENDING_REQUESTS_PER_USER:
                raise errors.ConflictError(
                    msg=f'Vous avez deja {pending} demande(s) en attente de validation.')
            scan = await scan_dao.create(
                db,
                CreateScanParam(target_id=target.id, allow_active_exploitation=True, profile=profile),
                owner_id=actor.id,
            )
            await db.flush()
            scan.status = ScanStatus.awaiting_approval.value
            scan.scope_note = (scope_note or '').strip()[:2000] or None
            await credit_service.charge_scan(db, actor, scan)
            scan_id, host = scan.id, target.url
        await publish_progress(scan_id, 'awaiting_approval', status='awaiting_approval',
                               message='En attente de validation par un administrateur')
        await notification_service.notify_admins(
            kind='audit_request',
            title='Nouvelle demande audit avance',
            body=f'Scan #{scan_id} - {host} - profil {profile}. En attente de validation.',
            link='/admin/requests',
        )
        async with async_db_session() as db:
            return await scan_dao.get(db, scan_id)

    @staticmethod
    async def pending_approval_select(*, actor: Actor) -> Select:
        require_admin(actor)
        return await scan_dao.get_list(status=ScanStatus.awaiting_approval.value)

    @staticmethod
    async def approve(*, actor: Actor, pk: int, note: str | None = None) -> Scan:
        require_admin(actor)
        async with async_db_session.begin() as db:
            scan = await scan_dao.get(db, pk)
            if not scan:
                raise errors.NotFoundError(msg='Scan not found')
            if scan.status != ScanStatus.awaiting_approval.value:
                raise errors.ConflictError(msg=f'Request already handled (status={scan.status})')
            await scan_dao.update(db, pk, {
                'status': ScanStatus.queued.value, 'reviewed_by': actor.id,
                'reviewed_at': timezone.now(), 'review_note': (note or '').strip()[:1000] or None,
            })
            owner_id = scan.owner_id
        await notification_service.notify_user(
            owner_id, kind='audit_decision', title='Audit avance approuve',
            body=f'Votre audit avance (scan #{pk}) a ete valide et va demarrer.', link=f'/scans/{pk}')
        await _dispatch(pk)
        async with async_db_session() as db:
            return await scan_dao.get(db, pk)

    @staticmethod
    async def reject(*, actor: Actor, pk: int, note: str | None = None) -> Scan:
        require_admin(actor)
        async with async_db_session.begin() as db:
            scan = await scan_dao.get(db, pk)
            if not scan:
                raise errors.NotFoundError(msg='Scan not found')
            if scan.status != ScanStatus.awaiting_approval.value:
                raise errors.ConflictError(msg=f'Request already handled (status={scan.status})')
            reason = (note or '').strip()[:1000] or 'Demande refusee'
            await scan_dao.update(db, pk, {
                'status': ScanStatus.failed.value, 'error': f'Demande refusee : {reason}',
                'reviewed_by': actor.id, 'reviewed_at': timezone.now(), 'review_note': reason,
            })
            await credit_service.refund_scan(db, pk, note='Demande audit refusee')
            owner_id = scan.owner_id
        await publish_progress(pk, 'failed', status='failed', message='Demande refusee')
        await notification_service.notify_user(
            owner_id, kind='audit_decision', title='Audit avance refuse',
            body=f'Votre demande (scan #{pk}) a ete refusee. Les credits ont ete restitues.', link=f'/scans/{pk}')
        async with async_db_session() as db:
            return await scan_dao.get(db, pk)

    @staticmethod
    async def quick_by_target(*, actor: Actor, target_id: int, profile: str = 'deep',
                              allow_active_exploitation: bool = False) -> Scan:
        """Create + bill + start a scan on an already-authorized owned target."""
        async with async_db_session.begin() as db:
            target = await target_dao.get(db, target_id)
            ensure_access(actor, target, not_found='Target not found')
            if not target.is_authorized:
                raise errors.ForbiddenError(msg='Target is not authorized for scanning.')
            await _guard_active_limit(db, actor)
            scan = await scan_dao.create(
                db,
                CreateScanParam(target_id=target.id, allow_active_exploitation=allow_active_exploitation, profile=profile),
                owner_id=actor.id,
            )
            await db.flush()
            scan.status = ScanStatus.queued.value
            await credit_service.charge_scan(db, actor, scan)
            scan_id = scan.id
        await _dispatch(scan_id)
        async with async_db_session() as db:
            return await scan_dao.get(db, scan_id)

    @staticmethod
    async def quick(
        *, actor: Actor, url: str, type: str, name: str | None = None, allow_active_exploitation: bool = False,
        profile: str = 'standard', aggression: str = 'safe',
        auth_token: str | None = None, id_range: str | None = None, allow_destructive: bool = False,
        mode: str = 'single',
    ) -> Scan:
        """One-shot: from a URL, create-or-reuse the caller's target, create the
        scan, bill it and start it.

        Admins get the target auto-authorized (operator use). Everyone else must
        have authorized the target first (scope attestation under the terms of
        use): an unknown URL is registered on their account (unauthorized) and the
        call is refused with its id so the client can collect the attestation.
        """
        _guard_options(actor, allow_active_exploitation=allow_active_exploitation,
                       aggression=aggression, allow_destructive=allow_destructive)
        # Reuse the Target validator (rejects local/private, enforces http(s)).
        target_param = CreateTargetParam(name=name or url, url=url, type=type)

        if not actor.is_admin:
            async with async_db_session.begin() as db:
                target = await target_dao.select_model_by_column(db, url=target_param.url, owner_id=actor.id)
                if not target:
                    target = await target_dao.create(db, target_param, owner_id=actor.id)
                    await db.flush()
                target_id, authorized = target.id, target.is_authorized
            if not authorized:
                raise errors.ForbiddenError(
                    msg="Autorisez d'abord cette cible (acceptation des conditions d'utilisation).", data={'target_id': target_id}
                )

        async with async_db_session.begin() as db:
            await _guard_active_limit(db, actor)
            target = await target_dao.select_model_by_column(db, url=target_param.url, owner_id=actor.id)
            if not target:
                target = await target_dao.create(db, target_param, owner_id=actor.id)
            if actor.is_admin:
                target.is_authorized = True
            await db.flush()
            scan = await scan_dao.create(
                db,
                CreateScanParam(
                    target_id=target.id,
                    allow_active_exploitation=allow_active_exploitation,
                    profile=profile,
                    mode=mode,
                ),
                owner_id=actor.id,
            )
            await db.flush()  # populate scan.id before the transaction commits
            scan.status = ScanStatus.queued.value
            await credit_service.charge_scan(db, actor, scan)
            scan_id = scan.id

        options = {'allow_destructive': bool(allow_destructive), 'aggression': aggression}
        if id_range:
            options['id_range'] = id_range
        # A domain audit pauses on awaiting_scope after cartography; keep its
        # exploit knobs in Redis so set_scope can re-pass them to steps 2-4.
        if mode == 'audit':
            await _stash_audit_opts(scan_id, auth_token, options)
        await _dispatch(scan_id, auth_token=auth_token, options=options)

        async with async_db_session() as db:
            return await scan_dao.get(db, scan_id)

    @staticmethod
    async def set_scope(*, actor: Actor, pk: int, asset_ids: list[int]) -> Scan:
        """Pick the in-scope hosts of a domain audit paused on ``awaiting_scope``
        and resume it (steps 2-4 run only on the selected, live, own hosts).

        Billing already happened when the audit was created, so resuming is free.
        The audit's exploit knobs (auth_token / aggression / id_range) were
        stashed in Redis at creation (never on the DB row) and are popped here so
        steps 2-4 probe with the same settings the operator chose — this is what
        lets BOLA/BFLA run with the provided token after the scope pause.
        """
        async with async_db_session.begin() as db:
            scan = await scan_dao.get(db, pk)
            ensure_access(actor, scan, not_found='Scan not found')
            if scan.status != ScanStatus.awaiting_scope.value:
                raise errors.ConflictError(msg=f'Scan is not awaiting scope (status={scan.status})')
            assets = await scan_asset_dao.get_by_scan(db, pk)
            valid_ids = {a.id for a in assets}
            chosen = [i for i in asset_ids if i in valid_ids]
            if not chosen:
                raise errors.RequestError(msg='Sélectionnez au moins un hôte à auditer.')
            # Guard: never let a third-party / non-resolving host into scope.
            blocked = [a for a in assets if a.id in chosen and (a.third_party or not a.alive)]
            if blocked:
                raise errors.ForbiddenError(
                    msg=f'Hôte hors périmètre (tiers ou injoignable) : {blocked[0].host}')
            await scan_asset_dao.set_selection(db, pk, chosen)
            await scan_dao.update(db, pk, {'status': ScanStatus.queued.value})
        auth_token, options = await _pop_audit_opts(pk)
        await _dispatch(pk, auth_token=auth_token, options=options)
        async with async_db_session() as db:
            return await scan_dao.get(db, pk)

    @staticmethod
    async def assets(*, actor: Actor, pk: int):
        async with async_db_session() as db:
            scan = await scan_dao.get(db, pk)
            ensure_access(actor, scan, not_found='Scan not found')
            return await scan_asset_dao.get_by_scan(db, pk)

    @staticmethod
    async def cancel(*, actor: Actor, pk: int) -> int:
        async with async_db_session.begin() as db:
            scan = await scan_dao.get(db, pk)
            ensure_access(actor, scan, not_found='Scan not found')
            active = (ScanStatus.pending.value, ScanStatus.awaiting_approval.value,
                      ScanStatus.awaiting_scope.value, ScanStatus.queued.value, ScanStatus.running.value)
            if scan.status not in active:
                raise errors.ForbiddenError(msg=f'Scan cannot be cancelled (status={scan.status})')
            refundable = scan.status in (ScanStatus.queued.value, ScanStatus.awaiting_approval.value)
            count = await scan_dao.update(
                db, pk, {'status': ScanStatus.failed.value, 'error': 'Cancelled by user'}
            )
            # Never started: nothing was consumed, give the credits back. (The
            # worker skips a job whose scan is no longer queued.)
            if refundable:
                await credit_service.refund_scan(db, pk, note='Scan annulé avant démarrage')
        await publish_progress(pk, 'failed', status='failed', message='Annulé')
        return count

    @staticmethod
    async def delete(*, actor: Actor, pk: list[int]) -> int:
        async with async_db_session.begin() as db:
            for scan_id in pk:
                scan = await scan_dao.get(db, scan_id)
                ensure_access(actor, scan, not_found='Scan not found')
                # A live scan holds reserved credits and a worker slot: cancel it
                # first (which refunds), then delete.
                if scan.status in _BUSY:
                    raise errors.ForbiddenError(msg='Ce scan est en cours : annulez-le avant de le supprimer.')
            return await scan_dao.delete(db, pk)


scan_service: ScanService = ScanService()
