import asyncio

from sqlalchemy import Select

from backend.app.shasec.schema.scan import CreateScanParam
from backend.app.shasec.schema.target import CreateTargetParam
from backend.app.shasec.service.orchestrator import run_pipeline
from backend.common.enums import ScanStatus
from backend.common.exception import errors
from backend.common.log import log
from backend.core.conf import settings
from backend.crud.crud_scan import scan_dao
from backend.crud.crud_target import target_dao
from backend.database.db_postgres import async_db_session
from backend.models import Scan

# Strong refs to in-flight in-process tasks (the fallback path) so the event loop
# does not garbage-collect them mid-run.
_RUNNING: set = set()
_arq_pool = None


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
    task = asyncio.create_task(run_pipeline(scan_id, auth_token=auth_token, options=options))
    _RUNNING.add(task)
    task.add_done_callback(_RUNNING.discard)


async def _dispatch(scan_id: int, auth_token: str | None = None, options: dict | None = None) -> None:
    """Durable execution via the arq worker when enabled; otherwise (or if the
    queue is unreachable) run in-process. auth_token and options are passed
    transiently and never persisted, so authenticated exploit modules (JWT, BFLA)
    and per-scan knobs (id_range, allow_destructive) can use them."""
    if settings.SHASEC_USE_ARQ:
        try:
            pool = await _get_arq_pool()
            await pool.enqueue_job('run_scan_job', scan_id, auth_token, options)
            return
        except Exception as exc:  # noqa: BLE001 — never block scan creation on the queue
            log.warning(f'arq enqueue failed for scan {scan_id} ({exc}); running in-process')
    _run_in_process(scan_id, auth_token=auth_token, options=options)


class ScanService:
    @staticmethod
    async def get_by_id(*, pk: int) -> Scan:
        async with async_db_session() as db:
            scan = await scan_dao.get(db, pk)
            if not scan:
                raise errors.NotFoundError(msg='Scan not found')
            return scan

    @staticmethod
    async def get_select(*, target_id: int = None, status: str = None) -> Select:
        return await scan_dao.get_list(target_id=target_id, status=status)

    @staticmethod
    async def create(*, obj: CreateScanParam) -> Scan:
        async with async_db_session.begin() as db:
            target = await target_dao.get(db, obj.target_id)
            if not target:
                raise errors.NotFoundError(msg='Target not found')
            return await scan_dao.create(db, obj)

    @staticmethod
    async def start(*, pk: int) -> Scan:
        """Validate preconditions, enforce the authorized-scope guardrail, then
        hand the scan to the orchestrator (inline task in Phase 1, arq in Phase 2).
        """
        async with async_db_session.begin() as db:
            scan = await scan_dao.get(db, pk)
            if not scan:
                raise errors.NotFoundError(msg='Scan not found')
            if scan.status != ScanStatus.pending.value:
                # Already started/finished: idempotent guard, surfaced as 409 so a
                # retried start is a clear conflict, never a second run.
                raise errors.ConflictError(msg=f'Scan already started (status={scan.status})')
            target = await target_dao.get(db, scan.target_id)
            if not target:
                raise errors.NotFoundError(msg='Target not found')
            if not target.is_authorized:
                raise errors.ForbiddenError(
                    msg='Target is not authorized for scanning. Authorize the target first.'
                )
            # Atomically claim the scan (pending -> running) BEFORE dispatch. The
            # read above gives clear errors on the common path; this conditional
            # update closes the race between two concurrent starts — only the
            # caller that flips the row proceeds, the loser's rowcount is 0.
            claimed = await scan_dao.claim_for_start(db, pk)
            if claimed == 0:
                raise errors.ConflictError(msg='Scan already started (concurrent start)')

        await _dispatch(pk)

        async with async_db_session() as db:
            return await scan_dao.get(db, pk)

    @staticmethod
    async def quick(
        *, url: str, type: str, name: str | None = None, allow_active_exploitation: bool = False,
        profile: str = 'standard', aggression: str = 'safe',
        auth_token: str | None = None, id_range: str | None = None, allow_destructive: bool = False,
    ) -> Scan:
        """One-shot: from a URL, create-or-reuse the target, create the scan and
        start it. The URL still lands on a Target row (so history is preserved);
        callers just don't have to manage it.

        The authenticated caller explicitly requested this URL, so the target is
        auto-authorized. (Ownership proof — e.g. DNS challenge — is future work.)
        """
        # Reuse the Target validator (rejects local/private, enforces http(s)).
        target_param = CreateTargetParam(name=name or url, url=url, type=type)
        async with async_db_session.begin() as db:
            target = await target_dao.select_model_by_column(db, url=target_param.url)
            if not target:
                target = await target_dao.create(db, target_param)
            target.is_authorized = True
            await db.flush()
            scan = await scan_dao.create(
                db,
                CreateScanParam(
                    target_id=target.id,
                    allow_active_exploitation=allow_active_exploitation,
                    profile=profile,
                ),
            )
            await db.flush()  # populate scan.id before the transaction commits
            scan_id = scan.id

        options = {'allow_destructive': bool(allow_destructive), 'aggression': aggression}
        if id_range:
            options['id_range'] = id_range
        await _dispatch(scan_id, auth_token=auth_token, options=options)

        async with async_db_session() as db:
            return await scan_dao.get(db, scan_id)

    @staticmethod
    async def cancel(*, pk: int) -> int:
        async with async_db_session.begin() as db:
            scan = await scan_dao.get(db, pk)
            if not scan:
                raise errors.NotFoundError(msg='Scan not found')
            if scan.status not in (ScanStatus.pending.value, ScanStatus.running.value):
                raise errors.ForbiddenError(msg=f'Scan cannot be cancelled (status={scan.status})')
            return await scan_dao.update(
                db, pk, {'status': ScanStatus.failed.value, 'error': 'Cancelled by user'}
            )

    @staticmethod
    async def delete(*, pk: list[int]) -> int:
        async with async_db_session.begin() as db:
            return await scan_dao.delete(db, pk)


scan_service: ScanService = ScanService()
