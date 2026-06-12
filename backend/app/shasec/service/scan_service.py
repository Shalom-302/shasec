import asyncio

from sqlalchemy import Select

from backend.app.shasec.schema.scan import CreateScanParam
from backend.app.shasec.schema.target import CreateTargetParam
from backend.app.shasec.service.orchestrator import run_pipeline
from backend.common.enums import ScanStatus
from backend.common.exception import errors
from backend.crud.crud_scan import scan_dao
from backend.crud.crud_target import target_dao
from backend.database.db_postgres import async_db_session
from backend.models import Scan

# Keep strong references to in-flight pipeline tasks so the event loop does not
# garbage-collect them mid-run (Phase 1 in-process execution; Phase 2 = arq).
_RUNNING: set = set()


def _fire(scan_id: int, auth_token: str | None = None) -> None:
    # auth_token is passed transiently (never persisted) so authenticated
    # exploit modules (JWT, BFLA) can use it.
    task = asyncio.create_task(run_pipeline(scan_id, auth_token=auth_token))
    _RUNNING.add(task)
    task.add_done_callback(_RUNNING.discard)


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
                raise errors.ForbiddenError(msg=f'Scan is not startable (status={scan.status})')
            target = await target_dao.get(db, scan.target_id)
            if not target:
                raise errors.NotFoundError(msg='Target not found')
            if not target.is_authorized:
                raise errors.ForbiddenError(
                    msg='Target is not authorized for scanning. Authorize the target first.'
                )

        _fire(pk)

        async with async_db_session() as db:
            return await scan_dao.get(db, pk)

    @staticmethod
    async def quick(
        *, url: str, type: str, name: str | None = None, allow_active_exploitation: bool = False,
        auth_token: str | None = None,
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
                CreateScanParam(target_id=target.id, allow_active_exploitation=allow_active_exploitation),
            )
            await db.flush()  # populate scan.id before the transaction commits
            scan_id = scan.id

        _fire(scan_id, auth_token=auth_token)

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


scan_service: ScanService = ScanService()
