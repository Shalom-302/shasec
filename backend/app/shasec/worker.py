"""arq worker — durable execution of the shasec scan pipeline (Phase 2).

Run it as a separate process/container:

    arq backend.app.shasec.worker.WorkerSettings

The API enqueues ``run_scan_job`` (see ``scan_service``) instead of spawning an
in-process asyncio task, so a scan survives an API restart. The job body is just
``run_pipeline`` — identical logic to the in-process path.

Capacity: ``max_jobs`` = settings.SHASEC_MAX_CONCURRENT_SCANS scans run at once;
the rest wait in Redis (status ``queued``). Run a single worker replica: on boot
it fails (and refunds) scans left ``running`` by a previous, interrupted worker.
"""
import asyncio

from arq.connections import RedisSettings

from backend.app.shasec.service.orchestrator import ScanFailure, _mark_failed, run_pipeline
from backend.common.log import log
from backend.core.conf import settings
from backend.crud.crud_scan import scan_dao
from backend.database.db_postgres import async_db_session


def redis_settings() -> RedisSettings:
    return RedisSettings(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        database=settings.REDIS_DATABASE,
        password=settings.REDIS_PASSWORD or None,
    )


async def run_scan_job(
    ctx: dict, scan_id: int, auth_token: str | None = None, options: dict | None = None
) -> None:
    log.info(f'[arq] running scan {scan_id} (job {ctx.get("job_id")})')
    try:
        await run_pipeline(scan_id, auth_token=auth_token, options=options)
    except asyncio.CancelledError:
        # job_timeout or worker shutdown: don't leave the scan "running" forever.
        await asyncio.shield(_mark_failed(scan_id, ScanFailure('Durée maximale du scan dépassée ou service interrompu. Relancez le scan.')))
        raise


async def recover_interrupted(ctx: dict) -> None:
    async with async_db_session() as db:
        orphans = await scan_dao.running_ids(db)
    for scan_id in orphans:
        log.warning(f'[arq] scan {scan_id} was interrupted by a worker restart; marking failed')
        await _mark_failed(scan_id, ScanFailure('Scan interrompu (redémarrage du service). Relancez-le.'))


class WorkerSettings:
    functions = [run_scan_job]
    redis_settings = redis_settings()
    on_startup = recover_interrupted
    max_jobs = max(1, settings.SHASEC_MAX_CONCURRENT_SCANS)
    # An interrupted scan is failed + refunded (above), never silently re-run.
    max_tries = 1
    job_timeout = 3600  # a scan (scanners + exploit + AI) can take a few minutes
    keep_result = 3600
