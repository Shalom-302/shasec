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

from arq import cron
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


async def reconcile_payments(ctx: dict) -> None:
    """Credit paid MoneyFusion payments whose webhook never arrived."""
    from backend.app.shasec.service.payment_service import enabled, payment_service
    if enabled():
        await payment_service.reconcile()


async def affiliate_promote(ctx: dict) -> None:
    """Pending commissions -> available (hold over + buyer used credits). Never pays."""
    from backend.app.shasec.service.affiliate_service import affiliate_service
    await affiliate_service.promote_due()


async def agent_autopilot(ctx: dict) -> None:
    """Daily autonomous review by the premium agent (proposals still need approval)."""
    from backend.app.shasec.service.agent_service import agent_service
    await agent_service.autopilot_all()


class WorkerSettings:
    functions = [run_scan_job]
    cron_jobs = [
        cron(reconcile_payments, minute=set(range(0, 60, 5)), run_at_startup=True),
        # 07:00 UTC = 07:00 Abidjan.
        cron(agent_autopilot, hour={7}, minute={0}, timeout=3600),
        cron(affiliate_promote, hour={6}, minute={30}),
    ]
    redis_settings = redis_settings()
    on_startup = recover_interrupted
    max_jobs = max(1, settings.SHASEC_MAX_CONCURRENT_SCANS)
    # An interrupted scan is failed + refunded (above), never silently re-run.
    max_tries = 1
    job_timeout = 3600  # a scan (scanners + exploit + AI) can take a few minutes
    keep_result = 3600
