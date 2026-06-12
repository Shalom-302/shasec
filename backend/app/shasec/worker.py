"""arq worker — durable execution of the shasec scan pipeline (Phase 2).

Run it as a separate process/container:

    arq backend.app.shasec.worker.WorkerSettings

The API enqueues ``run_scan_job`` (see ``scan_service``) instead of spawning an
in-process asyncio task, so a scan survives an API restart. The job body is just
``run_pipeline`` — identical logic to the in-process path.
"""
from arq.connections import RedisSettings

from backend.app.shasec.service.orchestrator import run_pipeline
from backend.common.log import log
from backend.core.conf import settings


def redis_settings() -> RedisSettings:
    return RedisSettings(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        database=settings.REDIS_DATABASE,
        password=settings.REDIS_PASSWORD or None,
    )


async def run_scan_job(ctx: dict, scan_id: int, auth_token: str | None = None) -> None:
    log.info(f'[arq] running scan {scan_id} (job {ctx.get("job_id")})')
    await run_pipeline(scan_id, auth_token=auth_token)


class WorkerSettings:
    functions = [run_scan_job]
    redis_settings = redis_settings()
    max_jobs = 10
    job_timeout = 3600  # a scan (scanners + exploit + AI) can take a few minutes
    keep_result = 3600
