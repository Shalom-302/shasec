import asyncio
import hashlib

from backend.app.shasec.plugins import get_plugins_for
from backend.app.shasec.plugins.base import RawFinding, ScanContext
from backend.app.shasec.schema.exploit import CreateExploitParam
from backend.app.shasec.schema.finding import CreateFindingParam
from backend.app.shasec.service.ai_service import ai_service
from backend.app.shasec.verifier import get_modules_for
from backend.app.shasec.verifier.base import ExploitContext
from backend.common.enums import SEVERITY_WEIGHT, ScanStatus
from backend.common.log import log
from backend.core.conf import settings
from backend.crud.crud_exploit import exploit_dao
from backend.crud.crud_finding import finding_dao
from backend.crud.crud_scan import scan_dao
from backend.crud.crud_target import target_dao
from backend.database.db_postgres import async_db_session
from backend.utils.timezone import timezone


def _fingerprint(target_url: str, rf: RawFinding) -> str:
    """Deterministic, scanner-agnostic correlation key."""
    seed = rf.fingerprint_seed or rf.title
    return hashlib.sha256(f'{target_url}|{seed}'.encode()).hexdigest()[:64]


def _aggregate(target_url: str, tagged: list[tuple[str, RawFinding]]) -> list[tuple[str, RawFinding, str]]:
    """Dedupe findings sharing a fingerprint; the highest severity wins."""
    by_fp: dict[str, tuple[str, RawFinding, str]] = {}
    for plugin_name, rf in tagged:
        fp = _fingerprint(target_url, rf)
        current = by_fp.get(fp)
        if current is None or SEVERITY_WEIGHT.get(rf.severity, 0) > SEVERITY_WEIGHT.get(current[1].severity, 0):
            by_fp[fp] = (plugin_name, rf, fp)
    return list(by_fp.values())


async def _run_exploit_stage(
    scan_id: int, target_url: str, target_type: str, auth_token: str | None = None
) -> None:
    """Run the consented exploit modules and persist proofs. Never raises — a
    failing module must not fail the scan."""
    ectx = ExploitContext(
        scan_id=scan_id, target_url=target_url, target_type=target_type, auth_token=auth_token
    )
    modules = get_modules_for(target_type)

    async def _safe(m):
        try:
            return await asyncio.wait_for(m.run(ectx), timeout=m.timeout + 5)
        except Exception as exc:  # noqa: BLE001
            log.error(f'exploit module {m.name} failed on scan {scan_id}: {exc}')
            return []

    results = await asyncio.gather(*[_safe(m) for m in modules])
    tagged = [(m.name, r) for m, rs in zip(modules, results) for r in rs]
    if not tagged:
        return
    async with async_db_session.begin() as db:
        for module_name, r in tagged:
            await exploit_dao.create(
                db,
                CreateExploitParam(
                    scan_id=scan_id,
                    module=module_name,
                    category=r.category,
                    title=r.title,
                    severity=r.severity,
                    confirmed=r.confirmed,
                    impact=r.impact,
                    request=r.request,
                    response=r.response,
                ),
            )
    confirmed = sum(1 for _, r in tagged if r.confirmed)
    log.info(f'shasec scan {scan_id} exploit stage: {confirmed}/{len(tagged)} confirmed proof(s)')


async def run_pipeline(scan_id: int, auth_token: str | None = None) -> None:
    """Execute the full scan pipeline for one scan and persist its findings.

    Phase 1: runs inline as an asyncio task (fire-and-forget from the API). The
    Scan.status state machine is the source of truth. Phase 2 moves this behind
    an arq worker for durability — the body stays identical.
    """
    async with async_db_session() as db:
        scan = await scan_dao.get(db, scan_id)
        target = await target_dao.get(db, scan.target_id) if scan else None
    if not scan or not target:
        return

    async with async_db_session.begin() as db:
        await scan_dao.update(
            db, scan_id, {'status': ScanStatus.running.value, 'started_at': timezone.now()}
        )

    try:
        ctx = ScanContext(scan_id=scan_id, target_url=target.url, target_type=target.type)
        plugins = get_plugins_for(target.type)

        async def _safe_run(p):
            try:
                return p.name, await asyncio.wait_for(p.run(ctx), timeout=p.timeout + 5)
            except Exception as exc:  # noqa: BLE001  — one plugin must never kill the scan
                log.error(f'shasec plugin {p.name} failed on scan {scan_id}: {exc}')
                return p.name, []

        results = await asyncio.gather(*[_safe_run(p) for p in plugins])
        tagged = [(name, rf) for name, rfs in results for rf in rfs]
        aggregated = _aggregate(target.url, tagged)

        async with async_db_session.begin() as db:
            for plugin_name, rf, fp in aggregated:
                finding = await finding_dao.create(
                    db,
                    CreateFindingParam(
                        scan_id=scan_id,
                        plugin=plugin_name,
                        title=rf.title,
                        severity=rf.severity,
                        description=rf.description,
                        evidence=rf.evidence,
                        recommendation=rf.recommendation,
                    ),
                )
                finding.fingerprint = fp

        # Active-exploitation stage — strictly gated: explicit per-scan consent
        # AND an authorized target. Sends attack payloads (still read-only/bounded)
        # and records each request/response as proof.
        if scan.allow_active_exploitation and target.is_authorized:
            await _run_exploit_stage(scan_id, target.url, target.type, auth_token)

        # AI analysis stage (Phase 3) — interprets the findings + proofs into a
        # score/summary/remediation. Best-effort: skips with no API key, never
        # fails the scan.
        if settings.AI_ANALYSIS_ENABLED:
            await ai_service.analyze_scan(scan_id)

        async with async_db_session.begin() as db:
            await scan_dao.update(
                db, scan_id, {'status': ScanStatus.completed.value, 'completed_at': timezone.now()}
            )
        log.info(f'shasec scan {scan_id} completed: {len(aggregated)} finding(s)')
    except Exception as exc:  # noqa: BLE001
        log.error(f'shasec scan {scan_id} failed: {exc}')
        async with async_db_session.begin() as db:
            await scan_dao.update(
                db,
                scan_id,
                {
                    'status': ScanStatus.failed.value,
                    'error': str(exc)[:500],
                    'completed_at': timezone.now(),
                },
            )
