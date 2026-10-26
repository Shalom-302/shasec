import asyncio
import hashlib

from backend.app.shasec.plugins import get_plugins_for
from backend.app.shasec.plugins.base import RawFinding, ScanContext
from backend.app.shasec.owasp import classify as classify_owasp
from backend.app.shasec.schema.exploit import CreateExploitParam
from backend.app.shasec.schema.finding import CreateFindingParam
from backend.app.shasec.schema.scan_asset import CreateScanAssetParam
from backend.app.shasec.service.cartography import map_domain
from backend.app.shasec.service.credit_service import credit_service
from backend.app.shasec.service.progress import publish as publish_progress
from backend.app.shasec.verifier import get_modules_for
from backend.app.shasec.verifier.base import ExploitContext
from backend.common.enums import PROFILE_BUDGET, SEVERITY_WEIGHT, FindingStatus, ScanMode, ScanProfile, ScanStatus
from backend.common.log import log
from backend.core.conf import settings
from backend.crud.crud_exploit import exploit_dao
from backend.crud.crud_finding import finding_dao
from backend.crud.crud_scan import scan_dao
from backend.crud.crud_scan_asset import scan_asset_dao
from backend.crud.crud_target import target_dao
from backend.database.db_postgres import async_db_session
from backend.utils.timezone import timezone


# Aggressive-mode coverage expansion. Bounded curated lists — more surface, not
# more volume. Destructive writes are NEVER enabled here.
_AGGR_BYPASS_PATHS = (
    '/admin', '/administrator', '/dashboard', '/internal', '/manage', '/config',
    '/debug', '/actuator', '/actuator/env', '/api/admin', '/private', '/console',
    '/metrics', '/swagger', '/swagger-ui', '/.git/config', '/backup',
)
_AGGR_LOGIN_PATHS = (
    '/admin', '/login', '/admin/login', '/administrator', '/user/login',
    '/signin', '/auth', '/account/login', '/api/v2/login',
)


def _amplify_options(options: dict | None) -> dict:
    """When ``aggression == 'aggressive'``, widen BOUNDED coverage defaults the
    verifier modules already honor. Never enables destructive writes; never
    raises request volume into flood territory (BOLA stays sequential/self-paced).
    """
    opts = dict(options or {})
    if opts.get('aggression') == 'aggressive':
        opts.setdefault('id_range', '1-50')
        opts.setdefault('bypass_paths', list(_AGGR_BYPASS_PATHS))
        opts.setdefault('login_paths', list(_AGGR_LOGIN_PATHS))
        # allow_destructive is deliberately left untouched — aggression must never
        # turn on write verbs.
    return opts


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
    scan_id: int, target_url: str, target_type: str, auth_token: str | None = None,
    options: dict | None = None, asset_id: int | None = None,
) -> None:
    """Run the consented exploit modules and persist proofs. Never raises — a
    failing module must not fail the scan.

    ``options`` carries transient, per-scan knobs the exploit modules read
    (e.g. ``id_range`` for BOLA, ``allow_destructive`` for verb-tampering). Never
    persisted — passed through like ``auth_token`` so a destructive opt-in can
    never linger on a stored row.
    """
    ectx = ExploitContext(
        scan_id=scan_id, target_url=target_url, target_type=target_type, auth_token=auth_token,
        options=_amplify_options(options),
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
                    # §14 lifecycle: a proven module result is confirmed, the rest
                    # stay suspected until corroborated.
                    status=(FindingStatus.confirmed if r.confirmed else FindingStatus.suspected).value,
                    impact=r.impact,
                    request=r.request,
                    response=r.response,
                    asset_id=asset_id,
                    owasp=classify_owasp(module_name, r.title, category=r.category, severity=r.severity),
                ),
            )
    confirmed = sum(1 for _, r in tagged if r.confirmed)
    log.info(f'shasec scan {scan_id} exploit stage: {confirmed}/{len(tagged)} confirmed proof(s)')


class ScanFailure(Exception):
    """A failure whose message is safe to show to the customer."""


_GENERIC_FAILURE = 'Erreur technique pendant le scan.'


async def _mark_failed(scan_id: int, exc: Exception) -> None:
    # Full detail goes to the logs only; customers see a clean message (no SQL,
    # paths or stack details from internal exceptions).
    log.error(f'shasec scan {scan_id} failed: {exc!r}')
    public = str(exc)[:200] if isinstance(exc, ScanFailure) else _GENERIC_FAILURE
    await publish_progress(scan_id, 'failed', status='failed', message=public)
    async with async_db_session.begin() as db:
        await scan_dao.update(
            db,
            scan_id,
            {
                'status': ScanStatus.failed.value,
                'error': public,
                'completed_at': timezone.now(),
            },
        )
        # A failed scan never costs the customer: give back what it debited.
        await credit_service.refund_scan(db, scan_id)


async def run_pipeline(scan_id: int, auth_token: str | None = None, options: dict | None = None) -> None:
    """Execute the full scan pipeline for one scan and persist its findings.

    Phase 1: runs inline as an asyncio task (fire-and-forget from the API). The
    Scan.status state machine is the source of truth. Phase 2 moves this behind
    an arq worker for durability — the body stays identical.
    """
    # Setup failures (DB/schema errors, missing target) must also end the scan:
    # otherwise it stays "running" forever and its credits are never refunded.
    try:
        async with async_db_session() as db:
            scan = await scan_dao.get(db, scan_id)
            target = await target_dao.get(db, scan.target_id) if scan else None
        if not scan:
            return
        # Cancelled while waiting in the queue (or a duplicate delivery): skip.
        if scan.status not in (ScanStatus.pending.value, ScanStatus.queued.value):
            log.info(f'shasec scan {scan_id} skipped (status={scan.status})')
            return
        if not target:
            raise ScanFailure('Application introuvable')

        async with async_db_session.begin() as db:
            await scan_dao.update(
                db, scan_id, {'status': ScanStatus.running.value, 'started_at': timezone.now()}
            )
        await publish_progress(scan_id, 'started', message=f'Scan de {target.url} démarré')
    except Exception as exc:  # noqa: BLE001
        await _mark_failed(scan_id, exc)
        return

    try:
        profile = (scan.profile or ScanProfile.standard.value)
        budget = PROFILE_BUDGET.get(profile, PROFILE_BUDGET[ScanProfile.standard.value])

        # ---- Domain audit, step 1: cartography (passive mapping, no attack) ----
        # When a whole-domain audit has not been scoped yet, map the surface and
        # pause on ``awaiting_scope`` so the operator picks the in-scope hosts.
        if scan.mode == ScanMode.audit.value:
            async with async_db_session() as db:
                existing = await scan_asset_dao.get_by_scan(db, scan_id)
            if not existing:
                await publish_progress(scan_id, 'cartography.start', message='Cartographie du domaine…')
                assets = await map_domain(target.url)
                async with async_db_session.begin() as db:
                    for a in assets:
                        await scan_asset_dao.create_model(db, CreateScanAssetParam(scan_id=scan_id, **a))
                alive = sum(1 for a in assets if a.get('alive'))
                await publish_progress(
                    scan_id, 'cartography.done',
                    message=f'{len(assets)} hôte(s) cartographié(s), {alive} actif(s) — sélectionnez le périmètre.',
                    total_hosts=len(assets), alive_hosts=alive,
                )
                async with async_db_session.begin() as db:
                    await scan_dao.update(db, scan_id, {'status': ScanStatus.awaiting_scope.value})
                await publish_progress(scan_id, 'awaiting_scope', status='awaiting_scope',
                                       message='En attente de sélection du périmètre')
                log.info(f'shasec audit {scan_id} cartography: {len(assets)} host(s), awaiting scope')
                return

        # ---- Build the list of hosts to scan (steps 2-4) -----------------------
        # single scan → the target itself; audit resume → each selected host.
        if scan.mode == ScanMode.audit.value:
            async with async_db_session() as db:
                selected = await scan_asset_dao.get_selected(db, scan_id)
            hosts = [(a.id, a.url or f'https://{a.host}', a.kind) for a in selected if a.alive]
            if not hosts:
                raise ScanFailure('Aucun hôte vivant sélectionné pour cet audit.')
        else:
            hosts = [(None, target.url, target.type)]

        total_findings = 0
        for host_index, (asset_id, host_url, host_type) in enumerate(hosts, start=1):
            prefix = f'[{host_index}/{len(hosts)}] ' if len(hosts) > 1 else ''
            total_findings += await _scan_host(
                scan_id, host_url, host_type, asset_id=asset_id, profile=profile, budget=budget,
                label=prefix, allow_exploit=(scan.allow_active_exploitation and target.is_authorized),
                auth_token=auth_token, options=options,
            )

        # No AI here — the analysis runs once, on demand, when the first report is
        # generated (keeps AI cost to one call per audit, not one per scan).
        async with async_db_session.begin() as db:
            await scan_dao.update(
                db, scan_id, {'status': ScanStatus.completed.value, 'completed_at': timezone.now()}
            )
        await publish_progress(scan_id, 'completed', status='completed', message='Terminé')
        log.info(f'shasec scan {scan_id} completed: {total_findings} finding(s) over {len(hosts)} host(s)')
    except Exception as exc:  # noqa: BLE001
        await _mark_failed(scan_id, exc)


async def _scan_host(
    scan_id: int, host_url: str, host_type: str, *, asset_id: int | None, profile: str, budget: int,
    label: str = '', allow_exploit: bool = False, auth_token: str | None = None, options: dict | None = None,
) -> int:
    """Run the scanner stage (budget-bounded) then the gated exploit stage against
    one host, persist findings/exploits tagged with ``asset_id`` + OWASP class, and
    return how many findings were kept."""
    ctx = ScanContext(scan_id=scan_id, target_url=host_url, target_type=host_type)
    plugins = get_plugins_for(host_type, profile)
    total_plugins = len(plugins)
    await publish_progress(
        scan_id, 'scanners.start',
        message=f'{label}{total_plugins} scanner(s) · {host_url} · profil {profile} · budget {budget}s',
        total=total_plugins, profile=profile, budget=budget,
    )

    done_count = 0
    done_lock = asyncio.Lock()

    async def _safe_run(p):
        await publish_progress(scan_id, 'plugin.start', message=f'{label}{p.name} en cours…', plugin=p.name)
        try:
            result = p.name, await asyncio.wait_for(p.run(ctx), timeout=p.timeout + 5)
        except Exception as exc:  # noqa: BLE001  — one plugin must never kill the scan
            log.error(f'shasec plugin {p.name} failed on scan {scan_id}: {exc}')
            result = p.name, []
        nonlocal done_count
        async with done_lock:
            done_count += 1
            current = done_count
        await publish_progress(
            scan_id, 'plugin.done', message=f'{label}{p.name} terminé ({current}/{total_plugins})',
            plugin=p.name, done=current, total=total_plugins,
        )
        return result

    # Budget-bounded scanner stage: run all selected plugins concurrently but
    # never let the slow tail exceed the profile's wall-clock budget. Plugins
    # still running at the deadline are cancelled; whatever already produced
    # findings is kept, so a hung scanner can't hold the whole scan hostage.
    tasks = [asyncio.create_task(_safe_run(p)) for p in plugins]
    done, pending = await asyncio.wait(tasks, timeout=budget) if tasks else (set(), set())
    for t in pending:
        t.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
        log.warning(
            f'shasec scan {scan_id}: {len(pending)} plugin(s) cancelled at budget {budget}s (profile {profile})'
        )
        await publish_progress(
            scan_id, 'scanners.budget',
            message=f'{label}{len(pending)} scanner(s) arrêté(s) au budget {budget}s', cancelled=len(pending),
        )
    results = [t.result() for t in done if not t.cancelled() and t.exception() is None]
    tagged = [(name, rf) for name, rfs in results for rf in rfs]
    aggregated = _aggregate(host_url, tagged)
    await publish_progress(scan_id, 'scanners.done', message=f'{label}{len(aggregated)} finding(s)', count=len(aggregated))

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
                    asset_id=asset_id,
                    owasp=classify_owasp(plugin_name, rf.title, severity=rf.severity),
                ),
            )
            finding.fingerprint = fp

    # Active-exploitation stage — strictly gated: explicit per-scan consent AND an
    # authorized target. Sends attack payloads (still read-only/bounded) and
    # records each request/response as proof.
    if allow_exploit:
        await publish_progress(scan_id, 'exploit.start', message=f'{label}Exploitation active…')
        await _run_exploit_stage(scan_id, host_url, host_type, auth_token, options, asset_id=asset_id)
        await publish_progress(scan_id, 'exploit.done', message=f'{label}Preuves collectées')

    return len(aggregated)
