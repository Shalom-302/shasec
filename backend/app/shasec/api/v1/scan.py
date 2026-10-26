import json
from typing import Annotated

from fastapi import APIRouter, Path, Query, Request, Response, WebSocket

from backend.app.shasec.schema.ai_analysis import GetAIAnalysisDetails
from backend.app.shasec.schema.finding import GetFindingDetails
from backend.app.shasec.schema.report import GetReportDetails
from backend.app.shasec.schema.scan import AdvancedScanParam, AuditScanParam, CreateScanParam, GetScanDetails, QuickScanParam, ReviewParam
from backend.app.shasec.schema.scan_asset import GetScanAssetDetails, SelectAssetsParam
from backend.app.shasec.service.finding_service import finding_service
from backend.app.shasec.service.progress import channel as progress_channel
from backend.app.shasec.service.progress import describe as progress_describe
from backend.app.shasec.service.progress import snapshot as progress_snapshot
from backend.app.shasec.service.report_service import report_service
from backend.app.shasec.service.access import Actor, actor_from, require_admin
from backend.app.shasec.service.scan_service import scan_service
from backend.common.enums import ScanBilling, ScanStatus
from backend.crud.crud_scan import scan_dao
from backend.common.exception import errors
from backend.common.enums import Role as RoleEnum
from backend.common.security.jwt import get_current_user, jwt_authentication
from backend.database.db_postgres import async_db_session
from backend.database.db_redis import redis_client
from backend.common.pagination import DependsPagination, paging_data
from backend.common.response.response_schema import ResponseModel, response_base
from backend.common.security.jwt import DependsJwtAuth
from backend.database.db_postgres import CurrentSession
from backend.utils.serializers import select_as_dict, select_list_serialize

router = APIRouter(prefix='/scans', tags=['Scan'])


async def _owned_scan(request: Request, pk: int):
    """Tenant gate for every per-scan route (404 if not the caller's)."""
    return await scan_service.get_by_id(actor=actor_from(request), pk=pk)


async def _reportable_scan(request: Request, pk: int):
    scan = await _owned_scan(request, pk)
    if scan.billing == ScanBilling.free.value:
        raise errors.PaymentRequiredError(
            msg='Les rapports détaillés sont réservés aux scans payés en crédits.'
        )
    return scan


@router.get('/pending-approval', summary='[admin] Advanced audits awaiting approval',
            dependencies=[DependsJwtAuth, DependsPagination])
async def get_pending_approval(request: Request, db: CurrentSession) -> ResponseModel:
    stmt = await scan_service.pending_approval_select(actor=actor_from(request))
    page_data = await paging_data(db, stmt, GetScanDetails)
    return response_base.success(request=request, data=page_data)


@router.get('/{pk}', summary='Get scan by ID', dependencies=[DependsJwtAuth])
async def get_scan(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    scan = await _owned_scan(request, pk)
    data = GetScanDetails(**select_as_dict(scan))
    return response_base.success(request=request, data=data)


@router.get('/', summary='Get scans (paginated)', dependencies=[DependsJwtAuth, DependsPagination])
async def get_pagination_scans(
    request: Request,
    db: CurrentSession,
    target_id: Annotated[int | None, Query()] = None,
    status: Annotated[str | None, Query()] = None,
) -> ResponseModel:
    scan_select = await scan_service.get_select(actor=actor_from(request), target_id=target_id, status=status)
    page_data = await paging_data(db, scan_select, GetScanDetails)
    return response_base.success(request=request, data=page_data)


@router.post('/', summary='Create scan', dependencies=[DependsJwtAuth])
async def create_scan(request: Request, obj: CreateScanParam) -> ResponseModel:
    scan = await scan_service.create(actor=actor_from(request), obj=obj)
    data = GetScanDetails(**select_as_dict(scan))
    return response_base.success(request=request, data=data)


@router.post('/quick', summary='Quick scan from a URL', dependencies=[DependsJwtAuth])
async def quick_scan(request: Request, obj: QuickScanParam) -> ResponseModel:
    scan = await scan_service.quick(
        actor=actor_from(request), url=obj.url, type=obj.type, name=obj.name,
        allow_active_exploitation=obj.allow_active_exploitation,
        profile=obj.profile,
        aggression=obj.aggression,
        auth_token=obj.auth_token,
        id_range=obj.id_range,
        allow_destructive=obj.allow_destructive,
    )
    data = GetScanDetails(**select_as_dict(scan))
    return response_base.success(request=request, data=data)


@router.post('/audit', summary='Start a whole-domain audit (5-step hunt) — admin/operator',
             dependencies=[DependsJwtAuth])
async def start_domain_audit(request: Request, obj: AuditScanParam) -> ResponseModel:
    actor = actor_from(request)
    require_admin(actor)
    scan = await scan_service.quick(
        actor=actor, url=obj.url, type=obj.type, name=obj.name, mode='audit',
        allow_active_exploitation=obj.allow_active_exploitation, profile=obj.profile,
        aggression=obj.aggression, auth_token=obj.auth_token, id_range=obj.id_range,
        allow_destructive=obj.allow_destructive,
    )
    return response_base.success(request=request, data=GetScanDetails(**select_as_dict(scan)))


@router.get('/{pk}/assets', summary='Discovered hosts of a domain audit (cartography)',
            dependencies=[DependsJwtAuth])
async def get_scan_assets(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    assets = await scan_service.assets(actor=actor_from(request), pk=pk)
    data = [GetScanAssetDetails.model_validate(a) for a in assets]
    return response_base.success(request=request, data=data)


@router.post('/{pk}/scope', summary='Select in-scope hosts and resume a domain audit',
             dependencies=[DependsJwtAuth])
async def set_scan_scope(request: Request, pk: Annotated[int, Path(...)], obj: SelectAssetsParam) -> ResponseModel:
    scan = await scan_service.set_scope(actor=actor_from(request), pk=pk, asset_ids=obj.asset_ids)
    return response_base.success(request=request, data=GetScanDetails(**select_as_dict(scan)))


@router.post('/advanced', summary='Request an advanced (active) audit — needs admin approval',
             dependencies=[DependsJwtAuth])
async def request_advanced_scan(request: Request, obj: AdvancedScanParam) -> ResponseModel:
    scan = await scan_service.request_advanced(
        actor=actor_from(request), target_id=obj.target_id, profile=obj.profile, scope_note=obj.scope_note)
    return response_base.success(request=request, data=GetScanDetails(**select_as_dict(scan)))


@router.post('/{pk}/approve', summary='[admin] Approve an advanced audit request', dependencies=[DependsJwtAuth])
async def approve_scan(request: Request, pk: Annotated[int, Path(...)], obj: ReviewParam) -> ResponseModel:
    scan = await scan_service.approve(actor=actor_from(request), pk=pk, note=obj.note)
    return response_base.success(request=request, data=GetScanDetails(**select_as_dict(scan)))


@router.post('/{pk}/reject', summary='[admin] Reject an advanced audit request', dependencies=[DependsJwtAuth])
async def reject_scan(request: Request, pk: Annotated[int, Path(...)], obj: ReviewParam) -> ResponseModel:
    scan = await scan_service.reject(actor=actor_from(request), pk=pk, note=obj.note)
    return response_base.success(request=request, data=GetScanDetails(**select_as_dict(scan)))


@router.post('/{pk}/start', summary='Start scan', dependencies=[DependsJwtAuth])
async def start_scan(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    scan = await scan_service.start(actor=actor_from(request), pk=pk)
    data = GetScanDetails(**select_as_dict(scan))
    return response_base.success(request=request, data=data)


@router.post('/{pk}/cancel', summary='Cancel scan', dependencies=[DependsJwtAuth])
async def cancel_scan(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    count = await scan_service.cancel(actor=actor_from(request), pk=pk)
    if count > 0:
        return response_base.success(request=request)
    return response_base.fail(request=request)


@router.delete('/', summary='Delete scans', dependencies=[DependsJwtAuth])
async def delete_scans(request: Request, pk: Annotated[list[int], Query(...)]) -> ResponseModel:
    count = await scan_service.delete(actor=actor_from(request), pk=pk)
    if count > 0:
        return response_base.success(request=request)
    return response_base.fail(request=request)


@router.get('/{pk}/findings', summary='Get scan findings', dependencies=[DependsJwtAuth])
async def get_scan_findings(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    await _owned_scan(request, pk)
    findings = await finding_service.get_by_scan(scan_id=pk)
    data = select_list_serialize(findings)
    return response_base.success(request=request, data=data)


@router.get('/{pk}/analysis', summary='Get scan AI analysis', dependencies=[DependsJwtAuth])
async def get_scan_analysis(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    await _owned_scan(request, pk)
    analysis = await finding_service.get_analysis(scan_id=pk)
    data = GetAIAnalysisDetails(**select_as_dict(analysis)) if analysis else None
    return response_base.success(request=request, data=data)


@router.get('/{pk}/reports', summary='Get scan reports', dependencies=[DependsJwtAuth])
async def get_scan_reports(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    await _owned_scan(request, pk)
    reports = await finding_service.get_reports(scan_id=pk)
    data = select_list_serialize(reports)
    return response_base.success(request=request, data=data)


@router.post('/{pk}/report', summary='Generate a report (html/markdown/json/pdf)', dependencies=[DependsJwtAuth])
async def generate_scan_report(
    request: Request,
    pk: Annotated[int, Path(...)],
    format: Annotated[str, Query()] = 'html',
    lang: Annotated[str, Query()] = 'fr',
) -> ResponseModel:
    await _reportable_scan(request, pk)
    report = await report_service.generate(scan_id=pk, format=format, lang=lang)
    data = GetReportDetails(**select_as_dict(report))
    return response_base.success(request=request, data=data)


@router.get('/{pk}/report/download', summary='Render & stream a report through the API', dependencies=[DependsJwtAuth])
async def download_scan_report(
    request: Request,
    pk: Annotated[int, Path(...)],
    format: Annotated[str, Query()] = 'pdf',
    lang: Annotated[str, Query()] = 'fr',
) -> Response:
    # Streams the report bytes directly (no public MinIO needed). The client saves
    # and opens it locally; auth via the Bearer token like every other route.
    await _reportable_scan(request, pk)
    content, mime, filename = await report_service.render(scan_id=pk, format=format, lang=lang)
    return Response(
        content=content,
        media_type=mime,
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


@router.websocket('/{pk}/ws')
async def scan_progress_ws(websocket: WebSocket, pk: Annotated[int, Path(...)]) -> None:
    """Live scan progress. WebSockets can't carry the HTTP bearer dependency, so
    the JWT is passed as ?token= and validated here. Forwards Redis pub/sub events
    (published by the pipeline) until the scan completes or the client disconnects.
    """
    try:
        sub = await jwt_authentication(websocket.query_params.get('token', ''))
        async with async_db_session() as db:
            user = await get_current_user(db, sub)
        roles = [r.name for r in (user.roles or [])]
        actor = Actor(id=user.id, is_admin=RoleEnum.ADMIN.value in roles)
        await scan_service.get_by_id(actor=actor, pk=pk)
    except Exception:  # noqa: BLE001 — invalid/absent token or not the caller's scan
        await websocket.close(code=1008)
        return

    await websocket.accept()
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(progress_channel(pk))
    try:
        async for msg in pubsub.listen():
            if msg.get('type') != 'message':
                continue
            await websocket.send_text(msg['data'])
            try:
                if json.loads(msg['data']).get('event') in ('completed', 'failed'):
                    break
            except (ValueError, TypeError):
                pass
    except Exception:  # noqa: BLE001 — client disconnect / transport error
        pass
    finally:
        try:
            await pubsub.unsubscribe(progress_channel(pk))
            await pubsub.aclose()
        except Exception:  # noqa: BLE001
            pass


@router.get('/{pk}/progress', summary='Scan progress: current phase, percent and steps', dependencies=[DependsJwtAuth])
async def get_scan_progress(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    """Pull the live progress of a scan over plain HTTP (poll this, or use the
    WebSocket for push). Returns the current macro-phase (Reconnaissance & scan,
    Corrélation, Validation contrôlée, Analyse IA…), a 0-100 percent, per-scanner
    counts (which are done, which are still running), and the ordered step log.
    """
    scan = await _owned_scan(request, pk)
    events = await progress_snapshot(pk)
    db_status = getattr(scan, 'status', None)
    data = progress_describe(events, db_status=db_status)
    data['db_status'] = db_status
    if db_status == ScanStatus.queued.value:
        async with async_db_session() as db:
            data['queue_position'] = await scan_dao.queue_position(db, pk)
    return response_base.success(request=request, data=data)


@router.get('/{pk}/exploits', summary='Get scan exploit proofs', dependencies=[DependsJwtAuth])
async def get_scan_exploits(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    await _owned_scan(request, pk)
    exploits = await finding_service.get_exploits(scan_id=pk)
    data = select_list_serialize(exploits)
    return response_base.success(request=request, data=data)
