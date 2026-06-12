from typing import Annotated

from fastapi import APIRouter, Path, Query, Request, Response

from backend.app.shasec.schema.ai_analysis import GetAIAnalysisDetails
from backend.app.shasec.schema.finding import GetFindingDetails
from backend.app.shasec.schema.report import GetReportDetails
from backend.app.shasec.schema.scan import CreateScanParam, GetScanDetails, QuickScanParam
from backend.app.shasec.service.finding_service import finding_service
from backend.app.shasec.service.report_service import report_service
from backend.app.shasec.service.scan_service import scan_service
from backend.common.pagination import DependsPagination, paging_data
from backend.common.response.response_schema import ResponseModel, response_base
from backend.common.security.jwt import DependsJwtAuth
from backend.database.db_postgres import CurrentSession
from backend.utils.serializers import select_as_dict, select_list_serialize

router = APIRouter(prefix='/scans', tags=['Scan'])


@router.get('/{pk}', summary='Get scan by ID', dependencies=[DependsJwtAuth])
async def get_scan(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    scan = await scan_service.get_by_id(pk=pk)
    data = GetScanDetails(**select_as_dict(scan))
    return response_base.success(request=request, data=data)


@router.get('/', summary='Get scans (paginated)', dependencies=[DependsJwtAuth, DependsPagination])
async def get_pagination_scans(
    request: Request,
    db: CurrentSession,
    target_id: Annotated[int | None, Query()] = None,
    status: Annotated[str | None, Query()] = None,
) -> ResponseModel:
    scan_select = await scan_service.get_select(target_id=target_id, status=status)
    page_data = await paging_data(db, scan_select, GetScanDetails)
    return response_base.success(request=request, data=page_data)


@router.post('/', summary='Create scan', dependencies=[DependsJwtAuth])
async def create_scan(request: Request, obj: CreateScanParam) -> ResponseModel:
    scan = await scan_service.create(obj=obj)
    data = GetScanDetails(**select_as_dict(scan))
    return response_base.success(request=request, data=data)


@router.post('/quick', summary='Quick scan from a URL', dependencies=[DependsJwtAuth])
async def quick_scan(request: Request, obj: QuickScanParam) -> ResponseModel:
    scan = await scan_service.quick(
        url=obj.url, type=obj.type, name=obj.name,
        allow_active_exploitation=obj.allow_active_exploitation,
        auth_token=obj.auth_token,
    )
    data = GetScanDetails(**select_as_dict(scan))
    return response_base.success(request=request, data=data)


@router.post('/{pk}/start', summary='Start scan', dependencies=[DependsJwtAuth])
async def start_scan(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    scan = await scan_service.start(pk=pk)
    data = GetScanDetails(**select_as_dict(scan))
    return response_base.success(request=request, data=data)


@router.post('/{pk}/cancel', summary='Cancel scan', dependencies=[DependsJwtAuth])
async def cancel_scan(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    count = await scan_service.cancel(pk=pk)
    if count > 0:
        return response_base.success(request=request)
    return response_base.fail(request=request)


@router.delete('/', summary='Delete scans', dependencies=[DependsJwtAuth])
async def delete_scans(request: Request, pk: Annotated[list[int], Query(...)]) -> ResponseModel:
    count = await scan_service.delete(pk=pk)
    if count > 0:
        return response_base.success(request=request)
    return response_base.fail(request=request)


@router.get('/{pk}/findings', summary='Get scan findings', dependencies=[DependsJwtAuth])
async def get_scan_findings(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    findings = await finding_service.get_by_scan(scan_id=pk)
    data = select_list_serialize(findings)
    return response_base.success(request=request, data=data)


@router.get('/{pk}/analysis', summary='Get scan AI analysis', dependencies=[DependsJwtAuth])
async def get_scan_analysis(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    analysis = await finding_service.get_analysis(scan_id=pk)
    data = GetAIAnalysisDetails(**select_as_dict(analysis)) if analysis else None
    return response_base.success(request=request, data=data)


@router.get('/{pk}/reports', summary='Get scan reports', dependencies=[DependsJwtAuth])
async def get_scan_reports(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
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
    report = await report_service.generate(scan_id=pk, format=format, lang=lang)
    data = GetReportDetails(**select_as_dict(report))
    return response_base.success(request=request, data=data)


@router.get('/{pk}/report/download', summary='Render & stream a report through the API', dependencies=[DependsJwtAuth])
async def download_scan_report(
    pk: Annotated[int, Path(...)],
    format: Annotated[str, Query()] = 'pdf',
    lang: Annotated[str, Query()] = 'fr',
) -> Response:
    # Streams the report bytes directly (no public MinIO needed). The client saves
    # and opens it locally; auth via the Bearer token like every other route.
    content, mime, filename = await report_service.render(scan_id=pk, format=format, lang=lang)
    return Response(
        content=content,
        media_type=mime,
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


@router.get('/{pk}/exploits', summary='Get scan exploit proofs', dependencies=[DependsJwtAuth])
async def get_scan_exploits(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    exploits = await finding_service.get_exploits(scan_id=pk)
    data = select_list_serialize(exploits)
    return response_base.success(request=request, data=data)
