from typing import Annotated

from fastapi import APIRouter, Path, Query, Request

from backend.app.shasec.schema.target import (
    AuthorizeTargetParam,
    CreateTargetParam,
    GetTargetDetails,
    UpdateTargetParam,
)
from backend.app.shasec.service.target_service import target_service
from backend.common.pagination import DependsPagination, paging_data
from backend.common.response.response_schema import ResponseModel, response_base
from backend.common.security.jwt import DependsJwtAuth
from backend.database.db_postgres import CurrentSession
from backend.utils.serializers import select_as_dict

router = APIRouter(prefix='/targets', tags=['Target'])


@router.get('/{pk}', summary='Get target by ID', dependencies=[DependsJwtAuth])
async def get_target(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    target = await target_service.get_by_id(pk=pk)
    data = GetTargetDetails(**select_as_dict(target))
    return response_base.success(request=request, data=data)


@router.get('/', summary='Get targets (paginated)', dependencies=[DependsJwtAuth, DependsPagination])
async def get_pagination_targets(
    request: Request,
    db: CurrentSession,
    name: Annotated[str | None, Query()] = None,
    type: Annotated[str | None, Query()] = None,
) -> ResponseModel:
    target_select = await target_service.get_select(name=name, type=type)
    page_data = await paging_data(db, target_select, GetTargetDetails)
    return response_base.success(request=request, data=page_data)


@router.post('/', summary='Create target', dependencies=[DependsJwtAuth])
async def create_target(request: Request, obj: CreateTargetParam) -> ResponseModel:
    target = await target_service.create(obj=obj)
    data = GetTargetDetails(**select_as_dict(target))
    return response_base.success(request=request, data=data)


@router.put('/{pk}', summary='Update target', dependencies=[DependsJwtAuth])
async def update_target(
    request: Request, pk: Annotated[int, Path(...)], obj: UpdateTargetParam
) -> ResponseModel:
    count = await target_service.update(pk=pk, obj=obj)
    if count > 0:
        return response_base.success(request=request)
    return response_base.fail(request=request)


@router.post('/{pk}/authorize', summary='Authorize (or revoke) a target for scanning', dependencies=[DependsJwtAuth])
async def authorize_target(
    request: Request, pk: Annotated[int, Path(...)], obj: AuthorizeTargetParam
) -> ResponseModel:
    count = await target_service.set_authorization(pk=pk, is_authorized=obj.is_authorized)
    if count > 0:
        return response_base.success(request=request)
    return response_base.fail(request=request)


@router.delete('/', summary='Delete targets', dependencies=[DependsJwtAuth])
async def delete_targets(request: Request, pk: Annotated[list[int], Query(...)]) -> ResponseModel:
    count = await target_service.delete(pk=pk)
    if count > 0:
        return response_base.success(request=request)
    return response_base.fail(request=request)
