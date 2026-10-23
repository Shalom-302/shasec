from typing import Annotated

from fastapi import APIRouter, Path, Request

from backend.app.shasec.schema.notification import GetNotificationDetails
from backend.app.shasec.service.access import actor_from
from backend.app.shasec.service.notification_service import notification_service
from backend.common.pagination import DependsPagination, paging_data
from backend.common.response.response_schema import ResponseModel, response_base
from backend.common.security.jwt import DependsJwtAuth
from backend.database.db_postgres import CurrentSession

router = APIRouter(prefix='/notifications', tags=['Notifications'])


@router.get('/me', summary='My notifications (paginated)', dependencies=[DependsJwtAuth, DependsPagination])
async def get_my_notifications(request: Request, db: CurrentSession) -> ResponseModel:
    stmt = notification_service.list_select(actor_from(request).id)
    page_data = await paging_data(db, stmt, GetNotificationDetails)
    return response_base.success(request=request, data=page_data)


@router.get('/me/unread-count', summary='My unread notification count', dependencies=[DependsJwtAuth])
async def get_unread_count(request: Request) -> ResponseModel:
    count = await notification_service.unread_count(actor_from(request).id)
    return response_base.success(request=request, data={'count': count})


@router.post('/{pk}/read', summary='Mark one notification read', dependencies=[DependsJwtAuth])
async def mark_read(request: Request, pk: Annotated[int, Path(...)]) -> ResponseModel:
    await notification_service.mark_read(actor_from(request).id, pk)
    return response_base.success(request=request)


@router.post('/read-all', summary='Mark all my notifications read', dependencies=[DependsJwtAuth])
async def mark_all_read(request: Request) -> ResponseModel:
    count = await notification_service.mark_read(actor_from(request).id)
    return response_base.success(request=request, data={'updated': count})
