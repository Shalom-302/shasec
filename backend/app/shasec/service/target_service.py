from typing import Sequence

from sqlalchemy import Select

from backend.app.shasec.schema.target import CreateTargetParam, UpdateTargetParam
from backend.common.exception import errors
from backend.crud.crud_target import target_dao
from backend.database.db_postgres import async_db_session
from backend.models import Target


class TargetService:
    @staticmethod
    async def get_by_id(*, pk: int) -> Target:
        async with async_db_session() as db:
            target = await target_dao.get(db, pk)
            if not target:
                raise errors.NotFoundError(msg='Target not found')
            return target

    @staticmethod
    async def get_select(*, name: str = None, type: str = None) -> Select:
        return await target_dao.get_list(name=name, type=type)

    @staticmethod
    async def create(*, obj: CreateTargetParam) -> Target:
        async with async_db_session.begin() as db:
            return await target_dao.create(db, obj)

    @staticmethod
    async def update(*, pk: int, obj: UpdateTargetParam) -> int:
        async with async_db_session.begin() as db:
            target = await target_dao.get(db, pk)
            if not target:
                raise errors.NotFoundError(msg='Target not found')
            return await target_dao.update(db, pk, obj)

    @staticmethod
    async def set_authorization(*, pk: int, is_authorized: bool) -> int:
        async with async_db_session.begin() as db:
            target = await target_dao.get(db, pk)
            if not target:
                raise errors.NotFoundError(msg='Target not found')
            return await target_dao.update(db, pk, {'is_authorized': is_authorized})

    @staticmethod
    async def delete(*, pk: list[int]) -> int:
        async with async_db_session.begin() as db:
            return await target_dao.delete(db, pk)


target_service: TargetService = TargetService()
