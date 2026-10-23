from typing import Sequence

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from backend.app.shasec.schema.target import CreateTargetParam, UpdateTargetParam
from backend.crud.crud_base import CRUDBase
from backend.models import Target


class CRUDTarget(CRUDBase[Target]):
    async def get(self, db: AsyncSession, pk: int) -> Target | None:
        return await self.select_model(db, pk)

    async def get_all(self, db: AsyncSession) -> Sequence[Target]:
        return await self.select_models(db)

    async def get_list(self, name: str = None, type: str = None, owner_id: int | None = None) -> Select:
        """``owner_id`` set = tenant-scoped listing; None = every row (admins)."""
        stmt = select(self.model).order_by(desc(self.model.created_time))
        where_list = []
        if owner_id is not None:
            where_list.append(self.model.owner_id == owner_id)
        if name:
            where_list.append(self.model.name.like(f'%{name}%'))
        if type:
            where_list.append(self.model.type == type)
        if where_list:
            stmt = stmt.where(*where_list)
        return stmt

    async def create(self, db: AsyncSession, obj_in: CreateTargetParam, owner_id: int | None = None) -> Target:
        return await self.create_model(db, obj_in, owner_id=owner_id)

    async def update(self, db: AsyncSession, pk: int, obj_in: UpdateTargetParam | dict) -> int:
        return await self.update_model(db, pk, obj_in)

    async def delete(self, db: AsyncSession, pk: list[int]) -> int:
        return await self.delete_model_by_column(db, allow_multiple=True, id__in=pk)


target_dao: CRUDTarget = CRUDTarget(Target)
