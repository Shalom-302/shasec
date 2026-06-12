from typing import Sequence

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from backend.app.shasec.schema.scan import CreateScanParam
from backend.crud.crud_base import CRUDBase
from backend.models import Scan


class CRUDScan(CRUDBase[Scan]):
    async def get(self, db: AsyncSession, pk: int) -> Scan | None:
        return await self.select_model(db, pk)

    async def get_all(self, db: AsyncSession) -> Sequence[Scan]:
        return await self.select_models(db)

    async def get_list(self, target_id: int = None, status: str = None) -> Select:
        stmt = select(self.model).order_by(desc(self.model.created_time))
        where_list = []
        if target_id:
            where_list.append(self.model.target_id == target_id)
        if status:
            where_list.append(self.model.status == status)
        if where_list:
            stmt = stmt.where(*where_list)
        return stmt

    async def create(self, db: AsyncSession, obj_in: CreateScanParam) -> Scan:
        return await self.create_model(db, obj_in)

    async def update(self, db: AsyncSession, pk: int, obj_in: dict) -> int:
        return await self.update_model(db, pk, obj_in)

    async def delete(self, db: AsyncSession, pk: list[int]) -> int:
        return await self.delete_model_by_column(db, allow_multiple=True, id__in=pk)


scan_dao: CRUDScan = CRUDScan(Scan)
