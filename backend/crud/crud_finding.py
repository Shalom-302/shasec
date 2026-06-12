from typing import Sequence

from sqlalchemy import asc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from backend.app.shasec.schema.finding import CreateFindingParam
from backend.crud.crud_base import CRUDBase
from backend.models import Finding


class CRUDFinding(CRUDBase[Finding]):
    async def get(self, db: AsyncSession, pk: int) -> Finding | None:
        return await self.select_model(db, pk)

    async def get_by_scan(self, db: AsyncSession, scan_id: int) -> Sequence[Finding]:
        stmt = select(self.model).where(self.model.scan_id == scan_id).order_by(asc(self.model.id))
        result = await db.execute(stmt)
        return result.scalars().all()

    async def get_list(self, scan_id: int = None, severity: str = None, plugin: str = None) -> Select:
        stmt = select(self.model).order_by(asc(self.model.id))
        where_list = []
        if scan_id:
            where_list.append(self.model.scan_id == scan_id)
        if severity:
            where_list.append(self.model.severity == severity)
        if plugin:
            where_list.append(self.model.plugin == plugin)
        if where_list:
            stmt = stmt.where(*where_list)
        return stmt

    async def create(self, db: AsyncSession, obj_in: CreateFindingParam) -> Finding:
        return await self.create_model(db, obj_in)

    async def delete_by_scan(self, db: AsyncSession, scan_id: int) -> int:
        return await self.delete_model_by_column(db, allow_multiple=True, scan_id=scan_id)


finding_dao: CRUDFinding = CRUDFinding(Finding)
