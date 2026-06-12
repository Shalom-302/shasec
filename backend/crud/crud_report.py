from typing import Sequence

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.shasec.schema.report import CreateReportParam
from backend.crud.crud_base import CRUDBase
from backend.models import Report


class CRUDReport(CRUDBase[Report]):
    async def get(self, db: AsyncSession, pk: int) -> Report | None:
        return await self.select_model(db, pk)

    async def get_by_scan(self, db: AsyncSession, scan_id: int) -> Sequence[Report]:
        stmt = select(self.model).where(self.model.scan_id == scan_id).order_by(desc(self.model.id))
        result = await db.execute(stmt)
        return result.scalars().all()

    async def create(self, db: AsyncSession, obj_in: CreateReportParam) -> Report:
        return await self.create_model(db, obj_in)


report_dao: CRUDReport = CRUDReport(Report)
