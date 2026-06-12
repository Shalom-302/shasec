from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.shasec.schema.ai_analysis import CreateAIAnalysisParam
from backend.crud.crud_base import CRUDBase
from backend.models import AIAnalysis


class CRUDAIAnalysis(CRUDBase[AIAnalysis]):
    async def get_by_scan(self, db: AsyncSession, scan_id: int) -> AIAnalysis | None:
        stmt = select(self.model).where(self.model.scan_id == scan_id)
        result = await db.execute(stmt)
        return result.scalars().first()

    async def create(self, db: AsyncSession, obj_in: CreateAIAnalysisParam) -> AIAnalysis:
        return await self.create_model(db, obj_in)


ai_analysis_dao: CRUDAIAnalysis = CRUDAIAnalysis(AIAnalysis)
