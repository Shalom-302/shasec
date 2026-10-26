from typing import Sequence

from sqlalchemy import asc, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.crud.crud_base import CRUDBase
from backend.models import ScanAsset


class CRUDScanAsset(CRUDBase[ScanAsset]):
    async def get_by_scan(self, db: AsyncSession, scan_id: int) -> Sequence[ScanAsset]:
        stmt = select(self.model).where(self.model.scan_id == scan_id).order_by(asc(self.model.id))
        return (await db.execute(stmt)).scalars().all()

    async def get_selected(self, db: AsyncSession, scan_id: int) -> Sequence[ScanAsset]:
        stmt = select(self.model).where(
            self.model.scan_id == scan_id, self.model.selected.is_(True)
        ).order_by(asc(self.model.id))
        return (await db.execute(stmt)).scalars().all()

    async def set_selection(self, db: AsyncSession, scan_id: int, asset_ids: list[int]) -> int:
        """Mark exactly ``asset_ids`` as in-scope for this scan; unmark the rest."""
        await db.execute(update(self.model).where(self.model.scan_id == scan_id).values(selected=False))
        if not asset_ids:
            return 0
        res = await db.execute(
            update(self.model)
            .where(self.model.scan_id == scan_id, self.model.id.in_(asset_ids))
            .values(selected=True)
        )
        return res.rowcount


scan_asset_dao: CRUDScanAsset = CRUDScanAsset(ScanAsset)
