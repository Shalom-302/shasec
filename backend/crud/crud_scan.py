from typing import Sequence

from sqlalchemy import desc, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from backend.app.shasec.schema.scan import CreateScanParam
from backend.common.enums import ScanStatus
from backend.crud.crud_base import CRUDBase
from backend.models import Scan


class CRUDScan(CRUDBase[Scan]):
    async def get(self, db: AsyncSession, pk: int) -> Scan | None:
        return await self.select_model(db, pk)

    async def get_all(self, db: AsyncSession) -> Sequence[Scan]:
        return await self.select_models(db)

    async def get_list(self, target_id: int = None, status: str = None, owner_id: int | None = None) -> Select:
        """``owner_id`` set = tenant-scoped listing; None = every row (admins)."""
        stmt = select(self.model).order_by(desc(self.model.created_time))
        where_list = []
        if owner_id is not None:
            where_list.append(self.model.owner_id == owner_id)
        if target_id:
            where_list.append(self.model.target_id == target_id)
        if status:
            where_list.append(self.model.status == status)
        if where_list:
            stmt = stmt.where(*where_list)
        return stmt

    async def create(self, db: AsyncSession, obj_in: CreateScanParam, owner_id: int | None = None) -> Scan:
        return await self.create_model(db, obj_in, owner_id=owner_id)

    async def update(self, db: AsyncSession, pk: int, obj_in: dict) -> int:
        return await self.update_model(db, pk, obj_in)

    async def claim_for_start(self, db: AsyncSession, pk: int) -> int:
        """Atomically transition a scan from ``pending`` to ``queued`` (the worker
        flips it to ``running`` when a slot frees up).

        The conditional ``WHERE status = 'pending'`` makes the claim a single
        atomic statement: under concurrent ``POST /{id}/start`` calls Postgres
        serialises the UPDATEs on the row, so exactly one call affects a row
        (rowcount 1, the winner) and the rest see the already-flipped status and
        affect none (rowcount 0). Prevents the double-dispatch where two rapid
        starts both read ``pending`` and enqueue competing runs.
        """
        stmt = (
            update(self.model)
            .where(self.model.id == pk, self.model.status == ScanStatus.pending.value)
            .values(status=ScanStatus.queued.value)
        )
        result = await db.execute(stmt)
        return result.rowcount

    async def lock_owner(self, db: AsyncSession, owner_id: int) -> None:
        """Serialize scan launches of one account for the rest of the transaction,
        so the per-account active-scan limit can't be raced by parallel requests."""
        await db.execute(text('SELECT pg_advisory_xact_lock(:k1, :k2)'), {'k1': 7301, 'k2': owner_id})

    async def count_active(self, db: AsyncSession, owner_id: int) -> int:
        stmt = select(func.count()).select_from(self.model).where(
            self.model.owner_id == owner_id,
            self.model.status.in_([ScanStatus.queued.value, ScanStatus.running.value]),
        )
        return int((await db.execute(stmt)).scalar() or 0)

    async def count_awaiting(self, db: AsyncSession, owner_id: int) -> int:
        stmt = select(func.count()).select_from(self.model).where(
            self.model.owner_id == owner_id,
            self.model.status == ScanStatus.awaiting_approval.value,
        )
        return int((await db.execute(stmt)).scalar() or 0)

    async def queue_position(self, db: AsyncSession, pk: int) -> int:
        """1-based position among queued scans (FIFO by id)."""
        stmt = select(func.count()).select_from(self.model).where(
            self.model.status == ScanStatus.queued.value, self.model.id <= pk,
        )
        return int((await db.execute(stmt)).scalar() or 0)

    async def running_ids(self, db: AsyncSession) -> list[int]:
        stmt = select(self.model.id).where(self.model.status == ScanStatus.running.value)
        return list((await db.execute(stmt)).scalars())

    async def delete(self, db: AsyncSession, pk: list[int]) -> int:
        return await self.delete_model_by_column(db, allow_multiple=True, id__in=pk)


scan_dao: CRUDScan = CRUDScan(Scan)
