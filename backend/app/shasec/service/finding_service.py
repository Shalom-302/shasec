from typing import Sequence

from sqlalchemy import Select

from backend.crud.crud_ai_analysis import ai_analysis_dao
from backend.crud.crud_exploit import exploit_dao
from backend.crud.crud_finding import finding_dao
from backend.crud.crud_report import report_dao
from backend.database.db_postgres import async_db_session
from backend.models import AIAnalysis, Exploit, Finding, Report


class FindingService:
    @staticmethod
    async def get_by_scan(*, scan_id: int) -> Sequence[Finding]:
        async with async_db_session() as db:
            return await finding_dao.get_by_scan(db, scan_id)

    @staticmethod
    async def get_select(*, scan_id: int = None, severity: str = None, plugin: str = None) -> Select:
        return await finding_dao.get_list(scan_id=scan_id, severity=severity, plugin=plugin)

    @staticmethod
    async def get_analysis(*, scan_id: int) -> AIAnalysis | None:
        async with async_db_session() as db:
            return await ai_analysis_dao.get_by_scan(db, scan_id)

    @staticmethod
    async def get_reports(*, scan_id: int) -> Sequence[Report]:
        async with async_db_session() as db:
            return await report_dao.get_by_scan(db, scan_id)

    @staticmethod
    async def get_exploits(*, scan_id: int) -> Sequence[Exploit]:
        async with async_db_session() as db:
            return await exploit_dao.get_by_scan(db, scan_id)


finding_service: FindingService = FindingService()
