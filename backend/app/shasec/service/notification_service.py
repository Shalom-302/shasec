"""In-app notifications: fan-out to admins, per-user inbox, read state."""
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.common.enums import Role as RoleEnum
from backend.database.db_postgres import async_db_session
from backend.models import Role, User
from backend.models.notification import Notification
from backend.models.associations import user_role


class NotificationService:
    @staticmethod
    async def _create(db: AsyncSession, user_id: int, *, kind: str, title: str,
                      body: str | None = None, link: str | None = None) -> None:
        db.add(Notification(user_id=user_id, kind=kind, title=title, body=body, link=link))

    @staticmethod
    async def notify_user(user_id: int, *, kind: str, title: str, body: str | None = None,
                          link: str | None = None) -> None:
        async with async_db_session.begin() as db:
            await NotificationService._create(db, user_id, kind=kind, title=title, body=body, link=link)

    @staticmethod
    async def notify_admins(*, kind: str, title: str, body: str | None = None, link: str | None = None) -> None:
        async with async_db_session.begin() as db:
            admin_ids = (await db.execute(
                select(User.id)
                .join(user_role, user_role.c.user_id == User.id)
                .join(Role, Role.id == user_role.c.role_id)
                .where(Role.name == RoleEnum.ADMIN.value)
            )).scalars().all()
            for uid in set(admin_ids):
                await NotificationService._create(db, uid, kind=kind, title=title, body=body, link=link)

    @staticmethod
    def list_select(user_id: int):
        return select(Notification).where(Notification.user_id == user_id).order_by(Notification.id.desc())

    @staticmethod
    async def unread_count(user_id: int) -> int:
        async with async_db_session() as db:
            return int((await db.execute(
                select(func.count()).select_from(Notification)
                .where(Notification.user_id == user_id, Notification.is_read.is_(False))
            )).scalar() or 0)

    @staticmethod
    async def mark_read(user_id: int, pk: int | None = None) -> int:
        async with async_db_session.begin() as db:
            stmt = update(Notification).where(Notification.user_id == user_id, Notification.is_read.is_(False))
            if pk is not None:
                stmt = stmt.where(Notification.id == pk)
            return (await db.execute(stmt.values(is_read=True))).rowcount


notification_service: NotificationService = NotificationService()
