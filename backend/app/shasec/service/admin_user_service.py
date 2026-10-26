"""Admin user-management (SaaS governance).

Lists client accounts with per-user aggregates (credits, scans, pending audit
requests) and derived *risk signals*, and performs privileged actions —
suspend / reactivate / credit-adjust — each written to an append-only
``AdminAudit`` trail and notified to the client.

Suspending an account flips ``User.status`` (which already blocks login and
token-refresh) AND evicts the account's live sessions from Redis: the JWT
middleware caches a user snapshot for 7 days and skips the DB status check on a
cache hit, so without this eviction a banned user would keep working until the
cache expired. We delete the three key families keyed by the account's x_id
(the JWT ``sub``): access tokens, refresh tokens and the cached user snapshot.
"""
from datetime import timedelta

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.shasec.service.credit_service import credit_service
from backend.common.enums import CreditKind, CreditSource, Role as RoleEnum, ScanStatus
from backend.common.exception import errors
from backend.core.conf import settings
from backend.crud.crud_user import user_dao
from backend.database.db_postgres import async_db_session
from backend.database.db_redis import redis_client
from backend.models import Role, Scan, Target, User
from backend.models.admin_audit import AdminAudit
from backend.models.associations import user_role
from backend.models.credit import CreditGrant, CreditVoucher
from backend.utils.timezone import timezone

# Risk thresholds (tunable). Kept conservative — a flag is a prompt to look,
# not an accusation.
_ACTIVE_AUDIT_MED = 3   # advanced/active-exploitation scans requested
_ACTIVE_AUDIT_HIGH = 6
_DOMAIN_SPREAD_MED = 3  # distinct targets hit with active tests
_DOMAIN_SPREAD_HIGH = 6
_VOLUME_INFO = 25       # total scans — informational "heavy user"
_SEV_ORDER = {'none': 0, 'low': 1, 'medium': 2, 'high': 3}


def _is_admin(user: User) -> bool:
    return any(getattr(r, 'name', None) == RoleEnum.ADMIN.value for r in (user.roles or []))


def _risk_signals(m: dict) -> list[dict]:
    """Derive risk signals from a per-user metrics dict. ``m`` keys:
    total, failed, awaiting, active_exploit, distinct_active_domains (optional)."""
    out: list[dict] = []
    total = m.get('total', 0)
    failed = m.get('failed', 0)
    if total >= 4 and failed >= 3 and failed * 2 >= total:
        out.append({'code': 'high_failure', 'label': 'Taux d’échec élevé',
                    'detail': f'{failed} scans en échec sur {total}.', 'severity': 'medium'})
    ae = m.get('active_exploit', 0)
    if ae >= _ACTIVE_AUDIT_MED:
        out.append({'code': 'active_audits', 'label': 'Nombreux audits actifs',
                    'detail': f'{ae} scans à tests actifs (XSS/injection/BOLA) demandés.',
                    'severity': 'high' if ae >= _ACTIVE_AUDIT_HIGH else 'medium'})
    dsd = m.get('distinct_active_domains', 0)
    if dsd >= _DOMAIN_SPREAD_MED:
        out.append({'code': 'domain_spread', 'label': 'Cibles actives variées',
                    'detail': f'Tests actifs demandés sur {dsd} cibles distinctes — à vérifier.',
                    'severity': 'high' if dsd >= _DOMAIN_SPREAD_HIGH else 'medium'})
    if m.get('awaiting', 0) >= 3:
        out.append({'code': 'pending_pileup', 'label': 'Demandes en attente',
                    'detail': f'{m["awaiting"]} demandes d’audit en attente de validation.', 'severity': 'low'})
    if total >= _VOLUME_INFO:
        out.append({'code': 'volume', 'label': 'Volume de scans élevé',
                    'detail': f'{total} scans lancés au total.', 'severity': 'low'})
    return out


def _risk_level(signals: list[dict]) -> str:
    lvl = 'none'
    for s in signals:
        if _SEV_ORDER[s['severity']] > _SEV_ORDER[lvl]:
            lvl = s['severity']
    return lvl


class AdminUserService:
    # ---- aggregate helpers ---------------------------------------------------
    @staticmethod
    async def _scan_metrics(db: AsyncSession, owner_ids: list[int] | None = None) -> dict[int, dict]:
        stmt = select(
            Scan.owner_id,
            func.count().label('total'),
            func.sum(case((Scan.status == ScanStatus.failed.value, 1), else_=0)).label('failed'),
            func.sum(case((Scan.status.in_([ScanStatus.queued.value, ScanStatus.running.value]), 1), else_=0)).label('active'),
            func.sum(case((Scan.status == ScanStatus.awaiting_approval.value, 1), else_=0)).label('awaiting'),
            func.sum(case((Scan.allow_active_exploitation.is_(True), 1), else_=0)).label('active_exploit'),
        ).where(Scan.owner_id.is_not(None)).group_by(Scan.owner_id)
        if owner_ids is not None:
            stmt = stmt.where(Scan.owner_id.in_(owner_ids))
        rows = (await db.execute(stmt)).all()
        return {r.owner_id: {'total': int(r.total or 0), 'failed': int(r.failed or 0),
                             'active': int(r.active or 0), 'awaiting': int(r.awaiting or 0),
                             'active_exploit': int(r.active_exploit or 0)} for r in rows}

    @staticmethod
    async def _target_metrics(db: AsyncSession, owner_ids: list[int] | None = None) -> dict[int, dict]:
        stmt = select(
            Target.owner_id,
            func.count().label('total'),
            func.sum(case((Target.is_authorized.is_(True), 1), else_=0)).label('authorized'),
        ).where(Target.owner_id.is_not(None)).group_by(Target.owner_id)
        if owner_ids is not None:
            stmt = stmt.where(Target.owner_id.in_(owner_ids))
        rows = (await db.execute(stmt)).all()
        return {r.owner_id: {'total': int(r.total or 0), 'authorized': int(r.authorized or 0)} for r in rows}

    @staticmethod
    async def _credit_metrics(db: AsyncSession, user_ids: list[int] | None = None) -> dict[int, dict]:
        now = timezone.now()
        stmt = select(
            CreditGrant.user_id, CreditGrant.kind, func.coalesce(func.sum(CreditGrant.remaining), 0),
        ).where(
            CreditGrant.remaining > 0,
            or_(CreditGrant.expires_at.is_(None), CreditGrant.expires_at > now),
        ).group_by(CreditGrant.user_id, CreditGrant.kind)
        if user_ids is not None:
            stmt = stmt.where(CreditGrant.user_id.in_(user_ids))
        out: dict[int, dict] = {}
        for uid, kind, total in (await db.execute(stmt)).all():
            bucket = out.setdefault(uid, {'credits': 0, 'free_scans': 0})
            if kind == CreditKind.credit.value:
                bucket['credits'] = int(total or 0)
            elif kind == CreditKind.free_scan.value:
                bucket['free_scans'] = int(total or 0)
        return out

    @staticmethod
    async def _distinct_active_domains(db: AsyncSession, user_id: int) -> int:
        stmt = select(func.count(func.distinct(Scan.target_id))).where(
            Scan.owner_id == user_id, Scan.allow_active_exploitation.is_(True),
        )
        return int((await db.execute(stmt)).scalar() or 0)

    # ---- listing -------------------------------------------------------------
    async def list_users(self, *, page: int, size: int, q: str | None = None,
                         status: bool | None = None, role: str | None = None) -> dict:
        async with async_db_session() as db:
            base = select(User)
            where = []
            if q:
                where.append(User.email.ilike(f'%{q}%'))
            if status is not None:
                where.append(User.status == status)
            if role:
                base = base.join(user_role, user_role.c.user_id == User.id).join(Role, Role.id == user_role.c.role_id)
                where.append(Role.name == role)
            if where:
                base = base.where(and_(*where))

            total = int((await db.execute(
                select(func.count()).select_from(base.order_by(None).subquery())
            )).scalar() or 0)

            rows = (await db.execute(
                base.order_by(User.join_time.desc()).offset((page - 1) * size).limit(size)
            )).unique().scalars().all()

            ids = [u.id for u in rows]
            scans = await self._scan_metrics(db, ids) if ids else {}
            targets = await self._target_metrics(db, ids) if ids else {}
            credits = await self._credit_metrics(db, ids) if ids else {}

            items = []
            for u in rows:
                sm = scans.get(u.id, {})
                signals = _risk_signals(sm)
                items.append({
                    'id': u.id, 'x_id': u.x_id, 'email': u.email,
                    'firstname': u.firstname, 'lastname': u.lastname, 'status': u.status,
                    'is_admin': _is_admin(u), 'roles': [r.name for r in (u.roles or [])],
                    'join_time': u.join_time, 'last_login_time': u.last_login_time,
                    'credits': credits.get(u.id, {}).get('credits', 0),
                    'free_scans': credits.get(u.id, {}).get('free_scans', 0),
                    'scan_count': sm.get('total', 0), 'active_scans': sm.get('active', 0),
                    'failed_scans': sm.get('failed', 0), 'pending_requests': sm.get('awaiting', 0),
                    'targets_count': targets.get(u.id, {}).get('total', 0),
                    'risk_level': _risk_level(signals), 'risk_count': len(signals),
                })
        return {'items': items, 'total': total, 'page': page, 'size': size,
                'total_pages': (total + size - 1) // size if size else 0}

    async def get_detail(self, user_id: int) -> dict:
        async with async_db_session() as db:
            u = await user_dao.get_with_relation(db, id=user_id, populates=['roles'])
            if not u:
                raise errors.NotFoundError(msg='Compte introuvable')
            sm = (await self._scan_metrics(db, [user_id])).get(user_id, {})
            tm = (await self._target_metrics(db, [user_id])).get(user_id, {})
            cm = (await self._credit_metrics(db, [user_id])).get(user_id, {})
            dsd = await self._distinct_active_domains(db, user_id)
            bal = await credit_service.balance(db, user_id)
            metrics = {**sm, 'distinct_active_domains': dsd}
            signals = _risk_signals(metrics)
            return {
                'id': u.id, 'x_id': u.x_id, 'email': u.email,
                'firstname': u.firstname, 'lastname': u.lastname, 'status': u.status,
                'is_admin': _is_admin(u), 'roles': [r.name for r in (u.roles or [])],
                'join_time': u.join_time, 'last_login_time': u.last_login_time,
                'credits': cm.get('credits', 0), 'free_scans': cm.get('free_scans', 0),
                'scan_count': sm.get('total', 0), 'active_scans': sm.get('active', 0),
                'failed_scans': sm.get('failed', 0), 'pending_requests': sm.get('awaiting', 0),
                'targets_count': tm.get('total', 0), 'authorized_targets': tm.get('authorized', 0),
                'active_requests_total': sm.get('active_exploit', 0), 'distinct_active_domains': dsd,
                'next_expiry': bal.get('next_expiry'),
                'risk_level': _risk_level(signals), 'risk_count': len(signals), 'signals': signals,
            }

    async def overview(self) -> dict:
        """Platform-wide counters and recent activity for the admin landing page."""
        now = timezone.now()
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        async def scalar(db: AsyncSession, stmt) -> int:
            return int((await db.execute(stmt)).scalar() or 0)

        async with async_db_session() as db:
            data = {
                'users_total': await scalar(db, select(func.count()).select_from(User)),
                'users_new_7d': await scalar(db, select(func.count()).select_from(User).where(
                    User.join_time >= now - timedelta(days=7))),
                'users_suspended': await scalar(db, select(func.count()).select_from(User).where(
                    User.status.is_(False))),
                'scans_today': await scalar(db, select(func.count()).select_from(Scan).where(
                    Scan.created_time >= day_start)),
                'scans_running': await scalar(db, select(func.count()).select_from(Scan).where(
                    Scan.status.in_([ScanStatus.queued.value, ScanStatus.running.value]))),
                'pending_requests': await scalar(db, select(func.count()).select_from(Scan).where(
                    Scan.status == ScanStatus.awaiting_approval.value)),
                'credits_outstanding': await scalar(db, select(func.coalesce(func.sum(CreditGrant.remaining), 0)).where(
                    CreditGrant.kind == CreditKind.credit.value, CreditGrant.remaining > 0,
                    or_(CreditGrant.expires_at.is_(None), CreditGrant.expires_at > now))),
                'credits_granted_30d': await scalar(db, select(func.coalesce(func.sum(CreditGrant.amount), 0)).where(
                    CreditGrant.kind == CreditKind.credit.value,
                    CreditGrant.source == CreditSource.admin.value,
                    CreditGrant.created_time >= now - timedelta(days=30))),
                'vouchers_active': await scalar(db, select(func.count()).select_from(CreditVoucher).where(
                    CreditVoucher.is_active.is_(True),
                    or_(CreditVoucher.valid_until.is_(None), CreditVoucher.valid_until > now))),
            }
            recent = (await db.execute(
                select(User.id, User.email, User.join_time).order_by(User.join_time.desc()).limit(5)
            )).all()
            data['recent_users'] = [{'id': r.id, 'email': r.email, 'join_time': r.join_time} for r in recent]
            actions = (await db.execute(
                select(AdminAudit, User.email)
                .outerjoin(User, User.id == AdminAudit.target_user_id)
                .order_by(AdminAudit.id.desc()).limit(8)
            )).all()
            data['recent_actions'] = [{
                'id': a.id, 'action': a.action, 'note': a.note, 'target_user_id': a.target_user_id,
                'target_email': email, 'created_time': a.created_time,
            } for a, email in actions]
        return data

    # ---- actions -------------------------------------------------------------
    @staticmethod
    async def _kill_sessions(x_id: str) -> None:
        """Evict a user's live access/refresh tokens and cached snapshot from Redis
        so a status change takes effect immediately (best-effort)."""
        try:
            await redis_client.delete_prefix(f'{settings.TOKEN_REDIS_PREFIX}:{x_id}:')
            await redis_client.delete_prefix(f'{settings.TOKEN_REFRESH_REDIS_PREFIX}:{x_id}:')
            await redis_client.delete_prefix(f'{settings.JWT_USER_REDIS_PREFIX}:{x_id}')
        except Exception:  # noqa: BLE001 — never fail the action on a cache hiccup
            pass

    async def _guard_target(self, db: AsyncSession, actor_id: int, user_id: int) -> User:
        u = await user_dao.get_with_relation(db, id=user_id, populates=['roles'])
        if not u:
            raise errors.NotFoundError(msg='Compte introuvable')
        if u.id == actor_id:
            raise errors.ForbiddenError(msg='Vous ne pouvez pas effectuer cette action sur votre propre compte')
        if _is_admin(u):
            raise errors.ForbiddenError(msg='Impossible d’agir sur un compte administrateur')
        return u

    async def suspend(self, *, actor_id: int, user_id: int, reason: str) -> None:
        async with async_db_session.begin() as db:
            u = await self._guard_target(db, actor_id, user_id)
            if not u.status:
                raise errors.ForbiddenError(msg='Ce compte est déjà suspendu')
            x_id = u.x_id
            await user_dao.set_status(db, u.id, False)
            db.add(AdminAudit(admin_id=actor_id, target_user_id=u.id, action='suspend', note=reason))
        await self._kill_sessions(x_id)
        from backend.app.shasec.service.notification_service import notification_service
        await notification_service.notify_user(
            user_id, kind='account', title='Votre compte a été suspendu',
            body=reason, link='/settings',
        )

    async def reactivate(self, *, actor_id: int, user_id: int, note: str | None = None) -> None:
        async with async_db_session.begin() as db:
            u = await self._guard_target(db, actor_id, user_id)
            if u.status:
                raise errors.ForbiddenError(msg='Ce compte est déjà actif')
            await user_dao.set_status(db, u.id, True)
            db.add(AdminAudit(admin_id=actor_id, target_user_id=u.id, action='reactivate', note=note))
        from backend.app.shasec.service.notification_service import notification_service
        await notification_service.notify_user(
            user_id, kind='account', title='Votre compte a été réactivé',
            body=note or 'Vous pouvez de nouveau utiliser Kortex.', link='/dashboard',
        )

    async def grant_credits(self, *, actor_id: int, user_id: int, amount: int,
                            expires_in_days: int | None, note: str | None) -> None:
        async with async_db_session.begin() as db:
            u = await user_dao.get(db, user_id)
            if not u:
                raise errors.NotFoundError(msg='Compte introuvable')
            expires_at = timezone.now() + timedelta(days=expires_in_days) if expires_in_days else None
            await credit_service.grant(
                db, user_id=user_id, amount=amount, source=CreditSource.admin.value,
                expires_at=expires_at, note=note,
            )
            db.add(AdminAudit(admin_id=actor_id, target_user_id=user_id, action='credit_grant',
                              note=f'+{amount} crédits' + (f' · {note}' if note else '')))
        from backend.app.shasec.service.notification_service import notification_service
        await notification_service.notify_user(
            user_id, kind='account', title=f'{amount} crédits ont été ajoutés à votre compte',
            body=note, link='/credits',
        )

    @staticmethod
    def audit_select(user_id: int):
        return select(AdminAudit).where(AdminAudit.target_user_id == user_id).order_by(AdminAudit.id.desc())


admin_user_service: AdminUserService = AdminUserService()
