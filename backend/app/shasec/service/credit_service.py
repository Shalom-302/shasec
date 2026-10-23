"""Credits ledger: balance, scan debits/refunds, vouchers and grants.

Model
-----
* A :class:`CreditGrant` is a bucket (``remaining`` units, optional expiry).
  ``kind`` is either ``free_scan`` (signup discovery scans, counted in scans) or
  ``credit`` (Kortex credits).
* Every movement is written to :class:`CreditTransaction` (append-only).
* A scan debit drains the buckets that expire first (subscription credits before
  never-expiring purchased credits) under ``SELECT … FOR UPDATE`` so two
  concurrent scans can never spend the same credit.

Billing rule for a non-admin scan: pay with credits when the balance covers the
profile price (detailed report unlocked); otherwise fall back to a free
discovery scan when one is left and the profile is allowed on the free tier.
Admins are never billed.
"""
import secrets
from datetime import timedelta

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.shasec.service.access import Actor
from backend.common.enums import CreditKind, CreditSource, CreditTxReason, ScanBilling, ScanProfile
from backend.common.exception import errors
from backend.core.conf import settings
from backend.models import Scan, User
from backend.models.credit import CreditGrant, CreditTransaction, CreditVoucher, CreditVoucherRedemption
from backend.utils.timezone import timezone

# Unambiguous alphabet for human-typed codes (no 0/O, 1/I/L).
_CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'


def advanced_cost(profile: str) -> int:
    from backend.core.conf import settings as _s
    return scan_cost(profile) + _s.CREDITS_ACTIVE_SURCHARGE


def scan_cost(profile: str) -> int:
    return {
        ScanProfile.fast.value: settings.CREDITS_COST_FAST,
        ScanProfile.standard.value: settings.CREDITS_COST_STANDARD,
        ScanProfile.deep.value: settings.CREDITS_COST_DEEP,
    }.get(getattr(profile, 'value', profile), settings.CREDITS_COST_STANDARD)


def normalize_code(code: str) -> str:
    return ''.join(ch for ch in (code or '').upper() if ch.isalnum())


def generate_code() -> str:
    body = ''.join(secrets.choice(_CODE_ALPHABET) for _ in range(12))
    return f'KX{body}'


def format_code(code: str) -> str:
    """KXABCDEFGHJKMN -> KX-ABCD-EFGH-JKMN (display only; storage is compact)."""
    head, body = code[:2], code[2:]
    return '-'.join([head] + [body[i:i + 4] for i in range(0, len(body), 4)])


def _active_clause(now):
    return and_(
        CreditGrant.remaining > 0,
        or_(CreditGrant.expires_at.is_(None), CreditGrant.expires_at > now),
    )


class CreditService:
    # ---- reads ---------------------------------------------------------------
    @staticmethod
    async def balance(db: AsyncSession, user_id: int) -> dict:
        now = timezone.now()
        rows = (
            await db.execute(
                select(CreditGrant.kind, func.coalesce(func.sum(CreditGrant.remaining), 0))
                .where(CreditGrant.user_id == user_id, _active_clause(now))
                .group_by(CreditGrant.kind)
            )
        ).all()
        totals = {kind: int(total) for kind, total in rows}
        next_expiry = (
            await db.execute(
                select(func.min(CreditGrant.expires_at)).where(
                    CreditGrant.user_id == user_id,
                    CreditGrant.kind == CreditKind.credit.value,
                    CreditGrant.expires_at.is_not(None),
                    _active_clause(now),
                )
            )
        ).scalar()
        return {
            'credits': totals.get(CreditKind.credit.value, 0),
            'free_scans': totals.get(CreditKind.free_scan.value, 0),
            'next_expiry': next_expiry,
        }

    @staticmethod
    async def active_grants(db: AsyncSession, user_id: int) -> list[CreditGrant]:
        now = timezone.now()
        stmt = (
            select(CreditGrant)
            .where(CreditGrant.user_id == user_id, _active_clause(now))
            .order_by(CreditGrant.expires_at.asc().nulls_last(), CreditGrant.id.asc())
        )
        return list((await db.execute(stmt)).scalars())

    @staticmethod
    def transactions_select(user_id: int):
        return (
            select(CreditTransaction)
            .where(CreditTransaction.user_id == user_id)
            .order_by(CreditTransaction.id.desc())
        )

    # ---- grants --------------------------------------------------------------
    @staticmethod
    async def grant(
        db: AsyncSession, *, user_id: int, amount: int, kind: str = CreditKind.credit.value,
        source: str = CreditSource.admin.value, expires_at=None, voucher_id: int | None = None,
        external_ref: str | None = None, note: str | None = None,
    ) -> CreditGrant:
        if amount <= 0:
            raise errors.RequestError(msg='Grant amount must be positive')
        if external_ref:
            dup = await db.scalar(select(CreditGrant.id).where(CreditGrant.external_ref == external_ref))
            if dup:
                raise errors.ConflictError(msg='This payment reference was already credited')
        g = CreditGrant(
            user_id=user_id, amount=amount, remaining=amount, kind=kind, source=source,
            expires_at=expires_at, voucher_id=voucher_id, external_ref=external_ref, note=note,
        )
        db.add(g)
        await db.flush()
        await db.refresh(g)  # load server-side defaults (created_time) for serialization
        db.add(CreditTransaction(
            user_id=user_id, delta=amount, kind=kind, reason=CreditTxReason.grant.value,
            grant_id=g.id, note=note or source,
        ))
        return g

    @staticmethod
    async def grant_signup(db: AsyncSession, user_id: int) -> None:
        if settings.CREDITS_FREE_SCANS > 0:
            await CreditService.grant(
                db, user_id=user_id, amount=settings.CREDITS_FREE_SCANS, kind=CreditKind.free_scan.value,
                source=CreditSource.signup.value, note='Scans de découverte offerts',
            )

    # ---- scan billing --------------------------------------------------------
    @staticmethod
    async def charge_scan(db: AsyncSession, actor: Actor, scan: Scan) -> None:
        """Bill ``scan`` (already flushed, so it has an id) for its owner.

        Sets ``scan.billing`` / ``scan.credits_charged``. Raises 402 when the
        account can pay neither with credits nor with a free discovery scan.
        """
        if actor.is_admin:
            scan.billing = ScanBilling.admin.value
            scan.credits_charged = 0
            return

        now = timezone.now()
        grants = list((await db.execute(
            select(CreditGrant)
            .where(CreditGrant.user_id == actor.id, _active_clause(now))
            .order_by(CreditGrant.expires_at.asc().nulls_last(), CreditGrant.id.asc())
            .with_for_update()
        )).scalars())
        credit_grants = [g for g in grants if g.kind == CreditKind.credit.value]
        free_grants = [g for g in grants if g.kind == CreditKind.free_scan.value]
        # Advanced (active) audits cost more and are never covered by free scans.
        active = bool(getattr(scan, 'allow_active_exploitation', False))
        cost = scan_cost(scan.profile) + (settings.CREDITS_ACTIVE_SURCHARGE if active else 0)

        if sum(g.remaining for g in credit_grants) >= cost:
            CreditService._drain(db, actor.id, credit_grants, cost, CreditKind.credit.value, scan.id)
            scan.billing = ScanBilling.credits.value
            scan.credits_charged = cost
            return

        if not active and free_grants and getattr(scan.profile, 'value', scan.profile) in settings.CREDITS_FREE_PROFILES:
            CreditService._drain(db, actor.id, free_grants, 1, CreditKind.free_scan.value, scan.id)
            scan.billing = ScanBilling.free.value
            scan.credits_charged = 0
            return

        if active:
            msg = f'Crédits insuffisants : un audit avancé coûte {cost} crédit(s).'
        elif free_grants:
            msg = (f'Le profil « {scan.profile} » nécessite {cost} crédit(s). '
                   f'Les scans gratuits sont limités aux profils : {", ".join(settings.CREDITS_FREE_PROFILES)}.')
        else:
            msg = f'Crédits insuffisants : ce scan coûte {cost} crédit(s).'
        raise errors.PaymentRequiredError(msg=msg, data={'cost': cost})

    @staticmethod
    def _drain(db: AsyncSession, user_id: int, grants: list[CreditGrant], amount: int, kind: str, scan_id: int):
        left = amount
        for g in grants:
            if left <= 0:
                break
            take = min(g.remaining, left)
            g.remaining -= take
            left -= take
            db.add(CreditTransaction(
                user_id=user_id, delta=-take, kind=kind, reason=CreditTxReason.scan_debit.value,
                grant_id=g.id, scan_id=scan_id,
            ))

    @staticmethod
    async def refund_scan(db: AsyncSession, scan_id: int, note: str = 'Scan en échec') -> int:
        """Give back whatever ``scan_id`` was debited (idempotent)."""
        already = await db.scalar(select(CreditTransaction.id).where(
            CreditTransaction.scan_id == scan_id, CreditTransaction.reason == CreditTxReason.scan_refund.value,
        ))
        if already:
            return 0
        debits = list((await db.execute(select(CreditTransaction).where(
            CreditTransaction.scan_id == scan_id, CreditTransaction.reason == CreditTxReason.scan_debit.value,
        ))).scalars())
        refunded = 0
        for tx in debits:
            if tx.grant_id is not None:
                g = await db.get(CreditGrant, tx.grant_id, with_for_update=True)
                if g is not None:
                    g.remaining += -tx.delta
            db.add(CreditTransaction(
                user_id=tx.user_id, delta=-tx.delta, kind=tx.kind, reason=CreditTxReason.scan_refund.value,
                grant_id=tx.grant_id, scan_id=scan_id, note=note,
            ))
            refunded += -tx.delta
        return refunded

    # ---- vouchers ------------------------------------------------------------
    @staticmethod
    async def create_vouchers(
        db: AsyncSession, *, actor: Actor, count: int, credits: int, max_redemptions: int,
        valid_until=None, credit_validity_days: int | None = None, note: str | None = None,
    ) -> list[CreditVoucher]:
        vouchers = []
        for _ in range(count):
            v = CreditVoucher(
                code=generate_code(), credits=credits, max_redemptions=max_redemptions,
                valid_until=valid_until, credit_validity_days=credit_validity_days, note=note,
                created_by=actor.id,
            )
            db.add(v)
            vouchers.append(v)
        await db.flush()
        for v in vouchers:
            await db.refresh(v)
        return vouchers

    @staticmethod
    async def redeem(db: AsyncSession, *, user_id: int, code: str) -> CreditGrant:
        compact = normalize_code(code)
        invalid = errors.RequestError(msg='Code invalide ou expiré')
        if not compact:
            raise invalid
        voucher = (await db.execute(
            select(CreditVoucher).where(CreditVoucher.code == compact).with_for_update()
        )).scalar_one_or_none()
        now = timezone.now()
        if (
            voucher is None or not voucher.is_active
            or (voucher.valid_until is not None and voucher.valid_until <= now)
            or voucher.redemption_count >= voucher.max_redemptions
        ):
            raise invalid
        used = await db.scalar(select(CreditVoucherRedemption.id).where(
            CreditVoucherRedemption.voucher_id == voucher.id, CreditVoucherRedemption.user_id == user_id,
        ))
        if used:
            raise errors.ConflictError(msg='Vous avez déjà utilisé ce code')

        voucher.redemption_count += 1
        db.add(CreditVoucherRedemption(voucher_id=voucher.id, user_id=user_id))
        expires_at = (
            now + timedelta(days=voucher.credit_validity_days) if voucher.credit_validity_days else None
        )
        return await CreditService.grant(
            db, user_id=user_id, amount=voucher.credits, kind=CreditKind.credit.value,
            source=CreditSource.voucher.value, expires_at=expires_at, voucher_id=voucher.id,
            note=f'Code {format_code(voucher.code)}',
        )

    @staticmethod
    async def user_id_by_email(db: AsyncSession, email: str) -> int:
        # Select the id only: User eagerly joins its roles collection.
        user_id = await db.scalar(select(User.id).where(User.email == email))
        if not user_id:
            raise errors.NotFoundError(msg='User not found')
        return user_id


credit_service: CreditService = CreditService()
