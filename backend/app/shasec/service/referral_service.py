"""Referral program.

A user shares ``/register?ref=<CODE>``. The new account is attached to the
referrer (once, forever). Each time the referee's payment is confirmed, the
referrer receives REFERRAL_REWARD_PERCENT % of the pack's credits — granted in
the SAME transaction as the buyer's credits, with its own unique external_ref,
so a replayed webhook can never pay the referrer twice.

Anti-abuse: no self-referral, referrer and referee must not share a phone
number, and a suspended referrer earns nothing.
"""
import secrets

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.shasec.service.credit_service import credit_service
from backend.common.exception import errors
from backend.common.log import log
from backend.core.conf import settings
from backend.models.credit import CreditGrant
from backend.models.payment import Payment
from backend.models.referral import Referral, ReferralCode
from backend.models.user import User

# No 0/O/1/I/L: codes are typed by hand from a WhatsApp message.
_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'


def normalize(code: str | None) -> str:
    return ''.join(ch for ch in (code or '').upper() if ch.isalnum())


def link_for(code: str) -> str:
    return f'{settings.PUBLIC_WEB_URL.rstrip("/")}/register?ref={code}'


class ReferralService:
    @staticmethod
    async def get_or_create_code(db: AsyncSession, user_id: int) -> str:
        row = await db.scalar(select(ReferralCode).where(ReferralCode.user_id == user_id))
        if row:
            return row.code
        for _ in range(10):
            code = 'KX' + ''.join(secrets.choice(_ALPHABET) for _ in range(6))
            if not await db.scalar(select(ReferralCode.id).where(ReferralCode.code == code)):
                db.add(ReferralCode(user_id=user_id, code=code))
                await db.flush()
                return code
        raise errors.ServerError(msg='Impossible de générer un code de parrainage.')

    @staticmethod
    async def attach(db: AsyncSession, *, referee_id: int, code: str | None, strict: bool) -> bool:
        """Attach ``referee_id`` to the owner of ``code``. ``strict`` raises a
        user-facing error on a bad code (checkout); sign-up ignores it silently."""
        code = normalize(code)
        if not code:
            return False

        def fail(msg: str) -> bool:
            if strict:
                raise errors.RequestError(msg=msg)
            log.info(f'[REF] ignored code {code} for user {referee_id}: {msg}')
            return False

        if await db.scalar(select(Referral.id).where(Referral.referee_id == referee_id)):
            return fail('Un parrain est déjà associé à votre compte.')
        owner = await db.scalar(select(ReferralCode.user_id).where(ReferralCode.code == code))
        if not owner:
            return fail('Code de parrainage inconnu.')
        if owner == referee_id:
            return fail('Vous ne pouvez pas utiliser votre propre code.')
        referrer = await db.get(User, owner)
        referee = await db.get(User, referee_id)
        if not referrer or not referrer.status:
            return fail('Code de parrainage inactif.')
        if referrer.phone and referee and referee.phone and referrer.phone == referee.phone:
            return fail('Code de parrainage non applicable à ce compte.')
        db.add(Referral(referee_id=referee_id, referrer_id=owner, code=code))
        await db.flush()
        return True

    @staticmethod
    async def reward(db: AsyncSession, payment: Payment, reference: str) -> tuple[int, int] | None:
        """Grant the referrer's share for a just-confirmed payment (same tx).
        Returns (referrer_id, credits) or None."""
        if settings.REFERRAL_REWARD_PERCENT <= 0:
            return None
        ref = await db.scalar(select(Referral).where(Referral.referee_id == payment.user_id))
        if not ref:
            return None
        referrer = await db.get(User, ref.referrer_id)
        if not referrer or not referrer.status:
            return None
        if settings.REFERRAL_FIRST_PURCHASE_ONLY:
            earlier = await db.scalar(select(func.count(Payment.id)).where(
                Payment.user_id == payment.user_id, Payment.status == 'paid', Payment.id != payment.id))
            if earlier:
                return None
        amount = payment.credits * settings.REFERRAL_REWARD_PERCENT // 100
        if amount <= 0:
            return None
        await credit_service.grant(
            db, user_id=ref.referrer_id, amount=amount, source='referral',
            external_ref=f'referral:{reference}',
            note=f'Parrainage — achat de {payment.amount} FCFA d’un filleul',
        )
        return ref.referrer_id, amount

    @staticmethod
    async def summary(db: AsyncSession, user_id: int) -> dict:
        code = await ReferralService.get_or_create_code(db, user_id)
        referees = await db.scalar(select(func.count(Referral.id)).where(Referral.referrer_id == user_id)) or 0
        earned = await db.scalar(select(func.coalesce(func.sum(CreditGrant.amount), 0)).where(
            CreditGrant.user_id == user_id, CreditGrant.source == 'referral')) or 0
        has_referrer = bool(await db.scalar(select(Referral.id).where(Referral.referee_id == user_id)))
        return {
            'code': code, 'link': link_for(code), 'referees': int(referees), 'credits_earned': int(earned),
            'reward_percent': settings.REFERRAL_REWARD_PERCENT,
            'first_purchase_only': settings.REFERRAL_FIRST_PURCHASE_ONLY,
            'has_referrer': has_referrer,
        }


referral_service = ReferralService()
