"""Affiliate program: promo code at checkout, cash commissions paid by the admin.

Buyer side: an approved affiliate's code gives ``discount_pct`` % off the list
price, on every purchase during AFFILIATE_COMMISSION_MONTHS after the buyer was
attached (attachment is once, forever: sign-up link or first code typed).

Affiliate side: each confirmed payment creates ONE commission
(``commission_pct`` % of the list price), in the same DB transaction as the
buyer's credits. Nothing is ever paid automatically:

    pending  --(hold period elapsed AND the buyer really used credits)-->  available
    available --(admin transfers the money, enters the reference)-->       paid
    pending|available --(admin, fraud or doubt)-->                         rejected

Anti-abuse: no own code, no shared phone between buyer/payer and affiliate,
payer number recorded on every payment and flagged when reused across buyers,
hold period, usage requirement, monthly cap, KYC-light identity on payouts.
"""
import re
from datetime import timedelta

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.common.exception import errors
from backend.common.log import log
from backend.core.conf import settings
from backend.database.db_postgres import async_db_session
from backend.models.affiliate import Affiliate, AffiliateCommission
from backend.models.credit import CreditTransaction
from backend.models.payment import Payment
from backend.models.referral import Referral
from backend.models.user import User
from backend.utils.timezone import timezone

_CODE_RE = re.compile(r'^[A-Z0-9]{4,12}$')
_RESERVED = {'ADMIN', 'KORTEX', 'DEFENDER', 'PROMO', 'GRATUIT', 'FREE', 'TEST'}
METHODS = ('wave', 'orange', 'mtn', 'moov')


def normalize(code: str | None) -> str:
    return ''.join(ch for ch in (code or '').upper() if ch.isalnum())


def digits(phone: str | None) -> str:
    d = ''.join(ch for ch in (phone or '') if ch.isdigit())
    if d.startswith('00'):
        d = d[2:]
    elif d.startswith('0'):
        d = settings.PHONE_DEFAULT_COUNTRY_CODE + d
    return d


def discounted(list_price: int, pct: int) -> int:
    """Buyer price, rounded to the nearest 5 FCFA (Mobile Money friendly)."""
    raw = list_price * (100 - max(0, min(pct, 90))) / 100
    return max(100, int(round(raw / 5.0)) * 5)


def _window_end(attached_at):
    """End of the commission/discount window for a buyer attached at ``attached_at``."""
    from datetime import timezone as _tz
    if attached_at.tzinfo is None:  # defensive: naive timestamps are UTC
        attached_at = attached_at.replace(tzinfo=_tz.utc)
    return attached_at + timedelta(days=30 * settings.AFFILIATE_COMMISSION_MONTHS)


def link_for(code: str) -> str:
    return f'{settings.PUBLIC_WEB_URL.rstrip("/")}/register?ref={code}'


class AffiliateService:
    # ---- program membership ---------------------------------------------------
    @staticmethod
    async def apply(*, user_id: int, code: str, full_name: str, payout_phone: str, payout_method: str) -> Affiliate:
        code = normalize(code)
        if not _CODE_RE.match(code) or code in _RESERVED:
            raise errors.RequestError(msg='Code invalide : 4 à 12 lettres ou chiffres, sans espace (ex. SHALOM).')
        if payout_method not in METHODS:
            raise errors.RequestError(msg='Moyen de versement invalide.')
        phone = digits(payout_phone)
        if not 8 <= len(phone) <= 15:
            raise errors.RequestError(msg='Numéro de versement invalide.')
        name = ' '.join((full_name or '').split())[:120]
        if len(name) < 3:
            raise errors.RequestError(msg='Indiquez votre nom complet, tel qu’il apparaît sur votre compte Mobile Money.')
        async with async_db_session.begin() as db:
            if await db.scalar(select(Affiliate.id).where(Affiliate.user_id == user_id)):
                raise errors.ConflictError(msg='Vous avez déjà une demande de parrainage.')
            if await db.scalar(select(Affiliate.id).where(Affiliate.code == code)):
                raise errors.ConflictError(msg='Ce code est déjà pris, choisissez-en un autre.')
            aff = Affiliate(user_id=user_id, code=code, full_name=name, payout_phone=phone,
                            payout_method=payout_method, discount_pct=settings.AFFILIATE_DEFAULT_DISCOUNT_PCT,
                            commission_pct=settings.AFFILIATE_DEFAULT_COMMISSION_PCT, terms_accepted_at=timezone.now())
            db.add(aff)
            await db.flush()
            email = await db.scalar(select(User.email).where(User.id == user_id))
        from backend.app.shasec.service.notification_service import notification_service
        from backend.app.shasec.service.otp_service import alert_admins_whatsapp
        await notification_service.notify_admins(kind='affiliate', title=f'Demande de parrainage : {code}',
                                                 body=f'{name} · {email} · {payout_method} {phone}', link='/admin/affiliates')
        await alert_admins_whatsapp(
            '🤝 Kortex Defender — nouvelle demande de parrainage\n'
            f'Code : {code}\nNom : {name}\nCompte : {email}\nVersement : {payout_method} {phone}\n'
            f'À valider : {settings.PUBLIC_WEB_URL.rstrip("/")}/admin/affiliates')
        return aff

    @staticmethod
    async def review(*, admin_id: int, affiliate_id: int, status: str, discount_pct: int | None,
                     commission_pct: int | None, note: str | None) -> Affiliate:
        if status not in ('approved', 'suspended', 'rejected'):
            raise errors.RequestError(msg='Statut invalide.')
        async with async_db_session.begin() as db:
            aff = await db.get(Affiliate, affiliate_id)
            if not aff:
                raise errors.NotFoundError(msg='Parrain introuvable.')
            aff.status = status
            if discount_pct is not None:
                aff.discount_pct = max(0, min(int(discount_pct), 90))
            if commission_pct is not None:
                aff.commission_pct = max(0, min(int(commission_pct), 90))
            aff.reviewed_by, aff.reviewed_at = admin_id, timezone.now()
            aff.note = (note or '').strip()[:500] or aff.note
            user_id, code = aff.user_id, aff.code
        from backend.app.shasec.service.notification_service import notification_service
        title = {'approved': f'Votre code parrain {code} est actif',
                 'suspended': f'Votre code parrain {code} est suspendu',
                 'rejected': 'Votre demande de parrainage a été refusée'}[status]
        await notification_service.notify_user(user_id, kind='affiliate', title=title, body=note, link='/parrainage')
        async with async_db_session() as db:
            return await db.get(Affiliate, affiliate_id)

    # ---- attribution + price --------------------------------------------------
    @staticmethod
    async def _check_eligible(db: AsyncSession, aff: Affiliate | None, buyer_id: int, strict: bool) -> Affiliate | None:
        def fail(msg: str):
            if strict:
                raise errors.RequestError(msg=msg)
            return None
        if not aff or aff.status != 'approved':
            return fail('Code promo inconnu ou inactif.')
        if aff.user_id == buyer_id:
            return fail('Vous ne pouvez pas utiliser votre propre code.')
        buyer = await db.get(User, buyer_id)
        owner = await db.get(User, aff.user_id)
        buyer_phone = digits(buyer.phone if buyer else None)
        owner_phones = {digits(aff.payout_phone), digits(owner.phone if owner else None)} - {''}
        if buyer_phone and buyer_phone in owner_phones:
            return fail('Ce code ne peut pas être utilisé sur ce compte.')
        return aff

    @staticmethod
    async def attach_on_signup(db: AsyncSession, *, referee_id: int, code: str | None) -> None:
        code = normalize(code)
        if not code:
            return
        aff = await db.scalar(select(Affiliate).where(Affiliate.code == code))
        if await AffiliateService._check_eligible(db, aff, referee_id, strict=False):
            db.add(Referral(referee_id=referee_id, referrer_id=aff.user_id, code=code))
            await db.flush()

    @staticmethod
    async def resolve(db: AsyncSession, *, buyer_id: int, code: str | None, payer_phone: str) -> Affiliate | None:
        """Affiliate whose discount/commission applies to this purchase (or None).
        Attaches the buyer on first use of a code. Raises on a bad typed code."""
        code = normalize(code)
        ref = await db.scalar(select(Referral).where(Referral.referee_id == buyer_id))
        if ref:
            aff = await db.scalar(select(Affiliate).where(Affiliate.user_id == ref.referrer_id))
            if code and (not aff or aff.code != code):
                raise errors.RequestError(
                    msg=f'Un code parrain est déjà associé à votre compte{f" ({aff.code})" if aff else ""}.')
            if not aff or aff.status != 'approved':
                return None
            if timezone.now() > _window_end(ref.created_time):
                if code:
                    raise errors.RequestError(msg='La période de votre code promo est terminée.')
                return None
        else:
            if not code:
                return None
            aff = await db.scalar(select(Affiliate).where(Affiliate.code == code))
            aff = await AffiliateService._check_eligible(db, aff, buyer_id, strict=True)
            db.add(Referral(referee_id=buyer_id, referrer_id=aff.user_id, code=code))
            await db.flush()
        if digits(payer_phone) in ({digits(aff.payout_phone)} - {''}):
            raise errors.RequestError(msg='Ce numéro Mobile Money ne peut pas être utilisé avec ce code.')
        return aff

    @staticmethod
    async def preview(*, buyer_id: int, code: str | None) -> dict:
        """Price preview for the credits page (no attachment, no side effect)."""
        from backend.app.shasec.service.payment_service import packs
        async with async_db_session() as db:
            ref = await db.scalar(select(Referral).where(Referral.referee_id == buyer_id))
            aff, attached = None, False
            if ref:
                aff = await db.scalar(select(Affiliate).where(Affiliate.user_id == ref.referrer_id))
                attached = True
                if aff and timezone.now() > _window_end(ref.created_time):
                    aff = None
            elif normalize(code):
                aff = await db.scalar(select(Affiliate).where(Affiliate.code == normalize(code)))
                try:
                    aff = await AffiliateService._check_eligible(db, aff, buyer_id, strict=True)
                except errors.RequestError as exc:
                    return {'valid': False, 'message': exc.msg, 'attached': False, 'code': None, 'discount_pct': 0,
                            'prices': {}}
        if not aff or aff.status != 'approved':
            return {'valid': False, 'attached': attached, 'code': None, 'discount_pct': 0, 'prices': {},
                    'message': 'Code promo inconnu ou inactif.' if normalize(code) and not attached else None}
        return {'valid': True, 'attached': attached, 'code': aff.code, 'discount_pct': aff.discount_pct,
                'prices': {p['id']: discounted(p['price'], aff.discount_pct) for p in packs()}, 'message': None}

    # ---- commissions ----------------------------------------------------------
    @staticmethod
    async def on_payment_confirmed(db: AsyncSession, payment: Payment) -> AffiliateCommission | None:
        """Same transaction as the buyer's credit grant: create the commission."""
        if not payment.affiliate_id:
            return None
        aff = await db.get(Affiliate, payment.affiliate_id)
        if not aff:
            return None
        base = payment.list_price or payment.amount
        amount = base * aff.commission_pct // 100
        if amount <= 0:
            return None
        flags, status, note = [], 'pending', None
        payer = digits(payment.payer_phone)
        owner = await db.get(User, aff.user_id)
        if payer and payer in ({digits(aff.payout_phone), digits(owner.phone if owner else None)} - {''}):
            status, note = 'rejected', 'Automatique : le payeur utilise le numéro du parrain.'
        if payer:
            others = await db.scalar(select(func.count(func.distinct(Payment.user_id))).where(
                Payment.payer_phone == payer, Payment.status == 'paid', Payment.user_id != payment.user_id))
            if others:
                flags.append(f'numéro payeur utilisé par {others} autre(s) compte(s)')
        month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        month_total = await db.scalar(select(func.coalesce(func.sum(AffiliateCommission.amount), 0)).where(
            AffiliateCommission.affiliate_id == aff.id, AffiliateCommission.created_time >= month_start,
            AffiliateCommission.status != 'rejected')) or 0
        if month_total + amount > settings.AFFILIATE_MONTHLY_CAP:
            flags.append(f'plafond mensuel dépassé ({month_total + amount} F)')
        c = AffiliateCommission(affiliate_id=aff.id, payment_id=payment.id, referee_id=payment.user_id, amount=amount,
                                status=status, available_at=timezone.now() + timedelta(days=settings.AFFILIATE_HOLD_DAYS),
                                flags='; '.join(flags) or None, note=note)
        db.add(c)
        await db.flush()
        return c

    @staticmethod
    async def promote_due() -> int:
        """pending -> available once the hold is over AND the buyer used credits
        (a scan debit after the payment). Never pays anything. Returns count."""
        now = timezone.now()
        async with async_db_session.begin() as db:
            rows = (await db.execute(
                select(AffiliateCommission, Payment.paid_at)
                .join(Payment, Payment.id == AffiliateCommission.payment_id)
                .where(AffiliateCommission.status == 'pending', AffiliateCommission.available_at <= now))).all()
            n = 0
            for c, paid_at in rows:
                used = await db.scalar(select(CreditTransaction.id).where(
                    CreditTransaction.user_id == c.referee_id, CreditTransaction.reason == 'scan_debit',
                    CreditTransaction.created_time >= (paid_at or c.created_time)).limit(1))
                if used:
                    c.status = 'available'
                    n += 1
        if n:
            log.info(f'[AFFILIATE] {n} commission(s) now available for payout')
        return n

    @staticmethod
    async def decide_commission(*, admin_id: int, commission_id: int, action: str, paid_ref: str | None,
                                note: str | None) -> AffiliateCommission:
        if action not in ('paid', 'rejected', 'available'):
            raise errors.RequestError(msg='Action invalide.')
        if action == 'paid' and not (paid_ref or '').strip():
            raise errors.RequestError(msg='Indiquez la référence du transfert (Wave / Orange Money…).')
        allowed_from = {'paid': ('available', 'pending'), 'rejected': ('pending', 'available'), 'available': ('pending',)}
        values = {'status': action, 'reviewed_by': admin_id, 'note': (note or '').strip()[:500] or None}
        if action == 'paid':
            values.update(paid_at=timezone.now(), paid_ref=paid_ref.strip()[:120])
        async with async_db_session.begin() as db:
            res = await db.execute(update(AffiliateCommission).where(
                AffiliateCommission.id == commission_id, AffiliateCommission.status.in_(allowed_from[action]))
                .values(**values))
            if res.rowcount == 0:
                raise errors.ConflictError(msg='Commission introuvable ou déjà traitée.')
            c = await db.get(AffiliateCommission, commission_id)
            aff = await db.get(Affiliate, c.affiliate_id)
        if action == 'paid':
            from backend.app.shasec.service.notification_service import notification_service
            await notification_service.notify_user(
                aff.user_id, kind='affiliate', title=f'Commission versée : {c.amount} F',
                body=f'Versement {aff.payout_method} sur {aff.payout_phone} · réf. {c.paid_ref}', link='/parrainage')
        return c

    @staticmethod
    async def summary(user_id: int) -> dict:
        async with async_db_session() as db:
            aff = await db.scalar(select(Affiliate).where(Affiliate.user_id == user_id))
            has_referrer = bool(await db.scalar(select(Referral.id).where(Referral.referee_id == user_id)))
            if not aff:
                return {'affiliate': None, 'has_referrer': has_referrer,
                        'defaults': {'discount_pct': settings.AFFILIATE_DEFAULT_DISCOUNT_PCT,
                                     'commission_pct': settings.AFFILIATE_DEFAULT_COMMISSION_PCT,
                                     'hold_days': settings.AFFILIATE_HOLD_DAYS,
                                     'months': settings.AFFILIATE_COMMISSION_MONTHS,
                                     'min_payout': settings.AFFILIATE_MIN_PAYOUT}}
            totals = dict((await db.execute(
                select(AffiliateCommission.status, func.coalesce(func.sum(AffiliateCommission.amount), 0))
                .where(AffiliateCommission.affiliate_id == aff.id).group_by(AffiliateCommission.status))).all())
            referees = await db.scalar(select(func.count(Referral.id)).where(Referral.referrer_id == user_id)) or 0
            recent = (await db.scalars(select(AffiliateCommission).where(AffiliateCommission.affiliate_id == aff.id)
                                       .order_by(AffiliateCommission.id.desc()).limit(30))).all()
        return {
            'affiliate': {'code': aff.code, 'status': aff.status, 'link': link_for(aff.code),
                          'discount_pct': aff.discount_pct, 'commission_pct': aff.commission_pct,
                          'payout_method': aff.payout_method, 'payout_phone': aff.payout_phone,
                          'full_name': aff.full_name},
            'has_referrer': has_referrer, 'referees': int(referees),
            'totals': {k: int(totals.get(k, 0)) for k in ('pending', 'available', 'paid', 'rejected')},
            'commissions': [{'id': c.id, 'amount': c.amount, 'status': c.status, 'created_time': c.created_time,
                             'available_at': c.available_at, 'paid_at': c.paid_at} for c in recent],
            'defaults': {'hold_days': settings.AFFILIATE_HOLD_DAYS, 'months': settings.AFFILIATE_COMMISSION_MONTHS,
                         'min_payout': settings.AFFILIATE_MIN_PAYOUT},
        }


affiliate_service = AffiliateService()
