"""Online credit purchases.

Three jobs, nothing else (same rules as the wabhook WhatsApp bot):
  1. create a checkout at OUR price (the client only names a pack);
  2. verify a payment server-to-server — never on the webhook's word;
  3. credit exactly once, whatever happens (webhook retries, double clicks,
     webhook + return page + reconciler racing each other).
"""
from datetime import timedelta

from sqlalchemy import select, update

from backend.app.shasec.service.credit_service import credit_service
from backend.app.shasec.service.moneyfusion import PaymentError, get_provider
from backend.common.exception import errors
from backend.common.log import log
from backend.core.conf import settings
from backend.database.db_postgres import async_db_session
from backend.models.payment import Payment
from backend.models.user import User
from backend.utils.timezone import timezone

# Pending checkouts one account may open per 30 minutes (anti-abuse of the
# aggregator account, each creation is a real API call).
_MAX_PENDING_PER_WINDOW = 5


def packs() -> list[dict]:
    return [
        {'id': k, 'label': v['label'], 'price': v['price'], 'credits': v['credits'],
         'validity_days': v.get('validity_days')}
        for k, v in settings.PAYMENT_PACKS.items()
    ]


def enabled() -> bool:
    return bool(settings.MONEYFUSION_API_URL)


def webhook_url() -> str:
    secret = settings.PAYMENT_WEBHOOK_SECRET or '_'
    return f'{settings.PUBLIC_WEB_URL.rstrip("/")}/api/payments/webhook/{secret}'


class PaymentService:
    @staticmethod
    async def create_checkout(*, user_id: int, pack_id: str, phone: str | None,
                              referral_code: str | None = None) -> Payment:
        pack = settings.PAYMENT_PACKS.get(pack_id)
        if not pack:
            raise errors.RequestError(msg='Offre inconnue.')
        if not enabled():
            raise errors.ForbiddenError(msg='Le paiement en ligne arrive bientôt. Contactez-nous pour un code crédit.')

        async with async_db_session.begin() as db:
            user = await db.get(User, user_id)
            phone = phone or (user.phone if user else None)
            if not phone:
                raise errors.RequestError(msg='Indiquez le numéro Mobile Money qui va payer.')
            if referral_code:
                from backend.app.shasec.service.referral_service import referral_service
                await referral_service.attach(db, referee_id=user_id, code=referral_code, strict=True)
            since = timezone.now() - timedelta(minutes=30)
            recent = await db.scalar(
                select(Payment.id).where(Payment.user_id == user_id, Payment.status == 'pending',
                                         Payment.created_time >= since)
                .order_by(Payment.id.desc()).offset(_MAX_PENDING_PER_WINDOW - 1).limit(1)
            )
            if recent:
                raise errors.ForbiddenError(msg='Trop de paiements en attente. Terminez-en un ou réessayez plus tard.')

            # Written BEFORE the user pays: freezes price and credits now.
            p = Payment(user_id=user_id, pack=pack_id, amount=int(pack['price']),
                        credits=int(pack['credits']), validity_days=pack.get('validity_days'))
            db.add(p)
            await db.flush()
            try:
                intent = await get_provider().create(
                    amount=p.amount, phone=phone, client_name=(user.email if user else phone),
                    label=f'Kortex Defender — {pack["label"]} ({p.credits} crédits)',
                    return_url=f'{settings.PUBLIC_WEB_URL.rstrip("/")}/credits/paiement?ref={p.x_id}',
                    webhook_url=webhook_url(),
                    metadata={'paymentId': p.x_id, 'userId': user_id},
                )
            except PaymentError as exc:
                # 4xx so the web shows the message (5xx are masked as "indisponible").
                raise errors.RequestError(msg=str(exc)) from exc
            p.reference = intent.reference
            p.checkout_url = intent.checkout_url
            await db.flush()
            await db.refresh(p)
            return p

    @staticmethod
    async def verify_and_credit(reference: str) -> str | None:
        """Check one payment with the aggregator and credit it if paid.

        Returns the payment's status afterwards (None if the reference is ours
        to ignore). Safe to call any number of times, concurrently."""
        async with async_db_session() as db:
            p = await db.scalar(select(Payment).where(Payment.reference == reference))
        if p is None:
            log.warning(f'[PAY] unknown reference ignored …{reference[-6:]}')
            return None
        if p.status != 'pending':
            return p.status

        try:
            st = await get_provider().verify(reference)
        except PaymentError as exc:
            log.warning(f'[PAY] verify unavailable …{reference[-6:]}: {exc}')
            return 'pending'

        if not st.paid:
            if st.status in ('failure', 'failed', 'cancelled', 'canceled'):
                async with async_db_session.begin() as db:
                    await db.execute(update(Payment).where(Payment.id == p.id, Payment.status == 'pending')
                                     .values(status='failed', note=f'Statut agrégateur : {st.status}'))
                return 'failed'
            return 'pending'

        # Under-payment check. The aggregator reports the NET amount (its fee
        # deducted), so allow the fee tolerance — and nothing more.
        floor = p.amount * (1.0 - settings.PAYMENT_FEE_TOLERANCE) - 0.5
        if st.amount is None:
            log.error(f'[PAY] no amount in aggregator answer …{reference[-6:]}: credited WITHOUT amount check')
        elif st.amount < floor:
            async with async_db_session.begin() as db:
                await db.execute(update(Payment).where(Payment.id == p.id, Payment.status == 'pending')
                                 .values(status='mismatch', amount_paid=st.amount,
                                         note=f'Payé {st.amount:g} au lieu de {p.amount}'))
            log.error(f'[PAY] under-payment …{reference[-6:]}: expected {p.amount}, got {st.amount:g}')
            return 'mismatch'

        now = timezone.now()
        async with async_db_session.begin() as db:
            # The DB decides who credits: only one concurrent caller sees rowcount 1.
            res = await db.execute(
                update(Payment).where(Payment.id == p.id, Payment.status == 'pending')
                .values(status='paid', amount_paid=st.amount, paid_at=now)
            )
            if res.rowcount == 0:
                return 'paid'
            pack = settings.PAYMENT_PACKS.get(p.pack, {})
            expires_at = now + timedelta(days=p.validity_days) if p.validity_days else None
            # Same transaction: if the grant fails, the status flip rolls back.
            # external_ref is UNIQUE — a second, independent double-credit guard.
            await credit_service.grant(
                db, user_id=p.user_id, amount=p.credits, source=pack.get('source', 'purchase'),
                expires_at=expires_at, external_ref=f'moneyfusion:{reference}',
                note=f'Achat {pack.get("label", p.pack)} — {p.amount} FCFA',
            )
            from backend.app.shasec.service.referral_service import referral_service
            referral = await referral_service.reward(db, p, reference)
        log.info(f'[PAY] user {p.user_id} credited +{p.credits} (…{reference[-6:]})')

        from backend.app.shasec.service.notification_service import notification_service
        try:
            await notification_service.notify_user(
                p.user_id, kind='account', title=f'Paiement reçu : +{p.credits} crédits',
                body=f'{p.amount} FCFA — merci !', link='/credits',
            )
            if referral:
                await notification_service.notify_user(
                    referral[0], kind='account', title=f'Parrainage : +{referral[1]} crédits',
                    body='Un de vos filleuls vient d’acheter des crédits. Merci de faire connaître Kortex Defender !',
                    link='/parrainage',
                )
        except Exception as exc:  # noqa: BLE001 - the credit is what matters
            log.warning(f'[PAY] notification failed: {exc}')
        return 'paid'

    @staticmethod
    async def reconcile() -> None:
        """Safety net: a lost webhook must not mean a customer paid for nothing."""
        cutoff = timezone.now() - timedelta(hours=settings.PAYMENT_PENDING_MAX_HOURS)
        async with async_db_session() as db:
            refs = (await db.scalars(
                select(Payment.reference).where(Payment.status == 'pending', Payment.reference.is_not(None),
                                                Payment.created_time >= cutoff)
            )).all()
        for ref in refs:
            try:
                await PaymentService.verify_and_credit(ref)
            except Exception as exc:  # noqa: BLE001 - one bad payment must not stop the sweep
                log.error(f'[PAY] reconcile error …{ref[-6:]}: {exc}')
        async with async_db_session.begin() as db:
            await db.execute(update(Payment).where(Payment.status == 'pending', Payment.created_time < cutoff)
                             .values(status='expired'))


payment_service = PaymentService()
