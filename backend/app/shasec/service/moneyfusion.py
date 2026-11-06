"""MoneyFusion provider — ported from the wabhook (WhatsApp) project.

Knows ONLY MoneyFusion: create a checkout, read a payment status. It never
touches credits or the database (that is ``payment_service``), so adding
CinetPay/PayDunya later means writing one more file like this one.
"""
import uuid
from dataclasses import dataclass, field

import httpx

from backend.common.log import log
from backend.core.conf import settings


class PaymentError(Exception):
    """Aggregator-side failure, with a message safe to show the user."""


@dataclass
class PaymentIntent:
    reference: str      # aggregator token = our idempotency key
    checkout_url: str   # where the browser is sent
    raw: dict = field(default_factory=dict)


@dataclass
class PaymentStatus:
    paid: bool
    amount: float | None  # amount ACTUALLY paid (None if the API doesn't say)
    status: str
    raw: dict = field(default_factory=dict)


# Fields MoneyFusion may use for the amount collected. Narrow down to one once a
# real production payload has been seen.
_AMOUNT_KEYS = ('Montant', 'montant', 'amount', 'totalPrice', 'total_price', 'price')


def _extract_amount(data: dict) -> float | None:
    for key in _AMOUNT_KEYS:
        if data.get(key) is not None:
            try:
                return float(str(data[key]).replace(' ', '').replace(',', '.'))
            except (TypeError, ValueError):
                continue
    return None


def _normalize(url: str) -> str:
    # The TLS cert only covers pay.moneyfusion.net: a leading "www." fails on a
    # hostname error, far away from "payment doesn't work".
    return url.replace('://www.', '://').rstrip('/')


class MoneyFusionProvider:
    name = 'moneyfusion'

    def __init__(self, api_url: str, verify_url: str):
        if not api_url or not verify_url:
            raise PaymentError('Le paiement en ligne n’est pas encore configuré.')
        self.api_url = _normalize(api_url)
        self.verify_url = _normalize(verify_url)

    async def create(self, *, amount: int, phone: str, client_name: str, label: str,
                     return_url: str, webhook_url: str, metadata: dict) -> PaymentIntent:
        payload = {
            'totalPrice': str(int(amount)),
            'article': [{'name': label, 'price': str(int(amount)), 'quantity': 1}],
            'numeroSend': phone,
            'nomclient': client_name,
            'personal_Info': [{**metadata, 'orderId': int(str(uuid.uuid4().int)[:8])}],
            'return_url': return_url,
            'webhook_url': webhook_url,
        }
        try:
            async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
                res = await client.post(self.api_url, json=payload)
        except httpx.HTTPError as exc:
            log.error(f'[MF] create failed: {type(exc).__name__}')
            raise PaymentError('Le service de paiement ne répond pas. Réessayez dans un instant.') from exc
        if res.status_code != 200:
            log.error(f'[MF] create HTTP {res.status_code}: {res.text[:200]}')
            raise PaymentError('Le service de paiement a refusé la demande.')
        data = res.json()
        if data.get('statut') is not True:
            raise PaymentError(data.get('message') or 'Création du paiement refusée.')
        token, url = data.get('token'), data.get('url')
        if not token or not isinstance(url, str):
            raise PaymentError('Réponse incomplète du service de paiement.')
        log.info(f'[MF] checkout created {int(amount)} FCFA …{str(token)[-6:]}')
        return PaymentIntent(reference=str(token), checkout_url=url, raw=data)

    async def verify(self, reference: str) -> PaymentStatus:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                res = await client.get(f'{self.verify_url}/{reference}')
        except httpx.HTTPError as exc:
            raise PaymentError('Vérification indisponible.') from exc
        if res.status_code not in (200, 201):
            raise PaymentError(f'Vérification indisponible (HTTP {res.status_code}).')
        body = res.json()
        inner = body.get('data') or {}
        state = str(inner.get('statut') or 'unknown').lower()
        return PaymentStatus(
            paid=body.get('statut') is True and state == 'paid',
            amount=_extract_amount(inner),
            status=state,
            raw=body,
        )


def get_provider() -> MoneyFusionProvider:
    return MoneyFusionProvider(settings.MONEYFUSION_API_URL, settings.MONEYFUSION_VERIFY_URL)
