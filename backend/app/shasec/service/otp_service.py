"""WhatsApp OTP (sign-up verification and forgotten-password reset).

A 6-digit code is sent to the user's phone through gowa
(go-whatsapp-web-multidevice: ``POST {GOWA_URL}/send/message`` with HTTP Basic
auth and body ``{"phone": "<digits>@s.whatsapp.net", "message": "..."}``). The
code + attempt counter live in Redis with a TTL; verifying it flips
``user.email_verified``. Everything here is best-effort-guarded so a gowa outage
yields a clean error, never a stack trace.
"""
import base64
import secrets

import httpx

from backend.common.exception import errors
from backend.common.log import log
from backend.core.conf import settings
from backend.database.db_redis import redis_client

_WA_SUFFIX = '@s.whatsapp.net'


# Purposes: 'signup' (account verification) and 'reset' (forgotten password).
# Separate keys so a sign-up code can never be replayed to reset a password.
_MESSAGES = {
    'signup': 'Kortex Defender : votre code de vérification est {code}. '
              'Il expire dans {minutes} minutes. Ne le partagez avec personne.',
    'reset': 'Kortex Defender : votre code de réinitialisation du mot de passe est {code}. '
             'Il expire dans {minutes} minutes. Si vous n’avez rien demandé, ignorez ce message.',
}


def _key(email: str, purpose: str = 'signup') -> str:
    base = f'{settings.OTP_REDIS_PREFIX}:{email.lower()}'
    return base if purpose == 'signup' else f'{settings.OTP_REDIS_PREFIX}:{purpose}:{email.lower()}'


def _cooldown_key(email: str, purpose: str = 'signup') -> str:
    base = f'{settings.OTP_REDIS_PREFIX}:cooldown:{email.lower()}'
    return base if purpose == 'signup' else f'{base}:{purpose}'


def _phone_count_key(phone: str) -> str:
    return f'{settings.OTP_REDIS_PREFIX}:phone:{phone}'


def _auth_headers() -> dict:
    headers = {'Content-Type': 'application/json'}
    if settings.GOWA_BASIC_USER or settings.GOWA_BASIC_PASS:
        raw = f'{settings.GOWA_BASIC_USER}:{settings.GOWA_BASIC_PASS}'.encode()
        headers['Authorization'] = 'Basic ' + base64.b64encode(raw).decode()
    return headers


async def _consume_phone_quota(phone: str) -> None:
    """Count one send for this number; refuse past the hourly cap."""
    key = _phone_count_key(phone)
    try:
        count = await redis_client.incr(key)
        if count == 1:
            await redis_client.expire(key, 3600)
    except Exception as exc:  # noqa: BLE001 - Redis down: don't block sign-up on the counter
        log.warning(f'otp phone quota unavailable for {phone}: {exc}')
        return
    if count > settings.OTP_MAX_SENDS_PER_PHONE_HOUR:
        raise errors.ForbiddenError(
            msg="Trop de codes envoyés à ce numéro. Réessayez dans une heure.")


class _Unreachable(Exception):
    """gowa answered but could not deliver to this JID (e.g. "no LID found")."""


def _wa_candidates(phone: str) -> list[str]:
    """JIDs to try for a number, most likely first.

    Côte d'Ivoire moved to 10-digit numbers in 2021 (an 01/05/07 prefix in front
    of the old 8 digits), but many WhatsApp accounts are still registered under
    the old number: 225 07 88 01 62 04 lives on WhatsApp as 225 88 01 62 04.
    """
    if phone.startswith('2250') and len(phone) == 13:
        return [phone, '225' + phone[5:]]
    return [phone]


def _gen_code() -> str:
    return ''.join(secrets.choice('0123456789') for _ in range(settings.OTP_LENGTH))


async def _send_whatsapp(phone: str, message: str) -> None:
    if not settings.GOWA_URL:
        raise errors.ServerError(msg="Service WhatsApp non configuré (GOWA_URL).")
    jid = phone if _WA_SUFFIX in phone else f'{phone}{_WA_SUFFIX}'
    headers = _auth_headers()
    try:
        async with httpx.AsyncClient(timeout=settings.GOWA_TIMEOUT) as client:
            resp = await client.post(f'{settings.GOWA_URL.rstrip("/")}/send/message',
                                     json={'phone': jid, 'message': message}, headers=headers)
    except httpx.HTTPError as exc:
        log.error(f'gowa send failed for {jid}: {exc}')
        raise errors.ServerError(msg="Envoi du code WhatsApp impossible pour le moment.") from exc
    if resp.status_code >= 400:
        log.error(f'gowa send {resp.status_code} for {jid}: {resp.text[:200]}')
        raise _Unreachable(jid)


async def _send_to_any(phone: str, message: str) -> None:
    """Send to the first candidate JID WhatsApp accepts (a failed try sends nothing)."""
    for jid in _wa_candidates(phone):
        try:
            await _send_whatsapp(jid, message)
            return
        except _Unreachable:
            continue
    # 4xx so the web form shows the message (5xx are masked as "indisponible").
    raise errors.ForbiddenError(
        msg="Ce numéro n’est pas joignable sur WhatsApp. Vérifiez-le (indicatif compris).")


def _normalize_phone(raw: str) -> str:
    digits = ''.join(ch for ch in raw if ch.isdigit())
    if raw.strip().startswith('+'):
        return digits
    if digits.startswith('00'):
        return digits[2:]
    if digits.startswith('0'):
        return settings.PHONE_DEFAULT_COUNTRY_CODE + digits
    return digits


async def alert_admins_whatsapp(message: str) -> None:
    """Best-effort WhatsApp alert to ADMIN_WHATSAPP_NUMBERS. Never raises: an
    alert failure must not break the action that triggered it."""
    for raw in filter(None, (n.strip() for n in settings.ADMIN_WHATSAPP_NUMBERS.split(','))):
        phone = _normalize_phone(raw)
        try:
            await _send_to_any(phone, message)
        except Exception as exc:  # noqa: BLE001
            log.warning(f'admin WhatsApp alert to {phone} failed: {getattr(exc, "msg", exc)}')


class OtpService:
    @staticmethod
    async def start(email: str, phone: str, purpose: str = 'signup') -> None:
        """Generate a code, store it (TTL + fresh attempt counter), send it."""
        await _consume_phone_quota(phone)
        code = _gen_code()
        key = _key(email, purpose)
        try:
            await redis_client.hset(key, mapping={'code': code, 'attempts': 0})
            await redis_client.expire(key, settings.OTP_TTL_SECONDS)
        except Exception as exc:  # noqa: BLE001
            log.error(f'otp store failed for {email}: {exc}')
            raise errors.ServerError(msg="Impossible de générer le code pour le moment.") from exc
        minutes = settings.OTP_TTL_SECONDS // 60
        await _send_to_any(phone, _MESSAGES[purpose].format(code=code, minutes=minutes))

    @staticmethod
    async def can_resend(email: str, purpose: str = 'signup') -> bool:
        try:
            return not await redis_client.get(_cooldown_key(email, purpose))
        except Exception:  # noqa: BLE001
            return True

    @staticmethod
    async def mark_resent(email: str, purpose: str = 'signup') -> None:
        try:
            await redis_client.setex(_cooldown_key(email, purpose), settings.OTP_RESEND_COOLDOWN_SECONDS, '1')
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    async def verify(email: str, code: str, purpose: str = 'signup') -> bool:
        """True if the code matches. Burns the code after too many wrong tries."""
        key = _key(email, purpose)
        try:
            data = await redis_client.hgetall(key)
        except Exception as exc:  # noqa: BLE001
            log.error(f'otp read failed for {email}: {exc}')
            raise errors.ServerError(msg="Vérification impossible pour le moment.") from exc
        if not data or 'code' not in data:
            raise errors.ForbiddenError(msg="Code expiré ou introuvable. Demandez un nouveau code.")
        attempts = int(data.get('attempts', 0)) + 1
        if attempts > settings.OTP_MAX_ATTEMPTS:
            await redis_client.delete(key)
            raise errors.ForbiddenError(msg="Trop de tentatives. Demandez un nouveau code.")
        if not secrets.compare_digest(str(data['code']), str(code).strip()):
            await redis_client.hset(key, 'attempts', attempts)
            raise errors.ForbiddenError(msg=f"Code incorrect ({settings.OTP_MAX_ATTEMPTS - attempts} essai(s) restant(s)).")
        await redis_client.delete(key)
        return True


otp_service: OtpService = OtpService()
