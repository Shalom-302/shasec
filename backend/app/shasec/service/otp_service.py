"""WhatsApp sign-up OTP.

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


def _key(email: str) -> str:
    return f'{settings.OTP_REDIS_PREFIX}:{email.lower()}'


def _cooldown_key(email: str) -> str:
    return f'{settings.OTP_REDIS_PREFIX}:cooldown:{email.lower()}'


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


async def _ensure_on_whatsapp(phone: str) -> None:
    """Refuse a number gowa reports as not on WhatsApp, before sending anything.

    Best-effort: if the check itself fails (gowa without /user/check, timeout,
    unexpected payload) we let the send go through and its own error handling apply.
    """
    if not settings.GOWA_URL:
        return
    try:
        async with httpx.AsyncClient(timeout=settings.GOWA_TIMEOUT) as client:
            resp = await client.get(f'{settings.GOWA_URL.rstrip("/")}/user/check',
                                    params={'phone': phone}, headers=_auth_headers())
        on_wa = (resp.json().get('results') or {}).get('is_on_whatsapp') if resp.status_code == 200 else None
    except Exception as exc:  # noqa: BLE001
        log.warning(f'gowa user/check failed for {phone}: {exc}')
        return
    if on_wa is False:
        raise errors.ForbiddenError(
            msg="Ce numéro n’est pas associé à un compte WhatsApp. Vérifiez-le (indicatif compris).")


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
        log.error(f'gowa send {resp.status_code}: {resp.text[:200]}')
        raise errors.ServerError(msg="Envoi du code WhatsApp refusé. Vérifiez le numéro.")


class OtpService:
    @staticmethod
    async def start(email: str, phone: str) -> None:
        """Generate a code, store it (TTL + fresh attempt counter), send it."""
        await _ensure_on_whatsapp(phone)
        await _consume_phone_quota(phone)
        code = _gen_code()
        try:
            await redis_client.hset(_key(email), mapping={'code': code, 'attempts': 0})
            await redis_client.expire(_key(email), settings.OTP_TTL_SECONDS)
        except Exception as exc:  # noqa: BLE001
            log.error(f'otp store failed for {email}: {exc}')
            raise errors.ServerError(msg="Impossible de générer le code pour le moment.") from exc
        minutes = settings.OTP_TTL_SECONDS // 60
        await _send_whatsapp(
            phone,
            f'Kortex Security : votre code de vérification est {code}. '
            f'Il expire dans {minutes} minutes. Ne le partagez avec personne.',
        )

    @staticmethod
    async def can_resend(email: str) -> bool:
        try:
            return not await redis_client.get(_cooldown_key(email))
        except Exception:  # noqa: BLE001
            return True

    @staticmethod
    async def mark_resent(email: str) -> None:
        try:
            await redis_client.setex(_cooldown_key(email), settings.OTP_RESEND_COOLDOWN_SECONDS, '1')
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    async def verify(email: str, code: str) -> bool:
        """True if the code matches. Burns the code after too many wrong tries."""
        key = _key(email)
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
