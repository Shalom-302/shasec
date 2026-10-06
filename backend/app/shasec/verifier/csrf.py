"""csrf — CSRF-exposure detection, purely observational (production-safe).

No forged request is ever executed against real data. The module only OBSERVES:
it fetches the target, inspects the ``Set-Cookie`` headers for session cookies that
lack CSRF-relevant protection (``SameSite`` absent or ``None``), and cross-checks
whether the app exposes any anti-CSRF token mechanism. When state-changing
endpoints (POST/PUT/PATCH/DELETE) exist in the spec and the session cookie is not
SameSite-protected, the endpoints are CSRF-prone.

This is detection, not exploitation — it proves the *precondition* for CSRF and
stops there.
"""
import re

import httpx

from backend.app.shasec.verifier import register
from backend.app.shasec.verifier._spec import fetch_spec, origin
from backend.app.shasec.verifier.base import ExploitContext, ExploitModule, ExploitResult
from backend.common.enums import FindingSeverity
from backend.common.log import log

_SESSION_COOKIE = re.compile(
    r'^(session|sessionid|sess|jsessionid|connect\.sid|sid|auth|authtoken|token|'
    r'access_token|remember|laravel_session|phpsessid|asp\.net_sessionid)$', re.I,
)
_CSRF_COOKIE = re.compile(r'(csrf|xsrf|_token|anti.?forgery)', re.I)
_STATE_CHANGING = ('post', 'put', 'patch', 'delete')


def _cookie_attrs(set_cookie: str) -> tuple[str, dict]:
    """Parse a Set-Cookie value into (name, {attr_lower: value_lower})."""
    parts = [p.strip() for p in set_cookie.split(';')]
    if not parts or '=' not in parts[0]:
        return '', {}
    name = parts[0].split('=', 1)[0].strip()
    attrs = {}
    for p in parts[1:]:
        if '=' in p:
            k, v = p.split('=', 1)
            attrs[k.strip().lower()] = v.strip().lower()
        else:
            attrs[p.strip().lower()] = ''
    return name, attrs


class CsrfModule(ExploitModule):
    name = 'csrf'
    category = 'CSRF'
    handles = ('api', 'website', 'graphql')
    timeout = 60

    async def run(self, ctx: ExploitContext) -> list[ExploitResult]:
        org = origin(ctx.target_url)
        results: list[ExploitResult] = []
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
            try:
                resp = await client.get(f'{org}/')
            except httpx.HTTPError:
                return results

            set_cookies = resp.headers.get_list('set-cookie') if hasattr(resp.headers, 'get_list') \
                else resp.headers.get('set-cookie', '').split('\n')
            has_csrf_mechanism = any(_CSRF_COOKIE.search(sc) for sc in set_cookies)
            log.info(f'[exploit:csrf] scan {ctx.scan_id} cookies={len(set_cookies)} csrf_mech={has_csrf_mechanism}')

            for sc in set_cookies:
                name, attrs = _cookie_attrs(sc)
                if not name or not _SESSION_COOKIE.match(name) or _CSRF_COOKIE.search(name):
                    continue
                samesite = attrs.get('samesite', '')
                if samesite in ('lax', 'strict'):
                    continue  # protected against cross-site sending
                if has_csrf_mechanism:
                    continue  # a token mechanism compensates

                results.append(ExploitResult(
                    category=self.category,
                    title=f'Cookie de session sans protection CSRF : `{name}`',
                    severity=FindingSeverity.medium.value,
                    confirmed=True,
                    impact=('Le cookie de session est envoyé en contexte cross-site (SameSite '
                            f'{"=None" if samesite == "none" else "absent"}) et aucun jeton anti-CSRF '
                            'n\'est observé : les requêtes changeant d\'état sont exposées au CSRF.'),
                    request=f'GET {org}/',
                    response=f'Set-Cookie: {name}=… ; SameSite={samesite or "(absent)"}',
                ))

            # Contextualise with the state-changing surface from the spec.
            if results:
                spec = await fetch_spec(client, org)
                if spec:
                    n = sum(
                        1 for _p, item in (spec.get('paths') or {}).items()
                        if isinstance(item, dict)
                        for m in item if isinstance(m, str) and m.lower() in _STATE_CHANGING
                    )
                    if n:
                        results.append(ExploitResult(
                            category=self.category,
                            title=f'{n} endpoint(s) changeant d\'état exposé(s) au CSRF',
                            severity=FindingSeverity.medium.value,
                            confirmed=False,
                            impact='Des opérations POST/PUT/PATCH/DELETE existent alors que la session '
                                   'n\'est pas protégée (SameSite/token) — surface CSRF réelle à corriger.',
                            request=f'(analyse OpenAPI de {org})',
                            response=f'{n} opération(s) state-changing déclarée(s)',
                        ))
        return results


register(CsrfModule())
