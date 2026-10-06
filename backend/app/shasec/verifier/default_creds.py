"""default_creds — can we LOG IN with a default/weak password?

This is the "regardez, je me suis connecté à /admin avec un mot de passe par
défaut" proof. Distinct from auth_bypass (which reaches a path *without* logging
in): this module actually authenticates. Only ever run against an authorized,
in-scope target (ExploitContext contract).

SAFE and bounded: a **short curated** default-credential list (NOT a brute force —
no lockout, no DoS). Three login shapes are supported, each with conservative
success detection to avoid false positives:

  * **HTTP Basic** — baseline 401 turning into 2xx proves the login.
  * **HTML form** — a *failure reference* (bogus password) is captured first, then
    a candidate is a hit only on a STRONG signal (a new session cookie, or a
    redirect away from the login page), never on a length diff alone.
  * **JSON API** — a 2xx carrying a token/session proves the login.

A successful login → critical, confirmed, with the working credential as proof.
"""
import re
from urllib.parse import urljoin, urlsplit

import httpx

from backend.app.shasec.verifier import register
from backend.app.shasec.verifier._spec import origin
from backend.app.shasec.verifier.base import ExploitContext, ExploitModule, ExploitResult
from backend.common.enums import FindingSeverity
from backend.common.log import log

_LOGIN_PATHS = ('/admin', '/login', '/admin/login', '/administrator', '/user/login')
_JSON_LOGIN_PATHS = ('/api/login', '/api/v1/login', '/auth/login', '/api/auth/login')

# Curated default/weak web credentials. Bounded — a default-cred check, not brute force.
_CREDS = (
    ('admin', 'admin'), ('admin', 'password'), ('admin', 'admin123'),
    ('admin', 'changeme'), ('admin', ''), ('administrator', 'administrator'),
    ('root', 'root'), ('admin', '12345'), ('user', 'user'),
)
_ERROR_MARKERS = ('invalid', 'incorrect', 'erreur', 'échoué', 'failed', 'wrong',
                  'denied', 'try again', 'mot de passe', 'identifiants')
_HTTP_TIMEOUT = 8.0
_BOGUS_PW = 'zZ9_shasec_wrong_pw_0x'


def _first_login_form(html: str, page_url: str) -> dict | None:
    """Return {action, user_field, pass_field, hidden{}} for the first form that
    carries a password input, or None."""
    for form in re.findall(r'<form\b[^>]*>.*?</form>', html, re.I | re.S):
        pw = re.search(r'<input\b[^>]*type=["\']?password["\']?[^>]*>', form, re.I)
        if not pw:
            continue
        action_m = re.search(r'<form\b[^>]*\baction=["\']([^"\']*)["\']', form, re.I)
        action = urljoin(page_url, action_m.group(1)) if action_m and action_m.group(1) else page_url
        pass_field = _input_name(pw.group(0)) or 'password'
        # username = first non-password, non-hidden text/email/plain input.
        user_field = None
        hidden: dict[str, str] = {}
        for inp in re.findall(r'<input\b[^>]*>', form, re.I):
            itype = (re.search(r'type=["\']?([a-z]+)["\']?', inp, re.I) or [None, 'text'])[1].lower()
            name = _input_name(inp)
            if not name:
                continue
            if itype == 'password':
                continue
            if itype == 'hidden':
                val = (re.search(r'value=["\']([^"\']*)["\']', inp, re.I) or [None, ''])[1]
                hidden[name] = val
            elif user_field is None and itype in ('text', 'email', 'tel', ''):
                user_field = name
        return {'action': action, 'user_field': user_field or 'username',
                'pass_field': pass_field, 'hidden': hidden}
    return None


def _input_name(input_tag: str) -> str | None:
    m = re.search(r'name=["\']([^"\']+)["\']', input_tag, re.I)
    return m.group(1) if m else None


def _has_error(body: str) -> bool:
    b = body[:6000].lower()
    return any(m in b for m in _ERROR_MARKERS)


def _session_cookies(resp: httpx.Response) -> set[str]:
    names = set()
    for h in resp.headers.get_list('set-cookie'):
        m = re.match(r'\s*([^=]+)=', h)
        if m:
            names.add(m.group(1).strip().lower())
    return names


class DefaultCredsModule(ExploitModule):
    name = 'default-creds'
    category = 'default-credentials'
    handles = ('website', 'api', 'graphql')
    timeout = 200

    async def run(self, ctx: ExploitContext) -> list[ExploitResult]:
        base = origin(ctx.target_url)
        if not base:
            return []
        login_paths = tuple(ctx.options.get('login_paths') or _LOGIN_PATHS)
        results: list[ExploitResult] = []

        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=False, verify=False,
                                     headers={'User-Agent': 'shasec/1.0 security audit'}) as client:
            for path in login_paths:
                if await self._try_basic(client, base, path, results):
                    continue
                await self._try_form(base, path, results)
            for path in _JSON_LOGIN_PATHS:
                await self._try_json(client, base, path, results)
        return results

    # --- HTTP Basic auth ------------------------------------------------------
    async def _try_basic(self, client, base, path, results) -> bool:
        url = f'{base}{path}'
        try:
            base_resp = await client.get(url)
        except httpx.HTTPError:
            return False
        if base_resp.status_code != 401 or 'basic' not in base_resp.headers.get('www-authenticate', '').lower():
            return False
        for user, pw in _CREDS:
            try:
                r = await client.get(url, auth=(user, pw))
            except httpx.HTTPError:
                continue
            if 200 <= r.status_code < 300:
                self._report(results, path, user, pw, 'HTTP Basic',
                             f'GET {url}  (Authorization: Basic {user}:{pw or "(vide)"})',
                             f'HTTP {r.status_code} (baseline: 401)')
                return True
        return True  # it WAS basic-auth; defaults failed but no point form-testing

    # --- HTML form ------------------------------------------------------------
    async def _try_form(self, base, path, results) -> None:
        url = f'{base}{path}'
        # Fetch page (follow redirects to reach the actual login page).
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=True, verify=False,
                                     headers={'User-Agent': 'shasec/1.0 security audit'}) as c:
            try:
                page = await c.get(url)
            except httpx.HTTPError:
                return
            form = _first_login_form(page.text or '', str(page.url))
            if not form:
                return
            ref = await self._submit(base, form, 'admin', _BOGUS_PW)  # failure reference
            if ref is None:
                return
        for user, pw in _CREDS:
            got = await self._submit(base, form, user, pw)
            if got is None:
                continue
            resp, cookies = got
            new_cookie = bool(cookies - ref[1])
            redirected_away = (resp.is_redirect and 'login' not in resp.headers.get('location', '').lower())
            success_2xx = (200 <= resp.status_code < 300 and not _has_error(resp.text or ''))
            # STRONG signal required: a new session cookie, or a redirect off the login page.
            if new_cookie or redirected_away or (success_2xx and ref[0].status_code != resp.status_code):
                self._report(results, path, user, pw, 'formulaire HTML',
                             f'POST {form["action"]}  ({form["user_field"]}={user}&{form["pass_field"]}={pw or "(vide)"})',
                             f'HTTP {resp.status_code}'
                             + (f' → {resp.headers.get("location")}' if resp.is_redirect else '')
                             + (f' · nouveau cookie de session: {", ".join(cookies - ref[1])}' if new_cookie else ''))
                return

    async def _submit(self, base, form, user, pw):
        """One isolated login attempt (fresh cookies + fresh CSRF). Returns
        (response, cookie_names) or None."""
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=False, verify=False,
                                     headers={'User-Agent': 'shasec/1.0 security audit'}) as c:
            # Carry the form's hidden fields (incl. CSRF token captured at parse time).
            hidden = dict(form['hidden'])
            data = {**hidden, form['user_field']: user, form['pass_field']: pw}
            try:
                resp = await c.post(form['action'], data=data)
            except httpx.HTTPError:
                return None
            return resp, _session_cookies(resp)

    # --- JSON API login -------------------------------------------------------
    async def _try_json(self, client, base, path, results) -> None:
        url = f'{base}{path}'
        for user, pw in _CREDS:
            for payload in ({'username': user, 'password': pw}, {'email': f'{user}@local', 'password': pw}):
                try:
                    r = await client.post(url, json=payload)
                except httpx.HTTPError:
                    continue
                if r.status_code == 404:
                    return
                body = (r.text[:2000] or '').lower()
                if 200 <= r.status_code < 300 and any(k in body for k in ('token', 'access_token', 'jwt', 'session', '"id"')):
                    self._report(results, path, user, pw, 'API JSON',
                                 f'POST {url}  {payload}',
                                 f'HTTP {r.status_code} · réponse contient un jeton/session')
                    return

    # --- shared reporting -----------------------------------------------------
    def _report(self, results, path, user, pw, mode, request, response) -> None:
        log.info(f'[exploit:default-creds] LOGIN {path} as {user} via {mode}')
        results.append(ExploitResult(
            category=self.category,
            title=f'Connexion réussie avec un identifiant par défaut sur {path} ({user})',
            severity=FindingSeverity.critical.value,
            confirmed=True,
            impact=f'Authentification réussie sur {path} avec un identifiant par défaut/faible '
                   f'({user} / {pw or "mot de passe vide"}) via {mode}. Accès non autorisé à '
                   f'l\'interface. À remédier immédiatement : changer le mot de passe, imposer une '
                   f'politique forte, activer le MFA, journaliser les connexions.',
            request=request,
            response=response,
        ))


register(DefaultCredsModule())
