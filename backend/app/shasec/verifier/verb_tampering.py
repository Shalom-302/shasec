"""verb_tampering — probe broken function-level authorization via HTTP methods.

Ported from ``_api_verb_tamper`` (api.sh), made SAFE-by-default per the
ExploitModule contract:

  * **OPTIONS-first (default, non-destructive):** send only ``OPTIONS`` and read
    the ``Allow`` header. Write verbs advertised there are reported as a *low,
    unconfirmed* candidate — advertisement alone is not a vulnerability.
  * **Destructive mode (opt-in):** only when ``ctx.options['allow_destructive']``
    is true does the module actually send ``PUT``/``PATCH``/``DELETE``. A 2xx on a
    write verb is then a *high, confirmed* broken-function-level-auth proof.

Endpoints come from the OpenAPI spec (shared ``_spec`` helper).
"""
import httpx

from backend.app.shasec.verifier import register
from backend.app.shasec.verifier._spec import fetch_spec, fill_path, origin
from backend.app.shasec.verifier.base import ExploitContext, ExploitModule, ExploitResult
from backend.common.enums import FindingSeverity
from backend.common.log import log

_WRITE_METHODS = ('PUT', 'PATCH', 'DELETE')
_MAX_ENDPOINTS = 40
_HTTP_TIMEOUT = 8.0


class VerbTamperingModule(ExploitModule):
    name = 'verb-tampering'
    category = 'broken-function-auth'
    handles = ('api', 'graphql', 'website')
    timeout = 180

    async def run(self, ctx: ExploitContext) -> list[ExploitResult]:
        base = origin(ctx.target_url)
        destructive = bool(ctx.options.get('allow_destructive'))
        headers = {'Authorization': f'Bearer {ctx.auth_token}'} if ctx.auth_token else {}
        results: list[ExploitResult] = []

        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=False, verify=False,
                                     headers=headers) as client:
            spec = await fetch_spec(client, base)
            if not spec:
                return []
            paths = list((spec.get('paths') or {}).keys())[:_MAX_ENDPOINTS]

            for path in paths:
                url = f'{base}{fill_path(path)}'
                try:
                    opt = await client.request('OPTIONS', url)
                except httpx.HTTPError:
                    continue
                allow = opt.headers.get('allow') or opt.headers.get('Allow') or ''
                advertised = [m for m in _WRITE_METHODS if m in allow.upper()]
                log.info(f'[exploit:verb] scan {ctx.scan_id} OPTIONS {url} -> allow="{allow}"')

                if advertised and not destructive:
                    results.append(ExploitResult(
                        category=self.category,
                        title=f'Méthodes d\'écriture annoncées : {", ".join(advertised)} sur {path}',
                        severity=FindingSeverity.low.value,
                        confirmed=False,
                        impact='Le header Allow annonce des verbes d\'écriture. À confirmer (mode destructif '
                               'explicite) que leur exécution est bien contrôlée par une autorisation.',
                        request=f'OPTIONS {url}',
                        response=f'HTTP {opt.status_code}\nAllow: {allow}',
                    ))
                    continue

                if destructive:
                    for method in advertised or _WRITE_METHODS:
                        try:
                            r = await client.request(method, url)
                        except httpx.HTTPError:
                            continue
                        if 200 <= r.status_code < 300:
                            results.append(ExploitResult(
                                category=self.category,
                                title=f'Verbe d\'écriture accepté : {method} {path}',
                                severity=FindingSeverity.high.value,
                                confirmed=True,
                                impact='Un verbe d\'écriture aboutit (2xx) — autorisation de fonction cassée : '
                                       'modification/suppression de ressource possible.',
                                request=f'{method} {url}',
                                response=f'HTTP {r.status_code}\n{(r.text or "")[:300]}',
                            ))
        return results


register(VerbTamperingModule())
