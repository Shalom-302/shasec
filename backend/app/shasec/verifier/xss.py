"""xss — reflected-XSS detection, non-destructive (production-safe).

Detection, not exploitation: we inject a unique **inert** canary carrying the
context-breaking characters (`< > " '`) and check whether it is reflected in an
HTML response *unencoded*. Reflection of raw markup in an HTML context proves the
sink is exploitable — WITHOUT ever running JavaScript (no event handler, no
alert, no session theft). We stop at the proof.

Guards to keep false positives out of a prod target:
  * only GET query parameters from the OpenAPI spec (never write bodies / real data);
  * only responses served as text/html count (JSON reflection is not XSS);
  * the finding requires the raw special characters to survive unencoded, and is
    reproduced once before being reported.
"""
import secrets

import httpx

from backend.app.shasec.verifier import register
from backend.app.shasec.verifier._spec import fetch_spec, fill_path, get_endpoints, origin, query_params
from backend.app.shasec.verifier.base import ExploitContext, ExploitModule, ExploitResult
from backend.common.enums import FindingSeverity
from backend.common.log import log

_MAX_TARGETS = 25
# Encoded forms that mean the app defended itself — reflection is then harmless.
_ENCODED_MARKERS = ('&lt;', '&gt;', '&#60;', '&#62;', '%3C', '%3E')


def _canary() -> tuple[str, str]:
    """Return (marker, payload). The payload breaks out of HTML contexts but is
    inert — it contains no executable event handler, so nothing runs."""
    marker = f'shasec{secrets.token_hex(4)}'
    # Angle brackets + quotes prove context break; `zzz` tag is not a real element.
    return marker, f'{marker}"\'><zzz>'


def _reflected_raw(body: str, marker: str) -> bool:
    """True if the raw, unencoded breakout is reflected (executable context)."""
    if marker not in body:
        return False
    # The raw markup form we injected, reflected verbatim = unencoded sink.
    return f'{marker}"\'><zzz>' in body or f'{marker}"><zzz>' in body or f'{marker}><zzz>' in body


class XssModule(ExploitModule):
    name = 'xss'
    category = 'XSS'
    handles = ('api', 'website', 'graphql')
    timeout = 150

    async def run(self, ctx: ExploitContext) -> list[ExploitResult]:
        results: list[ExploitResult] = []
        headers = {'Authorization': f'Bearer {ctx.auth_token}'} if ctx.auth_token else {}
        async with httpx.AsyncClient(timeout=12, follow_redirects=True, verify=False,
                                     headers=headers) as client:
            spec = await fetch_spec(client, origin(ctx.target_url))
            if not spec:
                return results

            targets: list[tuple[str, str]] = []
            for path, _method, op in get_endpoints(spec):
                for param in query_params(op):
                    targets.append((path, param))
                    if len(targets) >= _MAX_TARGETS:
                        break
                if len(targets) >= _MAX_TARGETS:
                    break

            org = origin(ctx.target_url)
            for path, param in targets:
                url = f'{org}{fill_path(path)}'
                marker, payload = _canary()
                try:
                    r = await client.get(url, params={param: payload})
                except httpx.HTTPError:
                    continue
                ctype = r.headers.get('content-type', '').lower()
                log.info(f'[exploit:xss] scan {ctx.scan_id} {url}?{param}= -> {r.status_code} ({ctype})')
                if 'html' not in ctype:
                    continue  # JSON/text reflection is not XSS
                if r.status_code in (401, 403, 429) or r.status_code >= 500:
                    continue
                if not _reflected_raw(r.text, marker):
                    continue  # not reflected, or reflected but encoded → safe

                # Reproduce with a fresh canary to rule out a fluke / cached echo.
                marker2, payload2 = _canary()
                try:
                    r2 = await client.get(url, params={param: payload2})
                except httpx.HTTPError:
                    continue
                if 'html' not in r2.headers.get('content-type', '').lower():
                    continue
                if not _reflected_raw(r2.text, marker2):
                    continue

                idx = r2.text.find(marker2)
                snippet = r2.text[max(0, idx - 20):idx + 40] if idx >= 0 else ''
                results.append(ExploitResult(
                    category=self.category,
                    title=f'Reflected XSS dans `{param}` sur {path}',
                    severity=FindingSeverity.high.value,
                    confirmed=True,
                    impact='Le paramètre est réfléchi non encodé en contexte HTML exécutable : un attaquant '
                           'peut injecter du script côté client (vol de session, actions au nom de la victime). '
                           'Détection non destructive — aucun script n\'a été exécuté.',
                    request=f'GET {url}?{param}={payload2}',
                    response=f'HTTP {r2.status_code} (text/html) — reflet brut : …{snippet}…',
                ))
        return results


register(XssModule())
