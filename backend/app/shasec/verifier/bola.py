"""bola — Broken Object Level Authorization (IDOR) probe.

Ported from ``_api_bola`` (api.sh). With a valid operator token, it iterates an ID
range over endpoints whose path carries an object identifier (``/users/{id}``,
``/orders/{orderId}``…). If several IDs return 2xx bodies of *distinct* sizes, the
authenticated caller is reaching objects that are probably not theirs — a BOLA/IDOR
candidate. Response bodies are also scanned for leaks (shared ``_leaks``).

Requires ``ctx.auth_token`` (the whole point is authenticated cross-object access);
skips cleanly otherwise. ID range configurable via ``ctx.options['id_range']``
(default ``1-10``). Read-only: GET only, bounded endpoints/IDs.
"""
import re

import httpx

from backend.app.shasec.verifier import register
from backend.app.shasec.verifier._leaks import scan_body
from backend.app.shasec.verifier._spec import fetch_spec, origin
from backend.app.shasec.verifier.base import ExploitContext, ExploitModule, ExploitResult
from backend.common.enums import FindingSeverity
from backend.common.log import log

_ID_PARAM = re.compile(r'\{[A-Za-z_]*[Ii][Dd]\}|:[A-Za-z_]*[Ii][Dd]\b')
_MAX_ENDPOINTS = 10
_HTTP_TIMEOUT = 6.0


def _parse_range(spec: str) -> tuple[int, int]:
    try:
        lo, hi = spec.split('-', 1)
        lo_i, hi_i = int(lo), int(hi)
        if lo_i <= hi_i and (hi_i - lo_i) <= 200:
            return lo_i, hi_i
    except (ValueError, AttributeError):
        pass
    return 1, 10


def _fill_id(path: str, value: int) -> str:
    path = re.sub(r'\{[^}]+\}', str(value), path)
    path = re.sub(r':[A-Za-z_][A-Za-z0-9_]*', str(value), path)
    return path


class BolaModule(ExploitModule):
    name = 'bola'
    category = 'bola'
    handles = ('api', 'graphql')
    timeout = 180

    async def run(self, ctx: ExploitContext) -> list[ExploitResult]:
        if not ctx.auth_token:
            return [ExploitResult(
                category=self.category,
                title='BOLA/IDOR ignoré : aucun token fourni',
                severity=FindingSeverity.info.value,
                confirmed=False,
                impact='Fournir un token valide (auth_token du scan) pour tester l\'accès inter-objets.',
            )]

        base = origin(ctx.target_url)
        id_from, id_to = _parse_range(str(ctx.options.get('id_range', '1-10')))
        headers = {'Authorization': f'Bearer {ctx.auth_token}'}
        results: list[ExploitResult] = []

        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=True, verify=False,
                                     headers=headers) as client:
            spec = await fetch_spec(client, base)
            if not spec:
                return []
            id_paths = [
                path for path, item in (spec.get('paths') or {}).items()
                if isinstance(item, dict) and isinstance(item.get('get'), dict) and _ID_PARAM.search(path)
            ][:_MAX_ENDPOINTS]

            for path in id_paths:
                sizes: list[int] = []
                ok = 0
                sample: list[str] = []
                leak_hits: list[tuple[str, str, str, str]] = []
                for oid in range(id_from, id_to + 1):
                    url = f'{base}{_fill_id(path, oid)}'
                    try:
                        r = await client.get(url)
                    except httpx.HTTPError:
                        continue
                    body = r.text or ''
                    sizes.append(len(body))
                    if 200 <= r.status_code < 300:
                        ok += 1
                        leak_hits += scan_body(body)
                    if len(sample) < 6:
                        sample.append(f'id={oid} -> {r.status_code} ({len(body)}o)')
                log.info(f'[exploit:bola] scan {ctx.scan_id} {path} ok={ok} distinct_sizes={len(set(sizes))}')

                if ok >= 3 and len({s for s in sizes if s > 0}) >= 3:
                    results.append(ExploitResult(
                        category=self.category,
                        title=f'BOLA/IDOR probable sur {path}',
                        severity=FindingSeverity.critical.value,
                        confirmed=True,
                        impact=f'{ok} IDs renvoient un 2xx avec des tailles de réponse distinctes : '
                               'le compte authentifié accède à des objets qui ne lui appartiennent '
                               'probablement pas.',
                        request=f'GET {base}{path}  (id ∈ [{id_from}..{id_to}], token fourni)',
                        response='\n'.join(sample),
                    ))
                    # Surface any sensitive data seen while iterating.
                    seen: set[str] = set()
                    for cat, title, sev, impact in leak_hits:
                        if title in seen:
                            continue
                        seen.add(title)
                        results.append(ExploitResult(
                            category=cat,
                            title=f'{title} (via BOLA {path})',
                            severity=sev,
                            confirmed=True,
                            impact=impact,
                            request=f'GET {base}{path}  (itération BOLA)',
                            response='(voir preuve BOLA ci-dessus)',
                        ))
        return results


register(BolaModule())
