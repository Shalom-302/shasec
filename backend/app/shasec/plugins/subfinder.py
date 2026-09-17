"""subfinder (ProjectDiscovery) — passive subdomain enumeration + surface triage.

Two passes, both in scope:
 1. Enumerate subdomains of the target's own domain (passive sources only).
 2. Lightly probe each discovered host to answer the pentester's real questions:
    is it a **frontend** (serves HTML) or an **API/backend** (serves JSON), and
    **where is its documentation** (OpenAPI/Swagger/Redoc/GraphQL)? — manual
    Phase 5/6 (API inventory & doc discovery).

The probe is bounded (capped host count, low concurrency, short timeouts, a
curated path list) to honour the manual's low-footprint rule. subfinder itself
skips cleanly when the binary is absent.
"""
import asyncio
import ipaddress
import re
import shutil
from urllib.parse import urlsplit

import httpx

from backend.app.shasec.plugins import register
from backend.app.shasec.plugins.base import RawFinding, ScanContext, ScannerPlugin, run_command
from backend.common.enums import FindingSeverity

# Subdomain prefixes that usually expose a softer / non-prod surface.
_INTERESTING = re.compile(
    r'^(dev|test|staging|stage|preprod|uat|qa|admin|internal|intranet|vpn|'
    r'git|jenkins|ci|api|gateway|dashboard|grafana|kibana|jira|mail|smtp|'
    r'ftp|backup|old|legacy|beta|demo|sandbox)\b', re.I,
)
# Names that strongly hint at an API/backend surface (worth probing doc paths).
_API_NAME = re.compile(r'^(api|apis|backend|back|gw|gateway|rest|graphql|gql|service|svc|ms|core)\b', re.I)

# Curated documentation paths, ordered by how definitive they are.
_DOC_PATHS = (
    '/openapi.json', '/swagger.json', '/v3/api-docs', '/v2/api-docs', '/api-docs',
    '/api/v1/openapi', '/docs', '/redoc', '/swagger-ui.html', '/swagger', '/api/docs',
    '/graphql', '/graphiql',
)
_DOC_MARKERS = ('swagger', 'openapi', '"paths"', 'redoc', 'graphiql', '__schema', 'apispec')

_MAX_HOSTS = 40          # cap the probe surface
_CONCURRENCY = 6         # polite parallelism
_HTTP_TIMEOUT = 6.0


def _host_of(target_url: str) -> str:
    parsed = urlsplit(target_url if '://' in target_url else f'//{target_url}')
    return (parsed.hostname or target_url).strip().rstrip('.')


class SubfinderPlugin(ScannerPlugin):
    name = 'subfinder'
    handles = ('host', 'website', 'api', 'graphql')
    timeout = 300

    async def run(self, ctx: ScanContext) -> list[RawFinding]:
        host = _host_of(ctx.target_url)
        if not host:
            return [RawFinding(title='subfinder: cible sans domaine', severity=FindingSeverity.info.value,
                               fingerprint_seed='subfinder-nohost')]
        try:
            ipaddress.ip_address(host)
            return [RawFinding(title='subfinder ignoré : la cible est une IP',
                               severity=FindingSeverity.info.value,
                               description='L\'énumération de sous-domaines ne s\'applique qu\'à un nom de domaine.',
                               fingerprint_seed='subfinder-ip')]
        except ValueError:
            pass

        if shutil.which('subfinder') is None:
            return [RawFinding(title='subfinder not installed', severity=FindingSeverity.info.value,
                               description='ProjectDiscovery subfinder unavailable; plugin skipped.',
                               recommendation='Bake the subfinder binary into the API image to enable subdomain recon.',
                               fingerprint_seed='subfinder-missing')]

        _, out, _ = await run_command(['subfinder', '-d', host, '-silent', '-all'], timeout=self.timeout)
        subs = sorted({ln.strip().rstrip('.') for ln in out.splitlines() if ln.strip()})
        subs = [s for s in subs if host in s] or subs
        if host not in subs:
            subs.insert(0, host)
        if not subs:
            return [RawFinding(title=f'subfinder : aucun sous-domaine découvert pour {host}',
                               severity=FindingSeverity.info.value, fingerprint_seed='subfinder-empty')]

        sample = '\n'.join(subs[:40]) + (f'\n… (+{len(subs) - 40})' if len(subs) > 40 else '')
        findings = [RawFinding(
            title=f"Surface d'attaque : {len(subs)} sous-domaine(s) découvert(s)",
            severity=FindingSeverity.info.value,
            description='Inventaire de sous-domaines (recon passive). Chacun est à valider contre le scope.',
            evidence=sample, fingerprint_seed='subfinder-surface',
        )]

        # --- Pass 2: classify frontend vs API + find docs -----------------------
        probed = await self._triage(subs[:_MAX_HOSTS])
        if probed:
            # Pipe-delimited (kind|host|doc|title) so the web console can render it
            # as a proper table; still readable in the raw finding.
            table = '\n'.join(
                f"{p['kind']} | {p['host']} | {p['doc']} | {p['title']}" for p in probed
            )
            findings.append(RawFinding(
                title='Cartographie des sous-domaines (frontend / API / doc)',
                severity=FindingSeverity.info.value,
                description='Type déduit du contenu servi (HTML = frontend, JSON/doc = API) et documentation '
                            'trouvée. Format par ligne : type | sous-domaine | doc | titre. Sonde légère — '
                            'à confirmer manuellement, uniquement dans le scope.',
                evidence=table[:4000], fingerprint_seed='subfinder-triage',
            ))
            for p in [x for x in probed if x['doc']]:
                findings.append(RawFinding(
                    title=f"Documentation d'API exposée : {p['doc']}",
                    severity=FindingSeverity.low.value,
                    description='Spécification/console d\'API accessible (OpenAPI/Swagger/Redoc/GraphQL). '
                                'Cartographie idéale des endpoints — vérifier si l\'exposition publique est voulue.',
                    evidence=f"{p['host']} · {p['kind']} · {p['doc']}",
                    recommendation='Restreindre l\'accès à la doc en production si elle n\'a pas à être publique.',
                    fingerprint_seed=f"subfinder-doc|{p['doc']}",
                ))

        for sub in [s for s in subs if _INTERESTING.search(s.split('.')[0])][:20]:
            findings.append(RawFinding(
                title=f'Sous-domaine sensible : {sub}',
                severity=FindingSeverity.low.value,
                description='Nom évoquant un environnement non-prod ou une interface d\'administration — '
                            'à vérifier (exposition, auth) si dans le scope.',
                evidence=sub, fingerprint_seed=f'subfinder-interesting|{sub}',
            ))
        return findings

    async def _triage(self, hosts: list[str]) -> list[dict]:
        sem = asyncio.Semaphore(_CONCURRENCY)
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=True, verify=False) as client:
            async def one(h):
                async with sem:
                    return await self._probe(client, h)
            results = await asyncio.gather(*[one(h) for h in hosts], return_exceptions=True)
        return [r for r in results if isinstance(r, dict) and r.get('reachable')]

    @staticmethod
    async def _probe(client: httpx.AsyncClient, host: str) -> dict:
        info = {'host': host, 'reachable': False, 'kind': 'inconnu', 'title': '', 'doc': ''}
        base = None
        for scheme in ('https', 'http'):
            try:
                resp = await client.get(f'{scheme}://{host}/')
                base = f'{scheme}://{host}'
                break
            except httpx.HTTPError:
                continue
        if base is None:
            return info
        info['reachable'] = True

        ctype = resp.headers.get('content-type', '').lower()
        body = resp.text[:2000] if resp.content else ''
        if 'json' in ctype or body.lstrip().startswith(('{', '[')):
            info['kind'] = 'api'
        elif 'html' in ctype:
            info['kind'] = 'frontend'
            m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
            if m:
                info['title'] = m.group(1).strip()[:60]

        # Probe doc paths when the host looks like an API (by content or by name).
        if info['kind'] == 'api' or _API_NAME.search(host.split('.')[0]):
            for path in _DOC_PATHS:
                try:
                    r = await client.get(f'{base}{path}')
                except httpx.HTTPError:
                    continue
                if r.status_code != 200:
                    continue
                dtype = r.headers.get('content-type', '').lower()
                dbody = r.text[:3000].lower() if r.content else ''
                if 'json' in dtype or any(mk in dbody for mk in _DOC_MARKERS):
                    info['doc'] = f'{base}{path}'
                    info['kind'] = 'api'
                    break
        return info


register(SubfinderPlugin())
