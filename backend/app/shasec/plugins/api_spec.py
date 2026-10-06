"""api_spec — discover and parse a target's API specification.

Ported from the spec-discovery stage of kaasec's ``api.sh``. Passive: probes the
well-known Swagger/OpenAPI locations, and when it finds a machine-readable spec it
*parses* it (native ``json``, no jq) to inventory every declared operation
(``METHOD /path``). That inventory is the map the active API verifiers (verb
tampering, BOLA, rate-limit — lot 2) will consume.

Findings:
  * machine-readable spec publicly reachable  → high (full attack surface leaked)
  * interactive docs UI (Swagger-UI/ReDoc)    → medium
  * GraphQL endpoint reachable                 → medium (introspection = lot 2)
  * parsed inventory of N operations           → info (evidence = sample list)
"""
import json
from urllib.parse import urlsplit, urlunsplit

import httpx

from backend.app.shasec.plugins import register
from backend.app.shasec.plugins.base import RawFinding, ScanContext, ScannerPlugin
from backend.common.enums import FindingSeverity

# Machine-readable specs (parseable → inventory).
_SPEC_PATHS = (
    '/swagger.json', '/swagger/v1/swagger.json', '/openapi.json', '/openapi/v3/openapi.json',
    '/api-docs', '/api-docs.json', '/v1/api-docs', '/v2/api-docs', '/v3/api-docs',
    '/api/v1/openapi', '/openapi.yaml', '/swagger.yaml',
)
# Human docs UIs (exposure, not parseable here).
_DOC_UI_PATHS = ('/swagger-ui.html', '/swagger-ui/', '/docs', '/redoc')
# GraphQL surfaces.
_GRAPHQL_PATHS = ('/graphql', '/graphiql', '/playground')

_HTTP_METHODS = {'get', 'post', 'put', 'patch', 'delete', 'options', 'head'}
_HTTP_TIMEOUT = 8.0
_MAX_PROBE_BYTES = 200 * 1024


def _origin(url: str) -> str:
    p = urlsplit(url if '://' in url else f'//{url}')
    scheme = p.scheme or 'https'
    return urlunsplit((scheme, p.netloc or p.path, '', '', ''))


def _base_path(spec: dict) -> str:
    """Swagger 2 basePath, or the path component of OpenAPI 3 servers[0].url."""
    bp = spec.get('basePath')
    if isinstance(bp, str) and bp:
        return bp.rstrip('/')
    servers = spec.get('servers')
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        server_path = urlsplit(str(servers[0].get('url', ''))).path
        return server_path.rstrip('/')
    return ''


def _operations(spec: dict) -> list[str]:
    """Return sorted ``METHOD /path`` strings declared in the spec."""
    paths = spec.get('paths')
    if not isinstance(paths, dict):
        return []
    bp = _base_path(spec)
    ops: set[str] = set()
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in item:
            if isinstance(method, str) and method.lower() in _HTTP_METHODS:
                ops.add(f'{method.upper()} {bp}{path}')
    return sorted(ops)


class ApiSpecPlugin(ScannerPlugin):
    name = 'api-spec'
    handles = ('api', 'graphql', 'website')
    timeout = 90

    async def run(self, ctx: ScanContext) -> list[RawFinding]:
        origin = _origin(ctx.target_url)
        if not urlsplit(origin).hostname:
            return [RawFinding(title='api-spec: cible invalide', severity=FindingSeverity.info.value,
                               fingerprint_seed='api-spec-nohost')]

        findings: list[RawFinding] = []
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=True, verify=False,
                                     headers={'User-Agent': 'shasec/1.0 security audit'}) as client:
            spec_found = await self._hunt_spec(client, origin, findings)
            if not spec_found:
                await self._hunt_docs_ui(client, origin, findings)
            await self._hunt_graphql(client, origin, findings)

        if not findings:
            findings.append(RawFinding(
                title='api-spec : aucune spécification/doc d\'API publiquement exposée',
                severity=FindingSeverity.info.value,
                description='Aucun OpenAPI/Swagger/GraphQL joignable sur les emplacements usuels.',
                fingerprint_seed='api-spec-none',
            ))
        return findings

    async def _hunt_spec(self, client, origin: str, findings: list[RawFinding]) -> bool:
        for path in _SPEC_PATHS:
            url = f'{origin}{path}'
            try:
                r = await client.get(url)
            except httpx.HTTPError:
                continue
            if r.status_code != 200:
                continue
            text = r.text[:_MAX_PROBE_BYTES] if r.content else ''
            if not any(marker in text for marker in ('"swagger"', '"openapi"', '"paths"')):
                continue

            findings.append(RawFinding(
                title=f'Spécification d\'API exposée publiquement : {path}',
                severity=FindingSeverity.high.value,
                description='Une spec OpenAPI/Swagger lisible par machine est accessible sans authentification : '
                            'un attaquant énumère l\'intégralité des endpoints et de leurs paramètres attendus.',
                evidence=url,
                recommendation='Restreindre l\'accès à la spec en production (auth/IP) si elle n\'a pas à être publique.',
                fingerprint_seed='api-spec-exposed',
            ))

            try:
                spec = json.loads(r.text)
            except (json.JSONDecodeError, ValueError):
                findings.append(RawFinding(
                    title='api-spec : spec trouvée mais non parsable en JSON',
                    severity=FindingSeverity.info.value, evidence=url,
                    description='Probablement du YAML — l\'inventaire automatique est ignoré pour cette spec.',
                    fingerprint_seed='api-spec-unparsable'))
                return True

            ops = _operations(spec)
            if ops:
                sample = '\n'.join(ops[:60]) + (f'\n… (+{len(ops) - 60})' if len(ops) > 60 else '')
                findings.append(RawFinding(
                    title=f'Inventaire d\'API : {len(ops)} opération(s) déclarée(s)',
                    severity=FindingSeverity.info.value,
                    description='Endpoints extraits de la spec (METHOD /path). Base des tests actifs '
                                '(verb tampering, BOLA, rate-limit).',
                    evidence=sample,
                    fingerprint_seed='api-spec-inventory',
                ))
            return True
        return False

    async def _hunt_docs_ui(self, client, origin: str, findings: list[RawFinding]) -> None:
        for path in _DOC_UI_PATHS:
            url = f'{origin}{path}'
            try:
                r = await client.get(url)
            except httpx.HTTPError:
                continue
            body = (r.text[:4000].lower() if r.content else '')
            if r.status_code == 200 and any(m in body for m in ('swagger', 'swaggerui', 'redoc')):
                findings.append(RawFinding(
                    title=f'Documentation d\'API interactive exposée : {path}',
                    severity=FindingSeverity.medium.value,
                    description='Console de doc (Swagger-UI/ReDoc) accessible publiquement — révèle endpoints '
                                'et schéma d\'authentification.',
                    evidence=url,
                    recommendation='Désactiver ou protéger la doc interactive en production.',
                    fingerprint_seed=f'api-spec-docui|{path}',
                ))
                return

    async def _hunt_graphql(self, client, origin: str, findings: list[RawFinding]) -> None:
        for path in _GRAPHQL_PATHS:
            url = f'{origin}{path}'
            try:
                r = await client.post(url, json={'query': '{__typename}'})
            except httpx.HTTPError:
                continue
            body = (r.text[:2000] if r.content else '')
            if r.status_code in (200, 400) and ('__typename' in body or '"data"' in body or 'GraphQL' in body):
                findings.append(RawFinding(
                    title=f'Endpoint GraphQL joignable : {path}',
                    severity=FindingSeverity.medium.value,
                    description='Surface GraphQL présente. Le test d\'introspection et des requêtes dangereuses '
                                'relève de l\'étape d\'exploitation active (verifier GraphQL).',
                    evidence=url,
                    fingerprint_seed=f'api-spec-graphql|{path}',
                ))
                return


register(ApiSpecPlugin())
