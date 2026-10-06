"""rate_limit — detect the absence of API rate limiting.

Ported from ``_api_rate_limit`` (api.sh). Fires a bounded burst at one endpoint
(the first GET declared in the spec, else the target root) and checks whether any
request is throttled (HTTP 429). No 429 across the whole burst ⇒ a medium finding:
brute-force / credential-stuffing / DoS exposure.

Bounded and read-only: only GETs, a fixed small burst, low concurrency.
"""
import asyncio

import httpx

from backend.app.shasec.verifier import register
from backend.app.shasec.verifier._spec import fetch_spec, fill_path, origin
from backend.app.shasec.verifier.base import ExploitContext, ExploitModule, ExploitResult
from backend.common.enums import FindingSeverity
from backend.common.log import log

_BURST = 30
_CONCURRENCY = 10
_HTTP_TIMEOUT = 5.0


class RateLimitModule(ExploitModule):
    name = 'rate-limit'
    category = 'rate-limiting'
    handles = ('api', 'graphql', 'website')
    timeout = 90

    async def run(self, ctx: ExploitContext) -> list[ExploitResult]:
        base = origin(ctx.target_url)
        headers = {'Authorization': f'Bearer {ctx.auth_token}'} if ctx.auth_token else {}

        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=True, verify=False,
                                     headers=headers) as client:
            target = await self._pick_endpoint(client, base, ctx.target_url)
            sem = asyncio.Semaphore(_CONCURRENCY)

            async def one() -> int:
                async with sem:
                    try:
                        r = await client.get(target)
                        return r.status_code
                    except httpx.HTTPError:
                        return 0

            codes = await asyncio.gather(*[one() for _ in range(_BURST)])
            throttled = sum(1 for c in codes if c == 429)
            ok = sum(1 for c in codes if 200 <= c < 400)
            log.info(f'[exploit:rate] scan {ctx.scan_id} burst {_BURST} on {target} -> 429×{throttled}, ok×{ok}')

            if throttled == 0 and ok >= _BURST // 2:
                return [ExploitResult(
                    category=self.category,
                    title='Absence de limitation de débit (rate limiting)',
                    severity=FindingSeverity.medium.value,
                    confirmed=True,
                    impact=f'{_BURST} requêtes en rafale sur {target} sans aucun HTTP 429 : '
                           'brute-force, credential-stuffing et DoS applicatif facilités.',
                    request=f'GET {target}  ×{_BURST} (rafale)',
                    response=f'{ok}/{_BURST} en 2xx/3xx, 0 réponse 429',
                )]
        return []

    async def _pick_endpoint(self, client: httpx.AsyncClient, base: str, target_url: str) -> str:
        spec = await fetch_spec(client, base)
        if spec:
            for path, item in (spec.get('paths') or {}).items():
                if isinstance(item, dict) and isinstance(item.get('get'), dict):
                    return f'{base}{fill_path(path)}'
        return target_url if '://' in target_url else f'{base}/'


register(RateLimitModule())
