from urllib.parse import urlsplit, urlunsplit

import httpx

from backend.app.shasec.verifier import register
from backend.app.shasec.verifier.base import ExploitContext, ExploitModule, ExploitResult
from backend.common.enums import FindingSeverity
from backend.common.log import log

# path -> (severity if exposed, why it matters)
_SENSITIVE = {
    '/.env': (FindingSeverity.critical, 'Environment file with secrets exposed'),
    '/.git/config': (FindingSeverity.critical, 'Git repository exposed (source/secrets recoverable)'),
    '/.git/HEAD': (FindingSeverity.high, 'Git metadata exposed'),
    '/.aws/credentials': (FindingSeverity.critical, 'AWS credentials exposed'),
    '/config.json': (FindingSeverity.high, 'Configuration file exposed'),
    '/.well-known/security.txt': (FindingSeverity.info, 'security.txt present'),
    '/actuator/env': (FindingSeverity.high, 'Spring actuator env (secrets) exposed'),
    '/actuator/health': (FindingSeverity.low, 'Spring actuator exposed'),
    '/server-status': (FindingSeverity.medium, 'Apache server-status exposed'),
    '/debug': (FindingSeverity.medium, 'Debug endpoint exposed'),
    '/.dockerenv': (FindingSeverity.low, 'Container marker reachable'),
    '/openapi.json': (FindingSeverity.low, 'API schema publicly exposed (full attack surface revealed)'),
    '/docs': (FindingSeverity.low, 'Interactive API docs (Swagger) publicly exposed in production'),
    '/redoc': (FindingSeverity.info, 'API docs (ReDoc) publicly exposed'),
}

# Markers that indicate the body is genuinely the sensitive resource (not a
# generic 200 HTML error page), to avoid false positives.
_CONFIRM_MARKERS = {
    '/.env': ('=',),
    '/.git/config': ('[core]', 'repositoryformatversion'),
    '/.git/HEAD': ('ref:',),
    '/actuator/env': ('"propertySources"', 'activeProfiles'),
    '/openapi.json': ('"openapi"', '"paths"'),
    '/docs': ('swagger', 'SwaggerUIBundle', 'redoc'),
    '/redoc': ('redoc', 'ReDoc'),
}


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, '', '', ''))


class ExposedEndpointsModule(ExploitModule):
    """Probe well-known sensitive paths and confirm real exposure (not just 200)."""

    name = 'exposed-endpoints'
    category = 'exposed-endpoint'
    handles = ('website', 'api', 'graphql')
    timeout = 60

    async def run(self, ctx: ExploitContext) -> list[ExploitResult]:
        origin = _origin(ctx.target_url)
        results: list[ExploitResult] = []
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            for path, (sev, why) in _SENSITIVE.items():
                url = f'{origin}{path}'
                try:
                    resp = await client.get(url)
                except httpx.HTTPError:
                    continue
                log.info(f'[exploit:exposed] scan {ctx.scan_id} GET {url} -> {resp.status_code}')
                if resp.status_code != 200:
                    continue
                body = resp.text[:2000]
                markers = _CONFIRM_MARKERS.get(path)
                confirmed = True if markers is None else any(m in body for m in markers)
                if not confirmed:
                    continue
                results.append(
                    ExploitResult(
                        category=self.category,
                        title=f'Exposed: {path}',
                        severity=sev.value,
                        confirmed=True,
                        impact=why,
                        request=f'GET {url}',
                        response=f'HTTP {resp.status_code}\n{body[:400]}',
                    )
                )
        return results


register(ExposedEndpointsModule())
