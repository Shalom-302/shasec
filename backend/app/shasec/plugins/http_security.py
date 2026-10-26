import httpx

from backend.app.shasec.plugins import register
from backend.app.shasec.plugins.base import RawFinding, ScanContext, ScannerPlugin
from backend.common.enums import FindingSeverity

# header -> (severity, title, recommendation)
_SECURITY_HEADERS = {
    'strict-transport-security': (
        FindingSeverity.medium, 'Missing HSTS header',
        'Add Strict-Transport-Security with a long max-age and includeSubDomains.',
    ),
    'content-security-policy': (
        FindingSeverity.medium, 'Missing Content-Security-Policy',
        'Define a restrictive CSP to mitigate XSS and injection.',
    ),
    'x-content-type-options': (
        FindingSeverity.low, 'Missing X-Content-Type-Options',
        'Set X-Content-Type-Options: nosniff.',
    ),
    'x-frame-options': (
        FindingSeverity.low, 'Missing X-Frame-Options',
        'Set X-Frame-Options: DENY or use CSP frame-ancestors.',
    ),
    'referrer-policy': (
        FindingSeverity.info, 'Missing Referrer-Policy',
        'Set Referrer-Policy such as no-referrer or strict-origin-when-cross-origin.',
    ),
    'permissions-policy': (
        FindingSeverity.info, 'Missing Permissions-Policy',
        'Restrict powerful browser features via Permissions-Policy.',
    ),
}


class HttpSecurityPlugin(ScannerPlugin):
    """Pure-Python baseline scanner: HTTP security headers, transport and banner.

    Needs no external binary, so it runs anywhere. It is the reference
    implementation of the plugin contract.
    """

    name = 'http-security'
    handles = ('website', 'api', 'graphql')
    timeout = 30
    tier = 'fast'

    async def run(self, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        # Probe with certificate verification first so an untrusted/self-signed
        # cert is reported as a finding (it is a real weakness), then retry with
        # verification OFF so a bad cert never blocks the header checks — the
        # host is reachable, we must still read its security headers.
        async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False) as client:
            try:
                resp = await client.get(ctx.target_url)
            except httpx.HTTPError as exc:
                return [
                    RawFinding(
                        title='Target unreachable',
                        severity=FindingSeverity.info.value,
                        description=f'Could not connect to {ctx.target_url}: {exc}',
                    )
                ]

            if ctx.target_url.lower().startswith('https://'):
                try:
                    async with httpx.AsyncClient(timeout=10, follow_redirects=False, verify=True) as verified:
                        await verified.get(ctx.target_url)
                except httpx.HTTPError as exc:
                    if 'certificate' in str(exc).lower() or 'ssl' in str(exc).lower():
                        findings.append(RawFinding(
                            title='Certificat TLS non fiable',
                            severity=FindingSeverity.medium.value,
                            description='Le certificat TLS n\'a pas pu être validé (auto-signé, expiré ou '
                                        'autorité inconnue). Un visiteur voit un avertissement et le trafic '
                                        'peut être intercepté (man-in-the-middle).',
                            evidence=str(exc)[:200],
                            recommendation='Installer un certificat émis par une autorité reconnue (ex. Let\'s Encrypt).',
                            fingerprint_seed='http-security-bad-cert',
                        ))

            headers = {k.lower(): v for k, v in resp.headers.items()}

            if ctx.target_url.lower().startswith('http://'):
                findings.append(
                    RawFinding(
                        title='Endpoint served over plaintext HTTP',
                        severity=FindingSeverity.high.value,
                        description='Traffic is not encrypted; credentials and data can be intercepted.',
                        evidence=ctx.target_url,
                        recommendation='Serve exclusively over HTTPS and redirect HTTP to HTTPS.',
                    )
                )

            for header, (sev, title, reco) in _SECURITY_HEADERS.items():
                if header not in headers:
                    findings.append(
                        RawFinding(
                            title=title,
                            severity=sev.value,
                            description=f'Response is missing the {header} header.',
                            evidence=f'GET {ctx.target_url} -> HTTP {resp.status_code}',
                            recommendation=reco,
                        )
                    )

            server = headers.get('server')
            if server:
                findings.append(
                    RawFinding(
                        title='Server banner discloses software',
                        severity=FindingSeverity.low.value,
                        description='The Server header reveals backend software, aiding fingerprinting.',
                        evidence=f'Server: {server}',
                        recommendation='Suppress or genericize the Server header.',
                    )
                )

        return findings


register(HttpSecurityPlugin())
