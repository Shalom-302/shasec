"""js_secrets — scan the target's HTML + linked JS bundles for leaked secrets.

Ported from kaasec's ``secrets.sh``. Passive: fetches the landing page, resolves
every linked ``<script src>`` / ``.js`` asset (bounded), downloads them and greps
their content for high-signal credential patterns (AWS/GCP/GitHub/Stripe/Slack/…).

Improvement over the bash original: detected secret *values are masked* before
they are turned into findings, so shasec never re-stores a live credential in its
own DB / PDF report. Hits are aggregated per pattern (not one finding per match)
to keep the report readable.
"""
import asyncio
import re
from urllib.parse import urljoin, urlsplit

import httpx

from backend.app.shasec.plugins import register
from backend.app.shasec.plugins.base import RawFinding, ScanContext, ScannerPlugin
from backend.common.enums import FindingSeverity

# (name, compiled regex, severity) — ordered from most to least specific.
_PATTERNS: tuple[tuple[str, re.Pattern, str], ...] = (
    ('AWS access key id', re.compile(r'AKIA[0-9A-Z]{16}'), FindingSeverity.critical.value),
    ('AWS secret key', re.compile(r'aws.{0,20}?(?:secret|private)[^A-Za-z0-9]{0,3}[A-Za-z0-9/+=]{40}', re.I), FindingSeverity.high.value),
    ('GitHub token', re.compile(r'ghp_[0-9A-Za-z]{36}'), FindingSeverity.critical.value),
    ('GitHub fine-grained PAT', re.compile(r'github_pat_[0-9A-Za-z_]{80,}'), FindingSeverity.critical.value),
    ('Stripe live secret key', re.compile(r'sk_live_[0-9A-Za-z]{24,}'), FindingSeverity.critical.value),
    ('Stripe publishable key', re.compile(r'pk_live_[0-9A-Za-z]{24,}'), FindingSeverity.medium.value),
    ('SendGrid API key', re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'), FindingSeverity.critical.value),
    ('Slack token', re.compile(r'xox[baprs]-[0-9A-Za-z-]{10,}'), FindingSeverity.critical.value),
    ('Slack webhook', re.compile(r'https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[A-Za-z0-9]+'), FindingSeverity.high.value),
    ('Google API key', re.compile(r'AIza[0-9A-Za-z_-]{35}'), FindingSeverity.high.value),
    ('Google OAuth token', re.compile(r'ya29\.[0-9A-Za-z_-]{20,}'), FindingSeverity.high.value),
    ('Mailgun key', re.compile(r'key-[0-9a-f]{32}'), FindingSeverity.high.value),
    ('Twilio account SID', re.compile(r'AC[0-9a-fA-F]{32}'), FindingSeverity.medium.value),
    ('Firebase cloud-messaging key', re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'), FindingSeverity.high.value),
    ('Private key block', re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), FindingSeverity.critical.value),
    ('JWT', re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), FindingSeverity.medium.value),
)

_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
_ANY_JS = re.compile(r'(?:src|href)=["\']([^"\']+\.js[^"\']*)["\']', re.I)

_MAX_ASSETS = 40          # cap the number of JS files fetched
_MAX_BYTES = 512 * 1024   # only scan the first 512 KB of each asset
_CONCURRENCY = 6
_HTTP_TIMEOUT = 8.0


def _mask(value: str) -> str:
    """Redact a secret for safe storage: keep a short head/tail, hide the middle."""
    v = value.strip()
    if len(v) <= 12:
        return v[:2] + '***'
    return f'{v[:4]}…{v[-4:]} (len {len(v)})'


class JsSecretsPlugin(ScannerPlugin):
    name = 'js-secrets'
    handles = ('website', 'api', 'graphql')
    timeout = 120
    tier = 'fast'

    async def run(self, ctx: ScanContext) -> list[RawFinding]:
        base = ctx.target_url if '://' in ctx.target_url else f'https://{ctx.target_url}'
        if not urlsplit(base).hostname:
            return [RawFinding(title='js-secrets: cible invalide', severity=FindingSeverity.info.value,
                               fingerprint_seed='js-secrets-nohost')]

        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=True, verify=False,
                                     headers={'User-Agent': 'shasec/1.0 security audit'}) as client:
            try:
                index = await client.get(base)
            except httpx.HTTPError as exc:
                return [RawFinding(title=f'js-secrets : page inaccessible ({base})',
                                   severity=FindingSeverity.info.value, evidence=str(exc)[:200],
                                   fingerprint_seed='js-secrets-unreachable')]

            html = index.text or ''
            asset_urls = self._extract_assets(html, str(index.url))
            bodies = await self._fetch_assets(client, asset_urls)

        # source label -> body. Always include the landing page itself.
        sources: dict[str, str] = {'(page)': html}
        sources.update(bodies)

        # pattern name -> {severity, samples[], sources set}
        hits: dict[str, dict] = {}
        for src_label, body in sources.items():
            if not body:
                continue
            window = body[:_MAX_BYTES]
            for name, rx, sev in _PATTERNS:
                for m in rx.findall(window)[:3]:
                    match = m if isinstance(m, str) else next((g for g in m if g), '')
                    entry = hits.setdefault(name, {'sev': sev, 'samples': [], 'sources': set()})
                    if len(entry['samples']) < 3:
                        entry['samples'].append(_mask(match))
                    entry['sources'].add(src_label)

        if not hits:
            return [RawFinding(
                title=f'Aucun secret évident dans le JS ({len(asset_urls)} asset(s) scanné(s))',
                severity=FindingSeverity.info.value,
                description='Scan regex des bundles JS + HTML : aucun motif de credential connu détecté. '
                            'Un scan approfondi (trufflehog/gitleaks) reste recommandé.',
                fingerprint_seed='js-secrets-clean',
            )]

        findings: list[RawFinding] = []
        for name, data in hits.items():
            srcs = ', '.join(sorted(data['sources'])[:5])
            findings.append(RawFinding(
                title=f'Secret potentiel exposé dans le JS : {name}',
                severity=data['sev'],
                description='Motif de credential détecté dans un asset servi publiquement. '
                            'Valeur masquée volontairement — à vérifier manuellement et à révoquer si réel.',
                evidence=f"Exemples (masqués) : {', '.join(data['samples'])}\nSource(s) : {srcs}",
                recommendation='Retirer le secret du code front, le révoquer/rotationner, et déplacer les '
                               'appels sensibles côté backend (jamais de clé privée dans un bundle client).',
                fingerprint_seed=f'js-secret|{name}',
            ))
        return findings

    def _extract_assets(self, html: str, page_url: str) -> list[str]:
        refs: list[str] = []
        refs += _SCRIPT_SRC.findall(html)
        refs += _ANY_JS.findall(html)
        resolved: list[str] = []
        seen: set[str] = set()
        for ref in refs:
            url = urljoin(page_url, ref)
            if url.startswith(('http://', 'https://')) and url not in seen:
                seen.add(url)
                resolved.append(url)
            if len(resolved) >= _MAX_ASSETS:
                break
        return resolved

    async def _fetch_assets(self, client: httpx.AsyncClient, urls: list[str]) -> dict[str, str]:
        sem = asyncio.Semaphore(_CONCURRENCY)

        async def one(u: str) -> tuple[str, str]:
            async with sem:
                try:
                    r = await client.get(u)
                    return u, (r.text or '')
                except httpx.HTTPError:
                    return u, ''

        pairs = await asyncio.gather(*[one(u) for u in urls])
        return {u: b for u, b in pairs if b}


register(JsSecretsPlugin())
