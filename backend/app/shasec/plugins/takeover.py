"""takeover — detect dangling CNAMEs vulnerable to subdomain takeover.

Ported from kaasec's ``takeover.sh`` (ref: github.com/EdOverflow/can-i-take-over-xyz).
Passive: enumerates subdomains (via ``subfinder`` when available, plus a curated
prefix list), resolves each CNAME with ``dig``, and — when a CNAME points at a
takeover-prone provider (GitHub Pages, S3, Heroku, Netlify…) — fetches the page
and confirms the provider's "unclaimed" fingerprint in the body.

A confirmed fingerprint is ``critical``; a matching CNAME whose body does not (yet)
match is surfaced as ``low`` for manual review, to keep false positives out of the
critical bucket.
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

# provider CNAME suffix -> regex of the "unclaimed / not-found" fingerprint.
_FINGERPRINTS: dict[str, re.Pattern] = {
    'github.io': re.compile(r"There isn't a GitHub Pages site here|project not found", re.I),
    'herokuapp.com': re.compile(r'No such app', re.I),
    's3.amazonaws.com': re.compile(r'NoSuchBucket', re.I),
    's3-website': re.compile(r'NoSuchBucket', re.I),
    'netlify.app': re.compile(r'Not Found - Request ID', re.I),
    'netlify.com': re.compile(r'Not Found - Request ID', re.I),
    'cloudfront.net': re.compile(r'The distribution you are trying to access', re.I),
    'fastly.net': re.compile(r'Fastly error: unknown domain', re.I),
    'wordpress.com': re.compile(r'Do you want to register', re.I),
    'pantheonsite.io': re.compile(r'The gods are wise', re.I),
    'readthedocs.io': re.compile(r'Unknown to us', re.I),
    'ghost.io': re.compile(r'Domain error', re.I),
    'surge.sh': re.compile(r'project not found', re.I),
    'bitbucket.io': re.compile(r'Repository not found', re.I),
    'azurewebsites.net': re.compile(r'404 Web Site not found', re.I),
    'myshopify.com': re.compile(r'Sorry, this shop is currently unavailable', re.I),
    'zendesk.com': re.compile(r'Help Center Closed', re.I),
    'statuspage.io': re.compile(r'You are being redirected', re.I),
    'tumblr.com': re.compile(r"There's nothing here", re.I),
}

# Common prefixes probed when subfinder is unavailable, so the plugin still
# catches the frequent cases without any external enumerator.
_COMMON_PREFIXES = (
    'www', 'api', 'dev', 'staging', 'stage', 'test', 'uat', 'preprod', 'blog',
    'shop', 'store', 'docs', 'status', 'cdn', 'assets', 'static', 'media', 'img',
    'mail', 'app', 'admin', 'portal', 'support', 'help', 'beta', 'demo', 'm',
)

_MAX_HOSTS = 60
_CONCURRENCY = 8
_HTTP_TIMEOUT = 6.0


def _host_of(target_url: str) -> str:
    parsed = urlsplit(target_url if '://' in target_url else f'//{target_url}')
    return (parsed.hostname or target_url).strip().rstrip('.')


class TakeoverPlugin(ScannerPlugin):
    name = 'takeover'
    handles = ('host', 'website', 'api', 'graphql')
    timeout = 240

    async def run(self, ctx: ScanContext) -> list[RawFinding]:
        host = _host_of(ctx.target_url)
        if not host:
            return [RawFinding(title='takeover: cible sans domaine', severity=FindingSeverity.info.value,
                               fingerprint_seed='takeover-nohost')]
        try:
            ipaddress.ip_address(host)
            return [RawFinding(title='takeover ignoré : la cible est une IP',
                               severity=FindingSeverity.info.value,
                               fingerprint_seed='takeover-ip')]
        except ValueError:
            pass

        if shutil.which('dig') is None:
            return [RawFinding(title='takeover : dig indisponible',
                               severity=FindingSeverity.info.value,
                               description='La résolution CNAME nécessite dig ; plugin ignoré.',
                               recommendation='Installer dnsutils (dig) dans l\'image de l\'API.',
                               fingerprint_seed='takeover-nodig')]

        hosts = await self._enumerate(host)
        cnames = await self._resolve_cnames(hosts)
        if not cnames:
            return [RawFinding(title=f'takeover : aucun CNAME sur {len(hosts)} hôte(s) testé(s)',
                               severity=FindingSeverity.info.value, fingerprint_seed='takeover-nocname')]

        # Keep only CNAMEs pointing at a takeover-prone provider.
        candidates = [
            (sub, cname, suffix)
            for sub, cname in cnames.items()
            for suffix in _FINGERPRINTS
            if suffix in cname
        ]
        if not candidates:
            return [RawFinding(
                title=f'takeover : aucun CNAME vers un service à risque ({len(cnames)} CNAME analysé(s))',
                severity=FindingSeverity.info.value, fingerprint_seed='takeover-safe')]

        findings = await self._confirm(candidates)
        return findings or [RawFinding(
            title='takeover : CNAMEs à risque détectés mais non confirmés',
            severity=FindingSeverity.info.value, fingerprint_seed='takeover-inconclusive')]

    async def _enumerate(self, host: str) -> list[str]:
        subs = {host}
        if shutil.which('subfinder'):
            try:
                _, out, _ = await run_command(['subfinder', '-d', host, '-silent', '-all'], timeout=120)
                subs.update(ln.strip().rstrip('.') for ln in out.splitlines()
                            if ln.strip() and host in ln)
            except (TimeoutError, OSError):
                pass
        subs.update(f'{p}.{host}' for p in _COMMON_PREFIXES)
        return list(subs)[:_MAX_HOSTS]

    async def _resolve_cnames(self, hosts: list[str]) -> dict[str, str]:
        sem = asyncio.Semaphore(_CONCURRENCY)

        async def one(sub: str) -> tuple[str, str]:
            async with sem:
                try:
                    _, out, _ = await run_command(['dig', '+short', 'CNAME', sub], timeout=10)
                except (TimeoutError, OSError):
                    return sub, ''
                cname = next((ln.strip().rstrip('.') for ln in out.splitlines() if ln.strip()), '')
                return sub, cname

        pairs = await asyncio.gather(*[one(h) for h in hosts])
        return {sub: cname for sub, cname in pairs if cname}

    async def _confirm(self, candidates: list[tuple[str, str, str]]) -> list[RawFinding]:
        findings: list[RawFinding] = []
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=True, verify=False,
                                     headers={'User-Agent': 'shasec/1.0 security audit'}) as client:
            for sub, cname, suffix in candidates:
                body = ''
                for scheme in ('https', 'http'):
                    try:
                        r = await client.get(f'{scheme}://{sub}/')
                        body = (r.text or '')[:4000]
                        break
                    except httpx.HTTPError:
                        continue
                if _FINGERPRINTS[suffix].search(body):
                    findings.append(RawFinding(
                        title=f'Subdomain takeover confirmé : {sub} → {suffix}',
                        severity=FindingSeverity.critical.value,
                        description='Le CNAME pointe vers un service désaffecté dont la page renvoie la '
                                    'signature "non réclamé" — un attaquant peut enregistrer la ressource '
                                    'et servir du contenu sous ce sous-domaine.',
                        evidence=f'{sub} → {cname} · fingerprint "{suffix}" trouvée',
                        recommendation='Supprimer l\'enregistrement CNAME orphelin ou réclamer la ressource '
                                       'chez le provider immédiatement.',
                        fingerprint_seed=f'takeover-confirmed|{sub}',
                    ))
                else:
                    findings.append(RawFinding(
                        title=f'CNAME vers service à risque (à vérifier) : {sub} → {suffix}',
                        severity=FindingSeverity.low.value,
                        description='Le CNAME pointe vers un provider sujet au takeover, sans signature '
                                    '"non réclamé" à l\'instant T. À surveiller si la ressource est déprovisionnée.',
                        evidence=f'{sub} → {cname}',
                        fingerprint_seed=f'takeover-candidate|{sub}',
                    ))
        return findings


register(TakeoverPlugin())
