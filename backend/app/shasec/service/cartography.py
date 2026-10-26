"""Step 1 of a domain audit — cartography (passive mapping only).

Enumerates the target domain's own subdomains (subfinder + crt.sh certificate
transparency + a curated prefix list), resolves each one, and sends a single
light HTTP probe to tell a live host from a dead name and a frontend from an API.
It NEVER attacks: no fuzzing, no payloads. Hosts delegated to a third-party SaaS
(CNAME to shopify, zendesk, github.io…) are flagged ``third_party`` and never
pre-selected, because they are not the operator's to test.

Output is a list of ``ScanAsset`` dicts the orchestrator persists; the operator
then ticks which live hosts are in scope before steps 2-4 run.
"""
import asyncio
import ipaddress
import re
import shutil
from urllib.parse import urlsplit

import httpx

from backend.app.shasec.plugins.base import run_command
from backend.common.log import log

_MAX_HOSTS = 60
_CONCURRENCY = 8
_HTTP_TIMEOUT = 6.0

_COMMON_PREFIXES = (
    'www', 'api', 'api-v1', 'api-v2', 'app', 'admin', 'portal', 'dashboard',
    'dev', 'staging', 'stage', 'test', 'uat', 'preprod', 'qa', 'sandbox', 'demo',
    'beta', 'docs', 'doc', 'swagger', 'status', 'auth', 'login', 'sso', 'id',
    'gateway', 'gw', 'backend', 'back', 'internal', 'intranet', 'vpn', 'git',
    'jenkins', 'ci', 'grafana', 'kibana', 'cdn', 'assets', 'static', 'media',
    'mail', 'smtp', 'ftp', 'blog', 'shop', 'store', 'support', 'help', 'm',
)

# CNAME suffixes that mean "this host lives at a third-party provider". Attacking
# it would hit someone else's infrastructure — out of scope by default.
_THIRD_PARTY = {
    'github.io': 'GitHub Pages', 'herokuapp.com': 'Heroku', 's3.amazonaws.com': 'AWS S3',
    's3-website': 'AWS S3', 'cloudfront.net': 'AWS CloudFront', 'netlify.app': 'Netlify',
    'netlify.com': 'Netlify', 'vercel.app': 'Vercel', 'fastly.net': 'Fastly',
    'wordpress.com': 'WordPress.com', 'pantheonsite.io': 'Pantheon', 'readthedocs.io': 'Read the Docs',
    'ghost.io': 'Ghost', 'surge.sh': 'Surge', 'bitbucket.io': 'Bitbucket', 'azurewebsites.net': 'Azure',
    'myshopify.com': 'Shopify', 'zendesk.com': 'Zendesk', 'statuspage.io': 'Statuspage',
    'tumblr.com': 'Tumblr', 'cloudflare.net': 'Cloudflare', 'fastly-edge.com': 'Fastly',
    'googlehosted.com': 'Google', 'sendgrid.net': 'SendGrid', 'cname.vercel-dns.com': 'Vercel',
}

_API_NAME = re.compile(r'^(api|apis|backend|back|gw|gateway|rest|graphql|gql|service|svc|ms|core|auth|sso|id)\b', re.I)


def _host_of(target_url: str) -> str:
    parsed = urlsplit(target_url if '://' in target_url else f'//{target_url}')
    return (parsed.hostname or target_url).strip().rstrip('.')


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


async def _subfinder(host: str) -> set[str]:
    if shutil.which('subfinder') is None:
        return set()
    try:
        _, out, _ = await run_command(['subfinder', '-d', host, '-silent', '-all'], timeout=180)
        return {ln.strip().rstrip('.') for ln in out.splitlines() if ln.strip()}
    except Exception as exc:  # noqa: BLE001
        log.warning(f'cartography subfinder failed for {host}: {exc}')
        return set()


async def _crtsh(host: str) -> set[str]:
    """Certificate-transparency passive enumeration — no packets to the target."""
    try:
        async with httpx.AsyncClient(timeout=40, verify=False) as client:
            r = await client.get(f'https://crt.sh/?q=%25.{host}&output=json')
            if r.status_code != 200:
                return set()
            names: set[str] = set()
            for row in r.json():
                for n in (row.get('name_value') or '').splitlines():
                    n = n.strip().lstrip('*.').rstrip('.').lower()
                    if n.endswith(host) and '@' not in n:
                        names.add(n)
            return names
    except Exception as exc:  # noqa: BLE001
        log.warning(f'cartography crt.sh failed for {host}: {exc}')
        return set()


async def _resolve(host: str) -> tuple[list[str], str | None]:
    """Return (ips, cname) using the stdlib resolver, dig for the CNAME when present."""
    ips: list[str] = []
    cname: str | None = None
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None)
        ips = sorted({str(i[4][0]) for i in infos})
    except Exception:  # noqa: BLE001
        pass
    if shutil.which('dig'):
        try:
            _, out, _ = await run_command(['dig', '+short', 'CNAME', host], timeout=8)
            line = out.strip().splitlines()
            if line:
                cname = line[0].strip().rstrip('.')
        except Exception:  # noqa: BLE001
            pass
    return ips, cname


def _third_party_of(cname: str | None) -> str | None:
    if not cname:
        return None
    for suffix, name in _THIRD_PARTY.items():
        if suffix in cname:
            return name
    return None


async def _probe(client: httpx.AsyncClient, host: str) -> dict:
    """One light GET. Fills alive / url / http_status / server / title / kind."""
    out = {'alive': False, 'url': None, 'http_status': None, 'server': None, 'title': None,
           'kind': 'api' if _API_NAME.search(host.split('.')[0]) else 'website'}
    resp = None
    base = None
    for scheme in ('https', 'http'):
        try:
            resp = await client.get(f'{scheme}://{host}/')
            base = f'{scheme}://{host}'
            break
        except httpx.HTTPError:
            continue
    if base is None:
        return out
    out['alive'] = True
    out['url'] = base
    out['http_status'] = resp.status_code
    out['server'] = (resp.headers.get('server') or '')[:120] or None
    ctype = resp.headers.get('content-type', '').lower()
    body = resp.text[:2000] if resp.content else ''
    if 'json' in ctype or body.lstrip()[:1] in '{[':
        out['kind'] = 'api'
    elif 'html' in ctype:
        out['kind'] = 'website'
        m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
        if m:
            out['title'] = m.group(1).strip()[:120]
    return out


async def map_domain(target_url: str) -> list[dict]:
    """Run cartography and return ScanAsset-shaped dicts (one per discovered host)."""
    root = _host_of(target_url)
    if not root or _is_ip(root):
        # No domain to enumerate: the single root host is the whole surface.
        return [{'host': root or target_url, 'source': 'root', 'kind': 'website', 'selected': True}]

    subs = {root}
    sf, crt = await asyncio.gather(_subfinder(root), _crtsh(root))
    subs |= {s for s in sf if s.endswith(root)}
    subs |= {s for s in crt if s.endswith(root)}
    subs |= {f'{p}.{root}' for p in _COMMON_PREFIXES}

    hosts = sorted(subs)[:_MAX_HOSTS]
    source = {h: ('root' if h == root else 'subfinder' if h in sf else 'crt.sh' if h in crt else 'wordlist') for h in hosts}

    sem = asyncio.Semaphore(_CONCURRENCY)
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=True, verify=False) as client:
        async def one(h: str) -> dict | None:
            async with sem:
                ips, cname = await _resolve(h)
                # Skip names that neither resolve nor point anywhere — dead entries.
                if not ips and not cname:
                    return None
                probe = await _probe(client, h)
                tp = _third_party_of(cname)
                return {
                    'host': h, 'source': source[h], 'ips': ','.join(ips)[:255] or None,
                    'cname': (cname or None), 'third_party': tp, **probe,
                    # Auto-select only our own live hosts; a human still confirms.
                    'selected': bool(probe['alive'] and not tp),
                }
        results = await asyncio.gather(*[one(h) for h in hosts], return_exceptions=True)

    assets = [r for r in results if isinstance(r, dict)]
    # Live first, then by host name; guarantee the root is present.
    assets.sort(key=lambda a: (not a['alive'], bool(a['third_party']), a['host']))
    if not any(a['host'] == root for a in assets):
        assets.insert(0, {'host': root, 'source': 'root', 'kind': 'website', 'alive': False, 'selected': False})
    return assets
