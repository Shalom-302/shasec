import asyncio
from urllib.parse import urlsplit, urlunsplit

import httpx

_LOCATIONS = (
    '/openapi.json', '/api/v1/openapi', '/openapi', '/v1/openapi.json',
    '/swagger.json', '/api-docs', '/v3/api-docs',
)


def origin(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, '', '', ''))


def fill_path(path: str) -> str:
    import re
    path = re.sub(r'\{[^}]+\}', '1', path)
    path = re.sub(r':[A-Za-z_][A-Za-z0-9_]*', '1', path)
    return path


async def fetch_spec(client: httpx.AsyncClient, origin_url: str):
    """Resilient OpenAPI fetch (retries on throttle), shared by exploit modules."""
    for loc in _LOCATIONS:
        for attempt in range(3):
            try:
                resp = await client.get(f'{origin_url}{loc}')
            except httpx.HTTPError:
                await asyncio.sleep(2 * (attempt + 1))
                continue
            if resp.status_code in (429, 503):
                await asyncio.sleep(2 * (attempt + 1))
                continue
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError:
                    break
                if isinstance(data, dict) and ('paths' in data or 'openapi' in data or 'swagger' in data):
                    return data
            break
    return None


def get_endpoints(spec: dict, methods=('get',)):
    """Yield (path, method, operation) for the given HTTP methods."""
    for path, item in (spec.get('paths') or {}).items():
        if not isinstance(item, dict):
            continue
        for method in methods:
            op = item.get(method)
            if isinstance(op, dict):
                yield path, method, op


def query_params(op: dict) -> list[str]:
    return [
        p['name']
        for p in op.get('parameters', []) or []
        if isinstance(p, dict) and p.get('in') == 'query' and p.get('name')
    ]


def requires_auth(op: dict, global_security: bool) -> bool:
    return len(op['security']) > 0 if 'security' in op else global_security
