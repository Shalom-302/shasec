import asyncio
import re
from urllib.parse import urlsplit, urlunsplit

import httpx

from backend.app.shasec.verifier import register
from backend.app.shasec.verifier.base import ExploitContext, ExploitModule, ExploitResult
from backend.common.enums import FindingSeverity
from backend.common.log import log

_OPENAPI_LOCATIONS = (
    '/openapi.json', '/api/v1/openapi', '/openapi', '/v1/openapi.json',
    '/swagger.json', '/api-docs', '/v3/api-docs',
)
# A leaked secret is a JSON *key* named like a credential whose *value* is an
# actual secret — NOT any occurrence of the word in the body. The old substring
# match fired on Prometheus metric text and the "Email & Password" UI label
# (false positives). We now parse JSON and inspect key→value pairs structurally.
_SENSITIVE_KEY_RE = re.compile(
    r'^(password|passwd|pwd|secret|client_secret|token|access_token|refresh_token|'
    r'id_token|api_?key|private_?key|aws_secret_access_key|ssn|credit_card|card_number)$',
    re.I,
)
# Values that are obviously placeholders / schema examples, not real secrets.
_PLACEHOLDER_VALUES = {
    'string', 'password', 'changeme', 'none', 'null', 'example', 'redacted',
    'your-secret', 'your-token', '<token>', '***', 'xxxxxxxx',
}


def _looks_like_secret(value) -> bool:
    """A real secret value: a non-trivial string with no spaces (labels/sentences
    contain spaces; secrets/tokens/hashes do not)."""
    if not isinstance(value, str):
        return False
    s = value.strip()
    if len(s) < 8 or ' ' in s:
        return False
    return s.lower() not in _PLACEHOLDER_VALUES


def _find_leaked_secrets(obj, path: str = '', _depth: int = 0) -> list[str]:
    """Walk a parsed JSON body; return dotted paths of sensitive keys that hold a
    real secret value. Bounded depth/breadth so a huge body can't stall us."""
    if _depth > 6:
        return []
    found: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            kp = f'{path}.{k}' if path else str(k)
            if isinstance(k, str) and _SENSITIVE_KEY_RE.match(k.replace('-', '_')) and _looks_like_secret(v):
                found.append(kp)
            found.extend(_find_leaked_secrets(v, kp, _depth + 1))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:50]):
            found.extend(_find_leaked_secrets(v, f'{path}[{i}]', _depth + 1))
    return found
# Path patterns that should almost never be reachable unauthenticated. Catches
# the most common real-world case: a dev forgot to add an auth dependency, so the
# OpenAPI declares no security yet the endpoint exposes internal/admin data.
_SENSITIVE_PATH = re.compile(
    r'(log|admin|internal|debug|config|setting|secret|token|\bkey|backup|dump|'
    r'database|/db|sql|queue|\bjob|scheduler|worker|user|account|metric|\benv|'
    r'credential|private|management|monitor)',
    re.I,
)
_MAX_ENDPOINTS = 80


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, '', '', ''))


def _fill_path(path: str) -> str:
    # Replace {id}, {pk}, :id etc. with a benign probe value.
    path = re.sub(r'\{[^}]+\}', '1', path)
    path = re.sub(r':[A-Za-z_][A-Za-z0-9_]*', '1', path)
    return path


class ApiAuthMatrixModule(ExploitModule):
    """Enumerate the API from its OpenAPI spec and prove broken authentication:
    endpoints that declare a security requirement yet answer 200 without a token.
    """

    name = 'api-auth-matrix'
    category = 'auth-bypass'
    handles = ('api', 'website', 'graphql')
    timeout = 120

    async def run(self, ctx: ExploitContext) -> list[ExploitResult]:
        origin = _origin(ctx.target_url)
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            spec = await self._fetch_spec(client, origin)
            if not spec:
                return []

            global_security = bool(spec.get('security'))
            results: list[ExploitResult] = []
            probed = 0

            for path, item in (spec.get('paths') or {}).items():
                if not isinstance(item, dict):
                    continue
                get_op = item.get('get')
                if not isinstance(get_op, dict):
                    continue  # only probe safe GET methods
                if probed >= _MAX_ENDPOINTS:
                    break
                probed += 1

                requires_auth = (
                    len(get_op['security']) > 0 if 'security' in get_op else global_security
                )
                url = f'{origin}{_fill_path(path)}'
                try:
                    resp = await client.get(url)  # deliberately no Authorization header
                except httpx.HTTPError:
                    continue
                log.info(f'[exploit:auth-matrix] scan {ctx.scan_id} GET {url} -> {resp.status_code} (auth_req={requires_auth})')

                if resp.status_code == 200:
                    body = resp.text[:400]
                    if requires_auth:
                        # The spec declares this endpoint protected, yet it answers
                        # without a token — a confirmed authentication bypass.
                        results.append(
                            ExploitResult(
                                category='auth-bypass',
                                title=f'Broken authentication: {path} reachable without a token',
                                severity=FindingSeverity.high.value,
                                confirmed=True,
                                impact='A protected endpoint returns data with no credentials.',
                                request=f'GET {url}\n(no Authorization header)',
                                response=f'HTTP 200\n{body}',
                            )
                        )
                    elif _SENSITIVE_PATH.search(path):
                        # Spec declares NO auth, but the path looks internal/admin.
                        # The most common real bug: a missing auth dependency.
                        results.append(
                            ExploitResult(
                                category='missing-auth',
                                title=f'Sensitive endpoint exposed without authentication: {path}',
                                severity=FindingSeverity.medium.value,
                                confirmed=True,
                                impact='An internal/administrative endpoint is reachable with no credentials '
                                       '(likely a missing auth dependency, not declared in the OpenAPI spec).',
                                request=f'GET {url}\n(no Authorization header)',
                                response=f'HTTP 200\n{body}',
                            )
                        )

                    # excessive-data: only JSON bodies, and only when a sensitive
                    # KEY carries a real secret VALUE (kills the Prometheus / UI-label
                    # false positives that fired on a bare substring match).
                    try:
                        parsed = resp.json()
                    except ValueError:
                        parsed = None
                    leaked = _find_leaked_secrets(parsed) if parsed is not None else []
                    if leaked:
                        results.append(
                            ExploitResult(
                                category='excessive-data',
                                title=f'Secret-bearing fields exposed without auth at {path}',
                                severity=FindingSeverity.high.value,
                                confirmed=True,
                                impact=f'Response exposes secret value(s) at: {", ".join(leaked[:8])}',
                                request=f'GET {url}',
                                response=f'HTTP 200\n{body}',
                            )
                        )
            return results

    @staticmethod
    async def _fetch_spec(client: httpx.AsyncClient, origin: str):
        # Resilient: the exploit stage runs after the noisy scanners, so the
        # target may be transiently rate-limiting. Retry each location with
        # backoff on throttle/transport errors before giving up.
        for loc in _OPENAPI_LOCATIONS:
            for attempt in range(3):
                try:
                    resp = await client.get(f'{origin}{loc}')
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
                break  # other status (404 etc.): move to next location
        return None


register(ApiAuthMatrixModule())
