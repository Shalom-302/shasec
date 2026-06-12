import asyncio
import os

import httpx

from backend.app.shasec.plugins import register
from backend.app.shasec.plugins.base import RawFinding, ScanContext, ScannerPlugin
from backend.common.enums import FindingSeverity

# ZAP risk label -> our severity
_RISK_MAP = {
    'High': FindingSeverity.high.value,
    'Medium': FindingSeverity.medium.value,
    'Low': FindingSeverity.low.value,
    'Informational': FindingSeverity.info.value,
}


class ZapPlugin(ScannerPlugin):
    """OWASP ZAP adapter — talks to ZAP's REST API (daemon mode).

    ZAP runs as a SEPARATE service (heavy Java app); enable it with
    ``docker compose --profile zap up``. This plugin is a thin API client:
    spider -> active scan -> pull alerts -> normalize. When ZAP is unreachable
    (service not started) it skips cleanly instead of failing the scan.
    """

    name = 'zap'
    handles = ('website', 'api', 'graphql')
    timeout = 1800  # active scans are slow

    @property
    def _base(self) -> str:
        return os.getenv('ZAP_ENDPOINT', 'http://monshaapi_zap:8090').rstrip('/')

    @property
    def _key(self) -> str:
        return os.getenv('ZAP_API_KEY', 'shasec-zap')

    async def run(self, ctx: ScanContext) -> list[RawFinding]:
        async with httpx.AsyncClient(timeout=30) as client:
            # Reachability probe — skip cleanly when the ZAP service is down.
            try:
                await client.get(f'{self._base}/JSON/core/view/version/', params={'apikey': self._key})
            except httpx.HTTPError:
                return [
                    RawFinding(
                        title='ZAP service not available',
                        severity=FindingSeverity.info.value,
                        description='OWASP ZAP daemon is unreachable; plugin skipped.',
                        recommendation="Start ZAP with `docker compose --profile zap up -d zap`.",
                        fingerprint_seed='zap-down',
                    )
                ]

            try:
                # Spider + passive scanning always run (crawl + observe — non-attacking).
                # The ACTIVE scan sends attack payloads and is slow, so it is opt-in via
                # ZAP_ACTIVE_SCAN=true to avoid hammering a production target by default.
                await self._spider(client, ctx.target_url)
                if os.getenv('ZAP_ACTIVE_SCAN', 'false').lower() == 'true':
                    await self._active_scan(client, ctx.target_url)
                alerts = await self._alerts(client, ctx.target_url)
            except httpx.HTTPError as exc:
                return [
                    RawFinding(
                        title='ZAP scan error',
                        severity=FindingSeverity.info.value,
                        description=f'ZAP API call failed: {exc}',
                        fingerprint_seed='zap-error',
                    )
                ]

        return self._normalize(alerts)

    async def _spider(self, client: httpx.AsyncClient, url: str) -> None:
        r = await client.get(f'{self._base}/JSON/spider/action/scan/', params={'apikey': self._key, 'url': url})
        scan_id = r.json().get('scan')
        await self._poll(client, '/JSON/spider/view/status/', {'scanId': scan_id}, deadline=300)

    async def _active_scan(self, client: httpx.AsyncClient, url: str) -> None:
        r = await client.get(f'{self._base}/JSON/ascan/action/scan/', params={'apikey': self._key, 'url': url})
        scan_id = r.json().get('scan')
        deadline = min(int(os.getenv('ZAP_MAX_SCAN_SECONDS', '600')), self.timeout - 120)
        await self._poll(client, '/JSON/ascan/view/status/', {'scanId': scan_id}, deadline=deadline)

    async def _poll(self, client: httpx.AsyncClient, path: str, params: dict, deadline: int) -> None:
        params = {'apikey': self._key, **params}
        waited = 0
        while waited < deadline:
            r = await client.get(f'{self._base}{path}', params=params)
            if str(r.json().get('status')) == '100':
                return
            await asyncio.sleep(3)
            waited += 3

    async def _alerts(self, client: httpx.AsyncClient, url: str) -> list[dict]:
        r = await client.get(
            f'{self._base}/JSON/core/view/alerts/',
            params={'apikey': self._key, 'baseurl': url},
        )
        return r.json().get('alerts', [])

    @staticmethod
    def _normalize(alerts: list[dict]) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for a in alerts:
            findings.append(
                RawFinding(
                    title=a.get('alert') or a.get('name') or 'ZAP alert',
                    severity=_RISK_MAP.get(a.get('risk', 'Informational'), FindingSeverity.info.value),
                    description=a.get('description'),
                    evidence=f"{a.get('method', '')} {a.get('url', '')}".strip() or a.get('param'),
                    recommendation=a.get('solution'),
                    fingerprint_seed=f"zap|{a.get('pluginId')}|{a.get('url')}|{a.get('param')}",
                )
            )
        return findings or [
            RawFinding(
                title='ZAP: no alerts',
                severity=FindingSeverity.info.value,
                fingerprint_seed='zap-clean',
            )
        ]


register(ZapPlugin())
