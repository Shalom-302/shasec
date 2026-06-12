import json
import re
import shutil

from backend.app.shasec.plugins import register
from backend.app.shasec.plugins.base import RawFinding, ScanContext, ScannerPlugin, run_command
from backend.common.enums import FindingSeverity

# Discovered paths whose names hint at an interesting/sensitive surface.
_SENSITIVE = re.compile(
    r'(/admin|/config|/backup|/\.git|/\.env|/internal|/debug|/actuator|/swagger|'
    r'/api-docs|/\.well-known|/dump|/console|/metrics|/private|/secret)',
    re.I,
)


class KatanaPlugin(ScannerPlugin):
    """ProjectDiscovery katana (Go) — fast crawler that maps the attack surface
    (endpoints, JS, forms). Reports the discovered surface and flags sensitive
    paths. Skips cleanly when the binary is absent.
    """

    name = 'katana'
    handles = ('website', 'api', 'graphql')
    timeout = 150

    async def run(self, ctx: ScanContext) -> list[RawFinding]:
        if shutil.which('katana') is None:
            return [
                RawFinding(
                    title='katana not installed',
                    severity=FindingSeverity.info.value,
                    description='ProjectDiscovery katana unavailable; plugin skipped.',
                    recommendation='Bake the katana binary into the API image to enable crawling.',
                    fingerprint_seed='katana-missing',
                )
            ]

        _, out, _ = await run_command(
            ['katana', '-u', ctx.target_url, '-jsonl', '-silent', '-no-color',
             '-depth', '2', '-concurrency', '10', '-timeout', '10'],
            timeout=self.timeout,
        )
        endpoints: list[str] = []
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith('{'):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            ep = (obj.get('request') or {}).get('endpoint') or obj.get('endpoint')
            if ep:
                endpoints.append(ep)
            if len(endpoints) >= 500:
                break

        uniq = sorted(set(endpoints))
        if not uniq:
            return [RawFinding(title='katana: aucune surface découverte', severity=FindingSeverity.info.value,
                               fingerprint_seed='katana-empty')]

        sample = '\n'.join(uniq[:25]) + (f'\n… (+{len(uniq) - 25})' if len(uniq) > 25 else '')
        findings = [
            RawFinding(
                title=f"Surface d'attaque : {len(uniq)} endpoint(s) découvert(s) (crawl)",
                severity=FindingSeverity.info.value,
                description='Cartographie des endpoints par katana — autant d\'entrées à auditer.',
                evidence=sample,
                fingerprint_seed='katana-surface',
            )
        ]
        for ep in [e for e in uniq if _SENSITIVE.search(e)][:15]:
            findings.append(
                RawFinding(
                    title=f'Chemin sensible découvert : {ep}',
                    severity=FindingSeverity.low.value,
                    description='Endpoint au nom sensible trouvé au crawl — à vérifier (auth, exposition).',
                    evidence=ep,
                    fingerprint_seed=f'katana-sensitive|{ep}',
                )
            )
        return findings


register(KatanaPlugin())
