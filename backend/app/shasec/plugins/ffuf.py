"""ffuf — content / endpoint discovery by wordlist (manual Phase 5).

Brute-forces paths with a wordlist to surface undocumented endpoints katana's
link-crawl can't reach. Per the manual: run at a LOW rate and only within scope —
hence the capped rate/threads below. Skips cleanly when the binary or a wordlist
is absent.
"""
import json
import os
import re
import shutil

from backend.app.shasec.plugins import register
from backend.app.shasec.plugins.base import RawFinding, ScanContext, ScannerPlugin, run_command
from backend.common.enums import FindingSeverity

# First existing path wins. dirb's common.txt ships in the image (small, ~4.6k).
_WORDLISTS = (
    '/usr/share/dirb/wordlists/common.txt',
    '/usr/share/wordlists/dirb/common.txt',
    '/usr/share/seclists/Discovery/Web-Content/common.txt',
)

_SENSITIVE = re.compile(
    r'(admin|config|backup|\.git|\.env|internal|debug|actuator|swagger|'
    r'api-docs|\.well-known|dump|console|metrics|private|secret|phpinfo|'
    r'\.bak|\.old|\.sql|\.zip|\.tar)', re.I,
)


class FfufPlugin(ScannerPlugin):
    name = 'ffuf'
    handles = ('website', 'api', 'graphql')
    timeout = 300

    async def run(self, ctx: ScanContext) -> list[RawFinding]:
        if shutil.which('ffuf') is None:
            return [RawFinding(
                title='ffuf not installed',
                severity=FindingSeverity.info.value,
                description='ffuf unavailable in this environment; plugin skipped.',
                recommendation='Install ffuf + a wordlist (e.g. dirb) in the API image to enable content discovery.',
                fingerprint_seed='ffuf-missing',
            )]

        wordlist = next((w for w in _WORDLISTS if os.path.exists(w)), None)
        if not wordlist:
            return [RawFinding(
                title='ffuf: aucune wordlist disponible',
                severity=FindingSeverity.info.value,
                description='Le binaire ffuf est présent mais aucune wordlist n\'a été trouvée.',
                recommendation='Installer un paquet de wordlists (dirb/seclists) dans l\'image.',
                fingerprint_seed='ffuf-nowordlist',
            )]

        base = ctx.target_url.rstrip('/')
        out_path = f'/tmp/ffuf_{ctx.scan_id}.json'
        if os.path.exists(out_path):
            os.remove(out_path)
        try:
            # Low rate + capped threads (manual: "débit faible"). Match codes that
            # indicate a real resource (incl. auth-gated 401/403).
            await run_command(
                # -ac auto-calibrates: on a SPA that answers 200 to everything it
                # learns the "catch-all" response and filters it, so only genuinely
                # distinct paths are reported instead of the whole wordlist.
                ['ffuf', '-u', f'{base}/FUZZ', '-w', wordlist, '-ac',
                 '-mc', '200,204,301,302,307,401,403,405',
                 '-t', '20', '-rate', '50', '-timeout', '10',
                 '-of', 'json', '-o', out_path, '-s'],
                timeout=self.timeout,
            )
            results = self._parse(out_path)
        finally:
            if os.path.exists(out_path):
                os.remove(out_path)

        if not results:
            return [RawFinding(title='ffuf: aucun chemin découvert', severity=FindingSeverity.info.value,
                               fingerprint_seed='ffuf-empty')]

        sample = '\n'.join(f'{r["status"]:>3}  {r["url"]}' for r in results[:30])
        if len(results) > 30:
            sample += f'\n… (+{len(results) - 30})'
        findings = [RawFinding(
            title=f"Découverte de contenu : {len(results)} chemin(s) trouvé(s) (ffuf)",
            severity=FindingSeverity.info.value,
            description='Endpoints/chemins révélés par brute-force de wordlist — surface à auditer.',
            evidence=sample[:2000],
            fingerprint_seed='ffuf-content',
        )]
        for r in [x for x in results if _SENSITIVE.search(x['url'])][:20]:
            findings.append(RawFinding(
                title=f'Chemin sensible exposé : {r["url"]} ({r["status"]})',
                severity=FindingSeverity.low.value,
                description='Chemin au nom sensible accessible — à vérifier (exposition, auth, contenu).',
                evidence=f'{r["status"]} {r["url"]} · {r.get("length", "?")} octets',
                fingerprint_seed=f'ffuf-sensitive|{r["url"]}',
            ))
        return findings

    @staticmethod
    def _parse(path: str) -> list[dict]:
        if not os.path.exists(path):
            return []
        try:
            with open(path, encoding='utf-8', errors='replace') as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return []
        out: list[dict] = []
        for r in data.get('results', []) if isinstance(data, dict) else []:
            if not isinstance(r, dict):
                continue
            out.append({
                'url': r.get('url', ''),
                'status': r.get('status', 0),
                'length': r.get('length', 0),
            })
        return out


register(FfufPlugin())
