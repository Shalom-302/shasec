"""WhatWeb — technology fingerprinting (manual Phase 4).

Identifies the web stack (server, framework, CMS, JS libs, headers) so later
phases know what they are testing. Read-only. Skips cleanly with an info finding
when the binary is absent. Per the manual: a detected version is a lead, never a
conclusion — never report "vulnerable" from a banner alone.
"""
import json
import os
import shutil

from backend.app.shasec.plugins import register
from backend.app.shasec.plugins.base import RawFinding, ScanContext, ScannerPlugin, run_command
from backend.common.enums import FindingSeverity


class WhatWebPlugin(ScannerPlugin):
    name = 'whatweb'
    handles = ('website', 'api', 'graphql')
    timeout = 120

    async def run(self, ctx: ScanContext) -> list[RawFinding]:
        if shutil.which('whatweb') is None:
            return [RawFinding(
                title='whatweb not installed',
                severity=FindingSeverity.info.value,
                description='WhatWeb unavailable in this environment; plugin skipped.',
                recommendation='Install whatweb in the API image (Dockerfile) to enable fingerprinting.',
                fingerprint_seed='whatweb-missing',
            )]

        out_path = f'/tmp/whatweb_{ctx.scan_id}.json'
        try:
            # -a 3 = aggressive-enough for versions but no intrusive probes; JSON to file.
            await run_command(
                ['whatweb', '--color=never', '--no-errors', '-a', '3',
                 f'--log-json={out_path}', ctx.target_url],
                timeout=self.timeout,
            )
            plugins = self._parse(out_path)
        finally:
            if os.path.exists(out_path):
                os.remove(out_path)

        if not plugins:
            return [RawFinding(title='whatweb: aucune empreinte', severity=FindingSeverity.info.value,
                               fingerprint_seed='whatweb-empty')]

        labelled = [f'{name}{" " + ver if ver else ""}' for name, ver in plugins]
        findings = [RawFinding(
            title=f'Empreinte technologique : {", ".join(labelled[:14])}'
                  + (f' … (+{len(labelled) - 14})' if len(labelled) > 14 else ''),
            severity=FindingSeverity.info.value,
            description='Pile technique identifiée par WhatWeb (fingerprinting) — oriente les tests suivants. '
                        'Rappel manuel : une version n\'est pas une preuve de vulnérabilité.',
            evidence='\n'.join(labelled),
            fingerprint_seed='whatweb-stack',
        )]
        # A disclosed version number widens the fingerprint — flag low for review.
        versioned = [f'{n} {v}' for n, v in plugins if v]
        if versioned:
            findings.append(RawFinding(
                title=f'Versions logicielles divulguées : {len(versioned)}',
                severity=FindingSeverity.low.value,
                description='Des composants exposent leur numéro de version — facilite la corrélation CVE.',
                evidence='\n'.join(versioned[:20]),
                recommendation='Masquer/génériciser les bannières et en-têtes de version quand c\'est possible.',
                fingerprint_seed='whatweb-versions',
            ))
        return findings

    @staticmethod
    def _parse(path: str) -> list[tuple[str, str]]:
        if not os.path.exists(path):
            return []
        try:
            with open(path, encoding='utf-8', errors='replace') as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return []
        entries = data if isinstance(data, list) else [data]
        found: list[tuple[str, str]] = []
        seen: set[str] = set()
        for entry in entries:
            plugins = entry.get('plugins') if isinstance(entry, dict) else None
            if not isinstance(plugins, dict):
                continue
            for name, meta in plugins.items():
                if name in seen:
                    continue
                seen.add(name)
                ver = ''
                if isinstance(meta, dict):
                    v = meta.get('version')
                    if isinstance(v, list):
                        ver = ', '.join(str(x) for x in v)
                    elif v:
                        ver = str(v)
                found.append((name, ver))
        return found


register(WhatWebPlugin())
