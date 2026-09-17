"""testssl.sh — TLS configuration analysis (manual Phase 4 / §2).

Probes the target's TLS: protocols, ciphers, certificate, known flaws (POODLE,
BEAST, Heartbleed, weak DH…). Read-only. Skips cleanly when the script is absent
or when the target has no TLS (e.g. a plaintext-HTTP lab like Juice Shop).
"""
import json
import os
import shutil
from urllib.parse import urlsplit

from backend.app.shasec.plugins import register
from backend.app.shasec.plugins.base import RawFinding, ScanContext, ScannerPlugin, run_command
from backend.common.enums import FindingSeverity

# testssl severity -> shasec severity. OK/INFO/DEBUG are dropped as noise.
_SEV_MAP = {
    'CRITICAL': FindingSeverity.critical.value,
    'HIGH': FindingSeverity.high.value,
    'MEDIUM': FindingSeverity.medium.value,
    'LOW': FindingSeverity.low.value,
    'WARN': FindingSeverity.low.value,
}


class TestsslPlugin(ScannerPlugin):
    name = 'testssl'
    handles = ('website', 'api', 'graphql', 'host')
    timeout = 600

    async def run(self, ctx: ScanContext) -> list[RawFinding]:
        if shutil.which('testssl.sh') is None:
            return [RawFinding(
                title='testssl.sh not installed',
                severity=FindingSeverity.info.value,
                description='testssl.sh unavailable in this environment; plugin skipped.',
                recommendation='Install testssl.sh in the API image (Dockerfile) to enable TLS analysis.',
                fingerprint_seed='testssl-missing',
            )]

        target = self._tls_target(ctx.target_url)
        if not target:
            return [RawFinding(title='testssl: cible sans hôte', severity=FindingSeverity.info.value,
                               fingerprint_seed='testssl-nohost')]

        out_path = f'/tmp/testssl_{ctx.scan_id}.json'
        if os.path.exists(out_path):
            os.remove(out_path)
        try:
            await run_command(
                ['testssl.sh', '--quiet', '--color', '0', '--severity', 'LOW',
                 '--jsonfile', out_path, target],
                timeout=self.timeout,
            )
            findings = self._parse(out_path, target)
        finally:
            if os.path.exists(out_path):
                os.remove(out_path)
        return findings

    @staticmethod
    def _tls_target(target_url: str) -> str:
        parsed = urlsplit(target_url if '://' in target_url else f'//{target_url}')
        host = parsed.hostname
        if not host:
            return ''
        port = parsed.port or (443 if parsed.scheme in ('https', '') else parsed.port)
        # No explicit port on an http:// URL: still try 443 (the TLS surface).
        return f'{host}:{port or 443}'

    @staticmethod
    def _parse(path: str, target: str) -> list[RawFinding]:
        if not os.path.exists(path):
            return [RawFinding(
                title=f'testssl : pas de service TLS exploitable sur {target}',
                severity=FindingSeverity.info.value,
                description='Aucun rapport produit — cible sans TLS ou injoignable en 443.',
                fingerprint_seed='testssl-notls',
            )]
        try:
            with open(path, encoding='utf-8', errors='replace') as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return [RawFinding(title='testssl: sortie illisible', severity=FindingSeverity.info.value,
                               fingerprint_seed='testssl-badjson')]

        entries = data if isinstance(data, list) else data.get('scanResult', [data])
        findings: list[RawFinding] = []
        for item in entries:
            if not isinstance(item, dict):
                continue
            sev = _SEV_MAP.get(str(item.get('severity', '')).upper())
            if not sev:
                continue
            fid = item.get('id', 'tls')
            findings.append(RawFinding(
                title=f'TLS · {fid}: {str(item.get("finding", ""))[:200]}',
                severity=sev,
                description='Relevé par testssl.sh (configuration TLS).',
                evidence=f'{target} · {fid}',
                recommendation='Corriger la configuration TLS (protocoles/ciphers/certificat) selon le détail.',
                fingerprint_seed=f'testssl|{fid}',
            ))
        return findings or [RawFinding(
            title=f'testssl : configuration TLS sans faiblesse notable sur {target}',
            severity=FindingSeverity.info.value,
            fingerprint_seed='testssl-clean',
        )]


register(TestsslPlugin())
