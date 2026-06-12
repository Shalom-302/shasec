import json
import shutil

from backend.app.shasec.plugins import register
from backend.app.shasec.plugins.base import RawFinding, ScanContext, ScannerPlugin, run_command
from backend.common.enums import FindingSeverity


class HttpxPlugin(ScannerPlugin):
    """ProjectDiscovery httpx (Go) — fast HTTP probe + technology fingerprinting.

    Adds tech-stack recon on top of the pure-Python http-security checker. The
    binary is installed as ``httpx-pd`` to avoid clashing with the Python httpx
    CLI; the plugin skips cleanly when it is absent.
    """

    name = 'httpx'
    handles = ('website', 'api', 'graphql')
    timeout = 90

    async def run(self, ctx: ScanContext) -> list[RawFinding]:
        if shutil.which('httpx-pd') is None:
            return [
                RawFinding(
                    title='httpx not installed',
                    severity=FindingSeverity.info.value,
                    description='ProjectDiscovery httpx unavailable; plugin skipped.',
                    recommendation='Bake the httpx binary into the API image to enable tech fingerprinting.',
                    fingerprint_seed='httpx-missing',
                )
            ]

        _, out, _ = await run_command(
            ['httpx-pd', '-u', ctx.target_url, '-json', '-silent', '-no-color',
             '-tech-detect', '-title', '-status-code', '-web-server', '-follow-redirects'],
            timeout=self.timeout,
        )
        line = next((ln for ln in out.splitlines() if ln.strip().startswith('{')), '')
        if not line:
            return [RawFinding(title='httpx: no parsable output', severity=FindingSeverity.info.value,
                               fingerprint_seed='httpx-empty')]
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return [RawFinding(title='httpx: unparsable output', severity=FindingSeverity.info.value,
                               fingerprint_seed='httpx-badjson')]

        findings: list[RawFinding] = []
        tech = data.get('tech') or data.get('technologies') or []
        if tech:
            findings.append(
                RawFinding(
                    title=f'Technologies détectées : {", ".join(tech[:12])}',
                    severity=FindingSeverity.info.value,
                    description='Pile technique identifiée par httpx (fingerprinting) — oriente les attaques suivantes.',
                    evidence=f"{data.get('url', '')} -> {data.get('status_code', '')}",
                    fingerprint_seed='httpx-tech',
                )
            )
        server = data.get('webserver')
        title = data.get('title')
        if server or title:
            findings.append(
                RawFinding(
                    title=f"Identité du service{(' : ' + server) if server else ''}",
                    severity=FindingSeverity.info.value,
                    description=f"Titre: {title or '—'} · Serveur: {server or '—'} · Statut: {data.get('status_code', '')}",
                    evidence=data.get('url', ''),
                    fingerprint_seed='httpx-ident',
                )
            )
        return findings or [RawFinding(title='httpx: aucun signal', severity=FindingSeverity.info.value,
                                       fingerprint_seed='httpx-none')]


register(HttpxPlugin())
