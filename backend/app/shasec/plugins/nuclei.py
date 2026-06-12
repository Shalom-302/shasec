import json
import shutil

from backend.app.shasec.plugins import register
from backend.app.shasec.plugins.base import RawFinding, ScanContext, ScannerPlugin, run_command
from backend.common.enums import FindingSeverity

_SEV_MAP = {
    'critical': FindingSeverity.critical.value,
    'high': FindingSeverity.high.value,
    'medium': FindingSeverity.medium.value,
    'low': FindingSeverity.low.value,
    'info': FindingSeverity.info.value,
    'unknown': FindingSeverity.info.value,
}


class NucleiPlugin(ScannerPlugin):
    """ProjectDiscovery nuclei adapter (CVEs / templates / known vulns).

    Requires the ``nuclei`` binary in the image. When it is absent the plugin
    skips cleanly with an info finding instead of failing the whole scan, so the
    contract is honored even before the binary is provisioned.
    """

    name = 'nuclei'
    handles = ('website', 'api', 'graphql', 'host')
    timeout = 600

    async def run(self, ctx: ScanContext) -> list[RawFinding]:
        if shutil.which('nuclei') is None:
            return [
                RawFinding(
                    title='nuclei not installed',
                    severity=FindingSeverity.info.value,
                    description='The nuclei binary is unavailable in this environment; plugin skipped.',
                    recommendation='Install nuclei in the API image (Dockerfile) to enable template/CVE scanning.',
                    fingerprint_seed='nuclei-missing',
                )
            ]

        code, out, err = await run_command(
            ['nuclei', '-u', ctx.target_url, '-jsonl', '-silent', '-no-color'],
            timeout=self.timeout,
        )

        findings: list[RawFinding] = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = ev.get('info', {}) if isinstance(ev.get('info'), dict) else {}
            sev = _SEV_MAP.get((info.get('severity') or 'info').lower(), FindingSeverity.info.value)
            findings.append(
                RawFinding(
                    title=info.get('name') or ev.get('template-id') or 'nuclei finding',
                    severity=sev,
                    description=info.get('description'),
                    evidence=ev.get('matched-at') or ev.get('host'),
                    recommendation=info.get('remediation'),
                    fingerprint_seed=f"{ev.get('template-id')}|{ev.get('matched-at')}",
                )
            )
        return findings


register(NucleiPlugin())
