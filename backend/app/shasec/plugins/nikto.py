import csv
import os
import shutil

from backend.app.shasec.plugins import register
from backend.app.shasec.plugins.base import RawFinding, ScanContext, ScannerPlugin, run_command
from backend.common.enums import FindingSeverity


class NiktoPlugin(ScannerPlugin):
    """Nikto web-server scanner adapter (server config, dated software, exposures).

    Subprocess wrapper. Skips cleanly with an info finding when the binary is
    absent, so the contract holds even before nikto is provisioned in the image.
    """

    name = 'nikto'
    handles = ('website', 'api')
    timeout = 180

    async def run(self, ctx: ScanContext) -> list[RawFinding]:
        if shutil.which('nikto') is None:
            return [
                RawFinding(
                    title='nikto not installed',
                    severity=FindingSeverity.info.value,
                    description='The nikto binary is unavailable in this environment; plugin skipped.',
                    recommendation='Install nikto in the API image (Dockerfile) to enable server scanning.',
                    fingerprint_seed='nikto-missing',
                )
            ]

        # CSV (not JSON): nikto only finalizes its JSON report at the very end, so
        # `-maxtime` truncates it into invalid JSON. CSV is written line-by-line and
        # stays valid even when the scan is time-capped.
        out_path = f'/tmp/nikto_{ctx.scan_id}.csv'
        try:
            await run_command(
                [
                    'nikto', '-h', ctx.target_url,
                    '-Format', 'csv', '-o', out_path,
                    '-maxtime', '120s', '-nointeractive', '-ask', 'no',
                ],
                timeout=self.timeout,
            )
            findings = self._parse_csv(out_path)
        finally:
            if os.path.exists(out_path):
                os.remove(out_path)

        return findings

    @staticmethod
    def _parse_csv(path: str) -> list[RawFinding]:
        # Row layout: host, ip, port, reference_url, method, uri, description.
        # The banner row has an empty method; the title line isn't a 7-col row.
        if not os.path.exists(path):
            return [
                RawFinding(
                    title='nikto produced no output',
                    severity=FindingSeverity.info.value,
                    description='nikto ran but wrote no report file.',
                    fingerprint_seed='nikto-empty',
                )
            ]
        findings: list[RawFinding] = []
        try:
            with open(path, newline='', encoding='utf-8', errors='replace') as fh:
                for row in csv.reader(fh):
                    if len(row) < 7:
                        continue
                    ref, method, uri, msg = row[3], row[4], row[5], row[6]
                    if not msg or not method:  # skip banner / non-finding rows
                        continue
                    findings.append(
                        RawFinding(
                            title=msg[:480],
                            severity=FindingSeverity.low.value,
                            description='Reported by nikto.' + (f' Reference: {ref}' if ref else ''),
                            evidence=f'{method} {uri}'.strip(),
                            fingerprint_seed=f'nikto|{uri}|{msg[:60]}',
                        )
                    )
        except OSError:
            pass
        return findings or [
            RawFinding(
                title='nikto: no issues reported',
                severity=FindingSeverity.info.value,
                fingerprint_seed='nikto-clean',
            )
        ]


register(NiktoPlugin())
