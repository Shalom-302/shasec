"""nmap — controlled port/service/version discovery (manual Phase 3).

Deliberately conservative, per the manual's "éviter les scans agressifs" rule:
 - ``-sT``  TCP connect scan — needs no root, safe inside the container;
 - ``-T3``  polite timing (no ``-T4/-T5`` flooding), overridable via options;
 - ``--top-ports 1000``  the common surface, not a full 65k sweep;
 - ``-sV --version-light``  service/version detection without intrusive probes;
 - no ``-A``, no default NSE scripts — nothing that writes or exploits.

Parses nmap's XML (``-oX -``) so the output is robust. Skips cleanly with an info
finding when the binary is absent, like every other external scanner.
"""
import shutil
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

from backend.app.shasec.plugins import register
from backend.app.shasec.plugins.base import RawFinding, ScanContext, ScannerPlugin, run_command
from backend.common.enums import FindingSeverity

# Services that are notable when reachable from outside — flagged low so the
# pentester verifies exposure/scope (never concluded "vulnerable" from a port).
_SENSITIVE_SERVICES = {
    'ftp': 21, 'telnet': 23, 'smtp': 25, 'rpcbind': 111, 'microsoft-ds': 445,
    'netbios-ssn': 139, 'ms-sql-s': 1433, 'mysql': 3306, 'rdp': 3389,
    'ms-wbt-server': 3389, 'postgresql': 5432, 'redis': 6379, 'mongodb': 27017,
    'elasticsearch': 9200, 'memcached': 11211, 'vnc': 5900, 'ldap': 389,
    'docker': 2375, 'kubernetes': 6443,
}


def _host_of(target_url: str) -> str:
    parsed = urlsplit(target_url if '://' in target_url else f'//{target_url}')
    return (parsed.hostname or target_url).strip().rstrip('.')


class NmapPlugin(ScannerPlugin):
    name = 'nmap'
    handles = ('host', 'website', 'api', 'graphql')
    timeout = 600

    async def run(self, ctx: ScanContext) -> list[RawFinding]:
        host = _host_of(ctx.target_url)
        if not host:
            return [RawFinding(title='nmap: cible sans hôte', severity=FindingSeverity.info.value,
                               fingerprint_seed='nmap-nohost')]

        if shutil.which('nmap') is None:
            return [RawFinding(
                title='nmap not installed',
                severity=FindingSeverity.info.value,
                description='The nmap binary is unavailable in this environment; plugin skipped.',
                recommendation='Install nmap in the API image (Dockerfile) to enable port/service discovery.',
                fingerprint_seed='nmap-missing',
            )]

        timing = str(ctx.options.get('nmap_timing', 'T3'))
        top_ports = str(ctx.options.get('nmap_top_ports', 1000))
        _, out, _ = await run_command(
            ['nmap', '-Pn', '-sT', f'-{timing}', '--top-ports', top_ports,
             '-sV', '--version-light', '-oX', '-', host],
            timeout=self.timeout,
        )

        ports = self._parse_xml(out)
        if not ports:
            return [RawFinding(
                title=f'nmap : aucun port ouvert détecté sur {host}',
                severity=FindingSeverity.info.value,
                description='Aucun des ports scannés n\'est ouvert (ou l\'hôte filtre le trafic).',
                fingerprint_seed='nmap-noports',
            )]

        listing = '\n'.join(
            f"{p['port']}/{p['proto']:3} {p['service']:16} {p['product']} {p['version']}".rstrip()
            for p in ports
        )
        findings = [RawFinding(
            title=f"Surface réseau : {len(ports)} port(s) ouvert(s) sur {host}",
            severity=FindingSeverity.info.value,
            description='Ports/services/versions (nmap, profil prudent). Rappel manuel : une version '
                        'détectée ne prouve pas une vulnérabilité — vérifier produit, version et contexte.',
            evidence=listing[:2000],
            fingerprint_seed='nmap-ports',
        )]
        for p in ports:
            svc = p['service']
            if svc in _SENSITIVE_SERVICES or p['port'] in _SENSITIVE_SERVICES.values():
                findings.append(RawFinding(
                    title=f"Service sensible exposé : {svc or 'inconnu'} sur {p['port']}/{p['proto']}",
                    severity=FindingSeverity.low.value,
                    description='Service d\'administration/données joignable depuis l\'extérieur — à vérifier '
                                '(faut-il vraiment qu\'il soit exposé ? auth, filtrage réseau).',
                    evidence=f"{host}:{p['port']} {p['product']} {p['version']}".strip(),
                    recommendation='Restreindre l\'accès (pare-feu / VPN) si l\'exposition n\'est pas nécessaire.',
                    fingerprint_seed=f"nmap-sensitive|{p['port']}|{svc}",
                ))
        return findings

    @staticmethod
    def _parse_xml(xml: str) -> list[dict]:
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return []
        ports: list[dict] = []
        for port in root.iterfind('.//port'):
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue
            svc = port.find('service')
            ports.append({
                'port': int(port.get('portid', 0)),
                'proto': port.get('protocol', 'tcp'),
                'service': (svc.get('name') if svc is not None else '') or '',
                'product': (svc.get('product') if svc is not None else '') or '',
                'version': (svc.get('version') if svc is not None else '') or '',
            })
        return ports


register(NmapPlugin())
