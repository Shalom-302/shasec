"""DNS / WHOIS reconnaissance — passive surface mapping (manual Phase 2).

Pure-Python baseline so it runs *everywhere* (like ``http-security``): A/AAAA
resolution always works via the stdlib resolver. When the ``dig`` and ``whois``
binaries are present it enriches the picture with the full record set and
registration data; when they are absent it degrades gracefully instead of
failing. Read-only and passive by design — it sends no application traffic, in
keeping with the manual's "recon passive" mandate.
"""
import asyncio
import ipaddress
import shutil
import socket
from urllib.parse import urlsplit

from backend.app.shasec.plugins import register
from backend.app.shasec.plugins.base import RawFinding, ScanContext, ScannerPlugin, run_command
from backend.common.enums import FindingSeverity

# DNS record types worth pulling for a surface map.
_DIG_TYPES = ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA')
# WHOIS fields we surface (lower-cased prefix match on the raw output).
_WHOIS_FIELDS = ('registrar', 'creation date', 'created', 'registry expiry date',
                 'expiry', 'expiration', 'name server', 'registrant organization', 'org')


def _host_of(target_url: str) -> str:
    """Extract a bare hostname from a URL or a raw host string."""
    parsed = urlsplit(target_url if '://' in target_url else f'//{target_url}')
    return (parsed.hostname or target_url).strip().rstrip('.')


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class DnsReconPlugin(ScannerPlugin):
    name = 'dns-recon'
    handles = ('host', 'website', 'api', 'graphql')
    timeout = 60

    async def run(self, ctx: ScanContext) -> list[RawFinding]:
        host = _host_of(ctx.target_url)
        if not host:
            return [RawFinding(title='dns-recon: cible sans hôte résoluble',
                               severity=FindingSeverity.info.value, fingerprint_seed='dns-nohost')]

        findings: list[RawFinding] = []

        # --- Baseline: stdlib resolution (always available) -------------------
        ips = await self._resolve(host)
        if ips:
            findings.append(RawFinding(
                title=f'Résolution DNS : {host} → {", ".join(ips[:8])}',
                severity=FindingSeverity.info.value,
                description='Adresses IP de la cible (recon passive) — point de départ de la surface.',
                evidence='\n'.join(ips),
                fingerprint_seed='dns-a',
            ))
        elif not _is_ip(host):
            findings.append(RawFinding(
                title=f'Résolution DNS impossible pour {host}',
                severity=FindingSeverity.info.value,
                description='Aucune adresse renvoyée par le résolveur — hôte inexistant ou hors ligne.',
                fingerprint_seed='dns-noresolve',
            ))

        # --- Enrichment: dig (full record set) --------------------------------
        if shutil.which('dig') and not _is_ip(host):
            records = await self._dig_records(host)
            if records:
                findings.append(RawFinding(
                    title=f'Enregistrements DNS de {host}',
                    severity=FindingSeverity.info.value,
                    description='Vue DNS complète (A/AAAA/CNAME/MX/NS/TXT/SOA) via dig.',
                    evidence=records[:2000],
                    fingerprint_seed='dns-records',
                ))

        # --- Enrichment: whois (registration data) ----------------------------
        if shutil.which('whois') and not _is_ip(host):
            info = await self._whois(host)
            if info:
                findings.append(RawFinding(
                    title=f'WHOIS : {host}',
                    severity=FindingSeverity.info.value,
                    description='Données d\'enregistrement publiques. Rappel manuel : une donnée '
                                'publique ne prouve pas le scope.',
                    evidence=info[:1500],
                    fingerprint_seed='dns-whois',
                ))

        return findings or [RawFinding(title='dns-recon: aucun signal', severity=FindingSeverity.info.value,
                                       fingerprint_seed='dns-none')]

    @staticmethod
    async def _resolve(host: str) -> list[str]:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.run_in_executor(None, socket.getaddrinfo, host, None)
        except (socket.gaierror, OSError, UnicodeError):
            return []
        return sorted({str(info[4][0]) for info in infos})

    async def _dig_records(self, host: str) -> str:
        lines: list[str] = []
        for rtype in _DIG_TYPES:
            try:
                _, out, _ = await run_command(['dig', '+short', rtype, host], timeout=10)
            except (TimeoutError, FileNotFoundError):
                continue
            for value in out.splitlines():
                value = value.strip()
                if value:
                    lines.append(f'{rtype:6} {value}')
        return '\n'.join(lines)

    async def _whois(self, host: str) -> str:
        try:
            _, out, _ = await run_command(['whois', host], timeout=20)
        except (TimeoutError, FileNotFoundError):
            return ''
        kept: list[str] = []
        seen: set[str] = set()
        for line in out.splitlines():
            low = line.strip().lower()
            if any(low.startswith(f) for f in _WHOIS_FIELDS):
                norm = line.strip()
                if norm not in seen:
                    seen.add(norm)
                    kept.append(norm)
        return '\n'.join(kept)


register(DnsReconPlugin())
