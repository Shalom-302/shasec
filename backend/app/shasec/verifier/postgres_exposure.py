"""postgres_exposure — is a PostgreSQL container reachable with default secrets?

Real-world scenario: a Postgres container published on 0.0.0.0:5432 with the
image's default / weak credentials. Only ever run against an authorized,
in-scope target (ExploitContext contract).

SAFE and bounded by design:
  * a **short, curated** default-credential list — NOT a brute force (no lockout,
    no DoS, professional low-footprint).
  * on a successful connect it runs **read-only, non-sensitive** proof queries
    only: server version + the list of database *names* (never table data, never
    rows). That is enough to prove access without exfiltrating anything.
  * one bounded connection attempt per credential, short timeout, hard cap.

A successful connect → critical, confirmed, with the exact credential as proof
and container-hardening remediation.
"""
from urllib.parse import urlsplit

from backend.app.shasec.verifier import register
from backend.app.shasec.verifier.base import ExploitContext, ExploitModule, ExploitResult
from backend.common.enums import FindingSeverity
from backend.common.log import log

try:
    import asyncpg
except ImportError:  # pragma: no cover - dep declared in pyproject
    asyncpg = None

_DEFAULT_PORT = 5432
_CONNECT_TIMEOUT = 5.0

# Curated default/weak pairs seen on unconfigured Postgres containers. Bounded on
# purpose — this is a default-credential check, not a brute force.
_CREDS = (
    ('postgres', 'postgres'),
    ('postgres', ''),
    ('postgres', 'admin'),
    ('postgres', 'password'),
    ('postgres', 'root'),
    ('postgres', 'changeme'),
    ('admin', 'admin'),
)
_PROBE_DBS = ('postgres', 'template1')

_REMEDIATION = (
    'Ne PAS publier le port : retirer `ports: ["5432:5432"]`, laisser Postgres sur le réseau Docker '
    'interne (accessible uniquement par les services applicatifs). Si un bind local est requis, '
    'utiliser `127.0.0.1:5432:5432`. Définir un mot de passe fort via secret Docker/env (jamais la '
    'valeur par défaut). Forcer `scram-sha-256` dans `pg_hba.conf` et supprimer toute règle `trust`. '
    'Restreindre les accès par host/CIDR. Vérifier avec `nmap -p5432 <host>` que le port n\'est plus exposé.'
)


class PostgresExposureModule(ExploitModule):
    name = 'postgres-exposure'
    category = 'exposed-service-default-creds'
    handles = ('host', 'website', 'api', 'graphql')
    timeout = 120

    async def run(self, ctx: ExploitContext) -> list[ExploitResult]:
        if asyncpg is None:
            log.warning('[exploit:postgres] asyncpg indisponible — module ignoré')
            return []

        hosts = ctx.options.get('pg_hosts') or [self._host_of(ctx.target_url)]
        hosts = [h for h in hosts if h]
        port = int(ctx.options.get('pg_port') or _DEFAULT_PORT)
        results: list[ExploitResult] = []

        for host in hosts:
            await self._test_host(host, port, results)
        return results

    @staticmethod
    def _host_of(target_url: str) -> str:
        p = urlsplit(target_url if '://' in target_url else f'//{target_url}')
        return (p.hostname or '').strip()

    async def _test_host(self, host: str, port: int, results: list[ExploitResult]) -> None:
        reachable = False
        for user, password in _CREDS:
            for db in _PROBE_DBS:
                conn = None
                try:
                    conn = await asyncpg.connect(
                        host=host, port=port, user=user, password=password,
                        database=db, timeout=_CONNECT_TIMEOUT,
                    )
                except (asyncpg.InvalidAuthorizationSpecificationError,
                        asyncpg.InvalidPasswordError):
                    reachable = True  # port answered Postgres → service IS exposed
                    continue
                except (OSError, asyncpg.PostgresError, Exception) as exc:  # noqa: BLE001
                    # connection refused / timeout / unknown db — try next.
                    if 'database' in str(exc).lower() and 'does not exist' in str(exc).lower():
                        reachable = True
                    continue

                # --- connected: read-only, non-sensitive proof only ---------------
                reachable = True
                try:
                    version = await conn.fetchval('SELECT version()')
                    dbnames = await conn.fetch('SELECT datname FROM pg_database WHERE datistemplate = false')
                    names = ', '.join(r['datname'] for r in dbnames)[:400]
                finally:
                    await conn.close()

                shown_pw = password if password else '(vide)'
                log.info(f'[exploit:postgres] ACCESS {host}:{port} as {user} (default cred)')
                results.append(ExploitResult(
                    category=self.category,
                    title=f'PostgreSQL accessible avec un identifiant par défaut : {host}:{port}',
                    severity=FindingSeverity.critical.value,
                    confirmed=True,
                    impact='Connexion réussie au conteneur PostgreSQL avec un identifiant par défaut/faible. '
                           'Accès complet aux bases de données (lecture/écriture selon le rôle). '
                           'Compromission directe des données.',
                    request=f'psql "postgresql://{user}:{shown_pw}@{host}:{port}/{db}"',
                    response=f'Connexion OK · {version} · bases: {names}\n\nRemédiation: {_REMEDIATION}',
                ))
                return  # one proof per host is enough

        if reachable:
            results.append(ExploitResult(
                category=self.category,
                title=f'Port PostgreSQL exposé publiquement : {host}:{port}',
                severity=FindingSeverity.medium.value,
                confirmed=True,
                impact='Le service PostgreSQL répond depuis l\'extérieur (le port est publié). Les identifiants '
                       'par défaut testés ont été rejetés, mais l\'exposition du port élargit la surface '
                       'd\'attaque (brute force ciblé, CVE du moteur).',
                request=f'TCP {host}:{port}',
                response=f'Le service répond au protocole PostgreSQL.\n\nRemédiation: {_REMEDIATION}',
            ))


register(PostgresExposureModule())
