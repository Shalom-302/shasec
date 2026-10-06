"""minio_exposure — MinIO / S3 default credentials + anonymous bucket exposure.

Targets an S3-compatible object store (typically a `api-minio.*` host). Only ever
run against an authorized, in-scope target (ExploitContext contract).

Two high-signal, bounded checks — both non-destructive (read-only):
  * **Console default credentials** — MinIO's console login API accepts JSON
    {accessKey, secretKey}. A 2xx + session cookie with `minioadmin:minioadmin`
    (or other shipped defaults) proves full admin over the store → critical.
  * **Anonymous bucket listing** — a bucket with a public read/list policy returns
    an XML <ListBucketResult> to an unauthenticated GET. That is a direct file
    leak → high.

If MinIO/S3 is detected but neither bites, a positive-evidence finding is emitted
(the work is visible even when the store is hardened).
"""
import re
from urllib.parse import urlsplit

import httpx

from backend.app.shasec.verifier import register
from backend.app.shasec.verifier._spec import origin
from backend.app.shasec.verifier.base import ExploitContext, ExploitModule, ExploitResult
from backend.common.enums import FindingSeverity
from backend.common.log import log

# MinIO console login API locations.
_CONSOLE_LOGIN = ('/api/v1/login', '/minio/api/v1/login')
# Credentials shipped by default / commonly left unchanged.
_DEFAULT_KEYS = (
    ('minioadmin', 'minioadmin'), ('minioadmin', 'minio123'),
    ('admin', 'admin'), ('minio', 'minio123'), ('minioadmin', 'password'),
)
# Bounded bucket wordlist for the anonymous-listing probe.
_BUCKETS = ('backup', 'backups', 'uploads', 'upload', 'public', 'assets', 'static',
            'media', 'data', 'files', 'images', 'documents', 'private', 'dump', 'db')
_HTTP_TIMEOUT = 8.0

_REMEDIATION = (
    'Changer immédiatement les identifiants racine (MINIO_ROOT_USER / MINIO_ROOT_PASSWORD) — jamais '
    'minioadmin. Ne pas exposer la console (port 9001) sur Internet ; la garder sur le réseau interne. '
    'Retirer toute policy publique des buckets (`mc anonymous set none`), activer le chiffrement, '
    'restreindre par IP/VPC et journaliser les accès.'
)


class MinioExposureModule(ExploitModule):
    name = 'minio-exposure'
    category = 'exposed-storage'
    handles = ('api', 'host', 'website')
    timeout = 150

    async def run(self, ctx: ExploitContext) -> list[ExploitResult]:
        base = origin(ctx.target_url)
        if not base:
            return []
        results: list[ExploitResult] = []
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=True, verify=False,
                                     headers={'User-Agent': 'shasec/1.0 security audit'}) as client:
            if not await self._detect(client, base):
                return []  # not a MinIO/S3 endpoint — nothing to assert
            await self._console_login(client, base, results)
            await self._anon_buckets(client, base, results)
            if not results:
                results.append(ExploitResult(
                    category=self.category,
                    title=f'MinIO/S3 détecté, durci sur les vecteurs testés : {urlsplit(base).hostname}',
                    severity=FindingSeverity.info.value,
                    confirmed=True,
                    impact='Endpoint MinIO/S3 identifié. Identifiants par défaut (minioadmin…) rejetés et '
                           'aucun listing de bucket anonyme sur la liste testée.',
                    request=f'GET {base}/',
                    response=f'MinIO détecté ; défauts rejetés ; buckets testés : {", ".join(_BUCKETS)}',
                ))
        return results

    async def _detect(self, client, base: str) -> bool:
        try:
            r = await client.get(f'{base}/')
        except httpx.HTTPError:
            return False
        server = r.headers.get('server', '').lower()
        body = r.text[:1500].lower() if r.content else ''
        return bool(
            'minio' in server or 'minio' in body or 'amazons3' in server
            or '<listbucketsresult' in body or 'accessdenied' in body
            or r.headers.get('x-amz-request-id') or r.headers.get('x-amz-bucket-region')
        )

    async def _console_login(self, client, base: str, results: list[ExploitResult]) -> None:
        for path in _CONSOLE_LOGIN:
            url = f'{base}{path}'
            try:
                probe = await client.post(url, json={'accessKey': 'shasec_probe', 'secretKey': 'shasec_probe'})
            except httpx.HTTPError:
                continue
            if probe.status_code == 404:
                continue
            for ak, sk in _DEFAULT_KEYS:
                try:
                    r = await client.post(url, json={'accessKey': ak, 'secretKey': sk})
                except httpx.HTTPError:
                    continue
                has_token = (any('token' in c.lower() for c in r.headers.get_list('set-cookie'))
                             or 'token' in (r.text[:500].lower()))
                if r.status_code in (200, 204) and has_token:
                    log.info(f'[exploit:minio] CONSOLE default creds OK on {url} ({ak})')
                    results.append(ExploitResult(
                        category=self.category,
                        title=f'Console MinIO accessible avec un identifiant par défaut : {ak}',
                        severity=FindingSeverity.critical.value,
                        confirmed=True,
                        impact=f'Connexion à la console MinIO réussie avec l\'identifiant par défaut '
                               f'{ak}/****. Contrôle administrateur complet du stockage objet (lecture, '
                               f'écriture, suppression de tous les buckets). Compromission des données.',
                        request=f'POST {url}  {{"accessKey":"{ak}","secretKey":"****"}}',
                        response=f'HTTP {r.status_code} · cookie de session émis\n\nRemédiation: {_REMEDIATION}',
                    ))
                    return
            return  # console endpoint existed; defaults failed — stop here

    async def _anon_buckets(self, client, base: str, results: list[ExploitResult]) -> None:
        for bucket in _BUCKETS:
            url = f'{base}/{bucket}/?list-type=2&max-keys=5'
            try:
                r = await client.get(url)
            except httpx.HTTPError:
                continue
            body = r.text[:2000] if r.content else ''
            if r.status_code == 200 and '<listbucketresult' in body.lower():
                keys = re.findall(r'<Key>([^<]+)</Key>', body)[:5]
                log.info(f'[exploit:minio] ANON bucket listing on /{bucket}')
                results.append(ExploitResult(
                    category=self.category,
                    title=f'Bucket S3 listable sans authentification : /{bucket}',
                    severity=FindingSeverity.high.value,
                    confirmed=True,
                    impact='Un bucket répond à une requête de listing anonyme — n\'importe qui peut '
                           'énumérer (et probablement télécharger) son contenu. Fuite de fichiers.',
                    request=f'GET {url}',
                    response=f'HTTP 200 · <ListBucketResult> · objets: {", ".join(keys) or "(vide)"}'
                             f'\n\nRemédiation: {_REMEDIATION}',
                ))


register(MinioExposureModule())
