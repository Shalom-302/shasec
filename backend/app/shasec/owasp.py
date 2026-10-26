"""OWASP Top 10 (2021) classification of findings and exploit proofs.

Deterministic, scanner-agnostic: a result is classified from what produced it
(plugin / exploit module), its category, and keywords in its title. Keyword rules
win over the source default because generic scanners (nuclei, nikto, zap) report
every class of issue. Pure recon/inventory output (subdomain lists, WHOIS, tool
notices) gets no category — it is context, not a vulnerability.
"""
import re

OWASP_TOP10: dict[str, str] = {
    'A01': 'Contrôle d’accès défaillant',
    'A02': 'Défaillances cryptographiques',
    'A03': 'Injection',
    'A04': 'Conception non sécurisée',
    'A05': 'Mauvaise configuration de sécurité',
    'A06': 'Composants vulnérables et obsolètes',
    'A07': 'Identification et authentification défaillantes',
    'A08': 'Intégrité des données et du logiciel',
    'A09': 'Journalisation et surveillance insuffisantes',
    'A10': 'Falsification de requête côté serveur (SSRF)',
}

# Ordered: the first matching keyword rule wins.
_KEYWORDS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r'\bssrf\b|server[- ]side request', re.I), 'A10'),
    (re.compile(r'sql|injection|\bxss\b|cross[- ]site scripting|ssti|template injection|command injection|\brce\b|lfi|path traversal', re.I), 'A03'),
    (re.compile(r'\bidor\b|\bbola\b|\bbfla\b|access control|unauthori[sz]ed|sans authentification|missing[- ]auth|privilege|csrf|cors', re.I), 'A01'),
    (re.compile(r'\bjwt\b|default (cred|password)|identifiants par défaut|brute|session|password policy|login', re.I), 'A07'),
    (re.compile(r'\bcve-\d{4}-\d+|outdated|obsolète|vulnerable version|end[- ]of[- ]life', re.I), 'A06'),
    (re.compile(r'\btls\b|\bssl\b|hsts|certificat|certificate|cipher|https', re.I), 'A02'),
    (re.compile(r'subresource integrity|\bsri\b|deserializ', re.I), 'A08'),
)

# Default class per source when no keyword matched.
_SOURCE_DEFAULT: dict[str, str] = {
    # exploit modules
    'bola': 'A01', 'api-auth-matrix': 'A01', 'auth-bypass': 'A01', 'verb-tampering': 'A01', 'csrf': 'A01',
    'sqli': 'A03', 'xss': 'A03', 'ssti': 'A03',
    'jwt': 'A07', 'default-creds': 'A07',
    'rate-limit': 'A04',
    'exposed-endpoints': 'A05', 'minio-exposure': 'A05', 'postgres-exposure': 'A05', 'graphql': 'A05',
    # scanner plugins
    'testssl': 'A02', 'js-secrets': 'A02',
    'http-security': 'A05', 'nikto': 'A05', 'nuclei': 'A05', 'zap': 'A05', 'ffuf': 'A05',
    'takeover': 'A05', 'api-spec': 'A05', 'katana': 'A05', 'nmap': 'A05',
}

# Inventory / recon output: never a vulnerability on its own.
_NO_CLASS_SOURCES = {'dns-recon', 'subfinder', 'whatweb', 'httpx', 'cartography'}


def classify(source: str, title: str = '', category: str | None = None, severity: str | None = None) -> str | None:
    """Return the OWASP Top 10 id (``A01``…``A10``) for a result, or ``None``."""
    if source in _NO_CLASS_SOURCES:
        return None
    # Informational scanner notices ("not installed", "no output", "aucun …") are not findings.
    if severity == 'info' and source not in _SOURCE_DEFAULT:
        return None
    text = f'{category or ""} {title or ""}'
    for pattern, owasp in _KEYWORDS:
        if pattern.search(text):
            return owasp
    return _SOURCE_DEFAULT.get(source)


def label(owasp: str | None) -> str:
    return f'{owasp} · {OWASP_TOP10[owasp]}' if owasp in OWASP_TOP10 else ''
