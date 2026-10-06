"""Shared response-leak scanner for the active API verifiers.

Ported from kaasec's ``_scan_body_for_leaks`` (api.sh). Given a response body, it
returns the sensitive patterns it recognises (JWT, secret-bearing fields, PII
dumps, stack traces, internal IPs, financial data). The caller turns each hit
into an ``ExploitResult`` and attaches the actual request/response as proof.

Leading underscore ⇒ the verifier auto-discovery skips this module (it is a
helper, not an ExploitModule).
"""
import re

from backend.common.enums import FindingSeverity

_JWT = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+')
_SECRET_FIELD = re.compile(
    r'"(password|password_hash|secret|api_key|token|access_token|refresh_token|private_key)"'
    r'\s*:\s*"[^"]{4,}"', re.I,
)
_INTERNAL_IP = re.compile(r'\b(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)(?:\d{1,3}\.){1,2}\d{1,3}\b')
_STACKTRACE = re.compile(
    r'Traceback \(most recent call last\)|Exception in|at [\w.$]+\([\w]+\.[a-z]+:\d+\)|'
    r'SQLSTATE\[|syntax error at or near',
)
_EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
_IBAN_FR = re.compile(r'\bFR\d{2}\d{10}[0-9A-Z]{11}\d{2}\b')
_CARD = re.compile(r'\b(?:4\d{15}|4\d{12}|5[1-5]\d{14})\b')

_MAX = 8000  # only inspect the first 8 KB, like the bash original


def scan_body(body: str) -> list[tuple[str, str, str, str]]:
    """Return ``(category, title, severity, impact)`` tuples for each leak found."""
    if not body:
        return []
    b = body[:_MAX]
    hits: list[tuple[str, str, str, str]] = []

    if _JWT.search(b):
        hits.append(('token-leak', 'JWT dans le corps de réponse', FindingSeverity.high.value,
                     'Un JWT est renvoyé — vérifier s\'il appartient à un autre utilisateur.'))
    if _SECRET_FIELD.search(b):
        hits.append(('excessive-data', 'Champ sensible non vide dans la réponse', FindingSeverity.critical.value,
                     'La réponse contient un champ password/secret/token avec une valeur.'))
    n_emails = len(set(_EMAIL.findall(b)))
    if n_emails >= 5:
        hits.append(('excessive-data', f'{n_emails} e-mails distincts dans la réponse', FindingSeverity.high.value,
                     'Dump probable de données personnelles (PII).'))
    if _IBAN_FR.search(b):
        hits.append(('excessive-data', 'IBAN français dans la réponse', FindingSeverity.critical.value,
                     'Donnée financière exposée.'))
    if _CARD.search(b):
        hits.append(('excessive-data', 'Numéro de carte probable dans la réponse', FindingSeverity.high.value,
                     'Vérifier Luhn manuellement ; donnée financière potentielle.'))
    if _STACKTRACE.search(b):
        hits.append(('info-leak', 'Stack trace dans la réponse', FindingSeverity.medium.value,
                     'Erreur verbeuse : fuite d\'internals (chemins, framework, requêtes SQL).'))
    if _INTERNAL_IP.search(b):
        hits.append(('info-leak', 'IP interne (RFC1918) dans la réponse', FindingSeverity.low.value,
                     'Adresse privée divulguée — aide à la cartographie interne.'))
    return hits
