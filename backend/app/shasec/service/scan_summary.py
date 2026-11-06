"""Client-facing results of a scan: what was found, what was PROVEN, what was
tested and what was not (and why), per subdomain.

The raw findings list mixes inventory notices, scanner noise and real issues.
This module turns it into what a paying client expects to read:

- verdict + counts of real issues (info excluded), and how many are verified;
- proofs from the active-validation stage (Exploit rows), confirmed first;
- OWASP Top 10 coverage: vulnerable / tested-clean / partially tested / not
  tested, with the reason (e.g. BOLA needs test accounts) — so "nothing found"
  is never confused with "not tested";
- discovered subdomains and the issues attached to each.
"""
from collections import Counter

from sqlalchemy import select

from backend.app.shasec.owasp import OWASP_TOP10
from backend.app.shasec.plugins import get_plugins_for
from backend.database.db_postgres import async_db_session
from backend.models import Finding, Scan, ScanAsset, Target
from backend.models.exploit import Exploit

_SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}

# Which OWASP classes a passive scanner can really assess (full) or only hint at (partial).
_PASSIVE_FULL = {
    'A02': {'testssl', 'http-security'},
    'A05': {'http-security', 'nikto', 'nuclei', 'zap', 'ffuf', 'api-spec', 'takeover', 'nmap'},
    'A06': {'nuclei', 'whatweb', 'nikto'},
}
_PASSIVE_PARTIAL = {
    'A01': {'ffuf', 'nuclei', 'api-spec'},   # exposed admin/doc paths, not object-level access
    'A03': {'zap', 'nuclei'},               # signatures only; real injection needs active payloads
    'A07': {'nuclei', 'http-security'},     # cookie/session flags, not auth logic
    'A08': {'http-security', 'js-secrets'},
}
_ACTIVE = {
    'A01': {'bola', 'api-auth-matrix', 'auth-bypass', 'verb-tampering', 'csrf'},
    'A03': {'sqli', 'xss', 'ssti'},
    'A04': {'rate-limit'},
    'A07': {'jwt', 'default-creds'},
    'A10': set(),
}
_NOT_TESTABLE = {'A09': 'Non vérifiable de l’extérieur : nécessite un accès aux journaux et à la supervision.'}


def _skipped(e: Exploit) -> bool:
    t = (e.title or '').lower()
    return not e.confirmed and e.severity == 'info' and ('ignoré' in t or 'ignore' in t or 'skipp' in t)


def _hosts_from_findings(findings: list[Finding], root: str) -> list[dict]:
    hosts: dict[str, dict] = {}
    for f in findings:
        if f.plugin != 'subfinder' or not f.evidence:
            continue
        for line in f.evidence.splitlines():
            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 2 and '.' in parts[1]:          # triage table: kind | host | doc | title
                h = hosts.setdefault(parts[1], {'host': parts[1]})
                h.update(kind=parts[0] or None, doc=(parts[2] or None) if len(parts) > 2 else None,
                         title=(parts[3] or None) if len(parts) > 3 else None, alive=True)
            elif len(parts) == 1 and '.' in parts[0] and ' ' not in parts[0] and not parts[0].startswith('…'):
                hosts.setdefault(parts[0], {'host': parts[0]})
    hosts.setdefault(root, {'host': root})
    return list(hosts.values())


async def build_summary(scan_id: int) -> dict:
    async with async_db_session() as db:
        scan = await db.get(Scan, scan_id)
        target = await db.get(Target, scan.target_id)
        findings = list((await db.scalars(select(Finding).where(Finding.scan_id == scan_id))).all())
        exploits = list((await db.scalars(select(Exploit).where(Exploit.scan_id == scan_id))).all())
        assets = list((await db.scalars(select(ScanAsset).where(ScanAsset.scan_id == scan_id))).all())

    real = [f for f in findings if f.severity != 'info' and f.status != 'false_positive']
    proofs = [e for e in exploits if not _skipped(e) and e.severity != 'info']
    confirmed = [e for e in proofs if e.confirmed]
    sev = Counter(f.severity for f in real) + Counter(e.severity for e in confirmed)

    # ---- verdict
    if sev['critical'] or any(e.severity in ('critical', 'high') for e in confirmed):
        verdict = ('critical', 'Risque critique : des failles exploitables ont été trouvées. Corrigez-les en priorité.')
    elif sev['high']:
        verdict = ('high', 'Risque élevé : plusieurs failles importantes à corriger rapidement.')
    elif sev['medium']:
        verdict = ('medium', 'Risque modéré : pas de faille critique, mais des faiblesses à corriger.')
    elif sev['low']:
        verdict = ('low', 'Risque faible : seuls des points d’amélioration ont été relevés.')
    else:
        verdict = ('none', 'Aucune faille trouvée sur les tests effectués (voir la couverture ci-dessous).')

    # ---- OWASP coverage
    ran_plugins = {p.name for p in get_plugins_for(target.type, scan.profile)} | {f.plugin for f in findings}
    ran_modules = {e.module for e in exploits if not _skipped(e)}
    skipped_modules = {e.module: (e.impact or e.title) for e in exploits if _skipped(e)}
    active = bool(scan.allow_active_exploitation)
    coverage = []
    for code, name in OWASP_TOP10.items():
        items_f = [f for f in real if f.owasp == code]
        items_e = [e for e in proofs if e.owasp == code]
        n_conf = sum(1 for e in items_e if e.confirmed) + sum(1 for f in items_f if f.status == 'confirmed')
        full = (_PASSIVE_FULL.get(code, set()) & ran_plugins) or (_ACTIVE.get(code, set()) & ran_modules)
        partial = _PASSIVE_PARTIAL.get(code, set()) & ran_plugins
        if items_f or items_e:
            state, note = 'vulnerable', f'{len(items_f) + len(items_e)} problème(s), dont {n_conf} vérifié(s) par preuve.'
        elif code in _NOT_TESTABLE:
            state, note = 'not_tested', _NOT_TESTABLE[code]
        elif full:
            state, note = 'tested', 'Testé : rien trouvé (' + ', '.join(sorted(full)) + ').'
        else:
            skipped = [m for m in _ACTIVE.get(code, set()) if m in skipped_modules]
            if skipped and code == 'A01':
                why = ('BOLA/IDOR et contrôle d’accès non testés : il faut des comptes de test (deux utilisateurs) '
                       'pour vérifier qu’un client ne peut pas lire les données d’un autre.')
            elif skipped:
                why = f'Tests actifs ({", ".join(sorted(skipped))}) ignorés : identifiants de test requis.'
            elif _ACTIVE.get(code) and not active:
                why = 'Test complet : nécessite un audit avancé (tests actifs, validé par un expert Kortex).'
            elif code == 'A10':
                why = 'Pas de test SSRF automatisé : nécessite un audit manuel.'
            elif partial:
                why = 'Vérification complète : audit manuel recommandé.'
            else:
                why = 'Aucun analyseur de ce scan ne couvre cette catégorie.'
            state = 'partial' if partial else 'not_tested'
            note = ('Partiellement testé (' + ', '.join(sorted(partial)) + '). ' if partial else '') + why
        worst = max([_SEV_RANK.get(x.severity, 0) for x in items_f + items_e] or [0])
        coverage.append({'code': code, 'name': name, 'state': state, 'findings': len(items_f),
                         'proofs': len(items_e), 'confirmed': n_conf, 'note': note,
                         'worst': next((k for k, v in _SEV_RANK.items() if v == worst and worst), None),
                         'items': [{'title': x.title, 'severity': x.severity,
                                    'verified': bool(getattr(x, 'confirmed', False)) or x.status == 'confirmed',
                                    'kind': 'proof' if isinstance(x, Exploit) else 'finding'}
                                   for x in sorted(items_e + items_f, key=lambda y: -_SEV_RANK.get(y.severity, 0))[:8]]})

    # ---- OWASP score: tested & clean = 1, partially tested & clean = 0.5,
    # vulnerable = 0, NOT TESTED = 0 (an untested category is never "safe").
    points = {'tested': 1.0, 'partial': 0.5}
    owasp_score = round(100 * sum(points.get(c['state'], 0.0) for c in coverage) / len(coverage))
    tested = sum(1 for c in coverage if c['state'] in ('tested', 'vulnerable'))
    partial_n = sum(1 for c in coverage if c['state'] == 'partial')
    vulnerable_n = sum(1 for c in coverage if c['state'] == 'vulnerable')

    # ---- subdomains
    root = (target.url.split('://', 1)[-1].split('/', 1)[0]).split(':')[0]
    if assets:
        hosts = [{'host': a.host, 'kind': a.kind, 'alive': a.alive, 'title': a.title, 'in_scope': a.selected,
                  'asset_id': a.id, 'third_party': a.third_party} for a in assets]
    else:
        hosts = _hosts_from_findings(findings, root)
    for h in hosts:
        mine_f = [f for f in real if (h.get('asset_id') and f.asset_id == h['asset_id'])
                  or (not h.get('asset_id') and h['host'] in f'{f.title} {f.evidence or ""}')]
        mine_e = [e for e in proofs if (h.get('asset_id') and e.asset_id == h['asset_id'])]
        if not assets and h['host'] == root:
            # Single-URL scan: everything not tied to another host belongs to the root.
            others = {x['host'] for x in hosts if x['host'] != root}
            mine_f = [f for f in real if not any(o in f'{f.title} {f.evidence or ""}' for o in others)]
            mine_e = proofs
        c = Counter(f.severity for f in mine_f) + Counter(e.severity for e in mine_e if e.confirmed)
        h['scanned'] = bool(assets and h.get('in_scope')) or h['host'] == root
        h['counts'] = {k: c[k] for k in ('critical', 'high', 'medium', 'low') if c[k]}
        h['top'] = [x.title for x in sorted(mine_f, key=lambda f: -_SEV_RANK.get(f.severity, 0))[:3]]
    hosts.sort(key=lambda h: (not h['scanned'], -sum(_SEV_RANK[k] * 10 + v for k, v in h['counts'].items()), h['host']))

    # ---- top issues
    top = sorted(
        [{'kind': 'proof', 'title': e.title, 'severity': e.severity, 'verified': e.confirmed, 'owasp': e.owasp,
          'detail': e.impact} for e in proofs]
        + [{'kind': 'finding', 'title': f.title, 'severity': f.severity, 'verified': f.status == 'confirmed',
            'owasp': f.owasp, 'detail': f.recommendation} for f in real],
        key=lambda x: (-_SEV_RANK.get(x['severity'], 0), not x['verified']))[:10]

    return {
        'verdict': {'level': verdict[0], 'text': verdict[1]},
        'counts': {k: sev[k] for k in ('critical', 'high', 'medium', 'low')},
        'informational': len(findings) - len(real),
        'verified': len(confirmed) + sum(1 for f in real if f.status == 'confirmed'),
        'active': active,
        'profile': scan.profile,
        'coverage': coverage,
        'owasp': {'score': owasp_score, 'tested': tested, 'partial': partial_n, 'vulnerable': vulnerable_n,
                  'untested': len(coverage) - tested - partial_n},
        'hosts': hosts,
        'subdomains_scanned': bool(assets),
        'top': top,
        'proofs': [{'id': e.id, 'module': e.module, 'title': e.title, 'severity': e.severity, 'confirmed': e.confirmed,
                    'owasp': e.owasp, 'impact': e.impact, 'request': (e.request or '')[:2000],
                    'response': (e.response or '')[:2000]}
                   for e in sorted(proofs, key=lambda e: (not e.confirmed, -_SEV_RANK.get(e.severity, 0)))],
        'skipped': [{'module': m, 'reason': r} for m, r in skipped_modules.items()],
    }
