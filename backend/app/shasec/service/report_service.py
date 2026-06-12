"""Report engine: turn a scan's findings + exploit proofs into a deliverable.

Phase 4. Renders an audit document from the persisted findings/exploits (and the
AI analysis when present) and stores it in object storage (MinIO). HTML, Markdown
and JSON render with Jinja2 alone; PDF additionally needs WeasyPrint baked into
the image (system libs Pango/Cairo) — until then a `pdf` request raises a clear
error instead of failing silently.
"""
import asyncio
import io
import json
from datetime import datetime

import jinja2

from backend.app.shasec.schema.report import CreateReportParam
from backend.app.shasec.service.ai_service import ai_service
from backend.common.cloud_storage.cloud_storage import MinioStorage
from backend.common.enums import ReportFormat
from backend.common.exception import errors
from backend.common.log import log
from backend.core.conf import settings
from backend.crud.crud_ai_analysis import ai_analysis_dao
from backend.crud.crud_exploit import exploit_dao
from backend.crud.crud_finding import finding_dao
from backend.crud.crud_report import report_dao
from backend.crud.crud_scan import scan_dao
from backend.crud.crud_target import target_dao
from backend.database.db_postgres import async_db_session

# Score penalty per severity. A confirmed exploit (proven impact) weighs more
# than an unconfirmed finding of the same level — proof beats suspicion.
_PENALTY = {'critical': 40, 'high': 20, 'medium': 8, 'low': 3, 'info': 0}
_SEV_ORDER = ('critical', 'high', 'medium', 'low', 'info')


def _security_score(findings: list, exploits: list) -> int:
    """Deterministic 0-100 score (higher = safer) used when no AI analysis
    exists yet. The AI score overrides this once Phase 3 is wired."""
    penalty = 0.0
    for f in findings:
        penalty += _PENALTY.get(f.severity, 0) * 0.5  # a finding is a suspicion
    for e in exploits:
        mult = 1.0 if e.confirmed else 0.4  # a confirmed proof hits full weight
        penalty += _PENALTY.get(e.severity, 0) * mult
    return max(0, min(100, round(100 - penalty)))


_HTML_TEMPLATE = jinja2.Template(
    """<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><title>Rapport d'audit — {{ target.name }}</title>
<style>
 body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#1a2332;margin:0;padding:40px;background:#fff}
 h1{font-size:26px;margin:0 0 4px} h2{font-size:18px;border-bottom:2px solid #e3e8ef;padding-bottom:6px;margin-top:34px}
 .muted{color:#6b7684;font-size:13px} .score{font-size:48px;font-weight:700}
 .grid{display:flex;gap:16px;margin:18px 0}
 .card{border:1px solid #e3e8ef;border-radius:10px;padding:16px 20px;flex:1}
 table{width:100%;border-collapse:collapse;font-size:13px;margin-top:10px}
 th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #eef1f5;vertical-align:top}
 th{background:#f7f9fc;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#6b7684}
 .sev{font-weight:700;padding:2px 8px;border-radius:6px;font-size:11px;text-transform:uppercase}
 .critical{background:#fde8e8;color:#b91c1c}.high{background:#fef0e7;color:#c2410c}
 .medium{background:#fef9e7;color:#a16207}.low{background:#eef6fc;color:#1d6fb8}.info{background:#f1f3f5;color:#555}
 .proof{background:#0f1626;color:#cdd6e4;border-radius:8px;padding:10px 12px;font-family:ui-monospace,Menlo,monospace;
   font-size:11.5px;white-space:pre-wrap;word-break:break-word;margin:6px 0}
 .ok{color:#15803d;font-weight:600} .tag{font-size:11px;color:#6b7684}
 footer{margin-top:40px;border-top:1px solid #e3e8ef;padding-top:12px;font-size:11px;color:#9aa4b2}
</style></head><body>
 <h1>Rapport d'audit de sécurité</h1>
 <div class="muted">Cible : <b>{{ target.url }}</b> ({{ target.type }}) · Scan #{{ scan.id }} ·
   Généré le {{ generated_at }}</div>

 <div class="grid">
  <div class="card"><div class="muted">Score de sécurité</div>
    <div class="score">{{ score }}<span style="font-size:18px;color:#9aa4b2">/100</span></div>
    <div class="tag">{{ "plus haut = plus sûr" }}</div></div>
  <div class="card"><div class="muted">Findings</div><div class="score">{{ findings|length }}</div>
    <div class="tag">{% for s in sev_order %}{% if counts[s] %}{{ counts[s] }} {{ s }} · {% endif %}{% endfor %}</div></div>
  <div class="card"><div class="muted">Preuves d'exploitation</div><div class="score">{{ exploits|length }}</div>
    <div class="tag">{{ confirmed_count }} confirmée(s)</div></div>
 </div>

 <h2>Résumé exécutif</h2>
 <p>{{ summary }}</p>

 <h2>Findings ({{ findings|length }})</h2>
 {% if findings %}<table><tr><th>Sév.</th><th>Titre</th><th>Scanner</th><th>Description</th></tr>
 {% for f in findings %}<tr><td><span class="sev {{ f.severity }}">{{ f.severity }}</span></td>
   <td><b>{{ f.title }}</b></td><td class="tag">{{ f.plugin }}</td>
   <td>{{ f.description or '' }}{% if f.evidence %}<div class="tag">{{ f.evidence }}</div>{% endif %}</td></tr>
 {% endfor %}</table>{% else %}<p class="ok">Aucun finding.</p>{% endif %}

 <h2>Preuves d'exploitation ({{ exploits|length }})</h2>
 {% if exploits %}{% for e in exploits %}
  <div style="margin:16px 0">
   <span class="sev {{ e.severity }}">{{ e.severity }}</span>
   {% if e.confirmed %}<span class="ok">✔ CONFIRMÉ</span>{% else %}<span class="tag">non confirmé</span>{% endif %}
   <b>{{ e.title }}</b> <span class="tag">[{{ e.category }} · {{ e.module }}]</span>
   {% if e.impact %}<div>{{ e.impact }}</div>{% endif %}
   {% if e.request %}<div class="proof">{{ e.request }}</div>{% endif %}
   {% if e.response %}<div class="proof">{{ e.response }}</div>{% endif %}
  </div>
 {% endfor %}{% else %}<p class="ok">Aucune preuve d'exploitation — la cible résiste aux modules exécutés.</p>{% endif %}

 {% if analysis %}<h2>Analyse IA ({{ analysis.provider }})</h2>
  {% if analysis.impacts %}<h3>Impacts</h3><p>{{ analysis.impacts }}</p>{% endif %}
  {% if analysis.recommendations %}<h3>Recommandations</h3><p>{{ analysis.recommendations }}</p>{% endif %}
 {% endif %}

 <footer>Généré par SHASEC · audit autorisé, borné et tracé · {{ generated_at }}.
   Les preuves ci-dessus ont été obtenues sur une cible explicitement autorisée.</footer>
</body></html>"""
)


def _render_markdown(ctx: dict) -> str:
    lines = [
        f"# Rapport d'audit de sécurité — {ctx['target'].name}",
        '',
        f"- **Cible** : {ctx['target'].url} ({ctx['target'].type})",
        f"- **Scan** : #{ctx['scan'].id}",
        f"- **Score** : {ctx['score']}/100 (plus haut = plus sûr)",
        f"- **Généré le** : {ctx['generated_at']}",
        '',
        '## Résumé exécutif',
        ctx['summary'],
        '',
        f"## Findings ({len(ctx['findings'])})",
    ]
    for f in ctx['findings']:
        lines.append(f"- **[{f.severity.upper()}]** {f.title} _({f.plugin})_ — {f.description or ''}")
    lines += ['', f"## Preuves d'exploitation ({len(ctx['exploits'])})"]
    if not ctx['exploits']:
        lines.append('_Aucune preuve — la cible résiste aux modules exécutés._')
    for e in ctx['exploits']:
        flag = '✔ CONFIRMÉ' if e.confirmed else 'non confirmé'
        lines += [
            f"### [{e.severity.upper()}] {flag} — {e.title}",
            f"`{e.category}` · `{e.module}`",
            f"{e.impact or ''}",
            '```http', (e.request or '').strip(), (e.response or '').strip(), '```', '',
        ]
    return '\n'.join(lines)


async def _localize_fr(findings: list, exploits: list) -> None:
    """Translate finding titles/descriptions + exploit titles/impacts to French,
    in place on the (detached) ORM rows — affects rendering only, never the DB."""
    refs: list[tuple] = []
    texts: list[str] = []
    for f in findings:
        for attr in ('title', 'description'):
            v = getattr(f, attr, None)
            if v:
                refs.append((f, attr))
                texts.append(v)
    for e in exploits:
        for attr in ('title', 'impact'):
            v = getattr(e, attr, None)
            if v:
                refs.append((e, attr))
                texts.append(v)
    if not texts:
        return
    translated = await ai_service.translate_fr(texts)
    if len(translated) != len(texts):
        return  # safety: leave English rather than misalign
    for (obj, attr), value in zip(refs, translated):
        try:
            setattr(obj, attr, value)
        except Exception:  # noqa: BLE001 — a read-only attr must not break the report
            pass


class ReportService:
    @staticmethod
    async def generate(*, scan_id: int, format: str = ReportFormat.html.value, lang: str = 'fr'):
        fmt = format.lower()
        if fmt not in {f.value for f in ReportFormat}:
            raise errors.RequestError(msg=f'Unsupported report format: {format}')

        async with async_db_session() as db:
            scan = await scan_dao.get(db, scan_id)
            if not scan:
                raise errors.NotFoundError(msg='Scan not found')
            target = await target_dao.get(db, scan.target_id)
            findings = list(await finding_dao.get_by_scan(db, scan_id))
            exploits = list(await exploit_dao.get_by_scan(db, scan_id))
            analysis = await ai_analysis_dao.get_by_scan(db, scan_id)

        findings.sort(key=lambda f: _SEV_ORDER.index(f.severity) if f.severity in _SEV_ORDER else 9)
        exploits.sort(key=lambda e: _SEV_ORDER.index(e.severity) if e.severity in _SEV_ORDER else 9)

        # Francophone report: scanner output (http-security, nuclei…) is English.
        # Translate the human-readable strings for rendering only — stored rows stay
        # canonical English. Best-effort: English fallback if AI is unavailable.
        if lang == 'fr':
            await _localize_fr(findings, exploits)

        counts = {s: sum(1 for f in findings if f.severity == s) for s in _SEV_ORDER}
        confirmed_count = sum(1 for e in exploits if e.confirmed)
        score = analysis.score if analysis else _security_score(findings, exploits)
        summary = (analysis.summary if analysis and analysis.summary
                   else _auto_summary(target, findings, exploits, confirmed_count))

        ctx = {
            'scan': scan, 'target': target, 'findings': findings, 'exploits': exploits,
            'analysis': analysis, 'counts': counts, 'sev_order': _SEV_ORDER,
            'confirmed_count': confirmed_count, 'score': score, 'summary': summary,
            'generated_at': scan.completed_at.strftime('%Y-%m-%d %H:%M UTC') if scan.completed_at else '',
        }

        content, ext, mime = _serialize(fmt, ctx)
        filename = f'shasec_report_scan{scan_id}_{ext}.{ext}'

        # MinIO client init + upload are blocking — keep them off the event loop.
        def _upload() -> str:
            store = MinioStorage(
                settings.MINIO_ENDPOINT, settings.MINIO_ACCESS_KEY,
                settings.MINIO_SECRET_KEY, settings.MINIO_BUCKET_NAME,
            )
            return store.upload_file(content, filename)['file_url']

        location = await asyncio.to_thread(_upload)

        async with async_db_session.begin() as db:
            report = await report_dao.create(db, CreateReportParam(scan_id=scan_id, format=fmt))
            report.location = location
            await db.flush()
            await db.refresh(report)
        log.info(f'shasec report for scan {scan_id} ({fmt}) -> {location}')
        return report


def _serialize(fmt: str, ctx: dict) -> tuple[bytes, str, str]:
    if fmt == ReportFormat.html.value:
        return _HTML_TEMPLATE.render(**ctx).encode(), 'html', 'text/html'
    if fmt == ReportFormat.markdown.value:
        return _render_markdown(ctx).encode(), 'md', 'text/markdown'
    if fmt == ReportFormat.json.value:
        payload = {
            'target': {'name': ctx['target'].name, 'url': ctx['target'].url, 'type': ctx['target'].type},
            'scan_id': ctx['scan'].id, 'score': ctx['score'], 'summary': ctx['summary'],
            'findings': [
                {'severity': f.severity, 'title': f.title, 'plugin': f.plugin,
                 'description': f.description, 'evidence': f.evidence} for f in ctx['findings']
            ],
            'exploits': [
                {'severity': e.severity, 'category': e.category, 'module': e.module, 'title': e.title,
                 'confirmed': e.confirmed, 'impact': e.impact, 'request': e.request,
                 'response': e.response} for e in ctx['exploits']
            ],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2).encode(), 'json', 'application/json'
    if fmt == ReportFormat.pdf.value:
        try:
            from weasyprint import HTML  # noqa: PLC0415
        except ModuleNotFoundError as exc:
            raise errors.ServerError(
                msg='PDF rendering needs WeasyPrint (+ Pango/Cairo) in the image. '
                    'Rebuild with the weasyprint extra, or use format=html/markdown for now.'
            ) from exc
        html = _HTML_TEMPLATE.render(**ctx)
        return HTML(string=html).write_pdf(), 'pdf', 'application/pdf'
    raise errors.RequestError(msg=f'Unsupported report format: {fmt}')


def _auto_summary(target, findings: list, exploits: list, confirmed: int) -> str:
    """A factual summary when no AI analysis exists yet."""
    if not findings and not exploits:
        return f"Aucun problème détecté sur {target.url}. La cible résiste aux scanners et modules exécutés."
    parts = [f"L'audit de {target.url} a relevé {len(findings)} finding(s)"]
    if exploits:
        parts.append(f"et produit {len(exploits)} preuve(s) d'exploitation dont {confirmed} confirmée(s)")
    highs = sum(1 for x in list(findings) + list(exploits) if x.severity in ('critical', 'high'))
    parts.append(
        f". {highs} élément(s) de criticité haute/critique nécessitent une remédiation prioritaire."
        if highs else ". Aucun élément critique : surface essentiellement liée à l'hygiène (en-têtes, exposition)."
    )
    return ' '.join(parts)


report_service: ReportService = ReportService()
