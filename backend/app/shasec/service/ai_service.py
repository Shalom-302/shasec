"""Phase 3 — AI analysis over a scan's correlated findings + exploit proofs.

A provider-agnostic layer (``AIProvider``) with a DeepSeek implementation
(OpenAI-compatible ``/chat/completions``). The AI never scans; it *interprets*
the normalized results into a security score, an executive summary, impacts and
prioritized remediations for the audited target. The stage is best-effort: any
failure (no API key, network, bad JSON) is logged and the scan still completes.
"""
import json
from abc import ABC, abstractmethod

import httpx

from backend.app.shasec.schema.ai_analysis import CreateAIAnalysisParam
from backend.common.log import log
from backend.core.conf import settings
from backend.crud.crud_ai_analysis import ai_analysis_dao
from backend.crud.crud_exploit import exploit_dao
from backend.crud.crud_finding import finding_dao
from backend.crud.crud_scan import scan_dao
from backend.crud.crud_target import target_dao
from backend.database.db_postgres import async_db_session

_SYSTEM_PROMPT = (
    "Tu es un analyste sécurité senior. On te donne les résultats normalisés d'un audit "
    "(findings + preuves confirmées) sur une cible autorisée. Tu n'exécutes aucun scan : "
    "tu interprètes. RÈGLES DE CALIBRAGE (essentielles, ne pas sur-évaluer) :\n"
    "1) La sévérité de chaque élément t'est donnée (critical/high/medium/low/info) : c'est "
    "le PLAFOND. N'élève JAMAIS un 'medium' au rang de 'critique'.\n"
    "2) Ne qualifie l'audit global de 'critique' QUE s'il existe au moins une preuve "
    "confirmée de sévérité 'critical' ou 'high'. Sinon parle de risque modéré ou faible.\n"
    "3) Distingue 'accessible sans authentification' de 'données exposées' : si le champ "
    "response_excerpt d'une preuve est vide ([], {}, '' ou null), l'endpoint est joignable "
    "mais l'exposition de données reste À CONFIRMER — dis-le explicitement, n'affirme PAS "
    "que des mots de passe/tokens/secrets ont fuité.\n"
    "4) N'invente aucune faille ni aucun impact non étayé par les preuves fournies.\n"
    "SCORE (entier 0-100, plus haut = plus sûr) cohérent avec la sévérité réelle : aucune "
    "preuve high/critical => score >= 60 ; uniquement de l'hygiène (en-têtes, bannière, docs) "
    "=> score >= 75.\n"
    "Réponds STRICTEMENT en JSON: score (int), summary (français, factuel, 3-5 phrases), "
    "impacts (ce qu'un attaquant pourrait RÉELLEMENT faire d'après les preuves), "
    "recommendations (correctifs priorisés POUR LA CIBLE, concrets)."
)


def _as_text(value) -> str:
    """DeepSeek may return a field as a list/dict (e.g. recommendations as a JSON
    array). Flatten to readable text instead of a Python repr."""
    if isinstance(value, list):
        return '\n'.join(str(x) for x in value)
    if isinstance(value, dict):
        return '\n'.join(f'{k}: {v}' for k, v in value.items())
    return str(value or '')


def _build_payload(target, findings: list, exploits: list) -> dict:
    return {
        'target': {'url': target.url, 'type': target.type} if target else {},
        'findings': [
            {'severity': f.severity, 'title': f.title, 'plugin': f.plugin,
             'description': f.description} for f in findings
        ],
        'exploits': [
            {'severity': e.severity, 'category': e.category, 'title': e.title,
             'confirmed': e.confirmed, 'impact': e.impact,
             # let the model see whether real data came back vs an empty body ([] / {})
             'response_excerpt': (e.response or '')[:160]} for e in exploits
        ],
    }


class AIProvider(ABC):
    name: str = 'base'

    @property
    @abstractmethod
    def enabled(self) -> bool:
        ...

    @abstractmethod
    async def analyze(self, payload: dict) -> dict:
        """Return {score:int, summary:str, impacts:str, recommendations:str, raw:dict}."""
        ...


class DeepSeekProvider(AIProvider):
    name = 'deepseek'

    @property
    def enabled(self) -> bool:
        return bool(settings.DEEPSEEK_API_KEY)

    async def analyze(self, payload: dict) -> dict:
        url = f'{settings.DEEPSEEK_BASE_URL.rstrip("/")}/chat/completions'
        body = {
            'model': settings.DEEPSEEK_MODEL,
            'messages': [
                {'role': 'system', 'content': _SYSTEM_PROMPT},
                {'role': 'user', 'content': json.dumps(payload, ensure_ascii=False)},
            ],
            'response_format': {'type': 'json_object'},
            'temperature': 0.2,
            'stream': False,
        }
        headers = {
            'Authorization': f'Bearer {settings.DEEPSEEK_API_KEY}',
            'Content-Type': 'application/json',
        }
        async with httpx.AsyncClient(timeout=settings.DEEPSEEK_TIMEOUT) as client:
            resp = await client.post(url, json=body, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        content = data['choices'][0]['message']['content']
        parsed = json.loads(content)
        return {
            'score': int(parsed.get('score', 0)),
            'summary': _as_text(parsed.get('summary')),
            'impacts': _as_text(parsed.get('impacts')),
            'recommendations': _as_text(parsed.get('recommendations')),
            'raw': {'model': data.get('model'), 'usage': data.get('usage')},
        }

    async def translate_fr(self, texts: list[str]) -> list[str]:
        """Batch-translate scanner strings to French for a francophone report.
        Returns the same length/order, or the originals on any mismatch."""
        url = f'{settings.DEEPSEEK_BASE_URL.rstrip("/")}/chat/completions'
        system = (
            "Tu es un traducteur technique en cybersécurité. Traduis en français chaque "
            "chaîne du tableau 'items'. Garde le sens technique exact ; ne traduis PAS les "
            "noms d'en-têtes HTTP, chemins d'URL, identifiants de code ni noms de produits. "
            "Réponds STRICTEMENT en JSON {\"items\": [...]} de MÊME longueur et MÊME ordre."
        )
        body = {
            'model': settings.DEEPSEEK_MODEL,
            'messages': [
                {'role': 'system', 'content': system},
                {'role': 'user', 'content': json.dumps({'items': texts}, ensure_ascii=False)},
            ],
            'response_format': {'type': 'json_object'},
            'temperature': 0,
            'stream': False,
        }
        headers = {'Authorization': f'Bearer {settings.DEEPSEEK_API_KEY}', 'Content-Type': 'application/json'}
        async with httpx.AsyncClient(timeout=settings.DEEPSEEK_TIMEOUT) as client:
            resp = await client.post(url, json=body, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        items = json.loads(data['choices'][0]['message']['content']).get('items')
        if isinstance(items, list) and len(items) == len(texts):
            return [str(x) for x in items]
        return texts


class AIService:
    provider: AIProvider = DeepSeekProvider()

    async def analyze_scan(self, scan_id: int) -> None:
        """Best-effort: produce and persist one AIAnalysis for the scan. Never raises."""
        if not settings.AI_ANALYSIS_ENABLED or not self.provider.enabled:
            log.info(f'shasec AI analysis skipped for scan {scan_id} (disabled or no API key)')
            return
        try:
            async with async_db_session() as db:
                if await ai_analysis_dao.get_by_scan(db, scan_id):
                    return  # one analysis per scan; already done
                scan = await scan_dao.get(db, scan_id)
                target = await target_dao.get(db, scan.target_id) if scan else None
                findings = list(await finding_dao.get_by_scan(db, scan_id))
                exploits = list(await exploit_dao.get_by_scan(db, scan_id))

            result = await self.provider.analyze(_build_payload(target, findings, exploits))

            async with async_db_session.begin() as db:
                await ai_analysis_dao.create(
                    db,
                    CreateAIAnalysisParam(
                        scan_id=scan_id,
                        score=result['score'],
                        summary=result['summary'],
                        impacts=result['impacts'],
                        recommendations=result['recommendations'],
                        provider=self.provider.name,
                        raw=result.get('raw'),
                    ),
                )
            log.info(f'shasec AI analysis for scan {scan_id} done (score={result["score"]})')
        except Exception as exc:  # noqa: BLE001 — analysis must never fail the scan
            log.error(f'shasec AI analysis failed for scan {scan_id}: {exc}')

    async def translate_fr(self, texts: list[str]) -> list[str]:
        """Best-effort French translation for report rendering. English fallback."""
        if not texts or not settings.AI_ANALYSIS_ENABLED or not self.provider.enabled:
            return texts
        try:
            return await self.provider.translate_fr(texts)
        except Exception as exc:  # noqa: BLE001 — never break report generation
            log.error(f'shasec FR translation failed: {exc}')
            return texts


ai_service: AIService = AIService()
