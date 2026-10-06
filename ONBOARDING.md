# SHASEC — Onboarding

Plateforme d'audit de sécurité Web/API (micro-services). Elle **orchestre des
scanners → normalise les findings → corrèle → analyse (IA) → rapport**, et expose
tout via une API REST + une console web.

Doctrine : **passive/safe par défaut, détection ≠ exploitation**. On prouve qu'une
faille existe (preuve minimale) et on s'arrête — on n'exécute jamais la charge
destructrice. L'actif est verrouillé par un double consentement.

---

## 1. Architecture en 30 secondes

```
Console web (Next.js)  ─┐
Client Qt              ─┤→  API FastAPI (/api/v1)  →  Orchestrator (pipeline)
CLI / curl             ─┘                                │
                                                         ├─ Plugins  (scanners, passifs)      → RawFinding
                                                         ├─ Verifiers (exploitation active)    → ExploitResult (preuve req/resp)
                                                         ├─ Agrégateur (dedup SHA-256)
                                                         ├─ IA (DeepSeek / Ollama)  → score + résumé FR
                                                         └─ Rapport (html/md/json/pdf)
```

**Auto-exposition** : déposer un fichier dans `plugins/` (passif) ou `verifier/`
(actif) suffit — `_discover()` l'enregistre, l'orchestrateur le lance, l'API
l'expose. **Aucune route à écrire, aucune migration.**

Fichiers clés :
- `backend/app/shasec/plugins/` — scanners passifs (contrat `ScannerPlugin.run → [RawFinding]`)
- `backend/app/shasec/verifier/` — modules actifs (contrat `ExploitModule.run → [ExploitResult]`)
- `backend/app/shasec/service/orchestrator.py` — le pipeline
- `backend/app/shasec/proxy/` — le Repeater (proxy « Burp-like »)
- `backend/app/shasec/api/v1/` — routes (auto-découvertes)
- `shasec-web/app/page.tsx` — la console

---

## 2. Ce qui a été ajouté (cette itération)

### 2.1 Plugins passifs (les « dieux » importés de kaasec)
| Fichier | Rôle | Sévérité |
|---|---|---|
| `plugins/js_secrets.py` | scanne HTML + bundles JS → clés/API-keys fuitées (**valeurs masquées** avant stockage) | crit→medium |
| `plugins/takeover.py` | CNAME orphelin → subdomain takeover (dig + subfinder, fingerprints providers) | crit / low |
| `plugins/api_spec.py` | découvre **et parse** OpenAPI/Swagger → inventaire d'endpoints (`METHOD /path`) | high / medium / info |

### 2.2 Verifiers actifs (exploitation non destructive)
| Fichier | Détection | Prod-safe |
|---|---|---|
| `verifier/xss.py` | reflet **non encodé** en contexte HTML exécutable (canari inerte, aucun script exécuté) | ✅ |
| `verifier/csrf.py` | cookie de session sans `SameSite` + absence de token anti-CSRF (**observationnel**) | ✅ |
| `verifier/graphql.py` | introspection activée + requêtes credentials (queries only) | ✅ |
| `verifier/verb_tampering.py` | **OPTIONS-first** : lit `Allow` ; write réels seulement si `allow_destructive` | ✅ |
| `verifier/rate_limit.py` | rafale bornée → absence de 429 | ✅ |
| `verifier/bola.py` | IDOR : itère `id_range` sur `/{id}` (nécessite un token) | ✅ |
| `verifier/_leaks.py` | util partagé : regex JWT / IBAN-FR / CB / PII / stacktrace / IP interne | — |

> Déjà présents avant : `api-auth-matrix`, `jwt`, `sqli`, `ssti`, `exposed-endpoints`.

### 2.3 Options transitoires (aucune migration, jamais stockées)
`id_range` (BOLA, défaut `1-10`) et `allow_destructive` (verb-tamper, défaut `false`)
transitent comme `auth_token` : schéma `QuickScanParam` → API → `scan_service` →
`_dispatch` → **worker arq** → `run_pipeline` → `ExploitContext.options`.
⚠️ **Le worker arq ne fait pas de hot-reload** : après un changement de code du
worker, `docker compose restart worker` (le rebuild d'image le fait en prod).

### 2.4 Proxy « Burp-like » — le Repeater (`backend/app/shasec/proxy/`)
| Fichier | Rôle |
|---|---|
| `flows.py` | modèle `HttpFlow` (req/resp) + store JSONL |
| `repeater.py` | rejoue/modifie **une** requête via httpx ; **scope-lock** + **read-only par défaut** |
| `mitm_addon.py` | interception optionnelle, **process séparé** (`mitmdump -s …`), jamais dans le trafic de prod |

Routes : `POST /security/proxy/replay`, `POST /security/proxy/flows/{id}/replay`,
`GET /security/proxy/flows`, `GET /security/proxy/flows/{id}`.
Garde-fous : hôte hors scope → **403** ; verbe d'écriture sans `allow_write` → **403**.

### 2.5 Console web (`shasec-web/app/page.tsx`)
- **Auth transparente** : login une fois → refresh cookie, sinon reconnexion
  silencieuse avec identifiants mémorisés → **plus jamais « Token has expired »**.
- **Findings en français + regroupés** : couche d'enrichissement (titre FR +
  « Pourquoi c'est un risque » + « Correctif »), doublons fusionnés
  (ex. 73 lignes → 29 types ; « HSTS · 27× »). Sévérités en français.
- **Panneau « Pistes à tester »** : actions concrètes déduites du scan
  (IDOR/BOLA, accès sans auth, URLs à inspecter) avec **« Charger dans le
  Repeater »** en un clic.
- **Repeater assisté** : Méthode (select), en-têtes via menu « ＋ en-tête
  courant », corps via « modèle de corps » (pose aussi le `Content-Type`, passe
  en POST si besoin).
- Vue **Preuves d'exploitation** (sortie des verifiers).

---

## 3. Démarrer / tester

Le stack tourne en **Docker Compose** (dev, bind-mount + hot-reload API).

```bash
cd C:/Users/LEGION/Desktop/shaapi/shaapi

# stack (api, postgres, redis, minio, worker, zap)
docker compose ps                 # état
./docker-run.sh up                # démarrer   (ou: docker compose up -d)
./docker-run.sh migrate           # alembic upgrade head (fait aussi au boot)

# console web (process séparé, port 3001)
cd shasec-web && npm run dev
```

Après un changement de code **du worker** : `docker compose restart worker`.

### Identifiants admin (test API)
```
email    : admin@kaanari.com
password : ShaSec#Admin2026!
```
Créer/réinitialiser (email neuf pour repartir de zéro) :
```bash
docker compose exec api python -m backend.cli create-admin --email admin@kaanari.com --password "<pwd>"
```

### Accès
- API : `http://localhost:8000/api/v1`
- Swagger : `http://localhost:8000/api/v1/docs`
- OpenAPI : `http://localhost:8000/api/v1/openapi`
- Console : `http://localhost:3001`

### Scan en 3 requêtes
```bash
B=http://localhost:8000/api/v1
TOKEN=$(curl -s -X POST $B/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"admin@kaanari.com","password":"ShaSec#Admin2026!"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['data']['access_token'])")

# passif (sûr, prod) — actif : allow_active_exploitation=true (+ id_range, allow_destructive)
curl -s -X POST $B/scans/quick -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"url":"https://kortex.sbs","type":"website","allow_active_exploitation":false}'

curl -s $B/scans/<ID>/findings  -H "Authorization: Bearer $TOKEN"
curl -s $B/scans/<ID>/exploits  -H "Authorization: Bearer $TOKEN"
curl -s $B/scans/<ID>/analysis  -H "Authorization: Bearer $TOKEN"
```

Endpoints utiles : `/scans/quick`, `/scans/{id}/progress`, `/findings`,
`/exploits`, `/analysis`, `/report`, `/scans/{id}/cancel` (kill switch),
`/security/proxy/replay`.

---

## 4. Doctrine de sécurité (production)

- **Défaut = passive + safe.** Actif seulement si `allow_active_exploitation` **et**
  cible `is_authorized`.
- **Détection, pas exploitation** : preuve minimale puis arrêt (stop-at-proof).
- **Charges bénignes** : marqueurs inertes, `${7*7}`, différentiel booléen. Jamais
  DROP/DELETE, jamais de commande OS.
- **Scope-lock** : uniquement l'hôte autorisé. **Kill switch** : `/scans/{id}/cancel`.
- **Preuve** : chaque `ExploitResult` porte la requête/réponse exacte.
- **Interdits** : brute force, reverse shell, C2, persistance, EDR bypass, dumping,
  exfiltration, écriture destructive.

---

## 5. Résultats des tests

- **kortex.sbs** (serveur perso) : passif 45 findings / 15 plugins ; actif → étape
  d'exploitation OK, `rate-limit` medium confirmé ; Repeater replay 200 + scope-lock 403.
- **kaanari.com** (prod, passif) : 138 findings, 15 plugins, zéro perturbation ;
  js-secrets a scanné 32 JS (rien), takeover 60 hôtes (rien) ; findings d'hygiène
  réels (HSTS/CSP/anti-clickjacking manquants).

---

## 6. À faire / points ouverts

- **IA** : DeepSeek renvoie **402 Payment Required** (crédit épuisé) → l'analyse FR
  ne se génère pas. Alternative prévue : brancher l'endpoint **Ollama**
  (`https://ollama.traaf.app/`, compatible OpenAI) dans `ai_service.py`.
- **`options` non peuplées par l'orchestrateur** hors quick-scan : `_run_exploit_stage`
  reçoit `options` uniquement via `quick`. OK pour l'usage actuel.
- **Secrets** : d'anciennes versions de `shasec.txt`/`.env` contenaient des secrets
  réels (clé DeepSeek, mots de passe) — à révoquer/rotationner + purger de l'historique git.
- **Actif sur kaanari.com (prod)** : non lancé volontairement — à faire seulement
  sur go explicite (reste OPTIONS-first/non destructif).
- **Idées console** : bouton « Comparer id=1 vs id=2 » (BOLA en 1 clic),
  code couleur des méthodes, pré-remplir `Authorization` avec le token du scan.

---

## 7. Ajouter un module (recette)

**Plugin passif** — `backend/app/shasec/plugins/mon_plugin.py` :
```python
from backend.app.shasec.plugins import register
from backend.app.shasec.plugins.base import RawFinding, ScanContext, ScannerPlugin
class MonPlugin(ScannerPlugin):
    name = 'mon-plugin'; handles = ('website','api')
    async def run(self, ctx: ScanContext) -> list[RawFinding]:
        return [RawFinding(title='…', severity='info', fingerprint_seed='…')]
register(MonPlugin())
```

**Verifier actif** — `backend/app/shasec/verifier/mon_module.py` : même schéma avec
`ExploitModule` / `ExploitResult` (toujours joindre `request`/`response` comme preuve,
rester non destructif par défaut).

Le fichier est pris automatiquement au prochain (re)chargement — rien d'autre à câbler.
