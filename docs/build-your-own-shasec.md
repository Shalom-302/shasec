# Build Your Own SHASEC

### ÉTUDE APPLIQUÉE & COURS — Concevoir une plateforme d'audit et d'exploitation d'API

> Des fondations d'un scanner jusqu'à la preuve d'exploitabilité — apprendre la
> sécurité offensive web en construisant son propre outil.
>
> **Compagnon de** *« Build Your Own shaapi »*. Là où shaapi enseigne à bâtir un
> backend **sûr par défaut**, SHASEC enseigne à **prouver** qu'il l'est — en
> l'attaquant.
>
> Kaanari — 2026 · SHASEC v0.1 · pédagogie offensive-pour-défensive

---

## Résumé

Un scan de sécurité qui rend « en-tête HSTS manquant » ne prouve rien : il
*suggère*. La valeur d'un audit naît quand on **démontre** qu'une faille est
réellement exploitable — *« voici la requête que j'ai envoyée, voici la réponse
qui le prouve »*. SHASEC est une plateforme qui orchestre plusieurs scanners,
normalise leurs résultats, puis **attaque** la cible de façon bornée et
non-destructive pour transformer chaque soupçon en preuve.

Ce document est double : un **récit** (d'un fichier d'architecture vierge à une
plateforme qui a trouvé 19 failles réelles sur une API en production) et un
**cours** en 8 séances qui enseigne, au passage, les fondations de la
**cybersécurité offensive web** : reconnaissance, OWASP API Security Top 10,
contournement d'authentification, forge de JWT, injections (SQL, template), et —
le plus important — la **frontière éthique** entre auditer et nuire.

**Principe directeur** : *Scanner → Corréler → Exploiter → Prouver → Rapporter.*
On ne reste jamais au scan ; mais on n'exploite jamais sans autorisation, sans
consentement explicite, et sans garde-fou.

**Mots-clés** : sécurité offensive, pentest d'API, OWASP API Top 10, JWT, SQLi,
SSTI, orchestration de scanners, FastAPI, plugin SDK, DevSecOps, éthique.

---

## Comment lire ce document

| Vous êtes… | Lisez en priorité |
|---|---|
| Curieux du *pourquoi* | Chapitre 0 (le problème, l'état de l'art, la thèse) |
| Étudiant / formateur | Les 8 séances (Partie I et II) |
| Pressé de tester une API | Séance 2 (premier scan) puis l'Annexe A (API REST) |
| Architecte | Séances 1, 4 (modèle de domaine + orchestration) |
| Préoccupé d'éthique/légal | Séance 5 §*La ligne rouge* + Annexe C |

Chaque séance suit la même trame : **Objectifs → Théorie → Démonstration guidée
→ Travaux pratiques (TP) → Livrable → Pour aller plus loin**. Les blocs de code
sont **réels** (extraits du code source de SHASEC). Les TP visent ~3 heures.

> ⚠️ **Avertissement légal.** Tout ce qui suit s'applique **uniquement** à des
> systèmes que vous possédez ou que vous êtes **explicitement autorisé** à
> tester. Scanner ou attaquer un système tiers sans autorisation écrite est un
> **délit** dans la plupart des juridictions. SHASEC matérialise cette règle
> dans le code (`Target.is_authorized` + consentement par scan) ; ce n'est pas
> optionnel, c'est ce qui sépare un outil d'audit d'une arme.

---

## Chapitre 0 — Introduction et positionnement

### 0.1 Le problème

La majorité des « scanners de sécurité » produisent des listes d'hygiène :
en-têtes manquants, versions obsolètes, ports ouverts. Utile, mais faible :

1. **Un scan ne prouve pas l'impact.** « L'endpoint `/admin/users` existe » ≠
   « j'ai lu la liste des utilisateurs sans authentification ».
2. **Le bruit noie le signal.** Dix scanners produisent dix formats, des
   doublons, des faux positifs. Personne ne lit 400 lignes.
3. **La frontière est floue.** Entre « auditer » et « attaquer », beaucoup
   d'outils n'ont aucun garde-fou : ils peuvent être pointés sur n'importe qui.

### 0.2 État de l'art

Les briques existent, séparées et hétérogènes :

| Outil | Rôle | Limite |
|---|---|---|
| **nuclei** | templates/CVE | un format, pas d'orchestration ni de corrélation |
| **nikto** | config serveur web | sortie texte, daté |
| **OWASP ZAP** | scan web actif | lourd (Java), API à piloter |
| **Burp Suite** | proxy/pentest manuel | non automatisable librement |
| **sqlmap** | exploitation SQLi | mono-vecteur |

Aucun ne fait *scanner → corréler → exploiter → prouver → rapporter* dans un
pipeline unique, avec un **modèle de données unifié** et des **garde-fous
d'autorisation**.

### 0.3 Contribution

SHASEC apporte quatre choses :

1. **Un contrat unique** (`ScannerPlugin`) : chaque scanner — interne ou externe
   — normalise sa sortie vers un seul type `Finding`. Le cœur ne connaît jamais
   nuclei ou nmap.
2. **Une corrélation déterministe** : déduplication par *fingerprint*
   agnostique du scanner, criticité = max.
3. **Un étage d'exploitation** qui transforme les findings en **preuves**
   (`Exploit`), avec requête + réponse stockées comme piste d'audit.
4. **L'autorisation comme fonctionnalité produit** : aucune exploitation sans
   cible autorisée + consentement explicite — pensé pour être **vendu à des
   agences** sans devenir une arme.

### 0.4 Méthodologie

On construit par **incréments livrables** (chaque phase est testable seule), et
on **prouve sur une vraie cible** à chaque étape. Le fil rouge de ce cours est
une API FastAPI réelle en production, `faithapi.kortexai.dev`, propriété de
l'auteur — donc autorisée.

---

## Le parcours — d'où on est parti, où on est arrivé

> Cette section est le **changelog narratif** du projet : la matière première de
> tout le cours qui suit.

### Point de départ : un fichier `shasec.txt`

Tout a commencé par une **spécification d'architecture** (`monshaapi/shasec.txt`)
sur un boilerplate `shaapi` vierge — zéro ligne de code métier. La vision :

```
Scanner → Corrélation → IA → Rapport
```

avec des modèles (Target, Scan, Finding, AIAnalysis, Report), des services, un
*Plugin Manager*, et une liste de scanners (nmap, nuclei, ZAP, nikto) et de
plugins internes (discovery, JWT, RBAC, GraphQL).

### Ce qui a été construit (l'état actuel)

| Phase | Livré | Statut |
|---|---|---|
| **0 — Fondations** | 6 modèles (`Target/Scan/Finding/AIAnalysis/Report/Exploit`), migrations Alembic, API REST unifiée `/api/v1/docs` | ✅ |
| **1 — SDK + scanners** | contrat `ScannerPlugin` + registre auto-découvert ; `http-security` (Python), `nuclei` 3.9, `nikto` 2.5, `zap` (service) | ✅ |
| **1.5 — Exploitation** | SDK `ExploitModule` + 5 modules (exposed-endpoints, api-auth-matrix, sqli, ssti, jwt), modèle `Exploit`, consentement `allow_active_exploitation` | ✅ |
| **2 — Durabilité** | worker arq + progression live WebSocket | ⏳ à venir |
| **3 — IA** | analyse Ollama : score, résumé, correctifs | ⏳ |
| **4 — Rapport** | Jinja2 → WeasyPrint → PDF → MinIO | ⏳ |

### La preuve par l'expérience

Lancé sur la vraie API `faithapi.kortexai.dev` (autorisée), un seul appel
`POST /scans/quick` a produit **11 findings + 19 preuves d'exploitation**, dont :

- 🔴 4 **HIGH** : champs sensibles (`token`/`secret`/`key`) exposés **sans
  authentification** (`/api/auth/providers`, `/api/monitoring/metrics`…) ;
- 🟠 11 **MEDIUM** : endpoints internes (`scheduler/jobs`, `logging/logs`,
  `audit/*`) accessibles **sans token** — auth oubliée ;
- 🟡 4 **LOW/info** : surface d'attaque exposée en prod (`/openapi.json`,
  `/docs`, `/redoc`).

> **La boucle.** shaapi est conçu pour résister ; SHASEC prouve s'il résiste — ou
> trouve exactement où il ne résiste pas. La sécurité n'est plus une promesse,
> c'est un test reproductible.

---

# Partie I — Construire son propre SHASEC

## Séance 1 — Modéliser le domaine de l'audit

### Objectifs
- Comprendre pourquoi un audit a besoin d'un **modèle de données**, pas juste
  d'un script.
- Poser la machine à états d'un scan et les garde-fous d'autorisation.

### Théorie — la *kill chain* d'un audit
Un pentest suit toujours la même chaîne :

```
Reconnaissance → Scan → Exploitation → Impact → Rapport
```

Chaque étape produit des artefacts qu'il faut **persister et relier** : une
*cible* (Target), un *audit* (Scan), des *vulnérabilités* (Finding), des
*preuves* (Exploit), une *synthèse* (AIAnalysis) et un *livrable* (Report). D'où
le modèle relationnel : l'URL vit sur le **Target** (on le scanne plusieurs fois
dans le temps), le **Scan** ne porte qu'un `target_id`.

### Démonstration guidée — le garde-fou dans le type
La règle d'or de l'offensive *légale* : **on ne scanne que ce qu'on est autorisé
à scanner.** Cette règle vit dans le modèle, pas dans un commentaire :

```python
class Target(Base):
    name: Mapped[str]
    url: Mapped[str]
    type: Mapped[str]   # website / api / graphql / host
    # Garde-fou : aucun scan ne démarre tant que le propriétaire n'a pas autorisé.
    is_authorized: Mapped[bool] = mapped_column(default=False)
```

Et la validation refuse les cibles locales (un scanner cloud ne peut pas les
joindre — c'est le rôle d'un agent CLI) :

```python
if _is_local_host(host):
    raise ValueError('Local or private targets are not reachable from the '
                     'deployed scanner. Use the shasec CLI agent.')
```

### TP
1. Ajoute un modèle `Project` qui regroupe des `Target`, avec un champ
   `owner_verified_at` (préparation au challenge DNS de la Séance 8).
2. Écris la migration Alembic et applique-la.

### Livrable
Une API qui stocke cibles et scans, avec le garde-fou `is_authorized` actif.

### Pour aller plus loin
Machine à états explicite (`pending → running → completed/failed`) comme **seule
source de vérité** ; toute transition future émettra un événement WebSocket.

---

## Séance 2 — Reconnaissance et le contrat plugin

### Objectifs
- Écrire le **contrat** que tout scanner respectera.
- Construire un premier scanner réel, en Python pur.

### Théorie — reconnaissance & fingerprinting
Avant d'attaquer, on **cartographie**. La reconnaissance passive lit ce que la
cible révèle gratuitement : en-têtes HTTP, bannière serveur, certificat TLS,
`/openapi.json`. Exemple : un en-tête `Server: uvicorn` révèle un backend
Python/FastAPI — une information qui oriente toutes les attaques suivantes.

Les **en-têtes de sécurité** sont le degré zéro de l'hygiène :

| En-tête | Protège contre |
|---|---|
| `Strict-Transport-Security` | downgrade HTTPS→HTTP |
| `Content-Security-Policy` | XSS / injection |
| `X-Frame-Options` | clickjacking |
| `X-Content-Type-Options` | MIME-sniffing |

### Démonstration guidée — le contrat
Tout repose sur un seul ABC. Un scanner externe (subprocess) et un scanner
interne (Python) rendent **le même type** :

```python
class ScannerPlugin(ABC):
    name: str = 'base'
    handles: tuple[str, ...] = ()      # types de cible supportés ; () = tous
    timeout: int = 120

    @abstractmethod
    async def run(self, ctx: ScanContext) -> list[RawFinding]:
        ...
```

Le premier plugin, `http-security`, n'a besoin d'aucun binaire (httpx) :

```python
class HttpSecurityPlugin(ScannerPlugin):
    name = 'http-security'
    handles = ('website', 'api', 'graphql')

    async def run(self, ctx):
        resp = await client.get(ctx.target_url)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        findings = []
        for header, (sev, title, reco) in _SECURITY_HEADERS.items():
            if header not in headers:
                findings.append(RawFinding(title=title, severity=sev.value, ...))
        return findings
```

Le **registre** auto-découvre tout module déposé dans `plugins/` qui appelle
`register()` — zéro liste centrale à éditer.

### TP
1. Écris un plugin `tls_info` qui inspecte le certificat (expiration, faiblesse
   d'algo) et émet des `RawFinding`.
2. Vérifie qu'il apparaît automatiquement dans un scan.

### Livrable
Un scan qui interroge une vraie URL et remonte ~7 findings d'en-têtes.

### Pour aller plus loin
La *normalisation* : chaque plugin traduit SON format vers `Finding`. C'est ce
qui rend le système extensible à l'infini sans toucher au cœur.

---

## Séance 3 — Intégrer les scanners du marché

### Objectifs
- Brancher nuclei, nikto et ZAP — trois modes d'intégration différents.
- Comprendre subprocess vs client-API, et l'isolation.

### Théorie — trois façons d'intégrer un outil
| Outil | Intégration | Pourquoi |
|---|---|---|
| **nuclei** | subprocess (binaire) | sort du JSONL propre à parser |
| **nikto** | subprocess (binaire Perl) | sortie fichier JSON |
| **ZAP** | **client API REST** | app Java lourde → service séparé |

Règle : un outil **léger** se wrappe en subprocess dans l'image ; un outil
**lourd** tourne comme service à part et on pilote son API.

### Démonstration guidée — skip propre
Un scanner absent ne doit **jamais** casser le scan. Chaque adaptateur le gère :

```python
class NucleiPlugin(ScannerPlugin):
    async def run(self, ctx):
        if shutil.which('nuclei') is None:
            return [RawFinding(title='nuclei not installed',
                               severity='info', ...)]   # skip propre
        code, out, _ = await run_command(
            ['nuclei', '-u', ctx.target_url, '-jsonl', '-silent'], timeout=600)
        return [self._normalize(json.loads(line)) for line in out.splitlines()]
```

ZAP, lui, est un **client** de l'API REST du démon :
`spider → active-scan → poll → GET /alerts → normalize`, et skippe si le service
est éteint.

### TP
1. Ajoute nuclei au Dockerfile (binaire) et nikto (source GitHub — il n'est plus
   packagé sur Debian trixie !).
2. Ajoute ZAP comme service `--profile zap` dans le compose.

### Livrable
Un scan qui agrège 4 scanners ; ceux dont le binaire manque skippent proprement.

### Pour aller plus loin
**Rate-limiting de la cible** : bombarder avec nuclei puis exploiter peut
déclencher un throttle. Leçon apprise en vrai → le fetch d'OpenAPI doit
**réessayer avec backoff** (voir Séance 5).

---

## Séance 4 — L'orchestration et la corrélation

### Objectifs
- Exécuter les plugins en concurrence, puis dédupliquer.
- Calculer la criticité.

### Théorie — corrélation déterministe
Deux scanners trouvent la même faille → **un seul** finding. La clé : un
*fingerprint* agnostique du scanner.

```python
def _fingerprint(target_url, rf):
    seed = rf.fingerprint_seed or rf.title
    return hashlib.sha256(f'{target_url}|{seed}'.encode()).hexdigest()[:64]

def _aggregate(target_url, tagged):
    by_fp = {}
    for plugin_name, rf in tagged:
        fp = _fingerprint(target_url, rf)
        cur = by_fp.get(fp)
        if cur is None or SEVERITY_WEIGHT[rf.severity] > SEVERITY_WEIGHT[cur[1].severity]:
            by_fp[fp] = (plugin_name, rf, fp)   # la sévérité max gagne
    return list(by_fp.values())
```

### Démonstration guidée — le pipeline
```python
async def run_pipeline(scan_id, auth_token=None):
    # status → running
    plugins = get_plugins_for(target.type)
    results = await asyncio.gather(*[_safe_run(p) for p in plugins])  # concurrence
    aggregated = _aggregate(target.url, [(n, rf) for n, rfs in results for rf in rfs])
    # persiste les findings (avec fingerprint)
    if scan.allow_active_exploitation and target.is_authorized:
        await _run_exploit_stage(scan_id, target.url, target.type, auth_token)
    # status → completed
```

Un plugin qui plante est isolé (`_safe_run`) : il ne tue jamais le scan.

### TP
1. Fais que `cancel` interrompe réellement les subprocess en cours.
2. Remplace l'exécution in-process par un worker **arq** (Redis) — durabilité.

### Livrable
Un orchestrateur qui passe `pending → running → completed`, dédupliqué.

### Pour aller plus loin
WebSocket : pousser `scan.progress` / `plugin.done` en direct au frontend.

---

## Séance 5 — De scanner à attaquant : le module d'exploitation

### Objectifs
- Comprendre l'**OWASP API Security Top 10**.
- Transformer un *soupçon* en *preuve*, de façon bornée et tracée.

### Théorie — OWASP API Security Top 10 (l'essentiel)
| # | Faille | Idée |
|---|---|---|
| API1 | **BOLA / IDOR** | accéder à l'objet d'un autre utilisateur |
| API2 | **Broken Auth** | endpoint protégé accessible sans token |
| API3 | **Excessive Data** | la réponse expose trop de champs |
| API5 | **BFLA** | un user lambda atteint une fonction admin |
| API7 | **Misconfig** | `/docs`, `.env`, debug exposés |
| API8 | **Injection** | SQL, NoSQL, template, commande |

### Théorie — scanner vs exploiter
- **Scanner** : *« cet endpoint déclare exiger une auth »* (lecture du spec).
- **Exploiter** : *« je l'ai appelé sans token et il a renvoyé 200 + des
  données »* (preuve).

### 🚩 La ligne rouge (à lire deux fois)
On construit de l'exploitation **qui prouve l'impact** :
auth bypass, JWT forge, IDOR borné, SQLi en preuve, SSTI/RCE PoC.

On ne construit **jamais** : destructif/DoS, ciblage de masse de tiers,
persistance/C2/évasion réutilisable. **L'autorisation n'est pas la question** —
même sur votre infra, un C2 reste une arme réutilisable contre autrui. La
distinction n'est pas *« à qui ça appartient »*, c'est *« la nature de
l'artefact »*. Chaque preuve est **non destructive, bornée, en périmètre, et
tracée** (requête + réponse stockées).

### Démonstration guidée — le contrat d'exploit + le vrai bug
Le contrat miroir du SDK scanner :

```python
class ExploitModule(ABC):
    name: str
    category: str        # auth-bypass / sql-injection / jwt-forgery / ...
    @abstractmethod
    async def run(self, ctx: ExploitContext) -> list[ExploitResult]: ...
```

Le module phare, `api-auth-matrix`, énumère l'API depuis `/openapi.json` et la
frappe **sans token**. Leçon clé apprise en vrai : **ne pas faire aveuglément
confiance au champ `security` du spec.** Le bug le plus fréquent du monde réel,
c'est *« le dev a oublié la dépendance d'auth »* — l'endpoint répond 200 sans
token alors que le spec ne déclare aucune sécurité :

```python
if resp.status_code == 200:
    if requires_auth:                        # spec dit "protégé" mais 200 sans token
        result(category='auth-bypass', severity='high', confirmed=True, ...)
    elif _SENSITIVE_PATH.search(path):       # spec dit "public" MAIS chemin interne
        result(category='missing-auth', severity='medium', confirmed=True, ...)
```

> Et le `_fetch_spec` **réessaie avec backoff** — sinon le rate-limit déclenché
> par nuclei juste avant le fait échouer silencieusement (bug réel rencontré).

### TP
1. Ajoute un module `exposed-endpoints` qui sonde `/.env`, `/.git/config`,
   `/actuator/env` et **confirme** par des marqueurs de contenu (pas juste 200).
2. Gate l'étage exploit derrière `allow_active_exploitation AND is_authorized`.

### Livrable
Un scan avec `allow_active_exploitation:true` qui persiste des `Exploit` avec
preuve. Sur faithapi : ~16 endpoints internes prouvés accessibles sans auth.

### Pour aller plus loin
Chaque `Exploit` stocke la réponse brute → l'auditeur **confirme à l'œil** les
HIGH (un champ nommé `token_url` n'est pas un secret).

---

## Séance 6 — Attaques authentifiées : JWT

### Objectifs
- Comprendre l'anatomie d'un JWT et ses faiblesses classiques.
- Forger un token et prouver le bypass.

### Théorie — anatomie d'un JWT
Un JWT = `base64url(header).base64url(payload).signature`. Deux faiblesses
mortelles :

1. **`alg:none`** — le serveur accepte un token *sans signature*. On remplace
   l'algo par `none`, on vide la signature, on forge n'importe quelle identité.
2. **Secret faible (HS256)** — la signature est un HMAC. Si le secret est
   devinable (`secret`, `changeme`, `your-256-bit-secret`…), on le craque
   **hors-ligne** et on signe n'importe quel token.

### Démonstration guidée — forge maison (sans dépendance)
```python
# alg:none — header forgé, signature vide
def _forge_alg_none(payload):
    header = {'alg': 'none', 'typ': 'JWT'}
    return f'{_b64e(json.dumps(header))}.{_b64e(json.dumps(payload))}.'

# secret faible — brute hors-ligne, comparaison HMAC à temps constant
for secret in _WEAK_SECRETS:
    expected = _b64e(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    if hmac.compare_digest(expected, sig_b64):
        result(severity='critical', title=f'JWT signed with weak secret "{secret}"')
```

Le token de test est fourni **transitoirement** au scan (`auth_token`) et
**jamais persisté** en base.

> 🛡️ **C'est exactement ce que shaapi anticipe** : *« une API sans état qui ne
> vérifie que la signature renverrait 200 ; shaapi renvoie 401 car les jetons
> sont aussi tracés dans Redis. »* SHASEC est l'attaquant qui le vérifie.

### TP
1. Étends la wordlist de secrets ; ajoute la détection **alg confusion**
   (RS256→HS256, signer avec la clé publique comme secret HMAC).
2. Après un secret craqué, **forge** un token `role:admin` et prouve l'accès à
   une route admin (puis arrête-toi — pas d'exfiltration).

### Livrable
Un module `jwt` qui rend CRITICAL sur `alg:none` accepté ou secret faible.

### Pour aller plus loin
BFLA/IDOR : avec un token *low-priv*, atteindre une fonction admin (priv-esc) ou
l'objet d'un autre utilisateur (BOLA) — la preuve d'impact bornée.

---

## Séance 7 — Injections : SQLi et SSTI

### Objectifs
- Détecter une injection **sans extraire ni détruire de données**.

### Théorie — prouver sans piller
- **SQLi error-based** : un simple `'` provoque une erreur SQL renvoyée au
  client → le paramètre atteint SQL non échappé. Lecture seule, sûr.
- **SQLi time-based** : injecter `SLEEP(4)` ; si la réponse met >4s → injection
  aveugle confirmée. **Un seul délai borné**, zéro donnée extraite.
- **SSTI** : injecter `{{1337*7}}` ; si la réponse contient `9359` (le produit,
  absent du payload), le serveur a **évalué** l'expression → RCE probable. PoC
  pur, aucune commande système.

### Démonstration guidée
```python
# SSTI — preuve par réflexion mathématique (pas de commande)
if _EXPECTED in r.text and _EXPECTED not in payload:   # "9359" présent
    result(category='template-injection', severity='high', confirmed=True,
           impact='Server evaluated 1337*7=9359 — likely RCE')

# SQLi — confirmation temporelle bornée
if elapsed >= _SLEEP_SECONDS - 0.5:
    result(category='sql-injection', severity='critical', confirmed=True,
           impact=f'Injected SLEEP delayed response by {elapsed:.1f}s — blind SQLi')
```

### TP
1. Ajoute la détection **boolean-based** (comparer `OR 1=1` vs `AND 1=2`).
2. Sur SSTI confirmé, démontre `id`/`whoami` **une seule fois** (preuve d'impact)
   — et pas plus.

### Livrable
Des modules `sqli` et `ssti` qui prouvent l'injection sans toucher aux données.

### Pour aller plus loin
Étendre aux injections NoSQL, en-têtes (Host/SSRF), et désérialisation.

---

# Partie II — Du laboratoire au produit

## Séance 8 — IA, rapport, et vendre l'outil

### Objectifs
- Synthétiser findings + preuves en un **livrable** vendable.
- Productiser l'autorisation pour la vente aux agences.

### 8.1 Analyse IA (Ollama)
Une `AIProvider` abstraite (impl `OllamaProvider`, endpoint
`https://ollama.traaf.app/`) prend les findings normalisés + les preuves et rend
un **score de sécurité**, un **résumé exécutif**, des **impacts** et des
**correctifs**. L'IA ne scanne jamais ; elle *interprète*.

### 8.2 Rapport PDF
`Findings + Preuves + Analyse IA → Jinja2 (HTML) → WeasyPrint (PDF) → MinIO`.
Le PDF est le livrable client : résumé exécutif, score, vulnérabilités, **preuves
d'exploitation**, correctifs.

### 8.3 Vendre à des agences : l'autorisation comme produit
Quand la cible n'est plus votre infra mais le **client de l'agence**, le
garde-fou `is_authorized` ne suffit plus : il faut une **preuve de propriété**.
→ **Challenge DNS** : l'agence prouve qu'elle contrôle le domaine en publiant un
enregistrement TXT (`shasec-verify=<token>`) avant toute exploitation. C'est ce
qui rend l'outil vendable sans devenir une arme.

### 8.4 En intégration continue
```bash
shasec scan https://staging.monapi.com || exit 1   # casse le build si HIGH/CRITICAL
```
La posture de sécurité devient un **test non-régressable**.

### 8.5 Projet final
Construire une API, la durcir avec shaapi, puis :
1. La scanner (4 scanners) jusqu'au vert.
2. L'attaquer avec consentement (`allow_active_exploitation`) → 0 preuve
   confirmée = elle résiste.
3. Générer le rapport PDF.
4. (Bonus) Brancher l'agent CLI local pour auditer une cible non-publique.

**Critères** : couverture de scan (25 %), justesse des preuves d'exploit (35 %),
0 faux positif après confirmation (20 %), rapport exploitable (20 %).

**Livrable** : un audit complet — scanné, attaqué, prouvé, rapporté.

---

## Annexe A — API REST (montée sur `/api/v1`)

```
POST /scans/quick           {url, type, allow_active_exploitation?, auth_token?}
POST /scans                 {target_id, allow_active_exploitation?}
POST /scans/{id}/start
POST /scans/{id}/cancel
GET  /scans/{id}
GET  /scans/{id}/findings
GET  /scans/{id}/exploits        # les preuves
GET  /scans/{id}/analysis
GET  /scans/{id}/reports
POST /targets/               {name, url, type}
POST /targets/{id}/authorize {is_authorized}
```

## Annexe B — Catalogue des scanners et modules

**Scanners** (`backend/app/shasec/plugins/`)
| Plugin | Type | Trouve |
|---|---|---|
| `http-security` | Python | en-têtes, transport, bannière |
| `nuclei` | binaire | CVE, templates, misconfig |
| `nikto` | binaire | config serveur web |
| `zap` | service API | scan web actif |

**Modules d'exploitation** (`backend/app/shasec/verifier/`)
| Module | Catégorie | Prouve |
|---|---|---|
| `exposed-endpoints` | exposed-endpoint | `.env`, `.git`, docs, secrets |
| `api-auth-matrix` | auth-bypass / missing-auth | endpoints sans auth |
| `jwt` | jwt-forgery | alg:none, secret faible |
| `sqli` | sql-injection | error/time-based |
| `ssti` | template-injection | RCE probable |

## Annexe C — Aide-mémoire éthique

1. **Autorisation écrite** avant tout test. Pas d'exception.
2. **Périmètre strict** : uniquement le host cible, aucun pivot.
3. **Non destructif** : prouver ≠ détruire ni exfiltrer en masse.
4. **Tracer** : chaque requête envoyée est journalisée (le `Exploit` l'est).
5. **Ce qu'on ne construit jamais** : DoS, ciblage de masse, persistance/C2,
   évasion malveillante.

## Annexe D — Dépannage (leçons réelles)

| Symptôme | Cause | Fix |
|---|---|---|
| Migration Alembic vide | `DB_AUTO_CREATE=true` recrée les tables hors-Alembic | passer à `false`, générer en conteneur one-off sans uvicorn |
| Colonne `NOT NULL` qui casse l'upgrade | lignes existantes | ajouter `server_default` |
| Exploit stage 0 résultat après scan | rate-limit de la cible post-nuclei | retry + backoff sur le fetch OpenAPI |
| `.id` à `None` après create | `create_model` ne flush pas | `await db.flush()` avant de lire `.id` |

---

## Conclusion

SHASEC défend une idée simple : **un audit doit prouver, pas suggérer** — et il
doit le faire **dans un cadre autorisé, borné et tracé**. La concrétisation est
une boucle : *scanner* (voir), *corréler* (dédupliquer), *exploiter* (prouver),
*rapporter* (livrer). Construit en partant d'un simple `shasec.txt`, l'outil a
trouvé, en quelques heures, 19 failles réelles sur une API en production — sans
jamais sortir de sa cible ni rien détruire.

> *« shaapi est conçu pour résister à SHASEC ; SHASEC prouve qu'il résiste — ou
> montre exactement où il faut corriger. »*

**Travaux futurs** : worker arq durable, progression live, analyse IA, rapport
PDF, modules IDOR/BFLA authentifiés, et le challenge DNS de propriété pour la
distribution aux agences.
