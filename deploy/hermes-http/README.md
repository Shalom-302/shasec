# Brancher Hermes sur shasec (chat admin)

Objectif : la chatbox `/admin/hermes` de shasec envoie du langage naturel à Hermes,
qui pilote shasec (scans/findings), et renvoie sa réponse — comme sur WhatsApp,
mais en web. Rien n'est exposé en public ; tout passe par un réseau Docker interne.

Hermes n'a pas d'API HTTP de chat : il répond à un prompt unique via `hermes -z`.
Le petit serveur `server.py` (ici) traduit `POST /chat` → `hermes -z` → `{"reply": …}`.
Il tourne **dans l'image Hermes existante** (aucune réinstallation) et n'écoute que
sur le réseau interne.

## 0. Réseau partagé (une fois)
```bash
docker network create hermes-link
```

## 1. Côté Hermes — ajouter l'adaptateur (`/opt/hermes-defender`)
Copie `server.py` dans `/opt/hermes-defender/hermes-http/server.py`, choisis un jeton
partagé, et ajoute ce service au `docker-compose.yml` de hermes-defender :

```yaml
  hermes-http:
    image: ghcr.io/shalom-302/hermes-defender:main   # la MÊME image, pas de réinstall
    container_name: hermes-http
    restart: unless-stopped
    user: "${HERMES_UID:-10000}:${HERMES_GID:-10000}"
    env_file: .env                                    # ANTHROPIC_API_KEY, etc.
    environment:
      HERMES_HOME: /opt/data
      HERMES_BIN: /opt/hermes/.venv/bin/hermes
      HERMES_SKILLS: shasec                           # il charge la skill qui pilote shasec
      HERMES_ADAPTER_TOKEN: ${HERMES_ADAPTER_TOKEN}    # même valeur que HERMES_TOKEN côté shasec
      HERMES_RUN_TIMEOUT: "300"
    entrypoint: ["/opt/hermes/.venv/bin/python", "/opt/adapter/server.py"]
    volumes:
      - hermes-data:/opt/data                         # même mémoire/auth que le gateway
      - ./skills/shasec:/opt/data/skills/shasec:ro
      - ./hermes-http/server.py:/opt/adapter/server.py:ro
    networks:
      - hermes-link                                   # joignable par shasec, zéro port public
```

Et en bas du même fichier, déclare le réseau externe :
```yaml
networks:
  whatsapp-shared-network:
    external: true
  hermes-link:
    external: true
```

Mets le jeton dans `/opt/hermes-defender/.env` :
```
HERMES_ADAPTER_TOKEN=<un-long-secret-aléatoire>
```

Démarre :
```bash
docker compose up -d hermes-http
docker compose logs -f hermes-http      # doit afficher "hermes-http adapter on :8700"
```

## 2. Côté shasec (stack Dokploy `shalom-shasec-kgg88c`)
`compose.image.yml` a déjà le nécessaire (réseau `hermes-link` externe + variables
`HERMES_URL`/`HERMES_TOKEN` sur l'`api`). Dans Dokploy, ajoute les variables d'env :
```
HERMES_URL=http://hermes-http:8700/chat
HERMES_TOKEN=<le-même-secret-que-HERMES_ADAPTER_TOKEN>
```
puis redeploy. (Le réseau `hermes-link` doit exister — étape 0 — avant le deploy.)

## 3. Test
Depuis le conteneur api de shasec :
```bash
docker exec <api> curl -s -X POST http://hermes-http:8700/chat \
  -H "Authorization: Bearer $HERMES_TOKEN" -H 'Content-Type: application/json' \
  -d '{"message":"présente-toi en une phrase","session_id":"admin-1"}'
```
Puis dans l'app : **Admin → Hermes (assistant)**, et écris un message.

## À vérifier / ajuster
- **Sortie de `hermes -z`** : l'adaptateur renvoie tout le stdout (nettoyé des codes
  couleur). Si Hermes y mêle des logs, regarde `docker compose logs hermes-http` et on
  filtrera (ex. ne garder que la dernière réponse). C'est le seul point à caler sur le
  vrai Hermes.
- **Durée** : un vrai audit lancé par Hermes peut durer des minutes ; `HERMES_RUN_TIMEOUT`
  (adaptateur) et le timeout HTTP backend sont à 300 s. Monte-les si besoin.
- **`--yolo`** : l'adaptateur auto-approuve les actions de l'agent. Sur le **defender**
  (privilégié), c'est admin-only — acceptable pour la phase 1. Pour le premium, voir §4.

## 4. Plus tard — instance client sandboxée (premium)
Même image, 2ᵉ conteneur, **sans les montages hôte**, mémoire par client :
```yaml
  hermes-client:
    image: ghcr.io/shalom-302/hermes-defender:main
    container_name: hermes-client
    restart: unless-stopped
    user: "10000:10000"
    env_file: .env
    environment:
      HERMES_HOME: /opt/data
      HERMES_BIN: /opt/hermes/.venv/bin/hermes
      HERMES_SKILLS: shasec
      HERMES_PROFILE_PREFIX: "client-"      # chaque session => profil isolé (-p client-<session>)
      HERMES_ADAPTER_TOKEN: ${HERMES_CLIENT_TOKEN}
    entrypoint: ["/opt/hermes/.venv/bin/python", "/opt/adapter/server.py"]
    volumes:
      - hermes-client-data:/opt/data        # volume SÉPARÉ du defender
      - ./skills/shasec:/opt/data/skills/shasec:ro
      - ./hermes-http/server.py:/opt/adapter/server.py:ro
      # PAS de /var/log, /etc/passwd, scripts, allowlist → sandbox
    networks:
      - hermes-link
```
Côté shasec on pointera alors les clients premium vers `http://hermes-client:8700/chat`,
tandis que l'admin garde le defender. C'est ainsi que le defender reste le « gardien »
et que tu contrôles le tempo.
```
```
