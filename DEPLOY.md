# Déploiement SHASEC (GitHub Actions → GHCR → Dokploy)

## Pipeline

```
push main ──► GitHub Actions (.github/workflows/build.yml)
              └─ build l'image (Dockerfile) ──► push ghcr.io/shalom-302/shasec:latest
                                                 └─ Dokploy pull (compose.image.yml) ──► prod
```

## 1. GitHub Actions

Aucun secret à configurer : le workflow utilise `GITHUB_TOKEN` (intégré) pour
pousser sur **GHCR**. Au premier push sur `main`, l'image est publiée sous
`ghcr.io/shalom-302/shasec`.

> Rends les packages GHCR **publics** (ou donne à Dokploy un token de lecture) :
> GitHub → repo → Packages → `shasec` **et** `shasec-web` → Package settings → Change visibility.

## 2. Dokploy

1. **Create Application → Docker Compose**, source = ce repo, fichier `compose.image.yml`.
2. **Le stack boote désormais sans config** : l'infra (postgres/minio/redis) a des
   valeurs par défaut qui passent le garde-fou prod. Mais pour une **vraie prod**,
   règle ces variables dans le panneau **Environment** :

   **Sécurité — à régler (sinon JWT forgeables / storage faible) :**
   | Variable | Valeur |
   |---|---|
   | `TOKEN_SECRET_KEY` | `python -c "import secrets;print(secrets.token_urlsafe(32))"` |
   | `OPERA_LOG_ENCRYPT_SECRET_KEY` | `python -c "import os;print(os.urandom(32).hex())"` |
   | `POSTGRES_PASSWORD` | un mot de passe fort (override le défaut) |
   | `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY` | identifiants MinIO forts |

   **Fonctionnel :**
   | Variable | Rôle |
   |---|---|
   | `MINIO_CLOUD_URL` | URL publique MinIO (liens de téléchargement des rapports) |
   | `DEEPSEEK_API_KEY` | clé api.deepseek.com (analyse IA + rapport FR ; vide = IA désactivée) |

   > **Pourquoi le 1er deploy échouait** (`postgres-1 is unhealthy`) : `POSTGRES_PASSWORD`
   > était **vide** → l'image postgres refuse de s'initialiser. C'est corrigé : le
   > compose fournit un défaut non-trivial. ⚠️ Si tu changes `POSTGRES_PASSWORD` APRÈS
   > un 1er boot, supprime le volume `pgdata` (il garde l'ancien mot de passe).

3. **Domaines** (onglet *Domains* de l'app compose, un domaine par service) :
   | Service | Port | Rôle |
   |---|---|---|
   | `web` | **3000** | Console Kortex Security (Next.js) — c'est l'URL publique des clients |
   | `api` | **8000** | API (Swagger, CLI shasec, Hermes). Optionnel pour le web : il joint l'API en interne via `http://api:8000` |

   En **HTTP** : décoche *HTTPS* sur le domaine et laisse `WEB_COOKIE_SECURE` à `false`.
   Quand tu passes en **HTTPS** (Let's Encrypt dans Dokploy), mets `WEB_COOKIE_SECURE=true`
   pour que les cookies de session aient le flag `Secure`.
4. **Deploy**. L'entrypoint applique les migrations (`alembic upgrade head`) au boot.

## 3. Mise à jour

Chaque push sur `main` republie les images `shasec:latest` et `shasec-web:latest`
(même repo, deux images : `Dockerfile` racine et `shasec-web/Dockerfile`) ; clique **Redeploy** dans
Dokploy (ou configure l'auto-deploy / webhook GHCR) pour tirer la nouvelle image.

## Notes

- `docker-compose.yml` (à la racine) reste le compose **de dev** (build local +
  bind-mount + hot-reload). `compose.image.yml` est le compose **de prod**.
- ZAP n'est pas inclus en prod par défaut (lourd) ; ajoute le service au besoin.
- Le worker arq + WebSocket (durabilité, tâche #5) n'est pas encore branché —
  les scans tournent in-process pour l'instant.
