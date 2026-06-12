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

> Rends le package GHCR **public** (ou donne à Dokploy un token de lecture) :
> GitHub → repo → Packages → `shasec` → Package settings → Change visibility.

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

3. **Domaine** : pointe le domaine Dokploy vers le service `api`, port **8000**.
4. **Deploy**. L'entrypoint applique les migrations (`alembic upgrade head`) au boot.

## 3. Mise à jour

Chaque push sur `main` republie l'image `:latest` ; clique **Redeploy** dans
Dokploy (ou configure l'auto-deploy / webhook GHCR) pour tirer la nouvelle image.

## Notes

- `docker-compose.yml` (à la racine) reste le compose **de dev** (build local +
  bind-mount + hot-reload). `compose.image.yml` est le compose **de prod**.
- ZAP n'est pas inclus en prod par défaut (lourd) ; ajoute le service au besoin.
- Le worker arq + WebSocket (durabilité, tâche #5) n'est pas encore branché —
  les scans tournent in-process pour l'instant.
