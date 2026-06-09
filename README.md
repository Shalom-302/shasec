# monshaapi

A lean, batteries-included **FastAPI** backend, generated with
[shaapi](https://github.com/Shalom-302/shaapi). Async SQLAlchemy + Alembic,
Postgres, Redis, JWT auth and Casbin RBAC, file storage, i18n and a
one-command Docker workflow — ready to build on.

> This project was scaffolded by `shaapi`. The `shaapi` command is also your
> day-to-day runner: it wraps `docker compose` directly, so the same commands
> work on **Windows, macOS and Linux** (no bash required).

## Quick start

```bash
shaapi up              # build + start the whole stack (dev: hot-reload)
shaapi db apply        # apply database migrations
shaapi auth init       # create an admin user to log into Swagger
shaapi storage init    # create the object-storage bucket
```

Then open:

- **API**: http://localhost:8000
- **Swagger**: http://localhost:8000/admin/api/v1/docs

> On Linux/macOS you can use the bundled `./docker-run.sh` instead of `shaapi`
> if you prefer a plain shell script — both drive the same Docker stack.

## Commands

Everything runs through `shaapi` (cross-platform) — no need to memorize raw
`docker compose` incantations. Commands are grouped by domain:

**Lifecycle**

```bash
shaapi up [--monitoring] [--prod]   # build + start (monitoring/prod optional)
shaapi down                         # stop and remove containers
shaapi logs [service]               # tail logs (e.g. shaapi logs api)
shaapi restart [service]            # restart all, or one service
shaapi ps                           # container status
shaapi shell                        # bash inside the api container
shaapi redis                        # redis-cli inside Redis
```

**Database (`db`)**

```bash
shaapi db generate --message "add posts table"   # autogenerate a migration
shaapi db apply                                   # alembic upgrade head
shaapi db preview                                 # SQL that apply would run
shaapi db pending                                 # current revision vs. head
shaapi db shell                                   # psql inside Postgres
```

**Auth (`auth`) & Storage (`storage`)**

```bash
shaapi auth init      # create an admin user (email + password)
shaapi storage init   # ensure the MinIO/S3 bucket exists
```

The equivalent `./docker-run.sh` subcommands exist for shell users on Unix
(`up`, `down`, `logs`, `migrate`, `makemigrations`, `shell`, …).

## What's inside

- **FastAPI** (async) with a layered architecture (`app/`, `common/`, `core/`,
  `crud/`, `models/`, `database/`, `middleware/`, `utils/`).
- **SQLAlchemy 2 + Alembic** migrations on **Postgres** (auto-create tables in
  dev, migrations in prod).
- **Redis** cache + rate limiting.
- **JWT auth** (sign in / sign up) + **Casbin RBAC** (users, roles, permissions).
- **File storage** (MinIO / S3 / GCS).
- **i18n** (English + French) and request-scoped translation middleware.
- **Login & operation logs**, request tracing (correlation id).
- **Realtime** via python-socketio.
- **Opt-in observability** (`shaapi up --monitoring`): Prometheus, Grafana,
  Tempo, Loki.
- **Docker**: multi-stage slim image built with [uv], hot-reload in dev.

## Project structure

```
backend/
├── app/            # Feature sub-apps (admin: auth, users, roles, RBAC, logs)
│   └── admin/
│       ├── api/        # API route handlers
│       ├── schema/     # Pydantic request/response models
│       └── service/    # Business logic
├── common/         # Cross-cutting: security, exceptions, responses, socketio…
├── core/           # Settings (conf.py), app registrar, paths
├── crud/           # Reusable async CRUD over the models
├── database/       # Postgres + Redis connections
├── middleware/     # Access log, i18n, operation log, state
├── models/         # SQLAlchemy models
├── lang/           # i18n message catalogs (en, fr)
├── seeder/         # Database seeds (incl. an example admin)
├── utils/          # Helpers (timezone, encrypt, serializers, health…)
├── cli.py          # In-container commands (used by `shaapi auth init`)
└── main.py         # Application entry point
devops/             # Compose helpers / infra
etc/                # Monitoring configs (only when generated with monitoring)
Dockerfile
docker-compose.yml
docker-compose.override.yml      # dev: bind-mount + hot-reload
docker-compose.monitoring.yml    # opt-in observability stack
docker-run.sh                    # shell runner (Unix); `shaapi` is the cross-platform equivalent
.env.template                    # copied to .env on first run
pyproject.toml / uv.lock         # dependencies, managed with uv
```

## Configuration

On first `shaapi up`, a `.env` is created from `.env.template`. Every value has
a sane default in `backend/core/conf.py`, so you only override what differs.
When running under Docker Compose, the database/Redis/MinIO hosts are pointed
at the container service names automatically.

Common variables:

| Variable | Purpose |
| --- | --- |
| `ENVIRONMENT` | `dev`, `preprod` or `prod`. |
| `POSTGRES_*` | Postgres host, port, user, password, database. |
| `REDIS_*` | Redis host, port, password, database index. |
| `MINIO_*` | Object storage endpoint, keys, bucket. |
| `TOKEN_SECRET_KEY` | Secret used to sign JWT access tokens. |
| `SMTP_*` / `EMAILS_FROM_*` | Outgoing mail. |
| `OBSERVABILITY_ENABLED` / `OTLP_GRPC_ENDPOINT` | Opt-in tracing/metrics export. |

## Database migrations

```bash
shaapi db generate --message "add posts table"   # autogenerate from model changes
shaapi db preview                                 # inspect the SQL first
shaapi db apply                                   # apply (alembic upgrade head)
shaapi db pending                                 # current revision vs. head
```

## Authentication

`shaapi auth init` creates the first admin user (with the `admin` role) inside
the running API container; you then log in from Swagger at
`/admin/api/v1/docs`. No admin is seeded by default — create yours with
`shaapi auth init`.

## License

MIT
