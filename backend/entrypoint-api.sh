#!/bin/bash
set -e

cd backend

# Apply database migrations (idempotent: no-op if already up to date).
# Migrations are authored explicitly with `shaapi db generate`, never
# auto-generated at boot.
alembic upgrade head

# Live-reload in development (the source is bind-mounted by the dev compose).
# In production (ENVIRONMENT=prod) the baked-in code is served without reload.
RELOAD=""
if [ "${ENVIRONMENT:-dev}" = "dev" ]; then
  RELOAD="--reload"
fi

# Start the API server (exec => uvicorn becomes PID 1 and receives signals)
exec uvicorn backend.main:app --host 0.0.0.0 --port 8000 $RELOAD
