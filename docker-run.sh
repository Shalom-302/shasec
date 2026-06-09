#!/bin/bash
# Manage the monshaapi Docker stack.
#
# Usage: ./docker-run.sh [command] [--monitoring] [--prod]
#
# Commands:
#   up           Start all containers (default)
#   down         Stop all containers
#   build        (Re)build the API image
#   logs         Tail logs from all services
#   api-logs     Tail API logs only
#   restart      Restart all containers
#   restart-api  Restart only the API container
#   dev          Start deps in background + API in foreground (live logs)
#   shell        Open a shell inside the API container
#   db           psql into Postgres
#   redis        redis-cli into Redis
#   migrate      Apply database migrations (alembic upgrade head)
#   makemigrations [msg]  Generate a new migration from model changes
#   ps           Show container status
#
# Options:
#   --monitoring  Include the Prometheus/Grafana/Tempo/Loki stack
#   --prod        Production mode: no source bind-mount, serve the baked image
set -e

cd "$(dirname "$0")"

# Pick a compose command (v2 plugin preferred)
if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DC="docker-compose"
else
  echo "❌ Docker Compose not found. Install Docker Desktop or the compose plugin."
  exit 1
fi

# Create .env from template on first run
if [ ! -f .env ]; then
  echo "ℹ️  No .env found — creating one from .env.template"
  cp .env.template .env
fi

# Parse positional command + flags
MONITORING=false
PROD=false
POSITIONAL=()
for arg in "$@"; do
  case "$arg" in
    --monitoring) MONITORING=true ;;
    --prod)       PROD=true ;;
    *)            POSITIONAL+=("$arg") ;;
  esac
done
COMMAND="${POSITIONAL[0]:-up}"

# Compose file composition
FILES="-f docker-compose.yml"
if [ "$PROD" = false ]; then
  FILES="$FILES -f docker-compose.override.yml"   # dev: bind-mount + reload
fi
if [ "$MONITORING" = true ]; then
  FILES="$FILES -f docker-compose.monitoring.yml"
  echo "🔍 Monitoring enabled — Grafana: http://localhost:3000  Prometheus: http://localhost:9090"
fi
DC="$DC $FILES"

case "$COMMAND" in
  up)
    echo "Starting monshaapi..."
    $DC up -d --build
    echo "✅ API: http://localhost:8000  |  Swagger: http://localhost:8000/admin/api/v1/docs"
    ;;
  down)        $DC down ;;
  build)       $DC build ;;
  logs)        $DC logs -f ;;
  api-logs)    $DC logs -f api ;;
  restart)     $DC restart ;;
  restart-api) $DC restart api ;;
  dev)
    $DC up -d postgres redis minio
    $DC up --build api
    ;;
  shell)       $DC exec api bash ;;
  db)          $DC exec postgres psql -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DATABASE:-monshaapi}" ;;
  redis)       $DC exec redis redis-cli ;;
  migrate)     $DC exec api bash -c "cd backend && alembic upgrade head" ;;
  makemigrations)
    MSG="${POSITIONAL[1]:-auto}"
    $DC exec api bash -c "cd backend && alembic revision --autogenerate -m '$MSG'"
    ;;
  ps)          $DC ps ;;
  *)
    echo "Unknown command: $COMMAND"
    echo "Run: up | down | build | logs | api-logs | restart | restart-api | dev | shell | db | redis | migrate | makemigrations | ps   [--monitoring] [--prod]"
    exit 1
    ;;
esac
