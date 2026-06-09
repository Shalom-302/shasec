# syntax=docker/dockerfile:1
# ============================================================================
# Stage 1 — builder: resolve & install dependencies into an isolated venv
# ============================================================================
FROM python:3.11-slim AS builder

# uv binary (fast, reproducible installs)
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /uvx /bin/

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    # Keep the venv OUTSIDE /app so a dev bind-mount of the source (.:/app)
    # never shadows the installed dependencies.
    UV_PROJECT_ENVIRONMENT=/opt/venv

# System build dependencies (asyncpg / cryptography / libpq)
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Optional extras (e.g. "--extra monitoring"); empty for the lean default.
ARG EXTRAS=""

# Install dependencies first (cached layer; only re-runs when deps change)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project ${EXTRAS}

# ============================================================================
# Stage 2 — runtime: slim image with only what's needed to run
# ============================================================================
FROM python:3.11-slim

WORKDIR /app

# Runtime system deps (libpq for Postgres, curl for healthchecks)
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

# Bring in the pre-built virtualenv (lives outside /app so dev bind-mounts work)
COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LANG=C.UTF-8

# Run as a non-root user (least privilege: limits the blast radius of an RCE).
RUN groupadd --system app && useradd --system --gid app --no-create-home app

# Application source
COPY . .

# Make the entrypoint executable and hand ownership of the app + venv to the
# non-root user (so it can write the log/ dir, byte-compile, etc.).
RUN chmod +x ./backend/entrypoint-api.sh \
    && chown -R app:app /app /opt/venv

USER app

EXPOSE 8000

ENTRYPOINT ["bash", "./backend/entrypoint-api.sh"]
