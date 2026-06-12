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

# Runtime system deps (libpq for Postgres, curl for healthchecks, and the
# Pango/Cairo/GDK-PixBuf stack WeasyPrint needs to render report PDFs).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpq5 curl \
        libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
        libffi8 shared-mime-info fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# nuclei (ProjectDiscovery) — security scanner binary baked into the image so
# the shasec nuclei plugin can run. Pulls the latest release, falls back to a
# pinned version if the GitHub API is unavailable at build time.
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends unzip ca-certificates; \
    ver="$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | grep -oP '\"tag_name\":\s*\"v\K[^\"]+' || echo 3.3.7)"; \
    arch="$(dpkg --print-architecture)"; \
    curl -fsSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${ver}/nuclei_${ver}_linux_${arch}.zip"; \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei; \
    chmod +x /usr/local/bin/nuclei; \
    rm /tmp/nuclei.zip; \
    apt-get purge -y unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# nikto (web-server scanner) — not packaged on Debian trixie, so install the
# Perl source from GitHub and expose a small wrapper on PATH.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends perl libnet-ssleay-perl libjson-perl ca-certificates; \
    curl -fsSL -o /tmp/nikto.tar.gz https://github.com/sullo/nikto/archive/refs/tags/2.5.0.tar.gz; \
    mkdir -p /opt; \
    tar -xzf /tmp/nikto.tar.gz -C /opt; \
    printf '#!/bin/sh\nexec perl /opt/nikto-2.5.0/program/nikto.pl "$@"\n' > /usr/local/bin/nikto; \
    chmod +x /usr/local/bin/nikto; \
    rm /tmp/nikto.tar.gz; \
    rm -rf /var/lib/apt/lists/*

# Bring in the pre-built virtualenv (lives outside /app so dev bind-mounts work)
COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LANG=C.UTF-8 \
    # Writable home for the non-root user so nuclei can cache its templates
    # (downloaded on first run) under /home/app.
    HOME=/home/app

# Run as a non-root user (least privilege: limits the blast radius of an RCE).
RUN groupadd --system app && useradd --system --gid app --no-create-home app

# Application source
COPY . .

# Make the entrypoint executable and hand ownership of the app + venv to the
# non-root user (so it can write the log/ dir, byte-compile, etc.).
RUN chmod +x ./backend/entrypoint-api.sh \
    && mkdir -p /home/app \
    && chown -R app:app /app /opt/venv /home/app

USER app

EXPOSE 8000

ENTRYPOINT ["bash", "./backend/entrypoint-api.sh"]
