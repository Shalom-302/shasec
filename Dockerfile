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
        nmap whois dnsutils \
        whatweb dirb bash openssl \
    && rm -rf /var/lib/apt/lists/*
# nmap (port/service recon), whois + dnsutils (dig) power the dns-recon and nmap
# shasec plugins. whatweb = fingerprinting (Phase 4); dirb ships the common.txt
# wordlist ffuf uses for content discovery (Phase 5); bash + openssl back
# testssl.sh (Phase 4). All plugins degrade gracefully when a tool is absent,
# but baking them in means the recon/fingerprinting phases work out of the box.

# nuclei (ProjectDiscovery) — security scanner binary baked into the image so
# the shasec nuclei plugin can run. Version is PINNED (no api.github.com call —
# that endpoint rate-limits shared CI runner IPs). Download is retried and
# non-fatal: a transient GitHub hiccup must not break the CI build/deploy — the
# nuclei plugin skips cleanly at runtime when the binary is absent.
ARG NUCLEI_VERSION=3.3.7
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends unzip ca-certificates; \
    arch="$(dpkg --print-architecture)"; \
    if curl -fsSL --retry 5 --retry-delay 3 --retry-all-errors --connect-timeout 20 \
        -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${arch}.zip"; then \
        unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei && chmod +x /usr/local/bin/nuclei && rm /tmp/nuclei.zip; \
    else \
        echo "WARNING: nuclei download failed — image builds without it; the plugin will skip at runtime"; \
    fi; \
    apt-get purge -y unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# nikto (web-server scanner) — not packaged on Debian trixie, so install the
# Perl source from GitHub. Retried + non-fatal for the same CI-resilience reason
# as nuclei above (the nikto plugin skips cleanly when the binary is absent).
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends perl libnet-ssleay-perl libjson-perl ca-certificates; \
    if curl -fsSL --retry 5 --retry-delay 3 --retry-all-errors --connect-timeout 20 \
        -o /tmp/nikto.tar.gz https://github.com/sullo/nikto/archive/refs/tags/2.5.0.tar.gz; then \
        mkdir -p /opt && tar -xzf /tmp/nikto.tar.gz -C /opt && \
        printf '#!/bin/sh\nexec perl /opt/nikto-2.5.0/program/nikto.pl "$@"\n' > /usr/local/bin/nikto && \
        chmod +x /usr/local/bin/nikto && rm /tmp/nikto.tar.gz; \
    else \
        echo "WARNING: nikto download failed — image builds without it; the plugin will skip at runtime"; \
    fi; \
    rm -rf /var/lib/apt/lists/*

# httpx + katana (ProjectDiscovery, Go) — recon allies. Pinned, retried,
# non-fatal (the plugins skip cleanly when a binary is absent). httpx is renamed
# httpx-pd so it never clashes with the Python httpx CLI.
ARG HTTPX_VERSION=1.9.0
ARG KATANA_VERSION=1.6.1
ARG SUBFINDER_VERSION=2.6.6
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends unzip ca-certificates; \
    arch="$(dpkg --print-architecture)"; \
    if curl -fsSL --retry 5 --retry-delay 3 --retry-all-errors --connect-timeout 20 \
        -o /tmp/httpx.zip "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${arch}.zip"; then \
        unzip -o /tmp/httpx.zip -d /tmp/httpx httpx && mv /tmp/httpx/httpx /usr/local/bin/httpx-pd \
        && chmod +x /usr/local/bin/httpx-pd && rm -rf /tmp/httpx /tmp/httpx.zip; \
    else echo "WARNING: httpx download failed — the httpx plugin will skip at runtime"; fi; \
    if curl -fsSL --retry 5 --retry-delay 3 --retry-all-errors --connect-timeout 20 \
        -o /tmp/katana.zip "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${arch}.zip"; then \
        unzip -o /tmp/katana.zip -d /usr/local/bin katana && chmod +x /usr/local/bin/katana && rm /tmp/katana.zip; \
    else echo "WARNING: katana download failed — the katana plugin will skip at runtime"; fi; \
    if curl -fsSL --retry 5 --retry-delay 3 --retry-all-errors --connect-timeout 20 \
        -o /tmp/subfinder.zip "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${arch}.zip"; then \
        unzip -o /tmp/subfinder.zip -d /usr/local/bin subfinder && chmod +x /usr/local/bin/subfinder && rm /tmp/subfinder.zip; \
    else echo "WARNING: subfinder download failed — the subfinder plugin will skip at runtime"; fi; \
    apt-get purge -y unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# ffuf (Go, content discovery — Phase 5) + testssl.sh (TLS analysis — Phase 4).
# Pinned, retried, non-fatal — the plugins skip cleanly when a tool is absent.
ARG FFUF_VERSION=2.1.0
ARG TESTSSL_VERSION=3.2.1
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends unzip ca-certificates; \
    arch="$(dpkg --print-architecture)"; \
    if curl -fsSL --retry 5 --retry-delay 3 --retry-all-errors --connect-timeout 20 \
        -o /tmp/ffuf.tar.gz "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${arch}.tar.gz"; then \
        tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf && chmod +x /usr/local/bin/ffuf && rm /tmp/ffuf.tar.gz; \
    else echo "WARNING: ffuf download failed — the ffuf plugin will skip at runtime"; fi; \
    if curl -fsSL --retry 5 --retry-delay 3 --retry-all-errors --connect-timeout 20 \
        -o /tmp/testssl.tar.gz "https://github.com/drwetter/testssl.sh/archive/refs/tags/v${TESTSSL_VERSION}.tar.gz"; then \
        mkdir -p /opt && tar -xzf /tmp/testssl.tar.gz -C /opt && \
        ln -sf "/opt/testssl.sh-${TESTSSL_VERSION}/testssl.sh" /usr/local/bin/testssl.sh && \
        chmod +x "/opt/testssl.sh-${TESTSSL_VERSION}/testssl.sh" && rm /tmp/testssl.tar.gz; \
    else echo "WARNING: testssl.sh download failed — the testssl plugin will skip at runtime"; fi; \
    apt-get purge -y unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

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
