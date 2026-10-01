# syntax=docker/dockerfile:1.4
# ==============================================================================
# Cyrene Exchange Unified Production Multi-Repository Container
# Combines:
#   1. Cyrene-Client (Navigator Web Console frontend)
#   2. Cyrene-Platform (Rust capability resolver)
#   3. Cyrene-Plugins-Official (Python Model Provider SDK & Connectors)
#   4. Cyrene-Exchange (API Gateway & Product Control/Data Plane)
# ==============================================================================

# --- Stage 1: Build Web Client (Node.js) ---
FROM node:24-alpine AS web-builder
WORKDIR /app/client
COPY Cyrene-Client/package.json Cyrene-Client/package-lock.json ./
RUN npm ci
COPY Cyrene-Client/ ./
RUN npm run build

# --- Stage 2: Build Platform Capability Resolver (Rust) ---
FROM rust:1.96.1-slim-bookworm AS platform-builder
WORKDIR /app/Cyrene-Platform

RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev git && rm -rf /var/lib/apt/lists/*

COPY Cyrene-Platform/ ./

RUN cargo build --locked --release -p cy-platform-api --bin cyrene-capability-resolver

# --- Stage 3: Runtime Image (Python 3.12) ---
FROM python:3.12-slim-bookworm AS runtime

ARG CYRENE_RUNTIME_MAINTENANCE_MANIFEST_SHA256
ARG CYRENE_RUNTIME_MAINTENANCE_WHEEL_SHA256
ARG CYRENE_RUNTIME_MAINTENANCE_RELEASE_ID

LABEL io.cyrene.runtime-maintenance.sdk-version="0.1.0" \
      io.cyrene.runtime-maintenance.manifest-sha256="${CYRENE_RUNTIME_MAINTENANCE_MANIFEST_SHA256}" \
      io.cyrene.runtime-maintenance.wheel-sha256="${CYRENE_RUNTIME_MAINTENANCE_WHEEL_SHA256}" \
      io.cyrene.runtime-maintenance.release-id="${CYRENE_RUNTIME_MAINTENANCE_RELEASE_ID}"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/usr/local/bin:/app/.venv/bin:$PATH" \
    CYRENE_DATABASE_PATH="/data/exchange.sqlite3" \
    CYRENE_HOST="0.0.0.0" \
    CYRENE_PORT="8000" \
    CYRENE_WEB_DIST="/app/exchange/web_dist"

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Copy Platform binary
COPY --from=platform-builder /app/Cyrene-Platform/target/release/cyrene-capability-resolver /usr/local/bin/cyrene-capability-resolver

WORKDIR /app

# Install the immutable, release-verified runtime maintenance SDK wheel.
COPY --from=runtime-maintenance-wheel /cyrene_runtime_maintenance-0.1.0-py3-none-any.whl /tmp/wheels/cyrene_runtime_maintenance-0.1.0-py3-none-any.whl
RUN printf '%s\n' "$CYRENE_RUNTIME_MAINTENANCE_MANIFEST_SHA256" | grep -Eq '^[0-9a-f]{64}$' && \
    printf '%s\n' "$CYRENE_RUNTIME_MAINTENANCE_WHEEL_SHA256" | grep -Eq '^[0-9a-f]{64}$' && \
    test -n "$CYRENE_RUNTIME_MAINTENANCE_RELEASE_ID" && \
    printf '%s  %s\n' "$CYRENE_RUNTIME_MAINTENANCE_WHEEL_SHA256" \
        /tmp/wheels/cyrene_runtime_maintenance-0.1.0-py3-none-any.whl | sha256sum -c - && \
    python -m pip install --no-cache-dir --no-deps \
        /tmp/wheels/cyrene_runtime_maintenance-0.1.0-py3-none-any.whl && \
    rm -rf /tmp/wheels

# Copy Plugins SDK & Core Providers
COPY Cyrene-Plugins-Official/sdk/python/cyrene_model_provider_contracts /app/plugins-sdk/cyrene_model_provider_contracts
COPY Cyrene-Plugins-Official/sdk/python/cyrene_plugin_runtime /app/plugins-sdk/cyrene_plugin_runtime
COPY Cyrene-Plugins-Official/plugins/providers/model-api-connector /app/plugins-sdk/model-api-connector

# Install Plugins SDK into Python site-packages
RUN pip install --no-cache-dir \
    /app/plugins-sdk/cyrene_model_provider_contracts \
    /app/plugins-sdk/cyrene_plugin_runtime \
    /app/plugins-sdk/model-api-connector

# Copy Exchange Source & Product
COPY Cyrene-Services/Cyrene-Exchange/pyproject.toml Cyrene-Services/Cyrene-Exchange/README.md /app/exchange/
COPY Cyrene-Services/Cyrene-Exchange/src /app/exchange/src
COPY Cyrene-Services/Cyrene-Exchange/product /app/exchange/product

# Install Exchange & Product with FastAPI / Uvicorn dependencies
RUN pip install --no-cache-dir /app/exchange && \
    pip install --no-cache-dir /app/exchange/product

# Copy Web UI build output
COPY --from=web-builder /app/client/dist /app/exchange/web_dist

# Create data directory and non-root user
RUN mkdir -p /data && \
    useradd -u 10001 -m -s /bin/bash cyrene && \
    chown -R cyrene:cyrene /data /app

# Copy entrypoint script
COPY Cyrene-Services/Cyrene-Exchange/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER cyrene

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://127.0.0.1:8000/healthz || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
