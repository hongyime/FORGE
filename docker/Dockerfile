# syntax=docker/dockerfile:1

# Dockerfile - FORGE Toolkit v7.2
#
# Production/runtime image for the self-hosted Compose stack plus a CI target
# for container-parity tests. Build from the repository root:
#   docker build -f docker/Dockerfile --target runtime -t forge-toolkit:local .

# UI dependencies are cached independently of UI source.
FROM node:22-slim AS frontend-dependencies
WORKDIR /app/frontend
COPY forge/reporting/webui/package.json forge/reporting/webui/package-lock.json ./
RUN npm ci
FROM frontend-dependencies AS frontend-dev
COPY --chown=node:node forge/reporting/webui/ /app/frontend/
RUN chown -R node:node /app/frontend
USER node
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
FROM frontend-dependencies AS frontend-builder
COPY forge/reporting/webui/ ./
RUN npm run build

FROM ubuntu:24.04 AS base

LABEL org.opencontainers.image.title="FORGE Toolkit"
LABEL org.opencontainers.image.version="7.2.0"
LABEL org.opencontainers.image.description="Authorised security assessment toolkit"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/forge/venv \
    PATH="/opt/forge/venv/bin:$PATH" \
    HOME=/home/forge \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-dev \
        python3-pip=24.* \
        python3-venv \
        libssl-dev=3.* \
        libffi-dev=3.* \
        libsqlite3-dev=3.* \
        gcc=4:13.* \
        g++=4:13.* \
        make=4.* \
        curl=8.* \
        git=1:2.* \
        ca-certificates \
        libkrb5-dev \
        krb5-user \
    && rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 1

RUN python3 -m venv "$VIRTUAL_ENV" \
    && python -m pip install --upgrade pip setuptools wheel

RUN useradd --create-home --shell /bin/bash --uid 10001 forge \
    && mkdir -p /app /data /plugins /remote-audit /ms-playwright \
        /home/forge/.cache/forge/models \
    && chown -R forge:forge /data /plugins /remote-audit /home/forge/.cache \
    && chmod 755 /app /data /plugins /remote-audit /ms-playwright

WORKDIR /app

FROM base AS ci

COPY pyproject.toml README.md ./
COPY alembic.ini ./
COPY alembic ./alembic
COPY forge ./forge
COPY tests ./tests

RUN python -m pip install ".[artifacts,graph,dev]" \
    && python -m playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip check

USER forge

CMD ["python", "-m", "pytest", "tests/", "--vcr-record=none", "-v", "--tb=short"]

# Resolve runtime dependencies before copying application source.
FROM base AS runtime-dependencies
COPY pyproject.toml README.md ./
RUN python -c "import tomllib,pathlib; p=tomllib.loads(pathlib.Path('pyproject.toml').read_text())['project']; d=p['dependencies']+p['optional-dependencies']['artifacts']+p['optional-dependencies']['graph']; pathlib.Path('/tmp/runtime-requirements.txt').write_text('\n'.join(d))" \
    && python -m pip install -r /tmp/runtime-requirements.txt \
    && python -m playwright install chromium

# Keep UI source and tests out of the final image's source layer.
FROM ubuntu:24.04 AS runtime-source
COPY forge/ /app/forge/
RUN rm -rf /app/forge/reporting/webui

# Runtime shares the builder's OS/Python ABI, without its compiler/development headers.
FROM ubuntu:24.04 AS runtime
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/forge/venv \
    PATH="/opt/forge/venv/bin:$PATH" \
    PYTHONPATH=/app \
    HOME=/home/forge \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
LABEL org.opencontainers.image.title="FORGE Toolkit"
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv curl git ca-certificates \
        libkrb5-3 krb5-user libstdc++6 libgomp1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=runtime-dependencies /opt/forge/venv /opt/forge/venv
COPY --from=runtime-dependencies /ms-playwright /ms-playwright
RUN python -m playwright install-deps chromium \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash --uid 10001 forge \
    && mkdir -p /app /data /plugins /remote-audit /home/forge/.cache/forge/models \
    && chown -R forge:forge /data /plugins /remote-audit /home/forge/.cache
WORKDIR /app
COPY pyproject.toml README.md ./
COPY alembic.ini ./
COPY alembic ./alembic
COPY --from=runtime-source /app/forge ./forge
COPY --from=frontend-builder /app/frontend/dist/ ./forge/reporting/webui/dist/
COPY forge-autopilot.sh forge-autopilot.bat ./
RUN chmod +x forge-autopilot.sh \
    && python -m pip install --no-deps --no-build-isolation . \
    && python -m pip check
USER forge
VOLUME ["/data", "/plugins", "/remote-audit", "/home/forge/.cache/forge/models"]
CMD ["forge", "--help"]

FROM runtime AS dev
USER root
RUN python -m pip install watchfiles==1.3.0 \
    && chown forge:forge /app
# Seed the initial dev image; later source edits arrive through Compose sync.
COPY --chown=forge:forge forge/ /app/forge/
COPY --chown=forge:forge alembic/ /app/alembic/
COPY --chown=forge:forge alembic.ini /app/alembic.ini
USER forge
CMD ["uvicorn", "forge.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--reload", "--reload-dir", "/app/forge"]

FROM runtime AS production

# ---------------------------------------------------------------------------
# rust-builder stage — compiles the Rust workspace inside a Linux container.
# Produces Linux ELF binaries (distinct from the Windows .exes built locally).
#
# NOTE (Phase 1 finding): All production crates (forge-server, forge-cli,
# forge-ui, forge-operations, etc.) are currently LIBRARY crates with no
# [[bin]] sections or main.rs entry points. The only binary produced by
# `cargo build --release --workspace` is `forge-xtask` (the build/verify
# tool). Before Phase 2 can proceed, each production crate that maps to a
# runtime service must gain a [[bin]] target + main.rs entrypoint.
#
# This stage is included to prove the Linux build works end-to-end and to
# establish the correct layer structure for when the binary entrypoints land.
# ---------------------------------------------------------------------------
FROM rust:1.94-slim AS rust-builder
WORKDIR /build
# Minimal system deps for openssl, sqlite, and postgres native builds
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev libsqlite3-dev libpq-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY native/ native/
RUN mkdir -p /out
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/native/target,sharing=locked \
    cd native && cargo build --release --workspace && \
    cp target/release/forge-xtask  /out/forge-xtask && \
    cp target/release/forge-server /out/forge-server && \
    cp target/release/forge        /out/forge

# ---------------------------------------------------------------------------
# rust-runtime target — minimal Debian runtime image for Rust binaries.
#
# Phase 2: forge-server and forge binaries are now available.
# ---------------------------------------------------------------------------
FROM debian:trixie-slim AS rust-runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 libsqlite3-0 tini \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 10001 forge && useradd -u 10001 -g 10001 -M -s /bin/false forge
COPY --from=rust-builder /out/forge-xtask  /usr/local/bin/forge-xtask
COPY --from=rust-builder /out/forge-server /usr/local/bin/forge-server
COPY --from=rust-builder /out/forge        /usr/local/bin/forge
USER 10001
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/forge-server"]
