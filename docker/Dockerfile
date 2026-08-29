# Dockerfile - FORGE Toolkit v7.2
#
# Production/runtime image for the self-hosted Compose stack plus a CI target
# for container-parity tests. Build from the repository root:
#   docker build -f docker/Dockerfile --target runtime -t forge-toolkit:local .

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

FROM base AS runtime

COPY pyproject.toml README.md ./
COPY alembic.ini ./
COPY alembic ./alembic
COPY forge ./forge
COPY forge-autopilot.sh forge-autopilot.bat ./

RUN chmod +x forge-autopilot.sh \
    && python -m pip install ".[artifacts,graph]" \
    && python -m playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip check

USER forge

VOLUME ["/data", "/plugins", "/remote-audit", "/home/forge/.cache/forge/models"]

CMD ["forge", "--help"]
