# Dockerfile — FORGE Toolkit v7.2
#
# Purpose: Reproducible CI/CD build environment and operator runtime container.
#          Matches the ubuntu-24.04 GitHub Actions runner to eliminate
#          "works on my machine" failures.
#
# Usage:
#   # Build CI image
#   docker build --target ci -t forge-ci:7.2 .
#
#   # Build operator runtime image (includes GGUF model mount point)
#   docker build --target runtime -t forge:7.2 .
#
#   # Run tests inside container (CI parity)
#   docker run --rm -v $(pwd):/workspace forge-ci:7.2 \
#       pytest tests/ --vcr-record=none -v
#
#   # Run FORGE operator CLI
#   docker run --rm -it \
#       -v /path/to/models:/root/.cache/forge/models:ro \
#       -v /path/to/engagements:/workspace/engagements \
#       forge:7.2 \
#       forge report generate --engagement 1
#
# Multi-stage design:
#   base       — shared OS dependencies; pinned apt packages
#   ci         — base + dev/test tools; used in GitHub Actions
#   runtime    — base + runtime deps only; operator-facing image
#
# Security notes:
#   - No SSH daemon; no SSHD_CONFIG; minimal attack surface.
#   - No default credentials; operators supply credentials at runtime.
#   - FORGE_OFFLINE_STRICT defaults to 1 in both images; operators override
#     explicitly when network access is required (pre-engagement sync only).
#   - llama_cpp model files are bind-mounted read-only; never baked into image.

# ── Base stage ────────────────────────────────────────────────────────────────

FROM ubuntu:24.04 AS base

LABEL org.opencontainers.image.title="FORGE Toolkit"
LABEL org.opencontainers.image.version="7.2.0"
LABEL org.opencontainers.image.description="Modular red team toolkit — authorised engagements only"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    FORGE_OFFLINE_STRICT=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Pinned apt packages for reproducibility
# renovate: datasource=repology depName=ubuntu_24_04/python3.11
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3.11=3.11.* \
        python3.11-dev=3.11.* \
        python3-pip=24.* \
        python3.11-venv=3.11.* \
        libssl-dev=3.* \
        libffi-dev=3.* \
        libsqlite3-dev=3.* \
        gcc=4:13.* \
        g++=4:13.* \
        make=4.* \
        curl=8.* \
        git=1:2.* \
        ca-certificates \
        # Required for impacket Kerberos + SMB
        libkrb5-dev \
        krb5-user \
        # Required for Playwright system deps
        libnss3 \
        libnspr4 \
        libatk1.0-0 \
        libatk-bridge2.0-0 \
        libcups2 \
        libxkbcommon0 \
        libxcomposite1 \
        libxdamage1 \
        libxrandr2 \
        libgbm1 \
        libasound2 \
    && rm -rf /var/lib/apt/lists/*

# Symlink python3.11 as the default python3 and python
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 \
    && update-alternatives --install /usr/bin/python  python  /usr/bin/python3.11 1

# Create non-root operator user (root required only for raw socket ops in Phase 5)
RUN useradd --create-home --shell /bin/bash --uid 1000 forge

WORKDIR /workspace


# ── CI stage (adds dev/test tools) ────────────────────────────────────────────

FROM base AS ci

COPY requirements.txt requirements-safe.txt requirements-full.txt requirements.lock ./

# Install runtime dependencies from hash-pinned lock file
RUN python -m pip install --require-hashes -r requirements.lock

# Install dev/test tools (not hash-pinned; version-pinned in requirements-full.txt)
RUN python -m pip install -r requirements-full.txt

# Install Playwright system browsers
RUN python -m playwright install chromium --with-deps

# Copy source
COPY forge/ ./forge/
COPY tests/ ./tests/
COPY pyproject.toml ./

# Default CI entrypoint: run full test suite
ENTRYPOINT ["python", "-m", "pytest"]
CMD ["tests/", "--vcr-record=none", "-v", "--tb=short"]


# ── Runtime stage (operator-facing; no dev tools) ─────────────────────────────

FROM base AS runtime

COPY requirements.txt requirements.lock ./

# Install only runtime dependencies
RUN python -m pip install --require-hashes -r requirements.lock

# Install Playwright system browsers (Phase 2 social OSINT requires Chromium)
RUN python -m pip install playwright==1.50.0 \
    && python -m playwright install chromium --with-deps

# Copy forge package and templates only (no tests, no dev tooling)
COPY forge/ ./forge/
COPY pyproject.toml ./

# Model bind-mount point — GGUF models are NEVER baked into the image
RUN mkdir -p /root/.cache/forge/models && chmod 755 /root/.cache/forge/models
VOLUME ["/root/.cache/forge/models"]

# Engagement data mount point
RUN mkdir -p /workspace/engagements && chmod 755 /workspace/engagements
VOLUME ["/workspace/engagements"]

# Install forge CLI entry point
RUN python -m pip install --no-deps --editable .

# Default user: forge (non-root)
# Phase 5 raw socket operations (icmp_channel.py) require CAP_NET_RAW;
# grant explicitly with: docker run --cap-add=NET_RAW ...
USER forge

ENTRYPOINT ["forge"]
CMD ["--help"]
