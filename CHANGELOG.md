# Changelog

## v0.1.0 — 2026-09-22

First public release of **FORGE Toolkit** — a deterministic, authorized
Attack Surface Management (ASM) engagement pipeline.

### What's included

**Core pipeline**
- `forge kill-chain` — multi-seed recursive discovery engine: subdomain
  enumeration, DNS/RDAP, GitHub keyscan, identity enrichment, cloud scan,
  Wayback/Common Crawl, HIBP domain check and passive vuln fingerprinting.
- Phases 0–6: KB sync, scoped intake, discovery, enrichment, validation,
  scoring and LLM/template report generation with guaranteed fallback.
- Scope gates on every network action; every operation is audit-logged.

**Storage and audit**
- Per-engagement SQLite databases with v48 schema (64 tables), WAL mode,
  FK enforcement and monotonic non-reused engagement IDs.
- Central control-DB with append-only `control_audit_events` table enforced
  by SQL triggers; SHA-256 hash-chained audit records byte-for-byte
  compatible with the `verify_control_audit_chain` verifier.

**Web and API**
- FastAPI backend at `http://localhost:8000` with JWT auth, RBAC and
  workspace isolation.
- React SPA dashboard at `http://localhost:8080`.
- HTMX server-rendered parallel route for lightweight access.

**Automation**
- `forge automation cycle` daily loop with feed-build, source-queue
  consumption and guarded live start.
- Scheduled monitoring with change-diffing and alert delivery.
- Remediation workflow with retest, SLA tracking and ticket sync.

**Connectors**
- Free-first catalog: ProjectDiscovery (subfinder, httpx, katana, nuclei),
  Gitleaks/TruffleHog local secret scanners, HIBP k-anonymity API.
- Data-only connector manifests for optional paid adapters.

**Testing**
- 2 100+ Python tests (unit, integration, webui, phase-5/6, connectors).
- Vitest frontend suite (44/44).
- Rust native layer (T1–T8): 500+ tests across forge-domain, forge-policy,
  forge-crypto, forge-adapters, forge-storage (schema, audit chain).

### Install (quickest path)

**Docker Compose (recommended)**
```bash
git clone <repo> forge
cd forge
cp docker/low-memory.env.example .env   # edit FORGE_WEB_SECRET_KEY etc.
docker compose -f docker/docker-compose.yml up -d
# API: http://localhost:8000   Web UI: http://localhost:8080
forge doctor
```

**pip**
```bash
python3 -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -e .
forge doctor
```

**Windows quick-start**
```powershell
git clone <repo> forge
cd forge
.\setup.bat       # creates .venv, installs deps, optional free connectors
forge doctor
```

### Rust rewrite status (T1–T8 of 36 complete)

The first-party Python runtime is being replaced with a native Rust binary
that will ship as a single compressed executable (UPX-ready) for zero-dependency
install. T1–T8 are accepted and merged. T9–T36 are in progress.

| Wave | Tasks | Status |
|---|---|---|
| Foundations, domain, config, gates | T1–T6 | ✅ accepted |
| Storage + audit chain | T7–T8 | ✅ accepted |
| Buses, plugins, runtime | T9–T12 | ⏳ queued |
| Discovery → reporting | T13–T30 | ⏳ planned |
| Packaging, release QA | T31–T36 | ⏳ planned |

The Python system is fully operational and used in production; the Rust binary
will replace it when T36 is reached.

### Known limitations

- `forge kill-chain` requires Python 3.11+ and optionally the free ProjectDiscovery
  binaries (`subfinder`, `httpx`, `katana`, `nuclei`) for full discovery coverage.
- Some tests require Docker services (`tests/integration/`). Run
  `pytest tests/unit tests/connectors tests/phase5 tests/phase6` for the
  no-Docker subset.
- Rust compilation requires Visual Studio 2022 build tools on Windows.
