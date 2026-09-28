# GAP-2 — Playwright / OSINT Venvs

**Status:** RECOMMENDED — keep as permanent Python sidecar (Option a)  
**Resolution phase:** Post-cutover technical debt, label as `forge-osint-sidecar`  
**Date assessed:** 2026-09-28  

---

## 1. What is this gap?

Two related Python capabilities have no Rust equivalent in `native/`:

### 1a. Playwright (headless browser scraping)

`pyproject.toml` declares:
```
playwright>=1.50.0,<2.0
playwright-stealth==1.0.6
```

Used for SPA-aware HTML crawling — Playwright renders JavaScript, mines emails,
tech-stack fingerprints, cloud refs, and GitHub org links from rendered DOM.

### 1b. Per-tool OSINT venvs

Six external OSINT tools run in isolated Python virtual environments to avoid
dependency pin conflicts with the main FORGE runtime:

| Tool | Capability |
|---|---|
| GHunt | Google account reconnaissance |
| theHarvester | Email/host/subdomain harvesting (crt.sh, DDG, etc.) |
| Maigret | Username-to-profile across 2000+ sites |
| Sherlock | Username-to-profile across 400+ sites |
| Holehe | Email account-existence checks across 100+ services |
| WhatsMyName | Username enumeration via YAML site database |

---

## 2. Current Python Callsites

Grep of `forge/` for `playwright` imports:

| File | Usage |
|---|---|
| `forge/phase1/crawler.py` | Main Playwright crawl loop — SPA-aware fetch, HTML mining |
| `forge/phase0/lots_scraper.py` | Playwright for LOTS (Living-off-Trusted-Sites) scraping |
| `forge/phase1/stealth_recon.py` | playwright-stealth integration for evasion |
| `forge/cli.py` | CLI entry point (imports crawler pipeline) |
| `forge/cli_helpers.py` | Helper plumbing for crawler invocation |
| `forge/engagement_orchestrator.py` | Orchestrates crawler as phase step |
| `forge/distributed/runnable.py` | Distributed runner includes crawler tasks |
| `forge/utils/playbooks/__init__.py` | Playbook includes WAF evasion + crawler |
| `forge/utils/playbooks/waf_evasion.py` | WAF evasion uses playwright-stealth |
| `forge/utils/kill_chain_runtime.py` | Kill-chain runtime wires in crawler step |

**10 Python callsite files** depend on Playwright. The crawler is a **core kill-chain
step** (step D in the OSINT module inventory: "Playwright fetch + cloud regex + HTML
mining").

---

## 3. Rust-Side Crawling (forge-discovery)

`native/crates/forge-discovery/src/` contains these files:
```
artifacts.rs, enrichment.rs, feed.rs, lib.rs, pipeline.rs,
resume.rs, scoring.rs, seed.rs, snapshot.rs, validation.rs
```

There is **no `crawler.rs`** in `forge-discovery`. The `domain-contracts.json`
migration ledger has a `CRAWL` entry (line 347) but it maps to
`forge/db/schema.py:crawl_results` — i.e., the DB schema is migrated, but there
is **no Rust headless-browser crawl implementation**.

---

## 4. Resolution Options

### Option (a) — Keep Python subprocess as permanent sidecar (`forge-osint-sidecar`)

**Approach:** The Rust `forge-discovery` pipeline calls the OSINT/browser scraping
capability via an HTTP sidecar service. The sidecar runs the existing Python
Playwright crawler and OSINT venvs. Rust services communicate with it over a
simple localhost HTTP API.

**Architecture:**
```
forge-server (Rust)
  └─► POST http://localhost:8090/crawl  {"url": "...", "engagement_id": N}
       │
       ▼
  forge-osint-sidecar (Python, Docker container)
       ├─ playwright crawl  →  JSON response
       └─ OSINT venv wrappers (GHunt, Maigret, Sherlock, Holehe, theHarvester, WhatsMyName)
```

**Tradeoffs:**

| Pro | Con |
|---|---|
| Zero Rust work required | Permanent Python container in an otherwise Rust stack |
| Playwright/stealth continues to work identically | Network boundary: sidecar adds latency + complexity |
| OSINT tools keep their isolated venvs | Adds one more service to Compose |
| All 10 callsites migrate to HTTP client calls | HTTP API must be designed and implemented |
| Scales independently (separate container resources) | Python container maintenance persists post-cutover |

**Verdict:** **RECOMMENDED.** This is the pragmatic path. Headless browsers and OSINT
tool wrappers are not the kind of code you want to rewrite in Rust for marginal gain.

---

### Option (b) — Port to Rust with `headless_chrome` or `chromiumoxide` crate

**Approach:** Implement headless browser crawling in Rust using the `chromiumoxide`
crate (Chrome DevTools Protocol) or `headless_chrome` crate.

**Tradeoffs:**

| Pro | Con |
|---|---|
| Pure Rust stack, no Python dependency | `chromiumoxide`/`headless_chrome` are not production-mature for complex scraping |
| No sidecar container | OSINT tool wrappers (GHunt, Maigret, etc.) have no Rust equivalent — still need Python |
| | Major engineering effort (weeks) |
| | playwright-stealth has no Rust equivalent |

**Verdict:** Not recommended. The Rust headless-browser ecosystem is not at parity
with Playwright for FORGE's use case. OSINT tools still need Python regardless.

---

### Option (c) — Drop browser-scraping capability entirely

**Approach:** Remove Playwright and OSINT venvs. Kill-chain step D ("Playwright
fetch + cloud regex + HTML mining") becomes a no-op or best-effort static fetch.

**Tradeoffs:**

| Pro | Con |
|---|---|
| Eliminates the gap entirely | Loses SPA-rendered page mining (major feature regression) |
| Clean Rust-only stack | Cloud regex extraction from rendered DOM is lost |
| | OSINT venvs (Maigret/Sherlock/Holehe) are also dropped — significant recon loss |

**Verdict:** Not recommended. Kill-chain step D is a core capability.

---

## 5. Recommended Action: Option (a) — `forge-osint-sidecar`

**Implementation plan (post-cutover technical debt):**

### Phase post-4: Design the sidecar HTTP API

```python
# forge-osint-sidecar endpoints (Python FastAPI or Flask)
POST /crawl          # Playwright SPA crawl → JSON {emails, hosts, cloud_refs, tech_stack}
POST /osint/harvest  # theHarvester → JSON
POST /osint/maigret  # Maigret → JSON
POST /osint/sherlock # Sherlock → JSON
POST /osint/holehe   # Holehe → JSON
POST /osint/ghunt    # GHunt → JSON
GET  /health         # liveness probe
```

### Rust client call (forge-discovery)

```rust
// In forge-discovery/src/crawler.rs (to be created)
use reqwest::Client;
async fn playwright_crawl(url: &str, engagement_id: i64) -> Result<CrawlResult> {
    let client = Client::new();
    let resp = client
        .post("http://forge-osint-sidecar:8090/crawl")
        .json(&serde_json::json!({"url": url, "engagement_id": engagement_id}))
        .send().await?;
    resp.json::<CrawlResult>().await
}
```

### Compose addition (Phase post-4)

```yaml
forge-osint-sidecar:
  build:
    context: ..
    dockerfile: docker/Dockerfile.osint-sidecar
  ports:
    - "127.0.0.1:8090:8090"
  environment:
    FORGE_DATA_DIR: /data
  networks:
    - forge-prod-net
  labels:
    forge.role: osint-sidecar
    forge.gap: GAP-2
```

---

## 6. Exact Next-Step Commands

```powershell
# Verify playwright callsite count (already confirmed: 10 files)
Select-String -Path "C:\forge\forge\**\*.py" -Pattern "playwright" -Recurse | Measure-Object

# Check OSINT venv bootstrap to understand sidecar scope
Get-Content "C:\forge\forge\phase0\lots_scraper.py" | Select-String "playwright" -Context 2,2

# Tag this as deferred technical debt in cutover plan
# (do not modify forge/ Python source — Phase 5 territory)
Write-Output "GAP-2 action: design forge-osint-sidecar HTTP API, wire after Phase 4 cutover"
```

---

## 7. What Remains for Phase 5

Phase 5 (Python deletion) **cannot** delete the Playwright/OSINT Python source
until the `forge-osint-sidecar` container is implemented and tested. These files
are explicitly **not** deletable at Phase 5:

- `forge/phase1/crawler.py`
- `forge/phase0/lots_scraper.py`
- `forge/phase1/stealth_recon.py`
- `forge/utils/playbooks/waf_evasion.py`

They migrate into the sidecar container's source, not into Rust.

---

## 8. References

- `pyproject.toml` lines 30–31: `playwright>=1.50.0,<2.0`, `playwright-stealth==1.0.6`
- `native/crates/forge-discovery/src/` — no `crawler.rs` exists
- `native/migration/domain-contracts.json` line 347 — CRAWL schema migrated, no crawler impl
- README.md OSINT module inventory, step D: "Playwright fetch + cloud regex + HTML mining"
