# Agent State

## Current Task: Ready for Competitive Upgrade Implementation

**Status**: READY | All backlog committed, specs complete, awaiting implementation start

---

## What's Done (This Sprint)

All backlog items verified and committed. Working tree clean (except .agents/ files).

### Committed (2026-08-30)

| Commit | What |
|--------|------|
| `a149da3` | docs(agents): competitive upgrade orchestration handoff |
| `88fd919` | test: continuous loop integration test scaffold |
| `f18cacd` | feat(automation): secrets auto-feed + live keyed providers integration |
| `8f48c00` | feat(offensive): Linper persistence suite |
| `770145c` | feat(automation): P1 priority scoring + query catalog |
| `35ae827` | feat(hardening): Linper defensive persistence detection |

### Specs Ready (gitignored docs/, read locally)

- `docs/competitive_upgrade_do_now.spec.md` — T1–T4, ~4.5 weeks
- `docs/competitive_upgrade_do_next.spec.md` — T5–T6, ~7 weeks
- `docs/competitive_upgrade_explore.spec.md` — T7–T8, strategic options
- `docs/competitive_upgrade_offensive_capabilities.md` — capability matrix
- `docs/forge_continuous_loop_architecture.md` — loop design

---

## Next: Implementation Order

### Phase 1 — Do Now (~4.5 weeks)

**T1: Cloudflare Tunnel C2 Infrastructure**
- File: `forge/c2/tunnel_manager.py`
- Spec: `docs/competitive_upgrade_do_now.spec.md` §T1
- cloudflared binary: `C:\Program Files (x86)\cloudflared\cloudflared.exe` v2026.7.3

**T2: AWS STS Token Forensics & Cloud Graph**
- File: `forge/cloud/sts_token_decoder.py`
- Spec: `docs/competitive_upgrade_do_now.spec.md` §T2

**T3: Pass-the-Hash Execution Engine**
- File: `forge/post_exploitation/pt_hash_executor.py`
- Spec: `docs/competitive_upgrade_do_now.spec.md` §T3

**T4: Password Spray Optimizer**
- File: `forge/auth/password_spray_optimizer.py`
- Spec: `docs/competitive_upgrade_do_now.spec.md` §T4

**T1.5 (Optional): Go Binary Auto-Updater**
- Missing: no auto-update for subfinder/httpx/katana/nuclei/Linper scripts
- Decision needed: add to Do Now tier?

### Phase 2 — Do Next (~7 weeks)

- T5: Kerberos ticket operations
- T6: Hybrid AD/Azure attack paths

### Phase 3 — Explore (Pending security review)

- T7: Mimikatz backend (opt-in add-on)
- T8: C2 listeners

---

## Key Facts for Next Agent

### Attack Mode
Already DEFAULT ON in `forge/cli.py` lines 328–332 — no change needed.

### Continuous Loop Architecture
`WinCredCollector → AWS STS decoder → PT HASH executor → lateral movement → new cred extraction`
`Cloud credentials → Secret Feed → Cloud Graph → Attack Paths`
All callbacks via CF Tunnel (zero public IP exposure).

### User Constraints (Verbatim)
1. No new commands — extend existing ones to avoid command fatigue
2. Continuous autonomous loop required
3. Attack mode default ON ✓ (already true)
4. Capability matrix must work together in a loop, not in silos
5. FORGE = "fully automated ASM and red team C2"
6. Minimise public IP exposure ✓ (CF tunnel in spec)

### Strategic Direction
**Path A confirmed** (ASM Toolkit + Offensive Capabilities):
- Credential extraction, attack paths, continuous loop
- Mimikatz: opt-in add-on
- C2 Listeners: defer to separate security review

---

## Deferred / Out of Scope

- HTML plan files (`forge-competitive-upgrade-plan.html`, `forge-montysecurity-upgrade-plan.html`) — artifacts only, not committed
- Full C2 Framework (Path B) — deferred pending security review

---

## Previous Work (Historical)

- 2026-08-30: Competitive research + 3-tier specs created
- 2026-08-30: Linper defensive module + offensive persistence suite
- 2026-08-30: P1 priority scoring, query catalog
- 2026-08-29: Docker hands-off startup hardening (B769)
- 2026-08-29: Linper/InfraHunter free upgrades integration (B770)
- Multiple B-series fixes for autonomous cycle reliability
- Docker packaging, Supabase integration, automation cycle hardening

---

<!-- MOLT_AUTO_START -->
## Auto State

- Updated: 2026-08-30 19:20:00 +08:00
- Machine: PRAWN-E14
- Harness: opencode
- Event: backlog-cleanup
- Branch: main
- HEAD: a149da3
- Dirty files: 2 (.agents/JOURNAL.md, .agents/STATE.md)
- Resume hint: Read .agents/STATE.md. Specs in docs/competitive_upgrade_do_now.spec.md. Start with T1 (CF Tunnel C2).
<!-- MOLT_AUTO_END -->