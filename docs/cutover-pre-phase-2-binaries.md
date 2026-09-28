# Pre-Phase-2: Rust Runtime Binaries

Date: 2026-09-29
Design choice: **B — Skeleton runtime** (see reasoning below)

## Reasoning for choice B

Step 1 reconnaissance found that both production crates are pure model/logic libraries with **zero HTTP serving code**:

- `forge-server` exports: `check_readiness()`, `HealthStatus`, `ComponentHealth`, `PlatformHealth`, `ReadinessState`, `WorkerHeartbeat`, `MetricsSample`, `JwtClaims`, `AuthRole`, `check_permission()`, `EngagementFilter`, `ProgressEvent`. No async runtime, no HTTP listener, no `tokio::main`, no `axum`/`actix-web` dependency.
- `forge-cli` exports: `route_command(name: &str) -> CommandOutcome`, `CommandKind`, `HiddenCommandKind`, `ExitCode`, `CommandOutcome`. No command executor, no arg parsing, no `clap` dependency at the crate level.

Choice A (real runtime) was not possible — there is no `serve_platform()`, `serve_api()`, or `dispatch()` function to call.  
Choice C (skip) was rejected — the binaries are buildable skeleton stubs that honestly represent the Phase 1 state and unblock Phase 2 compose file validation.

The skeletons call **real library functions** (`check_readiness()`, `route_command()`) to prove the crates link correctly and exercise non-trivial library code at startup.

---

## Binaries added

| binary | crate | Cargo.toml `[[bin]]` | entry point | release size (Windows) |
|---|---|---|---|---|
| `forge-server` | `forge-server` | `native/crates/forge-server/Cargo.toml` | `src/bin/forge-server.rs` | ~130 KB |
| `forge` | `forge-cli` | `native/crates/forge-cli/Cargo.toml` | `src/bin/forge.rs` | ~145 KB |

---

## Files created / edited

| Action | Path |
|---|---|
| Created | `native/crates/forge-server/src/bin/forge-server.rs` |
| Created | `native/crates/forge-cli/src/bin/forge.rs` |
| Edited  | `native/crates/forge-server/Cargo.toml` — added `[[bin]]` block |
| Edited  | `native/crates/forge-cli/Cargo.toml` — added `[[bin]]` block |
| Edited  | `docker/Dockerfile` — rust-builder copies forge-server + forge; rust-runtime installs all three binaries; CMD updated to forge-server |

---

## Function calls made from main.rs

- `forge-server` main → `forge_server::PlatformHealth::new()`, `forge_server::ComponentHealth::healthy()`, `forge_server::check_readiness()` — skeleton stub otherwise; real `serve_platform()` + async runtime wired in Phase 2
- `forge` main → `forge_cli::route_command(cmd_name)` — returns `CommandOutcome::Supported/Hidden/Unknown`; prints fallback to Python CLI; real command execution wired in Phase 2

---

## Verification results

| Check | Result |
|---|---|
| `cargo build --release --offline -p forge-server -p forge-cli` | **exit 0**, 2m 9s |
| `forge-server.exe` exists + size | 129.5 KB |
| `forge.exe` exists + size | 145.0 KB |
| `forge --help` smoke test (host) | **PASS** — correct output, exit 0 |
| `forge-server` smoke test (host) | **PASS** — startup banner + readiness:Ready, exit 0 |
| `cargo test -p forge-server -p forge-cli --offline` | **27 tests passed** (9 platform + 18 api/cli), 0 failed |
| Canary suite `run-canaries.ps1 -Quick -SkipBuild` | **13/13 PASS** |
| Docker image rebuild | **exit 0**, BuildKit cache hit; ~fast |
| Docker image size | **150 MB** (was 149 MB, +1 MB for two new binaries) |
| `docker run forge --help` | **PASS** — exit 0, correct output |
| `docker run forge-server` | **PASS** — startup banner, readiness:Ready, exit 0 |
| `docker run forge-xtask --help` | **PASS** — exit 0 |

---

## Phase 2 unblocked?

**Yes.**

The Phase 2 shadow-port Compose file can now reference `forge-toolkit-rust:local` and start `forge-server` and `forge` containers. Containers will start cleanly, print the structured startup banner, and exit 0 (skeleton behaviour). This proves:

1. `[[bin]]` targets are wired correctly in all production crates.
2. The Docker image contains all three expected binaries.
3. `cargo build --workspace` builds binaries in addition to library crates.
4. The `CMD ["/usr/local/bin/forge-server"]` default is live.

Phase 2 shadow traffic testing (HTTP parity, :9000/:9080 listeners) requires real `axum`/`actix-web` implementations in `forge-server` — that is the Phase 2 implementation task, not a Phase 1 exit blocker.

---

## Known limitations

- Binaries are skeletons: they start, print the banner, and exit 0. They **do not accept HTTP traffic**.
- Phase 2 shadow endpoint Compose file can reference them for `up -d` verification (containers start + exit cleanly) but real traffic parity testing (Phase 3) requires real HTTP handler implementations.
- `forge <cmd>` always exits 1 and prints a Python fallback — correct skeleton behaviour. Real command execution is Phase 2 territory.
- `forge-server` `--help` is not implemented (binary exits 0 immediately with the startup banner on any invocation). Phase 2 can add `clap` arg parsing.
- Linux ELF binaries built inside the Docker `rust-builder` stage are separate from the Windows `.exe` files built locally on the host. Both are verified.
