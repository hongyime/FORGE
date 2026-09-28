# Cutover Phase 1 — Rust Binaries + Docker Image
Date: 2026-09-29

## Retry context
Previous attempt (bg_bdea0582) failed on rustup network timeout at 453s inside
the container. Root cause: `native/rust-toolchain.toml` pins `channel = "1.94.1"`,
but the previous base image was `rust:1.82-slim` — so rustup tried to download
rustc 1.94.1 from static.rust-lang.org and hit a transient "error decoding
response body" at 453s.

This retry uses two hardening techniques:
1. **Pinned base image upgrade**: `rust:1.94-slim` (Debian trixie) — toolchain
   version 1.94.1 is already baked in, so rustup only syncs channel metadata
   (~4s) and downloads only the missing `clippy` component (~20s). No full
   rustc download, no network flakiness risk.
2. **BuildKit cache mounts**: cargo registry, cargo git, and build target dir
   are mounted as cache volumes so subsequent rebuilds skip crate downloads
   and incremental compilation.

Additional fix discovered during smoke test: `rust:1.94-slim` is Debian trixie
(GLIBC 2.39), but the original `rust-runtime` base was `debian:bookworm-slim`
(GLIBC 2.36). The compiled binary required GLIBC 2.39 and failed with
`version 'GLIBC_2.39' not found`. Fixed by upgrading runtime base from
`debian:bookworm-slim` to `debian:trixie-slim`.

## Dockerfile changes (delta from previous attempt)

| Change | Location | Detail |
|--------|----------|--------|
| Added `# syntax=docker/dockerfile:1` | Line 1 | Required for `--mount=type=cache` syntax |
| Upgraded builder base | `rust-builder FROM` | `rust:1.82-slim` → `rust:1.94-slim` (matches toolchain pin) |
| Added `/out/` staging dir | Before cargo build | `RUN mkdir -p /out` — binaries survive past cache-mount layer |
| Added BuildKit cache mounts | cargo build `RUN` | Cache `/usr/local/cargo/registry`, `/usr/local/cargo/git`, `/build/native/target` |
| Added `cp` to `/out/` | cargo build `RUN` | `cp target/release/forge-xtask /out/forge-xtask` — copies binary out before layer closes |
| Updated `COPY --from=rust-builder` path | `rust-runtime` stage | `/build/native/target/release/forge-xtask` → `/out/forge-xtask` |
| Upgraded runtime base | `rust-runtime FROM` | `debian:bookworm-slim` → `debian:trixie-slim` (GLIBC version parity) |

## Binary inventory
Only one binary is produced by `cargo build --release --workspace`:
- **`forge-xtask`** — the build/verify xtask tool

All 13 production crates (`forge-server`, `forge-cli`, `forge-ui`,
`forge-operations`, etc.) are library crates with no `[[bin]]` sections and
no `main.rs` entry points. This is expected per Phase 1 scope — the Dockerfile
comments document this. Phase 2 adds `[[bin]]` targets to the production crates.

## Build results

| Field | Value |
|-------|-------|
| Build 1 (cargo stage) | 20260929-040023 |
| Build 1 duration | ~50m (cold cache; full crate download + compile) |
| Build 1 exit code | 0 |
| Build 1 outcome | SUCCESS on cargo; FAIL on smoke (GLIBC mismatch) |
| Build 2 (runtime base fix) | 20260929-045935 |
| Build 2 duration | ~2m (all stages CACHED; only runtime stage rebuilt) |
| Build 2 exit code | 0 |
| Build 2 outcome | SUCCESS — smoke tests pass |
| Log (final) | `.omo/evidence/rust-rewrite/phase1-docker-build-retry-20260929-045935.log` |

## Image
| Field | Value |
|-------|-------|
| Name | `forge-toolkit-rust:local` |
| Size | **149 MB** |
| Base | `debian:trixie-slim` (Debian 13, GLIBC 2.39) |

## Smoke tests

| binary | --help output first line | verdict |
|--------|--------------------------|---------|
| forge-xtask | `Static migration inventory and allowlisted evidence checks` | **PASS** |
| forge-server | N/A (library crate, no binary) | N/A |
| forge | N/A (library crate, no binary) | N/A |

Full `forge-xtask --help` output:
```
Static migration inventory and allowlisted evidence checks

Usage: forge-xtask <COMMAND>

Commands:
  baseline
  inventory
  verify
  help       Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

## Exit criteria

- [x] Image built (exit code 0)
- [x] Smoke test passes (`forge-xtask --help` returns clean output)
- [x] Size documented (149 MB — well under 200 MB target)
- [x] BuildKit cache mounts in place (subsequent rebuilds will skip crate download + compile)
- [x] GLIBC version parity between builder and runtime

## Deviations from plan

1. **Base image version needed a matching runtime base**: Plan mentioned upgrading
   `rust:1.82-slim` to `rust:1.94-slim` but did not call out the downstream need
   to upgrade `rust-runtime` from `debian:bookworm-slim` to `debian:trixie-slim`.
   Added this fix after the GLIBC smoke test failure.

2. **Only one binary exists**: Plan referred to `forge-server` and `forge` as
   expected binaries. Confirmed via `Cargo.toml` inspection that all production
   crates are library-only at this time. The only real binary is `forge-xtask`.
   Smoke test adapted accordingly.

3. **`libssl3` package name on trixie**: The package is `libssl3t64` in trixie
   (vs `libssl3` in bookworm). The `RUN apt-get install libssl3` step succeeded
   because apt resolves the virtual package correctly; no change needed.

## Ready for Phase 2?

**Yes, with a prerequisite.**

The Rust image build pipeline is solid: pinned toolchain, BuildKit caches, GLIBC
parity, clean 149 MB runtime image. The Docker infrastructure is Phase-2-ready.

The prerequisite for Phase 2 (shipping production service binaries) is that each
production crate that maps to a runtime service (`forge-server`, `forge-cli`,
etc.) must gain a `[[bin]]` target with a `main.rs` entry point. Once those land,
the Dockerfile `COPY` placeholder lines just need to be uncommented and the
`CMD` updated — the build infrastructure already handles it.
