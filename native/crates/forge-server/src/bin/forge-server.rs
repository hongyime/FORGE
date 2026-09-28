//! forge-server — Rust shadow of the Python platform API + web UI service.
//!
//! Phase 2 target ports:
//!   - :9000  platform API  (shadows Python :8000)
//!   - :9080  web UI        (shadows Python :8080)
//!
//! Environment variables:
//!   FORGE_API_PORT      — platform API port  (default: 9000)
//!   FORGE_WEB_PORT      — web UI port        (default: 9080)
//!   FORGE_LOG_LEVEL     — log level string   (default: INFO)
//!   FORGE_STATE_DB_URL  — state database URL (default: sqlite:///data/forge.db)
//!
//! Status: SKELETON — HTTP handlers not yet implemented (Phase 2 target).
//! The library crate (forge-server) only contains model types and pure
//! functions (health checks, JWT auth helpers, permission checks).
//! A real HTTP runtime (axum/actix-web + tokio) will be wired in Phase 2.

use std::env;
use forge_server::{
    ComponentHealth, PlatformHealth, check_readiness, ReadinessState,
};

fn main() {
    let api_port  = env::var("FORGE_API_PORT").unwrap_or_else(|_| "9000".into());
    let web_port  = env::var("FORGE_WEB_PORT").unwrap_or_else(|_| "9080".into());
    let log_level = env::var("FORGE_LOG_LEVEL").unwrap_or_else(|_| "INFO".into());
    let db_url    = env::var("FORGE_STATE_DB_URL")
        .unwrap_or_else(|_| "sqlite:///data/forge.db".into());

    // Exercise real library code — proof the crate links correctly.
    let health = PlatformHealth::new(
        vec![ComponentHealth::healthy("db"), ComponentHealth::healthy("bus")],
        env!("CARGO_PKG_VERSION"),
        0,
    );
    let readiness = check_readiness(&health);

    eprintln!("forge-server (Rust) starting");
    eprintln!("  version   : {}", env!("CARGO_PKG_VERSION"));
    eprintln!("  api port  : {api_port}   (shadow of Python :8000)");
    eprintln!("  web port  : {web_port}  (shadow of Python :8080)");
    eprintln!("  log level : {log_level}");
    eprintln!("  db url    : {db_url}");
    eprintln!("  readiness : {:?}", readiness);
    eprintln!("  status    : SKELETON — HTTP handlers not yet implemented (Phase 2 target)");
    eprintln!("  note      : Real serve() call replaces this stub in Phase 2.");

    // Verify library link is complete.
    debug_assert!(
        readiness == ReadinessState::Ready,
        "skeleton health check failed — library link broken"
    );

    // Phase 2: replace with real tokio runtime + axum/actix-web server.
    // e.g.:
    //   tokio::runtime::Runtime::new().unwrap().block_on(async {
    //       forge_server::serve_platform(api_port, web_port).await
    //   })
    std::process::exit(0);
}
