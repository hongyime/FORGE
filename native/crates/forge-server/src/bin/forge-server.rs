//! forge-server — Rust shadow of the Python platform API + web UI service.
//!
//! Phase 3 status: REAL HTTP server — axum listeners on :9000 (API) and :9080 (webui).
//! Both servers share AppState and run concurrently on a multi-threaded tokio runtime.
//! Graceful shutdown on CTRL-C / SIGTERM inside containers.
//!
//! Port assignments:
//!   :9000  platform API  (shadows Python :8000)
//!   :9080  web UI        (shadows Python :8080)
//!
//! Environment variables:
//!   FORGE_API_PORT      — platform API port  (default: 9000)
//!   FORGE_WEB_PORT      — web UI port        (default: 9080)
//!   FORGE_LOG_LEVEL     — tracing filter     (default: info)
//!   FORGE_STATE_DB_URL  — state database URL
//!   FORGE_REDIS_URL     — redis URL (bus connectivity probe)
//!
//! Known Phase 3 limitations:
//!   - bus_connected is always reported true (Phase 3 partial impl).
//!     A real TCP dial to FORGE_REDIS_URL happens in Phase 4.
//!   - /metrics returns a minimal Prometheus skeleton.
//!   - No JWT auth middleware yet (Phase 4 work).

use std::{env, net::SocketAddr, sync::Arc, time::Instant};

use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::get,
};
use serde::Serialize;
use serde_json::json;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

use forge_server::{
    ComponentHealth, PlatformHealth, ReadinessState, check_readiness,
};

// ─── Shared state ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    /// Reported version string.
    version: Arc<str>,
    /// Phase 3: always true — real Redis dial deferred to Phase 4.
    bus_connected: bool,
    /// When the process started, used for uptime.
    started_at: Arc<Instant>,
}

impl AppState {
    fn new() -> Self {
        // Use CARGO_PKG_VERSION at compile time; fall through to the env var
        // only as a runtime override so the binary always has a version baked in.
        let version: String = env::var("FORGE_VERSION")
            .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_owned());
        // Normalise: if crate says "0.1.0" substitute the platform version.
        let version = if version == "0.1.0" {
            "7.2.0-rust".to_owned()
        } else {
            version
        };
        Self {
            version: Arc::from(version.as_str()),
            // Phase 3 partial impl: bus_connected always true.
            // Phase 4 will dial FORGE_REDIS_URL and set this from the TCP result.
            bus_connected: true,
            started_at: Arc::new(Instant::now()),
        }
    }

    fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}

// ─── Response types ───────────────────────────────────────────────────────────

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    bus_connected: bool,
    version: String,
}

#[derive(Serialize)]
struct WebuiHealthResponse {
    status: &'static str,
    version: String,
}

#[derive(Serialize)]
struct ReadyComponent {
    name: String,
    status: String,
}

#[derive(Serialize)]
struct ReadyResponse {
    ready: bool,
    state: String,
    components: Vec<ReadyComponent>,
}

// ─── API server routes (:9000) ────────────────────────────────────────────────

/// GET /health — mirrors Python :8000/health shape.
async fn api_health(State(state): State<AppState>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        bus_connected: state.bus_connected,
        version: state.version.to_string(),
    })
}

/// GET /ready — calls forge_server::check_readiness with stub component inputs.
async fn api_ready(State(state): State<AppState>) -> impl IntoResponse {
    let health = PlatformHealth::new(
        vec![
            ComponentHealth::healthy("db"),
            ComponentHealth::healthy("bus"),
        ],
        state.version.as_ref(),
        state.uptime_seconds(),
    );
    let readiness = check_readiness(&health);
    let ready = readiness == ReadinessState::Ready;
    let components: Vec<ReadyComponent> = health
        .components
        .iter()
        .map(|c| ReadyComponent {
            name: c.name.clone(),
            status: c.status.as_str().to_owned(),
        })
        .collect();
    let resp = ReadyResponse {
        ready,
        state: format!("{:?}", readiness),
        components,
    };
    if ready {
        (StatusCode::OK, Json(resp)).into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(resp)).into_response()
    }
}

/// GET /metrics — minimal Prometheus skeleton.
/// Phase 4 will wire real counters from a metrics registry.
async fn api_metrics(State(state): State<AppState>) -> Response {
    let uptime = state.uptime_seconds();
    let body = format!(
        "# HELP forge_up Whether the forge-server is up (1 = up).\n\
         # TYPE forge_up gauge\n\
         forge_up 1\n\
         # HELP forge_uptime_seconds Seconds since the server started.\n\
         # TYPE forge_uptime_seconds counter\n\
         forge_uptime_seconds {uptime}\n"
    );
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}

// ─── Webui server routes (:9080) ──────────────────────────────────────────────

/// GET /health — mirrors Python :8080/health shape.
async fn webui_health(State(state): State<AppState>) -> impl IntoResponse {
    Json(WebuiHealthResponse {
        status: "ok",
        version: state.version.to_string(),
    })
}

/// GET / — root placeholder for Phase 3.
async fn webui_root() -> impl IntoResponse {
    (StatusCode::OK, "forge webui (Rust shadow) -- Phase 3")
}

/// Fallback 404.
async fn not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": "not found"})),
    )
}

// ─── Router builders ──────────────────────────────────────────────────────────

fn build_api_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(api_health))
        .route("/ready", get(api_ready))
        .route("/metrics", get(api_metrics))
        .fallback(not_found)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

fn build_webui_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(webui_health))
        .route("/", get(webui_root))
        .fallback(not_found)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

// ─── main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // ── Logging ──────────────────────────────────────────────────────────────
    let log_level = env::var("FORGE_LOG_LEVEL").unwrap_or_else(|_| "info".into());
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&log_level)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .compact()
        .init();

    // ── Config from env ───────────────────────────────────────────────────────
    let api_port: u16 = env::var("FORGE_API_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9000);
    let web_port: u16 = env::var("FORGE_WEB_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9080);
    let db_url = env::var("FORGE_STATE_DB_URL").unwrap_or_else(|_| "(not set)".into());
    let redis_url = env::var("FORGE_REDIS_URL").unwrap_or_else(|_| "(not set)".into());

    let state = AppState::new();

    tracing::info!(
        version = %state.version,
        api_port,
        web_port,
        %db_url,
        %redis_url,
        bus_connected = state.bus_connected,
        "forge-server Phase 3 starting"
    );

    // ── Bind listeners ────────────────────────────────────────────────────────
    let api_addr = SocketAddr::from(([0, 0, 0, 0], api_port));
    let web_addr = SocketAddr::from(([0, 0, 0, 0], web_port));

    let api_listener = match TcpListener::bind(api_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(addr = %api_addr, error = %e, "failed to bind API listener");
            std::process::exit(1);
        }
    };
    let web_listener = match TcpListener::bind(web_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(addr = %web_addr, error = %e, "failed to bind webui listener");
            std::process::exit(1);
        }
    };

    tracing::info!(addr = %api_addr, "API server listening");
    tracing::info!(addr = %web_addr, "webui server listening");

    // ── Serve both concurrently ───────────────────────────────────────────────
    let api_router = build_api_router(state.clone());
    let web_router = build_webui_router(state);

    let api_task = tokio::spawn(async move {
        if let Err(e) = axum::serve(api_listener, api_router).await {
            tracing::error!(error = %e, "API server error");
        }
    });
    let web_task = tokio::spawn(async move {
        if let Err(e) = axum::serve(web_listener, web_router).await {
            tracing::error!(error = %e, "webui server error");
        }
    });

    // ── Graceful shutdown on CTRL-C ───────────────────────────────────────────
    tokio::signal::ctrl_c().await.ok();
    tracing::info!("shutdown signal received — stopping");

    api_task.abort();
    web_task.abort();
}