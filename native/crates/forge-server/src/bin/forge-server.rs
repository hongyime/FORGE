//! forge-server — Rust shadow of the Python platform API + web UI service.
//!
//! Phase 4 prerequisites (CODE-PREP):
//!   A. Real Redis TCP dial for `bus_connected` (AtomicBool, 5s refresh)
//!   B. JWT bearer-token middleware (presence-only) on write endpoints
//!   C. WebSocket `/ws/progress` echo skeleton
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

use std::{
    env,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use axum::{
    Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
};
use serde::Serialize;
use serde_json::json;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

use forge_server::{ComponentHealth, PlatformHealth, ReadinessState, check_readiness};

// ─── Redis dial helpers ────────────────────────────────────────────────────────

/// Parse `redis://HOST:PORT` → `"HOST:PORT"`.
/// Returns `None` if the URL doesn't match the expected shape.
fn parse_redis_addr(url: &str) -> Option<String> {
    // Strip `redis://` prefix (case-insensitive for the scheme).
    let rest = url
        .strip_prefix("redis://")
        .or_else(|| url.strip_prefix("Redis://"))?;
    // Strip any trailing path segments or auth info — keep only `host:port`.
    // We support only the plain `redis://HOST:PORT` shape per the spec.
    let host_port = rest.split('/').next()?.split('@').next_back()?;
    // Validate that host_port contains at least one colon (has a port).
    if host_port.contains(':') {
        Some(host_port.to_owned())
    } else {
        // No port — append default 6379.
        Some(format!("{host_port}:6379"))
    }
}

/// Attempt a 500 ms TCP connect to `addr`. Returns `true` on success.
async fn tcp_dial(addr: &str) -> bool {
    use tokio::time::{Duration, timeout};
    matches!(
        timeout(
            Duration::from_millis(500),
            tokio::net::TcpStream::connect(addr),
        )
        .await,
        Ok(Ok(_))
    )
}

// ─── Shared state ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    /// Reported version string.
    version: Arc<str>,
    /// Phase 4 A: Real Redis dial result, refreshed every 5s by a background task.
    /// Reads return the last known connectivity status.
    bus_connected: Arc<AtomicBool>,
    /// When the process started, used for uptime.
    started_at: Arc<Instant>,
}

impl AppState {
    fn new() -> Self {
        // Use CARGO_PKG_VERSION at compile time; fall through to the env var
        // only as a runtime override so the binary always has a version baked in.
        let version: String =
            env::var("FORGE_VERSION").unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_owned());
        // Normalise: if crate says "0.1.0" substitute the platform version.
        let version = if version == "0.1.0" {
            "7.2.0-rust".to_owned()
        } else {
            version
        };
        Self {
            version: Arc::from(version.as_str()),
            // Phase 4 A: Start as false; background task will update.
            bus_connected: Arc::new(AtomicBool::new(false)),
            started_at: Arc::new(Instant::now()),
        }
    }

    fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    fn bus_connected(&self) -> bool {
        self.bus_connected.load(Ordering::Relaxed)
    }
}

// ─── Phase 4 A: Redis bus probe background task ───────────────────────────────

/// Spawns a tokio task that dials FORGE_REDIS_URL every 5 s and updates
/// `bus_flag`. On parse failure or dial failure, stores `false`.
fn spawn_bus_probe(bus_flag: Arc<AtomicBool>) {
    let redis_url = env::var("FORGE_REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_owned());

    let addr = parse_redis_addr(&redis_url).unwrap_or_default();

    tokio::spawn(async move {
        loop {
            let connected = if addr.is_empty() {
                tracing::warn!("FORGE_REDIS_URL could not be parsed; bus_connected=false");
                false
            } else {
                let ok = tcp_dial(&addr).await;
                tracing::debug!(addr = %addr, bus_connected = ok, "Redis TCP probe");
                ok
            };
            bus_flag.store(connected, Ordering::Relaxed);
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    });
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

// ─── Phase 4 B: JWT bearer-token middleware ───────────────────────────────────

/// Axum middleware that enforces the presence of `Authorization: Bearer <token>`.
///
/// Phase 4 skeleton: only checks that the header is present and starts with
/// `Bearer `.  JWT signature verification is reserved for Phase 4 continuation.
///
/// Returns 401 if the header is missing or does not start with `Bearer `.
async fn require_bearer(
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    match headers.get("authorization") {
        Some(value) => match value.to_str() {
            Ok(v) if v.starts_with("Bearer ") && v.len() > "Bearer ".len() => {
                next.run(request).await
            }
            _ => (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "invalid Authorization header — expected Bearer <token>"})),
            )
                .into_response(),
        },
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Authorization header required"})),
        )
            .into_response(),
    }
}

// ─── API server routes (:9000) ────────────────────────────────────────────────

/// GET /health — mirrors Python :8000/health shape.
async fn api_health(State(state): State<AppState>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        bus_connected: state.bus_connected(),
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

/// POST /ready/refresh — Phase 4 B skeleton write endpoint protected by JWT
/// bearer middleware.  Returns 202 Accepted as a placeholder.
async fn api_ready_refresh() -> impl IntoResponse {
    (
        StatusCode::ACCEPTED,
        Json(json!({"status": "accepted", "message": "refresh scheduled (Phase 4 placeholder)"})),
    )
}

// ─── Phase 4 C: WebSocket /ws/progress ───────────────────────────────────────

/// GET /ws/progress — upgrades to WebSocket and echoes received messages.
///
/// Phase 4 skeleton: no auth yet (JWT param auth reserved for Phase 4
/// continuation), no real event emission.  Closes gracefully on disconnect.
async fn api_ws_progress(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(handle_ws_progress)
}

async fn handle_ws_progress(mut socket: WebSocket) {
    tracing::debug!("ws/progress: client connected");
    while let Some(msg) = socket.recv().await {
        match msg {
            Ok(Message::Text(text)) => {
                tracing::debug!(msg = %text, "ws/progress: echo text");
                if socket.send(Message::Text(text)).await.is_err() {
                    break;
                }
            }
            Ok(Message::Binary(data)) => {
                tracing::debug!(bytes = data.len(), "ws/progress: echo binary");
                if socket.send(Message::Binary(data)).await.is_err() {
                    break;
                }
            }
            Ok(Message::Ping(payload)) => {
                if socket.send(Message::Pong(payload)).await.is_err() {
                    break;
                }
            }
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(Message::Pong(_)) => {} // ignore
        }
    }
    tracing::debug!("ws/progress: client disconnected");
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
    (
        StatusCode::OK,
        "forge webui (Rust shadow) -- Phase 4 CODE-PREP",
    )
}

/// Fallback 404.
async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, Json(json!({"error": "not found"})))
}

// ─── Router builders ──────────────────────────────────────────────────────────

fn build_api_router(state: AppState) -> Router {
    // Write routes protected by JWT bearer middleware.
    let write_routes = Router::new()
        .route("/ready/refresh", post(api_ready_refresh))
        .layer(middleware::from_fn(require_bearer));

    // Read routes — unprotected.
    let read_routes = Router::new()
        .route("/health", get(api_health))
        .route("/ready", get(api_ready))
        .route("/metrics", get(api_metrics))
        .route("/ws/progress", get(api_ws_progress));

    Router::new()
        .merge(read_routes)
        .merge(write_routes)
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
    let redis_url = env::var("FORGE_REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_owned());

    let state = AppState::new();

    tracing::info!(
        version = %state.version,
        api_port,
        web_port,
        %db_url,
        %redis_url,
        "forge-server Phase 4 CODE-PREP starting"
    );

    // ── Phase 4 A: Start Redis bus probe background task ──────────────────────
    spawn_bus_probe(Arc::clone(&state.bus_connected));

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
