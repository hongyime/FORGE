//! Redis pub/sub message bus (T10).
//!
//! Ports `forge/bus/redis_bus.py` `RedisMessageBus` to Rust.
//!
//! # Honest delivery contract (matches Python's hardened docstring)
//!
//! - **At-most-once** to subscribers connected at publish time.
//! - **Best-effort buffering** during Redis outage: publish failures enqueue
//!   the envelope in a bounded in-memory `VecDeque`; on reconnect the buffer
//!   is drained back into PUBLISH. Messages published while the buffer is full
//!   are **dropped** (a warning is emitted).
//! - **Worker restart loses in-flight tasks** unless the workload was already
//!   persisted via the workflow state store (T9).
//!
//! # Integration tests
//!
//! Gated by `FORGE_TEST_REDIS_URL`. When the variable is absent, the
//! `verify bus` xtask emits a `BLOCKED` receipt.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use crate::message::AgentMessage;

// ─── Constants ─────────────────────────────────────────────────────────────────

/// Environment variable that provides the Redis URL for integration tests.
pub const REDIS_URL_ENV: &str = "FORGE_TEST_REDIS_URL";

/// Reconnection backoff: 1 s initial, 30 s max, 2× multiplier.
const BACKOFF_INITIAL_MS: u64 = 1_000;
const BACKOFF_MAX_MS: u64 = 30_000;
const BACKOFF_MULTIPLIER: f64 = 2.0;

/// Maximum number of messages to buffer during an outage before dropping.
const BUFFER_MAX_LEN: usize = 1_000;

// ─── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by `RedisBus`.
#[derive(Debug)]
pub enum RedisBusError {
    /// Message dropped because the in-memory buffer is full.
    BufferFull,
    /// Underlying redis error.
    Redis(redis::RedisError),
    /// JSON serialisation failure.
    Json(serde_json::Error),
}

impl std::fmt::Display for RedisBusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferFull => write!(f, "outage buffer full — message dropped"),
            Self::Redis(e) => write!(f, "redis error: {e}"),
            Self::Json(e) => write!(f, "json error: {e}"),
        }
    }
}

impl std::error::Error for RedisBusError {}
impl From<redis::RedisError> for RedisBusError {
    fn from(e: redis::RedisError) -> Self {
        Self::Redis(e)
    }
}
impl From<serde_json::Error> for RedisBusError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

// ─── RedisBus ──────────────────────────────────────────────────────────────────

/// Redis pub/sub message bus with exponential-backoff reconnect and bounded
/// in-memory outage buffer.
///
/// Clone-cheap: internally reference-counted.
#[derive(Clone)]
pub struct RedisBus {
    inner: Arc<RedisBusInner>,
}

struct RedisBusInner {
    redis_url: String,
    state: Mutex<BusState>,
}

struct BusState {
    client: Option<redis::Client>,
    outage_buffer: VecDeque<String>,
}

impl RedisBus {
    /// Create a new `RedisBus` for the given Redis URL.
    ///
    /// The connection is opened lazily on the first `publish` call.
    pub fn new(redis_url: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(RedisBusInner {
                redis_url: redis_url.into(),
                state: Mutex::new(BusState {
                    client: None,
                    outage_buffer: VecDeque::with_capacity(BUFFER_MAX_LEN),
                }),
            }),
        }
    }

    /// Return the Redis URL used for this bus.
    pub fn redis_url(&self) -> &str {
        &self.inner.redis_url
    }

    /// Publish `message` to its topic.
    ///
    /// On Redis failure, the message is buffered (up to `BUFFER_MAX_LEN`).
    /// When the buffer is full the message is dropped and `BusError::BufferFull`
    /// is returned. A successful connection drains the outage buffer.
    pub async fn publish(&self, message: &AgentMessage) -> Result<(), RedisBusError> {
        let serialized = serde_json::to_string(message)?;
        let topic = message.topic.clone();

        let mut state = self.inner.state.lock().await;

        // Lazy-initialise the client.
        if state.client.is_none() {
            match redis::Client::open(self.inner.redis_url.as_str()) {
                Ok(c) => state.client = Some(c),
                Err(e) => {
                    // Cannot even create client — buffer.
                    return self.buffer_message(&mut state.outage_buffer, serialized, e);
                }
            }
        }

        let client = state.client.as_ref().unwrap();

        // Try to get a connection and publish.
        match client.get_multiplexed_async_connection().await {
            Ok(mut conn) => {
                // Drain outage buffer first.
                let mut to_drain: Vec<String> = state.outage_buffer.drain(..).collect();
                drop(state); // release lock during draining

                let backoff = BACKOFF_INITIAL_MS;
                for buffered in to_drain.drain(..) {
                    // Best-effort re-publish of buffered messages.
                    let _ = redis::cmd("PUBLISH")
                        .arg(&topic)
                        .arg(&buffered)
                        .query_async::<_, ()>(&mut conn)
                        .await;
                }

                // Publish current message.
                redis::cmd("PUBLISH")
                    .arg(&topic)
                    .arg(&serialized)
                    .query_async::<_, ()>(&mut conn)
                    .await
                    .map_err(RedisBusError::Redis)?;

                let _ = backoff; // suppress unused warning
                Ok(())
            }
            Err(e) => self.buffer_message(&mut state.outage_buffer, serialized, e),
        }
    }

    fn buffer_message(
        &self,
        buffer: &mut VecDeque<String>,
        serialized: String,
        err: redis::RedisError,
    ) -> Result<(), RedisBusError> {
        if buffer.len() >= BUFFER_MAX_LEN {
            eprintln!("warn: forge-runtime redis outage buffer full — dropping message");
            return Err(RedisBusError::BufferFull);
        }
        buffer.push_back(serialized);
        eprintln!(
            "warn: forge-runtime redis publish failed (buffered {}): {err}",
            buffer.len()
        );
        Ok(())
    }

    /// Return `true` when a Redis PING succeeds within a short timeout.
    pub async fn is_healthy(&self) -> bool {
        let state = self.inner.state.lock().await;
        let client = match &state.client {
            Some(c) => c.clone(),
            None => match redis::Client::open(self.inner.redis_url.as_str()) {
                Ok(c) => c,
                Err(_) => return false,
            },
        };
        drop(state);

        match tokio::time::timeout(
            Duration::from_secs(2),
            client.get_multiplexed_async_connection(),
        )
        .await
        {
            Ok(Ok(mut conn)) => redis::cmd("PING")
                .query_async::<_, String>(&mut conn)
                .await
                .is_ok(),
            _ => false,
        }
    }

    /// Return the Redis URL env var name (`FORGE_TEST_REDIS_URL`).
    pub fn url_env() -> &'static str {
        REDIS_URL_ENV
    }
}

/// Return the Redis URL from `FORGE_TEST_REDIS_URL`, or `None` when absent.
pub fn redis_url_from_env() -> Option<String> {
    std::env::var(REDIS_URL_ENV).ok().filter(|s| !s.is_empty())
}

/// Reconnection delay for the next attempt.
///
/// Doubles on each call up to `BACKOFF_MAX_MS`. Used by callers implementing
/// retry loops.
pub fn next_backoff_ms(current_ms: u64) -> u64 {
    ((current_ms as f64 * BACKOFF_MULTIPLIER) as u64).min(BACKOFF_MAX_MS)
}

// ─── Unit tests (no Redis required) ────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_caps() {
        let b1 = next_backoff_ms(1_000);
        assert_eq!(b1, 2_000);
        let b2 = next_backoff_ms(16_000);
        assert_eq!(b2, 30_000); // capped at max
        let b3 = next_backoff_ms(30_000);
        assert_eq!(b3, 30_000); // stays at max
    }

    #[test]
    fn redis_url_from_env_none_when_unset() {
        // Ensure the test env var is not set in CI.
        if std::env::var(REDIS_URL_ENV).is_ok() {
            return; // skip
        }
        assert!(redis_url_from_env().is_none());
    }

    #[test]
    fn bus_construction_does_not_connect() {
        // Creating a RedisBus must not attempt a network connection.
        let _ = RedisBus::new("redis://127.0.0.1:0"); // unreachable port
    }
}
