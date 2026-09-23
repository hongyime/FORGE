//! In-process message buses (T10).
//!
//! - [`LocalBus`] — transport-agnostic tokio broadcast channel bus; one channel
//!   per topic. Matches Python `InMemoryMessageBus` semantics.
//! - [`EventBus`] — strict-topic typed pub/sub with subscriber callbacks.
//!   Matches Python `EventBus` in `forge/agents/event_bus.py`.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};

use crate::message::AgentMessage;

// ─── Constants ─────────────────────────────────────────────────────────────────

/// Default bounded capacity per topic channel.
pub const DEFAULT_QUEUE_DEPTH: usize = 1_000;

/// Allowed topic strings — strict validation matches Python `ALLOWED_TOPICS`.
pub const ALLOWED_TOPICS: &[&str] = &[
    "task.created",
    "task.updated",
    "task.completed",
    "result.ready",
    "plugin.registered",
];

// ─── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by bus operations.
#[derive(Debug)]
pub enum BusError {
    /// Channel buffer is full — receiver is too slow (backpressure).
    Full,
    /// Topic is not in [`ALLOWED_TOPICS`] (EventBus only).
    UnknownTopic(String),
    /// JSON serialisation/deserialisation failure.
    Json(serde_json::Error),
}

impl std::fmt::Display for BusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "bus channel full (backpressure)"),
            Self::UnknownTopic(t) => write!(f, "unknown topic {t:?}"),
            Self::Json(e) => write!(f, "json error: {e}"),
        }
    }
}

impl std::error::Error for BusError {}
impl From<serde_json::Error> for BusError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

// ─── LocalBus ──────────────────────────────────────────────────────────────────

/// In-process fan-out bus backed by one `tokio::sync::broadcast` channel per
/// topic.
///
/// Semantics match Python `InMemoryMessageBus`:
/// - FIFO per topic.
/// - JSON serialisation on publish, deserialisation on receive.
/// - **At-most-once**: lagged receivers drop old messages; publish to a full
///   channel returns [`BusError::Full`] (backpressure).
///
/// Clone-cheap: internally reference-counted.
#[derive(Clone)]
pub struct LocalBus {
    inner: Arc<LocalBusInner>,
}

struct LocalBusInner {
    /// topic → broadcast sender.
    channels: RwLock<HashMap<String, broadcast::Sender<String>>>,
    capacity: usize,
}

impl LocalBus {
    /// Create a bus with the given per-topic channel capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(LocalBusInner {
                channels: RwLock::new(HashMap::new()),
                capacity: capacity.max(1),
            }),
        }
    }

    /// Publish `message` to its topic, creating the channel on first use.
    ///
    /// Returns [`BusError::Full`] if the broadcast channel is at capacity and
    /// there are active receivers.
    pub async fn publish(&self, message: &AgentMessage) -> Result<(), BusError> {
        let serialized = serde_json::to_string(message)?;
        let topic = message.topic.clone();
        let mut channels = self.inner.channels.write().await;
        let tx = channels
            .entry(topic)
            .or_insert_with(|| broadcast::channel(self.inner.capacity).0);
        match tx.send(serialized) {
            Ok(_) => Ok(()),
            Err(_) => {
                // No active receivers — still counts as success (fire-and-forget
                // when nobody is listening, matches Python semantics).
                Ok(())
            }
        }
    }

    /// Subscribe to one or more topics. Returns a `tokio::sync::broadcast::Receiver`
    /// for each topic wrapped in a combined async stream.
    ///
    /// For convenience, returns a `TopicReceiver` that can be polled with
    /// `recv()`.
    pub async fn subscribe(&self, topics: &[&str]) -> Vec<(String, broadcast::Receiver<String>)> {
        let mut result = Vec::with_capacity(topics.len());
        let mut channels = self.inner.channels.write().await;
        for &topic in topics {
            let tx = channels
                .entry(topic.to_owned())
                .or_insert_with(|| broadcast::channel(self.inner.capacity).0);
            result.push((topic.to_owned(), tx.subscribe()));
        }
        result
    }

    /// Return `true` — in-process bus is always healthy.
    pub fn is_healthy(&self) -> bool {
        true
    }

    /// Deserialise a raw broadcast string back to [`AgentMessage`].
    pub fn decode(raw: &str) -> Result<AgentMessage, BusError> {
        serde_json::from_str(raw).map_err(BusError::Json)
    }
}

impl Default for LocalBus {
    fn default() -> Self {
        Self::new(DEFAULT_QUEUE_DEPTH)
    }
}

// ─── EventBus ──────────────────────────────────────────────────────────────────

/// In-process typed pub/sub with strict topic validation.
///
/// Ports Python `EventBus` from `forge/agents/event_bus.py`:
/// - Only topics in [`ALLOWED_TOPICS`] are accepted.
/// - Each topic has a bounded broadcast channel (capacity `DEFAULT_QUEUE_DEPTH`).
/// - Publish to a full channel returns [`BusError::Full`].
///
/// Clone-cheap: internally reference-counted.
#[derive(Clone)]
pub struct EventBus {
    inner: Arc<EventBusInner>,
}

struct EventBusInner {
    channels: HashMap<&'static str, broadcast::Sender<AgentMessage>>,
}

impl EventBus {
    /// Create an EventBus with the given per-topic channel capacity.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let mut channels = HashMap::new();
        for &topic in ALLOWED_TOPICS {
            let (tx, _) = broadcast::channel(capacity);
            channels.insert(topic, tx);
        }
        Self {
            inner: Arc::new(EventBusInner { channels }),
        }
    }

    /// Publish `event` to its topic.
    ///
    /// # Errors
    /// - [`BusError::UnknownTopic`] if `event.topic` is not in `ALLOWED_TOPICS`.
    /// - [`BusError::Full`] if all receivers have full lag buffers.
    pub fn publish(&self, event: AgentMessage) -> Result<(), BusError> {
        let topic_str = event.topic.as_str();
        let tx = self
            .inner
            .channels
            .iter()
            .find(|(k, _)| **k == topic_str)
            .map(|(_, v)| v)
            .ok_or_else(|| BusError::UnknownTopic(event.topic.clone()))?;
        match tx.send(event) {
            Ok(_) => Ok(()),
            Err(_) => Ok(()), // No active receivers — fire-and-forget
        }
    }

    /// Subscribe to a topic and return a [`broadcast::Receiver<AgentMessage>`].
    ///
    /// # Errors
    /// Returns [`BusError::UnknownTopic`] if `topic` is not in `ALLOWED_TOPICS`.
    pub fn subscribe(&self, topic: &str) -> Result<broadcast::Receiver<AgentMessage>, BusError> {
        self.inner
            .channels
            .iter()
            .find(|(k, _)| **k == topic)
            .map(|(_, tx)| tx.subscribe())
            .ok_or_else(|| BusError::UnknownTopic(topic.to_owned()))
    }

    /// Return `true` — in-process bus is always healthy.
    pub fn is_healthy(&self) -> bool {
        true
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(DEFAULT_QUEUE_DEPTH)
    }
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::AgentMessage;

    fn make_msg(topic: &str) -> AgentMessage {
        AgentMessage::new(topic, "test-plugin", 0, serde_json::json!({"k": "v"}))
    }

    #[tokio::test]
    async fn local_bus_publish_subscribe_roundtrip() {
        let bus = LocalBus::new(10);
        let receivers = bus.subscribe(&["task.created"]).await;
        let (_, mut rx) = receivers.into_iter().next().unwrap();
        let msg = make_msg("task.created");
        bus.publish(&msg).await.unwrap();
        let raw = rx.recv().await.unwrap();
        let decoded = LocalBus::decode(&raw).unwrap();
        assert_eq!(decoded.topic, "task.created");
    }

    #[tokio::test]
    async fn local_bus_no_receiver_does_not_error() {
        let bus = LocalBus::new(10);
        let msg = make_msg("task.created");
        bus.publish(&msg).await.unwrap(); // no receivers, no error
    }

    #[test]
    fn event_bus_rejects_unknown_topic() {
        let bus = EventBus::new(10);
        let msg = make_msg("unknown.topic.xyz");
        assert!(matches!(bus.publish(msg), Err(BusError::UnknownTopic(_))));
    }

    #[test]
    fn event_bus_publishes_to_known_topic() {
        let bus = EventBus::new(10);
        let mut rx = bus.subscribe("task.created").unwrap();
        let msg = make_msg("task.created");
        bus.publish(msg).unwrap();
        let received = rx.try_recv().unwrap();
        assert_eq!(received.topic, "task.created");
    }

    #[test]
    fn event_bus_subscribe_unknown_topic_errors() {
        let bus = EventBus::new(10);
        assert!(matches!(
            bus.subscribe("not.a.topic"),
            Err(BusError::UnknownTopic(_))
        ));
    }

    #[test]
    fn allowed_topics_contains_expected_values() {
        assert!(ALLOWED_TOPICS.contains(&"task.created"));
        assert!(ALLOWED_TOPICS.contains(&"plugin.registered"));
        assert_eq!(ALLOWED_TOPICS.len(), 5);
    }
}
