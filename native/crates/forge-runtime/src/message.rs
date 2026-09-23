//! Message envelope types shared by all bus implementations (T10).
//!
//! `AgentMessage` is the common event envelope; `BusEnvelope` is the JSON
//! wire format used for serialization across pub/sub transports.

use serde::{Deserialize, Serialize};

/// Common event envelope carried across all bus implementations.
///
/// Matches Python's `AgentMessage` from `forge.core.message_models`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMessage {
    /// Routing key (must be in `ALLOWED_TOPICS` for typed buses).
    pub topic: String,
    /// ID of the plugin or component that published this event.
    pub source_plugin_id: String,
    /// Engagement context; 0 for engagement-agnostic events.
    pub engagement_id: i64,
    /// Correlation ID for tracing across async boundaries.
    pub correlation_id: String,
    /// Arbitrary JSON payload.
    pub payload: serde_json::Value,
    /// Unique event identifier (UUID).
    pub event_id: String,
    /// UTC ISO-8601 timestamp.
    pub timestamp_utc: String,
}

impl AgentMessage {
    /// Construct a new `AgentMessage` with generated `event_id` and current
    /// UTC timestamp.
    pub fn new(
        topic: impl Into<String>,
        source_plugin_id: impl Into<String>,
        engagement_id: i64,
        payload: serde_json::Value,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            topic: topic.into(),
            source_plugin_id: source_plugin_id.into(),
            engagement_id,
            correlation_id: format!("corr-{ts}"),
            payload,
            event_id: format!("evt-{ts}"),
            timestamp_utc: format!("{ts}"),
        }
    }
}

/// JSON wire format: `{"topic": "…", "payload": {…}}`.
///
/// Used by `LocalBus` and `RedisBus` for serialisation so both transports
/// are format-compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusEnvelope {
    pub topic: String,
    pub payload: serde_json::Value,
}

impl BusEnvelope {
    pub fn from_message(msg: &AgentMessage) -> Self {
        Self {
            topic: msg.topic.clone(),
            payload: serde_json::to_value(msg).unwrap_or(serde_json::json!({})),
        }
    }

    pub fn into_message(self) -> Result<AgentMessage, serde_json::Error> {
        serde_json::from_value(self.payload)
    }
}
