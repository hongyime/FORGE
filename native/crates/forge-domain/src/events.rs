//! Validated source event data; no queue, dispatch, subscription or runtime behavior.
use crate::{error::DomainError, ids::EngagementId, metadata::JsonObject};
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EventTopic {
    #[serde(rename = "plugin.registered")]
    PluginRegistered,
    #[serde(rename = "result.ready")]
    ResultReady,
    #[serde(rename = "task.completed")]
    TaskCompleted,
    #[serde(rename = "task.created")]
    TaskCreated,
    #[serde(rename = "task.updated")]
    TaskUpdated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EventSource(String);
impl TryFrom<String> for EventSource {
    type Error = DomainError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(DomainError::InvalidEventSource)
        } else {
            Ok(Self(value))
        }
    }
}
impl From<EventSource> for String {
    fn from(value: EventSource) -> Self {
        value.0
    }
}

pub(crate) fn timestamp_utc() -> String {
    let t = time::OffsetDateTime::now_utc();
    let base = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    if t.microsecond() == 0 {
        format!("{base}+00:00")
    } else {
        format!("{base}.{:06}+00:00", t.microsecond())
    }
}

fn event_id() -> String {
    let mut bytes: [u8; 16] = rand::thread_rng().r#gen();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut output = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            output.push('-');
        }
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEvent {
    pub topic: EventTopic,
    pub source_plugin_id: EventSource,
    pub engagement_id: EngagementId,
    pub payload: JsonObject,
    #[serde(default = "event_id")]
    pub event_id: String,
    #[serde(default = "timestamp_utc")]
    pub timestamp_utc: String,
}
