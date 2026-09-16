use crate::{
    enums::OsFamily, ids::EngagementId, json_boundary::JsonInt, metadata::JsonObject,
    timestamp::Timestamp,
};
use serde::{Deserialize, Serialize};
fn crt_sh() -> String {
    "crt_sh".into()
}
fn tcp() -> String {
    "tcp".into()
}
record!(SubdomainResult {
    #[serde(deserialize_with = "crate::json_boundary::engagement")]
    engagement_id: EngagementId,
    domain: String,
    #[serde(default)] ip_addresses: Vec<String>,
    #[serde(default = "crt_sh")] source: String,
    #[serde(default = "Timestamp::now")] discovered_at: Timestamp,
});
record!(ServiceBanner {
    host_id: JsonInt,
    port: JsonInt,
    #[serde(default = "tcp")] protocol: String,
    service_name: Option<String>,
    banner: Option<String>,
    version: Option<String>,
});
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HostContext {
    pub os_family: Option<OsFamily>,
    pub web_server: Option<String>,
    #[serde(default)]
    pub detected_cdns: Vec<String>,
    #[serde(default)]
    pub trusted_domains: Vec<String>,
    pub user_agent_hint: Option<String>,
    #[serde(default)]
    pub scheduled_tasks: Vec<String>,
    pub beacon_interval_hint: Option<JsonInt>,
    #[serde(flatten)]
    pub extra: JsonObject,
}
