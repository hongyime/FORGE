use crate::{
    enums::OsFamily,
    json_boundary::{Integer, JsonFloat, JsonInt},
    timestamp::Timestamp,
};
fn lolbas() -> String {
    "lolbas".into()
}
record!(LolbinRecord {
    name: String,
    os_family: OsFamily,
    category: String,
    description: String,
    commands: Vec<String>,
    #[serde(default)] mitre_ids: Vec<String>,
    #[serde(default = "Integer::<1, 10>::constant::<5>")] stealth_rank: Integer<1, 10>,
    #[serde(default = "lolbas")] source: String,
});
record!(ExploitRecord {
    exploit_id: JsonInt,
    title: String,
    author: String,
    platform: String,
    #[serde(rename(deserialize = "type", serialize = "type_"))] type_: String,
    date_pub: Option<Timestamp>,
    #[serde(default)] cve_ids: Vec<String>,
    path: Option<String>,
});
record!(CveRecord {
    cve_id: String,
    description: String,
    cvss_v3: Option<JsonFloat>,
    cvss_v2: Option<JsonFloat>,
    severity: Option<String>,
    published_at: Option<Timestamp>,
    modified_at: Option<Timestamp>,
    #[serde(default)] cpe_matches: Vec<String>,
});
