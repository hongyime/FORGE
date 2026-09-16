use crate::{
    enums::{C2Channel, OsFamily},
    ids::EngagementId,
    json_boundary::{Integer, JsonBool, JsonInt},
    scalars::C2Url,
    timestamp::Timestamp,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

literal!(PayloadType { ReverseShell => "reverse_shell", C2Beacon => "c2_beacon", Dropper => "dropper", Stager => "stager" });
record!(PayloadSpec {
    #[serde(deserialize_with = "crate::json_boundary::engagement")]
    engagement_id: EngagementId,
    payload_type: PayloadType,
    target_os: OsFamily,
    technique: String,
    lhost: String,
    lport: Integer<1, 65535>,
    #[serde(default)] obfuscation_chain: Vec<String>,
    lots_host: Option<String>,
    #[serde(default = "super::true_value")] metadata_stripped: JsonBool,
});
record!(ObfuscationResult {
    criterion: String,
    input_hash: String,
    output_hash: String,
    #[serde(default = "Timestamp::now")]
    applied_at: Timestamp,
});
record!(PersistenceSpec {
    #[serde(deserialize_with = "crate::json_boundary::engagement")]
    engagement_id: EngagementId,
    host_id: Option<JsonInt>,
    technique: String,
    target_os: OsFamily,
    install_cmd: String,
    cleanup_cmd: Option<String>,
    #[serde(default)] lolbins_used: Vec<String>,
    #[serde(default)] obfuscation_applied: JsonBool,
});
fn http() -> C2Channel {
    C2Channel::Http
}
record!(BeaconInput {
    #[serde(deserialize_with = "crate::json_boundary::engagement")]
    engagement_id: EngagementId,
    host_id: Option<JsonInt>,
    #[serde(default = "Integer::<5, 3600>::constant::<30>")] beacon_interval: Integer<5, 3600>,
    #[serde(default = "Integer::<0, 50>::constant::<15>")] jitter_pct: Integer<0, 50>,
    c2_urls: Vec<C2Url>,
    #[serde(default = "http")] channel: C2Channel,
    #[serde(default = "super::true_value")] sleep_mask: JsonBool,
    smb_pipe_name: Option<String>,
    #[serde(default = "Integer::<10, 300>::constant::<30>")] smb_fallback_timeout: Integer<10, 300>,
    smb_username: Option<String>,
    smb_domain: Option<String>,
    icmp_target_ip: Option<String>,
    #[serde(default = "Integer::<30, 600>::constant::<180>")] icmp_packet_interval: Integer<30, 600>,
    #[serde(default = "Integer::<32, 128>::constant::<64>")] icmp_max_payload_size: Integer<32, 128>,
});

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "BeaconInput")]
pub struct C2BeaconConfig {
    #[serde(flatten)]
    data: BeaconInput,
}
impl TryFrom<BeaconInput> for C2BeaconConfig {
    type Error = crate::error::DomainError;
    fn try_from(mut data: BeaconInput) -> Result<Self, Self::Error> {
        let invalid = data.c2_urls.is_empty()
            || data
                .smb_pipe_name
                .as_ref()
                .is_some_and(|p| matches!(p.to_lowercase().as_str(), "svcctl" | "epmapper"))
            || data
                .icmp_target_ip
                .as_ref()
                .is_some_and(|p| p.parse::<Ipv4Addr>().is_err());
        if invalid {
            return Err(crate::error::DomainError::InvalidDescriptor);
        }
        match data.channel {
            C2Channel::Icmp if data.icmp_target_ip.is_none() => {
                return Err(crate::error::DomainError::InvalidDescriptor);
            }
            C2Channel::Smb => {
                if data.smb_pipe_name.as_ref().is_none_or(String::is_empty) {
                    let choices = ["atsvc", "winreg", "lsarpc", "browser", "netlogon"];
                    data.smb_pipe_name =
                        Some(choices[rand::thread_rng().gen_range(0..choices.len())].into());
                }
            }
            C2Channel::Http | C2Channel::Dns | C2Channel::Icmp => {}
        }
        Ok(Self { data })
    }
}
impl C2BeaconConfig {
    pub fn data(&self) -> &BeaconInput {
        &self.data
    }
}
