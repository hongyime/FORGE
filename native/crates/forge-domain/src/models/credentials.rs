use crate::{
    enums::ValidationService,
    ids::EngagementId,
    json_boundary::{JsonBool, JsonInt},
    scalars::Label,
    secrets::SecretString,
    timestamp::Timestamp,
};
use serde::{Deserialize, Serialize};
use std::path::{Component, PathBuf};

record!(CredentialValidationResult {
    credential_id: JsonInt,
    service: ValidationService,
    host: String,
    success: JsonBool,
    error: Option<String>,
    #[serde(default = "Timestamp::now")] validated_at: Timestamp,
});
literal!(AuthType { Password => "password", Kerberos => "kerberos", Certificate => "certificate" });

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub struct SourcePath(String);
impl From<String> for SourcePath {
    fn from(value: String) -> Self {
        let path: PathBuf = PathBuf::from(value)
            .components()
            .filter(|component| !matches!(component, Component::CurDir))
            .collect();
        Self(if path.as_os_str().is_empty() {
            ".".into()
        } else {
            path.to_string_lossy().into_owned()
        })
    }
}
impl From<SourcePath> for String {
    fn from(value: SourcePath) -> Self {
        value.0
    }
}

record!(CredentialInput {
    credential_id: JsonInt,
    username: String,
    domain: Option<String>,
    password: Option<SecretString>,
    ccache_path: Option<SourcePath>,
    cert_path: Option<SourcePath>,
    key_path: Option<SourcePath>,
    #[serde(default, deserialize_with = "crate::json_boundary::provided")]
    auth_type: Option<AuthType>,
});

/// Explicit auth_type runs the source validator; an omitted default intentionally does not.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "CredentialInput")]
pub struct LateralMovementCredential {
    #[serde(flatten)]
    data: CredentialInput,
}
impl TryFrom<CredentialInput> for LateralMovementCredential {
    type Error = crate::error::DomainError;
    fn try_from(mut data: CredentialInput) -> Result<Self, Self::Error> {
        let valid = match data.auth_type {
            None => true,
            Some(AuthType::Password) => data
                .password
                .as_ref()
                .is_some_and(|p| !p.expose_secret().is_empty()),
            Some(AuthType::Kerberos) => data.ccache_path.is_some(),
            Some(AuthType::Certificate) => data.cert_path.is_some() && data.key_path.is_some(),
        };
        if !valid {
            return Err(crate::error::DomainError::InvalidAuthMaterial);
        }
        data.auth_type = Some(data.auth_type.unwrap_or(AuthType::Password));
        Ok(Self { data })
    }
}
impl LateralMovementCredential {
    pub fn data(&self) -> &CredentialInput {
        &self.data
    }
}
record!(LateralMovementResult {
    #[serde(deserialize_with = "crate::json_boundary::engagement")]
    engagement_id: EngagementId,
    #[serde(deserialize_with = "crate::json_boundary::required_nullable")]
    source_host_id: Option<JsonInt>,
    target_host_id: JsonInt,
    technique: String,
    #[serde(deserialize_with = "crate::json_boundary::required_nullable")]
    credential_id: Option<JsonInt>,
    command: String,
    success: Option<JsonBool>,
    output: Option<Label<65536>>,
    #[serde(default)] scope_verified: JsonBool,
    #[serde(default)] operator_confirmed: JsonBool,
    #[serde(default = "Timestamp::now")] executed_at: Timestamp,
});
