use std::fmt;

/// Validation errors deliberately contain no rejected values or secret material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DomainError {
    TooLong { max_chars: usize },
    OutOfRange { field: &'static str },
    ForbiddenMetadata,
    DanglingEdges { references: usize },
    InvalidPluginId,
    InvalidC2Url,
    InvalidAuthMaterial,
    InvalidDescriptor,
    InvalidEventSource,
    InvalidManifestVersion,
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { max_chars } => write!(f, "text exceeds {max_chars} characters"),
            Self::OutOfRange { field } => write!(f, "{field} outside permitted range"),
            Self::ForbiddenMetadata => f.write_str("forbidden sensitive metadata key"),
            Self::DanglingEdges { references } => {
                write!(f, "{references} dangling edge references")
            }
            Self::InvalidPluginId => f.write_str("invalid plugin identifier"),
            Self::InvalidC2Url => f.write_str("invalid C2 URL"),
            Self::InvalidAuthMaterial => f.write_str("missing required authentication material"),
            Self::InvalidDescriptor => f.write_str("invalid descriptor fields"),
            Self::InvalidEventSource => f.write_str("event source must not be empty"),
            Self::InvalidManifestVersion => f.write_str("manifest version must not be empty"),
        }
    }
}
impl std::error::Error for DomainError {}
