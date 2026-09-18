//! Central source-model DTOs only; these types never execute described actions.
macro_rules! record {
    ($name:ident { $($(#[$attr:meta])* $field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name { $($(#[$attr])* pub $field: $ty,)* }
    };
}
macro_rules! literal {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        pub enum $name { $(#[serde(rename = $wire)] $variant),+ }
    };
}
mod commands;
mod credentials;
mod descriptors;
mod discovery;
mod findings;
mod hash_credentials;
mod reference;
mod reports;
mod source_credentials;
pub use commands::*;
pub use credentials::*;
pub use descriptors::*;
pub use discovery::*;
pub use findings::*;
pub use hash_credentials::*;
pub use reference::*;
pub use reports::*;
pub use source_credentials::*;

fn true_value() -> crate::json_boundary::JsonBool {
    crate::json_boundary::JsonBool::new(true)
}
