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
mod reference;
mod reports;
pub use commands::*;
pub use credentials::*;
pub use descriptors::*;
pub use discovery::*;
pub use findings::*;
pub use reference::*;
pub use reports::*;

fn true_value() -> crate::json_boundary::JsonBool {
    crate::json_boundary::JsonBool::new(true)
}
