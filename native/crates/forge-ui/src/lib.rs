//! `forge-ui` — Rust UI scaffold: Leptos SSR routes, overview, engagement detail (T28–T30).
//!
//! # Modules
//!
//! - `ui` — T28–T30: `UIRoute`, `EngagementSummary`, `OverviewView`,
//!   `DetailTab`, `EngagementDetailView`, `WorkspacePanel`.

pub mod ui;

pub use ui::{
    DetailTab, EngagementDetailView, EngagementStatus, EngagementSummary,
    OverviewView, UIRoute, WorkspacePanel,
};
