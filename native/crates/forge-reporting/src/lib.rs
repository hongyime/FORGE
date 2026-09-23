//! `forge-reporting` — Attack graph, entity model, ownership, exports, reports (T19–T20).
//!
//! # Modules
//!
//! - `graph` — T19: `EntityKind`, `GraphEntity`, `RelationshipKind`,
//!   `GraphRelationship`, `AttackGraph`, `export_attack_graph` (JSON/Mermaid/DOT/GraphML/CSV/Cypher).
//! - `reports` — T20: `ReportFamily`, `ProviderCascade`, `ReportArtifact`,

pub mod graph;
pub mod reports;

pub use graph::{
    AttackGraph, EntityKind, GraphEntity, GraphExportFormat, GraphRelationship,
    OwnershipClaim, RelationshipKind, export_attack_graph,
};

pub use reports::{
    FindingSummary, ProviderCascade, ProviderKind, ReportArtifact, ReportContext, ReportFamily,
    SeveritySummary, checksum_sha256_hex, raw_csv_export, raw_json_export,
    render_template_report,
};
