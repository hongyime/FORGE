//! `forge-reporting` — Attack graph, entity model, ownership, and exports (T19).
//!
//! # Modules
//!
//! - `graph` — T19: `EntityKind`, `GraphEntity`, `RelationshipKind`,
//!   `GraphRelationship`, `AttackGraph`, `export_attack_graph` (JSON/Mermaid/DOT/GraphML/CSV/Cypher).

pub mod graph;

pub use graph::{
    AttackGraph, EntityKind, GraphEntity, GraphExportFormat, GraphRelationship,
    OwnershipClaim, RelationshipKind, export_attack_graph,
};
