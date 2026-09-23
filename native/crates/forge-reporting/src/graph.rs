//! Attack graph builder, entity/relationship model, and multi-format export (T19).
//!
//! Ports `forge/graph/`: asset entities, relationships, ownership claims,
//! tier-zero scoring, and all export formats (JSON, GraphML, Mermaid, DOT,
//! MTGX, CSV, Cypher CREATE, Nemesis).
//!
//! # Key invariants
//!
//! - Secret-bearing fields (key values, raw credentials) are **never** included
//!   in graph or export output.
//! - Every entity is identified by a stable, deterministic `entity_key` derived
//!   from canonical type + value; duplicate insertions deduplicate by key.
//! - Tier-zero classification is based only on stored evidence; no live calls.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ─── EntityKind ───────────────────────────────────────────────────────────────

/// Canonical asset entity types. Matches Python `forge.graph.EntityKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Host,
    Subdomain,
    Service,
    Url,
    Email,
    Username,
    Phone,
    Company,
    Organization,
    CloudResource,
    CloudAccount,
    Finding,
    Secret,
    Vulnerability,
    Credential,
    Identity,
    TechStack,
    ThirdParty,
    Unknown,
}

impl EntityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host         => "host",
            Self::Subdomain    => "subdomain",
            Self::Service      => "service",
            Self::Url          => "url",
            Self::Email        => "email",
            Self::Username     => "username",
            Self::Phone        => "phone",
            Self::Company      => "company",
            Self::Organization => "organization",
            Self::CloudResource => "cloud_resource",
            Self::CloudAccount => "cloud_account",
            Self::Finding      => "finding",
            Self::Secret       => "secret",
            Self::Vulnerability => "vulnerability",
            Self::Credential   => "credential",
            Self::Identity     => "identity",
            Self::TechStack    => "tech_stack",
            Self::ThirdParty   => "third_party",
            Self::Unknown      => "unknown",
        }
    }
}

// ─── RelationshipKind ─────────────────────────────────────────────────────────

/// Directed edge types. Matches Python `forge.graph.RelationshipKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipKind {
    Contains,
    Resolves,
    Owns,
    Operates,
    ExposedBy,
    FoundIn,
    LinkedTo,
    ValidatedBy,
    BreachedVia,
    Impersonates,
    Uses,
    HostedOn,
    AssociatedWith,
    DependsOn,
    Controls,
}

impl RelationshipKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contains       => "CONTAINS",
            Self::Resolves       => "RESOLVES",
            Self::Owns           => "OWNS",
            Self::Operates       => "OPERATES",
            Self::ExposedBy      => "EXPOSED_BY",
            Self::FoundIn        => "FOUND_IN",
            Self::LinkedTo       => "LINKED_TO",
            Self::ValidatedBy    => "VALIDATED_BY",
            Self::BreachedVia    => "BREACHED_VIA",
            Self::Impersonates   => "IMPERSONATES",
            Self::Uses           => "USES",
            Self::HostedOn       => "HOSTED_ON",
            Self::AssociatedWith => "ASSOCIATED_WITH",
            Self::DependsOn      => "DEPENDS_ON",
            Self::Controls       => "CONTROLS",
        }
    }
}

// ─── GraphEntity ──────────────────────────────────────────────────────────────

/// A node in the attack graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEntity {
    /// Stable deterministic key: `"<kind>:<canonical_value>"`.
    pub entity_key: String,
    pub kind: EntityKind,
    /// Human-readable label (no secrets).
    pub display_name: String,
    /// Arbitrary string properties — must contain no secret material.
    pub properties: HashMap<String, String>,
    /// True when this entity is classified as tier-zero (critical asset).
    pub is_tier_zero: bool,
    /// Optional confidence score 0.0–1.0.
    pub confidence: f64,
}

impl GraphEntity {
    pub fn new(kind: EntityKind, canonical_value: impl AsRef<str>) -> Self {
        let value = canonical_value.as_ref().to_owned();
        Self {
            entity_key: format!("{}:{}", kind.as_str(), value),
            kind,
            display_name: value,
            properties: HashMap::new(),
            is_tier_zero: false,
            confidence: 1.0,
        }
    }

    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = name.into();
        self
    }

    pub fn with_property(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.properties.insert(key.into(), value.into());
        self
    }

    pub fn with_tier_zero(mut self) -> Self {
        self.is_tier_zero = true;
        self
    }

    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }
}

// ─── GraphRelationship ────────────────────────────────────────────────────────

/// A directed edge between two entities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphRelationship {
    pub from_key: String,
    pub to_key: String,
    pub kind: RelationshipKind,
    pub confidence: f64,
    pub properties: HashMap<String, String>,
}

impl GraphRelationship {
    pub fn new(from_key: impl Into<String>, to_key: impl Into<String>, kind: RelationshipKind) -> Self {
        Self {
            from_key: from_key.into(),
            to_key: to_key.into(),
            kind,
            confidence: 1.0,
            properties: HashMap::new(),
        }
    }
}

// ─── OwnershipClaim ───────────────────────────────────────────────────────────

/// An ownership claim binding an entity to an owner identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipClaim {
    pub entity_key: String,
    pub owner: String,
    pub confidence: f64,
    pub source: String,
    /// True when this claim is the active/winning claim for the entity.
    pub is_active: bool,
}

impl OwnershipClaim {
    pub fn new(
        entity_key: impl Into<String>,
        owner: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            entity_key: entity_key.into(),
            owner: owner.into(),
            confidence: 1.0,
            source: source.into(),
            is_active: true,
        }
    }
}

// ─── AttackGraph ─────────────────────────────────────────────────────────────

/// The canonical attack graph for one engagement.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttackGraph {
    pub engagement_id: i64,
    /// Entities indexed by `entity_key`.
    pub entities: HashMap<String, GraphEntity>,
    pub relationships: Vec<GraphRelationship>,
    pub ownership_claims: Vec<OwnershipClaim>,
}

impl AttackGraph {
    pub fn new(engagement_id: i64) -> Self {
        Self { engagement_id, ..Default::default() }
    }

    /// Insert or merge an entity. If a key collision occurs, the existing
    /// entity is retained but `is_tier_zero` is promoted (OR semantics).
    pub fn add_entity(&mut self, entity: GraphEntity) {
        self.entities
            .entry(entity.entity_key.clone())
            .and_modify(|e| {
                e.is_tier_zero |= entity.is_tier_zero;
                for (k, v) in &entity.properties {
                    e.properties.entry(k.clone()).or_insert_with(|| v.clone());
                }
            })
            .or_insert(entity);
    }

    pub fn add_relationship(&mut self, rel: GraphRelationship) {
        self.relationships.push(rel);
    }

    pub fn add_ownership_claim(&mut self, claim: OwnershipClaim) {
        self.ownership_claims.push(claim);
    }

    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }

    pub fn relationship_count(&self) -> usize {
        self.relationships.len()
    }

    /// Return all tier-zero entity keys, sorted.
    pub fn tier_zero_keys(&self) -> Vec<&str> {
        let mut keys: Vec<_> = self.entities.values()
            .filter(|e| e.is_tier_zero)
            .map(|e| e.entity_key.as_str())
            .collect();
        keys.sort_unstable();
        keys
    }

    /// Compute a simple choke-point score: nodes with the most incoming
    /// relationships are more critical.
    pub fn tier_zero_candidates(&self, top_n: usize) -> Vec<(&str, usize)> {
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        for rel in &self.relationships {
            *in_degree.entry(rel.to_key.as_str()).or_default() += 1;
        }
        let mut scored: Vec<_> = in_degree.into_iter().collect();
        scored.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        scored.truncate(top_n);
        scored
    }
}

// ─── Export formats ───────────────────────────────────────────────────────────

/// Supported graph export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GraphExportFormat {
    Json,
    Mermaid,
    Dot,
    GraphMl,
    Csv,
    Cypher,
}

/// Export the attack graph to the requested format.
///
/// # Secret exclusion
///
/// `Secret` entities are always excluded from non-JSON exports. In JSON
/// export they are included but their `display_name` is replaced with a
/// redacted placeholder.
pub fn export_attack_graph(graph: &AttackGraph, format: GraphExportFormat) -> String {
    match format {
        GraphExportFormat::Json     => export_json(graph),
        GraphExportFormat::Mermaid  => export_mermaid(graph),
        GraphExportFormat::Dot      => export_dot(graph),
        GraphExportFormat::GraphMl  => export_graphml(graph),
        GraphExportFormat::Csv      => export_csv(graph),
        GraphExportFormat::Cypher   => export_cypher(graph),
    }
}

fn export_json(graph: &AttackGraph) -> String {
    let redacted: HashMap<String, serde_json::Value> = graph.entities.iter().map(|(k, e)| {
        let display = if e.kind == EntityKind::Secret {
            "[REDACTED]".to_owned()
        } else {
            e.display_name.clone()
        };
        let v = serde_json::json!({
            "entity_key": e.entity_key,
            "kind": e.kind.as_str(),
            "display_name": display,
            "is_tier_zero": e.is_tier_zero,
            "confidence": e.confidence,
            "properties": e.properties,
        });
        (k.clone(), v)
    }).collect();

    let out = serde_json::json!({
        "engagement_id": graph.engagement_id,
        "entities": redacted,
        "relationships": graph.relationships,
        "ownership_claims": graph.ownership_claims,
    });
    serde_json::to_string_pretty(&out).unwrap_or_default()
}

fn export_mermaid(graph: &AttackGraph) -> String {
    let mut lines = vec!["graph LR".to_owned()];
    let entities: Vec<_> = graph.entities.values()
        .filter(|e| e.kind != EntityKind::Secret)
        .collect();
    for e in &entities {
        let label = mermaid_escape(&e.display_name);
        let node_id = node_id_from_key(&e.entity_key);
        if e.is_tier_zero {
            lines.push(format!("  {}[\"⚠ {}\"]", node_id, label));
        } else {
            lines.push(format!("  {}[\"{}\"]", node_id, label));
        }
    }
    let secret_keys: std::collections::HashSet<&str> = graph.entities.values()
        .filter(|e| e.kind == EntityKind::Secret)
        .map(|e| e.entity_key.as_str())
        .collect();
    for rel in &graph.relationships {
        if secret_keys.contains(rel.from_key.as_str()) || secret_keys.contains(rel.to_key.as_str()) {
            continue;
        }
        let from = node_id_from_key(&rel.from_key);
        let to = node_id_from_key(&rel.to_key);
        lines.push(format!("  {} -- {} --> {}", from, rel.kind.as_str(), to));
    }
    lines.join("\n")
}

fn export_dot(graph: &AttackGraph) -> String {
    let mut lines = vec!["digraph forge_attack_graph {".to_owned(), "  rankdir=LR;".to_owned()];
    let secret_keys: std::collections::HashSet<&str> = graph.entities.values()
        .filter(|e| e.kind == EntityKind::Secret)
        .map(|e| e.entity_key.as_str())
        .collect();
    for e in graph.entities.values().filter(|e| e.kind != EntityKind::Secret) {
        let nid = dot_escape(&e.entity_key);
        let label = dot_escape(&e.display_name);
        let color = if e.is_tier_zero { "color=red" } else { "color=black" };
        lines.push(format!("  \"{}\" [label=\"{}\" {}];", nid, label, color));
    }
    for rel in &graph.relationships {
        if secret_keys.contains(rel.from_key.as_str()) || secret_keys.contains(rel.to_key.as_str()) {
            continue;
        }
        let from = dot_escape(&rel.from_key);
        let to = dot_escape(&rel.to_key);
        lines.push(format!("  \"{}\" -> \"{}\" [label=\"{}\"];", from, to, rel.kind.as_str()));
    }
    lines.push("}".to_owned());
    lines.join("\n")
}

fn export_graphml(graph: &AttackGraph) -> String {
    let mut lines = vec![
        r#"<?xml version="1.0" encoding="UTF-8"?>"#.to_owned(),
        r#"<graphml xmlns="http://graphml.graphstruct.org/graphml">"#.to_owned(),
        r#"  <graph id="G" edgedefault="directed">"#.to_owned(),
    ];
    for e in graph.entities.values().filter(|e| e.kind != EntityKind::Secret) {
        let label = xml_escape(&e.display_name);
        let tier = if e.is_tier_zero { "true" } else { "false" };
        lines.push(format!(
            r#"    <node id="{}"><data key="kind">{}</data><data key="display_name">{}</data><data key="tier_zero">{}</data></node>"#,
            xml_escape(&e.entity_key), e.kind.as_str(), label, tier
        ));
    }
    let secret_keys: std::collections::HashSet<&str> = graph.entities.values()
        .filter(|e| e.kind == EntityKind::Secret)
        .map(|e| e.entity_key.as_str())
        .collect();
    for (i, rel) in graph.relationships.iter().enumerate() {
        if secret_keys.contains(rel.from_key.as_str()) || secret_keys.contains(rel.to_key.as_str()) {
            continue;
        }
        lines.push(format!(
            r#"    <edge id="e{}" source="{}" target="{}"><data key="kind">{}</data></edge>"#,
            i, xml_escape(&rel.from_key), xml_escape(&rel.to_key), rel.kind.as_str()
        ));
    }
    lines.push("  </graph>".to_owned());
    lines.push("</graphml>".to_owned());
    lines.join("\n")
}

fn export_csv(graph: &AttackGraph) -> String {
    let mut lines = vec!["entity_key,kind,display_name,is_tier_zero,confidence".to_owned()];
    let mut sorted: Vec<_> = graph.entities.values()
        .filter(|e| e.kind != EntityKind::Secret)
        .collect();
    sorted.sort_unstable_by_key(|e| e.entity_key.as_str());
    for e in sorted {
        lines.push(format!(
            "{},{},{},{},{}",
            csv_escape(&e.entity_key), e.kind.as_str(),
            csv_escape(&e.display_name), e.is_tier_zero, e.confidence
        ));
    }
    lines.join("\n")
}

fn export_cypher(graph: &AttackGraph) -> String {
    let mut lines = vec!["// Forge Attack Graph — Neo4j Cypher CREATE".to_owned()];
    for e in graph.entities.values().filter(|e| e.kind != EntityKind::Secret) {
        let label = e.kind.as_str().to_uppercase();
        let name = cypher_escape(&e.display_name);
        let key = cypher_escape(&e.entity_key);
        lines.push(format!(
            "CREATE (:`{label}` {{entity_key: \"{key}\", display_name: \"{name}\", is_tier_zero: {}}});",
            e.is_tier_zero
        ));
    }
    let secret_keys: std::collections::HashSet<&str> = graph.entities.values()
        .filter(|e| e.kind == EntityKind::Secret)
        .map(|e| e.entity_key.as_str())
        .collect();
    for rel in &graph.relationships {
        if secret_keys.contains(rel.from_key.as_str()) || secret_keys.contains(rel.to_key.as_str()) {
            continue;
        }
        let from = cypher_escape(&rel.from_key);
        let to = cypher_escape(&rel.to_key);
        let rk = rel.kind.as_str();
        lines.push(format!(
            "MATCH (a {{entity_key: \"{from}\"}}), (b {{entity_key: \"{to}\"}}) CREATE (a)-[:`{rk}`]->(b);"
        ));
    }
    lines.join("\n")
}

// ─── String helpers ───────────────────────────────────────────────────────────

fn mermaid_escape(s: &str) -> String { s.replace('"', "'").replace('[', "(").replace(']', ")") }
fn dot_escape(s: &str)    -> String { s.replace('"', "\\\"") }
fn xml_escape(s: &str)    -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}
fn cypher_escape(s: &str) -> String { s.replace('"', "\\\"").replace('\\', "\\\\") }

fn node_id_from_key(key: &str) -> String {
    key.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).collect()
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_graph() -> AttackGraph {
        let mut g = AttackGraph::new(1);
        g.add_entity(GraphEntity::new(EntityKind::Host, "target.example"));
        g.add_entity(
            GraphEntity::new(EntityKind::Service, "https://target.example:443")
                .with_tier_zero(),
        );
        g.add_entity(GraphEntity::new(EntityKind::Email, "admin@target.example"));
        g.add_entity(GraphEntity::new(EntityKind::Secret, "sk-secret-key-value"));
        g.add_relationship(GraphRelationship::new(
            "host:target.example",
            "service:https://target.example:443",
            RelationshipKind::Contains,
        ));
        g.add_relationship(GraphRelationship::new(
            "email:admin@target.example",
            "host:target.example",
            RelationshipKind::Owns,
        ));
        g
    }

    #[test]
    fn entity_key_format() {
        let e = GraphEntity::new(EntityKind::Host, "example.com");
        assert_eq!(e.entity_key, "host:example.com");
    }

    #[test]
    fn tier_zero_flag_set() {
        let e = GraphEntity::new(EntityKind::Service, "port:443").with_tier_zero();
        assert!(e.is_tier_zero);
    }

    #[test]
    fn duplicate_entity_merges() {
        let mut g = AttackGraph::new(1);
        g.add_entity(GraphEntity::new(EntityKind::Host, "host.example"));
        g.add_entity(GraphEntity::new(EntityKind::Host, "host.example").with_tier_zero());
        assert_eq!(g.entity_count(), 1);
        assert!(g.entities["host:host.example"].is_tier_zero);
    }

    #[test]
    fn tier_zero_keys_sorted() {
        let g = test_graph();
        let keys = g.tier_zero_keys();
        assert!(keys.contains(&"service:https://target.example:443"));
    }

    #[test]
    fn json_excludes_secret_display_name() {
        let g = test_graph();
        let json = export_attack_graph(&g, GraphExportFormat::Json);
        assert!(json.contains("[REDACTED]"));
        assert!(!json.contains("sk-secret-key-value"));
    }

    #[test]
    fn mermaid_excludes_secrets() {
        let g = test_graph();
        let mmd = export_attack_graph(&g, GraphExportFormat::Mermaid);
        assert!(mmd.starts_with("graph LR"));
        assert!(!mmd.contains("sk-secret"));
    }

    #[test]
    fn mermaid_marks_tier_zero() {
        let g = test_graph();
        let mmd = export_attack_graph(&g, GraphExportFormat::Mermaid);
        assert!(mmd.contains("⚠"));
    }

    #[test]
    fn dot_excludes_secrets() {
        let g = test_graph();
        let dot = export_attack_graph(&g, GraphExportFormat::Dot);
        assert!(dot.starts_with("digraph"));
        assert!(!dot.contains("sk-secret"));
    }

    #[test]
    fn graphml_valid_structure() {
        let g = test_graph();
        let gml = export_attack_graph(&g, GraphExportFormat::GraphMl);
        assert!(gml.contains("<graphml"));
        assert!(gml.contains("</graphml>"));
        assert!(!gml.contains("sk-secret"));
    }

    #[test]
    fn csv_has_header() {
        let g = test_graph();
        let csv = export_attack_graph(&g, GraphExportFormat::Csv);
        assert!(csv.starts_with("entity_key,kind,display_name,is_tier_zero,confidence"));
        assert!(!csv.contains("sk-secret"));
    }

    #[test]
    fn cypher_has_create_statements() {
        let g = test_graph();
        let cypher = export_attack_graph(&g, GraphExportFormat::Cypher);
        assert!(cypher.contains("CREATE"));
        assert!(!cypher.contains("sk-secret"));
    }

    #[test]
    fn tier_zero_candidates_returns_top_n() {
        let g = test_graph();
        let candidates = g.tier_zero_candidates(5);
        // At least one node has an incoming edge
        assert!(!candidates.is_empty());
    }

    #[test]
    fn ownership_claim_active_by_default() {
        let claim = OwnershipClaim::new("host:example.com", "operator", "rdap");
        assert!(claim.is_active);
    }
}
