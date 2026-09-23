//! Canary verifier for T19 — attack graph builder and multi-format exports.
//!
//! All canaries are in-memory; no network calls are made.

use std::path::Path;
use forge_reporting::{
    AttackGraph, EntityKind, GraphEntity, GraphExportFormat, GraphRelationship,
    OwnershipClaim, RelationshipKind, export_attack_graph,
};

pub fn run(_root: &Path, _evidence: &Path) -> crate::model::Result<i32> {
    let mut failures: Vec<String> = Vec::new();

    macro_rules! check {
        ($label:expr, $cond:expr) => {
            if !($cond) {
                failures.push(format!("FAIL [{}]: {}", $label, stringify!($cond)));
            }
        };
    }

    // ── EntityKind / entity key format ────────────────────────────────────────

    let host = GraphEntity::new(EntityKind::Host, "target.example");
    check!("entity/key_format",     host.entity_key == "host:target.example");
    check!("entity/display_name",   host.display_name == "target.example");
    check!("entity/not_tier_zero",  !host.is_tier_zero);
    check!("entity/confidence_1",   (host.confidence - 1.0).abs() < f64::EPSILON);

    let svc = GraphEntity::new(EntityKind::Service, "https://target.example:443")
        .with_tier_zero()
        .with_property("port", "443");
    check!("entity/tier_zero_flag",  svc.is_tier_zero);
    check!("entity/property_stored", svc.properties.get("port").map(|s| s.as_str()) == Some("443"));

    // ── RelationshipKind str ──────────────────────────────────────────────────

    check!("rel/contains_str",    RelationshipKind::Contains.as_str()    == "CONTAINS");
    check!("rel/resolves_str",    RelationshipKind::Resolves.as_str()    == "RESOLVES");
    check!("rel/owns_str",        RelationshipKind::Owns.as_str()        == "OWNS");
    check!("rel/linked_to_str",   RelationshipKind::LinkedTo.as_str()    == "LINKED_TO");
    check!("rel/found_in_str",    RelationshipKind::FoundIn.as_str()     == "FOUND_IN");

    // ── AttackGraph: add_entity, dedup ───────────────────────────────────────

    let mut g = AttackGraph::new(42);
    check!("graph/empty_entities",  g.entity_count() == 0);
    check!("graph/empty_rels",      g.relationship_count() == 0);
    check!("graph/engagement_id",   g.engagement_id == 42);

    g.add_entity(GraphEntity::new(EntityKind::Host, "target.example"));
    g.add_entity(GraphEntity::new(EntityKind::Service, "port:443").with_tier_zero());
    g.add_entity(GraphEntity::new(EntityKind::Email, "admin@target.example"));
    g.add_entity(GraphEntity::new(EntityKind::Secret, "sk-1234")); // should be excluded from exports
    check!("graph/4_entities",  g.entity_count() == 4);

    // Duplicate → dedup, tier_zero promoted
    g.add_entity(GraphEntity::new(EntityKind::Host, "target.example").with_tier_zero());
    check!("graph/dedup_5_becomes_4",       g.entity_count() == 4); // no new entry
    check!("graph/dedup_tier_zero_merged",  g.entities["host:target.example"].is_tier_zero);

    // ── Relationships ─────────────────────────────────────────────────────────

    g.add_relationship(GraphRelationship::new(
        "host:target.example", "service:port:443", RelationshipKind::Contains,
    ));
    g.add_relationship(GraphRelationship::new(
        "email:admin@target.example", "host:target.example", RelationshipKind::Owns,
    ));
    check!("graph/2_rels",  g.relationship_count() == 2);

    // ── Tier-zero keys ────────────────────────────────────────────────────────

    let tz_keys = g.tier_zero_keys();
    check!("graph/tz_service_present",  tz_keys.contains(&"service:port:443"));
    check!("graph/tz_host_present",     tz_keys.contains(&"host:target.example")); // promoted by dedup
    check!("graph/tz_secret_absent",    !tz_keys.contains(&"secret:sk-1234"));

    // ── Tier-zero candidates (choke-point scoring) ────────────────────────────

    let candidates = g.tier_zero_candidates(5);
    check!("graph/candidates_non_empty",  !candidates.is_empty());
    // host:target.example has 1 incoming edge (from email→host)
    let host_score = candidates.iter().find(|(k, _)| *k == "host:target.example").map(|(_, s)| *s);
    check!("graph/host_in_degree_1",  host_score == Some(1));

    // ── OwnershipClaim ────────────────────────────────────────────────────────

    let claim = OwnershipClaim::new("host:target.example", "operator-1", "rdap");
    check!("claim/active",       claim.is_active);
    check!("claim/entity_key",   claim.entity_key == "host:target.example");
    check!("claim/owner",        claim.owner == "operator-1");
    check!("claim/source",       claim.source == "rdap");

    g.add_ownership_claim(claim);
    check!("graph/1_claim",  g.ownership_claims.len() == 1);

    // ── JSON export ───────────────────────────────────────────────────────────

    let json_out = export_attack_graph(&g, GraphExportFormat::Json);
    check!("json/non_empty",           !json_out.is_empty());
    check!("json/has_engagement_id",   json_out.contains("\"engagement_id\""));
    check!("json/secret_redacted",     json_out.contains("[REDACTED]"));
    check!("json/no_raw_secret",       !json_out.contains("sk-1234"));
    check!("json/has_entities",        json_out.contains("\"entities\""));

    // ── Mermaid export ────────────────────────────────────────────────────────

    let mmd_out = export_attack_graph(&g, GraphExportFormat::Mermaid);
    check!("mermaid/starts_with_graph", mmd_out.starts_with("graph LR"));
    check!("mermaid/no_raw_secret",     !mmd_out.contains("sk-1234"));
    check!("mermaid/tier_zero_marker",  mmd_out.contains("⚠"));
    check!("mermaid/contains_node",     mmd_out.contains("target.example"));

    // ── DOT export ────────────────────────────────────────────────────────────

    let dot_out = export_attack_graph(&g, GraphExportFormat::Dot);
    check!("dot/digraph_header",   dot_out.starts_with("digraph"));
    check!("dot/has_closing",      dot_out.trim_end().ends_with('}'));
    check!("dot/no_raw_secret",    !dot_out.contains("sk-1234"));
    check!("dot/tier_zero_red",    dot_out.contains("color=red"));

    // ── GraphML export ────────────────────────────────────────────────────────

    let gml_out = export_attack_graph(&g, GraphExportFormat::GraphMl);
    check!("graphml/xml_decl",     gml_out.starts_with("<?xml"));
    check!("graphml/has_close",    gml_out.contains("</graphml>"));
    check!("graphml/no_raw_secret", !gml_out.contains("sk-1234"));
    check!("graphml/has_nodes",    gml_out.contains("<node "));
    check!("graphml/has_edges",    gml_out.contains("<edge "));

    // ── CSV export ────────────────────────────────────────────────────────────

    let csv_out = export_attack_graph(&g, GraphExportFormat::Csv);
    check!("csv/has_header",       csv_out.starts_with("entity_key,kind,display_name,is_tier_zero,confidence"));
    check!("csv/no_raw_secret",    !csv_out.contains("sk-1234"));
    check!("csv/has_host_row",     csv_out.contains("host:target.example"));

    // ── Cypher export ─────────────────────────────────────────────────────────

    let cy_out = export_attack_graph(&g, GraphExportFormat::Cypher);
    check!("cypher/has_create",    cy_out.contains("CREATE"));
    check!("cypher/no_raw_secret", !cy_out.contains("sk-1234"));
    check!("cypher/has_match",     cy_out.contains("MATCH"));

    // ── Summary ───────────────────────────────────────────────────────────────

    if failures.is_empty() {
        println!("graphs_verify: all canaries passed");
        Ok(0)
    } else {
        for f in &failures {
            eprintln!("{f}");
        }
        Err(format!("{} canary(ies) failed", failures.len()))
    }
}
