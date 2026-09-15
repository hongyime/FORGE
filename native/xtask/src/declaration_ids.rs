use crate::{model::Entry, syntax};
use std::collections::{BTreeMap, BTreeSet};
use tree_sitter::Node;

pub fn fingerprint(node: Node<'_>, source: &str) -> String {
    let mut parts = vec![syntax::text(node, source)];
    let mut ancestor = Some(node);
    while let Some(parent) = ancestor {
        parts.push(parent.kind());
        for name in ["condition", "name", "pattern", "type", "trait"] {
            parts.push(syntax::field(parent, name, source));
        }
        if parent.kind() == "decorated_definition" {
            let mut cursor = parent.walk();
            for child in parent.named_children(&mut cursor) {
                if child.kind() == "decorator" {
                    parts.push(syntax::text(child, source));
                }
            }
        }
        let mut previous = parent.prev_named_sibling();
        while let Some(attribute) = previous {
            previous = attribute.prev_named_sibling();
            if attribute.kind().ends_with("comment") {
                continue;
            }
            if attribute.kind() != "attribute_item" {
                break;
            }
            parts.push(syntax::text(attribute, source));
        }
        ancestor = parent.parent();
    }
    let framed: String = parts
        .iter()
        .map(|part| format!("{}:{part}", part.len()))
        .collect();
    crate::model::hash(framed.as_bytes())
}

fn family(entry: &Entry) -> (&str, &str, &str) {
    (&entry.path, &entry.kind, &entry.symbol)
}

// Match declaration bytes and structural ancestry before consulting provisional
// ordinals. A surviving duplicate must not inherit a removed sibling's evidence.
pub fn align(previous: &BTreeMap<String, Entry>, fresh: &[Entry]) -> Vec<Entry> {
    let mut groups: BTreeMap<_, Vec<&Entry>> = BTreeMap::new();
    for entry in previous.values() {
        groups.entry(family(entry)).or_default().push(entry);
    }
    let mut counts = BTreeMap::new();
    for entry in fresh {
        *counts.entry(family(entry)).or_insert(0) += 1;
    }
    let mut assigned = BTreeSet::new();
    let mut matched = vec![false; fresh.len()];
    let mut aligned = fresh.to_vec();
    for (index, entry) in aligned.iter_mut().enumerate() {
        let Some(candidates) = groups.get(&family(entry)) else {
            continue;
        };
        let eligible = |prior: &&&Entry| {
            !assigned.contains(&prior.id)
                && ((!entry.declaration_hash.is_empty()
                    && entry.declaration_hash == prior.declaration_hash)
                    // Upgrade older metadata only when the complete source and
                    // declaration location are unchanged.
                    || (prior.declaration_hash.is_empty()
                        && !entry.source_hash.is_empty()
                        && entry.source_hash == prior.source_hash
                        && entry.line == prior.line))
        };
        let chosen = candidates
            .iter()
            .filter(eligible)
            .find(|prior| prior.id == entry.id)
            .or_else(|| candidates.iter().find(eligible));
        if let Some(prior) = chosen {
            entry.id = prior.id.clone();
            assigned.insert(entry.id.clone());
            matched[index] = true;
        }
    }
    for (index, entry) in aligned.iter_mut().enumerate() {
        if matched[index] {
            continue;
        }
        let displaced_sibling = previous.get(&entry.id).is_some_and(|prior| {
            !prior.declaration_hash.is_empty()
                && !entry.declaration_hash.is_empty()
                && prior.declaration_hash != entry.declaration_hash
                && (groups.get(&family(entry)).is_some_and(|g| g.len() > 1)
                    || counts[&family(entry)] > 1)
        });
        if assigned.contains(&entry.id) || displaced_sibling {
            let base = format!("{}:declaration:{}", entry.id, entry.declaration_hash);
            entry.id = base.clone();
            let mut occurrence = 1;
            while assigned.contains(&entry.id) || previous.contains_key(&entry.id) {
                occurrence += 1;
                entry.id = format!("{base}:occurrence:{occurrence}");
            }
        }
        assigned.insert(entry.id.clone());
    }
    aligned
}
