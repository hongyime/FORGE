use crate::{
    model::{Entry, Inventory},
    syntax::{identity, text},
};
use tree_sitter::Node;

pub fn test(node: Node<'_>, source: &str, path: &str, scope: &str, out: &mut Inventory) {
    if node.kind() != "function_item" {
        return;
    }
    let mut previous = node.prev_named_sibling();
    let mut names = Vec::new();
    while let Some(attr) = previous {
        previous = attr.prev_named_sibling();
        if attr.kind().ends_with("comment") {
            continue;
        }
        if attr.kind() != "attribute_item" {
            break;
        }
        if let Some(attribute) = attr.named_child(0)
            && let Some(name) = attribute.named_child(0)
        {
            names.push(text(name, source).rsplit("::").next().unwrap_or(""));
        }
    }
    if names
        .iter()
        .any(|name| ["test", "rstest", "test_case"].contains(name))
    {
        let mut entry = Entry::new(path, "rust_test", scope, node.start_position().row + 1);
        entry.owner_task = 2;
        entry.parameterized = names
            .iter()
            .any(|name| ["case", "rstest", "test_case"].contains(name));
        entry.reason = "static_declaration_not_collected".into();
        out.tests.push(entry);
    } else if names.contains(&"cfg_attr") {
        let mut entry = Entry::new(
            path,
            "conditional_test_registration",
            scope,
            node.start_position().row + 1,
        );
        entry.owner_task = 2;
        entry.reason = "conditional_attribute_requires_collection".into();
        out.tests.push(entry);
    }
}

pub fn attribute(node: Node<'_>, source: &str, path: &str, scope: &str, out: &mut Inventory) {
    let mut entry = Entry::new(
        path,
        "attribute_registration",
        &format!("{scope}:{}", identity(node, source)),
        node.start_position().row + 1,
    );
    entry.reason = "attribute_macro_semantics_not_executed".into();
    out.contracts.push(entry);
}
