use crate::{
    aliases::Aliases,
    model::{Entry, Inventory},
    syntax::{field, identity, text},
};
use tree_sitter::Node;

pub fn call(
    node: Node<'_>,
    source: &str,
    path: &str,
    scope: &str,
    aliases: &Aliases,
    out: &mut Inventory,
) {
    let Some(function) = node.child_by_field_name("function") else {
        return;
    };
    // Traverse call/member syntax so test.each(cases)(name, fn) is one declaration.
    let expression = text(function, source);
    let mut parts = expression.split(['.', '(']);
    let first = parts.next().unwrap_or("");
    let root = match aliases.canonical(first) {
        "namespace" => parts.next().unwrap_or(""),
        name => name,
    };
    let test_file =
        path.contains(".test.") || path.contains(".spec.") || path.contains("/__tests__/");
    if !["test", "it", "describe", "suite", "fit", "xit", "xtest"].contains(&root) {
        if test_file && !["expect", "require"].contains(&root) {
            let mut entry = Entry::new(
                path,
                "frontend_dynamic_candidate",
                &format!("{scope}:{}", identity(node, source)),
                node.start_position().row + 1,
            );
            entry.reason = "unresolved_test_helper_or_alias_not_executed".into();
            entry.owner_task = 2;
            out.tests.push(entry);
        }
        return;
    }
    if node.parent().is_some_and(|p| {
        p.kind() == "call_expression" && p.child_by_field_name("function") == Some(node)
    }) {
        return;
    }
    let mut entry = Entry::new(
        path,
        if root == "describe" || root == "suite" {
            "frontend_suite"
        } else {
            "frontend_test"
        },
        &format!("{scope}:{}", identity(node, source)),
        node.start_position().row + 1,
    );
    entry.owner_task = 2;
    entry.parameterized = expression.contains(".each") || expression.contains(".for");
    entry.reason = "static_declaration_not_collected".into();
    if field(node, "arguments", source).is_empty() {
        entry.reason = "dynamic_registration_pending".into();
    }
    out.tests.push(entry);
}
