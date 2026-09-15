use crate::{
    aliases::Aliases,
    model::{Entry, Inventory},
    syntax::{field, identity, text},
};
use tree_sitter::Node;

fn decorators<'a>(node: Node<'_>, source: &'a str) -> Vec<&'a str> {
    let Some(parent) = node.parent().filter(|n| n.kind() == "decorated_definition") else {
        return vec![];
    };
    let mut cursor = parent.walk();
    parent
        .named_children(&mut cursor)
        .filter(|n| n.kind() == "decorator")
        .map(|n| text(n, source))
        .collect()
}

pub fn declaration(
    node: Node<'_>,
    source: &str,
    path: &str,
    scope: &str,
    aliases: &Aliases,
    out: &mut Inventory,
) {
    let name = field(node, "name", source);
    let mut attributes = decorators(node, source);
    let mut ancestor = node.parent();
    while let Some(parent) = ancestor {
        if parent.kind() == "class_definition" {
            attributes.extend(decorators(parent, source));
        }
        ancestor = parent.parent();
    }
    if node.kind() == "function_definition"
        && (name.starts_with("test_") || attributes.iter().any(|a| a.contains("hypothesis")))
    {
        let mut entry = Entry::new(path, "python_test", scope, node.start_position().row + 1);
        entry.owner_task = 2;
        entry.parameterized = attributes.iter().any(|a| {
            let callable = a
                .trim_start_matches('@')
                .split('(')
                .next()
                .unwrap_or("")
                .trim();
            let leaf = callable.rsplit('.').next().unwrap_or("");
            ["parametrize", "parameterized", "expand", "given"].contains(&aliases.canonical(leaf))
        });
        entry.reason = "static_declaration_not_collected".into();
        out.tests.push(entry);
    }
    if name == "pytest_generate_tests" || name == "load_tests" {
        let mut entry = Entry::new(
            path,
            "dynamic_test_registration",
            scope,
            node.start_position().row + 1,
        );
        entry.owner_task = 2;
        entry.reason = "dynamic_cases_require_contained_collection".into();
        out.tests.push(entry);
    }
}

pub fn registration(
    node: Node<'_>,
    source: &str,
    path: &str,
    scope: &str,
    aliases: &Aliases,
    out: &mut Inventory,
) {
    let function = field(node, "function", source);
    let leaf = aliases.canonical(function.rsplit('.').next().unwrap_or(""));
    let kind = match leaf {
        "add_typer" | "add_parser" | "add_command" => "cli_group",
        "command" | "group" | "callback" => "cli_command",
        "route" | "get" | "post" | "put" | "patch" | "delete" | "websocket" | "add_api_route" => {
            "route_candidate"
        }
        "Typer" | "ArgumentParser" => "cli_application",
        "fixture" => "test_fixture",
        "parametrize" | "given" => return,
        other
            if other.starts_with("register_")
                || ["register", "setattr", "exec", "eval", "import_module"].contains(&other) =>
        {
            "dynamic_registration"
        }
        _ => return,
    };
    let mut entry = Entry::new(
        path,
        kind,
        &format!("{scope}:{}", identity(node, source)),
        node.start_position().row + 1,
    );
    entry.reason = "static_registration_dynamic_resolution_pending".into();
    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };
    let mut cursor = args.walk();
    if let Some(first) = args.named_child(0) {
        if matches!(first.kind(), "identifier" | "attribute") {
            entry.registration_target = Some(text(first, source).into());
        } else if first.kind() == "string" {
            entry.registration_name = literal_name(first, source);
        }
    }
    entry.visibility = Some("public_default".into());
    for arg in args.named_children(&mut cursor) {
        if arg.kind() == "keyword_argument" && field(arg, "name", source) == "params" {
            entry.parameterized = true;
        }
        if arg.kind() == "keyword_argument"
            && field(arg, "name", source) == "name"
            && let Some(value) = arg.child_by_field_name("value")
        {
            entry.registration_name = literal_name(value, source);
        }
        if arg.kind() == "keyword_argument" && field(arg, "name", source) == "hidden" {
            entry.visibility = Some(
                match field(arg, "value", source) {
                    "True" => "hidden",
                    "False" => "public",
                    _ => "unresolved",
                }
                .into(),
            );
        }
    }
    out.contracts.push(entry);
}

fn literal_name(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let value = text(node, source).trim_matches(['\'', '"']);
    (value.len() <= 200
        && value
            .chars()
            .all(|c| c.is_alphanumeric() || "_-/.".contains(c)))
    .then(|| value.to_string())
}
