use crate::{
    aliases::Aliases,
    model::{Entry, Inventory, Result, hash},
};
use tree_sitter::{Node, Parser};

pub fn text<'s>(node: Node<'_>, source: &'s str) -> &'s str {
    &source[node.byte_range()]
}
pub fn field<'s>(node: Node<'_>, name: &str, source: &'s str) -> &'s str {
    node.child_by_field_name(name)
        .map(|n| text(n, source))
        .unwrap_or("")
}
pub fn identity(node: Node<'_>, source: &str) -> String {
    // Preserve whitespace inside literals; it can change a command/test name.
    hash(text(node, source).as_bytes())
}

pub fn discover(path: &str, source: &str, out: &mut Inventory) -> Result<()> {
    let language = if path.ends_with(".py") || path.ends_with(".pyi") {
        tree_sitter_python::LANGUAGE
    } else if path.ends_with(".rs") {
        tree_sitter_rust::LANGUAGE
    } else if path.ends_with(".tsx") {
        tree_sitter_typescript::LANGUAGE_TSX
    } else if path.ends_with(".ts") {
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT
    } else {
        tree_sitter_javascript::LANGUAGE
    };
    let mut parser = Parser::new();
    parser
        .set_language(&language.into())
        .map_err(|_| format!("{path}: parser initialization failed"))?;
    let mut tree = parser
        .parse(source, None)
        .ok_or_else(|| format!("{path}: parser did not finish"))?;
    if tree.root_node().has_error()
        && ![".py", ".pyi", ".rs"].iter().any(|ext| path.ends_with(ext))
        && let Some(compatible) = crate::jsx::recover(&mut parser, source)
    {
        tree = compatible;
        let mut entry = Entry::new(path, "parser_compatibility", "jsx_text_ampersands", 1);
        entry.reason =
            "specification_valid_jsx_text_reparsed_with_same_length_ampersand_mask".into();
        out.contracts.push(entry);
    }
    if tree.root_node().has_error() {
        let mut problem = tree.root_node();
        loop {
            let mut cursor = problem.walk();
            let child = problem
                .children(&mut cursor)
                .find(|node| node.has_error() || node.is_missing());
            match child {
                Some(child) => problem = child,
                None => break,
            }
        }
        let start = problem.start_position();
        return Err(format!(
            "{path}:{}:{}: malformed source declaration ({})",
            start.row + 1,
            start.column + 1,
            problem.kind()
        ));
    }
    let aliases = Aliases::collect(tree.root_node(), source);
    visit(tree.root_node(), source, path, "", 0, &aliases, out)
}

fn visit(
    node: Node<'_>,
    source: &str,
    path: &str,
    scope: &str,
    depth: usize,
    aliases: &Aliases,
    out: &mut Inventory,
) -> Result<()> {
    if depth > 256 {
        return Err(format!("{path}: syntax depth exceeds 256"));
    }
    let kind = node.kind();
    let mut next_scope = scope.to_string();
    let arrow = kind == "variable_declarator"
        && node
            .child_by_field_name("value")
            .is_some_and(|n| matches!(n.kind(), "arrow_function" | "function_expression"));
    if [
        "function_definition",
        "class_definition",
        "function_item",
        "mod_item",
        "struct_item",
        "enum_item",
        "trait_item",
        "function_declaration",
        "class_declaration",
        "method_definition",
    ]
    .contains(&kind)
        || arrow
    {
        let name = field(node, "name", source);
        let declaration_hash = crate::declaration_ids::fingerprint(node, source);
        let test_start = out.tests.len();
        next_scope = if scope.is_empty() {
            name.into()
        } else {
            format!("{scope}.{name}")
        };
        let mut entry = Entry::new(path, "symbol", &next_scope, node.start_position().row + 1);
        entry.declaration_hash = declaration_hash.clone();
        out.capabilities.push(entry);
        if path.ends_with(".py") || path.ends_with(".pyi") {
            crate::python::declaration(node, source, path, &next_scope, aliases, out);
        }
        if path.ends_with(".rs") {
            crate::rust_declarations::test(node, source, path, &next_scope, out);
        }
        for entry in &mut out.tests[test_start..] {
            entry.declaration_hash = declaration_hash.clone();
        }
    }
    if kind == "call" {
        crate::python::registration(node, source, path, scope, aliases, out);
    }
    if kind == "call_expression" && !path.ends_with(".rs") {
        crate::frontend::call(node, source, path, scope, aliases, out);
    }
    if kind == "attribute_item" && path.ends_with(".rs") {
        crate::rust_declarations::attribute(node, source, path, scope, out);
    }
    if kind == "macro_invocation" && path.ends_with(".rs") {
        let mut entry = Entry::new(
            path,
            "unresolved_macro",
            &format!("{scope}:{}", identity(node, source)),
            node.start_position().row + 1,
        );
        entry.reason = "macro_expansion_not_executed_may_declare_capabilities_or_tests".into();
        out.contracts.push(entry);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        visit(child, source, path, &next_scope, depth + 1, aliases, out)?;
    }
    Ok(())
}
