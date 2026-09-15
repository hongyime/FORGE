use crate::syntax::{field, text};
use std::collections::BTreeMap;
use tree_sitter::Node;

#[derive(Default)]
pub struct Aliases(BTreeMap<String, String>);

impl Aliases {
    pub fn collect(root: Node<'_>, source: &str) -> Self {
        let mut aliases = Self::default();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if matches!(node.kind(), "aliased_import" | "import_specifier") {
                let name = field(node, "name", source);
                let alias = field(node, "alias", source);
                if !alias.is_empty() {
                    aliases
                        .0
                        .insert(alias.into(), name.rsplit('.').next().unwrap_or(name).into());
                }
            }
            if node.kind() == "namespace_import"
                && let Some(name) = node.named_child(0)
            {
                aliases
                    .0
                    .insert(text(name, source).into(), "namespace".into());
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        aliases
    }

    pub fn canonical<'a>(&'a self, name: &'a str) -> &'a str {
        self.0.get(name).map(String::as_str).unwrap_or(name)
    }
}
