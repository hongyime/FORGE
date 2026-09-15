use tree_sitter::{Parser, Tree};

fn text_position(tree: &Tree, offset: usize) -> bool {
    tree.root_node()
        .descendant_for_byte_range(offset, offset + 1)
        .is_some_and(|node| node.kind() == "jsx_text")
}

// JSXTextCharacter admits '&': https://github.com/react/jsx/blob/main/spec.emu.
// The pinned tree-sitter grammar instead rejects some bare ampersands. Locate
// candidate text positions with a temporary, same-length mask. Restore every
// other byte before reparsing, then require a clean tree proving every changed
// position is JSX text. Original bytes still supply all symbols, IDs and hashes.
pub fn recover(parser: &mut Parser, source: &str) -> Option<Tree> {
    let positions: Vec<_> = source
        .bytes()
        .enumerate()
        .filter_map(|(index, byte)| (byte == b'&').then_some(index))
        .collect();
    if positions.is_empty() {
        return None;
    }
    let mut masked = source.as_bytes().to_vec();
    for &index in &positions {
        masked[index] = b'x';
    }
    let probe = parser.parse(&masked, None)?;
    let replacements: Vec<_> = positions
        .into_iter()
        .filter(|&index| text_position(&probe, index))
        .collect();
    if replacements.is_empty() {
        return None;
    }
    let mut compatible = source.as_bytes().to_vec();
    for &index in &replacements {
        compatible[index] = b'x';
    }
    let tree = parser.parse(&compatible, None)?;
    if tree.root_node().has_error()
        || !replacements
            .iter()
            .all(|&index| text_position(&tree, index))
    {
        return None;
    }
    Some(tree)
}
