mod support;
use support::*;

#[test]
fn jsx_text_ampersands_preserve_source_and_declarations() {
    for extension in ["tsx", "jsx"] {
        let repo = Fixture::new();
        repo.populate();
        let source = "const flag = left && right; export const Screen = () => <span value={left & right}>ATT&CK & plain &amp; {flag && count}</span>;\n";
        repo.put(&format!("forge/ui/screen.{extension}"), source);
        let output = repo.inventory();
        if !output.status.success() {
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_typescript::LANGUAGE_TSX.into())
                .unwrap();
            eprintln!(
                "fixture AST: {}",
                parser.parse(source, None).unwrap().root_node().to_sexp()
            );
        }
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(repo.ledgers().contains("Screen"));
        assert!(repo.ledgers().contains("jsx_text_ampersands"));
        assert_eq!(
            std::fs::read_to_string(repo.root.join(format!("forge/ui/screen.{extension}")))
                .unwrap(),
            source
        );
        let before = repo.ledgers();
        assert!(repo.inventory().status.success());
        assert_eq!(before, repo.ledgers());
    }
}

#[test]
fn jsx_ampersand_recovery_cannot_hide_malformed_syntax() {
    for source in [
        "export const Screen = () => <span>ATT&CK {value + }</span>;",
        "export const Screen = () => <span>ATT&CK <div></span>;",
        "export const Screen = () => <span>ATT&CK {value</span>;",
        "export const Screen = () => <span prop={value & }>ATT&CK</span>;",
    ] {
        let repo = Fixture::new();
        repo.put("forge/ui/broken.tsx", source);
        let output = repo.inventory();
        assert!(!output.status.success(), "accepted malformed JSX");
        assert!(stderr(&output).contains("forge/ui/broken.tsx:"));
    }
}
