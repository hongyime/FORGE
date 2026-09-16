use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
struct Fixture {
    file: String,
    bytes: u64,
    sha256: String,
}

#[derive(Deserialize)]
struct Manifest {
    files: Vec<Fixture>,
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn local_filename(name: &str) -> bool {
    name.ends_with(".json")
        && name.len() > 5
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
}

fn validate_bytes(fixture: &Fixture, bytes: &[u8]) -> Result<(), String> {
    if fixture.bytes != u64::try_from(bytes.len()).expect("fixture length fits u64") {
        return Err(format!("{}: recorded byte count differs", fixture.file));
    }
    if fixture.sha256 != format!("{:x}", Sha256::digest(bytes)) {
        return Err(format!("{}: recorded SHA256 differs", fixture.file));
    }
    Ok(())
}

fn validate_fixture(fixture: &Fixture) {
    assert!(
        local_filename(&fixture.file),
        "unsafe metadata fixture path"
    );
    let root = fixture_root().canonicalize().expect("fixture root exists");
    let path = root
        .join(&fixture.file)
        .canonicalize()
        .expect("fixture exists");
    assert_eq!(path.parent(), Some(root.as_path()), "fixture escaped root");
    let bytes = fs::read(path).expect("fixture is readable");
    assert_eq!(validate_bytes(fixture, &bytes), Ok(()));
}

#[test]
fn fixture_json_is_lf_only() {
    // Given shipped JSON files, when read as bytes, then all use LF only.
    let mut count = 0;
    for entry in fs::read_dir(fixture_root()).expect("fixture directory exists") {
        let path = entry.expect("directory entry is readable").path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let bytes = fs::read(&path).expect("fixture is readable");
            assert!(
                !bytes.contains(&b'\r'),
                "{}: CR/CRLF fixture bytes",
                path.display()
            );
            count += 1;
        }
    }
    assert!(count > 0, "fixture scan must not be empty");
}

#[test]
fn manifest_matches_crate_local_bytes() {
    // Given the manifest, when resolving local records, then sizes and hashes match.
    let bytes = fs::read(fixture_root().join("manifest.json")).expect("manifest exists");
    let manifest: Manifest = serde_json::from_slice(&bytes).expect("typed manifest");
    assert!(!manifest.files.is_empty(), "manifest must not be empty");
    for fixture in &manifest.files {
        validate_fixture(fixture);
    }
}

#[test]
fn provenance_matches_crate_local_bytes() {
    // Given provenance sidecars, when parsing only fixture metadata, then hashes
    // and sizes match; captured source hashes are intentionally not dereferenced.
    let mut count = 0;
    for entry in fs::read_dir(fixture_root()).expect("fixture directory exists") {
        let path = entry.expect("directory entry is readable").path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with("-provenance.json"))
        {
            let bytes = fs::read(path).expect("provenance is readable");
            let fixture: Fixture = serde_json::from_slice(&bytes).expect("typed provenance");
            validate_fixture(&fixture);
            count += 1;
        }
    }
    assert!(count > 0, "provenance scan must not be empty");
}

#[test]
fn metadata_paths_reject_traversal_and_platform_prefixes() {
    // Given untrusted metadata names, when checked, then only local basenames pass.
    for name in [
        "../a.json",
        "..\\a.json",
        "/a.json",
        "C:a.json",
        "C:\\a.json",
        "a/b.json",
        "\\\\host\\a.json",
        "",
        ".",
        "..",
    ] {
        assert!(!local_filename(name), "accepted unsafe path: {name}");
    }
    assert!(local_filename("reference-agent.json"));
}

#[test]
fn checksum_guard_rejects_size_and_hash_mutations() {
    // Given independently known SHA256 test-vector metadata, when bytes differ,
    // then both truncation and equal-length corruption are rejected.
    let fixture = Fixture {
        file: "sample.json".into(),
        bytes: 3,
        sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
    };
    assert_eq!(validate_bytes(&fixture, b"abc"), Ok(()));
    assert_eq!(
        validate_bytes(&fixture, b"ab"),
        Err("sample.json: recorded byte count differs".into())
    );
    assert_eq!(
        validate_bytes(&fixture, b"abd"),
        Err("sample.json: recorded SHA256 differs".into())
    );
}
