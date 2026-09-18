use super::support::{FIXTURES, LEDGER, cli, fixture, run};
use std::fs;

#[cfg(any(windows, unix))]
fn link_directory(target: &std::path::Path, link: &std::path::Path) {
    #[cfg(windows)]
    {
        use std::os::windows::{fs::MetadataExt, process::CommandExt};
        let output = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-File"])
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/domain_support/junction.ps1"),
            )
            .arg(link)
            .arg(target)
            .creation_flags(0x08000000)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_ne!(
            fs::symlink_metadata(link).unwrap().file_attributes() & 0x400,
            0
        );
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
}

#[cfg(any(windows, unix))]
fn unlink_directory(link: &std::path::Path) {
    #[cfg(windows)]
    fs::remove_dir(link).unwrap();
    #[cfg(unix)]
    fs::remove_file(link).unwrap();
}

#[test]
fn missing_and_oversized_fixture_inputs_fail() {
    for missing in [true, false] {
        let f = fixture();
        let path = format!("{FIXTURES}/hash-dataclass-source.json");
        if missing {
            fs::remove_file(f.root.join(&path)).unwrap();
        } else {
            f.bytes(&path, &vec![b' '; 8 * 1024 * 1024 + 1]);
        }
        let (ok, receipt) = run(&f, "fixture-input");
        assert!(!ok, "{receipt}");
        assert_eq!(receipt["executed"], 0);
    }
}

#[cfg(any(windows, unix))]
#[test]
fn linked_input_and_evidence_ancestors_are_rejected() {
    let f = fixture();
    let source_dir = f.root.join("native/migration");
    let moved = f.root.join("saved-migration");
    fs::rename(&source_dir, &moved).unwrap();
    link_directory(&moved, &source_dir);
    let (ok, receipt) = run(&f, "linked-input");
    assert!(!ok, "{receipt}");
    assert!(!receipt["errors"].as_array().unwrap().is_empty());
    unlink_directory(&source_dir);
    fs::rename(moved, source_dir).unwrap();
    let outside = f.root.join("outside");
    fs::create_dir(&outside).unwrap();
    let link = f.root.join(".omo/evidence/linked");
    link_directory(&outside, &link);
    let output = cli(&[
        "verify",
        "domain",
        "--root",
        f.root.to_str().unwrap(),
        "--evidence",
        link.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(!outside.join("receipt.json").exists());
    unlink_directory(&link);
    assert!(f.root.join(LEDGER).is_file());
}

#[test]
fn existing_success_and_empty_receipts_are_never_overwritten() {
    let f = fixture();
    assert!(run(&f, "success").0);
    for name in ["success", "empty"] {
        let relative = format!(".omo/evidence/{name}/receipt.json");
        if name == "empty" {
            f.bytes(&relative, b"");
        }
        let path = f.root.join(relative);
        let before = fs::read(&path).unwrap();
        let output = cli(&[
            "verify",
            "domain",
            "--root",
            f.root.to_str().unwrap(),
            "--evidence",
            path.parent().unwrap().to_str().unwrap(),
        ]);
        assert!(!output.status.success());
        assert_eq!(fs::read(path).unwrap(), before);
    }
}
