from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_posix_local_setup_uses_home_scoped_forge_paths() -> None:
    text = (REPO_ROOT / "scripts" / "setup_forge_posix_local.sh").read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash")
    assert "${HOME}/_forge_hydration_full" in text
    assert "${HOME}/.forge" in text
    assert "Add-MpPreference" not in text


def test_posix_local_setup_verifies_git_integrity() -> None:
    text = (REPO_ROOT / "scripts" / "setup_forge_posix_local.sh").read_text(encoding="utf-8")
    assert "git ls-files --deleted" in text
    assert "git fsck --no-dangling" in text
    assert "forge_hydration_manifest.json" in text
