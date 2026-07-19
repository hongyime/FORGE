"""
tests/phase5/test_exfiltration.py
Unit tests — Module 5-H: forge/utils/post/transfer_util.py + collectors/

Coverage target: 80%

Test categories:
  1. FilesystemCollector  — glob matching, max_size skip, stagger, in-memory compress
  2. BaseCollector        — metadata persisted to DB; content never logged
  3. SshAwsKeyCollector   — collects id_rsa / .aws/credentials; skips .pub
  4. EnvVarCollector      — captures secret-named vars; ignores safe vars
  5. ClipboardCollector   — single snapshot; handles pyperclip absence
  6. ThrottledUploader    — rate limiting; retry on failure; OFFLINE suppression
  7. Exfiltrator          — time-window gate; operator cancel; ExfilMonitor registration
  8. CyberChef recipe     — emit_cyberchef_recipe writes valid JSON with AES op
  9. Staging paths        — never new top-level dirs; always existing writable paths
"""
from __future__ import annotations

import gzip
import hashlib
import io
import builtins
import hashlib
import json
import os
import sqlite3
from datetime import time as dtime
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from forge.utils.post import collectors as collector_exports
from forge.utils.post.collectors.filesystem import (
    BaseCollector,
    FilesystemCollector,
    CollectedFile,
    DEFAULT_STAGGER,
    PAUSE_INTERVAL,
)
from forge.utils.post.collectors import COLLECTOR_REGISTRY
from forge.utils.post.collectors.ssh_aws_keys import (
    SshAwsKeyCollector,
    EnvVarCollector,
    ClipboardCollector,
)
from forge.utils.post.transfer_util import (
    Exfiltrator,
    ThrottledUploader,
    emit_cyberchef_recipe,
    register_exfil_monitor,
    _check_time_window,
)

AES_KEY = "aa" * 32   # 32 bytes as hex


def _require_collected(record: CollectedFile | None) -> CollectedFile:
    assert record is not None
    return record


def _authorized_collector(collector: BaseCollector) -> BaseCollector:
    return collector.configure_execution(roe_id="ROE-TEST")


def test_direct_collector_requires_roe_before_discovery(
    tmp_eng_db: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FORGE_ROE_ID", raising=False)
    stage = tmp_path / "stage"
    stage.mkdir()
    collector = FilesystemCollector(
        db_path=tmp_eng_db,
        engagement_id=1,
        root=tmp_path,
        patterns=["*.txt"],
        session_key=AES_KEY,
        staging_dir=stage,
    )

    with pytest.raises(RuntimeError, match="requires roe_id"):
        list(collector.discover())


# ── 1. FilesystemCollector ────────────────────────────────────────────────────

def test_filesystem_collector_finds_matching_files(tmp_eng_db: Path, tmp_path: Path) -> None:
    # Create test files
    (tmp_path / "report.docx").write_bytes(b"docx content")
    (tmp_path / "data.xlsx").write_bytes(b"xlsx content")
    (tmp_path / "ignore.exe").write_bytes(b"binary")

    collector = _authorized_collector(FilesystemCollector(
        db_path=tmp_eng_db, engagement_id=1,
        root=tmp_path, patterns=["*.docx", "*.xlsx"],
        session_key=AES_KEY, staging_dir=tmp_path / "stage",
    ))
    (tmp_path / "stage").mkdir()

    with mock.patch("time.sleep"):   # suppress stagger delays
        artifacts = list(collector.discover())
        results = [collector.collect(a) for a in artifacts if a]

    names = {Path(r.path).name for r in results if r}
    assert "report.docx" in names
    assert "data.xlsx" in names
    assert "ignore.exe" not in names


def test_filesystem_collector_skips_oversized_files(tmp_eng_db: Path, tmp_path: Path) -> None:
    big_file = tmp_path / "huge.docx"
    big_file.write_bytes(b"x" * (51 * 1024 * 1024))  # 51 MB > default 50 MB

    stage = tmp_path / "stage"
    stage.mkdir()
    collector = _authorized_collector(FilesystemCollector(
        db_path=tmp_eng_db, engagement_id=1,
        root=tmp_path, patterns=["*.docx"],
        max_size=50 * 1024 * 1024,
        session_key=AES_KEY, staging_dir=stage,
    ))
    with mock.patch("time.sleep"):
        artifacts = list(collector.discover())
        results = [collector.collect(a) for a in artifacts if a]
    assert len(results) == 0


def test_filesystem_collector_sha256_correct(tmp_eng_db: Path, tmp_path: Path) -> None:
    content = b"test file content for hashing"
    (tmp_path / "test.txt").write_bytes(content)
    stage = tmp_path / "stage"
    stage.mkdir()
    collector = _authorized_collector(FilesystemCollector(
        db_path=tmp_eng_db, engagement_id=1,
        root=tmp_path, patterns=["*.txt"],
        session_key=AES_KEY, staging_dir=stage,
    ))
    with mock.patch("time.sleep"):
        artifacts = list(collector.discover())
        results = [_require_collected(collector.collect(a)) for a in artifacts if a]
    assert len(results) == 1
    expected = hashlib.sha256(content).hexdigest()
    assert results[0].sha256 == expected


def test_filesystem_collector_staging_file_is_encrypted(tmp_eng_db: Path, tmp_path: Path) -> None:
    """Staged file must not equal raw content (must be gzip+encrypted)."""
    content = b"sensitive data"
    (tmp_path / "secret.txt").write_bytes(content)
    stage = tmp_path / "stage"
    stage.mkdir()
    collector = _authorized_collector(FilesystemCollector(
        db_path=tmp_eng_db, engagement_id=1,
        root=tmp_path, patterns=["*.txt"],
        session_key=AES_KEY, staging_dir=stage,
    ))
    with mock.patch("time.sleep"):
        artifacts = list(collector.discover())
        results = [_require_collected(collector.collect(a)) for a in artifacts if a]
    assert len(results) == 1
    # Staging file must not contain plaintext content
    sha16 = results[0].sha256[:16]
    stage_file = stage / f".{sha16}.tmp"
    assert stage_file.exists()
    staged = stage_file.read_bytes()
    assert content not in staged


# ── 2. BaseCollector: metadata in DB, content never stored ───────────────────

def test_metadata_persisted_to_db(tmp_eng_db: Path, tmp_path: Path) -> None:
    content = b"file content"
    (tmp_path / "creds.txt").write_bytes(content)
    stage = tmp_path / "stage"
    stage.mkdir()
    collector = _authorized_collector(FilesystemCollector(
        db_path=tmp_eng_db, engagement_id=1,
        root=tmp_path, patterns=["*.txt"],
        session_key=AES_KEY, staging_dir=stage,
    ))
    with mock.patch("time.sleep"):
        artifacts = list(collector.discover())
        results = [_require_collected(collector.collect(a)) for a in artifacts if a]
    con  = sqlite3.connect(tmp_eng_db)
    rows = con.execute("SELECT sha256 FROM exfiltrated_data").fetchall()
    con.close()
    assert any(results[0].sha256 == r[0] for r in rows)


def test_content_never_stored_in_db(tmp_eng_db: Path, tmp_path: Path) -> None:
    """File content must NEVER appear in the engagement DB."""
    secret_content = b"password=SuperSecret123!"
    (tmp_path / "env.txt").write_bytes(secret_content)
    stage = tmp_path / "stage"
    stage.mkdir()
    collector = _authorized_collector(FilesystemCollector(
        db_path=tmp_eng_db, engagement_id=1,
        root=tmp_path, patterns=["*.txt"],
        session_key=AES_KEY, staging_dir=stage,
    ))
    with mock.patch("time.sleep"):
        artifacts = list(collector.discover())
        [collector.collect(a) for a in artifacts if a]
    con      = sqlite3.connect(tmp_eng_db)
    all_data = str(con.execute("SELECT * FROM exfiltrated_data").fetchall())
    con.close()
    assert b"SuperSecret123!" not in all_data.encode()
    assert "SuperSecret123" not in all_data


def test_collector_lifecycle_state_moves_from_discovered_to_collected_to_skipped(
    tmp_eng_db: Path,
    tmp_path: Path,
) -> None:
    (tmp_path / "notes.txt").write_text("hello")
    stage = tmp_path / "stage"
    stage.mkdir()
    collector = _authorized_collector(FilesystemCollector(
        db_path=tmp_eng_db,
        engagement_id=1,
        root=tmp_path,
        patterns=["*.txt"],
        session_key=AES_KEY,
        staging_dir=stage,
    ))

    artifact = next(collector.discover())
    assert artifact.validation_state == "discovered"

    with mock.patch("time.sleep"):
        record = _require_collected(collector.collect(artifact))

    assert record.metadata.validation_state == "collected"
    assert collector.validate(record) is False
    assert record.metadata.validation_state == "skipped"


# ── 3. SshAwsKeyCollector ─────────────────────────────────────────────────────

def test_ssh_key_collector_skips_pub_files(
    tmp_eng_db: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    (ssh_dir / "id_rsa").write_bytes(b"-----BEGIN RSA PRIVATE KEY-----")
    (ssh_dir / "id_rsa.pub").write_bytes(b"ssh-rsa AAAA...")
    stage = tmp_path / "stage"
    stage.mkdir()

    # Point collector at our fake home dir
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

    collector = _authorized_collector(SshAwsKeyCollector(
        db_path=tmp_eng_db, engagement_id=1,
        session_key=AES_KEY, staging_dir=stage,
    ))
    with mock.patch("time.sleep"):
        artifacts = list(collector.discover())
        results = [collector.collect(a) for a in artifacts if a]

    collected_names = [Path(r.path).name for r in results if r]
    assert "id_rsa" in collected_names
    assert "id_rsa.pub" not in collected_names


def test_aws_credentials_collected(
    tmp_eng_db: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    aws_dir = tmp_path / ".aws"
    aws_dir.mkdir()
    (aws_dir / "credentials").write_bytes(b"[default]\naws_access_key_id=AKIA...")
    stage = tmp_path / "stage"
    stage.mkdir()

    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

    collector = _authorized_collector(SshAwsKeyCollector(
        db_path=tmp_eng_db, engagement_id=1,
        session_key=AES_KEY, staging_dir=stage,
    ))
    with mock.patch("time.sleep"):
        artifacts = list(collector.discover())
        results = [collector.collect(a) for a in artifacts if a]

    collected_names = [Path(r.path).name for r in results if r]
    assert "credentials" in collected_names


def test_registry_contains_legacy_and_new_collectors() -> None:
    for collector_name in (
        "ssh_aws_keys",
        "kubernetes",
        "gcp",
        "docker",
        "azure",
        "iac_cicd",
    ):
        assert collector_name in COLLECTOR_REGISTRY
    assert collector_exports.SshAwsKeyCollector is SshAwsKeyCollector
    assert collector_exports.EnvVarCollector is EnvVarCollector
    assert collector_exports.ClipboardCollector is ClipboardCollector


# ── 4. EnvVarCollector ────────────────────────────────────────────────────────

def test_env_var_collector_captures_secrets(
    tmp_eng_db: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "supersecret")
    monkeypatch.setenv("SAFE_VAR", "not_a_secret")
    stage = tmp_path / "stage"
    stage.mkdir()

    collector = _authorized_collector(EnvVarCollector(
        db_path=tmp_eng_db, engagement_id=1,
        session_key=AES_KEY, staging_dir=stage,
    ))
    artifacts = list(collector.discover())
    results = [_require_collected(collector.collect(a)) for a in artifacts if a]
    assert len(results) == 1
    
    # Verify content in staging
    staged = (stage / f".{results[0].sha256[:16]}.env.tmp").read_bytes()
    # Staged is encrypted, we don't check plaintext here (OPSEC)
    assert results[0].path == "ENV_VARS"


def test_env_var_collector_no_secret_vars_yields_nothing(
    tmp_eng_db: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Ensure no secret-pattern vars in env
    for var in list(os.environ.keys()):
        if any(p in var.upper() for p in ("KEY", "SECRET", "TOKEN", "PASSWORD")):
            monkeypatch.delenv(var, raising=False)
    stage = tmp_path / "stage"
    stage.mkdir()
    collector = _authorized_collector(EnvVarCollector(
        db_path=tmp_eng_db, engagement_id=1,
        session_key=AES_KEY, staging_dir=stage,
    ))
    artifacts = list(collector.discover())
    results = [collector.collect(a) for a in artifacts if a]
    assert len(results) == 0


# ── 5. ClipboardCollector ─────────────────────────────────────────────────────

def test_clipboard_collector_captures_content(tmp_eng_db: Path, tmp_path: Path) -> None:
    with mock.patch("pyperclip.paste", return_value="clipboard content"):
        stage = tmp_path / "stage"
        stage.mkdir()
        collector = _authorized_collector(ClipboardCollector(
            db_path=tmp_eng_db, engagement_id=1,
            session_key=AES_KEY, staging_dir=stage,
        ))
        artifacts = list(collector.discover())
        results = [_require_collected(collector.collect(a)) for a in artifacts if a]
        assert len(results) == 1
        assert results[0].path == "CLIPBOARD"


def test_clipboard_collector_handles_pyperclip_not_installed(
    tmp_eng_db: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stage = tmp_path / "stage"
    stage.mkdir()
    
    # Use a safer way to mock missing module
    original_import = builtins.__import__
    _ = monkeypatch

    def mocked_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "pyperclip":
            raise ImportError("pyperclip")
        return original_import(name, *args, **kwargs)

    with mock.patch("builtins.__import__", side_effect=mocked_import):
        collector = _authorized_collector(ClipboardCollector(
            db_path=tmp_eng_db, engagement_id=1,
            session_key=AES_KEY, staging_dir=stage,
        ))
        # Must not raise; yields nothing
        artifacts = list(collector.discover())
        results = [collector.collect(a) for a in artifacts if a]
        assert len(results) == 0


# ── 6. ThrottledUploader ──────────────────────────────────────────────────────

def test_throttled_uploader_calls_channel_send(tmp_path: Path) -> None:
    mock_channel = mock.MagicMock()
    mock_channel.send.return_value = True
    uploader = ThrottledUploader(mock_channel, max_bytes_per_sec=1024 * 1024, chunk_size=4096)
    result = uploader.upload(b"x" * 100)
    assert result is True
    mock_channel.send.assert_called()


def test_throttled_uploader_suppressed_in_offline_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _ = tmp_path
    monkeypatch.setenv("FORGE_OFFLINE_STRICT", "1")
    mock_channel = mock.MagicMock()
    uploader = ThrottledUploader(mock_channel)
    result   = uploader.upload(b"data")
    assert result is False
    mock_channel.send.assert_not_called()


def test_throttled_uploader_retries_on_channel_failure() -> None:
    mock_channel = mock.MagicMock()
    mock_channel.send.side_effect = [False, False, True]  # fail twice, succeed third
    uploader = ThrottledUploader(mock_channel, max_bytes_per_sec=10 * 1024 * 1024,
                                  chunk_size=4096, max_retries=3)
    with mock.patch("time.sleep"):
        result = uploader.upload(b"test data")
    assert result is True
    assert mock_channel.send.call_count == 3


# ── 7. Exfiltrator time-window gate ──────────────────────────────────────────

def test_time_window_blocks_outside_hours() -> None:
    with mock.patch("forge.utils.post.transfer_util.datetime") as mock_dt:
        mock_dt.now.return_value.time.return_value = dtime(3, 0)
        with pytest.raises(RuntimeError, match="[Bb]locked|window"):
            _check_time_window(dtime(9, 0), dtime(17, 0))


def test_time_window_permits_inside_hours() -> None:
    with mock.patch("forge.utils.post.transfer_util.datetime") as mock_dt:
        mock_dt.now.return_value.time.return_value = dtime(10, 30)
        _check_time_window(dtime(9, 0), dtime(17, 0))  # must not raise


def test_exfiltrator_requires_roe_before_confirm_or_collection(
    tmp_eng_db: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_channel = mock.MagicMock()
    confirm_calls: list[str] = []

    class _Confirm:
        def ask(self) -> bool:
            confirm_calls.append("ask")
            return True

    monkeypatch.setattr("questionary.confirm", lambda *args, **kwargs: _Confirm())
    exfil = Exfiltrator(
        db_path=tmp_eng_db,
        engagement_id=1,
        channel=mock_channel,
        session_key=AES_KEY,
        window=None,
        dry_run=False,
    )

    with pytest.raises(RuntimeError, match="requires roe_id"):
        exfil.run(collector_type="filesystem", root=tmp_path)
    assert confirm_calls == []
    mock_channel.send.assert_not_called()


def test_exfiltrator_operator_cancel_aborts(
    tmp_eng_db: Path,
    tmp_path: Path,
    patch_confirm_deny: object,
) -> None:
    _ = patch_confirm_deny
    mock_channel = mock.MagicMock()
    exfil = Exfiltrator(
        db_path=tmp_eng_db, engagement_id=1,
        channel=mock_channel, session_key=AES_KEY,
        window=None, dry_run=False,
        roe_id="ROE-TEST",
    )
    with pytest.raises(RuntimeError, match="[Cc]ancell?ed"):
        exfil.run(collector_type="filesystem", root=tmp_path)


def test_exfiltrator_uploads_staged_ext_suffixed_chunks(
    tmp_eng_db: Path,
    tmp_path: Path,
    patch_confirm: object,
) -> None:
    _ = patch_confirm
    mock_channel = mock.MagicMock()
    mock_channel.send.return_value = True
    stage = tmp_path / "stage"
    stage.mkdir()
    (tmp_path / "loot.txt").write_text("top secret")

    exfil = Exfiltrator(
        db_path=tmp_eng_db,
        engagement_id=1,
        channel=mock_channel,
        session_key=AES_KEY,
        staging_dir=stage,
        window=None,
        dry_run=False,
        roe_id="ROE-TEST",
    )

    with mock.patch("time.sleep"):
        hashes = exfil.run(collector_type="filesystem", root=tmp_path, patterns=["*.txt"])

    assert hashes
    mock_channel.send.assert_called()


# ── 8. ExfilMonitor registration ─────────────────────────────────────────────

def test_register_exfil_monitor_writes_to_db(tmp_eng_db: Path) -> None:
    hashes = ["abc123", "def456", "abc123"]  # duplicate should be ignored
    register_exfil_monitor(tmp_eng_db, engagement_id=1, sha256_list=hashes)
    con  = sqlite3.connect(tmp_eng_db)
    rows = con.execute("SELECT sha256 FROM exfil_monitor_targets").fetchall()
    con.close()
    stored = {r[0] for r in rows}
    assert "abc123" in stored
    assert "def456" in stored
    assert len(stored) == 2   # duplicate ignored by UNIQUE constraint


# ── 9. CyberChef recipe ───────────────────────────────────────────────────────

def test_emit_cyberchef_recipe_writes_json(tmp_path: Path) -> None:
    recipe_path = tmp_path / "recipe.json"
    emit_cyberchef_recipe(AES_KEY, recipe_path)
    assert recipe_path.exists()
    data = json.loads(recipe_path.read_text())
    assert isinstance(data, list)
    assert len(data) >= 1
    ops = [step.get("op", "") for step in data]
    assert any("AES" in op or "Decrypt" in op for op in ops)


def test_emit_cyberchef_recipe_contains_key(tmp_path: Path) -> None:
    recipe_path = tmp_path / "recipe.json"
    emit_cyberchef_recipe(AES_KEY, recipe_path)
    content = recipe_path.read_text()
    assert AES_KEY in content
