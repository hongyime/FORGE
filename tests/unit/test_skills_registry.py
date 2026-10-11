"""Unit tests for forge.skills.registry (Wave 3, Explore #23)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from forge.skills.registry import (
    ALLOWED_CAPABILITIES,
    ALLOWED_GATES,
    ALLOWED_SAFETY_CLASSES,
    SKILL_SCHEMA,
    SkillValidationError,
    load_skill_manifest,
    load_skill_manifests,
    skill_plugin_dirs,
    skill_registry_statuses,
)


# ---------------------------------------------------------------------------
# Fixtures


_VALID_MANIFEST = {
    "schema": "forge.skill.v1",
    "skill_id": "skill_recon_subdomain",
    "name": "Subdomain Reconnaissance",
    "version": "1.0.0",
    "description": "Passive subdomain discovery playbook using crt.sh and wordlists.",
    "capabilities": ["passive_discovery"],
    "required_gates": ["scope_manifest"],
    "safety_class": "passive",
}


def _write_manifest(path: Path, manifest: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Schema baseline


def test_schema_constant_matches_backlog_spec():
    assert SKILL_SCHEMA == "forge.skill.v1"


def test_allowed_safety_classes_includes_minimum_set():
    minimum = {"passive", "read_only_scope_gated", "active_validation_gated"}
    assert minimum.issubset(ALLOWED_SAFETY_CLASSES)


def test_allowed_capabilities_includes_minimum_set():
    minimum = {"passive_discovery", "operator_guide", "attack_path_review"}
    assert minimum.issubset(ALLOWED_CAPABILITIES)


def test_allowed_gates_includes_minimum_set():
    minimum = {"scope_manifest", "approval", "roe_id", "live_gate"}
    assert minimum.issubset(ALLOWED_GATES)


# ---------------------------------------------------------------------------
# load_skill_manifest success path


def test_valid_manifest_loads_cleanly():
    definition = load_skill_manifest(_VALID_MANIFEST)
    assert definition.skill_id == "skill_recon_subdomain"
    assert definition.name == "Subdomain Reconnaissance"
    assert definition.version == "1.0.0"
    assert definition.capabilities == ("passive_discovery",)
    assert definition.required_gates == ("scope_manifest",)
    assert definition.safety_class == "passive"
    assert definition.schema == SKILL_SCHEMA


def test_definition_to_dict_round_trip():
    definition = load_skill_manifest(_VALID_MANIFEST)
    reloaded = load_skill_manifest(definition.to_dict())
    assert reloaded.skill_id == definition.skill_id
    assert reloaded.capabilities == definition.capabilities


# ---------------------------------------------------------------------------
# load_skill_manifest validation


def test_rejects_wrong_schema():
    bad = dict(_VALID_MANIFEST, schema="forge.skill.v2")
    with pytest.raises(SkillValidationError, match="schema"):
        load_skill_manifest(bad)


def test_rejects_bad_skill_id():
    bad = dict(_VALID_MANIFEST, skill_id="recon")  # must start with 'skill_'
    with pytest.raises(SkillValidationError, match="skill_id"):
        load_skill_manifest(bad)


def test_rejects_skill_id_with_runner_prefix():
    bad = dict(_VALID_MANIFEST, skill_id="skill_")  # too short after prefix
    with pytest.raises(SkillValidationError, match="skill_id"):
        load_skill_manifest(bad)


def test_rejects_bad_version():
    bad = dict(_VALID_MANIFEST, version="v1")
    with pytest.raises(SkillValidationError, match="version"):
        load_skill_manifest(bad)


def test_rejects_unknown_safety_class():
    bad = dict(_VALID_MANIFEST, safety_class="unrestricted")
    with pytest.raises(SkillValidationError, match="safety_class"):
        load_skill_manifest(bad)


def test_rejects_unknown_capability():
    bad = dict(_VALID_MANIFEST, capabilities=["mystery_capability"])
    with pytest.raises(SkillValidationError, match="capabilities"):
        load_skill_manifest(bad)


def test_rejects_unknown_gate():
    bad = dict(_VALID_MANIFEST, required_gates=["unknown_gate"])
    with pytest.raises(SkillValidationError, match="required_gates"):
        load_skill_manifest(bad)


def test_requires_capabilities():
    bad = dict(_VALID_MANIFEST, capabilities=[])
    with pytest.raises(SkillValidationError, match="capabilities"):
        load_skill_manifest(bad)


def test_requires_description():
    bad = dict(_VALID_MANIFEST, description="")
    with pytest.raises(SkillValidationError, match="description"):
        load_skill_manifest(bad)


def test_read_only_scope_gated_requires_scope_and_rate_gates():
    bad = {
        **_VALID_MANIFEST,
        "safety_class": "read_only_scope_gated",
        "required_gates": [],
    }
    with pytest.raises(SkillValidationError, match="gates"):
        load_skill_manifest(bad)
    good = {
        **_VALID_MANIFEST,
        "safety_class": "read_only_scope_gated",
        "required_gates": ["scope_manifest", "rate_limit"],
    }
    load_skill_manifest(good)  # must not raise


def test_active_validation_gated_requires_four_gates():
    bad = {
        **_VALID_MANIFEST,
        "safety_class": "active_validation_gated",
        "required_gates": ["scope_manifest"],
    }
    with pytest.raises(SkillValidationError, match="gates"):
        load_skill_manifest(bad)
    good = {
        **_VALID_MANIFEST,
        "safety_class": "active_validation_gated",
        "required_gates": ["approval", "roe_id", "scope_manifest", "live_gate"],
    }
    load_skill_manifest(good)


def test_rejects_forge_runner_execution_path():
    bad = {
        **_VALID_MANIFEST,
        "execution_paths": ["forge connectors run --connector x"],
    }
    with pytest.raises(SkillValidationError, match="runner commands"):
        load_skill_manifest(bad)


def test_rejects_malformed_execution_path_prefix():
    bad = {
        **_VALID_MANIFEST,
        "execution_paths": ["https://example.com"],
    }
    with pytest.raises(SkillValidationError, match="manual"):
        load_skill_manifest(bad)


def test_accepts_valid_execution_paths():
    good = {
        **_VALID_MANIFEST,
        "execution_paths": ["manual:review-report", "docs:README.md"],
    }
    definition = load_skill_manifest(good)
    assert definition.execution_paths == (
        "manual:review-report",
        "docs:README.md",
    )


# ---------------------------------------------------------------------------
# Directory scanning


def test_skill_plugin_dirs_uses_data_dir(tmp_path: Path):
    dirs = skill_plugin_dirs(data_dir=tmp_path)
    assert any(str(d).endswith("skills") for d in dirs)


def test_skill_plugin_dirs_respects_env(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("FORGE_SKILL_PLUGIN_DIRS", str(tmp_path / "extra"))
    dirs = skill_plugin_dirs(data_dir=tmp_path)
    assert tmp_path / "extra" in dirs or (tmp_path / "extra").resolve() in {
        d.resolve() for d in dirs
    }


def test_skill_plugin_dirs_dedupes(tmp_path: Path):
    dirs = skill_plugin_dirs(
        data_dir=tmp_path,
        extra_dirs=[tmp_path / "skills", tmp_path / "skills"],
    )
    assert len(dirs) == len({d.resolve() for d in dirs})


def test_load_skill_manifests_reads_json_from_dir(tmp_path: Path):
    _write_manifest(tmp_path / "s1.json", _VALID_MANIFEST)
    manifests = load_skill_manifests([tmp_path])
    assert len(manifests) == 1
    assert manifests[0].skill_id == "skill_recon_subdomain"


def test_load_skill_manifests_rejects_duplicate_ids(tmp_path: Path):
    _write_manifest(tmp_path / "s1.json", _VALID_MANIFEST)
    _write_manifest(tmp_path / "sub" / "s2.json", _VALID_MANIFEST)
    with pytest.raises(SkillValidationError, match="duplicate"):
        load_skill_manifests([tmp_path])


def test_load_skill_manifests_skips_missing_dir(tmp_path: Path):
    manifests = load_skill_manifests([tmp_path / "does-not-exist"])
    assert manifests == ()


def test_load_skill_manifests_rejects_file_as_dir(tmp_path: Path):
    bad_dir = tmp_path / "oops.json"
    bad_dir.write_text("{}", encoding="utf-8")
    with pytest.raises(SkillValidationError, match="not a directory"):
        load_skill_manifests([bad_dir])


def test_skill_registry_statuses_reports_invalid_manifests(tmp_path: Path):
    _write_manifest(tmp_path / "ok.json", _VALID_MANIFEST)
    _write_manifest(tmp_path / "bad.json", {"schema": "forge.skill.v2"})
    rows = skill_registry_statuses([tmp_path])
    statuses = {row["status"] for row in rows}
    assert statuses == {"valid", "invalid"}


def test_skill_registry_statuses_valid_rows_contain_metadata(tmp_path: Path):
    _write_manifest(tmp_path / "ok.json", _VALID_MANIFEST)
    rows = skill_registry_statuses([tmp_path])
    valid = [row for row in rows if row["status"] == "valid"]
    assert len(valid) == 1
    assert valid[0]["skill_id"] == "skill_recon_subdomain"
    assert valid[0]["safety_class"] == "passive"
    assert "capabilities" in valid[0]


def test_rejects_oversized_manifest(tmp_path: Path):
    big_description = "x" * 2_000  # exceeds description cap
    _write_manifest(
        tmp_path / "big.json",
        {**_VALID_MANIFEST, "description": big_description},
    )
    rows = skill_registry_statuses([tmp_path])
    assert rows[0]["status"] == "invalid"


def test_rejects_malformed_json(tmp_path: Path):
    path = tmp_path / "junk.json"
    path.write_text("{not valid json", encoding="utf-8")
    rows = skill_registry_statuses([tmp_path])
    assert rows[0]["status"] == "invalid"
    assert "invalid" in rows[0]["error"].lower() or "JSON" in rows[0]["error"]
