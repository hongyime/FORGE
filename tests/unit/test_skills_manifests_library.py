"""Tests for the built-in forge.skill.v1 manifest library under forge/skills/manifests/.

Each shipped manifest MUST validate cleanly through
:func:`forge.skills.registry.load_skill_manifest` and MUST be surfaced by the
default ``skill_plugin_dirs()`` so ``forge skills list`` always shows the
built-in playbook library.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from forge.skills.registry import (
    SKILL_SCHEMA,
    SkillDefinition,
    SkillValidationError,
    builtin_skill_dir,
    load_skill_manifest,
    load_skill_manifests,
    skill_plugin_dirs,
    skill_registry_statuses,
)


# ---------------------------------------------------------------------------
# Expected set
# ---------------------------------------------------------------------------

#: Every manifest the FORGE repo ships under forge/skills/manifests/.
_EXPECTED_SKILL_IDS: frozenset[str] = frozenset(
    {
        "skill_recon_subdomain",
        "skill_credential_capture",
        "skill_post_login_automation",
        "skill_exploit_chain",
        "skill_goal_directed_engagement",
        "skill_report_generation",
    }
)


# ---------------------------------------------------------------------------
# Built-in skill directory
# ---------------------------------------------------------------------------


def test_builtin_skill_dir_exists() -> None:
    """forge/skills/manifests/ must exist in the source tree."""
    assert builtin_skill_dir().is_dir(), (
        f"built-in skill manifest dir missing: {builtin_skill_dir()}"
    )


def test_builtin_skill_dir_has_six_json_manifests() -> None:
    files = sorted(builtin_skill_dir().glob("*.json"))
    assert len(files) == 6, [str(p) for p in files]


def test_skill_plugin_dirs_includes_builtin_by_default() -> None:
    dirs = skill_plugin_dirs()
    assert builtin_skill_dir() in dirs


def test_skill_plugin_dirs_can_opt_out_of_builtin() -> None:
    dirs = skill_plugin_dirs(include_builtin=False)
    assert builtin_skill_dir() not in dirs


# ---------------------------------------------------------------------------
# Per-manifest schema compliance
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("skill_id", sorted(_EXPECTED_SKILL_IDS))
def test_each_builtin_manifest_validates(skill_id: str) -> None:
    """Every shipped manifest must validate cleanly through load_skill_manifest."""
    path = builtin_skill_dir() / f"{skill_id}.json"
    assert path.exists(), f"missing manifest file: {path}"
    payload = json.loads(path.read_text(encoding="utf-8"))
    definition = load_skill_manifest(payload, source=str(path))
    assert isinstance(definition, SkillDefinition)
    assert definition.skill_id == skill_id
    assert definition.schema == SKILL_SCHEMA
    assert definition.name.strip()
    assert definition.description.strip()
    assert definition.version.strip()


def test_load_builtin_manifests_returns_all_six() -> None:
    manifests = load_skill_manifests([builtin_skill_dir()])
    assert {m.skill_id for m in manifests} == _EXPECTED_SKILL_IDS


def test_builtin_manifests_have_no_duplicate_ids() -> None:
    manifests = load_skill_manifests([builtin_skill_dir()])
    assert len({m.skill_id for m in manifests}) == len(manifests)


def test_builtin_manifests_registry_statuses_all_valid() -> None:
    rows = skill_registry_statuses([builtin_skill_dir()])
    assert len(rows) == 6
    for row in rows:
        assert row["status"] == "valid", row
        assert row["skill_id"] in _EXPECTED_SKILL_IDS


# ---------------------------------------------------------------------------
# Safety-class invariants for the specific playbook library
# ---------------------------------------------------------------------------


def test_recon_subdomain_is_scope_gated_passive() -> None:
    """Subdomain recon is passive but scope-gated per invariant V1."""
    path = builtin_skill_dir() / "skill_recon_subdomain.json"
    definition = load_skill_manifest(
        json.loads(path.read_text(encoding="utf-8")),
        source=str(path),
    )
    assert definition.safety_class == "read_only_scope_gated"
    assert "scope_manifest" in definition.required_gates
    assert "rate_limit" in definition.required_gates
    assert "passive_discovery" in definition.capabilities


def test_credential_capture_requires_full_live_gates() -> None:
    """Credential capture is active-validation gated with the full gate set."""
    path = builtin_skill_dir() / "skill_credential_capture.json"
    definition = load_skill_manifest(
        json.loads(path.read_text(encoding="utf-8")),
        source=str(path),
    )
    assert definition.safety_class == "active_validation_gated"
    required = set(definition.required_gates)
    assert {"approval", "roe_id", "scope_manifest", "live_gate"}.issubset(required)
    assert "write_permission" in required


def test_post_login_automation_requires_full_live_gates() -> None:
    path = builtin_skill_dir() / "skill_post_login_automation.json"
    definition = load_skill_manifest(
        json.loads(path.read_text(encoding="utf-8")),
        source=str(path),
    )
    assert definition.safety_class == "active_validation_gated"
    required = set(definition.required_gates)
    assert {"approval", "roe_id", "scope_manifest", "live_gate"}.issubset(required)


def test_exploit_chain_requires_full_live_gates() -> None:
    path = builtin_skill_dir() / "skill_exploit_chain.json"
    definition = load_skill_manifest(
        json.loads(path.read_text(encoding="utf-8")),
        source=str(path),
    )
    assert definition.safety_class == "active_validation_gated"
    required = set(definition.required_gates)
    assert {"approval", "roe_id", "scope_manifest", "live_gate"}.issubset(required)


def test_goal_directed_engagement_requires_full_live_gates() -> None:
    path = builtin_skill_dir() / "skill_goal_directed_engagement.json"
    definition = load_skill_manifest(
        json.loads(path.read_text(encoding="utf-8")),
        source=str(path),
    )
    assert definition.safety_class == "active_validation_gated"
    required = set(definition.required_gates)
    assert {"approval", "roe_id", "scope_manifest", "live_gate"}.issubset(required)


def test_report_generation_is_passive_offline() -> None:
    path = builtin_skill_dir() / "skill_report_generation.json"
    definition = load_skill_manifest(
        json.loads(path.read_text(encoding="utf-8")),
        source=str(path),
    )
    assert definition.safety_class == "passive_offline"
    assert "report_generation" in definition.capabilities


# ---------------------------------------------------------------------------
# No manifest claims FORGE runner commands
# ---------------------------------------------------------------------------


def test_no_builtin_manifest_claims_forge_runner_commands() -> None:
    for path in sorted(builtin_skill_dir().glob("*.json")):
        raw = path.read_text(encoding="utf-8")
        # execution_paths validator forbids `forge connectors ...`;
        # also assert at the raw-text level as defense-in-depth.
        assert "forge connectors run" not in raw, path


def test_builtin_manifests_all_have_tags() -> None:
    manifests = load_skill_manifests([builtin_skill_dir()])
    for m in manifests:
        assert m.tags, f"{m.skill_id} has no tags"


# ---------------------------------------------------------------------------
# Regression: invalid manifest in library directory would fail CI
# ---------------------------------------------------------------------------


def test_builtin_manifests_raise_on_corruption(tmp_path: Path, monkeypatch) -> None:
    """If we ever ship a malformed manifest, skill_registry_statuses must flag it."""
    corrupt_dir = tmp_path / "manifests"
    corrupt_dir.mkdir()
    for path in builtin_skill_dir().glob("*.json"):
        (corrupt_dir / path.name).write_text(path.read_text(encoding="utf-8"))
    (corrupt_dir / "bad.json").write_text("{not valid json", encoding="utf-8")
    rows = skill_registry_statuses([corrupt_dir])
    assert any(row["status"] == "invalid" for row in rows)
    assert any(row["status"] == "valid" for row in rows)
