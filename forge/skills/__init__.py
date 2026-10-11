"""FORGE skill manifest registry (Explore #23).

Siblings to ``forge.connector.plugin.v1``. Skill manifests are data-only
JSON files describing operator playbooks for coding agents (Strix,
Claude Code, Codex, Gemini, Kiro) and are surfaced through
``forge skills list`` and ``forge operator-guide``.

Design invariants:

* Data-only. Manifests MUST NOT embed executable code or shell commands.
* Safety-class gating identical to connector plugins.
* ``skill_id`` MUST start with ``skill_`` and match a strict regex.
* Manifests MUST NOT claim FORGE runner commands.
* Loader scans ``FORGE_DATA_DIR/skills/`` plus ``FORGE_SKILL_PLUGIN_DIRS``.
"""

from __future__ import annotations

from forge.skills.registry import (
    ALLOWED_SAFETY_CLASSES,
    ALLOWED_CAPABILITIES,
    ALLOWED_GATES,
    SKILL_SCHEMA,
    SkillDefinition,
    SkillValidationError,
    builtin_skill_dir,
    load_skill_manifest,
    load_skill_manifests,
    skill_plugin_dirs,
    skill_registry_statuses,
)

__all__ = [
    "ALLOWED_CAPABILITIES",
    "ALLOWED_GATES",
    "ALLOWED_SAFETY_CLASSES",
    "SKILL_SCHEMA",
    "SkillDefinition",
    "SkillValidationError",
    "builtin_skill_dir",
    "load_skill_manifest",
    "load_skill_manifests",
    "skill_plugin_dirs",
    "skill_registry_statuses",
]
