"""forge.skill.v1 manifest loader and validator (Explore #23).

Skill manifests describe operator playbooks that coding-agent harnesses
(Strix, Claude Code, Codex, Gemini, Kiro) can load. They are a sibling
to ``forge.connector.plugin.v1`` manifests under the same safety-class
model.

Manifest shape::

    {
      "schema": "forge.skill.v1",
      "skill_id": "skill_recon_subdomain",
      "name": "Subdomain Reconnaissance",
      "version": "1.0.0",
      "description": "Passive subdomain discovery playbook.",
      "capabilities": ["passive_discovery"],
      "required_gates": ["scope_manifest"],
      "safety_class": "passive"
    }

Rules enforced by :func:`load_skill_manifest`:

* ``schema`` MUST equal :data:`SKILL_SCHEMA` (``forge.skill.v1``).
* ``skill_id`` MUST match :data:`_SKILL_ID_RE` (``^skill_...``).
* ``safety_class`` MUST be in :data:`ALLOWED_SAFETY_CLASSES`.
* Each capability MUST be in :data:`ALLOWED_CAPABILITIES`.
* Each required gate MUST be in :data:`ALLOWED_GATES`.
* Safety class ``read_only_scope_gated`` requires the standard
  ``scope_manifest`` + ``rate_limit`` gates.
* ``active_validation_gated`` safety requires ``approval``, ``roe_id``,
  ``scope_manifest``, and ``live_gate``.
* Execution paths (optional) MUST NOT claim ``forge connectors ...``
  runner commands.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "ALLOWED_CAPABILITIES",
    "ALLOWED_GATES",
    "ALLOWED_SAFETY_CLASSES",
    "SKILL_SCHEMA",
    "SkillDefinition",
    "SkillValidationError",
    "load_skill_manifest",
    "load_skill_manifests",
    "skill_plugin_dirs",
    "skill_registry_statuses",
]

SKILL_SCHEMA = "forge.skill.v1"

_SKILL_ID_RE = re.compile(r"^skill_[a-z0-9][a-z0-9_.\-]{2,63}$")
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[\-+][A-Za-z0-9.\-+]+)?$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,80}$")

_MAX_MANIFEST_BYTES = 128 * 1024
_MAX_NAME_LENGTH = 160
_MAX_DESCRIPTION_LENGTH = 1_200
_MAX_CAPABILITIES = 16
_MAX_GATES = 16
_MAX_EXECUTION_PATHS = 16

_SKILL_PLUGIN_DIR_ENV_VARS = (
    "FORGE_SKILL_PLUGIN_DIR",
    "FORGE_SKILL_PLUGIN_DIRS",
)

ALLOWED_SAFETY_CLASSES: frozenset[str] = frozenset(
    {
        "passive_offline",
        "passive",
        "passive_api",
        "k_anonymity",
        "read_only_scope_gated",
        "active_validation_gated",
    }
)

ALLOWED_CAPABILITIES: frozenset[str] = frozenset(
    {
        "passive_discovery",
        "identity_pivot",
        "artifact_parsing",
        "graph_enrichment",
        "report_generation",
        "monitoring",
        "credential_analysis",
        "active_validation",
        "operator_guide",
        "attack_path_review",
        "remediation_workflow",
    }
)

ALLOWED_GATES: frozenset[str] = frozenset(
    {
        "scope_manifest",
        "rate_limit",
        "write_permission",
        "paid_opt_in",
        "approval",
        "roe_id",
        "live_gate",
    }
)

_REQUIRED_GATES_BY_SAFETY: Mapping[str, tuple[str, ...]] = {
    "read_only_scope_gated": ("scope_manifest", "rate_limit"),
    "active_validation_gated": ("approval", "roe_id", "scope_manifest", "live_gate"),
}


class SkillValidationError(ValueError):
    """Raised when a skill manifest fails validation."""


@dataclass(frozen=True)
class SkillDefinition:
    """Validated ``forge.skill.v1`` manifest."""

    skill_id: str
    name: str
    version: str
    description: str
    capabilities: tuple[str, ...]
    required_gates: tuple[str, ...]
    safety_class: str
    execution_paths: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    source_path: str | None = None
    schema: str = field(default=SKILL_SCHEMA)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "skill_id": self.skill_id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "capabilities": list(self.capabilities),
            "required_gates": list(self.required_gates),
            "safety_class": self.safety_class,
            "execution_paths": list(self.execution_paths),
            "tags": list(self.tags),
            "source_path": self.source_path,
        }


# ---------------------------------------------------------------------------
# Manifest loading


def _text(payload: Mapping[str, Any], key: str, *, max_length: int, source: str) -> str:
    value = " ".join(str(payload.get(key) or "").strip().split())
    if not value:
        raise SkillValidationError(f"skill manifest {source}: missing required field {key!r}")
    if len(value) > max_length:
        raise SkillValidationError(f"skill manifest {source}: field {key!r} is too long")
    return value


def _tokens(
    payload: Mapping[str, Any],
    key: str,
    *,
    source: str,
    allowed: frozenset[str] | None = None,
    required: bool = False,
    max_items: int = 32,
) -> tuple[str, ...]:
    raw = payload.get(key, [])
    if raw in (None, ""):
        raw = []
    if not isinstance(raw, list):
        raise SkillValidationError(
            f"skill manifest {source}: field {key!r} must be a JSON list"
        )
    values: list[str] = []
    for item in raw:
        value = str(item or "").strip()
        if not value:
            continue
        if not _TOKEN_RE.fullmatch(value):
            raise SkillValidationError(
                f"skill manifest {source}: field {key!r} has invalid token {value!r}"
            )
        values.append(value)
    deduped = tuple(dict.fromkeys(values))
    if required and not deduped:
        raise SkillValidationError(
            f"skill manifest {source}: field {key!r} requires at least one value"
        )
    if len(deduped) > max_items:
        raise SkillValidationError(
            f"skill manifest {source}: field {key!r} has too many entries"
        )
    if allowed is not None:
        bad = [v for v in deduped if v not in allowed]
        if bad:
            raise SkillValidationError(
                f"skill manifest {source}: field {key!r} has unknown values "
                f"{sorted(bad)!r}; allowed: {sorted(allowed)!r}"
            )
    return deduped


def _execution_paths(
    payload: Mapping[str, Any],
    *,
    source: str,
) -> tuple[str, ...]:
    raw = payload.get("execution_paths", [])
    if raw in (None, ""):
        raw = []
    if not isinstance(raw, list):
        raise SkillValidationError(
            f"skill manifest {source}: field 'execution_paths' must be a JSON list"
        )
    results: list[str] = []
    for item in raw:
        value = str(item or "").strip()
        if not value:
            continue
        if len(value) > 160:
            raise SkillValidationError(
                f"skill manifest {source}: execution_path too long ({len(value)} chars)"
            )
        if value.lower().startswith("forge connectors "):
            raise SkillValidationError(
                f"skill manifest {source}: execution_paths cannot claim FORGE runner commands"
            )
        if not value.lower().startswith(("manual:", "operator:", "docs:", "external:")):
            raise SkillValidationError(
                f"skill manifest {source}: execution_path must start with "
                "'manual:', 'operator:', 'docs:', or 'external:'"
            )
        results.append(value)
    if len(results) > _MAX_EXECUTION_PATHS:
        raise SkillValidationError(
            f"skill manifest {source}: too many execution_paths (max {_MAX_EXECUTION_PATHS})"
        )
    return tuple(dict.fromkeys(results))


def load_skill_manifest(raw: Mapping[str, Any], *, source: str = "<memory>") -> SkillDefinition:
    """Validate and return a :class:`SkillDefinition`.

    Raises :class:`SkillValidationError` on any field or schema violation.
    """
    if not isinstance(raw, Mapping):
        raise SkillValidationError(f"skill manifest {source}: must be a JSON object")

    schema = str(raw.get("schema") or "").strip()
    if schema != SKILL_SCHEMA:
        raise SkillValidationError(
            f"skill manifest {source}: schema must be {SKILL_SCHEMA!r} (got {schema!r})"
        )

    skill_id = str(raw.get("skill_id") or "").strip()
    if not _SKILL_ID_RE.fullmatch(skill_id):
        raise SkillValidationError(
            f"skill manifest {source}: skill_id must match {_SKILL_ID_RE.pattern!r}"
        )

    version = str(raw.get("version") or "").strip()
    if not _VERSION_RE.fullmatch(version):
        raise SkillValidationError(
            f"skill manifest {source}: version must be semver (got {version!r})"
        )

    name = _text(raw, "name", max_length=_MAX_NAME_LENGTH, source=source)
    description = _text(raw, "description", max_length=_MAX_DESCRIPTION_LENGTH, source=source)

    safety_class = str(raw.get("safety_class") or "").strip()
    if safety_class not in ALLOWED_SAFETY_CLASSES:
        raise SkillValidationError(
            f"skill manifest {source}: safety_class {safety_class!r} is not allowed; "
            f"allowed: {sorted(ALLOWED_SAFETY_CLASSES)!r}"
        )

    capabilities = _tokens(
        raw,
        "capabilities",
        source=source,
        allowed=ALLOWED_CAPABILITIES,
        required=True,
        max_items=_MAX_CAPABILITIES,
    )
    gates = _tokens(
        raw,
        "required_gates",
        source=source,
        allowed=ALLOWED_GATES,
        required=False,
        max_items=_MAX_GATES,
    )
    tags = _tokens(
        raw,
        "tags",
        source=source,
        allowed=None,
        required=False,
        max_items=32,
    )

    expected_gates = _REQUIRED_GATES_BY_SAFETY.get(safety_class, ())
    missing = [gate for gate in expected_gates if gate not in gates]
    if missing:
        raise SkillValidationError(
            f"skill manifest {source}: safety_class {safety_class!r} requires gates "
            f"{sorted(missing)!r}"
        )

    execution_paths = _execution_paths(raw, source=source)

    return SkillDefinition(
        skill_id=skill_id,
        name=name,
        version=version,
        description=description,
        capabilities=capabilities,
        required_gates=gates,
        safety_class=safety_class,
        execution_paths=execution_paths,
        tags=tags,
        source_path=source if source and source != "<memory>" else None,
    )


# ---------------------------------------------------------------------------
# Directory scanning


def _split_dir_list(raw: str) -> list[str]:
    parts: list[str] = []
    for item in raw.replace("\r", "\n").replace("\n", os.pathsep).replace(",", os.pathsep).split(os.pathsep):
        value = item.strip()
        if value:
            parts.append(value)
    return parts


def skill_plugin_dirs(
    *,
    data_dir: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    extra_dirs: Sequence[str | Path] = (),
) -> tuple[Path, ...]:
    """Return the resolved, deduplicated list of skill manifest directories."""
    environ = env if env is not None else os.environ
    candidates: list[Path] = []
    if data_dir is not None:
        candidates.append(Path(data_dir).expanduser() / "skills")
    else:
        env_data_dir = environ.get("FORGE_DATA_DIR")
        if env_data_dir:
            candidates.append(Path(env_data_dir).expanduser() / "skills")

    for env_name in _SKILL_PLUGIN_DIR_ENV_VARS:
        raw = str(environ.get(env_name, "") or "")
        for item in _split_dir_list(raw):
            candidates.append(Path(item).expanduser())

    for item in extra_dirs:
        candidates.append(Path(item).expanduser())

    seen: set[str] = set()
    deduped: list[Path] = []
    for path in candidates:
        key = str(path.resolve(strict=False)).casefold()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return tuple(deduped)


def load_skill_manifests(
    skill_dirs: Sequence[str | Path],
) -> tuple[SkillDefinition, ...]:
    """Return the validated skill manifests found under *skill_dirs*.

    Raises :class:`SkillValidationError` on the first invalid manifest.
    """
    results: list[SkillDefinition] = []
    seen_ids: set[str] = set()
    for raw_dir in skill_dirs:
        root = Path(raw_dir).expanduser()
        if not root.exists():
            continue
        if not root.is_dir():
            raise SkillValidationError(
                f"skill plugin path is not a directory: {root}"
            )
        for manifest_path in sorted(root.rglob("*.json")):
            definition = _load_from_file(manifest_path)
            if definition.skill_id in seen_ids:
                raise SkillValidationError(
                    f"duplicate skill_id {definition.skill_id!r} in {manifest_path}"
                )
            seen_ids.add(definition.skill_id)
            results.append(definition)
    return tuple(results)


def skill_registry_statuses(
    skill_dirs: Sequence[str | Path],
) -> list[dict[str, Any]]:
    """Return a mixed ``valid`` / ``invalid`` row set for operator review.

    Mirrors :func:`forge.connectors.registry.connector_plugin_manifest_statuses`
    so the CLI table can show invalid manifests without aborting the whole
    scan.
    """
    rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for raw_dir in skill_dirs:
        root = Path(raw_dir).expanduser()
        if not root.exists():
            continue
        if not root.is_dir():
            rows.append(
                {
                    "path": str(root),
                    "status": "invalid",
                    "error": "skill plugin path is not a directory",
                }
            )
            continue
        for manifest_path in sorted(root.rglob("*.json")):
            try:
                definition = _load_from_file(manifest_path)
                if definition.skill_id in seen_ids:
                    raise SkillValidationError(
                        f"duplicate skill_id {definition.skill_id!r}"
                    )
                seen_ids.add(definition.skill_id)
            except SkillValidationError as exc:
                rows.append(
                    {
                        "path": str(manifest_path),
                        "status": "invalid",
                        "error": str(exc),
                    }
                )
                continue
            rows.append(
                {
                    "path": str(manifest_path),
                    "status": "valid",
                    "skill_id": definition.skill_id,
                    "name": definition.name,
                    "version": definition.version,
                    "safety_class": definition.safety_class,
                    "capabilities": list(definition.capabilities),
                    "required_gates": list(definition.required_gates),
                    "tags": list(definition.tags),
                }
            )
    return rows


def _load_from_file(path: Path) -> SkillDefinition:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise SkillValidationError(f"cannot stat skill manifest {path}: {exc}") from exc
    if size > _MAX_MANIFEST_BYTES:
        raise SkillValidationError(f"skill manifest is too large: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SkillValidationError(f"invalid skill manifest JSON {path}: {exc}") from exc
    except OSError as exc:
        raise SkillValidationError(f"cannot read skill manifest {path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise SkillValidationError(f"skill manifest {path}: must be a JSON object")
    return load_skill_manifest(payload, source=str(path))
