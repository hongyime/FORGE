"""FORGE first-run setup helper.

``forge setup`` creates the local operator state needed to run the
autopilot straight out of the box:

- Writes ``.env`` from ``.env.example`` if it is missing.
- Ensures ``FORGE_ROE_ID`` is set in that ``.env`` (defaults to
  ``ROE-1``, matching :class:`forge.autopilot.AutopilotDefaults`).
- Ensures ``FORGE_SAFE_MODE=0`` so the autopilot runs live by default.
- Creates the data/imports/reports/manifests directory structure.
- Copies the shipped ``manifests/default.json`` scope manifest template
  (if missing) and the ``imports/starter-targets.example.json`` feed
  example so new operators have working references.
- Runs ``forge doctor --json`` to report readiness state.

The command is intentionally non-destructive: existing ``.env`` files,
existing manifests, and existing feed files are left untouched. The
only writes are missing-file creations and additive ``.env`` key
inserts.

Nothing in this module launches live outbound work. ``forge doctor``
runs read-only; the autopilot is advertised at the end but not auto-
started.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from forge.autopilot.defaults import AutopilotDefaults


SETUP_SCHEMA_VERSION = "forge.setup.v1"


@dataclass
class SetupAction:
    """One recorded setup action.

    ``status`` is one of:

    - ``created`` — file written.
    - ``updated`` — existing file modified.
    - ``exists`` — file already present, no change.
    - ``missing_source`` — a template source file was expected but
      not found. The setup continues and records the gap.
    - ``skipped`` — operator-controlled skip.
    - ``error`` — an exception occurred.
    """

    name: str
    status: str
    path: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "path": self.path,
            "detail": self.detail,
        }


@dataclass
class SetupResult:
    schema_version: str = SETUP_SCHEMA_VERSION
    actions: list[SetupAction] = field(default_factory=list)
    doctor: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "actions": [a.to_dict() for a in self.actions],
            "doctor": self.doctor,
        }


# ---------------------------------------------------------------------------
# Env file helpers
# ---------------------------------------------------------------------------


def _read_env_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []


def _parse_env_keys(lines: Iterable[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip()
    return out


def _upsert_env_key(lines: list[str], key: str, value: str) -> tuple[list[str], str]:
    """Insert or replace a ``KEY=value`` line.

    Returns the updated line list and ``"updated"`` or ``"created"``.
    """
    seen = False
    out: list[str] = []
    status = "created"
    for raw in lines:
        stripped = raw.strip()
        if (
            not stripped.startswith("#")
            and "=" in stripped
            and stripped.split("=", 1)[0].strip() == key
        ):
            if not seen:
                out.append(f"{key}={value}")
                status = "updated"
                seen = True
            continue
        out.append(raw)
    if not seen:
        out.append(f"{key}={value}")
    return out, status


def ensure_env_file(
    *,
    root: Path,
    env_path: Path,
    example_path: Path,
    required_keys: Mapping[str, str],
) -> list[SetupAction]:
    """Create ``.env`` from ``.env.example`` and enforce required keys.

    Returns the list of recorded :class:`SetupAction` entries so the
    caller can report what changed.
    """
    actions: list[SetupAction] = []
    created_file = False
    if not env_path.exists():
        if example_path.exists():
            env_path.write_text(example_path.read_text(encoding="utf-8"), encoding="utf-8")
            actions.append(
                SetupAction(
                    name="env_file_create",
                    status="created",
                    path=str(env_path),
                    detail=f"copied from {example_path.name}",
                )
            )
            created_file = True
        else:
            env_path.write_text("", encoding="utf-8")
            actions.append(
                SetupAction(
                    name="env_file_create",
                    status="created",
                    path=str(env_path),
                    detail="empty — .env.example missing",
                )
            )
            created_file = True
    else:
        actions.append(
            SetupAction(
                name="env_file_create",
                status="exists",
                path=str(env_path),
            )
        )

    lines = _read_env_lines(env_path)
    existing = _parse_env_keys(lines)
    updates = 0
    for key, value in required_keys.items():
        current = existing.get(key, "")
        if current == value:
            continue
        if current:
            # Preserve a non-empty value the operator chose, EXCEPT when
            # the value violates the autopilot contract (SAFE_MODE must
            # be 0 for the loop to run live). Record a diagnostic action.
            if key == "FORGE_SAFE_MODE" and current not in ("0", "false", "no", "off"):
                lines, status = _upsert_env_key(lines, key, value)
                actions.append(
                    SetupAction(
                        name=f"env_key:{key}",
                        status=status,
                        path=str(env_path),
                        detail=(
                            f"forced {key}={value} (was {current!r}); "
                            "FORGE_SAFE_MODE=1 blocks the autopilot loop"
                        ),
                    )
                )
                updates += 1
                continue
            actions.append(
                SetupAction(
                    name=f"env_key:{key}",
                    status="exists",
                    path=str(env_path),
                    detail=f"existing value preserved",
                )
            )
            continue
        lines, status = _upsert_env_key(lines, key, value)
        actions.append(
            SetupAction(
                name=f"env_key:{key}",
                status=status,
                path=str(env_path),
                detail=f"set to {value}",
            )
        )
        updates += 1
    if updates > 0 or created_file:
        env_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return actions


# ---------------------------------------------------------------------------
# Directory and template helpers
# ---------------------------------------------------------------------------


def ensure_directories(paths: Iterable[Path]) -> list[SetupAction]:
    actions: list[SetupAction] = []
    for path in paths:
        if path.exists():
            actions.append(
                SetupAction(
                    name=f"dir:{path.name}",
                    status="exists",
                    path=str(path),
                )
            )
            continue
        try:
            path.mkdir(parents=True, exist_ok=True)
            actions.append(
                SetupAction(
                    name=f"dir:{path.name}",
                    status="created",
                    path=str(path),
                )
            )
        except OSError as exc:
            actions.append(
                SetupAction(
                    name=f"dir:{path.name}",
                    status="error",
                    path=str(path),
                    detail=str(exc),
                )
            )
    return actions


def ensure_template(
    *,
    name: str,
    source: Path,
    destination: Path,
) -> SetupAction:
    """Copy ``source`` to ``destination`` if the destination is missing."""
    if destination.exists():
        return SetupAction(
            name=name, status="exists", path=str(destination)
        )
    if not source.exists():
        return SetupAction(
            name=name,
            status="missing_source",
            path=str(source),
            detail=f"template missing — expected at {source}",
        )
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        return SetupAction(
            name=name,
            status="created",
            path=str(destination),
            detail=f"copied from {source.name}",
        )
    except OSError as exc:
        return SetupAction(
            name=name,
            status="error",
            path=str(destination),
            detail=str(exc),
        )


# ---------------------------------------------------------------------------
# Doctor integration
# ---------------------------------------------------------------------------


def _run_doctor_summary() -> dict[str, Any] | None:
    """Run ``forge doctor`` in JSON mode and return the parsed payload.

    Returns ``None`` on import failure; errors in the doctor payload
    are left in the payload so the caller can surface them.
    """
    try:
        from forge.doctor import collect_doctor_checks, doctor_payload_json
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "detail": f"doctor_import_failed:{exc}"}
    try:
        checks = collect_doctor_checks(live_provider_probes=False)
        payload = json.loads(doctor_payload_json(checks))
        return payload
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "detail": f"doctor_run_failed:{exc}"}


# ---------------------------------------------------------------------------
# Public API — ``forge setup``
# ---------------------------------------------------------------------------


def run_first_run_setup(
    *,
    root: Path | None = None,
    data_dir: Path | None = None,
    skip_doctor: bool = False,
    defaults: AutopilotDefaults | None = None,
    env: Mapping[str, str] | None = None,
) -> SetupResult:
    """Idempotent first-run setup.

    - Writes a non-destructive ``.env`` from ``.env.example`` and
      enforces the autopilot's required keys.
    - Creates data/imports/reports/manifests directories.
    - Copies the shipped scope-manifest and starter target feed to the
      operator's local tree (idempotent).
    - Runs ``forge doctor`` in JSON mode.

    Args:
        root: Repository root (defaults to CWD).
        data_dir: ``FORGE_DATA_DIR`` to ensure. Defaults to
            ``<root>/.forge_data`` when unset.
        skip_doctor: If True, skip the readiness probe.
        defaults: Autopilot defaults to seed required env keys from.
        env: Environment mapping override for testing.

    Returns:
        A :class:`SetupResult` with every recorded action.
    """
    root_path = Path(root) if root else Path.cwd()
    environ = env if env is not None else os.environ
    autopilot_defaults = defaults or AutopilotDefaults()

    env_path = root_path / ".env"
    example_path = root_path / ".env.example"
    data_dir_path = Path(
        data_dir
        or environ.get("FORGE_DATA_DIR", "")
        or (root_path / ".forge_data")
    )
    imports_dir = root_path / "imports"
    reports_dir = root_path / "reports"
    manifests_dir = root_path / "manifests"

    result = SetupResult()

    required_env = {
        "FORGE_ROE_ID": autopilot_defaults.default_roe_id or "ROE-1",
        "FORGE_SAFE_MODE": "0",
        "FORGE_SCOPE_MANIFEST": "manifests/default.json",
    }
    result.actions.extend(
        ensure_env_file(
            root=root_path,
            env_path=env_path,
            example_path=example_path,
            required_keys=required_env,
        )
    )

    result.actions.extend(
        ensure_directories(
            [
                data_dir_path,
                imports_dir,
                reports_dir,
                manifests_dir,
                data_dir_path / "engagements",
            ]
        )
    )

    # Scope manifest template. ``manifests/default.json`` ships with
    # all exploitation permissions enabled by the goal lock v2
    # contract; the operator must still populate domains/urls/ip_ranges
    # before launching live scans.
    shipped_manifest = root_path / "manifests" / "default.json"
    local_manifest = manifests_dir / "default.json"
    if shipped_manifest.resolve() == local_manifest.resolve():
        result.actions.append(
            SetupAction(
                name="scope_manifest_template",
                status="exists" if local_manifest.exists() else "missing_source",
                path=str(local_manifest),
            )
        )
    else:
        result.actions.append(
            ensure_template(
                name="scope_manifest_template",
                source=shipped_manifest,
                destination=local_manifest,
            )
        )

    # Starter target-feed example. We write a `.example.json` reference
    # alongside the operator-maintained `target-feed.json` so a bare
    # `forge autopilot` cycle has a documented shape to follow.
    shipped_feed = root_path / "imports" / "starter-targets.example.json"
    local_feed_example = imports_dir / "starter-targets.example.json"
    if shipped_feed.resolve() == local_feed_example.resolve():
        result.actions.append(
            SetupAction(
                name="starter_feed_example",
                status="exists" if local_feed_example.exists() else "missing_source",
                path=str(local_feed_example),
            )
        )
    else:
        result.actions.append(
            ensure_template(
                name="starter_feed_example",
                source=shipped_feed,
                destination=local_feed_example,
            )
        )

    if not skip_doctor:
        result.doctor = _run_doctor_summary()

    return result


__all__ = [
    "SETUP_SCHEMA_VERSION",
    "SetupAction",
    "SetupResult",
    "ensure_env_file",
    "ensure_directories",
    "ensure_template",
    "run_first_run_setup",
]
