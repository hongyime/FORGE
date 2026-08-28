from __future__ import annotations

import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from forge.automation_self_heal import DEFAULT_AUTOSTART_CONFIG_PATH, run_guarded_autostart
from forge.automation_target_feed import build_target_feed, write_target_feed
from forge.config import ForgeConfig

AUTOMATION_STATUS_SCHEMA_VERSION = "forge.automation_status.v1"
AUTOMATION_CYCLE_SCHEMA_VERSION = "forge.automation_cycle.v1"

SOURCE_QUEUE_FILES: dict[str, dict[str, str]] = {
    "abusech_threatfox": {
        "filename": "threatfox-inputs.local.json",
        "command": "import-cti",
    },
    "abusech_urlhaus": {
        "filename": "urlhaus-inputs.local.json",
        "command": "import-cti",
    },
    "misp_event_import": {
        "filename": "misp-inputs.local.json",
        "command": "import-cti",
    },
    "stix_taxii_import": {
        "filename": "stix-taxii-inputs.local.json",
        "command": "import-cti",
    },
    "projectdiscovery_cloud": {
        "filename": "projectdiscovery-cloud-imports.local.json",
        "command": "import-discovery",
    },
    "censys_lookup": {
        "filename": "censys-imports.local.json",
        "command": "import-discovery",
    },
    "runzero_asset_export": {
        "filename": "runzero-imports.local.json",
        "command": "import-discovery",
    },
    "asset_delta_import": {
        "filename": "asset-delta-imports.local.json",
        "command": "import-discovery",
    },
    "burp_dast_xml": {
        "filename": "burp-dast-imports.local.json",
        "command": "import-validation",
    },
}

INBOX_DIRNAME = "inbox"


def automation_status(
    *,
    imports_dir: Path | None = None,
    output: Path | None = None,
    data_dir: Path | None = None,
    engagement: int | None = None,
) -> dict[str, Any]:
    root_imports = Path(imports_dir or "imports")
    feed_path = Path(output or root_imports / "target-feed.json")
    cfg_data_dir = data_dir or ForgeConfig.load().data_dir
    queue_items = _load_queue_items(root_imports)
    ready_items, blocked_items = _classify_queue_items(
        queue_items,
        imports_dir=root_imports,
        engagement=engagement,
    )
    return {
        "schema_version": AUTOMATION_STATUS_SCHEMA_VERSION,
        "execution_policy": "read_only_status_no_commands_executed",
        "generated_at": _now_iso(),
        "paths": {
            "imports_dir": str(root_imports),
            "target_feed": str(feed_path),
            "data_dir": str(cfg_data_dir),
            "autostart_config": str(DEFAULT_AUTOSTART_CONFIG_PATH),
        },
        "feed": {
            "exists": feed_path.is_file(),
            "size_bytes": feed_path.stat().st_size if feed_path.is_file() else 0,
        },
        "queues": _queue_summary(queue_items, ready_items, blocked_items),
        "scan_policy": _scan_policy(),
        "ready_inputs": ready_items,
        "blocked_inputs": blocked_items,
        "next_actions": _status_next_actions(ready_items, blocked_items),
        "total_count": len(queue_items),
        "selected_count": len(ready_items),
        "omitted_count": len(blocked_items),
    }


def automation_cycle(
    *,
    apply: bool = False,
    live: bool = False,
    engagement: int | None = None,
    output: Path | None = None,
    source: list[str] | None = None,
    data_dir: Path | None = None,
    reports_dir: Path | None = None,
    imports_dir: Path | None = None,
    limit: int | None = None,
    supabase_config: Path | None = None,
    autostart_config: Path | None = None,
    command_runner: Any | None = None,
) -> dict[str, Any]:
    root_imports = Path(imports_dir or "imports")
    feed_output = Path(output or root_imports / "target-feed.json")
    cfg_data_dir = data_dir or ForgeConfig.load().data_dir
    sources = list(source or ["all"])
    feed_payload = build_target_feed(
        sources=sources,
        data_dir=Path(cfg_data_dir),
        reports_dir=reports_dir or Path("reports"),
        imports_dir=root_imports,
        limit=limit,
        existing_feed_path=feed_output,
        apply=apply,
        supabase_config_path=supabase_config or root_imports / "supabase-projects.local.json",
    )
    feed_written = False
    if apply:
        write_target_feed(feed_payload, feed_output)
        feed_written = True
    inbox_update = classify_import_inbox(imports_dir=root_imports, apply=apply)
    queue_items = _load_queue_items(root_imports)
    ready_items, blocked_items = _classify_queue_items(
        queue_items,
        imports_dir=root_imports,
        engagement=engagement,
    )
    queue_runs = _run_ready_queue_items(
        ready_items,
        apply=apply,
        command_runner=command_runner,
    )
    autostart_result: dict[str, Any] | None = None
    if live:
        autostart_result = run_guarded_autostart(
            config_path=autostart_config or DEFAULT_AUTOSTART_CONFIG_PATH,
            data_dir=Path(cfg_data_dir),
            apply=apply,
        )
    execution_policy = "dry_run_no_writes_or_live_commands_executed"
    if apply and live:
        execution_policy = "apply_with_live_guarded_autostart"
    elif apply:
        execution_policy = "apply_local_feed_and_queue_imports"
    return {
        "schema_version": AUTOMATION_CYCLE_SCHEMA_VERSION,
        "execution_policy": execution_policy,
        "apply_requested": bool(apply),
        "live_requested": bool(live),
        "generated_at": _now_iso(),
        "feed_written": feed_written,
        "feed": {
            "output": str(feed_output),
            "counts": feed_payload["counts"],
            "source_errors": feed_payload["source_errors"],
            "discovered_input_registry_update": feed_payload.get(
                "discovered_input_registry_update", {}
            ),
            "source_input_registry_updates": feed_payload.get(
                "source_input_registry_updates", []
            ),
        },
        "inbox": inbox_update,
        "queues": _queue_summary(queue_items, ready_items, blocked_items),
        "scan_policy": _scan_policy(),
        "ready_inputs": ready_items,
        "blocked_inputs": blocked_items,
        "queue_runs": queue_runs,
        "autostart": autostart_result,
        "total_count": 1 + len(queue_items) + (1 if live else 0),
        "selected_count": (1 if feed_written else 0)
        + sum(1 for item in queue_runs if item["status"] in {"completed", "planned"}),
        "omitted_count": len(blocked_items),
    }


def doctor_fix_safe(*, imports_dir: Path | None = None) -> dict[str, Any]:
    root_imports = Path(imports_dir or "imports")
    actions: list[dict[str, Any]] = []
    root_imports.mkdir(parents=True, exist_ok=True)
    actions.append({"id": "ensure_imports_dir", "status": "ok", "path": str(root_imports)})
    inbox = root_imports / INBOX_DIRNAME
    inbox.mkdir(parents=True, exist_ok=True)
    actions.append({"id": "ensure_imports_inbox", "status": "ok", "path": str(inbox)})
    local_files = [
        root_imports / "supabase-projects.local.json",
        root_imports / "discovered-inputs.local.json",
        *(root_imports / descriptor["filename"] for descriptor in SOURCE_QUEUE_FILES.values()),
    ]
    for path in local_files:
        if not path.exists():
            _write_json_atomic(path, _empty_local_payload(path))
            actions.append({"id": "create_local_json", "status": "created", "path": str(path)})
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            backup = path.with_suffix(path.suffix + ".bak")
            path.replace(backup)
            _write_json_atomic(path, _empty_local_payload(path))
            actions.append(
                {
                    "id": "repair_local_json",
                    "status": "repaired",
                    "path": str(path),
                    "backup": str(backup),
                }
            )
            continue
        if not isinstance(payload, dict):
            backup = path.with_suffix(path.suffix + ".bak")
            path.replace(backup)
            _write_json_atomic(path, _empty_local_payload(path))
            actions.append(
                {
                    "id": "repair_local_json",
                    "status": "repaired",
                    "path": str(path),
                    "backup": str(backup),
                }
            )
            continue
        actions.append({"id": "check_local_json", "status": "ok", "path": str(path)})
    return {
        "schema_version": "forge.doctor_safe_fix.v1",
        "execution_policy": "local_safe_fixes_no_live_or_provider_commands",
        "generated_at": _now_iso(),
        "actions": actions,
        "total_count": len(actions),
        "selected_count": sum(1 for item in actions if item["status"] in {"created", "repaired"}),
        "omitted_count": sum(1 for item in actions if item["status"] == "ok"),
    }


def classify_import_inbox(*, imports_dir: Path | None = None, apply: bool = False) -> dict[str, Any]:
    root_imports = Path(imports_dir or "imports")
    inbox = root_imports / INBOX_DIRNAME
    discovered: list[dict[str, Any]] = []
    if inbox.is_dir():
        for path in sorted(inbox.iterdir()):
            if not path.is_file():
                continue
            item = _classify_inbox_file(path, imports_dir=root_imports)
            if item is not None:
                discovered.append(item)
    planned = _inbox_queue_update_plan(discovered, imports_dir=root_imports)
    applied: list[dict[str, Any]] = []
    if apply and discovered:
        applied = _append_inbox_items_to_source_queues(discovered, imports_dir=root_imports)
    return {
        "schema_version": "forge.import_inbox_classification.v1",
        "execution_policy": "applied_local_queue_updates" if apply else "dry_run_no_writes",
        "inbox_dir": str(inbox),
        "apply_requested": bool(apply),
        "discovered_count": len(discovered),
        "discovered_inputs": discovered,
        "queue_update_plan": planned,
        "queue_updates": applied,
    }


def _classify_inbox_file(path: Path, *, imports_dir: Path) -> dict[str, Any] | None:
    haystack = f"{path.name} {path.suffix}".lower()
    connector_id = ""
    input_kind = ""
    priority = 70
    if any(marker in haystack for marker in ("threatfox",)):
        connector_id = "abusech_threatfox"
        input_kind = "cti_marker"
    elif any(marker in haystack for marker in ("urlhaus",)):
        connector_id = "abusech_urlhaus"
        input_kind = "cti_marker"
    elif "misp" in haystack:
        connector_id = "misp_event_import"
        input_kind = "cti_marker"
    elif "stix" in haystack or "taxii" in haystack:
        connector_id = "stix_taxii_import"
        input_kind = "cti_marker"
    elif any(marker in haystack for marker in ("projectdiscovery", "pd-cloud", "pd_cloud", "nuclei-cloud")):
        connector_id = "projectdiscovery_cloud"
        input_kind = "discovery_artifact"
        priority = 85
    elif "censys" in haystack:
        connector_id = "censys_lookup"
        input_kind = "discovery_artifact"
        priority = 80
    elif "runzero" in haystack or "run0" in haystack or "rumble" in haystack:
        connector_id = "runzero_asset_export"
        input_kind = "discovery_artifact"
        priority = 80
    elif "asset-delta" in haystack or "asset_delta" in haystack:
        connector_id = "asset_delta_import"
        input_kind = "discovery_artifact"
        priority = 80
    elif path.suffix.lower() == ".xml" and any(
        marker in haystack for marker in ("burp", "junit", "dast", "zap")
    ):
        connector_id = "burp_dast_xml"
        input_kind = "validation_artifact"
        priority = 75
    if not connector_id:
        return None
    return {
        "input_kind": input_kind,
        "connector_id": connector_id,
        "value": str(path.relative_to(imports_dir)),
        "status": "pending",
        "priority": priority,
        "source_groups": [f"inbox:{path.name}"],
    }


def _inbox_queue_update_plan(
    discovered: list[dict[str, Any]], *, imports_dir: Path
) -> list[dict[str, Any]]:
    counts: dict[Path, int] = {}
    for item in discovered:
        descriptor = SOURCE_QUEUE_FILES.get(str(item.get("connector_id") or ""))
        if descriptor is None:
            continue
        path = imports_dir / descriptor["filename"]
        counts[path] = counts.get(path, 0) + 1
    return [
        {
            "config_path": str(path),
            "applied": False,
            "pending_count": count,
            "appended_count": 0,
        }
        for path, count in sorted(counts.items(), key=lambda pair: str(pair[0]))
    ]


def _append_inbox_items_to_source_queues(
    discovered: list[dict[str, Any]], *, imports_dir: Path
) -> list[dict[str, Any]]:
    by_path: dict[Path, list[dict[str, Any]]] = {}
    for item in discovered:
        descriptor = SOURCE_QUEUE_FILES.get(str(item.get("connector_id") or ""))
        if descriptor is None:
            continue
        by_path.setdefault(imports_dir / descriptor["filename"], []).append(item)
    updates: list[dict[str, Any]] = []
    for path, items in sorted(by_path.items(), key=lambda pair: str(pair[0])):
        payload = _read_json_object(path)
        raw_inputs = payload.get("inputs")
        if not isinstance(raw_inputs, list):
            raw_inputs = []
        known = {
            _queue_item_key(item)
            for item in raw_inputs
            if isinstance(item, dict)
        }
        appended = 0
        for item in items:
            key = _queue_item_key(item)
            if key in known:
                continue
            raw_inputs.append({**item, "first_seen_at": _now_iso()})
            known.add(key)
            appended += 1
        payload["schema_version"] = "forge.source_inputs.v1"
        payload["connector_id"] = str(items[0].get("connector_id") or "")
        payload["input_kind"] = str(items[0].get("input_kind") or "")
        payload["updated_at"] = _now_iso()
        payload["inputs"] = raw_inputs
        _write_json_atomic(path, payload)
        updates.append(
            {
                "config_path": str(path),
                "applied": True,
                "pending_count": 0,
                "appended_count": appended,
            }
        )
    return updates


def _load_queue_items(imports_dir: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for connector_id, descriptor in SOURCE_QUEUE_FILES.items():
        path = imports_dir / descriptor["filename"]
        payload = _read_json_object(path)
        raw_inputs = payload.get("inputs")
        if not isinstance(raw_inputs, list):
            continue
        for index, raw_item in enumerate(raw_inputs):
            if not isinstance(raw_item, dict):
                continue
            item = dict(raw_item)
            item.setdefault("connector_id", connector_id)
            item.setdefault("input_kind", "")
            item["_queue_file"] = str(path)
            item["_queue_index"] = index
            items.append(item)
    return items


def _queue_item_key(item: dict[str, Any]) -> str:
    return "|".join(
        [
            str(item.get("input_kind") or "").strip().lower(),
            str(item.get("connector_id") or "").strip().lower(),
            str(item.get("value") or item.get("path") or item.get("report_file") or "")
            .strip()
            .lower(),
        ]
    )


def _empty_local_payload(path: Path) -> dict[str, Any]:
    if path.name == "supabase-projects.local.json":
        return {
            "projects": [],
            "_instructions": "Add owned read-only Supabase project_ref/key_env entries here.",
        }
    if path.name == "discovered-inputs.local.json":
        return {
            "schema_version": "forge.discovered_inputs.v1",
            "inputs": [],
            "_instructions": "Local discovered reusable inputs. Forge updates this file; do not add secrets.",
        }
    connector_id = ""
    input_kind = ""
    for candidate_connector_id, descriptor in SOURCE_QUEUE_FILES.items():
        if descriptor["filename"] == path.name:
            connector_id = candidate_connector_id
            command_kind = descriptor["command"]
            input_kind = (
                "cti_marker"
                if command_kind == "import-cti"
                else "validation_artifact"
                if command_kind == "import-validation"
                else "discovery_artifact"
            )
            break
    return {
        "schema_version": "forge.source_inputs.v1",
        "connector_id": connector_id,
        "input_kind": input_kind,
        "inputs": [],
    }


def _classify_queue_items(
    items: list[dict[str, Any]],
    *,
    imports_dir: Path,
    engagement: int | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    ready: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for item in items:
        status = str(item.get("status") or "pending").strip().lower()
        if status in {"imported", "completed", "promoted"}:
            continue
        connector_id = str(item.get("connector_id") or "").strip()
        descriptor = SOURCE_QUEUE_FILES.get(connector_id)
        if descriptor is None:
            blocked.append(_blocked(item, "unsupported_connector"))
            continue
        item_engagement = _item_engagement(item, engagement)
        if item_engagement is None:
            blocked.append(_blocked(item, "engagement_required"))
            continue
        artifact = _queue_artifact_path(item, imports_dir)
        if artifact is None:
            blocked.append(_blocked(item, "local_artifact_required"))
            continue
        if not artifact.is_file():
            blocked.append(_blocked(item, f"local_artifact_missing:{artifact}"))
            continue
        command = _queue_command(
            descriptor["command"],
            connector_id=connector_id,
            engagement=item_engagement,
            artifact=artifact,
            target=str(item.get("target") or ""),
        )
        ready.append(
            {
                "connector_id": connector_id,
                "input_kind": str(item.get("input_kind") or ""),
                "value": str(item.get("value") or ""),
                "queue_file": str(item.get("_queue_file") or ""),
                "queue_index": int(item.get("_queue_index") or 0),
                "engagement_id": item_engagement,
                "artifact_path": str(artifact),
                "command": command,
                "priority": _queue_priority(item),
                "status": "ready",
            }
        )
    ready.sort(key=lambda item: (-int(item["priority"]), str(item["connector_id"]), str(item["value"])))
    return ready, blocked


def _run_ready_queue_items(
    ready_items: list[dict[str, Any]],
    *,
    apply: bool,
    command_runner: Any | None,
) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for item in ready_items:
        command = list(item["command"])
        if not apply:
            runs.append({**item, "status": "planned", "returncode": None})
            continue
        runner = command_runner or _run_command
        result = runner(command, Path.cwd())
        status = "completed" if int(result.get("returncode", 1)) == 0 else "failed"
        runs.append(
            {
                **item,
                "status": status,
                "returncode": int(result.get("returncode", 1)),
                "stdout": str(result.get("stdout") or "")[:2000],
                "stderr": str(result.get("stderr") or "")[:2000],
            }
        )
        if status == "completed":
            _mark_queue_item_status(
                queue_file=Path(str(item["queue_file"])),
                queue_index=int(item["queue_index"]),
                status="imported",
            )
    return runs


def _queue_command(
    command_kind: str,
    *,
    connector_id: str,
    engagement: int,
    artifact: Path,
    target: str,
) -> list[str]:
    command = [
        "forge",
        "connectors",
        command_kind,
        "--engagement",
        str(engagement),
        "--connector",
        connector_id,
        "--report-file",
        str(artifact),
    ]
    if target:
        command.extend(["--target", target])
    if command_kind == "import-cti":
        command.append("--promote-targets")
    command.append("--json")
    return command


def _queue_artifact_path(item: dict[str, Any], imports_dir: Path) -> Path | None:
    raw_value = str(item.get("path") or item.get("report_file") or item.get("value") or "").strip()
    if not raw_value:
        return None
    path = Path(raw_value)
    if path.is_absolute():
        return path
    return imports_dir / path


def _item_engagement(item: dict[str, Any], fallback: int | None) -> int | None:
    raw_value = item.get("engagement_id", fallback)
    if raw_value is None or str(raw_value).strip() == "":
        return None
    try:
        return int(raw_value)
    except (TypeError, ValueError):
        return None


def _queue_priority(item: dict[str, Any]) -> int:
    raw_priority = item.get("priority")
    if raw_priority is not None:
        try:
            return int(raw_priority)
        except (TypeError, ValueError):
            pass
    source_groups = item.get("source_groups")
    if isinstance(source_groups, list) and len(source_groups) >= 2:
        return 80
    return 60


def _scan_policy() -> dict[str, Any]:
    return {
        "feed_sources": "all_by_default",
        "new_targets": "scan_immediately_when_cycle_runs_with_apply_live_and_roe_gates_pass",
        "multi_source_target_threshold": 2,
        "multi_source_priority": "high",
        "queue_order": "priority_desc_then_connector_then_value",
        "live_guard": "guarded_autostart_memory_disk_docker_cooldown_backoff_single_instance",
    }


def _blocked(item: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "connector_id": str(item.get("connector_id") or ""),
        "input_kind": str(item.get("input_kind") or ""),
        "value": str(item.get("value") or ""),
        "queue_file": str(item.get("_queue_file") or ""),
        "queue_index": int(item.get("_queue_index") or 0),
        "status": "blocked",
        "reason": reason,
    }


def _queue_summary(
    all_items: list[dict[str, Any]],
    ready_items: list[dict[str, Any]],
    blocked_items: list[dict[str, Any]],
) -> dict[str, Any]:
    by_connector: dict[str, int] = {}
    for item in all_items:
        connector_id = str(item.get("connector_id") or "unknown")
        by_connector[connector_id] = by_connector.get(connector_id, 0) + 1
    return {
        "total": len(all_items),
        "ready": len(ready_items),
        "blocked": len(blocked_items),
        "by_connector": dict(sorted(by_connector.items())),
    }


def _status_next_actions(
    ready_items: list[dict[str, Any]],
    blocked_items: list[dict[str, Any]],
) -> list[str]:
    actions: list[str] = []
    if ready_items:
        actions.append("forge automation cycle --apply --engagement N --json")
    if any(item["reason"] == "engagement_required" for item in blocked_items):
        actions.append("add engagement_id to queue entries or pass --engagement N")
    if any(str(item["reason"]).startswith("local_artifact_missing") for item in blocked_items):
        actions.append("place referenced artifacts under imports/ or fix queue item paths")
    if not actions:
        actions.append("forge automation cycle --apply --json")
    return actions


def _mark_queue_item_status(*, queue_file: Path, queue_index: int, status: str) -> None:
    payload = _read_json_object(queue_file)
    raw_inputs = payload.get("inputs")
    if not isinstance(raw_inputs, list) or queue_index >= len(raw_inputs):
        return
    item = raw_inputs[queue_index]
    if not isinstance(item, dict):
        return
    item["status"] = status
    item["last_processed_at"] = _now_iso()
    payload["updated_at"] = _now_iso()
    queue_file.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(queue_file.parent), prefix=f".{queue_file.stem}-", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_name, queue_file)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.stem}-", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _run_command(command: list[str], cwd: Path) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=20 * 60,
        check=False,
    )
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
