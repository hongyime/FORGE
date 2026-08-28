"""Build the deterministic target feed consumed by target import.

`build_target_feed` merges key-free local sources (engagement DB seeds,
report/dashboard artifacts, CTI observation files, connector output payloads)
and explicitly configured read-only Supabase REST tables into one
`target-feed.v1` payload with merge + dedupe by canonical target key.

Write policy: dry-run by default; `apply=True` writes atomically and preserves
existing feed entries.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from forge.config import ForgeConfig
from forge.connectors.secrets import resolve_connector_secret_value
from forge.db.session import get_engagement_db
from forge.engagement_ids import numeric_engagement_db_files
from forge.targets_import import (
    TARGET_FEED_SCHEMA_VERSION,
    _normalize_target_value,
    external_target_key,
    load_target_feed,
)

SUPPORTED_SOURCES = ("db", "reports", "cti", "connectors", "supabase")
_OFFLINE_SOURCES = ("db", "reports", "cti", "connectors")

_MAX_FILES_PER_DIR_SOURCE = 200
_MAX_REPORT_FILES = 500
_MAX_ENGAGEMENT_DBS = 500
_MAX_JSON_FILE_BYTES = 2 * 1024 * 1024
_MAX_WALK_DEPTH = 6
_MAX_VALUES_PER_FILE = 5000
_SUPABASE_PAGE_SIZE = 1000
_MAX_SUPABASE_TABLE_ROWS = 100000
_MAX_SUPABASE_DISCOVERED_TABLES = 1000
_DEFAULT_SUPABASE_CONFIG = Path("imports") / "supabase-projects.local.json"
_DEFAULT_DISCOVERED_INPUTS_REGISTRY = Path("imports") / "discovered-inputs.local.json"
_SPECIFIC_INPUT_REGISTRY_FILENAMES = {
    "abusech_threatfox": "threatfox-inputs.local.json",
    "abusech_urlhaus": "urlhaus-inputs.local.json",
    "misp_event_import": "misp-inputs.local.json",
    "stix_taxii_import": "stix-taxii-inputs.local.json",
    "projectdiscovery_cloud": "projectdiscovery-cloud-imports.local.json",
    "censys_lookup": "censys-imports.local.json",
    "runzero_asset_export": "runzero-imports.local.json",
    "asset_delta_import": "asset-delta-imports.local.json",
    "burp_dast_xml": "burp-dast-imports.local.json",
}
_DEFAULT_TARGET_COLUMNS = (
    "domain",
    "url",
    "host",
    "hostname",
    "ip",
    "ip_address",
    "email",
    "username",
    "cloud_ref",
)

_HARVEST_KEYS = {
    "domain",
    "host",
    "hostname",
    "url",
    "uri",
    "ip",
    "ip_address",
    "email",
    "emails",
    "username",
    "usernames",
    "user",
    "cloud_ref",
    "cloud_refs",
    "target",
    "targets",
    "target_value",
    "seed",
    "seeds",
    "seed_value",
    "domain",
    "domains",
    "subdomain",
    "subdomains",
    "host",
    "hosts",
    "hostname",
    "url",
    "urls",
    "uri",
    "ip",
    "ips",
    "ip_address",
    "ioc",
    "iocs",
}

_CTI_FILENAME_MARKERS = ("threatfox", "urlhaus", "misp", "stix", "taxii")
_CONNECTOR_SOURCE_EXCLUDED_NAMES = {
    "autostart.local.json",
    "discovered-inputs.local.json",
    "supabase-projects.local.json",
    "target-feed.json",
}
_SUPABASE_PROJECT_REF_RE = re.compile(
    r"(?i)\b([a-z0-9][a-z0-9-]{4,62})\.supabase\.(?:co|in)\b"
)
_DISCOVERABLE_INPUT_MARKERS = (
    {
        "input_kind": "cti_marker",
        "connector_id": "abusech_threatfox",
        "status": "accepted_local_marker",
        "markers": ("threatfox",),
        "next_action": "forge connectors import-cti --connector abusech_threatfox --report-file <path> --dry-run --json",
    },
    {
        "input_kind": "cti_marker",
        "connector_id": "abusech_urlhaus",
        "status": "accepted_local_marker",
        "markers": ("urlhaus",),
        "next_action": "forge connectors import-cti --connector abusech_urlhaus --report-file <path> --dry-run --json",
    },
    {
        "input_kind": "cti_marker",
        "connector_id": "misp_event_import",
        "status": "accepted_local_marker",
        "markers": ("misp",),
        "next_action": "forge connectors import-cti --connector misp_event_import --report-file <path> --dry-run --json",
    },
    {
        "input_kind": "cti_marker",
        "connector_id": "stix_taxii_import",
        "status": "accepted_local_marker",
        "markers": ("stix", "taxii"),
        "next_action": "forge connectors import-cti --connector stix_taxii_import --report-file <path> --dry-run --json",
    },
    {
        "input_kind": "discovery_artifact",
        "connector_id": "projectdiscovery_cloud",
        "status": "pending_local_import",
        "markers": ("projectdiscovery", "pd-cloud", "pd_cloud", "nuclei-cloud"),
        "next_action": "forge connectors import-discovery --connector projectdiscovery_cloud --report-file <path> --json",
    },
    {
        "input_kind": "discovery_artifact",
        "connector_id": "asset_delta_import",
        "status": "pending_local_import",
        "markers": ("asset-delta", "asset_delta", "asset delta"),
        "next_action": "forge connectors import-discovery --connector asset_delta_import --report-file <path> --json",
    },
    {
        "input_kind": "discovery_artifact",
        "connector_id": "runzero_asset_export",
        "status": "pending_local_import",
        "markers": ("runzero", "run0", "rumble"),
        "next_action": "forge connectors import-discovery --connector runzero_asset_export --report-file <path> --json",
    },
    {
        "input_kind": "discovery_artifact",
        "connector_id": "censys_lookup",
        "status": "pending_local_import",
        "markers": ("censys",),
        "next_action": "forge connectors import-discovery --connector censys_lookup --report-file <path> --json",
    },
    {
        "input_kind": "validation_artifact",
        "connector_id": "burp_dast_xml",
        "status": "pending_local_import",
        "markers": ("burp", "junit", "dast", "zap"),
        "next_action": "forge connectors import-validation --connector burp_dast_xml --report-file <path> --dry-run --json",
    },
)


@dataclass(frozen=True)
class FeedCandidate:
    target_type: str
    target_value: str
    canonical_value: str
    source_kind: str
    source_group: str
    confidence: float
    first_seen_at: str
    provenance: str


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _candidate(
    raw_value: str,
    *,
    source_kind: str,
    source_group: str,
    provenance: str,
    confidence: float,
    first_seen_at: str,
) -> FeedCandidate | None:
    value = str(raw_value or "").strip()
    if not value or len(value) > 300:
        return None
    try:
        normalized = _normalize_target_value("auto", value)
    except ValueError:
        return None
    if normalized is None:
        return None
    target_type, canonical_value = normalized
    return FeedCandidate(
        target_type=target_type,
        target_value=value,
        canonical_value=canonical_value,
        source_kind=source_kind,
        source_group=source_group,
        confidence=confidence,
        first_seen_at=first_seen_at,
        provenance=provenance,
    )


def _iter_json_strings(
    value: object,
    key_hint: str = "",
    depth: int = 0,
) -> Iterator[tuple[str, str]]:
    """Yield (key_hint, string_value) pairs from decoded JSON, bounded.

    The nearest ancestor object key is carried through nested dicts and lists
    so values under allowlisted keys such as "hosts" or "urls" keep their hint.
    """
    if depth > _MAX_WALK_DEPTH:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and key.strip():
                child_hint = key.strip().lower()
            else:
                child_hint = key_hint
            yield from _iter_json_strings(item, child_hint, depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_json_strings(item, key_hint, depth + 1)
    elif isinstance(value, str):
        yield key_hint, value


def _load_json_file(path: Path) -> tuple[object | None, str | None]:
    try:
        if path.stat().st_size > _MAX_JSON_FILE_BYTES:
            return None, f"file_too_large:{path.name}"
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, ValueError) as exc:
        return None, f"{type(exc).__name__}:{path.name}"


def _harvest_json_candidates(
    payload: object,
    *,
    source_kind: str,
    source_group: str,
    provenance: str,
    first_seen_at: str,
    confidence: float,
) -> list[FeedCandidate]:
    candidates: list[FeedCandidate] = []
    for key_hint, text in _iter_json_strings(payload):
        if len(candidates) >= _MAX_VALUES_PER_FILE:
            break
        if key_hint and key_hint not in _HARVEST_KEYS:
            continue
        candidate = _candidate(
            text,
            source_kind=source_kind,
            source_group=source_group,
            provenance=provenance,
            confidence=confidence,
            first_seen_at=first_seen_at,
        )
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def _extract_db_source(
    data_dir: Path, first_seen_at: str
) -> tuple[list[FeedCandidate], list[str]]:
    candidates: list[FeedCandidate] = []
    errors: list[str] = []
    db_paths = numeric_engagement_db_files(data_dir)[:_MAX_ENGAGEMENT_DBS]
    for db_path in db_paths:
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            try:
                rows = conn.execute(
                    "SELECT engagement_id, seed_value, seed_type"
                    " FROM engagement_seeds ORDER BY id"
                ).fetchall()
            finally:
                conn.close()
        except sqlite3.Error as exc:
            errors.append(f"db_error:{db_path.name}:{type(exc).__name__}")
            continue
        for engagement_id, seed_value, seed_type in rows:
            seed_text = str(seed_value or "").strip()
            if not seed_text:
                continue
            provenance = f"engagement:{engagement_id}"
            candidate = _candidate(
                seed_text,
                source_kind="db_seed",
                source_group="db",
                provenance=provenance,
                confidence=0.9,
                first_seen_at=first_seen_at,
            )
            if candidate is None:
                candidate = _typed_candidate(
                    str(seed_type), seed_text, engagement_id, first_seen_at
                )
            if candidate is not None:
                candidates.append(candidate)
    return candidates, errors


def _typed_candidate(
    seed_type: str, value: str, engagement_id: object, first_seen_at: str
) -> FeedCandidate | None:
    try:
        normalized = _normalize_target_value(seed_type, value)
    except ValueError:
        return None
    if normalized is None:
        return None
    target_type, canonical_value = normalized
    return FeedCandidate(
        target_type=target_type,
        target_value=value,
        canonical_value=canonical_value,
        source_kind="db_seed",
        source_group="db",
        confidence=0.9,
        first_seen_at=first_seen_at,
        provenance=f"engagement:{engagement_id}",
    )


def _extract_reports_source(
    reports_dir: Path, first_seen_at: str
) -> tuple[list[FeedCandidate], list[str]]:
    candidates: list[FeedCandidate] = []
    errors: list[str] = []
    scan_dirs = [
        reports_dir / "dashboard" / "data",
        reports_dir,
    ]
    seen_files: set[Path] = set()
    scanned = 0
    for scan_dir in scan_dirs:
        if not scan_dir.is_dir():
            continue
        for path in sorted(scan_dir.glob("*.json")):
            if scanned >= _MAX_REPORT_FILES:
                return candidates, errors
            resolved = path.resolve()
            if resolved in seen_files:
                continue
            seen_files.add(resolved)
            scanned += 1
            payload, error = _load_json_file(path)
            if error is not None:
                errors.append(f"reports_parse:{error}")
                continue
            family_id = path.stem
            source_kind = (
                "report_dashboard" if path.parent.name == "data" else "report_metadata"
            )
            candidates.extend(
                _harvest_json_candidates(
                    payload,
                    source_kind=source_kind,
                    source_group=f"report_family:{family_id}",
                    provenance=f"report_family:{family_id}",
                    first_seen_at=first_seen_at,
                    confidence=0.6,
                )
            )
    return candidates, errors


def _extract_dir_source(
    imports_dir: Path,
    *,
    filename_filter,
    source_kind: str,
    provenance_prefix: str,
    first_seen_at: str,
    confidence: float,
) -> tuple[list[FeedCandidate], list[str]]:
    candidates: list[FeedCandidate] = []
    errors: list[str] = []
    if not imports_dir.is_dir():
        return candidates, errors
    scanned = 0
    for path in sorted(imports_dir.glob("*.json")):
        if scanned >= _MAX_FILES_PER_DIR_SOURCE:
            break
        if not filename_filter(path.name):
            continue
        scanned += 1
        payload, error = _load_json_file(path)
        if error is not None:
            errors.append(f"{source_kind}_parse:{error}")
            continue
        candidates.extend(
            _harvest_json_candidates(
                payload,
                source_kind=source_kind,
                source_group=f"{provenance_prefix}{path.name}",
                provenance=f"{provenance_prefix}{path.name}",
                first_seen_at=first_seen_at,
                confidence=confidence,
            )
        )
    return candidates, errors


def _all_candidate_keys(groups: dict[str, list[FeedCandidate]]) -> set[str]:
    keys: set[str] = set()
    for candidates in groups.values():
        for candidate in candidates:
            keys.add(
                external_target_key(candidate.target_type, candidate.canonical_value)
            )
    return keys


def _supabase_config_path(config_path: Path | None) -> Path:
    return Path(config_path or _DEFAULT_SUPABASE_CONFIG)


def _discovered_inputs_registry_path(imports_dir: Path | None = None) -> Path:
    if imports_dir is not None:
        return Path(imports_dir) / _DEFAULT_DISCOVERED_INPUTS_REGISTRY.name
    return _DEFAULT_DISCOVERED_INPUTS_REGISTRY


def _specific_input_registry_path(
    connector_id: str, imports_dir: Path | None = None
) -> Path | None:
    filename = _SPECIFIC_INPUT_REGISTRY_FILENAMES.get(connector_id)
    if filename is None:
        return None
    return Path(imports_dir or "imports") / filename


def _supabase_key_env(project_ref: str) -> str:
    normalized = re.sub(r"[^A-Z0-9]+", "_", project_ref.upper()).strip("_")
    return f"FORGE_SUPABASE_{normalized}_READ_KEY"


def _existing_supabase_project_refs(config_path: Path | None) -> set[str]:
    path = _supabase_config_path(config_path)
    payload, error = _load_json_file(path) if path.is_file() else ({}, None)
    if error is not None or not isinstance(payload, dict):
        return set()
    refs: set[str] = set()
    raw_projects = payload.get("projects")
    if not isinstance(raw_projects, list):
        return refs
    for project in raw_projects:
        if not isinstance(project, dict):
            continue
        project_ref = str(project.get("project_ref") or "").strip().lower()
        if project_ref:
            refs.add(project_ref)
            continue
        url = str(project.get("url") or "").strip()
        match = _SUPABASE_PROJECT_REF_RE.search(url)
        if match:
            refs.add(match.group(1).lower())
    return refs


def _discovered_supabase_project_refs(
    groups: dict[str, list[FeedCandidate]],
) -> list[dict[str, str]]:
    discovered: dict[str, set[str]] = {}
    for source_name in _OFFLINE_SOURCES:
        for candidate in groups.get(source_name, []):
            haystack = " ".join(
                [
                    candidate.target_value,
                    candidate.canonical_value,
                    candidate.provenance,
                ]
            )
            for match in _SUPABASE_PROJECT_REF_RE.finditer(haystack):
                ref = match.group(1).lower()
                discovered.setdefault(ref, set()).add(candidate.source_group)
    return [
        {
            "project_ref": ref,
            "key_env": _supabase_key_env(ref),
            "source_groups": ",".join(sorted(source_groups))[:500],
        }
        for ref, source_groups in sorted(discovered.items())
    ]


def _input_registry_key(item: dict[str, object]) -> str:
    parts = [
        str(item.get("input_kind") or "").strip().lower(),
        str(item.get("connector_id") or "").strip().lower(),
        str(item.get("value") or item.get("project_ref") or "").strip().lower(),
    ]
    return "|".join(parts)


def _existing_discovered_input_keys(imports_dir: Path | None = None) -> set[str]:
    registry_path = _discovered_inputs_registry_path(imports_dir)
    payload, error = _load_json_file(registry_path) if registry_path.is_file() else ({}, None)
    if error is not None or not isinstance(payload, dict):
        return set()
    raw_inputs = payload.get("inputs")
    if not isinstance(raw_inputs, list):
        return set()
    keys: set[str] = set()
    for item in raw_inputs:
        if isinstance(item, dict):
            key = _input_registry_key(item)
            if key.strip("|"):
                keys.add(key)
    return keys


def _input_marker_hits(haystack: str) -> list[dict[str, object]]:
    lowered = haystack.lower()
    return [
        marker
        for marker in _DISCOVERABLE_INPUT_MARKERS
        if any(str(raw_marker).lower() in lowered for raw_marker in marker["markers"])
    ]


def _add_discovered_input(
    discovered: dict[str, dict[str, object]],
    *,
    input_kind: str,
    connector_id: str,
    value: str,
    status: str,
    source_group: str,
    next_action: str,
) -> None:
    entry = {
        "input_kind": input_kind,
        "connector_id": connector_id,
        "value": value,
        "status": status,
        "source_groups": [source_group],
        "next_action": next_action,
    }
    key = _input_registry_key(entry)
    existing = discovered.get(key)
    if existing is None:
        discovered[key] = entry
        return
    source_groups = set(str(group) for group in existing.get("source_groups", []))
    if source_group:
        source_groups.add(source_group)
    existing["source_groups"] = sorted(source_groups)


def _discover_input_registry_items(
    *,
    groups: dict[str, list[FeedCandidate]],
    discovered_supabase_projects: list[dict[str, str]],
    imports_dir: Path | None,
) -> list[dict[str, object]]:
    discovered: dict[str, dict[str, object]] = {}
    for project in discovered_supabase_projects:
        _add_discovered_input(
            discovered,
            input_kind="supabase_project",
            connector_id="supabase_table_import",
            value=str(project["project_ref"]),
            status="pending_key",
            source_group=str(project.get("source_groups") or ""),
            next_action=(
                "set "
                f"{project['key_env']} locally, then run "
                "forge automation feed-build --source supabase --apply --json"
            ),
        )
    for source_name in _OFFLINE_SOURCES:
        for candidate in groups.get(source_name, []):
            if not candidate.source_group.startswith(("cti_file:", "connector_file:")):
                continue
            haystack = " ".join(
                [
                    candidate.target_value,
                    candidate.canonical_value,
                    candidate.provenance,
                    candidate.source_group,
                ]
            )
            for marker in _input_marker_hits(haystack):
                value = str(marker["connector_id"])
                if ":" in candidate.source_group:
                    value = candidate.source_group.split(":", 1)[1]
                _add_discovered_input(
                    discovered,
                    input_kind=str(marker["input_kind"]),
                    connector_id=str(marker["connector_id"]),
                    value=value,
                    status=str(marker["status"]),
                    source_group=candidate.source_group,
                    next_action=str(marker["next_action"]),
                )
    root = imports_dir or Path("imports")
    if root.is_dir():
        scanned = 0
        for path in sorted(root.iterdir()):
            if scanned >= _MAX_FILES_PER_DIR_SOURCE:
                break
            if not path.is_file():
                continue
            if path.name.lower().endswith("-inputs.local.json"):
                continue
            scanned += 1
            haystack = f"{path.name} {path.suffix}"
            for marker in _input_marker_hits(haystack):
                _add_discovered_input(
                    discovered,
                    input_kind=str(marker["input_kind"]),
                    connector_id=str(marker["connector_id"]),
                    value=path.name,
                    status=str(marker["status"]),
                    source_group=f"import_file:{path.name}",
                    next_action=str(marker["next_action"]),
                )
    return [
        {
            **item,
            "source_groups": sorted(str(group) for group in item.get("source_groups", [])),
        }
        for item in sorted(discovered.values(), key=_input_registry_key)
    ]


def _append_discovered_input_registry_items(
    *,
    discovered_inputs: list[dict[str, object]],
    existing_keys: set[str],
    imports_dir: Path | None,
) -> list[dict[str, object]]:
    pending = [
        item
        for item in discovered_inputs
        if _input_registry_key(item) not in existing_keys
    ]
    if not pending:
        return []
    path = _discovered_inputs_registry_path(imports_dir)
    if path.is_file():
        payload, error = _load_json_file(path)
        if error is not None or not isinstance(payload, dict):
            payload = {}
    else:
        payload = {}
    raw_inputs = payload.get("inputs")
    if not isinstance(raw_inputs, list):
        raw_inputs = []
    known = set(existing_keys)
    appended: list[dict[str, object]] = []
    for item in pending:
        key = _input_registry_key(item)
        if not key.strip("|") or key in known:
            continue
        entry = dict(item)
        entry["first_seen_at"] = _now_iso()
        raw_inputs.append(entry)
        appended.append(item)
        known.add(key)
    payload["schema_version"] = "forge.discovered_inputs.v1"
    payload["updated_at"] = _now_iso()
    payload["inputs"] = raw_inputs
    payload.setdefault(
        "_instructions",
        (
            "Local no-secret registry maintained by feed-build --apply. "
            "Free/local artifact inputs can be imported directly; keyed/live "
            "inputs remain pending until local credentials exist."
        ),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=".discovered-inputs-", suffix=".tmp"
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
    return appended


def _append_specific_input_registry_items(
    *,
    appended_inputs: list[dict[str, object]],
    imports_dir: Path | None,
) -> list[dict[str, object]]:
    updates: list[dict[str, object]] = []
    by_path: dict[Path, list[dict[str, object]]] = {}
    for item in appended_inputs:
        connector_id = str(item.get("connector_id") or "").strip()
        path = _specific_input_registry_path(connector_id, imports_dir)
        if path is None:
            continue
        by_path.setdefault(path, []).append(item)
    for path, items in sorted(by_path.items(), key=lambda pair: str(pair[0])):
        if path.is_file():
            payload, error = _load_json_file(path)
            if error is not None or not isinstance(payload, dict):
                payload = {}
        else:
            payload = {}
        raw_inputs = payload.get("inputs")
        if not isinstance(raw_inputs, list):
            raw_inputs = []
        default_connector_id = str(items[0].get("connector_id") or "")
        default_input_kind = str(items[0].get("input_kind") or "")
        existing_keys = {
            _input_registry_key(
                {
                    **item,
                    "connector_id": item.get("connector_id") or default_connector_id,
                    "input_kind": item.get("input_kind") or default_input_kind,
                }
            )
            for item in raw_inputs
            if isinstance(item, dict)
        }
        written = 0
        for item in items:
            key = _input_registry_key(item)
            if not key.strip("|") or key in existing_keys:
                continue
            entry = dict(item)
            entry["first_seen_at"] = _now_iso()
            raw_inputs.append(entry)
            existing_keys.add(key)
            written += 1
        if not written:
            updates.append(
                {
                    "config_path": str(path),
                    "applied": True,
                    "appended_count": 0,
                    "pending_count": 0,
                }
            )
            continue
        payload["schema_version"] = "forge.source_inputs.v1"
        payload["updated_at"] = _now_iso()
        payload["connector_id"] = default_connector_id
        payload["input_kind"] = default_input_kind
        payload["inputs"] = raw_inputs
        payload.setdefault(
            "_instructions",
            (
                "Source-specific local input queue maintained by "
                "feed-build --apply. Values are references to local/free "
                "artifact inputs or pending keyed sources; no secrets belong here."
            ),
        )
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
        updates.append(
            {
                "config_path": str(path),
                "applied": True,
                "appended_count": written,
                "pending_count": 0,
            }
        )
    return updates


def _specific_input_registry_update_plan(
    *,
    pending_inputs: list[dict[str, object]],
    imports_dir: Path | None,
) -> list[dict[str, object]]:
    counts: dict[Path, int] = {}
    for item in pending_inputs:
        connector_id = str(item.get("connector_id") or "").strip()
        path = _specific_input_registry_path(connector_id, imports_dir)
        if path is None:
            continue
        counts[path] = counts.get(path, 0) + 1
    return [
        {
            "config_path": str(path),
            "applied": False,
            "appended_count": 0,
            "pending_count": count,
        }
        for path, count in sorted(counts.items(), key=lambda pair: str(pair[0]))
    ]


def _append_discovered_supabase_projects(
    *,
    config_path: Path | None,
    discovered_projects: list[dict[str, str]],
    existing_refs: set[str],
) -> list[dict[str, str]]:
    pending = [
        project
        for project in discovered_projects
        if str(project["project_ref"]).lower() not in existing_refs
    ]
    if not pending:
        return []
    path = _supabase_config_path(config_path)
    if path.is_file():
        payload, error = _load_json_file(path)
        if error is not None or not isinstance(payload, dict):
            payload = {}
    else:
        payload = {}
    raw_projects = payload.get("projects")
    if not isinstance(raw_projects, list):
        raw_projects = []
    known_refs = set(existing_refs)
    appended: list[dict[str, str]] = []
    for project in pending:
        project_ref = str(project["project_ref"]).lower()
        if project_ref in known_refs:
            continue
        entry = {
            "project_ref": project_ref,
            "key_env": project["key_env"],
            "limit": _MAX_SUPABASE_TABLE_ROWS,
            "status": "pending_key",
            "discovered_from": project.get("source_groups", ""),
        }
        raw_projects.append(entry)
        appended.append(
            {
                "project_ref": project_ref,
                "key_env": project["key_env"],
                "status": "pending_key",
            }
        )
        known_refs.add(project_ref)
    payload["projects"] = raw_projects
    payload.setdefault(
        "_instructions",
        (
            "Add owned read-only Supabase project entries to projects. Entries "
            "discovered from artifacts are pending until key_env is set locally."
        ),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=".supabase-projects-", suffix=".tmp"
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
    return appended


def _merge_candidates(
    groups: dict[str, list[FeedCandidate]],
    existing_items: list[dict[str, object]] | None = None,
) -> tuple[list[dict[str, object]], dict[str, int]]:
    merged: dict[str, dict[str, object]] = {}
    duplicates = 0
    for raw in existing_items or []:
        key = str(raw.get("target_key") or "")
        if key and key not in merged:
            merged[key] = dict(raw)
    for source_name in SUPPORTED_SOURCES:
        for candidate in groups.get(source_name, []):
            key = external_target_key(candidate.target_type, candidate.canonical_value)
            existing = merged.get(key)
            if existing is None:
                merged[key] = {
                    "target_type": candidate.target_type,
                    "target_value": candidate.target_value,
                    "canonical_value": candidate.canonical_value,
                    "target_key": key,
                    "source_kind": candidate.source_kind,
                    "source_group": candidate.source_group,
                    "confidence": candidate.confidence,
                    "first_seen_at": candidate.first_seen_at,
                    "provenance": candidate.provenance,
                }
                continue
            duplicates += 1
            prior_confidence = float(existing["confidence"])  # type: ignore[arg-type]
            if candidate.confidence > prior_confidence:
                existing["source_kind"] = candidate.source_kind
                existing["source_group"] = candidate.source_group
                existing["confidence"] = candidate.confidence
                existing["target_value"] = candidate.target_value
            prior_provenance = str(existing["provenance"])
            if candidate.provenance not in prior_provenance.split("|"):
                combined = f"{prior_provenance}|{candidate.provenance}"
                existing["provenance"] = combined[:240]
    items = [merged[key] for key in sorted(merged)]
    return items, {"omitted_duplicate": duplicates}


def _load_supabase_projects_config(
    config_path: Path | None,
) -> tuple[list[dict[str, Any]], list[str]]:
    path = Path(config_path or _DEFAULT_SUPABASE_CONFIG)
    if not path.is_file():
        return [], ["not_configured:local_config_file_missing"]
    payload, error = _load_json_file(path)
    if error is not None:
        return [], [f"config_parse:{error}"]
    if not isinstance(payload, dict):
        return [], ["config_invalid:root_not_object"]
    raw_projects = payload.get("projects")
    if not isinstance(raw_projects, list):
        return [], ["config_invalid:projects_not_list"]

    projects: list[dict[str, Any]] = []
    errors: list[str] = []
    for index, raw_project in enumerate(raw_projects):
        if not isinstance(raw_project, dict):
            errors.append(f"project_invalid:{index}:not_object")
            continue
        project_ref = str(raw_project.get("project_ref") or "").strip()
        url = str(raw_project.get("url") or "").strip().rstrip("/")
        if not url and project_ref:
            url = f"https://{project_ref}.supabase.co"
        key_env = str(raw_project.get("key_env") or "").strip()
        key_secret_ref = str(raw_project.get("key_secret_ref") or "").strip()
        tables = _string_list(raw_project.get("tables")) or ["*"]
        target_columns = _string_list(raw_project.get("target_columns")) or ["*"]
        limit = _coerce_supabase_limit(raw_project.get("limit"))
        label = project_ref or str(index)
        if not url.startswith("https://") or ".supabase." not in url:
            errors.append(f"project_invalid:{label}:url")
            continue
        if not tables:
            errors.append(f"project_invalid:{label}:tables")
            continue
        if not key_env and not key_secret_ref:
            errors.append(f"project_invalid:{label}:key_env")
            continue
        projects.append(
            {
                "project_ref": project_ref or url.split("//", 1)[-1].split(".", 1)[0],
                "url": url,
                "key_env": key_env,
                "key_secret_ref": key_secret_ref,
                "tables": tables,
                "target_columns": target_columns,
                "limit": limit,
            }
        )
    return projects, errors


def _string_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _coerce_supabase_limit(value: object) -> int:
    if isinstance(value, str) and value.strip().lower() in {"all", "max", "*"}:
        return _MAX_SUPABASE_TABLE_ROWS
    try:
        limit = int(value) if value is not None else _MAX_SUPABASE_TABLE_ROWS
    except (TypeError, ValueError):
        return _MAX_SUPABASE_TABLE_ROWS
    if limit <= 0:
        return _MAX_SUPABASE_TABLE_ROWS
    return min(limit, _MAX_SUPABASE_TABLE_ROWS)


def _parse_secret_ref(ref: str) -> dict[str, Any] | None:
    prefix = "forge-secret://"
    if not ref.startswith(prefix):
        return None
    parts = [part for part in ref[len(prefix) :].split("/") if part]
    if len(parts) != 3:
        return None
    try:
        engagement_id = int(parts[0])
    except ValueError:
        return None
    return {
        "engagement_id": engagement_id,
        "connector_id": parts[1],
        "secret_name": parts[2],
    }


def _resolve_supabase_key(
    project: dict[str, Any],
    *,
    config: ForgeConfig | None = None,
) -> str:
    key_env = str(project.get("key_env") or "").strip()
    if key_env:
        key_value = os.environ.get(key_env, "")
        if not key_value.strip():
            raise ValueError(f"key_env_unset:{key_env}")
        return key_value.strip()

    parsed = _parse_secret_ref(str(project.get("key_secret_ref") or "").strip())
    if parsed is None:
        raise ValueError("secret_ref_invalid")
    cfg = config or ForgeConfig.load()
    with get_engagement_db(parsed["engagement_id"], config=cfg) as con:
        key_value = resolve_connector_secret_value(
            con,
            engagement_id=parsed["engagement_id"],
            connector_id=parsed["connector_id"],
            secret_name=parsed["secret_name"],
        )
    if not key_value.strip():
        raise ValueError("secret_ref_empty")
    return key_value.strip()


def _safe_supabase_identifier(value: str) -> bool:
    return bool(value) and all(
        part.replace("_", "").isalnum() for part in value.split(".")
    )


def _is_connector_payload_filename(name: str) -> bool:
    lowered = name.lower()
    if lowered.endswith(".local.json"):
        return False
    if lowered in _CONNECTOR_SOURCE_EXCLUDED_NAMES:
        return False
    return not any(marker in lowered for marker in _CTI_FILENAME_MARKERS)


def _is_cti_payload_filename(name: str) -> bool:
    lowered = name.lower()
    if lowered.endswith("-inputs.local.json"):
        return False
    if lowered in _CONNECTOR_SOURCE_EXCLUDED_NAMES:
        return False
    return any(marker in lowered for marker in _CTI_FILENAME_MARKERS)


def _wants_all_supabase_tables(tables: list[str]) -> bool:
    return any(str(table).strip() == "*" for table in tables)


def _wants_all_supabase_columns(columns: list[str]) -> bool:
    return any(str(column).strip() == "*" for column in columns)


def _discover_supabase_tables(
    project: dict[str, Any],
    headers: dict[str, str],
) -> tuple[list[str], list[str]]:
    url = f"{project['url']}/rest/v1/"
    discovery_headers = dict(headers)
    discovery_headers["Accept"] = "application/openapi+json, application/json"
    try:
        response = httpx.get(url, headers=discovery_headers, timeout=15.0)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:  # noqa: BLE001
        return [], [f"{project['project_ref']}:discover_tables:http_{type(exc).__name__}"]
    if not isinstance(payload, dict):
        return [], [f"{project['project_ref']}:discover_tables:response_not_object"]
    paths = payload.get("paths")
    if not isinstance(paths, dict):
        return [], [f"{project['project_ref']}:discover_tables:paths_missing"]
    tables: list[str] = []
    omitted = 0
    for raw_path in sorted(paths):
        path = str(raw_path or "").strip("/")
        if not path or path.startswith("rpc/") or "/" in path:
            continue
        if not _safe_supabase_identifier(path):
            continue
        if len(tables) >= _MAX_SUPABASE_DISCOVERED_TABLES:
            omitted += 1
            continue
        tables.append(path)
    errors: list[str] = []
    if omitted:
        errors.append(
            f"{project['project_ref']}:discover_tables:omitted_after_"
            f"{_MAX_SUPABASE_DISCOVERED_TABLES}:{omitted}"
        )
    if not tables:
        errors.append(f"{project['project_ref']}:discover_tables:none")
    return tables, errors


def _supabase_table_rows(
    *,
    project: dict[str, Any],
    headers: dict[str, str],
    table_name: str,
    select_param: str,
) -> tuple[list[dict[str, Any]], list[str], int]:
    row_limit = int(project["limit"])
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    offset = 0
    while offset < row_limit:
        page_size = min(_SUPABASE_PAGE_SIZE, row_limit - offset)
        url = (
            f"{project['url']}/rest/v1/{quote(table_name, safe='')}"
            f"?select={quote(select_param, safe=',*')}"
            f"&limit={page_size}&offset={offset}"
        )
        try:
            response = httpx.get(url, headers=headers, timeout=15.0)
            response.raise_for_status()
            page = response.json()
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{project['project_ref']}:{table_name}:http_{type(exc).__name__}")
            break
        if not isinstance(page, list):
            errors.append(f"{project['project_ref']}:{table_name}:response_not_list")
            break
        dict_rows = [row for row in page if isinstance(row, dict)]
        rows.extend(dict_rows)
        if len(page) < page_size:
            break
        offset += page_size
    if len(rows) >= row_limit:
        errors.append(f"{project['project_ref']}:{table_name}:row_limit_reached:{row_limit}")
    return rows, errors, row_limit


def _harvest_supabase_row(
    row: dict[str, Any],
    *,
    columns: list[str],
    source_group: str,
    first_seen_at: str,
) -> list[FeedCandidate]:
    candidates: list[FeedCandidate] = []
    if _wants_all_supabase_columns(columns):
        for _key_hint, value in _iter_json_strings(row):
            candidate = _candidate(
                value,
                source_kind="supabase_table",
                source_group=source_group,
                provenance=source_group,
                confidence=0.65,
                first_seen_at=first_seen_at,
            )
            if candidate is not None:
                candidates.append(candidate)
        return candidates
    allowed = {column.lower() for column in columns}
    for key, value in row.items():
        key_hint = str(key or "").strip().lower()
        if key_hint not in allowed:
            continue
        values = value if isinstance(value, list) else [value]
        for item in values:
            if not isinstance(item, str):
                continue
            candidate = _candidate(
                item,
                source_kind="supabase_table",
                source_group=source_group,
                provenance=source_group,
                confidence=0.65,
                first_seen_at=first_seen_at,
            )
            if candidate is not None:
                candidates.append(candidate)
    return candidates


def _extract_supabase_source(
    config_path: Path | None,
    first_seen_at: str,
) -> tuple[list[FeedCandidate], list[str], dict[str, int]]:
    projects, errors = _load_supabase_projects_config(config_path)
    candidates: list[FeedCandidate] = []
    source_group_counts: dict[str, int] = {}
    for project in projects:
        project_ref = str(project["project_ref"])
        try:
            key_value = _resolve_supabase_key(project)
        except (LookupError, ValueError) as exc:
            errors.append(f"{project_ref}:{exc}")
            continue
        headers = {
            "apikey": key_value,
            "Authorization": f"Bearer {key_value}",
            "Accept": "application/json",
        }
        raw_tables = list(project["tables"])
        if _wants_all_supabase_tables(raw_tables):
            tables, discovery_errors = _discover_supabase_tables(project, headers)
            errors.extend(discovery_errors)
        else:
            tables = raw_tables
        columns = list(project["target_columns"])
        select_param = "*" if _wants_all_supabase_columns(columns) else ",".join(columns)
        for table in tables:
            table_name = str(table).strip()
            source_group = f"supabase:{project_ref}:{table_name}"
            if not _safe_supabase_identifier(table_name):
                errors.append(f"{project_ref}:{table_name}:invalid_table")
                continue
            rows, row_errors, _row_limit = _supabase_table_rows(
                project=project,
                headers=headers,
                table_name=table_name,
                select_param=select_param,
            )
            errors.extend(row_errors)
            if not rows:
                continue
            row_count = 0
            for row in rows:
                row_count += 1
                candidates.extend(
                    _harvest_supabase_row(
                        row,
                        columns=columns,
                        source_group=source_group,
                        first_seen_at=first_seen_at,
                    )
                )
            source_group_counts[source_group] = row_count
    return candidates, errors, source_group_counts


def build_target_feed(
    *,
    sources: list[str],
    data_dir: Path,
    reports_dir: Path | None,
    imports_dir: Path | None,
    limit: int | None,
    existing_feed_path: Path | None,
    apply: bool = False,
    supabase_config_path: Path | None = None,
) -> dict[str, object]:
    selected_sources = [s.strip().lower() for s in sources if s.strip()]
    if not selected_sources:
        selected_sources = ["all"]
    if "all" in selected_sources:
        selected_sources = list(SUPPORTED_SOURCES)
    invalid_sources = [s for s in selected_sources if s not in SUPPORTED_SOURCES]
    if invalid_sources:
        raise ValueError(f"unsupported source(s): {', '.join(sorted(invalid_sources))}")
    active_offline = [s for s in _OFFLINE_SOURCES if s in selected_sources]
    wants_supabase = "supabase" in selected_sources
    generated_at = _now_iso()

    groups: dict[str, list[FeedCandidate]] = {name: [] for name in SUPPORTED_SOURCES}
    source_group_counts: dict[str, int] = {}
    source_errors: list[dict[str, str]] = []

    if "db" in active_offline:
        found, errors = _extract_db_source(data_dir, generated_at)
        groups["db"] = found
        if found:
            source_group_counts["db"] = len(found)
        source_errors.extend({"source": "db", "error": err} for err in errors)

    if "reports" in active_offline:
        found, errors = _extract_reports_source(reports_dir or Path("reports"), generated_at)
        groups["reports"] = found
        for candidate in found:
            source_group_counts[candidate.source_group] = (
                source_group_counts.get(candidate.source_group, 0) + 1
            )
        source_errors.extend({"source": "reports", "error": err} for err in errors)

    cti_dir = imports_dir
    connectors_dir = imports_dir
    if "cti" in active_offline:
        found, errors = _extract_dir_source(
            cti_dir or Path("imports"),
            filename_filter=_is_cti_payload_filename,
            source_kind="cti_observation",
            provenance_prefix="cti_file:",
            first_seen_at=generated_at,
            confidence=0.5,
        )
        groups["cti"] = found
        for candidate in found:
            source_group_counts[candidate.source_group] = (
                source_group_counts.get(candidate.source_group, 0) + 1
            )
        source_errors.extend({"source": "cti", "error": err} for err in errors)

    if "connectors" in active_offline:
        found, errors = _extract_dir_source(
            connectors_dir or Path("imports"),
            filename_filter=_is_connector_payload_filename,
            source_kind="connector_output",
            provenance_prefix="connector_file:",
            first_seen_at=generated_at,
            confidence=0.5,
        )
        groups["connectors"] = found
        for candidate in found:
            source_group_counts[candidate.source_group] = (
                source_group_counts.get(candidate.source_group, 0) + 1
            )
        source_errors.extend({"source": "connectors", "error": err} for err in errors)

    if wants_supabase:
        found, errors, supabase_group_counts = _extract_supabase_source(
            supabase_config_path, generated_at
        )
        groups["supabase"] = found
        source_group_counts.update(supabase_group_counts)
        source_errors.extend({"source": "supabase", "error": err} for err in errors)

    existing_supabase_refs = _existing_supabase_project_refs(supabase_config_path)
    discovered_supabase_projects = _discovered_supabase_project_refs(groups)
    new_discovered_supabase_projects = [
        project
        for project in discovered_supabase_projects
        if project["project_ref"] not in existing_supabase_refs
    ]
    discovered_inputs = _discover_input_registry_items(
        groups=groups,
        discovered_supabase_projects=discovered_supabase_projects,
        imports_dir=imports_dir,
    )
    existing_input_keys = _existing_discovered_input_keys(imports_dir)
    new_discovered_inputs = [
        item
        for item in discovered_inputs
        if _input_registry_key(item) not in existing_input_keys
    ]
    appended_supabase_projects: list[dict[str, str]] = []
    appended_inputs: list[dict[str, object]] = []
    specific_input_registry_updates: list[dict[str, object]] = []
    if apply and new_discovered_supabase_projects:
        appended_supabase_projects = _append_discovered_supabase_projects(
            config_path=supabase_config_path,
            discovered_projects=discovered_supabase_projects,
            existing_refs=existing_supabase_refs,
        )
    if apply and new_discovered_inputs:
        appended_inputs = _append_discovered_input_registry_items(
            discovered_inputs=discovered_inputs,
            existing_keys=existing_input_keys,
            imports_dir=imports_dir,
        )
        specific_input_registry_updates = _append_specific_input_registry_items(
            appended_inputs=appended_inputs,
            imports_dir=imports_dir,
        )
    elif not apply and new_discovered_inputs:
        specific_input_registry_updates = _specific_input_registry_update_plan(
            pending_inputs=new_discovered_inputs,
            imports_dir=imports_dir,
        )

    existing_items_raw: list[dict[str, object]] = []
    new_vs_existing = 0
    if existing_feed_path is not None and Path(existing_feed_path).is_file():
        try:
            loaded_existing = load_target_feed(
                feed_url=None,
                feed_file=Path(existing_feed_path),
                auth_header_env=None,
                limit=None,
            )
            existing_keys = {item.target_key for item in loaded_existing}
            existing_items_raw = [
                {
                    "target_type": item.target_type,
                    "target_value": item.target_value,
                    "canonical_value": item.canonical_value,
                    "target_key": item.target_key,
                    "source_kind": item.source_kind,
                    "source_group": item.source_group,
                    "confidence": item.confidence,
                    "first_seen_at": item.first_seen_at,
                    "provenance": item.provenance,
                }
                for item in loaded_existing
            ]
            new_vs_existing = sum(
                1 for key in _all_candidate_keys(groups) if key not in existing_keys
            )
        except (OSError, ValueError):
            source_errors.append(
                {"source": "existing_feed", "error": "unreadable_existing_feed"}
            )
    elif existing_feed_path is not None:
        new_vs_existing = len(_all_candidate_keys(groups))

    items, dedupe_counts = _merge_candidates(groups, existing_items_raw)
    total_before_limit = len(items)
    if limit is not None and limit >= 0:
        items = items[:limit]
    omitted_by_limit = total_before_limit - len(items)

    per_group: dict[str, int] = {}
    for source_name in SUPPORTED_SOURCES:
        count = len(groups[source_name])
        if count:
            per_group[source_name] = count
    for candidate_item in items:
        kind = str(candidate_item["source_kind"])
        per_group[kind] = per_group.get(kind, 0) + 1

    counts = {
        "total": len(items),
        "selected": len(items),
        "omitted_duplicate": dedupe_counts["omitted_duplicate"],
        "omitted_by_limit": omitted_by_limit,
        "new_vs_existing": new_vs_existing,
        "by_source": {
            "db": len(groups["db"]),
            "reports": len(groups["reports"]),
            "cti": len(groups["cti"]),
            "connectors": len(groups["connectors"]),
            "supabase": len(groups["supabase"]),
        },
        "by_source_group": dict(sorted(source_group_counts.items())),
        "per_group": dict(sorted(per_group.items())),
    }

    payload: dict[str, object] = {
        "schema_version": TARGET_FEED_SCHEMA_VERSION,
        "execution_policy": (
            "applied_local_write" if apply else "dry_run_no_writes"
        ),
        "dry_run": not apply,
        "apply_requested": bool(apply),
        "sources": selected_sources,
        "generated_at": generated_at,
        "counts": counts,
        "source_errors": source_errors,
        "discovered_supabase_projects": discovered_supabase_projects,
        "new_discovered_supabase_projects": (
            appended_supabase_projects
            if apply
            else new_discovered_supabase_projects
        ),
        "supabase_project_config_update": {
            "config_path": str(_supabase_config_path(supabase_config_path)),
            "applied": bool(apply),
            "appended_count": len(appended_supabase_projects),
            "pending_key_count": len(new_discovered_supabase_projects)
            if not apply
            else len(appended_supabase_projects),
        },
        "discovered_inputs": discovered_inputs,
        "new_discovered_inputs": appended_inputs if apply else new_discovered_inputs,
        "discovered_input_registry_update": {
            "config_path": str(_discovered_inputs_registry_path(imports_dir)),
            "applied": bool(apply),
            "appended_count": len(appended_inputs),
            "pending_count": len(new_discovered_inputs)
            if not apply
            else len(appended_inputs),
        },
        "source_input_registry_updates": specific_input_registry_updates,
        "items": items,
    }
    return payload


def write_target_feed(payload: dict[str, object], output_path: Path) -> None:
    """Atomically persist a feed payload, preserving schema contract."""
    feed_document = {
        "schema_version": TARGET_FEED_SCHEMA_VERSION,
        "generated_at": payload.get("generated_at"),
        "items": payload.get("items", []),
    }
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(output_path.parent), prefix=".target-feed-", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(feed_document, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_name, output_path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
