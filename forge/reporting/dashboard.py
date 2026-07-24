"""Static engagement dashboard + detail pages.

Builds a compact overview page across every engagement and a dedicated
detail page per engagement so the main dashboard stays readable.
"""
from __future__ import annotations

import html
import json
import os
import re
import sqlite3
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from xml.etree import ElementTree

from forge.audit.manifest import summarize_run_audit_manifest
from forge.utils.cloud_exposure_gate import (
    effective_cloud_validation_status,
    is_deterministic_cloud_exposure,
    is_reportable_cloud_validation,
    linked_cloud_validation_reportability,
    latest_cloud_validation_reportability_index,
    normalize_cloud_exposure_asset_type,
)
from forge.utils.validation_proof import parse_validated_detail

GRAPHML_NS = {"g": "http://graphml.graphdrawing.org/xmlns"}
MALTEGO_NS = {"m": "http://maltego.paterva.com/xml/mtgx"}
SECTION_LIMIT = 12
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_GRAPH_FORBIDDEN_METADATA_KEYS = {
    "api_key",
    "apikey",
    "access_token",
    "client_secret",
    "credential",
    "credentials",
    "key_enc",
    "key_raw",
    "password",
    "password_enc",
    "private_key",
    "raw_secret",
    "raw_token",
    "refresh_token",
    "secret",
    "secret_enc",
    "token",
    "token_enc",
}
_SEED_BASE_METADATA_KEYS = {
    "confidence",
    "confidence_band",
    "corroborated",
    "corroborating_seed_count",
    "depth",
    "seed_type",
    "source",
    "status",
    "supporting_relations",
}


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "engagement"


def _format_size(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    size = float(size_bytes)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} {unit}"
        size /= 1024.0
    return f"{size_bytes} B"


def _format_dt(value: str) -> str:
    if not value:
        return ""
    cleaned = value.replace("Z", "+00:00")
    for candidate in (cleaned, cleaned.replace(" ", "T", 1)):
        try:
            dt = datetime.fromisoformat(candidate)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return value


def _timestamp_epoch_ms(value: str) -> int:
    if not value:
        return 0
    cleaned = str(value).replace("Z", "+00:00").strip()
    for candidate in (cleaned, cleaned.replace(" ", "T", 1)):
        try:
            return int(datetime.fromisoformat(candidate).timestamp() * 1000)
        except ValueError:
            continue
    return 0


def _truncate(value: Any, limit: int = 140) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit - 3]}..."


def _safe_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:  # noqa: BLE001
        return None


def _is_sensitive_metadata_key(key: Any) -> bool:
    normalized = str(key or "").strip().lower()
    return (
        not normalized
        or normalized in _GRAPH_FORBIDDEN_METADATA_KEYS
        or normalized.endswith("_enc")
    )


def _safe_graph_metadata_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [_safe_graph_metadata_value(item) for item in value[:50]]
    if isinstance(value, dict):
        return _safe_graph_metadata(value)
    return str(value)


def _safe_graph_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    clean: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        if _is_sensitive_metadata_key(raw_key):
            continue
        key = str(raw_key).strip()
        clean[key] = _safe_graph_metadata_value(raw_value)
    return clean


def _merge_seed_node_metadata(node_metadata: dict[str, Any], raw_metadata: Any) -> None:
    safe_metadata = _safe_graph_metadata(raw_metadata)
    safe_metadata.pop("synthesis", None)
    for key, value in safe_metadata.items():
        output_key = "discovery_source" if key == "source" else key
        if output_key in _SEED_BASE_METADATA_KEYS or output_key in node_metadata:
            output_key = f"metadata_{output_key}"
        node_metadata[output_key] = value


def _normalize_engagement_tags(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        candidates = re.split(r"[\r\n,]+", raw)
    elif isinstance(raw, (list, tuple, set)):
        candidates = list(raw)
    else:
        return []
    tags: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        tag = re.sub(r"\s+", " ", str(item or "")).strip()
        if not tag:
            continue
        dedupe_key = tag.casefold()
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        tags.append(tag[:48])
        if len(tags) >= 12:
            break
    return tags


def _engagement_metadata(con: sqlite3.Connection, engagement_id: int) -> dict[str, Any]:
    if "metadata_json" not in _table_columns(con, "engagements"):
        return {}
    try:
        row = con.execute(
            """
            SELECT metadata_json
            FROM engagements
            WHERE id=?
            """,
            (engagement_id,),
        ).fetchone()
    except sqlite3.OperationalError:
        return {}
    if row is None:
        return {}
    metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
    return metadata if isinstance(metadata, dict) else {}


def _engagement_tags(con: sqlite3.Connection, engagement_id: int) -> list[str]:
    metadata = _engagement_metadata(con, engagement_id)
    return _normalize_engagement_tags(metadata.get("tags"))


def _effective_run_status(status: str, metadata: Any) -> str:
    normalized = str(status or "").strip().lower()
    metadata_dict = metadata if isinstance(metadata, dict) else {}
    if normalized == "running":
        if metadata_dict.get("pause_requested"):
            return "pausing"
        if metadata_dict.get("stop_requested"):
            return "stopping"
        return normalized
    if normalized == "cancelled" and metadata_dict.get("lifecycle_state") == "paused":
        return "paused"
    return normalized


def _run_policy_summary(metadata: Any, *, dry_run: bool, attack_mode: bool) -> dict[str, Any]:
    metadata_dict = metadata if isinstance(metadata, dict) else {}
    policy = metadata_dict.get("live_execution_policy")
    policy_dict = policy if isinstance(policy, dict) else {}
    live_default = not dry_run
    roe_id = str(policy_dict.get("roe_id") or metadata_dict.get("roe_id") or "").strip()
    requires_roe = bool(policy_dict.get("requires_explicit_roe", attack_mode))
    return {
        "roe_id": roe_id,
        "roe_present": bool(policy_dict.get("roe_present", bool(roe_id))),
        "roe_missing": bool(policy_dict.get("roe_missing", requires_roe and not roe_id)),
        "live_probing_allowed": bool(
            policy_dict.get("live_probing_allowed", metadata_dict.get("live_probing_allowed", live_default))
        ),
        "tool_execution_allowed": bool(
            policy_dict.get("tool_execution_allowed", metadata_dict.get("tool_execution_allowed", live_default))
        ),
        "active_recon_allowed": bool(policy_dict.get("active_recon_allowed", attack_mode and live_default)),
        "credential_validation_allowed": bool(
            policy_dict.get("credential_validation_allowed", attack_mode and live_default)
        ),
        "destructive_actions_allowed": bool(policy_dict.get("destructive_actions_allowed", False)),
        "post_exploitation_allowed": bool(policy_dict.get("post_exploitation_allowed", False)),
        "requires_explicit_roe": requires_roe,
        "scope_gate": str(policy_dict.get("scope_gate") or "engagement_scope_json_root_domains"),
    }


def _preview_json(value: Any, limit: int = 180) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        parsed = _safe_json_loads(value)
        if parsed is None:
            return _truncate(value, limit)
        value = parsed
    if isinstance(value, dict):
        keys = ", ".join(sorted(str(k) for k in value.keys())[:8])
        return _truncate(keys or json.dumps(value, ensure_ascii=False), limit)
    if isinstance(value, list):
        preview = ", ".join(_truncate(item, 36) for item in value[:6])
        return _truncate(preview, limit)
    return _truncate(value, limit)


def _crawl_source_summary(value: Any) -> str:
    parsed = _safe_json_loads(value) if isinstance(value, str) else value
    if not isinstance(parsed, dict):
        return ""
    sources: list[str] = []
    for key in ("archive_sources", "provider_sources"):
        raw_sources = parsed.get(key)
        if not isinstance(raw_sources, list):
            continue
        for raw_source in raw_sources:
            source = str(raw_source or "").strip()
            if source and source not in sources:
                sources.append(source)
    if sources:
        return ", ".join(sources)
    return str(parsed.get("discovered_from") or "").strip()


def _connect_readonly(db_path: Path) -> sqlite3.Connection | None:
    try:
        con = sqlite3.connect(
            f"file:{db_path.as_posix()}?mode=ro",
            uri=True,
            timeout=2.0,
        )
    except sqlite3.OperationalError:
        return None
    con.row_factory = sqlite3.Row
    return con


def _table_columns(con: sqlite3.Connection, table_name: str) -> set[str]:
    try:
        rows = con.execute(f"PRAGMA table_info({table_name})").fetchall()
    except sqlite3.OperationalError:
        return set()
    return {str(row["name"]) if "name" in row.keys() else str(row[1]) for row in rows}


def _table_exists(con: sqlite3.Connection, table_name: str) -> bool:
    return bool(_table_columns(con, table_name))


def _fetch_rows(
    con: sqlite3.Connection,
    sql: str,
    params: tuple[Any, ...],
) -> list[sqlite3.Row]:
    try:
        return con.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []


def _fetch_count(
    con: sqlite3.Connection,
    sql: str,
    params: tuple[Any, ...],
) -> int:
    try:
        row = con.execute(sql, params).fetchone()
    except sqlite3.OperationalError:
        return 0
    if row is None:
        return 0
    return int(row[0] or 0)


def _host_identity_key(hostname: str, ip: str) -> str:
    normalized_host = str(hostname or "").strip().lower()
    normalized_ip = str(ip or "").strip().lower()
    if normalized_host and normalized_host != normalized_ip:
        return f"host:{normalized_host}"
    if normalized_ip:
        return f"ip:{normalized_ip}"
    return ""


def _seed_host_candidates(
    con: sqlite3.Connection,
    engagement_id: int,
) -> list[dict[str, str]]:
    if not _table_exists(con, "engagement_seeds"):
        return []
    rows = _fetch_rows(
        con,
        """
        SELECT seed_value, seed_type, source, status, discovered_at, updated_at
        FROM engagement_seeds
        WHERE engagement_id=?
          AND seed_type IN ('domain', 'subdomain')
          AND COALESCE(status, 'pending') != 'failed'
        ORDER BY depth ASC, id DESC
        """,
        (engagement_id,),
    )
    candidates: list[dict[str, str]] = []
    for row in rows:
        seed_value = str(row["seed_value"] or "").strip().lower()
        if not seed_value or "." not in seed_value:
            continue
        candidates.append(
            {
                "hostname": seed_value,
                "ip": "",
                "os_family": "",
                "discovered_at": str(row["updated_at"] or row["discovered_at"] or ""),
                "source": str(row["source"] or ""),
            }
        )
    return [
        candidate
        for candidate in candidates
        if str(candidate["source"] or "").strip().lower() not in {"scope", "operator"}
    ]


def _seed_email_candidates(
    con: sqlite3.Connection,
    engagement_id: int,
) -> list[dict[str, str]]:
    if not _table_exists(con, "engagement_seeds"):
        return []
    rows = _fetch_rows(
        con,
        """
        SELECT seed_value, source, discovered_at, updated_at
        FROM engagement_seeds
        WHERE engagement_id=?
          AND seed_type='email'
          AND COALESCE(status, 'pending') != 'failed'
        ORDER BY depth ASC, id DESC
        """,
        (engagement_id,),
    )
    candidates: list[dict[str, str]] = []
    for row in rows:
        email = str(row["seed_value"] or "").strip().lower()
        if "@" not in email:
            continue
        candidates.append(
            {
                "email": email,
                "domain": email.split("@", 1)[1],
                "source": str(row["source"] or ""),
                "first_seen_at": str(row["updated_at"] or row["discovered_at"] or ""),
            }
        )
    return candidates


def _merged_host_rows(con: sqlite3.Connection, engagement_id: int, *, limit: int | None = None) -> list[dict[str, str]]:
    host_rows = _fetch_rows(
        con,
        """
        SELECT hostname, ip, os_family, discovered_at
        FROM hosts
        WHERE engagement_id=?
        ORDER BY id DESC
        """,
        (engagement_id,),
    )
    merged: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in host_rows:
        item = {
            "hostname": str(row["hostname"] or ""),
            "ip": str(row["ip"] or ""),
            "os_family": str(row["os_family"] or ""),
            "discovered_at": str(row["discovered_at"] or ""),
            "source": "",
        }
        key = _host_identity_key(item["hostname"], item["ip"])
        if not key or key in seen:
            continue
        seen.add(key)
        merged.append(item)
    for candidate in _seed_host_candidates(con, engagement_id):
        key = _host_identity_key(candidate["hostname"], candidate["ip"])
        if not key or key in seen:
            continue
        seen.add(key)
        merged.append(candidate)
    return merged[:limit] if limit is not None else merged


def _merged_email_rows(con: sqlite3.Connection, engagement_id: int, *, limit: int | None = None) -> list[dict[str, str]]:
    email_rows = _fetch_rows(
        con,
        """
        SELECT email, domain, source, first_seen_at
        FROM emails
        WHERE engagement_id=?
        ORDER BY id DESC
        """,
        (engagement_id,),
    )
    merged: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in email_rows:
        item = {
            "email": str(row["email"] or "").lower(),
            "domain": str(row["domain"] or ""),
            "source": str(row["source"] or ""),
            "first_seen_at": str(row["first_seen_at"] or ""),
        }
        if not item["email"] or item["email"] in seen:
            continue
        seen.add(item["email"])
        merged.append(item)
    for candidate in _seed_email_candidates(con, engagement_id):
        if not candidate["email"] or candidate["email"] in seen:
            continue
        seen.add(candidate["email"])
        merged.append(candidate)
    return merged[:limit] if limit is not None else merged


def _reportable_cloud_validation_index(
    con: sqlite3.Connection,
    engagement_id: int,
) -> dict[tuple[str, str], bool]:
    return latest_cloud_validation_reportability_index(
        con,
        engagement_id,
        require_stable_proof=True,
    )


def _validation_asset_types_for_key_service(service: str) -> list[str]:
    normalized = normalize_cloud_exposure_asset_type(service)
    return {
        "amazon": ["aws_s3"],
        "aws": ["aws_s3"],
        "azure": ["azure_blob"],
        "digitalocean": ["do_spaces"],
        "do": ["do_spaces"],
        "firebase": ["firebase"],
        "gcp": ["gcs"],
        "google": ["gcs"],
        "supabase": ["supabase"],
    }.get(normalized, [normalized] if normalized else [])


def _key_validation_detail_is_reportable(value: object) -> bool:
    proof = parse_validated_detail(value)
    return str(proof["validation_status"] or "").strip().upper() == "VALIDATED"


def _key_row_is_reportable(
    row: sqlite3.Row,
    validation_index: dict[tuple[str, str], bool],
) -> bool:
    state = str(row["validation_state"] or "").strip().upper() if "validation_state" in row.keys() else ""
    if state != "ACTIVE":
        return False
    identifier = str(row["domain"] or "").strip().lower() if "domain" in row.keys() else ""
    service = str(row["service"] or "").strip().lower() if "service" in row.keys() else ""
    linked_reportable = linked_cloud_validation_reportability(
        validation_index,
        _validation_asset_types_for_key_service(service),
        identifier,
    )
    if linked_reportable is not None:
        return linked_reportable
    return _key_validation_detail_is_reportable(
        row["validation_detail"] if "validation_detail" in row.keys() else ""
    )


def _reportable_key_scanner_rows(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    limit: int | None = None,
) -> list[sqlite3.Row]:
    columns = _table_columns(con, "key_scanner_findings")
    if not {"engagement_id", "validation_state"}.issubset(columns):
        return []
    select_parts = [
        "validation_state",
        "service" if "service" in columns else "NULL AS service",
        "domain" if "domain" in columns else "NULL AS domain",
        "validation_detail" if "validation_detail" in columns else "NULL AS validation_detail",
    ]
    rows = _fetch_rows(
        con,
        f"""
        SELECT {', '.join(select_parts)}
        FROM key_scanner_findings
        WHERE engagement_id=?
        ORDER BY id DESC
        """,
        (engagement_id,),
    )
    validation_index = _reportable_cloud_validation_index(con, engagement_id)
    reportable = [row for row in rows if _key_row_is_reportable(row, validation_index)]
    return reportable[:limit] if limit is not None else reportable


def _vulnerability_validation_asset(row: sqlite3.Row) -> str:
    provider = str(row["cloud_provider"] or "").strip().lower() if "cloud_provider" in row.keys() else ""
    parameter = str(row["parameter"] or "").strip().lower() if "parameter" in row.keys() else ""
    target_url = str(row["target_url"] or "").strip().lower() if "target_url" in row.keys() else ""
    hint = f"{parameter} {target_url}"
    if provider in {"firebase", "supabase"}:
        return provider
    if provider in {"aws", "amazon"} and ("s3" in hint or "aws_s3" in hint):
        return "aws_s3"
    if provider in {"gcp", "google"} and ("gcs" in hint or "gs://" in hint):
        return "gcs"
    if provider == "azure" and "blob" in hint:
        return "azure_blob"
    if provider in {"digitalocean", "do"} and "space" in hint:
        return "do_spaces"
    for value in (provider, parameter.split(":", 1)[0], urlparse(target_url).scheme):
        normalized = normalize_cloud_exposure_asset_type(value)
        if normalized:
            return normalized
    return ""


def _vulnerability_validation_identifier(row: sqlite3.Row) -> str:
    resource_id = str(row["resource_id"] or "").strip().lower() if "resource_id" in row.keys() else ""
    if resource_id:
        return resource_id
    target_url = str(row["target_url"] or "").strip()
    if target_url:
        parsed = urlparse(target_url)
        identifier = f"{parsed.netloc}/{parsed.path.strip('/')}".strip("/")
        if identifier:
            return identifier.lower()
    return ""


def _vulnerability_row_is_reportable(
    row: sqlite3.Row,
    validation_index: dict[tuple[str, str], bool],
) -> bool:
    vuln_type = str(row["vuln_type"] or "").strip().upper() if "vuln_type" in row.keys() else ""
    title = str(row["title"] or "").strip()
    asset = _vulnerability_validation_asset(row)
    if is_deterministic_cloud_exposure(vuln_type, title, (asset,)):
        identifier = _vulnerability_validation_identifier(row)
        if not asset or not identifier:
            return False
        reportable = validation_index.get((asset, identifier))
        return reportable is True
    if vuln_type == "DETERMINISTIC_KEY_EXPOSURE" or title.lower().startswith("active exposed "):
        identifier = _vulnerability_validation_identifier(row)
        linked_reportable = linked_cloud_validation_reportability(
            validation_index,
            (asset,),
            identifier,
        )
        if linked_reportable is not None:
            return linked_reportable
        proof = parse_validated_detail(str(row["evidence"] or "") if "evidence" in row.keys() else "")
        return str(proof["validation_status"] or "").strip().upper() == "VALIDATED"
    return True


def _reportable_vulnerability_rows(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    limit: int | None = None,
) -> list[sqlite3.Row]:
    columns = _table_columns(con, "vulnerability_findings")
    if not columns:
        return []
    select_parts = [
        "id" if "id" in columns else "NULL AS id",
        "host_id" if "host_id" in columns else "NULL AS host_id",
        "severity" if "severity" in columns else "'INFO' AS severity",
        "vuln_type" if "vuln_type" in columns else "NULL AS vuln_type",
        "title" if "title" in columns else "NULL AS title",
        "target_url" if "target_url" in columns else "NULL AS target_url",
        "parameter" if "parameter" in columns else "NULL AS parameter",
        "evidence" if "evidence" in columns else "NULL AS evidence",
        "cloud_provider" if "cloud_provider" in columns else "NULL AS cloud_provider",
        "resource_id" if "resource_id" in columns else "NULL AS resource_id",
        "found_at" if "found_at" in columns else "NULL AS found_at",
    ]
    rows = _fetch_rows(
        con,
        f"""
        SELECT {', '.join(select_parts)}
        FROM vulnerability_findings
        WHERE engagement_id=?
        ORDER BY id DESC
        """,
        (engagement_id,),
    )
    validation_index = _reportable_cloud_validation_index(con, engagement_id)
    reportable = [
        row for row in rows if _vulnerability_row_is_reportable(row, validation_index)
    ]
    return reportable[:limit] if limit is not None else reportable


def _severity_summary(con: sqlite3.Connection, engagement_id: int) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for row in _reportable_vulnerability_rows(con, engagement_id):
        severity = str(row["severity"] or "INFO").upper()
        if severity not in counts:
            counts[severity] = 0
        counts[severity] += 1
    for row in _fetch_rows(
        con,
        """
        SELECT UPPER(COALESCE(severity, 'INFO')) AS severity, COUNT(*)
        FROM passive_vulns
        WHERE engagement_id=? AND COALESCE(false_positive, 0)=0
        GROUP BY UPPER(COALESCE(severity, 'INFO'))
        """,
        (engagement_id,),
    ):
        severity = str(row["severity"] or "INFO").upper()
        if severity not in counts:
            counts[severity] = 0
        counts[severity] += int(row[1] or 0)
    return counts


def _highest_severity(summary: dict[str, int]) -> str:
    for severity in SEVERITY_ORDER:
        if int(summary.get(severity, 0) or 0) > 0:
            return severity
    return "INFO"


def _severity_summary_text(summary: dict[str, int]) -> str:
    parts = [
        f"{severity[0]}:{int(summary.get(severity, 0) or 0)}"
        for severity in SEVERITY_ORDER
        if int(summary.get(severity, 0) or 0) > 0
    ]
    return " / ".join(parts) if parts else "none"


def _relative_href(source_page: Path, target_path: Path) -> str:
    rel = os.path.relpath(target_path, start=source_page.parent)
    return rel.replace("\\", "/")


def _files_matching(reports_dir: Path, patterns: tuple[str, ...]) -> list[Path]:
    matches: list[Path] = []
    for pattern in patterns:
        matches.extend(reports_dir.glob(pattern))
    return sorted(set(matches), key=lambda path: (path.suffix, path.name.lower()))


def _artifact_files(eng_id: str, reports_dir: Path) -> list[Path]:
    return _files_matching(
        reports_dir,
        (
            f"engagement_{eng_id}*.md",
            f"engagement_{eng_id}*.pdf",
            f"engagement_{eng_id}*.json",
            f"engagement_{eng_id}*.csv",
        ),
    )


def _audit_files(eng_id: str, reports_dir: Path) -> list[Path]:
    return _files_matching(
        reports_dir,
        (
            f"audit_{eng_id}*.md",
            f"audit_{eng_id}*.pdf",
            f"audit_{eng_id}*.json",
            f"audit_{eng_id}*.csv",
        ),
    )


def _materialize_audit_manifest_artifacts(
    con: sqlite3.Connection,
    *,
    db_path: Path,
    reports_dir: Path,
    engagement_id: int,
    verify: bool,
) -> list[Path]:
    existing = _audit_files(str(engagement_id), reports_dir)
    if not _table_exists(con, "run_audit_manifests"):
        return existing
    rows = _fetch_rows(
        con,
        """
        SELECT id, run_id
        FROM run_audit_manifests
        WHERE engagement_id=?
        ORDER BY run_id DESC, id DESC
        """,
        (engagement_id,),
    )
    for row in rows:
        run_id = int(row["run_id"] or 0)
        if run_id <= 0:
            continue
        summary = summarize_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=engagement_id,
            run_id=run_id,
            verify=verify,
        )
        if not summary.get("present"):
            continue
        short_hash = str(summary.get("short_hash") or "unknown")[:12] or "unknown"
        payload = {
            "schema": "forge.run_audit_manifest_summary.v1",
            "engagement_id": int(engagement_id),
            "run_id": run_id,
            **summary,
        }
        artifact_path = reports_dir / f"audit_{engagement_id}_run_{run_id}_{short_hash}.json"
        artifact_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    return _audit_files(str(engagement_id), reports_dir)


def _graph_files(eng_id: str, reports_dir: Path) -> list[Path]:
    return sorted(reports_dir.glob(f"{eng_id}_attack_graph*"), key=lambda path: path.name.lower())


def _graph_root_from_artifact(path: Path) -> ElementTree.Element | None:
    try:
        if path.suffix.lower() == ".graphml":
            return ElementTree.parse(path).getroot()
        if path.suffix.lower() == ".mtgx":
            with zipfile.ZipFile(path) as archive:
                graphml_name = next(
                    (
                        name
                        for name in archive.namelist()
                        if name.lower() == "graphs/graph1.graphml" or name.lower().endswith(".graphml")
                    ),
                    "",
                )
                if not graphml_name:
                    return None
                return ElementTree.fromstring(archive.read(graphml_name))
    except Exception:  # noqa: BLE001
        return None
    return None


def _graph_entity_type_to_node_type(entity_type: str) -> str:
    normalized = str(entity_type or "").strip().lower()
    if normalized in {"maltego.domain", "maltego.url", "maltego.ipv4address", "maltego.ipv6address"}:
        return "HOST"
    if normalized in {"maltego.emailaddress", "maltego.phonenumber", "maltego.alias"}:
        return "CREDENTIAL"
    if normalized in {"maltego.person", "maltego.company"}:
        return "EXTERNAL"
    return "UNKNOWN"


def _graph_entity_properties(data: ElementTree.Element) -> tuple[str, dict[str, str]]:
    entity = data.find("m:MaltegoEntity", MALTEGO_NS)
    if entity is None:
        return "", {}
    entity_type = str(entity.attrib.get("type") or "").strip()
    properties: dict[str, str] = {}
    for prop in entity.findall(".//m:Property", MALTEGO_NS):
        name = str(prop.attrib.get("name") or "").strip()
        if not name:
            continue
        value = str(prop.findtext("m:Value", default="", namespaces=MALTEGO_NS) or "").strip()
        properties[name] = value
    return entity_type, properties


def _graph_link_properties(data: ElementTree.Element) -> dict[str, str]:
    link = data.find("m:MaltegoLink", MALTEGO_NS)
    if link is None:
        return {}
    properties: dict[str, str] = {}
    for prop in link.findall(".//m:Property", MALTEGO_NS):
        name = str(prop.attrib.get("name") or "").strip()
        if not name:
            continue
        value = str(prop.findtext("m:Value", default="", namespaces=MALTEGO_NS) or "").strip()
        properties[name] = value
    return properties


_MTGX_NODE_CONTROL_PROPERTIES = {
    "label",
    "metadata_json",
    "node_type",
    "on_critical_path",
    "severity",
    "source_id",
    "source_table",
}
_MTGX_EDGE_CONTROL_PROPERTIES = {
    "edge_type",
    "metadata_json",
    "on_critical_path",
    "weight",
}


def _safe_metadata_property_value(raw: str) -> Any:
    parsed = _safe_json_loads(raw)
    if isinstance(parsed, dict):
        return _safe_graph_metadata(parsed)
    if parsed is not None:
        return _safe_graph_metadata_value(parsed)
    return raw


def _merge_metadata_json(metadata: dict[str, Any], raw: str) -> None:
    parsed_metadata = _safe_json_loads(raw)
    if isinstance(parsed_metadata, dict):
        metadata.update(_safe_graph_metadata(parsed_metadata))
    else:
        metadata["metadata_json"] = raw


def _merge_safe_forge_property(
    metadata: dict[str, Any],
    raw_name: str,
    raw_value: str,
    *,
    control_properties: set[str],
) -> None:
    if not raw_value:
        return
    name = str(raw_name or "").strip()
    if not name.startswith("forge."):
        return
    key = name.removeprefix("forge.").strip()
    if not key or key in control_properties or _is_sensitive_metadata_key(key):
        return
    metadata.setdefault(key, _safe_metadata_property_value(raw_value))


def _graph_payload_from_root(root: ElementTree.Element, *, source: str, generated_at: str) -> dict[str, Any] | None:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    for node in root.findall(".//g:node", GRAPHML_NS):
        node_id = str(node.attrib.get("id") or "").strip()
        node_payload: dict[str, Any] = {
            "node_id": node_id or f"node-{len(nodes) + 1}",
            "label": node_id or f"Node {len(nodes) + 1}",
            "node_type": "UNKNOWN",
            "severity": "INFO",
            "source_table": "graphml",
            "source_id": 0,
            "on_critical_path": False,
            "metadata": {},
        }
        for data in node.findall("g:data", GRAPHML_NS):
            entity_type, properties = _graph_entity_properties(data)
            if entity_type:
                label = (
                    properties.get("forge.label")
                    or properties.get("fqdn")
                    or properties.get("email")
                    or properties.get("person.fullname")
                    or properties.get("phone-number")
                    or properties.get("short-title")
                    or properties.get("alias")
                    or next(
                        (
                            value
                            for name, value in properties.items()
                            if value and not name.startswith("forge.")
                        ),
                        "",
                    )
                )
                if label:
                    node_payload["label"] = label
                node_payload["node_type"] = (
                    str(properties.get("forge.node_type") or "").strip().upper()
                    or _graph_entity_type_to_node_type(entity_type)
                )
                node_payload["severity"] = (
                    str(properties.get("forge.severity") or "").strip().upper() or "INFO"
                )
                node_payload["source_table"] = (
                    str(properties.get("forge.source_table") or "").strip() or "mtgx"
                )
                if properties.get("forge.source_id"):
                    try:
                        node_payload["source_id"] = int(str(properties["forge.source_id"]).strip())
                    except ValueError:
                        node_payload["source_id"] = str(properties["forge.source_id"]).strip()
                metadata_json = str(properties.get("forge.metadata_json") or "").strip()
                if metadata_json:
                    _merge_metadata_json(node_payload["metadata"], metadata_json)
                node_payload["on_critical_path"] = properties.get("forge.on_critical_path") == "1"
                node_payload["metadata"]["maltego_entity_type"] = entity_type
                for name, value in properties.items():
                    if not value:
                        continue
                    if name.startswith("forge."):
                        _merge_safe_forge_property(
                            node_payload["metadata"],
                            name,
                            value,
                            control_properties=_MTGX_NODE_CONTROL_PROPERTIES,
                        )
                        continue
                    if value == node_payload["label"] or _is_sensitive_metadata_key(name):
                        continue
                    node_payload["metadata"][name] = value
                continue

            for child in list(data):
                if child.tag.endswith("EntityRenderer"):
                    continue
            key = str(data.attrib.get("key") or "").strip().lower()
            text = str(data.text or "").strip()
            if not key:
                continue
            if key == "label" and text:
                node_payload["label"] = text
            elif key in {"entity_type", "node_type"} and text:
                node_payload["node_type"] = text.upper()
            elif key == "severity" and text:
                node_payload["severity"] = text.upper()
            elif key == "critical":
                node_payload["on_critical_path"] = text == "1"
            elif key == "source_table" and text:
                node_payload["source_table"] = text
            elif key == "source_id" and text:
                try:
                    node_payload["source_id"] = int(text)
                except ValueError:
                    node_payload["source_id"] = text
            elif key == "metadata_json" and text:
                _merge_metadata_json(node_payload["metadata"], text)
            elif text:
                if not _is_sensitive_metadata_key(key):
                    node_payload["metadata"][key] = text
        nodes.append(node_payload)

    for edge in root.findall(".//g:edge", GRAPHML_NS):
        source_node_id = str(edge.attrib.get("source") or "").strip()
        target_node_id = str(edge.attrib.get("target") or "").strip()
        if not source_node_id or not target_node_id:
            continue
        edge_payload: dict[str, Any] = {
            "source_node_id": source_node_id,
            "target_node_id": target_node_id,
            "edge_type": "relationship",
            "weight": 1.0,
            "on_critical_path": False,
            "metadata": {},
        }
        for data in edge.findall("g:data", GRAPHML_NS):
            properties = _graph_link_properties(data)
            if properties:
                edge_payload["edge_type"] = (
                    str(
                        properties.get("forge.edge_type")
                        or properties.get("maltego.link.manual.type")
                        or edge_payload["edge_type"]
                    )
                    .strip()
                    or "relationship"
                )
                if properties.get("forge.weight"):
                    try:
                        edge_payload["weight"] = float(properties["forge.weight"])
                    except ValueError:
                        pass
                edge_payload["on_critical_path"] = properties.get("forge.on_critical_path") == "1"
                if properties.get("maltego.link.manual.type"):
                    edge_payload["label"] = properties["maltego.link.manual.type"]
                metadata_json = str(properties.get("forge.metadata_json") or "").strip()
                if metadata_json:
                    _merge_metadata_json(edge_payload["metadata"], metadata_json)
                for name, value in properties.items():
                    _merge_safe_forge_property(
                        edge_payload["metadata"],
                        name,
                        value,
                        control_properties=_MTGX_EDGE_CONTROL_PROPERTIES,
                    )
                continue

            key = str(data.attrib.get("key") or "").strip().lower()
            text = str(data.text or "").strip()
            if not key:
                continue
            if key in {"relation", "edge_type"} and text:
                edge_payload["edge_type"] = text
            elif key == "weight" and text:
                try:
                    edge_payload["weight"] = float(text)
                except ValueError:
                    pass
            elif key == "critical":
                edge_payload["on_critical_path"] = text == "1"
            elif key == "label" and text:
                edge_payload["label"] = text
            elif key in {"metadata_json", "edge_metadata_json"} and text:
                _merge_metadata_json(edge_payload["metadata"], text)
            elif text and not _is_sensitive_metadata_key(key):
                edge_payload["metadata"][key] = text
        edges.append(edge_payload)

    if not nodes:
        return None

    critical_path_nodes = [
        str(node.get("node_id") or "")
        for node in nodes
        if bool(node.get("on_critical_path"))
    ]
    return {
        "nodes": nodes,
        "edges": edges,
        "critical_path_nodes": critical_path_nodes,
        "critical_path_weight": 0.0,
        "generated_at": generated_at,
        "source": source,
    }


def _graph_summary(files: list[Path]) -> dict[str, Any]:
    graph_json = next((path for path in files if path.suffix.lower() == ".json"), None)

    if graph_json is not None:
        try:
            payload = json.loads(graph_json.read_text(encoding="utf-8", errors="replace"))
            nodes = payload.get("nodes", []) or []
            entity_types = Counter(
                str(node.get("node_type") or node.get("entity_type") or "UNKNOWN")
                for node in nodes
            )
            return {
                "nodes": int(payload.get("node_count") or len(nodes)),
                "edges": int(payload.get("edge_count") or len(payload.get("edges", []) or [])),
                "critical_nodes": len(payload.get("critical_path_nodes", []) or []),
                "critical_weight": payload.get("critical_path_weight"),
                "entity_types": entity_types.most_common(8),
                "sample_nodes": [
                    str(node.get("label") or node.get("node_id") or "")
                    for node in nodes[:8]
                ],
                "source": graph_json.name,
            }
        except Exception:  # noqa: BLE001
            pass

    for artifact in files:
        if artifact.suffix.lower() not in {".graphml", ".mtgx"}:
            continue
        generated_at = _format_dt(datetime.fromtimestamp(artifact.stat().st_mtime).isoformat())
        root = _graph_root_from_artifact(artifact)
        if root is None:
            continue
        payload = _graph_payload_from_root(root, source=artifact.name, generated_at=generated_at)
        if _graph_payload_has_structure(payload):
            return _graph_summary_from_payload(payload, artifact.name)

    return {}


def _graph_payload_with_defaults(
    payload: dict[str, Any] | None,
    *,
    source: str = "",
    generated_at: str = "",
) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return payload
    enriched = dict(payload)
    if source and not str(enriched.get("source") or "").strip():
        enriched["source"] = source
    if generated_at and not str(enriched.get("generated_at") or "").strip():
        enriched["generated_at"] = generated_at
    return enriched


def _graph_edge_endpoints(edge: dict[str, Any]) -> tuple[str, str]:
    return (
        str(edge.get("source_node_id") or edge.get("source") or "").strip(),
        str(edge.get("target_node_id") or edge.get("target") or "").strip(),
    )


def _set_graph_edge_endpoints(edge: dict[str, Any], source: str, target: str) -> None:
    if "source" in edge and "source_node_id" not in edge:
        edge["source"] = source
    if "target" in edge and "target_node_id" not in edge:
        edge["target"] = target
    edge["source_node_id"] = source
    edge["target_node_id"] = target


def _graph_node_validation_key(node: dict[str, Any]) -> tuple[str, str]:
    metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
    asset = ""
    for value in (
        metadata.get("validation_asset_type"),
        metadata.get("service"),
        metadata.get("parameter"),
        metadata.get("cloud_provider"),
    ):
        normalized = normalize_cloud_exposure_asset_type(str(value or "").split(":", 1)[0])
        if normalized:
            asset = normalized
            break
    node_text = f"{node.get('label') or ''} {metadata.get('target_url') or ''}".lower()
    if asset in {"aws", "amazon"} and "s3" in node_text:
        asset = "aws_s3"
    identifier = str(
        metadata.get("resource_id")
        or metadata.get("identifier")
        or metadata.get("domain")
        or ""
    ).strip().lower()
    return asset, identifier


def _graph_node_is_unreportable_cloud_finding(
    node: dict[str, Any],
    validation_index: dict[tuple[str, str], bool],
) -> bool:
    metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
    vuln_type = str(metadata.get("vuln_type") or node.get("vuln_type") or "").strip().upper()
    label = str(node.get("label") or node.get("title") or "")
    asset, identifier = _graph_node_validation_key(node)
    if not is_deterministic_cloud_exposure(vuln_type, label, (asset,)):
        return False
    if not asset or not identifier:
        return True
    reportable = validation_index.get((asset, identifier))
    return reportable is not True


def _graph_node_key_validation_detail(node: dict[str, Any]) -> str:
    metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
    detail = str(metadata.get("validation_detail") or "").strip()
    if detail:
        return detail
    method = str(metadata.get("validation_method") or "").strip()
    status = str(metadata.get("validation_status") or "").strip().upper()
    proof = str(metadata.get("validation_proof") or "").strip()
    if status == "VALIDATED" and method:
        return f"VALIDATED:{method}:{proof}"
    return ""


def _graph_node_is_unreportable_key_finding(
    node: dict[str, Any],
    validation_index: dict[tuple[str, str], bool],
) -> bool:
    node_type = str(node.get("node_type") or node.get("entity_type") or "").strip().upper()
    source_table = str(node.get("source_table") or "").strip().lower()
    metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
    vuln_type = str(metadata.get("vuln_type") or node.get("vuln_type") or "").strip().upper()
    label = str(node.get("label") or node.get("title") or "").strip().lower()
    is_key_scanner_node = node_type == "APIKEY" or source_table == "key_scanner_findings"
    is_key_finding_node = (
        source_table == "vulnerability_findings"
        and (vuln_type == "DETERMINISTIC_KEY_EXPOSURE" or label.startswith("active exposed "))
    )
    if not is_key_scanner_node and not is_key_finding_node:
        return False
    if source_table and source_table not in {"key_scanner_findings", "vulnerability_findings"} and node_type != "APIKEY":
        return False
    asset, identifier = _graph_node_validation_key(node)
    linked_reportable = linked_cloud_validation_reportability(
        validation_index,
        (asset,),
        identifier,
    )
    if linked_reportable is not None:
        return not linked_reportable
    detail = _graph_node_key_validation_detail(node)
    if not detail and not any(
        str(metadata.get(key) or "").strip()
        for key in ("validation_status", "validation_method", "validation_proof")
    ):
        return True
    return not _key_validation_detail_is_reportable(detail)


def _graph_node_is_cloud_review_node(node: dict[str, Any]) -> bool:
    node_type = str(node.get("node_type") or node.get("entity_type") or "").strip().upper()
    source_table = str(node.get("source_table") or "").strip().lower()
    return (
        node_type == "CLOUD"
        or source_table in {"cloud_assets", "cloud_validation_results"}
        or str(node.get("node_id") or "").strip().upper().startswith("CLOUD::")
    )


def _canonical_cloud_node_score(
    node: dict[str, Any],
    asset: str,
    identifier: str,
) -> int:
    node_id = str(node.get("node_id") or "").strip().lower()
    if node_id == f"cloud::{asset}::{identifier}":
        return 3
    if node_id.startswith(f"cloud::{asset}::"):
        return 2
    if asset and asset in node_id:
        return 1
    return 0


def _merge_cloud_node_metadata(
    target: dict[str, Any],
    duplicate: dict[str, Any],
    *,
    asset: str,
) -> None:
    target_metadata = target.setdefault("metadata", {})
    duplicate_metadata = duplicate.get("metadata") if isinstance(duplicate.get("metadata"), dict) else {}
    if not isinstance(target_metadata, dict):
        target_metadata = {}
        target["metadata"] = target_metadata
    aliases = set(
        str(item or "").strip().lower()
        for item in target_metadata.get("asset_type_aliases", [])
        if str(item or "").strip()
    )
    for metadata in (target_metadata, duplicate_metadata):
        for key in ("asset_type_original", "validation_asset_type_original", "service"):
            candidate = normalize_cloud_exposure_asset_type(str(metadata.get(key) or ""))
            raw_candidate = str(metadata.get(key) or "").strip().lower()
            if raw_candidate and raw_candidate != asset and candidate == asset:
                aliases.add(raw_candidate)
    for key, value in duplicate_metadata.items():
        if key not in target_metadata and value not in (None, ""):
            target_metadata[key] = value
    target_metadata["service"] = asset
    if aliases:
        target_metadata["asset_type_aliases"] = sorted(aliases)


def _dedupe_graph_payload_cloud_alias_nodes(
    payload: dict[str, Any],
) -> dict[str, Any]:
    nodes = payload.get("nodes", []) if isinstance(payload.get("nodes"), list) else []
    if len(nodes) < 2:
        return payload
    choices: dict[tuple[str, str], tuple[int, int]] = {}
    keys_by_index: dict[int, tuple[str, str]] = {}
    for index, node in enumerate(nodes):
        if not isinstance(node, dict) or not _graph_node_is_cloud_review_node(node):
            continue
        asset, identifier = _graph_node_validation_key(node)
        if not asset or not identifier:
            continue
        key = (asset, identifier)
        keys_by_index[index] = key
        score = _canonical_cloud_node_score(node, asset, identifier)
        if key not in choices or score > choices[key][1]:
            choices[key] = (index, score)
    duplicate_keys = {key for key in keys_by_index.values() if sum(value == key for value in keys_by_index.values()) > 1}
    if not duplicate_keys:
        return payload

    keep_by_key = {key: index for key, (index, _score) in choices.items()}
    remap: dict[str, str] = {}
    merged_nodes: list[dict[str, Any]] = []
    output_by_index: dict[int, dict[str, Any]] = {}
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            continue
        key = keys_by_index.get(index)
        if key not in duplicate_keys:
            merged_nodes.append(node)
            output_by_index[index] = node
            continue
        keep_index = keep_by_key[key]
        keep_node = output_by_index.get(keep_index)
        if keep_node is None:
            keep_node = dict(nodes[keep_index])
            output_by_index[keep_index] = keep_node
            merged_nodes.append(keep_node)
        if index == keep_index:
            continue
        duplicate_id = str(node.get("node_id") or "")
        keep_id = str(keep_node.get("node_id") or "")
        if duplicate_id and keep_id:
            remap[duplicate_id] = keep_id
        _merge_cloud_node_metadata(keep_node, node, asset=key[0])
    if not remap:
        return payload

    filtered_edges: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str, str]] = set()
    for edge in payload.get("edges", []) if isinstance(payload.get("edges"), list) else []:
        if not isinstance(edge, dict):
            continue
        rewired = dict(edge)
        source_raw, target_raw = _graph_edge_endpoints(rewired)
        source = remap.get(source_raw, source_raw)
        target = remap.get(target_raw, target_raw)
        if source == target:
            continue
        _set_graph_edge_endpoints(rewired, source, target)
        edge_key = (source, target, str(rewired.get("edge_type") or ""))
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)
        filtered_edges.append(rewired)

    filtered = dict(payload)
    filtered["nodes"] = merged_nodes
    filtered["edges"] = filtered_edges
    filtered["node_count"] = len(merged_nodes)
    filtered["edge_count"] = len(filtered_edges)
    critical_path_nodes: list[str] = []
    seen_critical_path_nodes: set[str] = set()
    for node_id in (
        payload.get("critical_path_nodes", [])
        if isinstance(payload.get("critical_path_nodes"), list)
        else []
    ):
        remapped = remap.get(str(node_id), str(node_id))
        if remapped and remapped not in seen_critical_path_nodes:
            seen_critical_path_nodes.add(remapped)
            critical_path_nodes.append(remapped)
    filtered["critical_path_nodes"] = critical_path_nodes
    return filtered


def _filter_graph_payload_for_validation(
    con: sqlite3.Connection,
    engagement_id: int,
    payload: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not _graph_payload_has_structure(payload):
        return payload
    validation_index = _reportable_cloud_validation_index(con, engagement_id)
    payload = _dedupe_graph_payload_cloud_alias_nodes(payload)
    nodes = payload.get("nodes", []) if isinstance(payload.get("nodes"), list) else []
    removed: set[str] = set()
    filtered_nodes: list[dict[str, Any]] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_id = str(node.get("node_id") or "")
        if _graph_node_is_unreportable_cloud_finding(
            node,
            validation_index,
        ) or _graph_node_is_unreportable_key_finding(node, validation_index):
            if node_id:
                removed.add(node_id)
            continue
        filtered_nodes.append(node)
    if not removed:
        return payload
    edges = payload.get("edges", []) if isinstance(payload.get("edges"), list) else []
    filtered_edges = [
        edge
        for edge in edges
        if isinstance(edge, dict) and not any(endpoint in removed for endpoint in _graph_edge_endpoints(edge))
    ]
    filtered = dict(payload)
    filtered["nodes"] = filtered_nodes
    filtered["edges"] = filtered_edges
    filtered["node_count"] = len(filtered_nodes)
    filtered["edge_count"] = len(filtered_edges)
    filtered["critical_path_nodes"] = [
        node_id
        for node_id in (
            payload.get("critical_path_nodes", [])
            if isinstance(payload.get("critical_path_nodes"), list)
            else []
        )
        if str(node_id) not in removed
    ]
    return filtered


def _cloud_validation_section_row(row: sqlite3.Row) -> dict[str, str]:
    stored_type = str(row["asset_type"] or "").strip().lower()
    asset_type = normalize_cloud_exposure_asset_type(stored_type)
    stored_status = str(row["validation_status"] or "").strip().upper()
    method = str(row["validation_method"] or "").strip()
    evidence = row["evidence"]
    notes = row["notes"]
    reportable = is_reportable_cloud_validation(
        asset_type,
        stored_status,
        method,
        evidence=evidence,
        notes=notes,
        require_stable_proof=True,
    )
    return {
        "Asset": str(row["display_identifier"] or ""),
        "Type": asset_type,
        "Stored Type": stored_type,
        "Status": effective_cloud_validation_status(
            asset_type,
            stored_status,
            method,
            evidence=evidence,
            notes=notes,
            require_stable_proof=True,
        ),
        "Stored Status": stored_status,
        "Reportable": "yes" if reportable else "no",
        "Method": method,
        "HTTP": str(row["http_status"] or ""),
        "Evidence": _truncate(evidence, 120),
        "Notes": _truncate(notes, 120),
        "Checked": _format_dt(str(row["checked_at"] or "")),
    }


def _parse_graph_payload(raw: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(raw)
    except Exception:  # noqa: BLE001
        return {"raw": raw}
    if isinstance(payload, dict):
        return payload
    return {"raw": payload}


def _graph_payload_has_structure(payload: dict[str, Any] | None) -> bool:
    if not isinstance(payload, dict):
        return False
    nodes = payload.get("nodes")
    edges = payload.get("edges")
    return isinstance(nodes, list) and bool(nodes) or isinstance(edges, list) and bool(edges)


def _graph_summary_from_payload(payload: dict[str, Any], source: str) -> dict[str, Any]:
    nodes = payload.get("nodes", []) if isinstance(payload.get("nodes"), list) else []
    edges = payload.get("edges", []) if isinstance(payload.get("edges"), list) else []
    critical_path = {
        str(item)
        for item in (payload.get("critical_path_nodes", []) if isinstance(payload.get("critical_path_nodes"), list) else [])
        if str(item).strip()
    }
    entity_types = Counter(
        str(node.get("node_type") or node.get("entity_type") or "UNKNOWN")
        for node in nodes
        if isinstance(node, dict)
    )
    return {
        "nodes": int(payload.get("node_count") or len(nodes)),
        "edges": int(payload.get("edge_count") or len(edges)),
        "critical_nodes": sum(
            1
            for node in nodes
            if isinstance(node, dict)
            and (
                bool(node.get("on_critical_path"))
                or str(node.get("node_id") or "").strip() in critical_path
            )
        ),
        "critical_weight": payload.get("critical_path_weight"),
        "entity_types": entity_types.most_common(8),
        "sample_nodes": [
            str(node.get("label") or node.get("node_id") or "")
            for node in nodes[:8]
            if isinstance(node, dict)
        ],
        "source": source,
    }


def _graph_payload_from_graphml(graphml_path: Path) -> dict[str, Any] | None:
    root = _graph_root_from_artifact(graphml_path)
    if root is None:
        return None
    return _graph_payload_from_root(
        root,
        source=graphml_path.name,
        generated_at=_format_dt(datetime.fromtimestamp(graphml_path.stat().st_mtime).isoformat()),
    )


def _seed_graph_node_type(seed_type: str) -> str:
    normalized = str(seed_type or "").strip().lower()
    if normalized in {"domain", "subdomain", "url", "apk_url", "ipv4", "ipv6"}:
        return "HOST"
    if normalized in {"email", "phone", "username"}:
        return "CREDENTIAL"
    if normalized in {"company", "name"}:
        return "EXTERNAL"
    return "UNKNOWN"


def _seed_graph_severity(
    confidence_band: str,
    confidence: float,
) -> str:
    band = str(confidence_band or "").strip().lower()
    if band == "confirmed":
        return "HIGH"
    if band == "high" or confidence >= 0.9:
        return "MEDIUM"
    if band == "medium" or confidence >= 0.7:
        return "LOW"
    return "INFO"


def _seed_graph_payload_for_engagement(
    con: sqlite3.Connection,
    engagement_id: int,
) -> tuple[dict[str, Any] | None, str]:
    if not _table_exists(con, "engagement_seeds"):
        return None, ""

    engagement_row = con.execute(
        "SELECT name FROM engagements WHERE id=?",
        (engagement_id,),
    ).fetchone()
    engagement_label = (
        str(engagement_row["name"] or "").strip()
        if engagement_row is not None and "name" in engagement_row.keys()
        else ""
    ) or f"Engagement {engagement_id}"

    seed_rows = _fetch_rows(
        con,
        """
        SELECT id, seed_value, seed_type, source, status, depth, confidence, parent_seed_id, metadata_json, discovered_at, updated_at
        FROM engagement_seeds
        WHERE engagement_id=?
          AND COALESCE(status, 'pending') != 'failed'
        ORDER BY depth ASC, id ASC
        """,
        (engagement_id,),
    )
    if not seed_rows:
        return None, ""

    nodes: list[dict[str, Any]] = [
        {
            "node_id": f"ENGAGEMENT::{engagement_id}",
            "label": engagement_label,
            "node_type": "EXTERNAL",
            "severity": "INFO",
            "source_table": "engagements",
            "source_id": engagement_id,
            "metadata": {"role": "engagement_root"},
        }
    ]
    edges: list[dict[str, Any]] = []
    node_ids_by_seed_id: dict[int, str] = {}
    latest_timestamps: list[str] = []

    for row in seed_rows:
        seed_id = int(row["id"])
        metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
        metadata_dict = metadata if isinstance(metadata, dict) else {}
        synthesis = metadata_dict.get("synthesis") if isinstance(metadata_dict.get("synthesis"), dict) else {}
        confidence = float(row["confidence"] or 0.0)
        confidence_band = str(synthesis.get("confidence_band") or "")
        node_id = f"SEED::{seed_id}"
        node_ids_by_seed_id[seed_id] = node_id
        node_metadata = {
            "seed_type": str(row["seed_type"] or ""),
            "source": str(row["source"] or ""),
            "status": str(row["status"] or ""),
            "depth": int(row["depth"] or 0),
            "confidence": confidence,
            "confidence_band": confidence_band,
            "corroborated": bool(synthesis.get("corroborated")),
            "supporting_relations": int(synthesis.get("supporting_relations") or 0),
            "corroborating_seed_count": int(synthesis.get("corroborating_seed_count") or 0),
        }
        _merge_seed_node_metadata(node_metadata, metadata_dict)
        nodes.append(
            {
                "node_id": node_id,
                "label": str(row["seed_value"] or ""),
                "node_type": _seed_graph_node_type(str(row["seed_type"] or "")),
                "severity": _seed_graph_severity(confidence_band, confidence),
                "source_table": "engagement_seeds",
                "source_id": seed_id,
                "metadata": node_metadata,
            }
        )
        for timestamp_key in ("updated_at", "discovered_at"):
            timestamp = str(row[timestamp_key] or "").strip()
            if timestamp:
                latest_timestamps.append(timestamp)

    edge_seen: set[tuple[str, str, str]] = set()
    for row in seed_rows:
        seed_id = int(row["id"])
        node_id = node_ids_by_seed_id.get(seed_id)
        if not node_id:
            continue
        parent_seed_id = int(row["parent_seed_id"]) if row["parent_seed_id"] is not None else None
        if parent_seed_id is not None and parent_seed_id in node_ids_by_seed_id:
            source_node_id = node_ids_by_seed_id[parent_seed_id]
            edge_key = (source_node_id, node_id, "parent_seed")
            if edge_key not in edge_seen:
                edge_seen.add(edge_key)
                edges.append(
                    {
                        "source_node_id": source_node_id,
                        "target_node_id": node_id,
                        "edge_type": "parent_seed",
                        "weight": max(1.0, float(row["confidence"] or 0.0) * 100.0),
                    }
                )
        else:
            edge_key = (f"ENGAGEMENT::{engagement_id}", node_id, "seed_root")
            if edge_key not in edge_seen:
                edge_seen.add(edge_key)
                edges.append(
                    {
                        "source_node_id": f"ENGAGEMENT::{engagement_id}",
                        "target_node_id": node_id,
                        "edge_type": "seed_root",
                        "weight": max(1.0, float(row["confidence"] or 0.0) * 40.0),
                    }
                )

    if _table_exists(con, "seed_relations"):
        relation_rows = _fetch_rows(
            con,
            """
            SELECT source_seed_id, target_seed_id, relation_type, confidence, evidence_json, discovered_at
            FROM seed_relations
            WHERE engagement_id=?
            ORDER BY id ASC
            """,
            (engagement_id,),
        )
        for row in relation_rows:
            source_seed_id = int(row["source_seed_id"])
            target_seed_id = int(row["target_seed_id"])
            source_node_id = node_ids_by_seed_id.get(source_seed_id)
            target_node_id = node_ids_by_seed_id.get(target_seed_id)
            relation_type = str(row["relation_type"] or "").strip() or "related"
            if not source_node_id or not target_node_id:
                continue
            edge_key = (source_node_id, target_node_id, relation_type)
            if edge_key in edge_seen:
                continue
            edge_seen.add(edge_key)
            evidence = _safe_json_loads(str(row["evidence_json"] or "{}"))
            edge_payload: dict[str, Any] = {
                "source_node_id": source_node_id,
                "target_node_id": target_node_id,
                "edge_type": relation_type,
                "label": relation_type,
                "weight": max(1.0, float(row["confidence"] or 0.0) * 100.0),
            }
            if isinstance(evidence, dict) and evidence:
                edge_payload["metadata"] = _safe_graph_metadata(evidence)
            edges.append(edge_payload)
            timestamp = str(row["discovered_at"] or "").strip()
            if timestamp:
                latest_timestamps.append(timestamp)

    latest_timestamp = max(latest_timestamps) if latest_timestamps else ""
    return (
        {
            "nodes": nodes,
            "edges": edges,
            "critical_path_nodes": [],
            "critical_path_weight": 0.0,
            "generated_at": _format_dt(latest_timestamp),
            "source": "engagement_seed_graph",
        },
        latest_timestamp,
    )


def _graph_payload_for_engagement(
    con: sqlite3.Connection,
    engagement_id: int,
    graph_files: list[Path],
) -> tuple[dict[str, Any] | None, str]:
    if _table_exists(con, "attack_graph_snapshots"):
        rows = _fetch_rows(
            con,
            """
            SELECT graph_json, snapshot_at
            FROM attack_graph_snapshots
            WHERE engagement_id=?
            ORDER BY snapshot_at DESC
            LIMIT 1
            """,
            (engagement_id,),
        )
        if rows:
            payload = _parse_graph_payload(str(rows[0]["graph_json"] or ""))
            if _graph_payload_has_structure(payload):
                snapshot_at = str(rows[0]["snapshot_at"] or "")
                graph_payload = _graph_payload_with_defaults(
                    payload,
                    source="attack_graph_snapshot",
                    generated_at=_format_dt(snapshot_at),
                )
                return (
                    _filter_graph_payload_for_validation(con, engagement_id, graph_payload),
                    snapshot_at,
                )

    graph_json = next((path for path in graph_files if path.suffix.lower() == ".json"), None)
    if graph_json is not None:
        try:
            payload = _parse_graph_payload(graph_json.read_text(encoding="utf-8", errors="replace"))
            if _graph_payload_has_structure(payload):
                generated_at = _format_dt(datetime.fromtimestamp(graph_json.stat().st_mtime).isoformat())
                graph_payload = _graph_payload_with_defaults(
                    payload,
                    source=graph_json.name,
                    generated_at=generated_at,
                )
                return (
                    _filter_graph_payload_for_validation(con, engagement_id, graph_payload),
                    generated_at,
                )
        except Exception:  # noqa: BLE001
            pass

    graphml = next((path for path in graph_files if path.suffix.lower() == ".graphml"), None)
    if graphml is not None:
        payload = _graph_payload_from_graphml(graphml)
        if _graph_payload_has_structure(payload):
            return (
                _filter_graph_payload_for_validation(con, engagement_id, payload),
                _format_dt(datetime.fromtimestamp(graphml.stat().st_mtime).isoformat()),
            )

    mtgx = next((path for path in graph_files if path.suffix.lower() == ".mtgx"), None)
    if mtgx is not None:
        payload = _graph_payload_from_graphml(mtgx)
        if _graph_payload_has_structure(payload):
            return (
                _filter_graph_payload_for_validation(con, engagement_id, payload),
                _format_dt(datetime.fromtimestamp(mtgx.stat().st_mtime).isoformat()),
            )

    seed_payload, seed_snapshot_at = _seed_graph_payload_for_engagement(con, engagement_id)
    if _graph_payload_has_structure(seed_payload):
        return seed_payload, seed_snapshot_at

    return None, ""


def _graph_state_for_engagement(
    con: sqlite3.Connection,
    engagement_id: int,
    graph_files: list[Path],
) -> tuple[dict[str, Any], dict[str, Any] | None, str]:
    graph_payload, graph_snapshot_at = _graph_payload_for_engagement(con, engagement_id, graph_files)
    if _graph_payload_has_structure(graph_payload):
        payload_source = str(graph_payload.get("source") or "engagement_graph_payload")
        return (
            _graph_summary_from_payload(graph_payload, payload_source),
            graph_payload,
            graph_snapshot_at,
        )

    return _graph_summary(graph_files), graph_payload, graph_snapshot_at


def _site_root(output_path: Path) -> Path:
    return output_path.parent / output_path.stem


def _artifact_payload(root_page: Path, artifact: Path, *, kind: str) -> dict[str, Any]:
    stat = artifact.stat()
    modified_at = _format_dt(datetime.fromtimestamp(stat.st_mtime).isoformat())
    return {
        "name": artifact.name,
        "kind": kind,
        "href": _relative_href(root_page, artifact),
        "size_bytes": int(stat.st_size),
        "size_label": _format_size(int(stat.st_size)),
        "modified_at": modified_at,
    }


def _report_preview_payload(root_page: Path, artifact: Path) -> dict[str, str]:
    try:
        preview = artifact.read_text(encoding="utf-8", errors="replace")[:7000]
    except Exception:  # noqa: BLE001
        preview = "(unreadable)"
    return {
        "name": artifact.name,
        "href": _relative_href(root_page, artifact),
        "preview": preview,
    }


def _engagement_db_files(data_dir: Path) -> list[Path]:
    roots: list[Path] = [data_dir / "engagements"]
    legacy_root = Path.cwd() / ".forge_data" / "engagements"
    if legacy_root not in roots:
        roots.append(legacy_root)

    selected: dict[str, Path] = {}
    for root in roots:
        if not root.exists():
            continue
        for db_path in root.glob("*.db"):
            try:
                int(db_path.stem)
            except ValueError:
                continue
            existing = selected.get(db_path.name)
            if existing is None or db_path.stat().st_mtime >= existing.stat().st_mtime:
                selected[db_path.name] = db_path

    return sorted(
        selected.values(),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )


def _seed_list(con: sqlite3.Connection, engagement_id: int, scope: list[str]) -> list[str]:
    seeds: list[str] = []
    seen: set[str] = set()
    if _table_exists(con, "engagement_seeds"):
        for row in _fetch_rows(
            con,
            """
            SELECT seed_value
            FROM engagement_seeds
            WHERE engagement_id=?
            ORDER BY depth ASC, id ASC
            """,
            (engagement_id,),
        ):
            value = str(row["seed_value"] or "").strip()
            if value and value not in seen:
                seeds.append(value)
                seen.add(value)
    for row in _fetch_rows(
        con,
        """
        SELECT target
        FROM audit_log
        WHERE engagement_id=? AND action='kill_chain_start'
        ORDER BY id ASC
        """,
        (engagement_id,),
    ):
        value = str(row["target"] or "").strip()
        if value and value not in seen:
            seeds.append(value)
            seen.add(value)

    for item in scope:
        value = str(item or "").strip()
        if value and value not in seen:
            seeds.append(value)
            seen.add(value)
    return seeds


def _summary_counts(con: sqlite3.Connection, engagement_id: int) -> dict[str, int]:
    counts: dict[str, int] = {
        "hosts": 0,
        "emails": 0,
        "email_intelligence": 0,
        "account_existence": 0,
        "services": 0,
        "engagement_seeds": 0,
        "seed_runs": 0,
        "engagement_runs": 0,
        "seed_relations": 0,
        "artifact_queue": 0,
        "crawl_results": 0,
        "social_profiles": 0,
        "key_scanner_findings": 0,
        "cloud_validation_results": 0,
        "audit_log": 0,
        "port_scan_results": 0,
        "passive_vulns": 0,
        "vulnerability_findings": 0,
        "auth_test_results": 0,
        "subdomains": 0,
    }

    counts["hosts"] = len(_merged_host_rows(con, engagement_id))
    counts["emails"] = len(_merged_email_rows(con, engagement_id))
    if _table_exists(con, "services") and _table_exists(con, "hosts"):
        counts["services"] = _fetch_count(
            con,
            """
            SELECT COUNT(*)
            FROM services s
            JOIN hosts h ON h.id=s.host_id
            WHERE h.engagement_id=?
            """,
            (engagement_id,),
        )
    if _table_exists(con, "subdomains") and "engagement_id" in _table_columns(con, "subdomains"):
        counts["subdomains"] = _fetch_count(
            con,
            "SELECT COUNT(*) FROM subdomains WHERE engagement_id=?",
            (engagement_id,),
        )

    for table in (
        "engagement_seeds",
        "seed_runs",
        "engagement_runs",
        "seed_relations",
        "artifact_queue",
        "crawl_results",
        "social_profiles",
        "email_intelligence",
        "account_existence",
        "key_scanner_findings",
        "cloud_validation_results",
        "audit_log",
        "port_scan_results",
        "passive_vulns",
        "vulnerability_findings",
        "auth_test_results",
    ):
        if _table_exists(con, table):
            if table == "key_scanner_findings":
                counts[table] = len(_reportable_key_scanner_rows(con, engagement_id))
                continue
            if table == "vulnerability_findings":
                counts[table] = len(_reportable_vulnerability_rows(con, engagement_id))
                continue
            counts[table] = _fetch_count(
                con,
                f"SELECT COUNT(*) FROM {table} WHERE engagement_id=?",
                (engagement_id,),
            )
    return counts


def _latest_engagement_run(
    con: sqlite3.Connection,
    engagement_id: int,
    db_path: Path | None = None,
    verify_manifest: bool = True,
) -> dict[str, Any] | None:
    if not _table_exists(con, "engagement_runs"):
        return None
    row = con.execute(
        """
        SELECT id,
               run_kind,
               status,
               seed_value,
               seed_type,
               seed_count,
               max_iterations,
               current_iteration,
               resume_enabled,
               dry_run,
               attack_mode,
               error,
               metadata_json,
               started_at,
               completed_at,
               updated_at
        FROM engagement_runs
        WHERE engagement_id=?
        ORDER BY started_at DESC, id DESC
        LIMIT 1
        """,
        (engagement_id,),
    ).fetchone()
    if row is None:
        return None
    metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
    policy_summary = _run_policy_summary(
        metadata,
        dry_run=bool(row["dry_run"]),
        attack_mode=bool(row["attack_mode"]),
    )
    return {
        "id": int(row["id"]),
        "run_kind": str(row["run_kind"] or ""),
        "status": _effective_run_status(str(row["status"] or ""), metadata),
        "seed_value": str(row["seed_value"] or ""),
        "seed_type": str(row["seed_type"] or ""),
        "seed_count": int(row["seed_count"] or 0),
        "max_iterations": int(row["max_iterations"] or 0),
        "current_iteration": int(row["current_iteration"] or 0),
        "resume_enabled": bool(row["resume_enabled"]),
        "dry_run": bool(row["dry_run"]),
        "attack_mode": bool(row["attack_mode"]),
        **policy_summary,
        "error": _truncate(row["error"], 160),
        "metadata": metadata if isinstance(metadata, dict) else {},
        "audit_manifest": summarize_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=engagement_id,
            run_id=int(row["id"]),
            verify=verify_manifest and db_path is not None,
        ),
        "started_at": _format_dt(str(row["started_at"] or "")),
        "completed_at": _format_dt(str(row["completed_at"] or "")),
        "updated_at": _format_dt(str(row["updated_at"] or "")),
    }


def _seed_graph_summary(con: sqlite3.Connection, engagement_id: int) -> dict[str, Any]:
    summary = {
        "total_seeds": 0,
        "corroborated_seeds": 0,
        "confirmed_seeds": 0,
        "high_confidence_seeds": 0,
        "max_depth": 0,
        "relations": 0,
        "seed_types": [],
    }
    if not _table_exists(con, "engagement_seeds"):
        return summary
    rows = _fetch_rows(
        con,
        """
        SELECT seed_type, depth, metadata_json
        FROM engagement_seeds
        WHERE engagement_id=?
        ORDER BY id ASC
        """,
        (engagement_id,),
    )
    summary["total_seeds"] = len(rows)
    if _table_exists(con, "seed_relations"):
        summary["relations"] = _fetch_count(
            con,
            "SELECT COUNT(*) FROM seed_relations WHERE engagement_id=?",
            (engagement_id,),
        )
    seed_type_counts = Counter(str(row["seed_type"] or "") for row in rows if row["seed_type"])
    summary["seed_types"] = sorted(seed_type_counts.items(), key=lambda item: (item[0], item[1]))
    for row in rows:
        summary["max_depth"] = max(summary["max_depth"], int(row["depth"] or 0))
        metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
        synthesis = metadata.get("synthesis") if isinstance(metadata, dict) else {}
        if not isinstance(synthesis, dict):
            continue
        band = str(synthesis.get("confidence_band") or "")
        if synthesis.get("corroborated"):
            summary["corroborated_seeds"] += 1
        if band == "confirmed":
            summary["confirmed_seeds"] += 1
        if band in {"confirmed", "high"}:
            summary["high_confidence_seeds"] += 1
    return summary


def _relation_evidence_preview(evidence: Any) -> str:
    if isinstance(evidence, dict):
        rule = str(evidence.get("rule") or "").strip()
        extract_rule = str(evidence.get("extract_rule") or "").strip()
        artifactish = (
            rule == "artifact_seed_provenance"
            or rule.startswith("artifact_")
            or extract_rule.startswith("artifact_")
            or any(
                key in evidence
                for key in (
                    "source_file",
                    "extract_path",
                    "parser",
                    "format",
                    "payload_count",
                    "metadata_payload_count",
                    "relationship_payload_count",
                )
            )
        )
        if artifactish:
            parts: list[str] = []
            for key in ("rule", "extract_rule", "parser", "format", "artifact_type"):
                value = str(evidence.get(key) or "").strip()
                if value:
                    parts.append(f"{key}={value}")
            for key in (
                "payload_count",
                "metadata_payload_count",
                "relationship_payload_count",
                "ocr_payload_count",
            ):
                value = evidence.get(key)
                if value not in (None, ""):
                    parts.append(f"{key}={value}")
            source_summary = _crawl_source_summary(evidence)
            if source_summary:
                parts.append(f"sources={source_summary}")
            root_domain = str(evidence.get("root_domain") or "").strip()
            if root_domain:
                parts.append(f"root={root_domain}")
            source_url = str(evidence.get("source_url") or "").strip()
            if source_url:
                parts.append(f"source={_truncate(source_url, 64)}")
            source_file = str(evidence.get("source_file") or "").strip()
            if source_file and source_file != source_url:
                parts.append(f"file={_truncate(source_file, 48)}")
            extract_path = str(evidence.get("extract_path") or "").strip()
            if extract_path:
                parts.append(f"extract={_truncate(extract_path, 48)}")
            if parts:
                return _truncate(" ".join(parts), 180)
        preferred = []
        for key in ("rule", "service", "ref", "source_url", "artifact_type"):
            value = str(evidence.get(key) or "").strip()
            if value:
                preferred.append(f"{key}={value}")
        if preferred:
            return _truncate(", ".join(preferred), 96)
        compact = json.dumps(evidence, sort_keys=True)
        return _truncate(compact, 96)
    if evidence is None:
        return ""
    return _truncate(str(evidence), 96)


def _artifact_metadata_brief(metadata: Any) -> str:
    if not isinstance(metadata, dict):
        return ""
    parts: list[str] = []
    fmt = str(metadata.get("format") or "").strip()
    if fmt:
        parts.append(f"fmt={fmt}")
    payload_count = metadata.get("payload_count")
    if payload_count not in (None, ""):
        parts.append(f"payloads={payload_count}")
    meta_count = metadata.get("metadata_payload_count")
    if meta_count not in (None, ""):
        parts.append(f"meta={meta_count}")
    rel_count = metadata.get("relationship_payload_count")
    if rel_count not in (None, ""):
        parts.append(f"rels={rel_count}")
    content_type = str(metadata.get("content_type") or "").strip()
    if content_type:
        parts.append(f"type={_truncate(content_type, 48)}")
    download_filename = str(metadata.get("download_filename") or "").strip()
    if download_filename:
        filename = download_filename.replace("\\", "/").rsplit("/", 1)[-1]
        parts.append(f"file={_truncate(filename, 48)}")
    return " ".join(parts[:6])


def _email_intelligence_brief(source: str, breach_names: Any, enrichment_data: Any) -> str:
    source_key = str(source or "").strip().lower()
    parsed_breach_names = breach_names
    if isinstance(parsed_breach_names, str):
        maybe_names = _safe_json_loads(parsed_breach_names)
        if maybe_names is not None:
            parsed_breach_names = maybe_names
    parsed_enrichment = enrichment_data
    if isinstance(parsed_enrichment, str):
        maybe_data = _safe_json_loads(parsed_enrichment)
        if maybe_data is not None:
            parsed_enrichment = maybe_data
    if source_key == "emailrep" and isinstance(parsed_enrichment, dict):
        details = (
            parsed_enrichment.get("details")
            if isinstance(parsed_enrichment.get("details"), dict)
            else {}
        )
        profiles = details.get("profiles") if isinstance(details, dict) else []
        parts: list[str] = []
        reputation = str(parsed_enrichment.get("reputation") or "").strip()
        if reputation:
            parts.append(f"rep={reputation}")
        suspicious = parsed_enrichment.get("suspicious")
        if isinstance(suspicious, bool):
            parts.append(f"suspicious={'yes' if suspicious else 'no'}")
        blacklisted = details.get("blacklisted") if isinstance(details, dict) else None
        if isinstance(blacklisted, bool):
            parts.append(f"blacklisted={'yes' if blacklisted else 'no'}")
        if isinstance(profiles, list) and profiles:
            parts.append(f"profiles={len(profiles)}")
        if parts:
            return " ".join(parts)
    if isinstance(parsed_breach_names, list) and parsed_breach_names:
        preview = ", ".join(str(item) for item in parsed_breach_names[:3] if str(item).strip())
        if preview:
            return _truncate(preview, 120)
    return _preview_json(parsed_enrichment, limit=120)


def _engagement_run_section_row(
    row: sqlite3.Row,
    manifest: dict[str, Any] | None = None,
) -> dict[str, str]:
    metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
    policy = _run_policy_summary(
        metadata,
        dry_run=bool(row["dry_run"]),
        attack_mode=bool(row["attack_mode"]),
    )
    live_bits = [
        f"probe={'yes' if policy['live_probing_allowed'] else 'no'}",
        f"tools={'yes' if policy['tool_execution_allowed'] else 'no'}",
        f"active={'yes' if policy['active_recon_allowed'] else 'no'}",
        f"creds={'yes' if policy['credential_validation_allowed'] else 'no'}",
    ]
    manifest = manifest or {"present": False, "verification_status": "missing"}
    manifest_status = str(manifest.get("verification_status") or "missing")
    result = {
        "Kind": str(row["run_kind"] or ""),
        "Status": _effective_run_status(str(row["status"] or ""), metadata),
        "Seed": str(row["seed_value"] or ""),
        "Type": str(row["seed_type"] or ""),
        "Seeds": str(row["seed_count"] or ""),
        "Iteration": f"{int(row['current_iteration'] or 0)}/{int(row['max_iterations'] or 0)}",
        "Resume": "yes" if row["resume_enabled"] else "no",
        "Dry": "yes" if row["dry_run"] else "no",
        "Attack": "yes" if row["attack_mode"] else "no",
        "Live": " ".join(live_bits),
        "ROE": policy["roe_id"] or "-",
        "ROE Missing": "yes" if policy["roe_missing"] else "no",
        "Destructive": "yes" if policy["destructive_actions_allowed"] else "no",
        "Post-Ex": "yes" if policy["post_exploitation_allowed"] else "no",
        "Started": _format_dt(str(row["started_at"] or "")),
        "Completed": _format_dt(str(row["completed_at"] or "")),
        "Error": _truncate(row["error"], 96),
    }
    result["Manifest"] = str(manifest.get("short_hash") or "-")
    result["Manifest OK"] = "yes" if manifest.get("verified") is True else manifest_status
    return result


def _detail_sections(
    con: sqlite3.Connection,
    engagement_id: int,
    db_path: Path | None = None,
) -> dict[str, list[dict[str, str]]]:
    sections: dict[str, list[dict[str, str]]] = {}

    sections["hosts"] = [
        {
            "Host": str(row["hostname"] or ""),
            "IP": str(row["ip"] or ""),
            "OS": str(row["os_family"] or ""),
            "Source": str(row["source"] or ""),
            "Seen": _format_dt(str(row["discovered_at"] or "")),
        }
        for row in _merged_host_rows(con, engagement_id, limit=SECTION_LIMIT)
    ]

    sections["emails"] = [
        {
            "Email": str(row["email"] or ""),
            "Domain": str(row["domain"] or ""),
            "Source": str(row["source"] or ""),
            "Seen": _format_dt(str(row["first_seen_at"] or "")),
        }
        for row in _merged_email_rows(con, engagement_id, limit=SECTION_LIMIT)
    ]

    sections["email_intelligence"] = []
    if _table_exists(con, "email_intelligence"):
        columns = _table_columns(con, "email_intelligence")
        paste_expr = "paste_count" if "paste_count" in columns else "0"
        breach_names_expr = "breach_names" if "breach_names" in columns else "'[]'"
        enrichment_expr = "enrichment_data" if "enrichment_data" in columns else "'{}'"
        seen_column = (
            "last_synced"
            if "last_synced" in columns
            else "queried_at"
            if "queried_at" in columns
            else "discovered_at"
            if "discovered_at" in columns
            else ""
        )
        seen_expr = f"{seen_column} AS seen_at" if seen_column else "'' AS seen_at"
        order_by = f"{seen_column} DESC, id DESC" if seen_column else "id DESC"
        rows = _fetch_rows(
            con,
            f"""
            SELECT email,
                   source,
                   breach_count,
                   {paste_expr} AS paste_count,
                   {breach_names_expr} AS breach_names,
                   {enrichment_expr} AS enrichment_data,
                   {seen_expr}
            FROM email_intelligence
            WHERE engagement_id=?
            ORDER BY {order_by}
            LIMIT ?
            """,
            (engagement_id, SECTION_LIMIT),
        )
        sections["email_intelligence"] = [
            {
                "Email": str(row["email"] or ""),
                "Source": str(row["source"] or ""),
                "Breaches": str(row["breach_count"] or 0),
                "Pastes": str(row["paste_count"] or 0),
                "Signals": _email_intelligence_brief(
                    str(row["source"] or ""),
                    row["breach_names"],
                    row["enrichment_data"],
                ),
                "Seen": _format_dt(str(row["seen_at"] or "")),
            }
            for row in rows
        ]

    sections["account_existence"] = []
    if _table_exists(con, "account_existence"):
        columns = _table_columns(con, "account_existence")
        if {"email", "service"}.issubset(columns):
            exists_expr = "exists_flag" if "exists_flag" in columns else "1"
            rate_expr = "rate_limited" if "rate_limited" in columns else "0"
            source_expr = "source_tool" if "source_tool" in columns else "'holehe'"
            seen_column = "queried_at" if "queried_at" in columns else ""
            seen_expr = f"{seen_column} AS seen_at" if seen_column else "'' AS seen_at"
            order_by = f"{seen_column} DESC, id DESC" if seen_column else "id DESC"
            rows = _fetch_rows(
                con,
                f"""
                SELECT email,
                       service,
                       {exists_expr} AS exists_flag,
                       {rate_expr} AS rate_limited,
                       {source_expr} AS source_tool,
                       {seen_expr}
                FROM account_existence
                WHERE engagement_id=?
                ORDER BY {order_by}
                LIMIT ?
                """,
                (engagement_id, SECTION_LIMIT),
            )
            sections["account_existence"] = [
                {
                    "Email": str(row["email"] or ""),
                    "Service": str(row["service"] or ""),
                    "Exists": "yes" if int(row["exists_flag"] or 0) == 1 else "no",
                    "Rate Limited": "yes" if int(row["rate_limited"] or 0) == 1 else "no",
                    "Source": str(row["source_tool"] or ""),
                    "Seen": _format_dt(str(row["seen_at"] or "")),
                }
                for row in rows
            ]

    sections["engagement_seeds"] = []
    for row in _fetch_rows(
        con,
        """
        SELECT seed_value, seed_type, source, status, depth, confidence, metadata_json
        FROM engagement_seeds
        WHERE engagement_id=?
        ORDER BY depth ASC, id DESC
        LIMIT ?
        """,
        (engagement_id, SECTION_LIMIT),
    ):
        metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
        synthesis = metadata.get("synthesis") if isinstance(metadata, dict) else {}
        corroborator_count = int(synthesis.get("corroborating_seed_count") or 0) if isinstance(synthesis, dict) else 0
        corroborator_types = synthesis.get("corroborating_seed_types") if isinstance(synthesis, dict) else []
        type_preview = (
            ", ".join(str(item) for item in list(corroborator_types)[:3] if str(item).strip())
            if isinstance(corroborator_types, list)
            else ""
        )
        corroborated_by = str(corroborator_count)
        if type_preview:
            corroborated_by = f"{corroborated_by} ({type_preview})"
        sections["engagement_seeds"].append(
            {
                "Seed": str(row["seed_value"] or ""),
                "Type": str(row["seed_type"] or ""),
                "Source": str(row["source"] or ""),
                "Status": str(row["status"] or ""),
                "Depth": str(row["depth"] or ""),
                "Conf": str(row["confidence"] or ""),
                "Band": str(synthesis.get("confidence_band") or "") if isinstance(synthesis, dict) else "",
                "Relations": str(synthesis.get("supporting_relations") or 0) if isinstance(synthesis, dict) else "0",
                "CorroboratedBy": corroborated_by,
            }
        )

    sections["seed_relations"] = [
        {
            "From": f"{str(row['source_seed'] or '')} [{str(row['source_type'] or '')}]",
            "Relation": str(row["relation_type"] or ""),
            "To": f"{str(row['target_seed'] or '')} [{str(row['target_type'] or '')}]",
            "Conf": str(row["confidence"] or ""),
            "Evidence": _relation_evidence_preview(_safe_json_loads(str(row["evidence_json"] or "{}"))),
            "Seen": _format_dt(str(row["discovered_at"] or "")),
        }
        for row in _fetch_rows(
            con,
            """
            SELECT src.seed_value AS source_seed,
                   src.seed_type AS source_type,
                   tgt.seed_value AS target_seed,
                   tgt.seed_type AS target_type,
                   sr.relation_type,
                   sr.confidence,
                   sr.evidence_json,
                   sr.discovered_at
            FROM seed_relations sr
            JOIN engagement_seeds src ON src.id=sr.source_seed_id
            JOIN engagement_seeds tgt ON tgt.id=sr.target_seed_id
            WHERE sr.engagement_id=?
            ORDER BY sr.confidence DESC, sr.id DESC
            LIMIT ?
            """,
            (engagement_id, SECTION_LIMIT),
        )
    ]

    sections["seed_runs"] = [
        {
            "Seed": str(row["seed_value"] or ""),
            "Type": str(row["seed_type"] or ""),
            "Loop": str(row["loop_name"] or ""),
            "Status": str(row["status"] or ""),
            "In": str(row["input_count"] or ""),
            "Out": str(row["output_count"] or ""),
            "Started": _format_dt(str(row["started_at"] or "")),
            "Completed": _format_dt(str(row["completed_at"] or "")),
            "Error": _truncate(row["error"], 96),
        }
        for row in _fetch_rows(
            con,
            """
            SELECT es.seed_value,
                   es.seed_type,
                   sr.loop_name,
                   sr.status,
                   sr.input_count,
                   sr.output_count,
                   sr.started_at,
                   sr.completed_at,
                   sr.error
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=?
            ORDER BY sr.started_at DESC, sr.id DESC
            LIMIT ?
            """,
            (engagement_id, max(SECTION_LIMIT * 2, 20)),
        )
    ]

    engagement_run_rows = _fetch_rows(
        con,
        """
        SELECT id,
               run_kind,
               status,
               seed_value,
               seed_type,
               seed_count,
               max_iterations,
               current_iteration,
               resume_enabled,
               dry_run,
               attack_mode,
               metadata_json,
               started_at,
               completed_at,
               error
        FROM engagement_runs
        WHERE engagement_id=?
        ORDER BY started_at DESC, id DESC
        LIMIT ?
        """,
        (engagement_id, max(SECTION_LIMIT, 10)),
    )
    sections["engagement_runs"] = [
        _engagement_run_section_row(
            row,
            summarize_run_audit_manifest(
                con,
                db_path=db_path,
                engagement_id=engagement_id,
                run_id=int(row["id"]),
                verify=db_path is not None,
            ),
        )
        for row in engagement_run_rows
    ]

    sections["services"] = [
        {
            "Host": str(row["hostname"] or row["ip"] or ""),
            "Port": str(row["port"] or ""),
            "Proto": str(row["protocol"] or ""),
            "Service": str(row["service_name"] or ""),
            "Version": str(row["version"] or ""),
            "Seen": _format_dt(str(row["discovered_at"] or "")),
        }
        for row in _fetch_rows(
            con,
            """
            SELECT h.hostname, h.ip, s.port, s.protocol, s.service_name, s.version, s.discovered_at
            FROM services s
            JOIN hosts h ON h.id=s.host_id
            WHERE h.engagement_id=?
            ORDER BY s.id DESC
            LIMIT ?
            """,
            (engagement_id, SECTION_LIMIT),
        )
    ]

    key_finding_columns = _table_columns(con, "key_scanner_findings")
    key_validation_detail_expr = (
        "validation_detail"
        if "validation_detail" in key_finding_columns
        else "NULL AS validation_detail"
    )
    key_validated_at_expr = (
        "validated_at" if "validated_at" in key_finding_columns else "NULL AS validated_at"
    )
    key_source_backend_expr = (
        "source_backend"
        if "source_backend" in key_finding_columns
        else "NULL AS source_backend"
    )
    key_source_url_expr = (
        "source_url" if "source_url" in key_finding_columns else "NULL AS source_url"
    )
    key_repo_name_expr = (
        "repo_name" if "repo_name" in key_finding_columns else "NULL AS repo_name"
    )
    key_rows = _fetch_rows(
        con,
        f"""
        SELECT domain,
               service,
               pattern_name,
               validation_state,
               found_at,
               {key_source_backend_expr},
               {key_source_url_expr},
               {key_repo_name_expr},
               {key_validation_detail_expr},
               {key_validated_at_expr}
        FROM key_scanner_findings
        WHERE engagement_id=?
        ORDER BY id DESC
        LIMIT ?
        """,
        (engagement_id, SECTION_LIMIT),
    )
    sections["key_scanner_findings"] = []
    for row in key_rows:
        proof = parse_validated_detail(row["validation_detail"])
        sections["key_scanner_findings"].append(
            {
                "Domain": str(row["domain"] or ""),
                "Service": str(row["service"] or ""),
                "Pattern": str(row["pattern_name"] or ""),
                "State": str(row["validation_state"] or ""),
                "Backend": str(row["source_backend"] or ""),
                "Source": _truncate(row["source_url"], 96),
                "Repository": str(row["repo_name"] or ""),
                "Validation Status": str(proof["validation_status"] or ""),
                "Validation Method": str(proof["validation_method"] or ""),
                "Validation Proof": _truncate(proof["validation_proof"], 120),
                "Proof": _truncate(row["validation_detail"], 120),
                "Validated": _format_dt(str(row["validated_at"] or "")),
                "Seen": _format_dt(str(row["found_at"] or "")),
            }
        )

    artifact_queue_columns = _table_columns(con, "artifact_queue")
    artifact_local_path_expr = (
        "local_path" if "local_path" in artifact_queue_columns else "NULL AS local_path"
    )
    artifact_discovered_from_expr = (
        "discovered_from"
        if "discovered_from" in artifact_queue_columns
        else "NULL AS discovered_from"
    )
    sections["artifact_queue"] = [
        {
            "Artifact": str(row["source_url"] or ""),
            "Type": str(row["artifact_type"] or ""),
            "Status": str(row["status"] or ""),
            "Origin": str(row["discovered_from"] or ""),
            "Source": _crawl_source_summary(row["metadata_json"]),
            "Local": _truncate(row["local_path"], 96),
            "Meta": _artifact_metadata_brief(_safe_json_loads(str(row["metadata_json"] or "{}"))),
            "Notes": _truncate(row["notes"], 96),
            "Queued": _format_dt(str(row["queued_at"] or "")),
        }
        for row in _fetch_rows(
            con,
            f"""
            SELECT source_url,
                   artifact_type,
                   status,
                   notes,
                   metadata_json,
                   queued_at,
                   {artifact_local_path_expr},
                   {artifact_discovered_from_expr}
            FROM artifact_queue
            WHERE engagement_id=?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, SECTION_LIMIT),
        )
    ]

    sections["crawl_results"] = [
        {
            "URL": str(row["resolved_url"] or ""),
            "Source": _crawl_source_summary(row["tech_stack_json"]),
            "Title": str(row["title"] or ""),
            "Screenshot": str(row["screenshot_path"] or ""),
            "Tech": _preview_json(row["tech_stack_json"]),
            "Seen": _format_dt(str(row["discovered_at"] or "")),
        }
        for row in _fetch_rows(
            con,
            """
            SELECT COALESCE(final_url, url) AS resolved_url,
                   title,
                   screenshot_path,
                   tech_stack_json,
                   discovered_at
            FROM crawl_results
            WHERE engagement_id=?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, SECTION_LIMIT),
        )
    ]

    sections["social_profiles"] = [
        {
            "Email": str(row["email"] or ""),
            "Source": str(row["source"] or ""),
            "Details": _preview_json(row["profile_data"]),
            "Seen": _format_dt(str(row["queried_at"] or "")),
        }
        for row in _fetch_rows(
            con,
            """
            SELECT email, source, profile_data, queried_at
            FROM social_profiles
            WHERE engagement_id=?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, SECTION_LIMIT),
        )
    ]

    sections["port_scan_results"] = [
        {
            "Host": str(row["host"] or ""),
            "Port": str(row["port"] or ""),
            "Proto": str(row["proto"] or ""),
            "Service": str(row["service"] or ""),
            "Version": str(row["version"] or ""),
            "Conf": str(row["confidence"] or ""),
            "Seen": _format_dt(str(row["scanned_at"] or "")),
        }
        for row in _fetch_rows(
            con,
            """
            SELECT host, port, proto, service, version, confidence, scanned_at
            FROM port_scan_results
            WHERE engagement_id=?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, SECTION_LIMIT),
        )
    ]

    sections["passive_vulns"] = [
        {
            "Severity": str(row["severity"] or ""),
            "Plugin": str(row["plugin"] or ""),
            "Vuln": str(row["vuln_id"] or ""),
            "Verified": "yes" if int(row["verified"] or 0) else "no",
            "False+": "yes" if int(row["false_positive"] or 0) else "no",
            "URL": str(row["url"] or ""),
            "Seen": _format_dt(str(row["discovered_at"] or "")),
        }
        for row in _fetch_rows(
            con,
            """
            SELECT severity, plugin, vuln_id, verified, false_positive, url, discovered_at
            FROM passive_vulns
            WHERE engagement_id=?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, SECTION_LIMIT),
        )
    ]

    sections["vulnerability_findings"] = [
        {
            "Severity": str(row["severity"] or ""),
            "Type": str(row["vuln_type"] or ""),
            "Title": str(row["title"] or ""),
            "Target": str(row["target_url"] or ""),
            "Seen": _format_dt(str(row["found_at"] or "")),
        }
        for row in _reportable_vulnerability_rows(
            con,
            engagement_id,
            limit=SECTION_LIMIT,
        )
    ]

    sections["auth_test_results"] = [
        {
            "Target": str(row["target_url"] or ""),
            "Type": str(row["attack_type"] or ""),
            "Success": "yes" if int(row["success"] or 0) else "no",
            "Tested": _format_dt(str(row["tested_at"] or "")),
        }
        for row in _fetch_rows(
            con,
            """
            SELECT target_url, attack_type, success, tested_at
            FROM auth_test_results
            WHERE engagement_id=?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, SECTION_LIMIT),
        )
    ]

    validation_columns = _table_columns(con, "cloud_validation_results")
    validation_asset_expr = (
        "COALESCE(NULLIF(provider_identifier, ''), identifier) AS display_identifier"
        if "provider_identifier" in validation_columns
        else "identifier AS display_identifier"
    )
    sections["cloud_validation_results"] = [
        _cloud_validation_section_row(row)
        for row in _fetch_rows(
            con,
            f"""
            SELECT {validation_asset_expr},
                   asset_type,
                   validation_status,
                   validation_method,
                   http_status,
                   evidence,
                   notes,
                   checked_at
            FROM cloud_validation_results
            WHERE engagement_id=?
            ORDER BY COALESCE(checked_at, '') DESC, id DESC
            LIMIT ?
            """,
            (engagement_id, SECTION_LIMIT),
        )
    ]

    sections["audit_log"] = [
        {
            "When": _format_dt(str(row["logged_at"] or "")),
            "Phase": str(row["phase"] or ""),
            "Module": str(row["module"] or ""),
            "Action": str(row["action"] or ""),
            "Target": _truncate(row["target"], 96),
            "Result": _truncate(row["result"], 96),
        }
        for row in _fetch_rows(
            con,
            """
            SELECT logged_at, phase, module, action, target, result
            FROM audit_log
            WHERE engagement_id=?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, max(SECTION_LIMIT * 2, 20)),
        )
    ]

    return sections


def _engagement_summary(db_path: Path) -> dict[str, Any]:
    engagement_id_str = db_path.stem
    summary: dict[str, Any] = {
        "id": engagement_id_str,
        "slug": f"engagement-{engagement_id_str}",
        "name": "",
        "status": "",
        "operator": "",
        "tags": [],
        "created_at": "",
        "updated_at": "",
        "path": str(db_path),
        "size_bytes": db_path.stat().st_size,
        "scope": [],
        "seeds": [],
        "primary_seed": "",
        "latest_audit": "",
        "counts": {},
        "severity_summary": {severity: 0 for severity in SEVERITY_ORDER},
        "highest_severity": "INFO",
        "sections": {},
        "run_summary": None,
        "seed_graph_summary": {},
    }

    try:
        engagement_id = int(engagement_id_str)
    except ValueError:
        return summary

    con = _connect_readonly(db_path)
    if con is None:
        return summary

    try:
        if _table_exists(con, "engagements"):
            row = con.execute(
                """
                SELECT name, scope_json, status, operator, created_at, updated_at
                FROM engagements
                WHERE id=?
                """,
                (engagement_id,),
            ).fetchone()
            if row is not None:
                summary["name"] = str(row["name"] or "")
                summary["status"] = str(row["status"] or "")
                summary["operator"] = str(row["operator"] or "")
                summary["created_at"] = _format_dt(str(row["created_at"] or ""))
                summary["updated_at"] = _format_dt(str(row["updated_at"] or ""))
                scope = _safe_json_loads(str(row["scope_json"] or "[]"))
                summary["scope"] = scope if isinstance(scope, list) else []
                summary["tags"] = _engagement_tags(con, engagement_id)

        summary["counts"] = _summary_counts(con, engagement_id)
        summary["severity_summary"] = _severity_summary(con, engagement_id)
        summary["highest_severity"] = _highest_severity(summary["severity_summary"])
        summary["sections"] = _detail_sections(con, engagement_id, db_path=db_path)
        summary["run_summary"] = _latest_engagement_run(con, engagement_id, db_path=db_path)
        summary["seed_graph_summary"] = _seed_graph_summary(con, engagement_id)
        summary["seeds"] = _seed_list(con, engagement_id, summary["scope"])
        summary["primary_seed"] = summary["seeds"][0] if summary["seeds"] else ""

        latest_rows = _fetch_rows(
            con,
            """
            SELECT logged_at
            FROM audit_log
            WHERE engagement_id=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (engagement_id,),
        )
        latest = latest_rows[0] if latest_rows else None
        if latest is not None:
            summary["latest_audit"] = _format_dt(str(latest["logged_at"] or ""))
    finally:
        con.close()

    slug_source = summary["name"] or summary["primary_seed"] or f"engagement-{engagement_id_str}"
    summary["slug"] = f"engagement-{engagement_id_str}-{_slugify(slug_source)}"
    if not summary["name"]:
        summary["name"] = f"Engagement {engagement_id_str}"
    return summary


def _base_styles() -> str:
    return """
    :root{
      --bg:#0b1020;
      --panel:#11172a;
      --panel-alt:#16203a;
      --border:#26324f;
      --text:#e8edf7;
      --muted:#91a0bc;
      --accent:#66d9c2;
      --accent-strong:#97f6d2;
      --warn:#f7c95f;
      --danger:#ff7a7a;
      --good:#77d68a;
      --link:#8ec5ff;
      --shadow:0 18px 46px rgba(0,0,0,.30);
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      background:
        radial-gradient(circle at top right, rgba(102,217,194,.12), transparent 28%),
        radial-gradient(circle at top left, rgba(142,197,255,.10), transparent 24%),
        linear-gradient(180deg, #0a0f1d 0%, #0b1020 56%, #090d18 100%);
      color:var(--text);
      font:14px/1.5 "Segoe UI", Inter, system-ui, sans-serif;
    }
    a{color:var(--link);text-decoration:none}
    a:hover{text-decoration:underline}
    .shell{max-width:1400px;margin:0 auto;padding:28px 22px 40px}
    .hero{
      display:flex;justify-content:space-between;gap:18px;align-items:flex-end;
      margin-bottom:24px;padding:24px;border:1px solid var(--border);
      border-radius:20px;background:linear-gradient(160deg, rgba(17,23,42,.98), rgba(12,17,31,.88));
      box-shadow:var(--shadow);
    }
    .hero h1{margin:0 0 6px;font-size:34px;line-height:1.05;letter-spacing:-.03em}
    .subtle,.muted{color:var(--muted)}
    .hero-meta{text-align:right;min-width:180px}
    .hero-meta .stamp{font-size:12px;color:var(--muted)}
    .chips{display:flex;flex-wrap:wrap;gap:8px}
    .chip{
      display:inline-flex;gap:8px;align-items:center;padding:6px 10px;border-radius:999px;
      border:1px solid var(--border);background:rgba(255,255,255,.03);color:var(--text)
    }
    .chip code{background:none;padding:0;color:var(--accent-strong)}
    .stats{
      display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
      gap:12px;margin:18px 0 24px;
    }
    .stat{
      padding:14px 16px;border-radius:16px;border:1px solid var(--border);
      background:linear-gradient(180deg, rgba(17,23,42,.92), rgba(11,16,32,.92));
      box-shadow:var(--shadow);
    }
    .stat .label{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
    .stat .value{margin-top:6px;font-size:28px;font-weight:700;letter-spacing:-.03em}
    .panel{
      border:1px solid var(--border);border-radius:18px;background:rgba(17,23,42,.92);
      box-shadow:var(--shadow);overflow:hidden;
    }
    .panel-head{
      display:flex;justify-content:space-between;gap:12px;align-items:center;
      padding:16px 18px;border-bottom:1px solid var(--border);background:rgba(255,255,255,.02);
    }
    .panel-head h2,.panel-head h3{margin:0;font-size:15px;letter-spacing:.02em}
    .panel-body{padding:18px}
    table{width:100%;border-collapse:collapse}
    th{
      color:var(--muted);font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;
      text-align:left;padding:12px 12px 10px;border-bottom:1px solid var(--border);
      background:rgba(255,255,255,.02);position:sticky;top:0;
    }
    td{padding:11px 12px;border-bottom:1px solid rgba(255,255,255,.05);vertical-align:top}
    tbody tr:hover{background:rgba(255,255,255,.025)}
    .right{text-align:right}
    .mono{font-family:"Cascadia Code","JetBrains Mono",Consolas,monospace}
    .tiny{font-size:12px}
    .pill{
      display:inline-block;padding:3px 8px;border-radius:999px;border:1px solid var(--border);
      background:rgba(255,255,255,.04);font-size:11px;color:var(--text)
    }
    .pill.ok{color:var(--good);border-color:rgba(119,214,138,.35)}
    .pill.warn{color:var(--warn);border-color:rgba(247,201,95,.35)}
    .pill.danger{color:var(--danger);border-color:rgba(255,122,122,.35)}
    .pill.accent{color:var(--accent-strong);border-color:rgba(102,217,194,.35)}
    .search{
      width:min(440px,100%);padding:12px 14px;border-radius:12px;background:#0b1327;
      color:var(--text);border:1px solid var(--border);font:inherit;
    }
    .eng-link{
      display:inline-flex;align-items:center;gap:8px;padding:8px 12px;border-radius:10px;
      background:rgba(102,217,194,.12);border:1px solid rgba(102,217,194,.28);color:var(--accent-strong);
      font-weight:600;
    }
    .grid{
      display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px;
    }
    .meta-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
    .meta{
      padding:12px 14px;border-radius:14px;background:rgba(255,255,255,.03);border:1px solid var(--border)
    }
    .meta .k{display:block;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
    .meta .v{font-size:14px;word-break:break-word}
    .section-stack{display:flex;flex-direction:column;gap:16px}
    .artifact-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
    .artifact{
      padding:14px;border-radius:14px;border:1px solid var(--border);
      background:rgba(255,255,255,.03)
    }
    .artifact strong{display:block;margin-bottom:6px}
    .artifact-kind{
      display:inline-flex;align-items:center;padding:3px 8px;margin-bottom:8px;border-radius:999px;
      border:1px solid var(--border);background:rgba(255,255,255,.05);font-size:11px;text-transform:uppercase;
      letter-spacing:.08em;color:var(--muted)
    }
    .route-grid{
      display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px
    }
    .route-card{
      padding:18px;border-radius:16px;border:1px solid var(--border);
      background:linear-gradient(180deg, rgba(255,255,255,.035), rgba(255,255,255,.015))
    }
    .route-card h3{margin:0 0 10px;font-size:14px;letter-spacing:.03em}
    .route-card p{margin:0}
    .timeline{display:flex;flex-direction:column;gap:12px}
    .timeline-item{
      display:grid;grid-template-columns:120px 1fr;gap:14px;padding:14px;border-radius:14px;
      border:1px solid var(--border);background:rgba(255,255,255,.03)
    }
    .timeline-item .time{color:var(--muted);font-size:12px}
    .timeline-item strong{display:block;margin-bottom:4px}
    .graph-stage{
      position:relative;overflow:hidden;min-height:220px;padding:18px;border-radius:16px;
      border:1px solid rgba(102,217,194,.24);
      background:
        linear-gradient(180deg, rgba(8,17,34,.96), rgba(10,18,35,.88)),
        radial-gradient(circle at 20% 20%, rgba(102,217,194,.10), transparent 28%);
    }
    .graph-stage::before{
      content:"";position:absolute;inset:0;
      background:
        linear-gradient(rgba(142,197,255,.07) 1px, transparent 1px),
        linear-gradient(90deg, rgba(142,197,255,.07) 1px, transparent 1px);
      background-size:34px 34px;mask-image:linear-gradient(180deg, rgba(0,0,0,.8), transparent);
      pointer-events:none;
    }
    .graph-nodes{
      position:relative;z-index:1;display:flex;flex-wrap:wrap;gap:12px;align-items:flex-start
    }
    .graph-node{
      max-width:180px;padding:10px 12px;border-radius:14px;
      border:1px solid rgba(102,217,194,.26);background:rgba(102,217,194,.10);
      box-shadow:0 14px 34px rgba(0,0,0,.18)
    }
    .graph-node span{display:block;font-size:12px;line-height:1.4}
    .report-callout{display:flex;flex-direction:column;gap:10px}
    .report-callout .title{display:flex;justify-content:space-between;gap:12px;align-items:center}
    .report-callout .title strong{font-size:14px}
    .lane-grid{
      display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px
    }
    .lane{
      padding:14px;border-radius:14px;border:1px solid var(--border);background:rgba(255,255,255,.03)
    }
    .lane .eyebrow{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
    .lane .figure{margin-top:8px;font-size:26px;font-weight:700;letter-spacing:-.03em}
    pre{
      margin:10px 0 0;padding:14px;border-radius:12px;background:#09101f;border:1px solid var(--border);
      color:#dfe8f8;overflow:auto;white-space:pre-wrap;word-break:break-word;font:12px/1.45 "Cascadia Code","JetBrains Mono",Consolas,monospace;
      max-height:420px;
    }
    .empty{
      padding:18px;border:1px dashed var(--border);border-radius:14px;color:var(--muted);
      background:rgba(255,255,255,.02)
    }
    .toolbar{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}
    .backlink{display:inline-flex;align-items:center;gap:8px;color:var(--accent-strong);font-weight:600}
    .summary-line{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
    .hide{display:none}
    @media (max-width: 820px){
      .hero{flex-direction:column;align-items:flex-start}
      .hero-meta{text-align:left}
      .shell{padding:18px 14px 32px}
      .timeline-item{grid-template-columns:1fr}
    }
    """


def _render_overview_page(
    engagements: list[dict[str, Any]],
    output_path: Path,
    generated_at: str,
) -> str:
    total_reports = sum(len(item["report_files"]) for item in engagements)
    total_graphs = sum(1 for item in engagements if item["graph_files"])
    total_hosts = sum(int(item["counts"].get("hosts", 0)) for item in engagements)
    total_emails = sum(int(item["counts"].get("emails", 0)) for item in engagements)
    total_services = sum(int(item["counts"].get("services", 0)) for item in engagements)
    total_critical = sum(int(item["severity_summary"].get("CRITICAL", 0)) for item in engagements)
    total_high = sum(int(item["severity_summary"].get("HIGH", 0)) for item in engagements)
    status_options = sorted(
        {
            str(item.get("status") or "unknown").strip() or "unknown"
            for item in engagements
        },
        key=lambda value: value.lower(),
    )
    tag_options = sorted(
        {
            tag
            for item in engagements
            for tag in item.get("tags", [])
        },
        key=lambda value: value.casefold(),
    )

    rows: list[str] = []
    for item in engagements:
        detail_href = _relative_href(output_path, item["detail_page"])
        seed_text = ", ".join(item["seeds"][:2]) or item["primary_seed"] or "-"
        if len(item["seeds"]) > 2:
            seed_text = f"{seed_text} (+{len(item['seeds']) - 2})"
        graph_badge = (
            f'<span class="pill accent">nodes {item["graph_summary"].get("nodes", 0)}</span>'
            if item["graph_summary"]
            else '<span class="pill">none</span>'
        )
        status = item["status"] or "unknown"
        severity_text = _severity_summary_text(item["severity_summary"])
        latest_activity = item["latest_audit"] or item["updated_at"] or ""
        updated_ms = _timestamp_epoch_ms(latest_activity)
        severity_counts = item.get("severity_summary", {})
        finding_count = sum(int(severity_counts.get(level, 0) or 0) for level in SEVERITY_ORDER)
        tags = item.get("tags", [])
        tag_text = ", ".join(str(tag) for tag in tags)
        row_meta = str(item["operator"] or "-")
        if tag_text:
            row_meta = f"{row_meta} · {tag_text}"
        tag_keys = "|".join(str(tag).casefold() for tag in tags)
        rows.append(
            "<tr class='eng-row'"
            f" data-status='{html.escape(str(status))}'"
            f" data-severity='{html.escape(str(item['highest_severity']))}'"
            f" data-tags='{html.escape(tag_keys)}'"
            f" data-updated-ms='{updated_ms}'"
            f" data-finding-count='{finding_count}'>"
            f"<td><a class='eng-link' href='{html.escape(detail_href)}'>{html.escape(item['id'])}</a></td>"
            f"<td><strong>{html.escape(item['name'])}</strong><div class='tiny muted'>{html.escape(row_meta)}</div></td>"
            f"<td><span class='mono tiny'>{html.escape(seed_text)}</span></td>"
            f"<td><span class='pill'>{html.escape(status)}</span></td>"
            f"<td><span class='pill warn'>{html.escape(item['highest_severity'])}</span><div class='tiny muted'>{html.escape(severity_text)}</div></td>"
            f"<td class='right'>{int(item['counts'].get('hosts', 0))}</td>"
            f"<td class='right'>{int(item['counts'].get('emails', 0))}</td>"
            f"<td class='right'>{int(item['counts'].get('services', 0))}</td>"
            f"<td class='right'>{len(item['report_files'])}</td>"
            f"<td>{graph_badge}</td>"
            f"<td class='tiny'>{html.escape(item['latest_audit'] or item['updated_at'] or '-')}</td>"
            f"<td class='tiny mono'>{html.escape(item['slug'])}</td>"
            "</tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FORGE Dashboard</title>
  <style>{_base_styles()}</style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <div>
        <div class="chips">
          <span class="chip">FORGE engagement index</span>
          <span class="chip">detail pages per engagement</span>
        </div>
        <h1>Dashboard</h1>
        <p class="muted">The overview stays compact. Each engagement now opens into its own static page for reports, graph artifacts, audit history, and evidence tables.</p>
      </div>
      <div class="hero-meta">
        <div class="stamp">Generated</div>
        <div>{html.escape(generated_at)}</div>
        <div class="stamp">Entry file: {html.escape(output_path.name)}</div>
      </div>
    </section>

    <section class="stats">
      <div class="stat"><div class="label">Engagements</div><div class="value">{len(engagements)}</div></div>
      <div class="stat"><div class="label">Critical</div><div class="value">{total_critical}</div></div>
      <div class="stat"><div class="label">High</div><div class="value">{total_high}</div></div>
      <div class="stat"><div class="label">Reports</div><div class="value">{total_reports}</div></div>
      <div class="stat"><div class="label">Graphs</div><div class="value">{total_graphs}</div></div>
      <div class="stat"><div class="label">Hosts</div><div class="value">{total_hosts}</div></div>
      <div class="stat"><div class="label">Emails</div><div class="value">{total_emails}</div></div>
      <div class="stat"><div class="label">Services</div><div class="value">{total_services}</div></div>
    </section>

    <section class="panel">
      <div class="panel-head toolbar">
        <h2>Engagements</h2>
        <div>
          <input id="filter" class="search" type="search" placeholder="Filter by id, name, seed, operator, status, slug" oninput="filterRows()">
          <select id="status-filter" class="search" onchange="filterRows()">
            <option value="ALL">All statuses</option>
            {''.join(f"<option value='{html.escape(status)}'>{html.escape(status)}</option>" for status in status_options)}
          </select>
          <select id="severity-filter" class="search" onchange="filterRows()">
            <option value="ALL">All severities</option>
            <option value="CRITICAL">Has critical</option>
            <option value="HIGH_PLUS">Has high or critical</option>
            <option value="MEDIUM_PLUS">Has medium or above</option>
            <option value="FINDINGS">Any finding rows</option>
          </select>
          <select id="tag-filter" class="search" onchange="filterRows()">
            <option value="ALL">All tags</option>
            {''.join(f"<option value='{html.escape(tag.casefold())}'>{html.escape(tag)}</option>" for tag in tag_options)}
          </select>
          <input id="updated-after-filter" class="search" type="date" onchange="filterRows()" oninput="filterRows()" title="Updated on or after">
          <input id="updated-before-filter" class="search" type="date" onchange="filterRows()" oninput="filterRows()" title="Updated on or before">
          <select id="recency-filter" class="search" onchange="filterRows()">
            <option value="ALL">Any recency</option>
            <option value="24H">Updated in 24h</option>
            <option value="7D">Updated in 7d</option>
            <option value="30D">Updated in 30d</option>
            <option value="STALE_30D">Stale over 30d</option>
          </select>
          <span id="filter-state" class="tiny muted"></span>
        </div>
      </div>
      <div class="panel-body" style="padding:0">
        <table id="engagement-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Seeds</th>
              <th>Status</th>
              <th>Severity</th>
              <th class="right">Hosts</th>
              <th class="right">Emails</th>
              <th class="right">Services</th>
              <th class="right">Reports</th>
              <th>Graph</th>
              <th>Latest audit</th>
              <th>Slug</th>
            </tr>
          </thead>
          <tbody>
            {''.join(rows) if rows else '<tr><td colspan="12"><div class="empty">No engagement databases were found.</div></td></tr>'}
          </tbody>
        </table>
      </div>
    </section>
  </div>

  <script>
    const OVERVIEW_FILTERS_KEY = 'forge.overviewFilters';
    function readSavedFilters() {{
      try {{
        const raw = window.localStorage.getItem(OVERVIEW_FILTERS_KEY);
        if (!raw) return {{}};
        const parsed = JSON.parse(raw);
        return parsed && typeof parsed === 'object' ? parsed : {{}};
      }} catch (_error) {{
        return {{}};
      }}
    }}
    function writeSavedFilters(state) {{
      try {{
        const isDefaultState =
          !state.q &&
          (state.statusFilter || 'ALL') === 'ALL' &&
          (state.severityFilter || 'ALL') === 'ALL' &&
          (state.tagFilter || 'ALL') === 'ALL' &&
          !state.updatedAfterValue &&
          !state.updatedBeforeValue &&
          (state.recencyFilter || 'ALL') === 'ALL';
        if (isDefaultState) {{
          window.localStorage.removeItem(OVERVIEW_FILTERS_KEY);
          return;
        }}
        window.localStorage.setItem(OVERVIEW_FILTERS_KEY, JSON.stringify(state));
      }} catch (_error) {{
        return;
      }}
    }}
    function applySavedFilters() {{
      const saved = readSavedFilters();
      const textFilter = document.getElementById('filter');
      const statusFilter = document.getElementById('status-filter');
      const severityFilter = document.getElementById('severity-filter');
      const tagFilter = document.getElementById('tag-filter');
      const updatedAfterFilter = document.getElementById('updated-after-filter');
      const updatedBeforeFilter = document.getElementById('updated-before-filter');
      const recencyFilter = document.getElementById('recency-filter');
      if (typeof saved.q === 'string') textFilter.value = saved.q;
      if (typeof saved.statusFilter === 'string') statusFilter.value = saved.statusFilter;
      if (typeof saved.severityFilter === 'string') severityFilter.value = saved.severityFilter;
      if (typeof saved.tagFilter === 'string') tagFilter.value = saved.tagFilter;
      if (typeof saved.updatedAfterValue === 'string') updatedAfterFilter.value = saved.updatedAfterValue;
      if (typeof saved.updatedBeforeValue === 'string') updatedBeforeFilter.value = saved.updatedBeforeValue;
      if (typeof saved.recencyFilter === 'string') recencyFilter.value = saved.recencyFilter;
    }}
    function filterRows() {{
      const q = document.getElementById('filter').value.toLowerCase().trim();
      const statusFilter = document.getElementById('status-filter').value;
      const severityFilter = document.getElementById('severity-filter').value;
      const tagFilter = document.getElementById('tag-filter').value;
      const updatedAfterValue = document.getElementById('updated-after-filter').value;
      const updatedBeforeValue = document.getElementById('updated-before-filter').value;
      const recencyFilter = document.getElementById('recency-filter').value;
      const rows = Array.from(document.querySelectorAll('#engagement-table tbody tr.eng-row'));
      const now = Date.now();
      const updatedAfterMs = updatedAfterValue ? Date.parse(`${{updatedAfterValue}}T00:00:00`) : 0;
      const updatedBeforeMs = updatedBeforeValue ? Date.parse(`${{updatedBeforeValue}}T23:59:59.999`) : 0;
      let visible = 0;
      rows.forEach((row) => {{
        const status = (row.dataset.status || 'unknown').trim();
        const highestSeverity = (row.dataset.severity || 'INFO').trim().toUpperCase();
        const rowTags = (row.dataset.tags || '').split('|').filter(Boolean);
        const findingCount = Number(row.dataset.findingCount || '0');
        const updatedMs = Number(row.dataset.updatedMs || '0');
        const statusMatch = statusFilter === 'ALL' || status === statusFilter;
        const severityMatch =
          severityFilter === 'ALL' ||
          (severityFilter === 'CRITICAL' && highestSeverity === 'CRITICAL') ||
          (severityFilter === 'HIGH_PLUS' && ['CRITICAL', 'HIGH'].includes(highestSeverity)) ||
          (severityFilter === 'MEDIUM_PLUS' && ['CRITICAL', 'HIGH', 'MEDIUM'].includes(highestSeverity)) ||
          (severityFilter === 'FINDINGS' && findingCount > 0);
        const tagMatch = tagFilter === 'ALL' || rowTags.includes(tagFilter);
        const dateRangeMatch =
          (!updatedAfterValue || (updatedMs > 0 && !Number.isNaN(updatedAfterMs) && updatedMs >= updatedAfterMs)) &&
          (!updatedBeforeValue || (updatedMs > 0 && !Number.isNaN(updatedBeforeMs) && updatedMs <= updatedBeforeMs));
        const recencyMatch =
          recencyFilter === 'ALL' ||
          (recencyFilter === '24H' && updatedMs > 0 && now - updatedMs <= 24 * 60 * 60 * 1000) ||
          (recencyFilter === '7D' && updatedMs > 0 && now - updatedMs <= 7 * 24 * 60 * 60 * 1000) ||
          (recencyFilter === '30D' && updatedMs > 0 && now - updatedMs <= 30 * 24 * 60 * 60 * 1000) ||
          (recencyFilter === 'STALE_30D' && (!updatedMs || now - updatedMs > 30 * 24 * 60 * 60 * 1000));
        const searchableText = `${{row.textContent}} ${{row.dataset.tags || ''}}`.toLowerCase();
        const queryMatch = !q || searchableText.includes(q);
        const match = statusMatch && severityMatch && tagMatch && dateRangeMatch && recencyMatch && queryMatch;
        row.classList.toggle('hide', !match);
        if (match) visible += 1;
      }});
      writeSavedFilters({{
        q,
        statusFilter,
        severityFilter,
        tagFilter,
        updatedAfterValue,
        updatedBeforeValue,
        recencyFilter,
      }});
      document.getElementById('filter-state').textContent = `${{visible}} / ${{rows.length}} match`;
    }}
    applySavedFilters();
    filterRows();
  </script>
</body>
</html>
"""


def _render_meta_block(label: str, value: str, mono: bool = False) -> str:
    class_name = "v mono" if mono else "v"
    return (
        '<div class="meta">'
        f'<span class="k">{html.escape(label)}</span>'
        f'<span class="{class_name}">{html.escape(value or "-")}</span>'
        "</div>"
    )


def _render_table(title: str, rows: list[dict[str, str]]) -> str:
    if not rows:
        return (
            '<section class="panel">'
            f'<div class="panel-head"><h3>{html.escape(title)}</h3></div>'
            '<div class="panel-body"><div class="empty">No rows captured for this section.</div></div>'
            "</section>"
        )

    headers = list(rows[0].keys())
    header_html = "".join(f"<th>{html.escape(head)}</th>" for head in headers)
    body_html = []
    for row in rows:
        body_html.append(
            "<tr>" + "".join(
                f"<td>{html.escape(str(row.get(head, '')))}</td>" for head in headers
            ) + "</tr>"
        )
    return (
        '<section class="panel">'
        f'<div class="panel-head"><h3>{html.escape(title)}</h3></div>'
        '<div class="panel-body" style="padding:0">'
        f"<table><thead><tr>{header_html}</tr></thead><tbody>{''.join(body_html)}</tbody></table>"
        "</div></section>"
    )


def _render_artifact_card(page_path: Path, artifact: Path, kind: str) -> str:
    href = _relative_href(page_path, artifact)
    return (
        '<div class="artifact">'
        f"<span class=\"artifact-kind\">{html.escape(kind)}</span>"
        f"<strong><a href=\"{html.escape(href)}\">{html.escape(artifact.name)}</a></strong>"
        f"<div class=\"tiny muted\">{html.escape(_format_size(artifact.stat().st_size))}</div>"
        f"<div class=\"tiny muted\">{html.escape(_format_dt(datetime.fromtimestamp(artifact.stat().st_mtime).isoformat()))}</div>"
        "</div>"
    )


def _report_export_sort_key(path: Path) -> tuple[int, str]:
    order = {
        ".md": 0,
        ".pdf": 1,
        ".json": 2,
        ".csv": 3,
    }
    return (order.get(path.suffix.lower(), 99), path.name.lower())


def _report_export_descriptor(path: Path, *, raw_export: bool) -> dict[str, str]:
    suffix = path.suffix.lower()
    if suffix == ".md":
        label = "Markdown"
        format_name = "markdown"
    elif suffix == ".pdf":
        label = "PDF"
        format_name = "pdf"
    elif suffix == ".csv":
        label = "CSV"
        format_name = "csv"
    elif suffix == ".json":
        label = "Raw JSON" if raw_export else "Report JSON"
        format_name = "raw_json" if raw_export else "report_json"
    else:
        label = suffix.lstrip(".").upper() or path.name
        format_name = suffix.lstrip(".").lower() or "artifact"
    return {
        "artifact_name": path.name,
        "format": format_name,
        "label": label,
    }


def _report_family_groups(report_files: list[Path]) -> list[tuple[str, list[Path]]]:
    families: dict[str, list[Path]] = {}
    family_mtimes: dict[str, float] = {}
    family_has_json: dict[str, bool] = {}
    for artifact in report_files:
        try:
            stat = artifact.stat()
        except OSError:
            continue
        families.setdefault(artifact.stem, []).append(artifact)
        family_mtimes[artifact.stem] = max(family_mtimes.get(artifact.stem, 0.0), stat.st_mtime)
        family_has_json[artifact.stem] = family_has_json.get(artifact.stem, False) or artifact.suffix.lower() == ".json"
    grouped = [
        (
            stem,
            sorted(artifacts, key=_report_export_sort_key),
        )
        for stem, artifacts in families.items()
    ]
    grouped.sort(
        key=lambda item: (
            family_mtimes.get(item[0], 0.0),
            family_has_json.get(item[0], False),
            item[0].lower(),
        ),
        reverse=True,
    )
    return grouped


def _report_payload_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _report_payload_value(
    payload: dict[str, Any],
    lineage: dict[str, Any],
    *keys: str,
) -> str:
    for source in (payload, lineage):
        for key in keys:
            value = source.get(key)
            if value not in ("", None):
                return str(value).strip()
    return ""


def _report_history_payload(report_files: list[Path]) -> list[dict[str, Any]]:
    history: list[dict[str, Any]] = []
    for family_stem, family_files in _report_family_groups(report_files):
        json_candidates = [path for path in family_files if path.suffix.lower() == ".json"]
        json_candidates.sort(
            key=lambda artifact: (artifact.stat().st_mtime, artifact.name.lower()),
            reverse=True,
        )
        parsed_payload: dict[str, Any] | None = None
        artifact_name = family_files[0].name if family_files else ""
        for artifact in json_candidates:
            try:
                payload = json.loads(artifact.read_text(encoding="utf-8", errors="replace"))
            except Exception:  # noqa: BLE001
                continue
            if isinstance(payload, dict):
                parsed_payload = payload
                artifact_name = artifact.name
                break

        payload = parsed_payload or {}
        lineage = _report_payload_mapping(payload.get("report_lineage"))
        provider = _report_payload_value(payload, lineage, "provider", "rendered_provider")
        requested_provider = _report_payload_value(payload, lineage, "requested_provider")
        upstream_provider = _report_payload_value(payload, lineage, "upstream_provider")
        rendered_provider = _report_payload_value(lineage, payload, "rendered_provider", "render_backend", "provider")
        fallback_reason = _report_payload_value(payload, lineage, "fallback_reason")
        report_write_error = _report_payload_value(payload, lineage, "report_write_error", "write_error")
        format_name = _report_payload_value(payload, lineage, "format")
        findings_checksum = _report_payload_value(payload, lineage, "findings_checksum")
        raw_export = provider == "raw_export"
        render_backend = upstream_provider if raw_export and upstream_provider else rendered_provider
        latest_mtime = max(
            (path.stat().st_mtime for path in family_files),
            default=0.0,
        )
        generated_at = _format_dt(_report_payload_value(payload, lineage, "generated_at"))
        if not generated_at and latest_mtime:
            generated_at = _format_dt(datetime.fromtimestamp(latest_mtime).isoformat())
        available_exports = [
            _report_export_descriptor(path, raw_export=raw_export)
            for path in family_files
        ]
        history.append(
            {
                "family_stem": family_stem,
                "artifact_name": artifact_name,
                "provider": provider,
                "requested_provider": requested_provider,
                "render_backend": render_backend,
                "rendered_provider": rendered_provider,
                "upstream_provider": upstream_provider,
                "format": format_name,
                "generated_at": generated_at,
                "fallback_reason": fallback_reason,
                "report_write_error": report_write_error,
                "findings_checksum": findings_checksum,
                "raw_export": raw_export,
                "export_count": len(available_exports),
                "available_exports": available_exports,
            }
        )
    return history


def _report_summary_payload(report_files: list[Path]) -> dict[str, Any] | None:
    history = _report_history_payload(report_files)
    return history[0] if history else None


def _latest_report_family_files(report_files: list[Path]) -> list[Path]:
    groups = _report_family_groups(report_files)
    if not groups:
        return []
    return groups[0][1]


def _render_report_history(report_history: list[dict[str, Any]]) -> str:
    if len(report_history) <= 1:
        return ""
    items: list[str] = []
    for family in report_history[1:6]:
        exports = "".join(
            f"<span class='pill'>{html.escape(str(item.get('label') or item.get('format') or 'artifact'))}</span>"
            for item in family.get("available_exports") or []
            if isinstance(item, dict)
        )
        meta = "".join(
            (
                _render_meta_block("Generated", str(family.get("generated_at") or "-")),
                _render_meta_block("Rendered", str(family.get("render_backend") or family.get("provider") or "-")),
                _render_meta_block("Exports", str(family.get("export_count") or 0)),
            )
        )
        detail_lines = []
        if family.get("fallback_reason"):
            detail_lines.append(
                f"<div class='tiny muted'>Fallback reason: {html.escape(str(family['fallback_reason']))}</div>"
            )
        if family.get("report_write_error"):
            detail_lines.append(
                f"<div class='tiny muted'>Write degradation: {html.escape(str(family['report_write_error']))}</div>"
            )
        if family.get("findings_checksum"):
            detail_lines.append(
                f"<div class='tiny mono'>Checksum {html.escape(_truncate(str(family['findings_checksum']), 96))}</div>"
            )
        items.append(
            "<div class='route-card'>"
            f"<strong>{html.escape(str(family.get('artifact_name') or '-'))}</strong>"
            f"<div class='meta-list' style='margin-top:10px'>{meta}</div>"
            + (
                f"<div style='display:flex;flex-wrap:wrap;gap:8px;margin-top:10px'>{exports}</div>"
                if exports
                else ""
            )
            + "".join(detail_lines)
            + "</div>"
        )
    return (
        '<section class="panel">'
        '<div class="panel-head"><h2>Report History</h2></div>'
        f"<div class='panel-body'><div class='section-stack'>{''.join(items)}</div></div>"
        "</section>"
    )


def _render_report_preview(page_path: Path, artifact: Path) -> str:
    try:
        preview = artifact.read_text(encoding="utf-8", errors="replace")[:7000]
    except Exception:  # noqa: BLE001
        preview = "(unreadable)"
    href = _relative_href(page_path, artifact)
    return (
        '<section class="panel">'
        f'<div class="panel-head"><h3><a href="{html.escape(href)}">{html.escape(artifact.name)}</a></h3></div>'
        f'<div class="panel-body"><pre>{html.escape(preview)}</pre></div>'
        "</section>"
    )


def _render_report_backend_summary(summary: dict[str, Any] | None) -> str:
    if not summary:
        return ""
    meta_blocks = [
        _render_meta_block("Requested", str(summary.get("requested_provider") or "-")),
        _render_meta_block("Rendered", str(summary.get("render_backend") or "-")),
        _render_meta_block("Exported", str(summary.get("provider") or "-")),
        _render_meta_block("Format", str(summary.get("format") or "-")),
        _render_meta_block("Generated", str(summary.get("generated_at") or "-")),
    ]
    if summary.get("artifact_name"):
        meta_blocks.append(_render_meta_block("Artifact", str(summary.get("artifact_name") or "-"), mono=True))
    lines = [f"<div class='meta-list'>{''.join(meta_blocks)}</div>"]
    available_exports = summary.get("available_exports") or []
    if available_exports:
        chips = "".join(
            f"<span class='pill'>{html.escape(str(item.get('label') or item.get('format') or 'artifact'))}</span>"
            for item in available_exports
            if isinstance(item, dict)
        )
        if chips:
            lines.append(
                "<div style='display:flex;flex-direction:column;gap:8px;margin-top:12px'>"
                "<div class='tiny muted'>Exports</div>"
                f"<div style='display:flex;flex-wrap:wrap;gap:8px'>{chips}</div>"
                "</div>"
            )
    if summary.get("fallback_reason"):
        lines.append(
            f"<p class='tiny muted'>Fallback reason: {html.escape(str(summary['fallback_reason']))}</p>"
        )
    if summary.get("report_write_error"):
        lines.append(
            f"<p class='tiny muted'>Write degradation: {html.escape(str(summary['report_write_error']))}</p>"
        )
    if summary.get("findings_checksum"):
        lines.append(
            f"<p class='tiny mono'>Checksum {html.escape(_truncate(str(summary['findings_checksum']), 96))}</p>"
        )
    return "".join(lines)


def _render_graph_summary(summary: dict[str, Any]) -> str:
    if not summary:
        return '<div class="empty">No attack-graph summary could be derived.</div>'
    chips = [
        f'<span class="pill accent">nodes {int(summary.get("nodes", 0))}</span>',
        f'<span class="pill accent">edges {int(summary.get("edges", 0))}</span>',
        f'<span class="pill warn">critical {int(summary.get("critical_nodes", 0))}</span>',
    ]
    if summary.get("critical_weight") is not None:
        chips.append(f'<span class="pill">{html.escape(str(summary["critical_weight"]))} weight</span>')
    entity_chips = "".join(
        f'<span class="pill">{html.escape(str(kind))} {count}</span>'
        for kind, count in summary.get("entity_types", [])
    )
    sample_nodes = "".join(
        f"<li class='mono tiny'>{html.escape(_truncate(label, 120))}</li>"
        for label in summary.get("sample_nodes", [])
    )
    entity_chip_block = entity_chips or '<span class="pill">no entity types</span>'
    return (
        "<div>"
        f"<div class='summary-line'>{''.join(chips)}</div>"
        f"<div class='chips' style='margin-top:10px'>{entity_chip_block}</div>"
        f"<div class='tiny muted' style='margin-top:12px'>Source: {html.escape(str(summary.get('source', '-')))}</div>"
        f"<ul>{sample_nodes}</ul>"
        "</div>"
    )


def _render_graph_stage(summary: dict[str, Any]) -> str:
    if not summary:
        return '<div class="empty">No graph artifact is available yet. When `forge graph build` runs, this slot becomes the engagement-level Maltego workspace.</div>'
    nodes = summary.get("sample_nodes", [])[:6]
    node_markup = "".join(
        f"<div class='graph-node'><span>{html.escape(_truncate(label, 84))}</span></div>"
        for label in nodes
    )
    if not node_markup:
        node_markup = "<div class='graph-node'><span>Awaiting labeled nodes from GraphML or JSON output.</span></div>"
    return (
        "<div class='graph-stage'>"
        f"<div class='graph-nodes'>{node_markup}</div>"
        "</div>"
    )


def _render_audit_timeline(rows: list[dict[str, str]]) -> str:
    if not rows:
        return '<div class="empty">No audit activity has been recorded for this engagement yet.</div>'
    items = []
    for row in rows[:8]:
        action = row.get("Action", "")
        phase = row.get("Phase", "")
        module = row.get("Module", "")
        result = row.get("Result", "")
        target = row.get("Target", "")
        items.append(
            "<div class='timeline-item'>"
            f"<div class='time mono'>{html.escape(row.get('When', '-'))}</div>"
            "<div>"
            f"<strong>{html.escape(action or 'event')}</strong>"
            f"<div class='tiny muted'>{html.escape(phase)} · {html.escape(module)}</div>"
            f"<div class='tiny'>{html.escape(target)}</div>"
            f"<div class='tiny muted'>{html.escape(result)}</div>"
            "</div>"
            "</div>"
        )
    return f"<div class='timeline'>{''.join(items)}</div>"


def _render_report_callout(
    previews: list[dict[str, str]],
    report_summary: dict[str, Any] | None = None,
) -> str:
    backend_summary = _render_report_backend_summary(report_summary)
    if not previews:
        empty_state = (
            '<div class="empty">No markdown executive report is available yet. '
            "If Phase 6 fell back to JSON or raw structured export, the backend summary and artifacts above still show what rendered.</div>"
        )
        return f"<div class='report-callout'>{backend_summary}{empty_state}</div>"
    preview = previews[0]
    return (
        "<div class='report-callout'>"
        "<div class='title'>"
        f"<strong>{html.escape(preview['name'])}</strong>"
        f"<a class='tiny mono' href=\"{html.escape(preview['href'])}\">open artifact</a>"
        "</div>"
        f"{backend_summary}"
        "<p class='tiny muted'>Executive narrative preview</p>"
        f"<pre>{html.escape(preview['preview'])}</pre>"
        "</div>"
    )


def _render_engagement_page(
    engagement: dict[str, Any],
    index_path: Path,
    page_path: Path,
) -> str:
    counts = engagement["counts"]
    severity_summary = engagement.get("severity_summary", {})
    highest_severity = engagement.get("highest_severity", "INFO")
    graph_files = engagement["graph_files"]
    report_files = engagement["report_files"]
    audit_files = engagement.get("audit_files", [])
    run_summary = engagement.get("run_summary") or {}
    meta_blocks = [
        _render_meta_block("Engagement ID", engagement["id"], mono=True),
        _render_meta_block("Slug", engagement["slug"], mono=True),
        _render_meta_block("Status", engagement["status"] or "unknown"),
        _render_meta_block("Operator", engagement["operator"] or "-"),
        _render_meta_block("Tags", ", ".join(engagement.get("tags", [])) or "-"),
        _render_meta_block("Created", engagement["created_at"] or "-"),
        _render_meta_block("Updated", engagement["updated_at"] or "-"),
        _render_meta_block("Latest audit", engagement["latest_audit"] or "-"),
        _render_meta_block(
            "Latest run",
            (
                f"{run_summary.get('run_kind', '-')}: "
                f"{run_summary.get('status', '-')}"
                f" ({run_summary.get('current_iteration', 0)}/{run_summary.get('max_iterations', 0)})"
                if run_summary
                else "-"
            ),
        ),
        _render_meta_block("Database", engagement["path"], mono=True),
    ]

    scope_html = (
        '<div class="chips">'
        + "".join(f'<span class="chip"><code>{html.escape(str(item))}</code></span>' for item in engagement["scope"])
        + "</div>"
        if engagement["scope"]
        else '<div class="empty">No explicit scope entries stored in the engagement metadata.</div>'
    )
    seed_html = (
        '<div class="chips">'
        + "".join(f'<span class="chip"><code>{html.escape(str(seed))}</code></span>' for seed in engagement["seeds"])
        + "</div>"
        if engagement["seeds"]
        else '<div class="empty">No seed history found for this engagement.</div>'
    )

    artifact_cards = (
        "".join(_render_artifact_card(page_path, path, "report") for path in report_files)
        + "".join(_render_artifact_card(page_path, path, "graph") for path in graph_files)
        + "".join(_render_artifact_card(page_path, path, "audit") for path in audit_files)
    )
    artifact_block = (
        artifact_cards
        or '<div class="empty">No report, graph, or audit artifacts were found beside the engagement DB.</div>'
    )

    latest_report_files = _latest_report_family_files(report_files)
    preview_files = [path for path in latest_report_files if path.suffix.lower() == ".md"]
    report_previews = "".join(_render_report_preview(page_path, path) for path in preview_files)
    if not report_previews:
        report_previews = (
            '<section class="panel">'
            '<div class="panel-head"><h3>Report previews</h3></div>'
            '<div class="panel-body"><div class="empty">No markdown reports matched this engagement id.</div></div>'
            "</section>"
        )
    report_payloads = [_report_preview_payload(page_path, path) for path in preview_files]
    report_summary = engagement.get("report_summary")

    section_titles = {
        "hosts": "Recent Hosts",
        "emails": "Recent Emails",
        "email_intelligence": "Email Intelligence",
        "account_existence": "Account Existence",
        "engagement_seeds": "Engagement Seeds",
        "seed_runs": "Recent Seed Runs",
        "engagement_runs": "Recent Engagement Runs",
        "services": "Recent Services",
        "key_scanner_findings": "Recent Key Findings",
        "artifact_queue": "Queued Artifacts",
        "crawl_results": "Recent Web Crawl Results",
        "social_profiles": "Recent Social Profiles",
        "port_scan_results": "Recent Port Scan Results",
        "passive_vulns": "Recent Passive Vulnerabilities",
        "vulnerability_findings": "Recent Vulnerability Findings",
        "auth_test_results": "Recent Auth Test Results",
        "cloud_validation_results": "Cloud Validation Results",
        "audit_log": "Recent Audit Log",
    }
    evidence_sections = "".join(
        _render_table(section_titles[key], engagement["sections"].get(key, []))
        for key in section_titles
    )
    timeline_html = _render_audit_timeline(engagement["sections"].get("audit_log", []))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FORGE {html.escape(engagement['id'])}</title>
  <style>{_base_styles()}</style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <div>
        <a class="backlink" href="{html.escape(_relative_href(page_path, index_path))}">← Back to dashboard</a>
        <div class="chips" style="margin-top:14px">
          <span class="chip">engagement {html.escape(engagement['id'])}</span>
          <span class="chip">{html.escape(engagement['status'] or 'unknown')}</span>
          <span class="chip">{len(report_files)} reports</span>
          <span class="chip">{len(graph_files)} graph artifacts</span>
          <span class="chip">{len(audit_files)} audit artifacts</span>
          {''.join(f'<span class="chip">{html.escape(str(tag))}</span>' for tag in engagement.get('tags', []))}
        </div>
        <h1>{html.escape(engagement['name'])}</h1>
        <p class="muted">Primary seed: <span class="mono">{html.escape(engagement['primary_seed'] or '-')}</span></p>
      </div>
      <div class="hero-meta">
        <div class="stamp">Latest audit</div>
        <div>{html.escape(engagement['latest_audit'] or engagement['updated_at'] or '-')}</div>
        <div class="stamp">DB size: {html.escape(_format_size(int(engagement['size_bytes'] or 0)))}</div>
      </div>
    </section>

    <section class="stats">
      <div class="stat"><div class="label">Hosts</div><div class="value">{int(counts.get('hosts', 0))}</div></div>
      <div class="stat"><div class="label">Emails</div><div class="value">{int(counts.get('emails', 0))}</div></div>
      <div class="stat"><div class="label">Services</div><div class="value">{int(counts.get('services', 0))}</div></div>
      <div class="stat"><div class="label">Highest severity</div><div class="value">{html.escape(str(highest_severity))}</div></div>
      <div class="stat"><div class="label">Critical / High</div><div class="value">{int(severity_summary.get('CRITICAL', 0))} / {int(severity_summary.get('HIGH', 0))}</div></div>
      <div class="stat"><div class="label">Audit rows</div><div class="value">{int(counts.get('audit_log', 0))}</div></div>
      <div class="stat"><div class="label">Run status</div><div class="value">{html.escape(str(run_summary.get('status', 'untracked')))}</div></div>
    </section>

    <div class="section-stack">
      <section class="panel">
        <div class="panel-head"><h2>Metadata</h2></div>
        <div class="panel-body">
          <div class="meta-list">{''.join(meta_blocks)}</div>
        </div>
      </section>

      <section class="panel">
        <div class="panel-head"><h2>Engagement Lanes</h2></div>
        <div class="panel-body">
          <div class="lane-grid">
            <div class="lane">
              <div class="eyebrow">Inputs</div>
              <div class="figure">{len(engagement["seeds"])}</div>
              <div class="tiny muted">Tracked seeds</div>
            </div>
            <div class="lane">
              <div class="eyebrow">Surface</div>
              <div class="figure">{int(counts.get('hosts', 0)) + int(counts.get('emails', 0))}</div>
              <div class="tiny muted">Hosts + emails</div>
            </div>
            <div class="lane">
              <div class="eyebrow">Signals</div>
              <div class="figure">{int(sum(int(severity_summary.get(level, 0)) for level in SEVERITY_ORDER))}</div>
              <div class="tiny muted">Severity-scored findings</div>
            </div>
            <div class="lane">
              <div class="eyebrow">Evidence</div>
              <div class="figure">{len(report_files) + len(graph_files) + len(audit_files)}</div>
              <div class="tiny muted">Artifacts linked here</div>
            </div>
          </div>
        </div>
      </section>

      <div class="route-grid">
        <section class="panel">
          <div class="panel-head"><h3>Route Inputs</h3></div>
          <div class="panel-body">
            <div class="route-card">
              <h3>Seeds</h3>
              {seed_html}
            </div>
            <div class="route-card" style="margin-top:14px">
              <h3>Scope</h3>
              {scope_html}
            </div>
          </div>
        </section>
        <section class="panel">
          <div class="panel-head"><h3>Executive Report</h3></div>
          <div class="panel-body">
            {_render_report_callout(report_payloads, report_summary)}
          </div>
        </section>
        <section class="panel">
          <div class="panel-head"><h3>Maltego Workspace</h3></div>
          <div class="panel-body">
            {_render_graph_stage(engagement["graph_summary"])}
            <p class="tiny muted" style="margin-top:14px">This route is reserved for the interactive graph view. Until the richer client lands, the page exposes the graph summary plus direct MTGX and GraphML artifact links.</p>
          </div>
        </section>
      </div>

      <section class="panel">
        <div class="panel-head"><h2>Artifacts</h2></div>
        <div class="panel-body">
          <div class="artifact-list">{artifact_block}</div>
        </div>
      </section>

      <section class="panel">
        <div class="panel-head"><h2>Attack Graph</h2></div>
          <div class="panel-body">
            {_render_graph_summary(engagement["graph_summary"])}
          <p class="tiny muted" style="margin-top:14px">MTGX is the native Maltego workspace artifact, while GraphML remains the lightweight import/export path. The page links above keep both visible instead of burying them in the report directory.</p>
        </div>
      </section>

      <section class="panel">
        <div class="panel-head"><h2>Audit Timeline</h2></div>
        <div class="panel-body">
          {timeline_html}
        </div>
      </section>

      {evidence_sections}

      {_render_report_history(_report_history_payload(report_files))}

      {report_previews}
    </div>
  </div>
</body>
</html>
"""


def _engagement_index_payload(engagement: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": engagement["id"],
        "slug": engagement["slug"],
        "name": engagement["name"],
        "status": engagement["status"],
        "operator": engagement["operator"],
        "tags": engagement.get("tags", []),
        "created_at": engagement["created_at"],
        "updated_at": engagement["updated_at"],
        "latest_audit": engagement["latest_audit"],
        "primary_seed": engagement["primary_seed"],
        "seeds": engagement["seeds"],
        "counts": engagement["counts"],
        "severity_summary": engagement["severity_summary"],
        "highest_severity": engagement["highest_severity"],
        "graph_summary": engagement["graph_summary"],
        "run_summary": engagement.get("run_summary"),
        "seed_graph_summary": engagement.get("seed_graph_summary", {}),
        "report_count": len(engagement["report_files"]),
        "graph_count": len(engagement["graph_files"]),
        "audit_count": len(engagement.get("audit_files", [])),
        "detail_route": engagement["detail_route"],
        "detail_data": engagement["detail_data"],
    }


def _engagement_detail_payload(engagement: dict[str, Any], root_page: Path) -> dict[str, Any]:
    report_history = _report_history_payload(engagement["report_files"])
    latest_report_files = _latest_report_family_files(engagement["report_files"])
    preview_files = [path for path in latest_report_files if path.suffix.lower() == ".md"]
    report_previews = [_report_preview_payload(root_page, path) for path in preview_files]
    artifacts = [
        _artifact_payload(root_page, path, kind="report")
        for path in engagement["report_files"]
    ] + [
        _artifact_payload(root_page, path, kind="graph")
        for path in engagement["graph_files"]
    ] + [
        _artifact_payload(root_page, path, kind="audit")
        for path in engagement.get("audit_files", [])
    ]
    payload = {
        **_engagement_index_payload(engagement),
        "path": engagement["path"],
        "size_bytes": engagement["size_bytes"],
        "size_label": _format_size(int(engagement["size_bytes"] or 0)),
        "scope": engagement["scope"],
        "sections": engagement["sections"],
        "artifacts": artifacts,
        "report_previews": report_previews,
    }
    report_summary = engagement.get("report_summary")
    if report_summary is not None:
        payload["report_summary"] = report_summary
    if report_history:
        payload["report_history"] = report_history
    if engagement.get("graph_payload") is not None:
        payload["graph_payload"] = engagement["graph_payload"]
    if engagement.get("graph_snapshot_at"):
        payload["graph_snapshot_at"] = engagement["graph_snapshot_at"]
    return payload


def generate_dashboard(
    data_dir: Path,
    reports_dir: Path,
    output_path: Path,
) -> Path:
    """Build the overview dashboard and per-engagement detail pages."""
    dbs = _engagement_db_files(data_dir)
    site_root = _site_root(output_path)
    root_index_path = site_root / "index.html"
    engagement_dir = site_root / "engagements"
    data_dir_root = site_root / "data" / "engagements"
    site_root.mkdir(parents=True, exist_ok=True)
    engagement_dir.mkdir(parents=True, exist_ok=True)
    data_dir_root.mkdir(parents=True, exist_ok=True)

    engagements: list[dict[str, Any]] = []
    for db_path in dbs:
        item = _engagement_summary(db_path)
        item["report_files"] = _artifact_files(item["id"], reports_dir)
        item["graph_files"] = _graph_files(item["id"], reports_dir)
        item["audit_files"] = _audit_files(item["id"], reports_dir)
        con = _connect_readonly(db_path)
        if con is not None:
            try:
                try:
                    engagement_id = int(item["id"])
                except (TypeError, ValueError):
                    engagement_id = None
                if engagement_id is not None:
                    item["audit_files"] = _materialize_audit_manifest_artifacts(
                        con,
                        db_path=db_path,
                        reports_dir=reports_dir,
                        engagement_id=engagement_id,
                        verify=True,
                    )
                    graph_summary, graph_payload, graph_snapshot_at = _graph_state_for_engagement(
                        con,
                        engagement_id,
                        item["graph_files"],
                    )
                else:
                    graph_summary, graph_payload, graph_snapshot_at = {}, None, ""
            finally:
                con.close()
        else:
            graph_summary, graph_payload, graph_snapshot_at = {}, None, ""
        item["graph_summary"] = graph_summary
        item["graph_payload"] = graph_payload
        item["graph_snapshot_at"] = graph_snapshot_at
        item["report_summary"] = _report_summary_payload(item["report_files"])
        item["detail_route"] = f"engagements/{item['slug']}/"
        item["detail_data"] = f"data/engagements/{item['slug']}.json"
        item["detail_page"] = engagement_dir / item["slug"] / "index.html"
        item["detail_page"].parent.mkdir(parents=True, exist_ok=True)
        item["detail_page"].write_text(
            _render_engagement_page(item, root_index_path, item["detail_page"]),
            encoding="utf-8",
        )
        (data_dir_root / f"{item['slug']}.json").write_text(
            json.dumps(_engagement_detail_payload(item, root_index_path), indent=2),
            encoding="utf-8",
        )
        engagements.append(item)

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    overview_html = _render_overview_page(engagements, output_path, generated_at)
    site_overview_html = _render_overview_page(engagements, root_index_path, generated_at)
    output_path.write_text(
        overview_html,
        encoding="utf-8",
    )
    root_index_path.write_text(site_overview_html, encoding="utf-8")
    (site_root / "data" / "engagements.json").write_text(
        json.dumps(
            {
                "generated_at": generated_at,
                "items": [_engagement_index_payload(item) for item in engagements],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return output_path
