"""Parsed artifact persistence action helpers."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar


ArtifactDiscoveryPayload = tuple[str, str, str]
RunOrderedBatch = Callable[..., list[Any]]
TextDiscoveryBatchT = TypeVar("TextDiscoveryBatchT")


def _safe_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:  # noqa: BLE001
        return None


@dataclass
class ArtifactProcessingSummary:
    queued_local: int = 0
    processed: int = 0
    failed: int = 0
    skipped: int = 0
    firebase_projects: int = 0
    supabase_configs: int = 0
    discovered_seeds: int = 0


def merge_artifact_processing_summary(
    summary: ArtifactProcessingSummary,
    delta: ArtifactProcessingSummary,
) -> ArtifactProcessingSummary:
    summary.queued_local += delta.queued_local
    summary.processed += delta.processed
    summary.failed += delta.failed
    summary.skipped += delta.skipped
    summary.firebase_projects += delta.firebase_projects
    summary.supabase_configs += delta.supabase_configs
    summary.discovered_seeds += delta.discovered_seeds
    return summary


@dataclass
class ParsedArtifact:
    artifact_id: int
    source_url: str
    artifact_type: str
    path: Path
    payloads: list[tuple[str, str, str]] = field(default_factory=list)
    firebase_projects: list[Any] = field(default_factory=list)
    supabase_configs: list[Any] = field(default_factory=list)
    parse_metadata: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class ArtifactTextDiscoveryBatch:
    source_file: str
    emails: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    ip_seeds: list[tuple[str, str]] = field(default_factory=list)
    host_seeds: list[tuple[str, str]] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    identity_seeds: list[tuple[str, str, str, str]] = field(default_factory=list)
    key_findings: list[dict[str, object]] = field(default_factory=list)
    cloud_assets: list[tuple[str, str, str]] = field(default_factory=list)


@dataclass(frozen=True)
class ArtifactParsedResultAction:
    artifact_id: int
    status: str
    notes: str
    metadata: dict[str, Any] | None = None
    processed_delta: int = 0
    failed_delta: int = 0
    firebase_projects_delta: int = 0
    supabase_configs_delta: int = 0
    discovered_seeds_delta: int = 0


def artifact_parsed_result_actions(
    parsed_artifacts: Sequence[ParsedArtifact],
    *,
    persist_parsed_artifact: Callable[[ParsedArtifact], tuple[int, int, int, dict[str, Any]]],
) -> list[ArtifactParsedResultAction]:
    actions: list[ArtifactParsedResultAction] = []
    for parsed in parsed_artifacts:
        if parsed.error:
            actions.append(
                ArtifactParsedResultAction(
                    artifact_id=parsed.artifact_id,
                    status="failed",
                    notes=parsed.error,
                    failed_delta=1,
                )
            )
            continue
        firebase_count, supabase_count, seed_count, parse_metadata = persist_parsed_artifact(parsed)
        actions.append(
            ArtifactParsedResultAction(
                artifact_id=parsed.artifact_id,
                status="parsed",
                notes=f"firebase={firebase_count} supabase={supabase_count} seeds={seed_count}",
                metadata=parse_metadata,
                processed_delta=1,
                firebase_projects_delta=firebase_count,
                supabase_configs_delta=supabase_count,
                discovered_seeds_delta=seed_count,
            )
        )
    return actions


def apply_artifact_parsed_result_actions(
    parsed_actions: Sequence[ArtifactParsedResultAction],
    *,
    update_artifact_status: Callable[[int, str, str, dict[str, Any] | None], None],
) -> ArtifactProcessingSummary:
    summary = ArtifactProcessingSummary()
    for parsed_action in parsed_actions:
        update_artifact_status(
            parsed_action.artifact_id,
            parsed_action.status,
            parsed_action.notes,
            parsed_action.metadata,
        )
        summary.processed += parsed_action.processed_delta
        summary.failed += parsed_action.failed_delta
        summary.firebase_projects += parsed_action.firebase_projects_delta
        summary.supabase_configs += parsed_action.supabase_configs_delta
        summary.discovered_seeds += parsed_action.discovered_seeds_delta
    return summary


def persist_parsed_artifact(
    con: sqlite3.Connection,
    parsed: ParsedArtifact,
    *,
    artifact_relation_context: Callable[[sqlite3.Connection, ParsedArtifact], dict[str, Any]],
    artifact_source_seed_id: Callable[[sqlite3.Connection, str], int | None],
    ensure_local_artifact_source_seed: Callable[..., int | None],
    artifact_discovery_payloads: Callable[[ParsedArtifact], list[ArtifactDiscoveryPayload]],
    expand_structured_discovery_jobs: Callable[
        [list[ArtifactDiscoveryPayload]],
        list[ArtifactDiscoveryPayload],
    ],
    collect_generic_text_discovery_batches: Callable[
        [list[ArtifactDiscoveryPayload]],
        Sequence[TextDiscoveryBatchT],
    ],
    persist_generic_text_discovery_batch: Callable[..., int],
    dedupe_firebase_projects: Callable[[list[Any]], list[Any]],
    store_firebase_projects: Callable[..., tuple[int, int]],
    dedupe_supabase_configs: Callable[[list[Any]], list[Any]],
    store_supabase_configs: Callable[..., tuple[int, int]],
) -> tuple[int, int, int, dict[str, Any]]:
    discovered_seeds = 0
    artifact_context = artifact_relation_context(con, parsed)
    source_seed_id = artifact_source_seed_id(con, parsed.source_url)
    if source_seed_id is None:
        source_seed_id = ensure_local_artifact_source_seed(
            con,
            parsed,
            artifact_context=artifact_context,
        )
    discovery_payloads = artifact_discovery_payloads(parsed)
    discovery_jobs = expand_structured_discovery_jobs(discovery_payloads)
    for batch in collect_generic_text_discovery_batches(discovery_jobs):
        discovered_seeds += persist_generic_text_discovery_batch(
            con,
            batch,
            source_seed_id=source_seed_id,
            artifact_context=artifact_context,
        )
    firebase_count, firebase_seeds = store_firebase_projects(
        con,
        dedupe_firebase_projects(list(parsed.firebase_projects)),
        source_seed_id=source_seed_id,
        source_url=parsed.source_url,
        artifact_context=artifact_context,
    )
    supabase_count, supabase_seeds = store_supabase_configs(
        con,
        dedupe_supabase_configs(list(parsed.supabase_configs)),
        source_seed_id=source_seed_id,
        source_url=parsed.source_url,
        artifact_context=artifact_context,
    )
    return (
        firebase_count,
        supabase_count,
        discovered_seeds + firebase_count + firebase_seeds + supabase_seeds,
        parsed.parse_metadata,
    )


def firebase_project_persistence_entry(
    project: Any,
    *,
    source_url: str,
) -> dict[str, Any] | None:
    relation_metadata = {
        "rule": "artifact_mobile_config",
        "source_url": source_url,
        "source_file": project.source_file,
        "extract_path": project.extract_path,
    }
    return {
        "project_id": project.project_id,
        "source_file": project.source_file,
        "extract_path": project.extract_path,
        "storage_bucket": project.storage_bucket,
        "storage_bucket_url": (
            f"https://storage.googleapis.com/{project.storage_bucket}"
            if project.storage_bucket
            else ""
        ),
        "storage_relation_metadata": {
            "rule": "artifact_mobile_config_storage_bucket",
            "source_url": source_url,
            "source_file": project.source_file,
            "extract_path": project.extract_path,
        },
        "rtdb_url": project.rtdb_url,
        "api_key_enc": project.api_key_enc,
        "project_relation_metadata": relation_metadata,
    }


def supabase_config_persistence_entry(
    config: Any,
    *,
    source_url: str,
    redact_secret: Callable[[Any], str],
    encrypt_secret_material: Callable[[Any], str | None],
) -> dict[str, Any] | None:
    relation_metadata = {
        "rule": "artifact_mobile_config",
        "source_url": source_url,
        "source_file": config.source_file,
        "extract_path": config.extract_path,
    }
    return {
        "project_ref": config.project_ref,
        "project_url": config.project_url,
        "source_file": config.source_file,
        "relation_metadata": relation_metadata,
        "key_redacted": redact_secret(config.anon_key),
        "key_enc": encrypt_secret_material(config.anon_key),
    }


def store_firebase_projects(
    con: sqlite3.Connection,
    firebase_projects: list[Any],
    *,
    source_seed_id: int | None = None,
    source_url: str = "",
    artifact_context: dict[str, Any] | None = None,
    artifact_child_seed_depth: Callable[[sqlite3.Connection, int | None], int],
    run_ordered_batch: RunOrderedBatch,
    firebase_project_persistence_entry: Callable[..., dict[str, Any] | None],
    store_cloud_asset_reference: Callable[..., None],
    artifact_cloud_asset_metadata: Callable[..., dict[str, Any]],
    insert_seed: Callable[..., bool],
    link_artifact_source_seed: Callable[..., None],
    merge_artifact_relation_context_fn: Callable[
        [dict[str, Any] | None, dict[str, Any] | None],
        dict[str, Any],
    ],
    store_artifact_url_seed: Callable[..., int],
    store_key_finding: Callable[..., None],
) -> tuple[int, int]:
    firebase_count = 0
    discovered_seeds = 0
    child_depth = artifact_child_seed_depth(con, source_seed_id)
    project_batches = run_ordered_batch(
        firebase_projects,
        lambda project: firebase_project_persistence_entry(
            project,
            source_url=source_url,
        ),
        default_factory=lambda: None,
    )
    for project_entry in project_batches:
        if not isinstance(project_entry, dict):
            continue
        firebase_count += 1
        store_cloud_asset_reference(
            con,
            asset_type="firebase",
            identifier=str(project_entry["project_id"]),
            source="firebase_extract",
            metadata=artifact_cloud_asset_metadata(
                con,
                source_seed_id=source_seed_id,
                relation_metadata=dict(project_entry["project_relation_metadata"]),
                artifact_context=artifact_context,
            ),
        )
        insert_seed(
            con,
            str(project_entry["project_id"]),
            "other",
            source="artifact",
            confidence=0.8,
            depth=child_depth,
        )
        link_artifact_source_seed(
            con,
            source_seed_id,
            str(project_entry["project_id"]),
            "other",
            confidence=0.8,
            metadata=merge_artifact_relation_context_fn(
                dict(project_entry["project_relation_metadata"]),
                artifact_context,
            ),
        )
        if project_entry["storage_bucket"]:
            store_cloud_asset_reference(
                con,
                asset_type="gcs",
                identifier=str(project_entry["storage_bucket"]),
                source="firebase_extract_storage_bucket",
                metadata=artifact_cloud_asset_metadata(
                    con,
                    source_seed_id=source_seed_id,
                    relation_metadata=dict(project_entry["storage_relation_metadata"]),
                    artifact_context=artifact_context,
                ),
            )
            if store_artifact_url_seed(
                con,
                str(project_entry["storage_bucket_url"]),
                source="artifact",
                confidence=0.7,
                source_seed_id=source_seed_id,
                depth=child_depth,
                relation_metadata=merge_artifact_relation_context_fn(
                    dict(project_entry["storage_relation_metadata"]),
                    artifact_context,
                ),
            ):
                discovered_seeds += 1
        if project_entry["rtdb_url"]:
            store_artifact_url_seed(
                con,
                str(project_entry["rtdb_url"]),
                source="artifact",
                confidence=0.72,
                source_seed_id=source_seed_id,
                depth=child_depth,
                relation_metadata=merge_artifact_relation_context_fn(
                    dict(project_entry["project_relation_metadata"]),
                    artifact_context,
                ),
            )
        if project_entry["api_key_enc"]:
            store_key_finding(
                con,
                service="firebase",
                domain=str(project_entry["project_id"]),
                source_url=str(project_entry["source_file"]),
                pattern_name="firebase_mobile_config",
                key_redacted="<age-encrypted>",
                key_enc=str(project_entry["api_key_enc"]),
            )
    return firebase_count, discovered_seeds


def store_supabase_configs(
    con: sqlite3.Connection,
    supabase_configs: list[Any],
    *,
    source_seed_id: int | None = None,
    source_url: str = "",
    artifact_context: dict[str, Any] | None = None,
    artifact_child_seed_depth: Callable[[sqlite3.Connection, int | None], int],
    run_ordered_batch: RunOrderedBatch,
    supabase_config_persistence_entry: Callable[..., dict[str, Any] | None],
    store_cloud_asset_reference: Callable[..., None],
    artifact_cloud_asset_metadata: Callable[..., dict[str, Any]],
    store_artifact_url_seed: Callable[..., int],
    merge_artifact_relation_context_fn: Callable[
        [dict[str, Any] | None, dict[str, Any] | None],
        dict[str, Any],
    ],
    insert_seed: Callable[..., bool],
    link_artifact_source_seed: Callable[..., None],
    store_key_finding: Callable[..., None],
) -> tuple[int, int]:
    supabase_count = 0
    discovered_seeds = 0
    child_depth = artifact_child_seed_depth(con, source_seed_id)
    config_batches = run_ordered_batch(
        supabase_configs,
        lambda config: supabase_config_persistence_entry(
            config,
            source_url=source_url,
        ),
        default_factory=lambda: None,
    )
    for config_entry in config_batches:
        if not isinstance(config_entry, dict):
            continue
        supabase_count += 1
        store_cloud_asset_reference(
            con,
            asset_type="supabase",
            identifier=str(config_entry["project_ref"]),
            source="mobile_config_parse",
            metadata=artifact_cloud_asset_metadata(
                con,
                source_seed_id=source_seed_id,
                relation_metadata=dict(config_entry["relation_metadata"]),
                artifact_context=artifact_context,
            ),
        )
        if store_artifact_url_seed(
            con,
            str(config_entry["project_url"]),
            source="artifact",
            confidence=0.8,
            source_seed_id=source_seed_id,
            depth=child_depth,
            relation_metadata=merge_artifact_relation_context_fn(
                dict(config_entry["relation_metadata"]),
                artifact_context,
            ),
        ):
            discovered_seeds += 1
        if insert_seed(
            con,
            str(config_entry["project_ref"]),
            "other",
            source="artifact",
            confidence=0.72,
            depth=child_depth,
        ):
            discovered_seeds += 1
        link_artifact_source_seed(
            con,
            source_seed_id,
            str(config_entry["project_ref"]),
            "other",
            confidence=0.72,
            metadata=merge_artifact_relation_context_fn(
                dict(config_entry["relation_metadata"]),
                artifact_context,
            ),
        )
        store_key_finding(
            con,
            service="supabase",
            domain=str(config_entry["project_ref"]),
            source_url=str(config_entry["source_file"]),
            pattern_name="supabase_mobile_config",
            key_redacted=str(config_entry["key_redacted"]),
            key_enc=config_entry["key_enc"],
        )
    return supabase_count, discovered_seeds


def persist_generic_text_discovery_batch(
    con: sqlite3.Connection,
    batch: ArtifactTextDiscoveryBatch,
    *,
    source_seed_id: int | None = None,
    artifact_context: dict[str, Any] | None = None,
    artifact_child_seed_depth: Callable[[sqlite3.Connection, int | None], int],
    run_ordered_batch: RunOrderedBatch,
    artifact_text_email_persistence_entry: Callable[..., dict[str, Any] | None],
    artifact_text_phone_persistence_entry: Callable[..., dict[str, Any] | None],
    artifact_text_ip_persistence_entry: Callable[..., dict[str, Any] | None],
    artifact_text_host_persistence_entry: Callable[..., dict[str, Any] | None],
    artifact_text_url_persistence_entry: Callable[..., dict[str, Any] | None],
    artifact_text_identity_seed_persistence_entry: Callable[..., dict[str, Any] | None],
    artifact_text_key_finding_persistence_entry: Callable[..., dict[str, Any] | None],
    artifact_text_cloud_asset_persistence_entry: Callable[..., dict[str, Any] | None],
    insert_email: Callable[..., bool],
    insert_seed: Callable[..., bool],
    link_artifact_source_seed: Callable[..., None],
    store_artifact_url_seed: Callable[..., int],
    merge_artifact_relation_context_fn: Callable[
        [dict[str, Any] | None, dict[str, Any] | None],
        dict[str, Any],
    ],
    merge_artifact_metadata_into_seed: Callable[..., None],
    store_key_finding: Callable[..., None],
    artifact_cloud_asset_metadata: Callable[..., dict[str, Any]],
    store_cloud_asset_reference: Callable[..., None],
) -> int:
    inserted = 0
    source_file = batch.source_file
    child_depth = artifact_child_seed_depth(con, source_seed_id)
    email_entries = run_ordered_batch(
        batch.emails,
        lambda email: artifact_text_email_persistence_entry(
            email,
            source_file=source_file,
        ),
        default_factory=lambda: None,
    )
    for email_entry in email_entries:
        if not isinstance(email_entry, dict):
            continue
        if insert_email(
            con,
            str(email_entry["email"]),
            source="artifact",
            depth=child_depth,
        ):
            inserted += 1
        link_artifact_source_seed(
            con,
            source_seed_id,
            str(email_entry["email"]),
            "email",
            confidence=0.74,
            metadata=merge_artifact_relation_context_fn(
                dict(email_entry["metadata"]),
                artifact_context,
            ),
        )

    phone_entries = run_ordered_batch(
        batch.phones,
        lambda phone: artifact_text_phone_persistence_entry(
            phone,
            source_file=source_file,
        ),
        default_factory=lambda: None,
    )
    for phone_entry in phone_entries:
        if not isinstance(phone_entry, dict):
            continue
        if insert_seed(
            con,
            str(phone_entry["phone"]),
            "phone",
            source="artifact",
            confidence=0.66,
            depth=child_depth,
        ):
            inserted += 1
        link_artifact_source_seed(
            con,
            source_seed_id,
            str(phone_entry["phone"]),
            "phone",
            confidence=0.66,
            metadata=merge_artifact_relation_context_fn(
                dict(phone_entry["metadata"]),
                artifact_context,
            ),
        )

    ip_entries = run_ordered_batch(
        batch.ip_seeds,
        lambda ip_seed: artifact_text_ip_persistence_entry(
            ip_seed,
            source_file=source_file,
        ),
        default_factory=lambda: None,
    )
    for ip_entry in ip_entries:
        if not isinstance(ip_entry, dict):
            continue
        if insert_seed(
            con,
            str(ip_entry["ip_value"]),
            str(ip_entry["ip_seed_type"]),
            source="artifact",
            confidence=0.64,
            depth=child_depth,
        ):
            inserted += 1
        link_artifact_source_seed(
            con,
            source_seed_id,
            str(ip_entry["ip_value"]),
            str(ip_entry["ip_seed_type"]),
            confidence=0.64,
            metadata=merge_artifact_relation_context_fn(
                dict(ip_entry["metadata"]),
                artifact_context,
            ),
        )

    host_entries = run_ordered_batch(
        batch.host_seeds,
        lambda host_seed: artifact_text_host_persistence_entry(
            host_seed,
            source_file=source_file,
        ),
        default_factory=lambda: None,
    )
    for host_entry in host_entries:
        if not isinstance(host_entry, dict):
            continue
        confidence = float(host_entry["confidence"])
        if insert_seed(
            con,
            str(host_entry["host_value"]),
            str(host_entry["host_seed_type"]),
            source="artifact",
            confidence=confidence,
            depth=child_depth,
        ):
            inserted += 1
        link_artifact_source_seed(
            con,
            source_seed_id,
            str(host_entry["host_value"]),
            str(host_entry["host_seed_type"]),
            confidence=confidence,
            metadata=merge_artifact_relation_context_fn(
                dict(host_entry["metadata"]),
                artifact_context,
            ),
        )

    url_entries = run_ordered_batch(
        batch.urls,
        lambda url: artifact_text_url_persistence_entry(
            url,
            source_file=source_file,
        ),
        default_factory=lambda: None,
    )
    for url_entry in url_entries:
        if not isinstance(url_entry, dict):
            continue
        inserted += store_artifact_url_seed(
            con,
            str(url_entry["url"]),
            source="artifact",
            confidence=0.68,
            source_seed_id=source_seed_id,
            depth=child_depth,
            relation_metadata=merge_artifact_relation_context_fn(
                dict(url_entry["relation_metadata"]),
                artifact_context,
            ),
        )

    identity_entries = run_ordered_batch(
        batch.identity_seeds,
        lambda identity_seed: artifact_text_identity_seed_persistence_entry(
            identity_seed,
            source_file=source_file,
        ),
        default_factory=lambda: None,
    )
    for identity_entry in identity_entries:
        if not isinstance(identity_entry, dict):
            continue
        seed_value = str(identity_entry["seed_value"])
        seed_type = str(identity_entry["seed_type"])
        confidence = float(identity_entry["confidence"])
        metadata = merge_artifact_relation_context_fn(
            dict(identity_entry["metadata"]),
            artifact_context,
        )
        if insert_seed(
            con,
            seed_value,
            seed_type,
            source="artifact",
            confidence=confidence,
            depth=child_depth,
        ):
            inserted += 1
        merge_artifact_metadata_into_seed(
            con,
            seed_value,
            seed_type,
            metadata,
        )
        link_artifact_source_seed(
            con,
            source_seed_id,
            seed_value,
            seed_type,
            confidence=confidence,
            metadata=metadata,
        )

    key_entries = run_ordered_batch(
        batch.key_findings,
        artifact_text_key_finding_persistence_entry,
        default_factory=lambda: None,
    )
    for key_entry in key_entries:
        if not isinstance(key_entry, dict):
            continue
        store_key_finding(
            con,
            service=str(key_entry["service"]),
            domain=str(key_entry["domain"]),
            source_url=str(key_entry["source_url"]),
            pattern_name=str(key_entry["pattern_name"]),
            key_redacted=str(key_entry["key_redacted"]),
            key_enc=(None if key_entry.get("key_enc") is None else str(key_entry["key_enc"])),
            source_backend=str(key_entry["source_backend"]),
            repo_name=str(key_entry["repo_name"]),
            validation_detail=str(key_entry.get("validation_detail") or "artifact_queue_ingest"),
        )

    cloud_asset_entries = run_ordered_batch(
        batch.cloud_assets,
        lambda cloud_asset: artifact_text_cloud_asset_persistence_entry(
            cloud_asset,
            source_file=source_file,
        ),
        default_factory=lambda: None,
    )
    for cloud_asset_entry in cloud_asset_entries:
        if not isinstance(cloud_asset_entry, dict):
            continue
        cloud_metadata = artifact_cloud_asset_metadata(
            con,
            source_seed_id=source_seed_id,
            relation_metadata=dict(cloud_asset_entry["relation_metadata"]),
            artifact_context=artifact_context,
        )
        store_cloud_asset_reference(
            con,
            asset_type=str(cloud_asset_entry["asset_type"]),
            identifier=str(cloud_asset_entry["identifier"]),
            source=str(cloud_asset_entry["source"]),
            metadata=cloud_metadata,
        )
    return inserted


def store_artifact_key_finding(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    service: str,
    domain: str,
    source_url: str,
    pattern_name: str,
    key_redacted: str,
    key_enc: str | None,
    source_backend: str = "mobile_config_parse",
    repo_name: str | None = None,
    validation_detail: str = "artifact_queue_ingest",
) -> None:
    con.execute(
        """
        INSERT OR IGNORE INTO key_scanner_findings
            (engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state, validation_detail)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'UNCONFIRMED', ?)
        """,
        (
            engagement_id,
            domain,
            service,
            pattern_name,
            source_backend,
            source_url,
            repo_name or Path(source_url).name,
            key_redacted,
            key_enc,
            validation_detail,
        ),
    )


def merge_artifact_seed_metadata(existing: Any, incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing) if isinstance(existing, dict) else {}
    for key, value in incoming.items():
        if value in (None, "", [], {}):
            continue
        if key in {"archive_sources", "provider_sources"}:
            existing_sources = merged.get(key)
            normalized: list[str] = []
            if isinstance(existing_sources, list):
                for raw_item in existing_sources:
                    item = str(raw_item or "").strip()
                    if item and item not in normalized:
                        normalized.append(item)
            if isinstance(value, list):
                for raw_item in value:
                    item = str(raw_item or "").strip()
                    if item and item not in normalized:
                        normalized.append(item)
                    if len(normalized) >= 8:
                        break
            if normalized:
                merged[key] = normalized
            continue
        if key not in merged or merged.get(key) in (None, "", [], {}):
            merged[key] = value
    return merged


def store_artifact_cloud_asset_reference(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    asset_type: str,
    identifier: str,
    source: str,
    metadata: dict[str, Any] | None = None,
    audit_artifact_lineage: Callable[..., None] | None = None,
) -> None:
    normalized_type = str(asset_type or "").strip().lower()
    original_identifier = str(identifier or "").strip()
    normalized_identifier = original_identifier.lower()
    if not normalized_type or not normalized_identifier:
        return
    existing = con.execute(
        """
        SELECT metadata_json
        FROM cloud_assets
        WHERE engagement_id=? AND asset_type=? AND identifier=?
        """,
        (engagement_id, normalized_type, normalized_identifier),
    ).fetchone()
    existing_metadata = _safe_json_loads(str(existing[0] or "{}")) if existing is not None else {}
    merged_metadata = merge_artifact_seed_metadata(existing_metadata, metadata or {})
    metadata_json = json.dumps(merged_metadata, sort_keys=True)
    con.execute(
        """
        INSERT INTO cloud_assets
            (engagement_id, asset_type, identifier, provider_identifier, source, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, asset_type, identifier) DO UPDATE SET
            provider_identifier = CASE
                WHEN cloud_assets.provider_identifier IS NULL
                  OR TRIM(cloud_assets.provider_identifier) = ''
                  OR cloud_assets.provider_identifier = cloud_assets.identifier
                THEN excluded.provider_identifier
                ELSE cloud_assets.provider_identifier
            END,
            metadata_json = excluded.metadata_json
        """,
        (
            engagement_id,
            normalized_type,
            normalized_identifier,
            original_identifier,
            source,
            metadata_json,
        ),
    )
    if existing is None and audit_artifact_lineage is not None:
        audit_artifact_lineage(
            action="artifact_cloud_asset_inventoried",
            target=normalized_identifier,
            result=(
                f"asset_type={normalized_type} source={source} "
                "validation_status=UNVALIDATED reportable=no"
            ),
        )


def store_artifact_url_seed(
    con: sqlite3.Connection,
    url: str,
    *,
    source: str,
    confidence: float,
    source_seed_id: int | None = None,
    depth: int = 1,
    relation_metadata: dict[str, Any] | None = None,
    artifact_url_seed_persistence_entry: Callable[..., dict[str, Any] | None],
    insert_seed: Callable[..., bool],
    link_artifact_source_seed: Callable[..., None],
    store_social_profile_url_pivots: Callable[..., None],
    store_cloud_asset_from_url: Callable[..., None],
    queue_artifact_text_discovered_url: Callable[..., int],
) -> int:
    entry = artifact_url_seed_persistence_entry(
        url,
        relation_metadata=relation_metadata,
    )
    if not isinstance(entry, dict):
        return 0
    inserted = 0
    entry_url = str(entry["url"])
    entry_seed_type = str(entry["seed_type"])
    entry_relation_metadata = dict(entry["relation_metadata"])
    if insert_seed(
        con,
        entry_url,
        entry_seed_type,
        source=source,
        confidence=confidence,
        depth=depth,
    ):
        inserted += 1
    link_artifact_source_seed(
        con,
        source_seed_id,
        entry_url,
        entry_seed_type,
        confidence=confidence,
        metadata=entry_relation_metadata,
    )
    store_social_profile_url_pivots(
        con,
        entry_url,
        seed_type=entry_seed_type,
        relation_metadata=entry_relation_metadata,
        pivot_entries=list(entry["social_pivot_entries"]),
        depth=max(1, int(depth or 0) + 1),
    )
    for related_seed_entry in entry["related_seed_entries"]:
        if not isinstance(related_seed_entry, dict):
            continue
        related_seed_value = str(related_seed_entry["seed_value"])
        related_seed_type = str(related_seed_entry["seed_type"])
        related_confidence = float(related_seed_entry["confidence"])
        if insert_seed(
            con,
            related_seed_value,
            related_seed_type,
            source=source,
            confidence=related_confidence,
            depth=depth,
        ):
            inserted += 1
        link_artifact_source_seed(
            con,
            source_seed_id,
            related_seed_value,
            related_seed_type,
            confidence=related_confidence,
            metadata=entry_relation_metadata,
        )
    store_cloud_asset_from_url(
        con,
        entry_url,
        source="artifact_url_extract",
        cloud_asset_entries=list(entry["cloud_asset_entries"]),
        source_seed_id=source_seed_id,
        relation_metadata=entry_relation_metadata,
    )
    queue_artifact_text_discovered_url(
        con,
        entry_url,
        seed_type=entry_seed_type,
        relation_metadata=entry_relation_metadata,
    )
    return inserted


def artifact_text_email_persistence_entry(
    email: str,
    *,
    source_file: str,
) -> dict[str, Any] | None:
    return {
        "email": email,
        "metadata": {"rule": "artifact_text_extract", "source_file": source_file},
    }


def artifact_text_phone_persistence_entry(
    phone: str,
    *,
    source_file: str,
) -> dict[str, Any] | None:
    return {
        "phone": phone,
        "metadata": {"rule": "artifact_text_extract", "source_file": source_file},
    }


def artifact_text_ip_persistence_entry(
    ip_seed: tuple[str, str],
    *,
    source_file: str,
) -> dict[str, Any] | None:
    ip_value, ip_seed_type = ip_seed
    return {
        "ip_value": ip_value,
        "ip_seed_type": ip_seed_type,
        "metadata": {"rule": "artifact_text_extract", "source_file": source_file},
    }


def artifact_text_host_persistence_entry(
    host_seed: tuple[str, str],
    *,
    source_file: str,
) -> dict[str, Any] | None:
    host_value, host_seed_type = host_seed
    return {
        "host_value": host_value,
        "host_seed_type": host_seed_type,
        "confidence": 0.64 if host_seed_type == "subdomain" else 0.6,
        "metadata": {"rule": "artifact_network_dsn_extract", "source_file": source_file},
    }


def artifact_text_url_persistence_entry(
    url: str,
    *,
    source_file: str,
    helm_index_chart_url_metadata: Callable[..., dict[str, Any]],
) -> dict[str, Any] | None:
    return {
        "url": url,
        "relation_metadata": helm_index_chart_url_metadata(
            url,
            source_file=source_file,
        ),
    }


def artifact_text_identity_seed_persistence_entry(
    identity_seed: tuple[str, str, str, str],
    *,
    source_file: str,
) -> dict[str, Any] | None:
    seed_value, seed_type, contact_field, contact_title = identity_seed
    if seed_type not in {"name", "company"}:
        return None
    confidence = {"company": 0.72, "name": 0.7}.get(seed_type, 0.5)
    metadata = {
        "rule": "calendar_contact_explicit_field",
        "source_file": source_file,
        "contact_field": contact_field,
        "normalized_value": seed_value,
        "artifact_contact_identity": True,
    }
    if contact_title:
        metadata["contact_title"] = contact_title
    return {
        "seed_value": seed_value,
        "seed_type": seed_type,
        "confidence": confidence,
        "metadata": metadata,
    }


def artifact_text_key_finding_persistence_entry(
    finding: dict[str, object],
) -> dict[str, Any] | None:
    return {
        "service": str(finding["service"]),
        "domain": str(finding["domain"]),
        "source_url": str(finding["source_url"]),
        "pattern_name": str(finding["pattern_name"]),
        "key_redacted": str(finding["key_redacted"]),
        "key_enc": None if finding.get("key_enc") is None else str(finding["key_enc"]),
        "source_backend": str(finding["source_backend"]),
        "repo_name": str(finding["repo_name"]),
        "validation_detail": str(finding.get("validation_detail") or "artifact_queue_ingest"),
    }


def artifact_text_cloud_asset_persistence_entry(
    cloud_asset: tuple[str, str, str],
    *,
    source_file: str,
) -> dict[str, Any] | None:
    asset_type, identifier, source = cloud_asset
    return {
        "asset_type": asset_type,
        "identifier": identifier,
        "source": source,
        "relation_metadata": {
            "rule": source,
            "source_file": source_file,
        },
    }


__all__ = [
    "ArtifactDiscoveryPayload",
    "ArtifactParsedResultAction",
    "ArtifactProcessingSummary",
    "ArtifactTextDiscoveryBatch",
    "ParsedArtifact",
    "RunOrderedBatch",
    "apply_artifact_parsed_result_actions",
    "artifact_parsed_result_actions",
    "artifact_text_cloud_asset_persistence_entry",
    "artifact_text_email_persistence_entry",
    "artifact_text_host_persistence_entry",
    "artifact_text_identity_seed_persistence_entry",
    "artifact_text_ip_persistence_entry",
    "artifact_text_key_finding_persistence_entry",
    "artifact_text_phone_persistence_entry",
    "artifact_text_url_persistence_entry",
    "firebase_project_persistence_entry",
    "merge_artifact_processing_summary",
    "merge_artifact_seed_metadata",
    "persist_generic_text_discovery_batch",
    "persist_parsed_artifact",
    "store_artifact_cloud_asset_reference",
    "store_artifact_key_finding",
    "store_artifact_url_seed",
    "store_firebase_projects",
    "store_supabase_configs",
    "supabase_config_persistence_entry",
]
