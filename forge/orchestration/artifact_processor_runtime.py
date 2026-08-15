"""Runtime adapters for the legacy artifact queue processor."""

from __future__ import annotations

import base64
import re
import sqlite3
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote, unquote, urlparse

from forge.db.direct_connect import direct_connect
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.orchestration.artifacts import (
    ArtifactDownloadRequest,
    ArtifactDownloadResult,
    ArtifactProcessingSummary,
    ArtifactQueueRowsProcessCallbacks,
    ArtifactTextDiscoveryBatch,
    ArtifactTextScanStageResult,
    ArtifactWorkItem,
    ParsedArtifact,
    artifact_cloud_asset_url_entry,
    artifact_cloud_asset_metadata,
    artifact_data_uri_image_payload_entry,
    artifact_data_uri_image_structured_payload_text,
    artifact_data_uri_payload_entry,
    artifact_data_uri_structured_payload_text,
    artifact_discovery_payloads,
    artifact_text_discovery_batch_entry,
    artifact_text_discovery_job,
    artifact_text_scan_stage,
    artifact_relation_context_from_queue,
    artifact_structured_discovery_jobs_for_payload,
    artifact_structured_discovery_payload_entry,
    artifact_structured_discovery_payload_job,
    artifact_structured_discovery_result_entry,
    artifact_url_cloud_asset_entries,
    artifact_url_cloud_asset_family_entries,
    artifact_url_related_seed_entries,
    artifact_url_seed_persistence_entry,
    artifact_url_social_pivot_entries,
    artifact_social_profile_url_pivot_entry,
    artifact_queue_dispatch_result_from_row,
    artifact_remote_download_reconciliation_result_from_item,
    artifact_progress_snapshot,
    artifact_progress_stage_label,
    artifact_queue_rows_process_callbacks_from_services,
    download_remote_artifact_batch,
    decode_artifact_data_uri_bytes,
    collect_artifact_text_discoveries,
    collect_artifact_text_discovery_batches,
    collect_artifact_text_discovery_job_result,
    collect_artifact_cloud_asset_text_discovery_family,
    collect_artifact_identity_text_discovery_family,
    collect_artifact_key_text_discovery_family,
    collect_artifact_network_host_text_discovery_family,
    collect_artifact_simple_text_discovery_family,
    collect_artifact_url_text_discovery_family,
    expand_artifact_structured_discovery_jobs,
    extract_cloud_config_family,
    extract_cloud_configs_from_payload,
    extract_cloud_configs_from_payloads,
    extract_mobile_configs_from_member_bytes,
    extract_mobile_bundle_family,
    extract_mobile_bundle_text_payloads,
    extract_nested_mobile_bundle_configs,
    extract_nested_mobile_configs_from_7z,
    extract_nested_mobile_configs_from_member_jobs,
    extract_nested_mobile_configs_from_tar,
    extract_nested_mobile_configs_from_zip,
    ingest_local_artifacts_for_engagement,
    nested_mobile_7z_member_entry,
    nested_mobile_member_job,
    nested_mobile_member_result_entry,
    nested_mobile_tar_member_entry,
    nested_mobile_zip_member_entry,
    parse_artifact_work_item,
    parse_local_artifact_batch,
    payload_cloud_config_job,
    payload_cloud_config_result_entry,
    persist_generic_text_discovery_batch,
    persist_parsed_artifact,
    firebase_project_persistence_entry,
    rebased_mobile_member_config_entry,
    rebased_mobile_member_payload_entry,
    rebased_mobile_member_project_entry,
    merge_artifact_relation_context,
    process_artifact_queue_for_engagement,
    run_ordered_local_artifact_batch,
    scan_mobile_bundle_artifact,
    scan_text_artifact,
    safe_artifact_relation_context,
    store_firebase_projects,
    store_artifact_cloud_asset_reference,
    store_cloud_assets_from_url_entries,
    store_social_profile_url_pivots,
    store_supabase_configs,
    supabase_config_persistence_entry,
)


@dataclass(frozen=True)
class ArtifactProcessorRuntimeServices:
    run_ordered_batch: Callable[..., list[Any]]
    local_artifact_record: Callable[[Path], tuple[str, str, dict[str, Any]] | None]
    local_artifact_metadata_matches: Callable[[Any, dict[str, Any]], bool]
    dispatch_one: Callable[[tuple[int, Any]], Any]
    download_remote_artifacts: Callable[
        [list[ArtifactDownloadRequest]],
        Sequence[ArtifactDownloadResult],
    ]
    reconcile_one: Callable[
        [tuple[int, ArtifactDownloadRequest, ArtifactDownloadResult]],
        Any,
    ]
    update_artifact_status: Callable[..., None]
    set_artifact_local_path: Callable[..., None]
    parse_local_artifacts: Callable[
        [list[ArtifactWorkItem]],
        Sequence[ParsedArtifact],
    ]
    persist_parsed_artifact: Callable[[Any, ParsedArtifact], tuple[int, int, int, dict[str, Any]]]


class ArtifactProcessorRuntimeAdapter(Protocol):
    _db_path: Path
    _engagement_id: int
    _max_workers: int
    _classify_artifact: Callable[[Path], str | None]
    _resolve_local_path: Callable[[str, str], Path | None]
    _parse_local_artifact: Callable[[ArtifactWorkItem], ParsedArtifact]
    _scan_mobile_bundle_artifact: Callable[..., Any]
    _scan_text_artifact: Callable[..., Any]
    _extract_mobile_bundle_family: Callable[..., Any]
    _extract_mobile_bundle_text_payloads: Callable[[Path], list[Any]]
    _extract_text_payloads_from_zip: Callable[..., list[tuple[str, str, str]]]
    _extract_text_payloads_from_tar: Callable[..., list[tuple[str, str, str]]]
    _extract_text_artifact_stage: Callable[..., Any]
    _extract_text_payloads: Callable[[Path], list[tuple[str, str, str]]]
    _extract_nested_mobile_bundle_configs: Callable[..., Any]
    _extract_nested_mobile_configs_from_zip: Callable[..., Any]
    _extract_nested_mobile_configs_from_7z: Callable[..., Any]
    _extract_nested_mobile_configs_from_tar: Callable[..., Any]
    _nested_mobile_zip_member_entry: Callable[..., Any]
    _nested_mobile_tar_member_entry: Callable[..., Any]
    _nested_mobile_7z_member_entry: Callable[..., Any]
    _nested_mobile_member_job: Callable[..., Any]
    _nested_mobile_member_result_entry: Callable[..., Any]
    _extract_nested_mobile_configs_from_member_jobs: Callable[..., Any]
    _extract_mobile_configs_from_member_bytes: Callable[..., Any]
    _rebased_mobile_member_payload_entry: Callable[..., Any]
    _rebased_mobile_member_project_entry: Callable[..., Any]
    _rebased_mobile_member_config_entry: Callable[..., Any]
    _artifact_source_seed_provenance: Callable[..., Any]
    _artifact_relation_context: Callable[..., Any]
    _artifact_source_seed_id: Callable[..., Any]
    _ensure_local_artifact_source_seed: Callable[..., Any]
    _artifact_discovery_payloads: Callable[..., Any]
    _expand_structured_discovery_jobs: Callable[..., Any]
    _structured_discovery_payload_job: Callable[..., Any]
    _structured_discovery_jobs_for_payload: Callable[..., Any]
    _structured_discovery_result_entry: Callable[..., Any]
    _structured_discovery_payload_entry: Callable[..., Any]
    _build_structured_discovery_payload_fragment: Callable[..., Any]
    _STRUCTURED_DISCOVERY_FAMILIES: tuple[str, ...]
    _decode_text_artifact_bytes: Callable[..., Any]
    _data_uri_payload_entry: Callable[..., Any]
    _data_uri_image_payload_entry: Callable[..., Any]
    _ocr_image_bytes: Callable[..., Any]
    _barcode_image_bytes_payload: Callable[..., Any]
    _image_metadata_payload: Callable[..., Any]
    _iac_text_structured_payload_family: Callable[..., Any]
    _terraform_text_structured_payload_text: Callable[..., Any]
    _bicep_text_structured_payload_text: Callable[..., Any]
    _artifact_child_seed_depth: Callable[..., Any]
    _artifact_text_email_persistence_entry: Callable[..., Any]
    _artifact_text_phone_persistence_entry: Callable[..., Any]
    _artifact_text_ip_persistence_entry: Callable[..., Any]
    _artifact_text_host_persistence_entry: Callable[..., Any]
    _artifact_text_url_persistence_entry: Callable[..., Any]
    _artifact_text_identity_seed_persistence_entry: Callable[..., Any]
    _artifact_text_key_finding_persistence_entry: Callable[..., Any]
    _artifact_text_cloud_asset_persistence_entry: Callable[..., Any]
    _firebase_project_persistence_entry: Callable[..., Any]
    _supabase_config_persistence_entry: Callable[..., Any]
    _insert_email: Callable[..., Any]
    _store_cloud_asset_reference: Callable[..., Any]
    _insert_seed: Callable[..., Any]
    _link_artifact_source_seed: Callable[..., Any]
    _store_artifact_url_seed: Callable[..., Any]
    _store_key_finding: Callable[..., Any]
    _merge_artifact_relation_context: Callable[..., Any]
    _merge_artifact_metadata_into_seed: Callable[..., Any]
    _artifact_cloud_asset_metadata: Callable[..., Any]
    _generic_text_discovery_job: Callable[..., Any]
    _collect_generic_text_discovery_job_result: Callable[..., Any]
    _collect_generic_text_discoveries: Callable[..., Any]
    _collect_generic_text_discovery_family: Callable[..., Any]
    _artifact_text_url_family_candidates: Callable[..., Any]
    _artifact_text_direct_url_candidate: Callable[..., Any]
    _artifact_text_contact_identity_candidates: Callable[..., Any]
    _artifact_text_key_pattern_findings: Callable[..., Any]
    _artifact_text_cloud_asset_family_candidates: Callable[..., Any]
    _artifact_key_patterns: list[Any]
    _artifact_text_discovery_family_entry: Callable[..., Any]
    _artifact_text_discovery_merge_entry: Callable[..., Any]
    _merge_artifact_text_discovery_batch: Callable[..., Any]
    _collect_generic_text_discovery_batches: Callable[..., Any]
    _persist_generic_text_discovery_batch: Callable[..., Any]
    _artifact_url_seed_family_entry: Callable[..., Any]
    _artifact_url_seed_family_merge_entry: Callable[..., Any]
    _artifact_url_social_pivot_entries: Callable[..., Any]
    _artifact_url_related_seed_entries: Callable[..., Any]
    _artifact_url_cloud_asset_entries: Callable[..., Any]
    _social_profile_url_pivot_entry: Callable[..., Any]
    _cloud_asset_url_entry: Callable[..., Any]
    _audit_artifact_lineage: Callable[..., Any]
    _lookup_seed_id: Callable[..., Any]
    _insert_relation: Callable[..., Any]
    _extract_cloud_configs_from_payloads: Callable[..., Any]
    _extract_cloud_configs_from_payload: Callable[..., Any]
    _extract_cloud_config_family: Callable[..., Any]
    _extract_firebase_from_text: Callable[[str, str, str], list[Any]]
    _payload_cloud_config_job: Callable[[tuple[str, str, str]], tuple[str, str, str] | None]
    _payload_cloud_config_result_entry: Callable[..., Any]
    _extractor: Any
    _artifact_payload_summary: Callable[..., Any]
    _dedupe_firebase_projects: Callable[..., Any]
    _store_firebase_projects: Callable[..., Any]
    _dedupe_supabase_configs: Callable[..., Any]
    _store_supabase_configs: Callable[..., Any]
    _remote_url_scope_checker: Callable[[str], tuple[bool, str]]
    _remote_scope_denied_callback: Callable[[ArtifactDownloadRequest, str], ArtifactDownloadResult]
    _download_remote_artifact_request: Callable[[ArtifactDownloadRequest], ArtifactDownloadResult]
    _run_ordered_local_batch: Callable[..., list[Any]]
    _local_artifact_record: Callable[[Path], tuple[str, str, dict[str, Any]] | None]
    _local_artifact_metadata_matches: Callable[[Any, dict[str, Any]], bool]
    _artifact_queue_dispatch_entry: Callable[[tuple[int, Any]], Any]
    _download_remote_artifacts: Callable[
        [list[ArtifactDownloadRequest]],
        Sequence[ArtifactDownloadResult],
    ]
    _remote_download_reconciliation_entry: Callable[
        [tuple[int, ArtifactDownloadRequest, ArtifactDownloadResult]],
        Any,
    ]
    _update_artifact_status: Callable[..., None]
    _set_artifact_local_path: Callable[..., None]
    _parse_local_artifacts: Callable[
        [list[ArtifactWorkItem]],
        Sequence[ParsedArtifact],
    ]
    _persist_parsed_artifact: Callable[[Any, ParsedArtifact], tuple[int, int, int, dict[str, Any]]]


def artifact_processor_runtime_services(
    adapter: ArtifactProcessorRuntimeAdapter,
) -> ArtifactProcessorRuntimeServices:
    return ArtifactProcessorRuntimeServices(
        run_ordered_batch=adapter._run_ordered_local_batch,
        local_artifact_record=adapter._local_artifact_record,
        local_artifact_metadata_matches=adapter._local_artifact_metadata_matches,
        dispatch_one=adapter._artifact_queue_dispatch_entry,
        download_remote_artifacts=adapter._download_remote_artifacts,
        reconcile_one=adapter._remote_download_reconciliation_entry,
        update_artifact_status=adapter._update_artifact_status,
        set_artifact_local_path=adapter._set_artifact_local_path,
        parse_local_artifacts=adapter._parse_local_artifacts,
        persist_parsed_artifact=adapter._persist_parsed_artifact,
    )


def artifact_processor_local_artifact_metadata(path: Path) -> dict[str, Any]:
    from forge.orchestration.artifacts import local_artifact_metadata

    return local_artifact_metadata(path)


def artifact_processor_local_artifact_metadata_matches(
    existing_metadata: Any,
    current_metadata: dict[str, Any],
) -> bool:
    from forge.orchestration.artifacts import local_artifact_metadata_matches

    return local_artifact_metadata_matches(existing_metadata, current_metadata)


def artifact_processor_local_artifact_record(
    adapter: ArtifactProcessorRuntimeAdapter,
    path: Path,
) -> tuple[str, str, dict[str, Any]] | None:
    from forge.orchestration.artifacts import local_artifact_record

    return local_artifact_record(
        path,
        classify_artifact=adapter._classify_artifact,
        local_artifact_metadata=artifact_processor_local_artifact_metadata,
    )


def artifact_processor_dispatch_entry(
    adapter: ArtifactProcessorRuntimeAdapter,
    item: tuple[int, Any],
) -> tuple[int, ArtifactWorkItem | None, ArtifactDownloadRequest | None, tuple[int, str] | None] | None:
    return artifact_queue_dispatch_result_from_row(
        item,
        resolve_local_path=adapter._resolve_local_path,
        classify_artifact=adapter._classify_artifact,
    )


def artifact_processor_remote_download_reconciliation_entry(
    adapter: ArtifactProcessorRuntimeAdapter,
    item: tuple[int, ArtifactDownloadRequest, ArtifactDownloadResult],
) -> tuple[
    int,
    tuple[int, str] | None,
    tuple[int, str] | None,
    tuple[int, Path, str, dict[str, Any]] | None,
    ArtifactWorkItem | None,
] | None:
    return artifact_remote_download_reconciliation_result_from_item(
        item,
        classify_artifact=adapter._classify_artifact,
    )


def parse_local_artifacts_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    work_items: list[ArtifactWorkItem],
    *,
    progress_label: str | None = None,
    progress_callback: Callable[[str, dict[str, object]], None] | None = None,
) -> list[ParsedArtifact]:
    return parse_local_artifact_batch(
        work_items,
        max_workers=adapter._max_workers,
        parse_one=adapter._parse_local_artifact,
        progress_label=progress_label,
        progress_callback=progress_callback,
    )


def download_remote_artifacts_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    requests: list[ArtifactDownloadRequest],
    *,
    progress_label: str | None = None,
    progress_callback: Callable[[str, dict[str, object]], None] | None = None,
) -> list[ArtifactDownloadResult]:
    return download_remote_artifact_batch(
        requests,
        max_workers=adapter._max_workers,
        remote_url_scope_checker=adapter._remote_url_scope_checker,
        remote_scope_denied_callback=adapter._remote_scope_denied_callback,
        download_one=adapter._download_remote_artifact_request,
        progress_label=progress_label,
        progress_callback=progress_callback,
    )


def parse_artifact_work_item_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    work_item: ArtifactWorkItem,
    *,
    artifact_format_label: Callable[[str | Path], str],
) -> ParsedArtifact:
    return parse_artifact_work_item(
        work_item,
        scan_mobile_bundle_artifact=adapter._scan_mobile_bundle_artifact,
        scan_text_artifact=adapter._scan_text_artifact,
        artifact_format_label=artifact_format_label,
    )


def scan_mobile_bundle_artifact_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    path: Path,
    artifact_type: str,
) -> tuple[list[Any], list[Any], list[Any], dict[str, Any]]:
    return scan_mobile_bundle_artifact(
        path,
        artifact_type,
        run_ordered_batch=adapter._run_ordered_local_batch,
        extract_mobile_bundle_family=adapter._extract_mobile_bundle_family,
        extract_cloud_configs_from_payloads=adapter._extract_cloud_configs_from_payloads,
        artifact_payload_summary=adapter._artifact_payload_summary,
        dedupe_firebase_projects=adapter._dedupe_firebase_projects,
        dedupe_supabase_configs=adapter._dedupe_supabase_configs,
    )


def scan_text_artifact_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    path: Path,
    artifact_type: str,
) -> tuple[list[Any], list[Any], list[Any], dict[str, Any]]:
    return scan_text_artifact(
        path,
        artifact_type,
        run_ordered_batch=adapter._run_ordered_local_batch,
        extract_text_artifact_stage=adapter._extract_text_artifact_stage,
        extract_cloud_configs_from_payloads=adapter._extract_cloud_configs_from_payloads,
        artifact_payload_summary=adapter._artifact_payload_summary,
        dedupe_firebase_projects=adapter._dedupe_firebase_projects,
        dedupe_supabase_configs=adapter._dedupe_supabase_configs,
    )


def extract_mobile_bundle_family_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    family: str,
    *,
    path: Path,
    artifact_type: str,
) -> list[Any]:
    return extract_mobile_bundle_family(
        family,
        path=path,
        artifact_type=artifact_type,
        extract_mobile_bundle_text_payloads=adapter._extract_mobile_bundle_text_payloads,
        extract_apk=adapter._extractor.extract_apk,
        extract_supabase_apk=adapter._extractor.extract_supabase_apk,
        extract_ipa=adapter._extractor.extract_ipa,
        extract_supabase_ipa=adapter._extractor.extract_supabase_ipa,
    )


def extract_text_artifact_stage_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    family: str,
    *,
    path: Path,
    artifact_type: str,
) -> ArtifactTextScanStageResult:
    return artifact_text_scan_stage(
        family,
        path=path,
        artifact_type=artifact_type,
        extract_text_payloads=adapter._extract_text_payloads,
        extract_nested_mobile_bundle_configs=adapter._extract_nested_mobile_bundle_configs,
    )


def extract_mobile_bundle_text_payloads_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    path: Path,
) -> list[tuple[str, str, str]]:
    return extract_mobile_bundle_text_payloads(
        path,
        extract_text_payloads_from_zip=adapter._extract_text_payloads_from_zip,
        extract_text_payloads_from_tar=adapter._extract_text_payloads_from_tar,
    )


def run_ordered_local_batch_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    items: Sequence[Any],
    worker: Callable[[Any], Any],
    *,
    default_factory: Callable[[], Any],
) -> list[Any]:
    return run_ordered_local_artifact_batch(
        items,
        worker,
        default_factory=default_factory,
        max_workers=adapter._max_workers,
    )


def extract_cloud_configs_from_payloads_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    payloads: list[tuple[str, str, str]],
) -> tuple[list[Any], list[Any]]:
    return extract_cloud_configs_from_payloads(
        payloads,
        run_ordered_batch=adapter._run_ordered_local_batch,
        payload_cloud_config_job=adapter._payload_cloud_config_job,
        extract_cloud_configs_from_payload=adapter._extract_cloud_configs_from_payload,
        payload_cloud_config_result_entry=adapter._payload_cloud_config_result_entry,
    )


def payload_cloud_config_job_for_processor(
    payload: tuple[str, str, str],
) -> tuple[str, str, str] | None:
    return payload_cloud_config_job(payload)


def payload_cloud_config_result_entry_for_processor(
    result_batch: tuple[int, tuple[list[Any], list[Any]] | None],
) -> tuple[list[Any], list[Any]] | None:
    return payload_cloud_config_result_entry(result_batch)


def extract_cloud_configs_from_payload_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    source_file: str,
    extract_path: str,
    text: str,
) -> tuple[list[Any], list[Any]]:
    return extract_cloud_configs_from_payload(
        source_file,
        extract_path,
        text,
        run_ordered_batch=adapter._run_ordered_local_batch,
        extract_cloud_config_family=adapter._extract_cloud_config_family,
    )


def extract_cloud_config_family_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    family: str,
    *,
    source_file: str,
    extract_path: str,
    text: str,
) -> list[Any]:
    return extract_cloud_config_family(
        family,
        source_file=source_file,
        extract_path=extract_path,
        text=text,
        extract_firebase_from_text=adapter._extract_firebase_from_text,
        extract_supabase_from_text=adapter._extractor._extract_supabase_from_text,  # noqa: SLF001
    )


def extract_nested_mobile_bundle_configs_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    path: Path,
    artifact_type: str,
    *,
    py7zr_available: bool,
) -> tuple[list[tuple[str, str, str]], list[Any], list[Any], int]:
    return extract_nested_mobile_bundle_configs(
        path,
        artifact_type,
        py7zr_available=py7zr_available,
        extract_nested_mobile_configs_from_zip=adapter._extract_nested_mobile_configs_from_zip,
        extract_nested_mobile_configs_from_7z=adapter._extract_nested_mobile_configs_from_7z,
        extract_nested_mobile_configs_from_tar=adapter._extract_nested_mobile_configs_from_tar,
    )


def nested_mobile_zip_member_entry_for_processor(
    member: Any,
    *,
    nested_mobile_artifact_suffixes: set[str],
    remote_artifact_max_bytes: int,
) -> dict[str, str] | None:
    return nested_mobile_zip_member_entry(
        member,
        nested_mobile_artifact_suffixes=nested_mobile_artifact_suffixes,
        remote_artifact_max_bytes=remote_artifact_max_bytes,
    )


def nested_mobile_tar_member_entry_for_processor(
    member: Any,
    *,
    nested_mobile_artifact_suffixes: set[str],
    remote_artifact_max_bytes: int,
) -> dict[str, str] | None:
    return nested_mobile_tar_member_entry(
        member,
        nested_mobile_artifact_suffixes=nested_mobile_artifact_suffixes,
        remote_artifact_max_bytes=remote_artifact_max_bytes,
    )


def nested_mobile_7z_member_entry_for_processor(
    member: Any,
    *,
    safe_archive_member_name: Callable[[str], str],
    nested_mobile_artifact_suffixes: set[str],
    remote_artifact_max_bytes: int,
) -> dict[str, str] | None:
    return nested_mobile_7z_member_entry(
        member,
        safe_archive_member_name=safe_archive_member_name,
        nested_mobile_artifact_suffixes=nested_mobile_artifact_suffixes,
        remote_artifact_max_bytes=remote_artifact_max_bytes,
    )


def extract_nested_mobile_configs_from_zip_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    zf: Any,
    source_path: Path,
) -> tuple[list[tuple[str, str, str]], list[Any], list[Any], int]:
    return extract_nested_mobile_configs_from_zip(
        zf,
        source_path,
        run_ordered_batch=adapter._run_ordered_local_batch,
        nested_mobile_zip_member_entry=adapter._nested_mobile_zip_member_entry,
        nested_mobile_member_job=adapter._nested_mobile_member_job,
        extract_nested_mobile_configs_from_member_jobs=adapter._extract_nested_mobile_configs_from_member_jobs,
    )


def extract_nested_mobile_configs_from_tar_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    tf: Any,
    source_path: Path,
) -> tuple[list[tuple[str, str, str]], list[Any], list[Any], int]:
    return extract_nested_mobile_configs_from_tar(
        tf,
        source_path,
        run_ordered_batch=adapter._run_ordered_local_batch,
        nested_mobile_tar_member_entry=adapter._nested_mobile_tar_member_entry,
        nested_mobile_member_job=adapter._nested_mobile_member_job,
        extract_nested_mobile_configs_from_member_jobs=adapter._extract_nested_mobile_configs_from_member_jobs,
    )


def extract_nested_mobile_configs_from_7z_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    data: bytes,
    source_path: Path,
    *,
    seven_zip_file_factory: Callable[..., Any] | None,
    remote_artifact_max_bytes: int,
) -> tuple[list[tuple[str, str, str]], list[Any], list[Any], int]:
    return extract_nested_mobile_configs_from_7z(
        data,
        source_path,
        seven_zip_file_factory=seven_zip_file_factory,
        run_ordered_batch=adapter._run_ordered_local_batch,
        nested_mobile_7z_member_entry=adapter._nested_mobile_7z_member_entry,
        nested_mobile_member_job=adapter._nested_mobile_member_job,
        extract_nested_mobile_configs_from_member_jobs=adapter._extract_nested_mobile_configs_from_member_jobs,
        remote_artifact_max_bytes=remote_artifact_max_bytes,
    )


def nested_mobile_member_job_for_processor(
    member_job: tuple[str, bytes],
) -> tuple[str, bytes] | None:
    return nested_mobile_member_job(member_job)


def extract_nested_mobile_configs_from_member_jobs_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    member_jobs: list[tuple[str, bytes]],
    source_path: Path,
) -> tuple[list[tuple[str, str, str]], list[Any], list[Any], int]:
    return extract_nested_mobile_configs_from_member_jobs(
        member_jobs,
        source_path,
        run_ordered_batch=adapter._run_ordered_local_batch,
        extract_mobile_configs_from_member_bytes=adapter._extract_mobile_configs_from_member_bytes,
        nested_mobile_member_result_entry=adapter._nested_mobile_member_result_entry,
    )


def nested_mobile_member_result_entry_for_processor(
    result_entry: tuple[
        int,
        tuple[list[tuple[str, str, str]], list[Any], list[Any]] | None,
    ],
) -> tuple[list[tuple[str, str, str]], list[Any], list[Any]] | None:
    return nested_mobile_member_result_entry(result_entry)


def extract_mobile_configs_from_member_bytes_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    data: bytes,
    source_path: Path,
    member_name: str,
    *,
    nested_mobile_artifact_suffixes: set[str],
    archive_style_mobile_artifact_suffixes: set[str],
    remote_artifact_max_bytes: int,
    firebase_project_type: type[Any],
    supabase_config_type: type[Any],
) -> tuple[list[tuple[str, str, str]], list[Any], list[Any]]:
    return extract_mobile_configs_from_member_bytes(
        data,
        source_path,
        member_name,
        nested_mobile_artifact_suffixes=nested_mobile_artifact_suffixes,
        archive_style_mobile_artifact_suffixes=archive_style_mobile_artifact_suffixes,
        remote_artifact_max_bytes=remote_artifact_max_bytes,
        run_ordered_batch=adapter._run_ordered_local_batch,
        scan_text_artifact=adapter._scan_text_artifact,
        extract_mobile_bundle_family=adapter._extract_mobile_bundle_family,
        rebased_mobile_member_payload_entry=adapter._rebased_mobile_member_payload_entry,
        rebased_mobile_member_project_entry=adapter._rebased_mobile_member_project_entry,
        rebased_mobile_member_config_entry=adapter._rebased_mobile_member_config_entry,
        firebase_project_type=firebase_project_type,
        supabase_config_type=supabase_config_type,
    )


def rebased_mobile_member_payload_entry_for_processor(
    payload: tuple[str, str, str],
    *,
    source_path: Path,
    member_name: str,
) -> tuple[str, str, str] | None:
    return rebased_mobile_member_payload_entry(
        payload,
        source_path=source_path,
        member_name=member_name,
    )


def rebased_mobile_member_project_entry_for_processor(
    project: Any,
    *,
    source_path: Path,
    member_name: str,
    firebase_project_type: type[Any],
) -> Any:
    return rebased_mobile_member_project_entry(
        project,
        source_path=source_path,
        member_name=member_name,
        firebase_project_type=firebase_project_type,
    )


def rebased_mobile_member_config_entry_for_processor(
    config: Any,
    *,
    source_path: Path,
    member_name: str,
    supabase_config_type: type[Any],
) -> Any:
    return rebased_mobile_member_config_entry(
        config,
        source_path=source_path,
        member_name=member_name,
        supabase_config_type=supabase_config_type,
    )


def safe_artifact_relation_context_for_processor(
    parsed: ParsedArtifact,
    artifact_metadata: Any,
) -> dict[str, Any]:
    return safe_artifact_relation_context(
        parse_metadata=parsed.parse_metadata,
        artifact_type=parsed.artifact_type,
        artifact_metadata=artifact_metadata,
    )


def merge_artifact_relation_context_for_processor(
    relation_metadata: dict[str, Any] | None,
    artifact_context: dict[str, Any] | None,
) -> dict[str, Any]:
    return merge_artifact_relation_context(relation_metadata, artifact_context)


def artifact_cloud_asset_metadata_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    con: sqlite3.Connection,
    *,
    source_seed_id: int | None,
    relation_metadata: dict[str, Any] | None,
    artifact_context: dict[str, Any] | None,
) -> dict[str, Any]:
    return artifact_cloud_asset_metadata(
        source_seed_id=source_seed_id,
        relation_metadata=relation_metadata,
        artifact_context=artifact_context,
        artifact_source_seed_provenance=lambda seed_id: adapter._artifact_source_seed_provenance(
            con,
            seed_id,
        ),
    )


def artifact_relation_context_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    con: sqlite3.Connection,
    parsed: ParsedArtifact,
) -> dict[str, Any]:
    return artifact_relation_context_from_queue(
        con,
        adapter._engagement_id,
        parsed,
    )


def persist_parsed_artifact_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    con: sqlite3.Connection,
    parsed: ParsedArtifact,
) -> tuple[int, int, int, dict[str, Any]]:
    return persist_parsed_artifact(
        con,
        parsed,
        artifact_relation_context=adapter._artifact_relation_context,
        artifact_source_seed_id=adapter._artifact_source_seed_id,
        ensure_local_artifact_source_seed=adapter._ensure_local_artifact_source_seed,
        artifact_discovery_payloads=adapter._artifact_discovery_payloads,
        expand_structured_discovery_jobs=adapter._expand_structured_discovery_jobs,
        collect_generic_text_discovery_batches=adapter._collect_generic_text_discovery_batches,
        persist_generic_text_discovery_batch=adapter._persist_generic_text_discovery_batch,
        dedupe_firebase_projects=adapter._dedupe_firebase_projects,
        store_firebase_projects=adapter._store_firebase_projects,
        dedupe_supabase_configs=adapter._dedupe_supabase_configs,
        store_supabase_configs=adapter._store_supabase_configs,
    )


def persist_generic_text_discovery_batch_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    con: sqlite3.Connection,
    batch: ArtifactTextDiscoveryBatch,
    *,
    source_seed_id: int | None = None,
    artifact_context: dict[str, Any] | None = None,
) -> int:
    return persist_generic_text_discovery_batch(
        con,
        batch,
        source_seed_id=source_seed_id,
        artifact_context=artifact_context,
        artifact_child_seed_depth=adapter._artifact_child_seed_depth,
        run_ordered_batch=adapter._run_ordered_local_batch,
        artifact_text_email_persistence_entry=adapter._artifact_text_email_persistence_entry,
        artifact_text_phone_persistence_entry=adapter._artifact_text_phone_persistence_entry,
        artifact_text_ip_persistence_entry=adapter._artifact_text_ip_persistence_entry,
        artifact_text_host_persistence_entry=adapter._artifact_text_host_persistence_entry,
        artifact_text_url_persistence_entry=adapter._artifact_text_url_persistence_entry,
        artifact_text_identity_seed_persistence_entry=adapter._artifact_text_identity_seed_persistence_entry,
        artifact_text_key_finding_persistence_entry=adapter._artifact_text_key_finding_persistence_entry,
        artifact_text_cloud_asset_persistence_entry=adapter._artifact_text_cloud_asset_persistence_entry,
        insert_email=adapter._insert_email,
        insert_seed=adapter._insert_seed,
        link_artifact_source_seed=adapter._link_artifact_source_seed,
        store_artifact_url_seed=adapter._store_artifact_url_seed,
        merge_artifact_relation_context_fn=adapter._merge_artifact_relation_context,
        merge_artifact_metadata_into_seed=adapter._merge_artifact_metadata_into_seed,
        store_key_finding=adapter._store_key_finding,
        artifact_cloud_asset_metadata=adapter._artifact_cloud_asset_metadata,
        store_cloud_asset_reference=adapter._store_cloud_asset_reference,
    )


def store_generic_text_discoveries_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    con: sqlite3.Connection,
    text: str,
    *,
    source_file: str,
    source_seed_id: int | None = None,
) -> int:
    batch = adapter._collect_generic_text_discoveries(
        text,
        source_file=source_file,
    )
    return adapter._persist_generic_text_discovery_batch(
        con,
        batch,
        source_seed_id=source_seed_id,
    )


def artifact_url_seed_persistence_entry_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    url: str,
    *,
    relation_metadata: dict[str, Any] | None = None,
    artifact_url_looks_templated: Callable[[object], bool],
    artifact_url_looks_standards_namespace: Callable[[str], bool],
    is_mobile_bundle_url: Callable[[str], bool],
) -> dict[str, Any] | None:
    return artifact_url_seed_persistence_entry(
        url,
        relation_metadata=relation_metadata,
        artifact_url_looks_templated=artifact_url_looks_templated,
        artifact_url_looks_standards_namespace=artifact_url_looks_standards_namespace,
        is_mobile_bundle_url=is_mobile_bundle_url,
        run_ordered_batch=adapter._run_ordered_local_batch,
        artifact_url_seed_family_entry=adapter._artifact_url_seed_family_entry,
        artifact_url_seed_family_merge_entry=adapter._artifact_url_seed_family_merge_entry,
    )


def artifact_url_seed_family_entry_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    family: str,
    *,
    url: str,
    hostname: str,
    relation_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if family == "social_pivots":
        return {
            "social_pivot_entries": adapter._artifact_url_social_pivot_entries(
                url,
                relation_metadata=relation_metadata,
            )
        }
    if family == "related_seeds":
        return {"related_seed_entries": adapter._artifact_url_related_seed_entries(hostname)}
    if family == "cloud_assets":
        return {
            "cloud_asset_entries": adapter._artifact_url_cloud_asset_entries(
                url,
                source="artifact_url_extract",
            )
        }
    return {}


def artifact_url_related_seed_entries_for_processor(
    hostname: str,
    *,
    is_social_platform_host: Callable[[str], bool],
    is_managed_cloud_provider_host: Callable[[str], bool],
    normalize_root_domain: Callable[[str], str],
) -> list[dict[str, Any]]:
    return artifact_url_related_seed_entries(
        hostname,
        is_social_platform_host=is_social_platform_host,
        is_managed_cloud_provider_host=is_managed_cloud_provider_host,
        normalize_root_domain=normalize_root_domain,
    )


def artifact_url_social_pivot_entries_for_processor(
    url: str,
    *,
    relation_metadata: dict[str, Any] | None = None,
    social_profile_platform_hint: Callable[[dict[str, Any]], str],
    extract_social_profile_handle_from_url: Callable[[str], str],
    classify_seed_value: Callable[[str], str],
    social_profile_company_name: Callable[..., str],
    social_profile_name: Callable[[dict[str, Any]], str],
) -> list[dict[str, Any]]:
    return artifact_url_social_pivot_entries(
        url,
        relation_metadata=relation_metadata,
        social_profile_platform_hint=social_profile_platform_hint,
        extract_social_profile_handle_from_url=extract_social_profile_handle_from_url,
        classify_seed_value=classify_seed_value,
        social_profile_company_name=social_profile_company_name,
        social_profile_name=social_profile_name,
    )


def artifact_url_cloud_asset_entries_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    url: str,
    *,
    source: str,
) -> list[dict[str, Any]]:
    return artifact_url_cloud_asset_entries(
        url,
        source=source,
        run_ordered_batch=adapter._run_ordered_local_batch,
        artifact_url_cloud_asset_family_entries=adapter._artifact_url_cloud_asset_family_entries,
    )


def artifact_url_cloud_asset_family_entries_for_processor(
    family: str,
    *,
    url: str,
    hostname: str,
    source: str,
    aws_s3_url_patterns: tuple[Any, ...],
    do_spaces_url_patterns: tuple[Any, ...],
    gcs_url_patterns: tuple[Any, ...],
    azure_blob_url_patterns: tuple[Any, ...],
    azure_static_website_host_re: Any,
    azure_key_vault_url_re: Any,
    cloudflare_workers_host_re: Any,
    cloudflare_pages_host_re: Any,
    cloudflare_r2_host_re: Any,
) -> list[dict[str, Any]]:
    return artifact_url_cloud_asset_family_entries(
        family,
        url=url,
        hostname=hostname,
        source=source,
        aws_s3_url_patterns=aws_s3_url_patterns,
        do_spaces_url_patterns=do_spaces_url_patterns,
        gcs_url_patterns=gcs_url_patterns,
        azure_blob_url_patterns=azure_blob_url_patterns,
        azure_static_website_host_re=azure_static_website_host_re,
        azure_key_vault_url_re=azure_key_vault_url_re,
        cloudflare_workers_host_re=cloudflare_workers_host_re,
        cloudflare_pages_host_re=cloudflare_pages_host_re,
        cloudflare_r2_host_re=cloudflare_r2_host_re,
    )


def store_social_profile_url_pivots_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    con: sqlite3.Connection,
    engagement_id: int,
    url: str,
    *,
    seed_type: str,
    relation_metadata: dict[str, Any] | None = None,
    pivot_entries: list[dict[str, Any]] | None = None,
    depth: int = 1,
) -> None:
    url_seed_id = adapter._lookup_seed_id(con, url, seed_type)
    if url_seed_id is None:
        return
    prepared_pivot_entries = (
        pivot_entries
        if pivot_entries is not None
        else adapter._artifact_url_social_pivot_entries(
            url,
            relation_metadata=relation_metadata,
        )
    )
    store_social_profile_url_pivots(
        con,
        engagement_id,
        url,
        seed_type=seed_type,
        pivot_entries=list(prepared_pivot_entries),
        depth=depth,
        run_ordered_batch=adapter._run_ordered_local_batch,
        social_profile_url_pivot_entry=adapter._social_profile_url_pivot_entry,
        lookup_seed_id=adapter._lookup_seed_id,
        insert_seed=adapter._insert_seed,
        insert_relation=adapter._insert_relation,
    )


def store_cloud_assets_from_url_entries_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    con: sqlite3.Connection,
    url: str,
    *,
    source: str,
    cloud_asset_entries: list[dict[str, Any]] | None = None,
    source_seed_id: int | None = None,
    relation_metadata: dict[str, Any] | None = None,
) -> None:
    prepared_cloud_asset_entries = (
        cloud_asset_entries
        if cloud_asset_entries is not None
        else adapter._artifact_url_cloud_asset_entries(url, source=source)
    )
    store_cloud_assets_from_url_entries(
        con,
        source_seed_id=source_seed_id,
        relation_metadata=relation_metadata,
        cloud_asset_entries=list(prepared_cloud_asset_entries),
        run_ordered_batch=adapter._run_ordered_local_batch,
        cloud_asset_url_entry=adapter._cloud_asset_url_entry,
        artifact_cloud_asset_metadata=adapter._artifact_cloud_asset_metadata,
        store_cloud_asset_reference=adapter._store_cloud_asset_reference,
    )


def artifact_social_profile_url_pivot_entry_for_processor(
    pivot_entry: tuple[int, dict[str, Any]],
) -> dict[str, Any] | None:
    return artifact_social_profile_url_pivot_entry(pivot_entry)


def artifact_cloud_asset_url_entry_for_processor(
    cloud_asset_entry: tuple[int, dict[str, Any]],
) -> dict[str, str] | None:
    return artifact_cloud_asset_url_entry(cloud_asset_entry)


def store_artifact_cloud_asset_reference_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    asset_type: str,
    identifier: str,
    source: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    def _audit_lineage(*, action: str, target: str, result: str) -> None:
        adapter._audit_artifact_lineage(
            con,
            action=action,
            target=target,
            result=result,
        )

    store_artifact_cloud_asset_reference(
        con,
        engagement_id,
        asset_type=asset_type,
        identifier=identifier,
        source=source,
        metadata=metadata,
        audit_artifact_lineage=_audit_lineage,
    )


def firebase_match_entry_for_processor(
    candidate: tuple[str, str],
) -> dict[str, Any] | None:
    raw_match, raw_project_id = candidate
    project_id = str(raw_project_id or "").strip().lower()
    if not project_id:
        return None
    raw_match_text = str(raw_match or "").strip()
    return {
        "project_id": project_id,
        "rtdb_url": raw_match_text if ".firebaseio.com" in raw_match_text.lower() else None,
    }


def extract_firebase_from_text_for_processor(
    text: str,
    source_file: str,
    extract_path: str,
    *,
    firebase_url_patterns: tuple[Any, ...],
    firebase_api_key_re: Any,
    firebase_storage_bucket_re: Any,
    encrypt_secret_material: Callable[[str], str],
    normalize_storage_bucket: Callable[[str], str],
    run_ordered_batch: Callable[..., list[Any]],
    firebase_match_entry: Callable[[tuple[str, str]], dict[str, Any] | None],
    firebase_project_factory: Callable[..., Any],
) -> list[Any]:
    projects: list[Any] = []
    project_ids: set[str] = set()
    api_key_match = firebase_api_key_re.search(text)
    api_key_enc = encrypt_secret_material(api_key_match.group(0)) if api_key_match else None
    storage_bucket_match = firebase_storage_bucket_re.search(text)
    storage_bucket = (
        normalize_storage_bucket(storage_bucket_match.group(1))
        if storage_bucket_match
        else None
    )
    match_candidates: list[tuple[str, str]] = []
    for pattern in firebase_url_patterns:
        for match in pattern.finditer(text):
            match_candidates.append((match.group(0), str(match.group(1) or "")))
    match_entries = run_ordered_batch(
        match_candidates,
        firebase_match_entry,
        default_factory=lambda: None,
    )
    rtdb_url = None
    for match_entry in match_entries:
        if not isinstance(match_entry, dict):
            continue
        project_id = str(match_entry["project_id"])
        if not project_id or project_id in project_ids:
            continue
        project_ids.add(project_id)
        if match_entry["rtdb_url"]:
            rtdb_url = str(match_entry["rtdb_url"])
        projects.append(
            firebase_project_factory(
                project_id=project_id,
                api_key_enc=api_key_enc,
                rtdb_url=rtdb_url,
                bundle_id=None,
                source_file=source_file,
                extract_path=extract_path,
                storage_bucket=storage_bucket,
            )
        )
    return projects


def terraform_state_payload_family_for_processor(
    family: str,
    *,
    text: str,
    source_file: str,
    member_name: str,
    extract_terraform_state_structured_payloads: Callable[..., list[tuple[str, str, str]]],
    extract_terraform_state_text_payloads: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if family == "structured":
        return extract_terraform_state_structured_payloads(
            text,
            source_file=source_file,
            member_name=member_name,
        )
    if family == "text":
        return extract_terraform_state_text_payloads(
            text,
            source_file=source_file,
            member_name=member_name,
        )
    return []


def terraform_state_text_payloads_for_processor(
    text: str,
    *,
    source_file: str,
    member_name: str,
) -> list[tuple[str, str, str]]:
    if not text.strip():
        return []
    return [(source_file, member_name, text)]


def terraform_state_structured_payloads_for_processor(
    text: str,
    *,
    source_file: str,
    member_name: str,
    terraform_state_structured_payload_text: Callable[[str], str],
) -> list[tuple[str, str, str]]:
    structured_payload = terraform_state_structured_payload_text(text)
    if not structured_payload:
        return []
    return [(source_file, f"{member_name}#tfstate-structured", structured_payload)]


def terraform_state_structured_payload_text_for_processor(
    text: str,
    *,
    safe_json_loads: Callable[[str], Any],
    iter_terraform_state_resource_values: Callable[[dict[str, Any]], list[tuple[str, dict[str, Any]]]],
    terraform_state_resource_candidate: Callable[[tuple[str, dict[str, Any]]], str],
    terraform_structured_candidate_entry: Callable[[tuple[int, str]], tuple[str, str] | None],
    run_ordered_batch: Callable[..., list[Any]],
) -> str:
    payload = safe_json_loads(text)
    if not isinstance(payload, dict):
        return ""

    candidate_lines = run_ordered_batch(
        iter_terraform_state_resource_values(payload),
        terraform_state_resource_candidate,
        default_factory=str,
    )
    prepared_candidate_entries = run_ordered_batch(
        list(enumerate(candidate_lines)),
        terraform_structured_candidate_entry,
        default_factory=lambda: None,
    )
    lines: list[str] = []
    seen: set[str] = set()
    for candidate_entry in prepared_candidate_entries:
        if not isinstance(candidate_entry, tuple) or len(candidate_entry) != 2:
            continue
        candidate, lowered = candidate_entry
        if lowered in seen:
            continue
        seen.add(lowered)
        lines.append(candidate)
    return "\n".join(lines)


def terraform_block_assignments_for_processor(
    block_text: str,
    *,
    terraform_assignment_line_entry: Callable[[tuple[int, str]], tuple[str, str] | None],
    run_ordered_batch: Callable[..., list[Any]],
) -> dict[str, str]:
    assignment_entries = run_ordered_batch(
        list(enumerate(str(block_text or "").splitlines())),
        terraform_assignment_line_entry,
        default_factory=lambda: None,
    )
    assignments: dict[str, str] = {}
    for assignment_entry in assignment_entries:
        if not isinstance(assignment_entry, tuple) or len(assignment_entry) != 2:
            continue
        key, value = assignment_entry
        assignments[key] = value
    return assignments


def terraform_assignment_line_entry_for_processor(
    line_entry: tuple[int, str],
) -> tuple[str, str] | None:
    _line_index, raw_line = line_entry
    stripped = str(raw_line or "").strip()
    if not stripped or stripped.startswith(("#", "//", "/*", "*")):
        return None
    match = re.match(r'([A-Za-z0-9_]+)\s*=\s*"([^"\r\n]+)"', stripped)
    if not match:
        return None
    key = str(match.group(1) or "").strip().lower()
    value = str(match.group(2) or "").strip()
    if not key or not value:
        return None
    return key, value


def iter_terraform_text_blocks_for_processor(
    text: str,
    *,
    terraform_block_start_pattern: Any,
) -> list[tuple[str, str]]:
    lines = str(text or "").splitlines()
    blocks: list[tuple[str, str]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = terraform_block_start_pattern.match(line)
        if not match:
            index += 1
            continue
        resource_type = str(match.group(1) or "").strip().lower()
        brace_depth = line.count("{") - line.count("}")
        block_lines = [line]
        index += 1
        while index < len(lines):
            current = lines[index]
            block_lines.append(current)
            brace_depth += current.count("{") - current.count("}")
            index += 1
            if brace_depth <= 0:
                break
        blocks.append((resource_type, "\n".join(block_lines)))
    return blocks


def terraform_structured_candidate_entry_for_processor(
    candidate_entry: tuple[int, str],
) -> tuple[str, str] | None:
    _candidate_index, candidate = candidate_entry
    value = str(candidate or "").strip()
    if not value:
        return None
    return value, value.lower()


def terraform_text_structured_payload_text_for_processor(
    text: str,
    *,
    source_hint: str = "",
    iter_terraform_text_blocks: Callable[[str], list[tuple[str, str]]],
    terraform_text_block_candidate: Callable[[tuple[str, str]], str],
    terraform_backend_config_candidates: Callable[[str], list[str]],
    terragrunt_remote_state_backend_candidates: Callable[[str], list[str]],
    terraform_structured_candidate_entry: Callable[[tuple[int, str]], tuple[str, str] | None],
    looks_like_terraform_backend_config_name: Callable[[str], bool],
    looks_like_terragrunt_config_name: Callable[[str], bool],
    run_ordered_batch: Callable[..., list[Any]],
) -> str:
    candidate_lines = run_ordered_batch(
        iter_terraform_text_blocks(text),
        terraform_text_block_candidate,
        default_factory=str,
    )
    if looks_like_terraform_backend_config_name(source_hint) or looks_like_terragrunt_config_name(source_hint):
        candidate_lines.extend(terraform_backend_config_candidates(text))
    if looks_like_terragrunt_config_name(source_hint):
        candidate_lines.extend(terragrunt_remote_state_backend_candidates(text))
    prepared_candidate_entries = run_ordered_batch(
        list(enumerate(candidate_lines)),
        terraform_structured_candidate_entry,
        default_factory=lambda: None,
    )
    lines: list[str] = []
    seen: set[str] = set()
    for candidate_entry in prepared_candidate_entries:
        if not isinstance(candidate_entry, tuple) or len(candidate_entry) != 2:
            continue
        candidate, lowered = candidate_entry
        if lowered in seen:
            continue
        seen.add(lowered)
        lines.append(candidate)
    return "\n".join(lines)


def terraform_text_block_candidate_for_processor(
    block_job: tuple[str, str],
    *,
    terraform_block_assignments: Callable[[str], dict[str, str]],
) -> str:
    resource_type, block_text = block_job
    assignments = terraform_block_assignments(block_text)
    if not assignments:
        return ""
    if resource_type.startswith("aws_s3_bucket"):
        bucket = str(assignments.get("bucket") or "").strip().lower()
        if re.fullmatch(r"[a-z0-9.\-]{3,63}", bucket):
            return f"s3://{bucket}"
        return ""
    if resource_type == "digitalocean_spaces_bucket":
        bucket = str(assignments.get("name") or assignments.get("bucket") or "").strip().lower()
        region = str(assignments.get("region") or "").strip().lower()
        if re.fullmatch(r"[a-z0-9.\-]{3,63}", bucket) and re.fullmatch(r"[a-z0-9\-]{2,32}", region):
            return f"https://{bucket}.{region}.digitaloceanspaces.com"
        return ""
    if resource_type.startswith("google_storage_bucket"):
        bucket = str(assignments.get("name") or assignments.get("bucket") or "").strip().lower()
        if re.fullmatch(r"[a-z0-9._\-]{3,222}", bucket):
            return f"gs://{bucket}"
        return ""
    if resource_type in {"google_firebase_project", "google_firebase_web_app", "google_firebase_database_instance"}:
        project_ref = str(
            assignments.get("project")
            or assignments.get("project_id")
            or assignments.get("name")
            or ""
        ).strip().lower()
        if re.fullmatch(r"[a-z0-9\-]{4,64}", project_ref):
            return f"https://{project_ref}.firebaseio.com"
        return ""
    if resource_type == "azurerm_storage_container":
        container_name = str(assignments.get("name") or "").strip().lower()
        account_name = str(assignments.get("storage_account_name") or "").strip().lower()
        if re.fullmatch(r"[a-z0-9\-]{3,24}", account_name) and re.fullmatch(r"[^/?#]+", container_name):
            return f"https://{account_name}.blob.core.windows.net/{container_name}"
    return ""


def digitalocean_spaces_url_from_endpoint_for_processor(
    bucket: str,
    endpoint: str,
    *,
    do_spaces_endpoint_host_pattern: Any,
) -> str:
    bucket_name = str(bucket or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9.\-]{3,63}", bucket_name):
        return ""
    raw_endpoint = str(endpoint or "").strip().strip("/")
    if not raw_endpoint:
        return ""
    parsed = urlparse(raw_endpoint if "://" in raw_endpoint else f"https://{raw_endpoint}")
    hostname = str(parsed.hostname or "").strip().lower().strip(".")
    match = do_spaces_endpoint_host_pattern.fullmatch(hostname)
    if not match:
        return ""
    region = str(match.group("region") or "").strip().lower()
    if not region:
        return ""
    return f"https://{bucket_name}.{region}.digitaloceanspaces.com"


def azure_blob_url_from_parts_for_processor(account_name: str, container_name: str) -> str:
    account = str(account_name or "").strip().lower()
    container = str(container_name or "").strip().lower()
    if (
        re.fullmatch(r"[a-z0-9\-]{3,24}", account)
        and re.fullmatch(r"[^/?#]+", container)
    ):
        return f"https://{account}.blob.core.windows.net/{container}"
    return ""


def azure_blob_parts_from_composite_name_for_processor(value: str) -> tuple[str, str]:
    parts = [part.strip().lower() for part in str(value or "").split("/") if part.strip()]
    if len(parts) >= 3:
        return parts[0], parts[-1]
    return "", ""


def iac_resource_azure_blob_candidate_for_processor(
    type_hint: str,
    lookup: dict[str, Any],
    *,
    yaml_ref_value: Callable[..., Any],
    azure_blob_url_from_parts: Callable[[str, str], str],
    azure_blob_parts_from_composite_name: Callable[[Any], tuple[str, str]],
) -> str:
    if not (
        "microsoft.storage/storageaccounts/blobservices/containers" in type_hint
        or "azure-native:storage:blobcontainer" in type_hint
        or "azure:storage" in type_hint
        or "azurerm_storage_container" in type_hint
    ):
        return ""
    account_name = str(
        yaml_ref_value(
            lookup,
            "storageAccountName",
            "storage-account-name",
            "storage_account_name",
            "accountName",
            "account-name",
            "account_name",
            "account",
        )
    ).strip().lower()
    container_name = str(
        yaml_ref_value(
            lookup,
            "containerName",
            "container-name",
            "container_name",
            "container",
            "name",
        )
    ).strip().lower()
    candidate = azure_blob_url_from_parts(account_name, container_name)
    if candidate:
        return candidate
    composite_account, composite_container = azure_blob_parts_from_composite_name(
        yaml_ref_value(lookup, "name")
    )
    return azure_blob_url_from_parts(composite_account, composite_container)


def iac_resource_firebase_candidate_for_processor(
    type_hint: str,
    lookup: dict[str, Any],
    *,
    yaml_ref_value: Callable[..., Any],
    yaml_valid_project_ref: Callable[[Any], str],
) -> str:
    if "firebase" not in type_hint:
        return ""
    project_ref = yaml_valid_project_ref(
        yaml_ref_value(
            lookup,
            "projectId",
            "project-id",
            "project_id",
            "project",
            "name",
        )
    )
    return f"https://{project_ref}.firebaseio.com" if project_ref else ""


def iac_resource_supabase_candidate_for_processor(
    type_hint: str,
    lookup: dict[str, Any],
    *,
    yaml_ref_value: Callable[..., Any],
    yaml_valid_project_ref: Callable[[Any], str],
) -> str:
    if "supabase" not in type_hint:
        return ""
    project_ref = yaml_valid_project_ref(
        yaml_ref_value(
            lookup,
            "projectRef",
            "project-ref",
            "project_ref",
            "ref",
            "name",
        )
    )
    return f"https://{project_ref}.supabase.co" if project_ref else ""


def iac_resource_s3_candidate_for_processor(
    type_hint: str,
    lookup: dict[str, Any],
    *,
    yaml_ref_value: Callable[..., Any],
    yaml_valid_bucket_name: Callable[[Any], str],
) -> str:
    if not ("aws::s3::bucket" in type_hint or "aws:s3" in type_hint or "aws.s3" in type_hint):
        return ""
    bucket = yaml_valid_bucket_name(
        yaml_ref_value(lookup, "bucketName", "bucket-name", "bucket_name", "bucket", "name")
    )
    if bucket and re.fullmatch(r"[a-z0-9.\-]{3,63}", bucket):
        return f"s3://{bucket}"
    return ""


def iac_resource_gcs_candidate_for_processor(
    type_hint: str,
    lookup: dict[str, Any],
    *,
    yaml_ref_value: Callable[..., Any],
    yaml_valid_bucket_name: Callable[[Any], str],
) -> str:
    if not (
        "gcp:storage" in type_hint
        or "google.storage" in type_hint
        or "google::cloud::storage" in type_hint
        or "google_storage_bucket" in type_hint
    ):
        return ""
    bucket = yaml_valid_bucket_name(
        yaml_ref_value(lookup, "bucketName", "bucket-name", "bucket_name", "bucket", "name")
    )
    return f"gs://{bucket}" if bucket else ""


def iac_resource_digitalocean_spaces_candidate_for_processor(
    type_hint: str,
    lookup: dict[str, Any],
    *,
    yaml_ref_value: Callable[..., Any],
    yaml_valid_bucket_name: Callable[[Any], str],
) -> str:
    if not ("digitalocean" in type_hint and "space" in type_hint):
        return ""
    bucket = yaml_valid_bucket_name(
        yaml_ref_value(lookup, "bucketName", "bucket-name", "bucket_name", "bucket", "name")
    )
    region = str(
        yaml_ref_value(lookup, "region", "spaceRegion", "space-region", "space_region")
    ).strip().lower()
    if bucket and re.fullmatch(r"[a-z0-9\-]{2,32}", region):
        return f"https://{bucket}.{region}.digitaloceanspaces.com"
    return ""


def iac_resource_structured_candidates_for_processor(
    mapping: dict[str, Any],
    normalized: dict[str, Any],
    *,
    yaml_ref_value: Callable[..., Any],
    yaml_child_mapping: Callable[..., dict[str, Any]],
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
    yaml_valid_bucket_name: Callable[[Any], str],
    yaml_valid_project_ref: Callable[[Any], str],
    azure_blob_url_from_parts: Callable[[str, str], str],
    azure_blob_parts_from_composite_name: Callable[[Any], tuple[str, str]],
    iac_resource_s3_candidate: Callable[..., str],
    iac_resource_gcs_candidate: Callable[..., str],
    iac_resource_digitalocean_spaces_candidate: Callable[..., str],
    iac_resource_firebase_candidate: Callable[..., str],
    iac_resource_supabase_candidate: Callable[..., str],
    iac_resource_azure_blob_candidate: Callable[..., str],
) -> list[str]:
    type_hint = str(
        yaml_ref_value(
            normalized,
            "type",
            "resource_type",
            "resourceType",
            "kind",
        )
        or ""
    ).strip().lower()
    if not type_hint:
        return []

    properties = yaml_child_mapping(mapping, "properties", "config", "inputs")
    prop_norm = yaml_normalized_mapping(properties)
    lookup = dict(normalized)
    lookup.update(prop_norm)

    candidate_jobs = [
        iac_resource_s3_candidate(
            type_hint,
            lookup,
            yaml_ref_value=yaml_ref_value,
            yaml_valid_bucket_name=yaml_valid_bucket_name,
        ),
        iac_resource_gcs_candidate(
            type_hint,
            lookup,
            yaml_ref_value=yaml_ref_value,
            yaml_valid_bucket_name=yaml_valid_bucket_name,
        ),
        iac_resource_digitalocean_spaces_candidate(
            type_hint,
            lookup,
            yaml_ref_value=yaml_ref_value,
            yaml_valid_bucket_name=yaml_valid_bucket_name,
        ),
        iac_resource_firebase_candidate(
            type_hint,
            lookup,
            yaml_ref_value=yaml_ref_value,
            yaml_valid_project_ref=yaml_valid_project_ref,
        ),
        iac_resource_supabase_candidate(
            type_hint,
            lookup,
            yaml_ref_value=yaml_ref_value,
            yaml_valid_project_ref=yaml_valid_project_ref,
        ),
        iac_resource_azure_blob_candidate(
            type_hint,
            lookup,
            yaml_ref_value=yaml_ref_value,
            azure_blob_url_from_parts=azure_blob_url_from_parts,
            azure_blob_parts_from_composite_name=azure_blob_parts_from_composite_name,
        ),
    ]
    return [candidate for candidate in candidate_jobs if candidate]


def terraform_backend_config_candidates_for_processor(
    text: str,
    *,
    terraform_block_assignments: Callable[[str], dict[str, str]],
    digitalocean_spaces_url_from_endpoint: Callable[[str, str], str],
    azure_blob_url_from_parts: Callable[[str, str], str],
) -> list[str]:
    assignments = terraform_block_assignments(text)
    if not assignments:
        return []

    candidates: list[str] = []
    bucket = str(assignments.get("bucket") or "").strip().lower()
    if bucket and re.fullmatch(r"[a-z0-9._\-]{3,222}", bucket):
        assignment_keys = set(assignments)
        do_spaces_url = digitalocean_spaces_url_from_endpoint(
            bucket,
            str(
                assignments.get("endpoint")
                or assignments.get("endpoint_url")
                or assignments.get("s3_endpoint")
                or ""
            ),
        )
        if do_spaces_url:
            candidates.append(do_spaces_url)
        if assignment_keys & {
            "dynamodb_table",
            "encrypt",
            "endpoint",
            "endpoint_url",
            "key",
            "profile",
            "region",
            "role_arn",
            "s3_endpoint",
            "skip_credentials_validation",
            "workspace_key_prefix",
        } and not do_spaces_url:
            candidates.append(f"s3://{bucket}")
        elif assignment_keys & {
            "access_token",
            "credentials",
            "impersonate_service_account",
            "prefix",
        }:
            candidates.append(f"gs://{bucket}")

    container_name = str(
        assignments.get("container_name")
        or assignments.get("container")
        or ""
    ).strip().lower()
    account_name = str(
        assignments.get("storage_account_name")
        or assignments.get("account_name")
        or ""
    ).strip().lower()
    azure_blob_url = azure_blob_url_from_parts(account_name, container_name)
    if azure_blob_url:
        candidates.append(azure_blob_url)

    return candidates


def iter_terragrunt_remote_state_blocks_for_processor(text: str) -> list[str]:
    lines = str(text or "").splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if not re.match(r"^\s*remote_state\s*\{", line, re.IGNORECASE):
            index += 1
            continue
        brace_depth = line.count("{") - line.count("}")
        block_lines = [line]
        index += 1
        while index < len(lines):
            current = lines[index]
            block_lines.append(current)
            brace_depth += current.count("{") - current.count("}")
            index += 1
            if brace_depth <= 0:
                break
        blocks.append("\n".join(block_lines))
    return blocks


def terragrunt_remote_state_backend_candidates_for_processor(
    text: str,
    *,
    iter_terragrunt_remote_state_blocks: Callable[[str], list[str]],
    terraform_backend_config_candidates: Callable[[str], list[str]],
    run_ordered_batch: Callable[..., list[Any]],
) -> list[str]:
    candidate_batches = run_ordered_batch(
        iter_terragrunt_remote_state_blocks(text),
        terraform_backend_config_candidates,
        default_factory=list,
    )
    candidates: list[str] = []
    seen: set[str] = set()
    for candidate_batch in candidate_batches:
        for raw_candidate in candidate_batch:
            candidate = str(raw_candidate or "").strip()
            lowered = candidate.lower()
            if not candidate or lowered in seen:
                continue
            seen.add(lowered)
            candidates.append(candidate)
    return candidates


def parse_key_value_scalar_for_processor(raw_value: str) -> str:
    value = str(raw_value or "").strip()
    if not value:
        return ""
    if value.startswith(('"""', "'''")) and value.endswith(('"""', "'''")) and len(value) >= 6:
        value = value[3:-3].strip()
    elif (
        len(value) >= 2
        and value[0] == value[-1]
        and value[0] in {"'", '"'}
    ):
        value = value[1:-1].strip()
    else:
        value = re.split(r"\s(?:#|;|//).*$", value, maxsplit=1)[0].strip()
    return value.rstrip(",").strip()


def key_value_section_path_for_processor(section_name: str) -> tuple[str, ...]:
    cleaned = str(section_name or "").strip().strip("[]")
    if not cleaned:
        return ()
    cleaned = cleaned.replace('"', "").replace("'", "")
    parts = [
        re.sub(r"[^a-z0-9_\-]+", "", part.strip().lower())
        for part in re.split(r"[./]+", cleaned)
    ]
    return tuple(part for part in parts if part)


def key_value_line_entry_for_processor(
    line_entry: tuple[int, str],
    *,
    key_value_section_path: Callable[[str], tuple[str, ...]],
    parse_key_value_scalar: Callable[[str], str],
) -> tuple[str, tuple[str, ...]] | tuple[str, str, str] | None:
    _line_index, raw_line = line_entry
    stripped = str(raw_line or "").strip()
    if not stripped or stripped.startswith(("#", ";", "//", "/*", "*")):
        return None
    section_match = re.match(r"^\[\[?([^\[\]]+)\]\]?$", stripped)
    if section_match:
        return "section", key_value_section_path(str(section_match.group(1) or ""))
    if stripped.startswith(("{", "}", "[", "]")):
        return None
    assignment_match = re.match(
        r"^(?:export\s+)?([A-Za-z0-9_.\-]+)\s*(=|:)\s*(.+)$",
        stripped,
    )
    if not assignment_match:
        return None
    raw_key = str(assignment_match.group(1) or "").strip()
    if not raw_key:
        return None
    value = parse_key_value_scalar(str(assignment_match.group(3) or ""))
    if not value:
        return None
    key_path = key_value_section_path(raw_key)
    if not key_path:
        return None
    return "assignment", ".".join(key_path), value


def parse_key_value_entries_for_processor(
    text: str,
    *,
    key_value_line_entry: Callable[
        [tuple[int, str]],
        tuple[str, tuple[str, ...]] | tuple[str, str, str] | None,
    ],
    run_ordered_batch: Callable[..., list[Any]],
) -> list[tuple[tuple[str, ...], str, str]]:
    line_entries = run_ordered_batch(
        list(enumerate(str(text or "").splitlines())),
        key_value_line_entry,
        default_factory=lambda: None,
    )
    entries: list[tuple[tuple[str, ...], str, str]] = []
    section_path: tuple[str, ...] = ()
    for line_entry in line_entries:
        if not isinstance(line_entry, tuple) or not line_entry:
            continue
        entry_type = str(line_entry[0] or "")
        if entry_type == "section" and len(line_entry) == 2 and isinstance(line_entry[1], tuple):
            section_path = line_entry[1]
            continue
        if entry_type != "assignment" or len(line_entry) != 3:
            continue
        _entry_type, key_name, value = line_entry
        entries.append((section_path, str(key_name), str(value)))
    return entries


def key_value_structured_inputs_for_processor(
    entries: list[tuple[tuple[str, ...], str, str]],
    *,
    yaml_key_fingerprint: Callable[[str], str],
) -> tuple[dict[str, str], dict[tuple[str, ...], dict[str, str]], list[str]]:
    env_map: dict[str, str] = {}
    section_maps: dict[tuple[str, ...], dict[str, str]] = {}
    direct_candidates: list[str] = []
    seen_direct: set[str] = set()

    def _set_env(name: str, value: str) -> None:
        candidate_name = str(name or "").strip().upper()
        candidate_value = str(value or "").strip()
        if not candidate_name or not candidate_value:
            return
        env_map[candidate_name] = candidate_value
        env_map.setdefault(candidate_name.replace("-", "_"), candidate_value)

    def _append_direct(candidate: str) -> None:
        value = str(candidate or "").strip()
        lowered = value.lower()
        if not value or lowered in seen_direct:
            return
        seen_direct.add(lowered)
        direct_candidates.append(value)

    for section_path, key_name, value in entries:
        section_mapping = section_maps.setdefault(section_path, {})
        normalized_key = str(key_name or "").strip().lower()
        if normalized_key:
            section_mapping.setdefault(normalized_key, value)
            section_mapping.setdefault(yaml_key_fingerprint(normalized_key), value)
        raw_env_name = re.sub(r"[^A-Za-z0-9]+", "_", normalized_key).strip("_").upper()
        if raw_env_name:
            _set_env(raw_env_name, value)
        if section_path:
            section_prefix = "_".join(part.upper() for part in section_path)
            if section_prefix and raw_env_name:
                _set_env(f"{section_prefix}_{raw_env_name}", value)
        if value.startswith(("http://", "https://", "s3://", "gs://")):
            _append_direct(value)
        elif re.fullmatch(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", value):
            _append_direct(value.lower())

    return env_map, section_maps, direct_candidates


def key_value_structured_payload_lines_for_processor(
    env_map: dict[str, str],
    section_maps: dict[tuple[str, ...], dict[str, str]],
    direct_candidates: list[str],
    *,
    key_value_structured_candidate_jobs: Callable[
        [dict[str, str], dict[tuple[str, ...], dict[str, str]]],
        list[tuple[str, tuple[str, ...], dict[str, str]]],
    ],
    key_value_structured_candidate_job: Callable[
        [tuple[str, tuple[str, ...], dict[str, str]]],
        tuple[str, tuple[str, ...], dict[str, str]] | None,
    ],
    key_value_structured_candidate_batch: Callable[
        [tuple[str, tuple[str, ...], dict[str, str]]],
        list[str],
    ],
    key_value_structured_candidate_family_entries: Callable[[tuple[int, Sequence[str]]], list[str]],
    key_value_structured_direct_candidate_entry: Callable[[tuple[int, str]], str | None],
    key_value_structured_append_entry: Callable[[tuple[int, str | None]], tuple[str, str] | None],
    run_ordered_batch: Callable[..., list[Any]],
) -> str:
    lines: list[str] = []
    seen: set[str] = set()

    structured_candidate_jobs = run_ordered_batch(
        key_value_structured_candidate_jobs(env_map, section_maps),
        key_value_structured_candidate_job,
        default_factory=lambda: None,
    )
    candidate_batches = run_ordered_batch(
        [
            job
            for job in structured_candidate_jobs
            if isinstance(job, tuple)
        ],
        key_value_structured_candidate_batch,
        default_factory=list,
    )
    prepared_candidate_families = run_ordered_batch(
        list(enumerate(candidate_batches)),
        key_value_structured_candidate_family_entries,
        default_factory=list,
    )
    prepared_direct_candidates = run_ordered_batch(
        list(enumerate(direct_candidates)),
        key_value_structured_direct_candidate_entry,
        default_factory=lambda: None,
    )
    append_candidates = [
        candidate
        for candidate_family in prepared_candidate_families
        for candidate in candidate_family
    ]
    append_candidates.extend(prepared_direct_candidates)
    prepared_append_entries = run_ordered_batch(
        list(enumerate(append_candidates)),
        key_value_structured_append_entry,
        default_factory=lambda: None,
    )
    for append_entry in prepared_append_entries:
        if not isinstance(append_entry, tuple) or len(append_entry) != 2:
            continue
        value, lowered = append_entry
        if lowered in seen:
            continue
        seen.add(lowered)
        lines.append(value)
    return "\n".join(lines)


def key_value_structured_payload_text_for_processor(
    text: str,
    *,
    source_hint: str,
    looks_text_config_name: Callable[[str], bool],
    parse_key_value_entries: Callable[[str], list[tuple[tuple[str, ...], str, str]]],
    key_value_structured_inputs: Callable[
        [list[tuple[tuple[str, ...], str, str]]],
        tuple[dict[str, str], dict[tuple[str, ...], dict[str, str]], list[str]],
    ],
    key_value_structured_payload_lines: Callable[
        [dict[str, str], dict[tuple[str, ...], dict[str, str]], list[str]],
        str,
    ],
) -> str:
    if not looks_text_config_name(source_hint):
        return ""
    entries = parse_key_value_entries(text)
    if not entries:
        return ""
    env_map, section_maps, direct_candidates = key_value_structured_inputs(entries)
    return key_value_structured_payload_lines(env_map, section_maps, direct_candidates)


def strip_jsonc_comments_for_processor(text: str) -> str:
    result: list[str] = []
    in_string = False
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if in_string:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            result.append(char)
            index += 1
            continue
        if char == "/" and next_char == "/":
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                index += 1
            continue
        if char == "/" and next_char == "*":
            index += 2
            while index + 1 < len(text) and not (text[index] == "*" and text[index + 1] == "/"):
                if text[index] in "\r\n":
                    result.append(text[index])
                index += 1
            index += 2 if index + 1 < len(text) else 0
            continue
        result.append(char)
        index += 1
    return "".join(result)


def json_document_from_line_for_processor(
    raw_line: str,
    *,
    safe_json_loads: Callable[[str], Any],
) -> Any:
    candidate = str(raw_line or "").strip()
    if not candidate:
        return None
    parsed_line = safe_json_loads(candidate)
    if isinstance(parsed_line, (dict, list)):
        return parsed_line
    return None


def json_documents_from_text_for_processor(
    text: str,
    *,
    source_hint: str,
    looks_text_config_name: Callable[[str], bool],
    looks_like_container_image_blob_path: Callable[[str], bool],
    strip_jsonc_comments: Callable[[str], str],
    safe_json_loads: Callable[[str], Any],
    json_document_from_line: Callable[[str], Any],
    run_ordered_batch: Callable[..., list[Any]],
) -> list[Any]:
    if not (
        looks_text_config_name(source_hint)
        or looks_like_container_image_blob_path(source_hint)
    ):
        return []
    stripped = str(text or "").strip()
    if not stripped:
        return []

    candidate_texts = [stripped]
    if Path(str(source_hint or "").lower()).suffix == ".jsonc":
        jsonc_stripped = strip_jsonc_comments(stripped).strip()
        if jsonc_stripped and jsonc_stripped != stripped:
            candidate_texts.append(jsonc_stripped)
    for candidate_text in candidate_texts:
        parsed = safe_json_loads(candidate_text)
        if isinstance(parsed, (dict, list)):
            return [parsed]

    parsed_lines = run_ordered_batch(
        stripped.splitlines(),
        json_document_from_line,
        default_factory=lambda: None,
    )
    return [
        parsed_line
        for parsed_line in parsed_lines
        if isinstance(parsed_line, (dict, list))
    ]


def json_structured_payload_text_for_processor(
    text: str,
    *,
    source_hint: str,
    json_documents_from_text: Callable[..., list[Any]],
    json_document_looks_like_docker_auth_config: Callable[[Any, str], bool],
    docker_auth_config_candidates: Callable[[Any], list[str]],
    ecs_task_definition_candidates: Callable[[Any], list[str]],
    lambda_config_candidates: Callable[[Any], list[str]],
    amplify_client_config_candidates: Callable[..., list[str]],
    structured_document_lines: Callable[[Any], list[str]],
    ordered_line_batch_entries: Callable[[tuple[int, Sequence[str]]], list[str]],
    run_ordered_batch: Callable[..., list[Any]],
) -> str:
    documents = json_documents_from_text(text, source_hint=source_hint)
    if not documents:
        return ""

    docker_auth_line_batches = run_ordered_batch(
        documents,
        lambda document: (
            docker_auth_config_candidates(document)
            if json_document_looks_like_docker_auth_config(document, source_hint)
            else []
        ),
        default_factory=list,
    )
    ecs_task_line_batches = run_ordered_batch(
        documents,
        ecs_task_definition_candidates,
        default_factory=list,
    )
    lambda_config_line_batches = run_ordered_batch(
        documents,
        lambda_config_candidates,
        default_factory=list,
    )
    amplify_client_line_batches = run_ordered_batch(
        documents,
        lambda document: amplify_client_config_candidates(
            document,
            source_hint=source_hint,
        ),
        default_factory=list,
    )
    line_batches = run_ordered_batch(
        documents,
        structured_document_lines,
        default_factory=list,
    )
    line_batches = [
        *docker_auth_line_batches,
        *ecs_task_line_batches,
        *lambda_config_line_batches,
        *amplify_client_line_batches,
        *line_batches,
    ]
    prepared_line_batches = run_ordered_batch(
        list(enumerate(line_batches)),
        ordered_line_batch_entries,
        default_factory=list,
    )
    lines: list[str] = []
    seen: set[str] = set()
    for line_batch in prepared_line_batches:
        for candidate in line_batch:
            lowered = candidate.lower()
            if not candidate or lowered in seen:
                continue
            seen.add(lowered)
            lines.append(candidate)
    return "\n".join(lines)


def json_document_looks_like_docker_auth_config_for_processor(
    document: Any,
    source_hint: str,
    *,
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
) -> bool:
    if not isinstance(document, dict):
        return False
    source_name = Path(str(source_hint or "").replace("\\", "/")).name.lower()
    if source_name in {".dockercfg", ".dockerconfigjson"}:
        return True
    normalized = yaml_normalized_mapping(document)
    return any(key in normalized for key in ("auths", "credhelpers", "credsstore", "credstore"))


def firebaserc_project_ref_url_for_processor(
    value: Any,
    *,
    yaml_valid_project_ref: Callable[[str], str],
) -> str:
    project_ref = yaml_valid_project_ref(str(value or ""))
    if not project_ref:
        return ""
    return f"https://{project_ref}.firebaseio.com"


def firebaserc_structured_payload_text_for_processor(
    text: str,
    *,
    source_hint: str,
    safe_json_loads: Callable[[str], Any],
    firebaserc_project_ref_url: Callable[[Any], str],
    run_ordered_batch: Callable[..., list[Any]],
) -> str:
    source_name = Path(str(source_hint or "").replace("\\", "/")).name.lower()
    if source_name != ".firebaserc":
        return ""
    payload = safe_json_loads(str(text or ""))
    if not isinstance(payload, dict):
        return ""

    project_ref_values: list[Any] = []
    projects = payload.get("projects")
    if isinstance(projects, dict):
        project_ref_values.extend(projects.values())

    targets = payload.get("targets")
    if isinstance(targets, dict):
        project_ref_values.extend(targets)

    project_url_candidates = run_ordered_batch(
        project_ref_values,
        firebaserc_project_ref_url,
        default_factory=str,
    )

    candidates: list[str] = []
    seen: set[str] = set()
    for project_url in project_url_candidates:
        if not project_url or project_url in seen:
            continue
        seen.add(project_url)
        candidates.append(project_url)

    return "\n".join(candidates)


def observability_structured_document_candidates_for_processor(
    document: Any,
    label: str,
    *,
    observability_structured_node_candidates: Callable[..., list[str]],
) -> list[str]:
    del label
    candidate_values = observability_structured_node_candidates(
        document,
        inherited_scheme="http",
        use_workers=True,
    )
    candidates: list[str] = []
    seen: set[str] = set()
    for value in candidate_values:
        candidate = str(value or "").strip()
        lowered = candidate.lower()
        if not candidate or lowered in seen:
            continue
        seen.add(lowered)
        candidates.append(candidate)
    return candidates


def observability_child_candidate_values_for_processor(
    child_job: tuple[int, Any, str],
    *,
    observability_structured_node_candidates: Callable[..., list[str]],
) -> list[str]:
    _child_index, child, inherited_scheme = child_job
    return observability_structured_node_candidates(
        child,
        inherited_scheme=inherited_scheme,
        use_workers=False,
    )


def observability_endpoint_jobs_for_processor(value: Any, scheme: str) -> list[tuple[Any, str]]:
    jobs: list[tuple[Any, str]] = []

    def _walk_endpoint(raw_value: Any) -> None:
        if len(jobs) >= 4096:
            return
        if isinstance(raw_value, (str, int, float)):
            jobs.append((raw_value, scheme))
            return
        if isinstance(raw_value, list):
            for item in raw_value[:4096]:
                _walk_endpoint(item)

    _walk_endpoint(value)
    return jobs


def observability_scheme_candidate_for_processor(value: Any) -> str:
    scheme = str(value or "").strip().lower()
    return scheme if scheme in {"http", "https"} else ""


def observability_target_url_candidate_for_processor(
    target_scheme: tuple[Any, str],
    *,
    normalize_artifact_text_url: Callable[[str], str],
    classify_seed_value: Callable[[str], str],
    observability_scheme_candidate: Callable[[Any], str],
) -> str:
    raw_target, raw_scheme = target_scheme
    target = str(raw_target or "").strip().strip("\"'")
    if not target or any(marker in target for marker in ("${", "$(", "{{", "}}", "*")):
        return ""
    if "://" in target:
        normalized = normalize_artifact_text_url(target)
        return normalized if classify_seed_value(normalized) in {"url", "apk_url"} else ""

    match = re.fullmatch(
        r"(?P<host>[A-Za-z0-9][A-Za-z0-9.-]{1,253})(?::(?P<port>\d{1,5}))(?P<path>/[^\s?#]*)?",
        target,
    )
    if not match:
        return ""
    host = str(match.group("host") or "").strip().lower().strip(".")
    if not host or "." not in host or host in {"localhost", "example.com"}:
        return ""
    if classify_seed_value(host) not in {"domain", "subdomain"}:
        return ""
    port = int(match.group("port") or 0)
    if port < 1 or port > 65535:
        return ""
    scheme = observability_scheme_candidate(raw_scheme) or "http"
    path = str(match.group("path") or "").strip()
    return f"{scheme}://{host}:{port}{path}"


def observability_structured_payload_text_for_processor(
    text: str,
    *,
    source_hint: str,
    observability_text_config_artifact_label: Callable[[str], str],
    observability_structured_labels: Collection[str],
    yaml_safe_load_all: Callable[[str], Any] | None,
    observability_structured_document_candidates: Callable[[Any, str], list[str]],
    ordered_line_batch_entries: Callable[[tuple[int, Sequence[str]]], list[str]],
    run_ordered_batch: Callable[..., list[Any]],
) -> str:
    label = observability_text_config_artifact_label(source_hint)
    if label not in observability_structured_labels or yaml_safe_load_all is None:
        return ""
    try:
        documents = list(yaml_safe_load_all(text))
    except Exception:  # noqa: BLE001
        return ""

    candidate_batches = run_ordered_batch(
        documents,
        lambda document: observability_structured_document_candidates(document, label),
        default_factory=list,
    )
    prepared_candidate_batches = run_ordered_batch(
        list(enumerate(candidate_batches)),
        ordered_line_batch_entries,
        default_factory=list,
    )

    lines: list[str] = []
    seen: set[str] = set()
    for candidate_batch in prepared_candidate_batches:
        for candidate in candidate_batch:
            lowered = candidate.lower()
            if not candidate or lowered in seen:
                continue
            seen.add(lowered)
            lines.append(candidate)
    return "\n".join(lines)


def edge_proxy_structured_payload_text_for_processor(
    text: str,
    *,
    source_hint: str,
    edge_proxy_config_artifact_label: Callable[[str], str],
    edge_proxy_structured_labels: Collection[str],
    edge_proxy_line_url_candidates: Callable[[str], list[str]],
    ordered_line_batch_entries: Callable[[tuple[int, Sequence[str]]], list[str]],
    run_ordered_batch: Callable[..., list[Any]],
) -> str:
    if edge_proxy_config_artifact_label(source_hint) not in edge_proxy_structured_labels:
        return ""
    line_batches = run_ordered_batch(
        str(text or "").splitlines()[:4096],
        edge_proxy_line_url_candidates,
        default_factory=list,
    )
    prepared_line_batches = run_ordered_batch(
        list(enumerate(line_batches)),
        ordered_line_batch_entries,
        default_factory=list,
    )
    lines: list[str] = []
    seen: set[str] = set()
    for line_batch in prepared_line_batches:
        for candidate in line_batch:
            normalized = str(candidate or "").strip()
            lowered = normalized.lower()
            if not normalized or lowered in seen:
                continue
            seen.add(lowered)
            lines.append(normalized)
    return "\n".join(lines)


def edge_proxy_endpoint_url_candidate_for_processor(
    raw_value: str,
    default_scheme: str = "http",
    *,
    api_spec_url_candidate_entry: Callable[[str], str],
) -> str:
    value = str(raw_value or "").strip().replace("\\/", "/")
    value = value.strip().strip("\"'`[]{}(),;")
    if not value:
        return ""
    lowered = value.lower()
    if any(marker in value for marker in ("${", "$(", "{{", "}}", "<", ">", "*", "$")):
        return ""
    if lowered.startswith(("unix:", "file:", "mailto:", "tel:", "s3://", "gs://")):
        return ""
    if value.startswith(("/", ".", "-")):
        return ""
    if lowered.startswith(("grpc://", "h2c://")):
        value = f"http://{value.split('://', 1)[1]}"
    elif lowered.startswith("grpcs://"):
        value = f"https://{value.split('://', 1)[1]}"
    elif value.startswith("//"):
        scheme = default_scheme if default_scheme in {"http", "https"} else "http"
        value = f"{scheme}:{value}"
    elif "://" not in value:
        scheme = default_scheme if default_scheme in {"http", "https"} else "http"
        value = f"{scheme}://{value}"
    return api_spec_url_candidate_entry(value)


def edge_proxy_line_url_candidates_for_processor(
    raw_line: str,
    *,
    edge_proxy_host_rule_pattern: Any,
    edge_proxy_host_rule_value_pattern: Any,
    edge_proxy_keyed_value_pattern: Any,
    edge_proxy_endpoint_token_pattern: Any,
    edge_proxy_endpoint_url_candidate: Callable[[str], str],
) -> list[str]:
    line = str(raw_line or "").strip()
    if not line or line.startswith(("#", "//", ";")):
        return []

    raw_candidates: list[str] = []
    host_rule_found = False
    for host_rule in edge_proxy_host_rule_pattern.finditer(line):
        host_rule_found = True
        values = str(host_rule.group("values") or "")
        for value_match in edge_proxy_host_rule_value_pattern.finditer(values):
            value = value_match.group("quoted") or value_match.group("bare") or ""
            if value:
                raw_candidates.append(value)

    keyed_match = edge_proxy_keyed_value_pattern.match(line)
    if any(marker in line for marker in ("${", "$(", "{{", "}}", "<", ">")):
        pass
    elif keyed_match:
        raw_candidates.extend(
            match.group(0)
            for match in edge_proxy_endpoint_token_pattern.finditer(
                str(keyed_match.group("value") or "")
            )
        )
    else:
        scan_line = line
        yaml_value_match = re.match(
            r"""^(?:-\s*)?["']?[A-Za-z0-9_.\-/]+["']?\s*:\s*(?P<value>.+?)\s*$""",
            line,
        )
        if yaml_value_match:
            scan_line = str(yaml_value_match.group("value") or "").strip()
        if (
            not host_rule_found
            and (
                "://" in scan_line
                or scan_line.endswith("{")
                or re.search(
                    r"\b(?:hdr\(host\)|host\(|hostsni\(|acl|backend|route|upstream|virtualhost)\b",
                    scan_line,
                    re.IGNORECASE,
                )
            )
        ):
            raw_candidates.extend(
                match.group(0)
                for match in edge_proxy_endpoint_token_pattern.finditer(scan_line)
            )

    normalized_candidates = [
        edge_proxy_endpoint_url_candidate(candidate)
        for candidate in raw_candidates
    ]
    lines: list[str] = []
    seen: set[str] = set()
    for candidate in normalized_candidates:
        lowered = candidate.lower()
        if not candidate or lowered in seen:
            continue
        seen.add(lowered)
        lines.append(candidate)
    return lines


def orchestration_annotation_endpointish_key_for_processor(key_fingerprint: str) -> bool:
    return any(
        marker in key_fingerprint
        for marker in (
            "endpoint",
            "hostname",
            "serveralias",
            "vhost",
            "domain",
            "externaldns",
        )
    ) or key_fingerprint.endswith(("host", "url", "address"))


def orchestration_endpoint_values_for_processor(value: Any) -> list[str]:
    values: list[str] = []

    def _walk(raw_value: Any) -> None:
        if len(values) >= 4096:
            return
        if isinstance(raw_value, (str, int, float)):
            values.append(str(raw_value).strip())
            return
        if isinstance(raw_value, list):
            for item in raw_value[:4096]:
                _walk(item)

    _walk(value)
    return [value for value in values if value]


def orchestration_text_values_for_processor(value: Any) -> list[str]:
    values: list[str] = []

    def _walk(raw_value: Any) -> None:
        if len(values) >= 4096:
            return
        if isinstance(raw_value, str):
            values.append(raw_value)
            return
        if isinstance(raw_value, list):
            for item in raw_value[:4096]:
                _walk(item)
            return
        if isinstance(raw_value, dict):
            for item in list(raw_value.values())[:4096]:
                _walk(item)

    _walk(value)
    return [value for value in values if value]


def kopia_structured_payload_text_for_processor(
    text: str,
    *,
    source_hint: str = "",
    looks_like_kopia_text_config_artifact_name: Callable[[str], bool],
    safe_json_loads: Callable[[str], Any],
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
    yaml_ref_value: Callable[..., Any],
    yaml_valid_bucket_name: Callable[[Any], str],
    artifact_managed_cloud_url_candidate: Callable[[str], str],
) -> str:
    source_name = Path(str(source_hint or "").replace("\\", "/")).name.lower()
    if not (
        looks_like_kopia_text_config_artifact_name(source_hint)
        or source_name == "repository.config"
    ):
        return ""
    document = safe_json_loads(str(text or "").strip())
    if not isinstance(document, dict):
        return ""
    storage = document.get("storage")
    if not isinstance(storage, dict):
        return ""
    config = storage.get("config")
    if not isinstance(config, dict):
        config = {}
    storage_type = str(storage.get("type") or config.get("type") or "").strip().lower()
    merged = dict(storage)
    merged.update(config)
    normalized = yaml_normalized_mapping(merged)
    candidates: list[str] = []

    def _append(value: str) -> None:
        candidate = str(value or "").strip()
        if candidate:
            candidates.append(candidate)

    endpoint = artifact_managed_cloud_url_candidate(
        yaml_ref_value(normalized, "endpoint", "server", "url")
    )
    if endpoint:
        _append(endpoint)
    if "s3" in storage_type:
        bucket = yaml_valid_bucket_name(
            yaml_ref_value(normalized, "bucket", "bucketName", "bucket_name")
        )
        if bucket and re.fullmatch(r"[a-z0-9.\-]{3,63}", bucket):
            _append(f"s3://{bucket}")
    if storage_type in {"gcs", "google", "googlecloudstorage", "google-cloud-storage"}:
        bucket = yaml_valid_bucket_name(
            yaml_ref_value(normalized, "bucket", "bucketName", "bucket_name")
        )
        if bucket:
            _append(f"gs://{bucket}")
    if "azure" in storage_type or "blob" in storage_type:
        account_name = str(
            yaml_ref_value(
                normalized,
                "storage_account_name",
                "storageAccountName",
                "account_name",
                "accountName",
                "account",
            )
        ).strip().lower()
        container_name = str(
            yaml_ref_value(
                normalized,
                "container",
                "container_name",
                "containerName",
                "bucket",
                "bucketName",
            )
        ).strip().lower()
        if (
            re.fullmatch(r"[a-z0-9\-]{3,24}", account_name)
            and re.fullmatch(r"[^/?#]+", container_name)
        ):
            _append(f"https://{account_name}.blob.core.windows.net/{container_name}")

    deduped: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        lowered = candidate.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        deduped.append(candidate)
    return "\n".join(deduped)


def duplicacy_preference_entry_has_hint_for_processor(
    entry: dict[str, Any],
    *,
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
) -> bool:
    normalized = yaml_normalized_mapping(entry)
    return any(
        key in normalized
        for key in (
            "storage",
            "storage_url",
            "storageurl",
            "storage_url_string",
            "storageurlstring",
            "url",
        )
    )


def duplicacy_bucket_from_storage_url_for_processor(
    storage_url: str,
    *,
    yaml_valid_bucket_name: Callable[[Any], str],
) -> str:
    parsed = urlparse(str(storage_url or "").strip())
    if parsed.netloc:
        bucket = parsed.netloc
    elif parsed.path.startswith("/"):
        path_segments = [segment for segment in parsed.path.split("/") if segment]
        bucket = path_segments[0] if path_segments else ""
    else:
        bucket = parsed.path
    bucket = str(bucket or "").split("/", 1)[0].split(":", 1)[0].strip()
    return yaml_valid_bucket_name(bucket)


def duplicacy_s3_storage_candidates_for_processor(
    storage_url: str,
    *,
    yaml_valid_bucket_name: Callable[[Any], str],
    artifact_managed_cloud_url_candidate: Callable[[str], str],
) -> list[str]:
    parsed = urlparse(str(storage_url or "").strip())
    candidates: list[str] = []
    netloc = parsed.netloc.strip()
    path_segments = [segment for segment in parsed.path.split("/") if segment]
    bucket_candidate = ""
    if "@" in netloc:
        bucket_candidate = netloc.rsplit("@", 1)[1]
    elif netloc and "." in netloc and path_segments:
        bucket_candidate = path_segments[0]
        endpoint_url = artifact_managed_cloud_url_candidate(
            f"https://{netloc}/{bucket_candidate}"
        )
        if endpoint_url:
            candidates.append(endpoint_url)
    elif netloc:
        bucket_candidate = netloc
    elif path_segments:
        bucket_candidate = path_segments[0]
    bucket = yaml_valid_bucket_name(bucket_candidate)
    if bucket and re.fullmatch(r"[a-z0-9.\-]{3,63}", bucket):
        candidates.append(f"s3://{bucket}")
    return candidates


def duplicacy_storage_url_candidates_for_processor(
    storage_url: str,
    context: dict[str, Any],
    *,
    yaml_ref_value: Callable[..., Any],
    yaml_valid_bucket_name: Callable[[Any], str],
    artifact_managed_cloud_url_candidate: Callable[[str], str],
    duplicacy_s3_storage_candidates: Callable[..., list[str]],
    duplicacy_bucket_from_storage_url: Callable[..., str],
) -> list[str]:
    value = str(storage_url or "").strip().strip("\"'")
    if not value:
        return []
    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    if scheme in {"http", "https"}:
        managed_url = artifact_managed_cloud_url_candidate(value)
        return [managed_url] if managed_url else []
    if scheme == "s3":
        return duplicacy_s3_storage_candidates(
            value,
            yaml_valid_bucket_name=yaml_valid_bucket_name,
            artifact_managed_cloud_url_candidate=artifact_managed_cloud_url_candidate,
        )
    if scheme in {"gcd", "gcs", "gs", "google", "googlecloudstorage"}:
        bucket = duplicacy_bucket_from_storage_url(
            value,
            yaml_valid_bucket_name=yaml_valid_bucket_name,
        )
        return [f"gs://{bucket}"] if bucket else []
    if scheme in {"azure", "az", "azureblob"}:
        account_name = str(
            yaml_ref_value(
                context,
                "storage_account_name",
                "storageAccountName",
                "account_name",
                "accountName",
                "account",
                "azure_storage_account",
                "azureStorageAccount",
            )
        ).strip().lower()
        container_name = duplicacy_bucket_from_storage_url(
            value,
            yaml_valid_bucket_name=yaml_valid_bucket_name,
        )
        if (
            re.fullmatch(r"[a-z0-9\-]{3,24}", account_name)
            and re.fullmatch(r"[^/?#]+", container_name)
        ):
            return [f"https://{account_name}.blob.core.windows.net/{container_name}"]
    return []


def duplicacy_preference_entry_candidates_for_processor(
    entry: dict[str, Any],
    *,
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
    yaml_ref_value: Callable[..., Any],
    run_ordered_local_batch: Callable[..., list[Any]],
    duplicacy_storage_url_candidates: Callable[..., list[str]],
) -> list[str]:
    normalized = yaml_normalized_mapping(entry)
    storage_values: list[str] = []
    for key in (
        "storage",
        "storage_url",
        "storageUrl",
        "storage-url",
        "storage_url_string",
        "url",
    ):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            storage_values.append(value.strip())
    storage = entry.get("storage")
    if isinstance(storage, dict):
        storage_normalized = yaml_normalized_mapping(storage)
        storage_url = yaml_ref_value(
            storage_normalized,
            "url",
            "uri",
            "storage_url",
            "storageUrl",
            "bucket",
            "container",
        )
        if storage_url:
            storage_values.append(storage_url)
        normalized.update(storage_normalized)
    candidate_batches = run_ordered_local_batch(
        storage_values,
        lambda storage_value: duplicacy_storage_url_candidates(storage_value, normalized),
        default_factory=list,
    )
    candidates: list[str] = []
    seen: set[str] = set()
    for candidate_batch in candidate_batches:
        for candidate in candidate_batch:
            lowered = candidate.lower()
            if not candidate or lowered in seen:
                continue
            seen.add(lowered)
            candidates.append(candidate)
    return candidates


def duplicacy_structured_payload_text_for_processor(
    text: str,
    *,
    source_hint: str = "",
    looks_like_duplicacy_preferences_text_config_artifact_name: Callable[[str], bool],
    safe_json_loads: Callable[[str], Any],
    duplicacy_preference_entry_has_hint: Callable[[dict[str, Any]], bool],
    run_ordered_local_batch: Callable[..., list[Any]],
    duplicacy_preference_entry_candidates: Callable[[dict[str, Any]], list[str]],
) -> str:
    source_name = Path(str(source_hint or "").replace("\\", "/")).name.lower()
    if not (
        looks_like_duplicacy_preferences_text_config_artifact_name(source_hint)
        or source_name == "preferences"
    ):
        return ""
    document = safe_json_loads(str(text or "").strip())
    if isinstance(document, list):
        entries = [entry for entry in document if isinstance(entry, dict)]
    elif isinstance(document, dict):
        entries = [document] if duplicacy_preference_entry_has_hint(document) else []
    else:
        entries = []
    if not entries:
        return ""
    candidate_batches = run_ordered_local_batch(
        entries,
        duplicacy_preference_entry_candidates,
        default_factory=list,
    )
    candidates: list[str] = []
    seen: set[str] = set()
    for candidate_batch in candidate_batches:
        for candidate in candidate_batch:
            lowered = candidate.lower()
            if not candidate or lowered in seen:
                continue
            seen.add(lowered)
            candidates.append(candidate)
    return "\n".join(candidates)


def borg_bucket_from_repository_url_for_processor(
    repository_url: str,
    *,
    yaml_valid_bucket_name: Callable[[Any], str],
) -> str:
    parsed = urlparse(str(repository_url or "").strip())
    if parsed.netloc:
        bucket = parsed.netloc
    elif parsed.path.startswith("/"):
        path_segments = [segment for segment in parsed.path.split("/") if segment]
        bucket = path_segments[0] if path_segments else ""
    else:
        bucket = parsed.path
    bucket = str(bucket or "").split("/", 1)[0].split(":", 1)[0].strip()
    return yaml_valid_bucket_name(bucket)


def borg_s3_repository_candidates_for_processor(
    repository_url: str,
    *,
    yaml_valid_bucket_name: Callable[[Any], str],
    artifact_managed_cloud_url_candidate: Callable[[str], str],
) -> list[str]:
    parsed = urlparse(str(repository_url or "").strip())
    candidates: list[str] = []
    netloc = parsed.netloc.strip()
    path_segments = [segment for segment in parsed.path.split("/") if segment]
    bucket_candidate = ""
    if "@" in netloc:
        bucket_candidate = netloc.rsplit("@", 1)[1]
    elif netloc and "." in netloc and path_segments:
        bucket_candidate = path_segments[0]
        endpoint_url = artifact_managed_cloud_url_candidate(
            f"https://{netloc}/{bucket_candidate}"
        )
        if endpoint_url:
            candidates.append(endpoint_url)
    elif netloc:
        bucket_candidate = netloc
    elif path_segments:
        bucket_candidate = path_segments[0]
    bucket = yaml_valid_bucket_name(bucket_candidate)
    if bucket and re.fullmatch(r"[a-z0-9.\-]{3,63}", bucket):
        candidates.append(f"s3://{bucket}")
    return candidates


def borg_network_repository_candidate_for_processor(
    repository: str,
    *,
    strip_artifact_network_dsn_userinfo: Callable[[str], str],
) -> str:
    value = str(repository or "").strip().strip("\"'")
    if not value or re.search(r"\s", value):
        return ""
    parsed = urlparse(value)
    if parsed.scheme.lower() in {"ssh", "sftp"} and parsed.hostname:
        return strip_artifact_network_dsn_userinfo(value)
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return ""
    scp_match = re.match(
        r"^(?:(?:[^@\s:/]+)@)?(?P<host>[A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+):(?P<path>[^\"'<>`\s]+)$",
        value,
    )
    if not scp_match:
        return ""
    host = scp_match.group("host").lower().strip(".")
    path = scp_match.group("path").replace("\\", "/").lstrip("/")
    if not host or not path:
        return ""
    return f"ssh://{host}/{path}"


def borg_repository_candidates_for_processor(
    repository: str,
    context: dict[str, Any],
    *,
    yaml_ref_value: Callable[..., Any],
    yaml_valid_bucket_name: Callable[[Any], str],
    artifact_managed_cloud_url_candidate: Callable[[str], str],
    strip_artifact_network_dsn_userinfo: Callable[[str], str],
    borg_s3_repository_candidates: Callable[..., list[str]],
    borg_bucket_from_repository_url: Callable[..., str],
    borg_network_repository_candidate: Callable[..., str],
) -> list[str]:
    value = str(repository or "").strip().strip("\"'")
    if not value or "{{" in value or "}}" in value or re.search(r"\s", value):
        return []
    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    candidates: list[str] = []

    def _append(candidate: str) -> None:
        normalized = str(candidate or "").strip()
        if normalized:
            candidates.append(normalized)

    if scheme in {"http", "https"}:
        managed_url = artifact_managed_cloud_url_candidate(value)
        if managed_url:
            _append(managed_url)
    elif scheme == "s3":
        for candidate in borg_s3_repository_candidates(
            value,
            yaml_valid_bucket_name=yaml_valid_bucket_name,
            artifact_managed_cloud_url_candidate=artifact_managed_cloud_url_candidate,
        ):
            _append(candidate)
    elif scheme in {"gcd", "gcs", "gs", "google", "googlestorage", "googlecloudstorage"}:
        bucket = borg_bucket_from_repository_url(
            value,
            yaml_valid_bucket_name=yaml_valid_bucket_name,
        )
        if bucket:
            _append(f"gs://{bucket}")
    elif scheme in {"azure", "az", "azureblob"}:
        account_name = str(
            yaml_ref_value(
                context,
                "storage_account_name",
                "storageAccountName",
                "account_name",
                "accountName",
                "account",
                "azure_storage_account",
                "azureStorageAccount",
                "AZURE_STORAGE_ACCOUNT",
                "AZURE_BLOB_ACCOUNT",
            )
        ).strip().lower()
        container_name = borg_bucket_from_repository_url(
            value,
            yaml_valid_bucket_name=yaml_valid_bucket_name,
        )
        if (
            re.fullmatch(r"[a-z0-9\-]{3,24}", account_name)
            and re.fullmatch(r"[^/?#]+", container_name)
        ):
            _append(f"https://{account_name}.blob.core.windows.net/{container_name}")
    elif scheme in {"ssh", "sftp"}:
        _append(
            borg_network_repository_candidate(
                value,
                strip_artifact_network_dsn_userinfo=strip_artifact_network_dsn_userinfo,
            )
        )
    elif not scheme:
        _append(
            borg_network_repository_candidate(
                value,
                strip_artifact_network_dsn_userinfo=strip_artifact_network_dsn_userinfo,
            )
        )

    deduped: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        lowered = str(candidate or "").strip().lower()
        if not candidate or lowered in seen:
            continue
        seen.add(lowered)
        deduped.append(candidate)
    return deduped


def borg_repository_candidates_from_env_map_for_processor(
    env_map: dict[str, str],
    *,
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
    yaml_key_fingerprint: Callable[[str], str],
    run_ordered_local_batch: Callable[..., list[Any]],
    borg_repository_candidates: Callable[[str, dict[str, Any]], list[str]],
) -> list[str]:
    if not env_map:
        return []
    normalized = yaml_normalized_mapping(env_map)
    repository_values: list[str] = []
    seen_values: set[str] = set()
    for key in (
        "BORG_REPO",
        "BORG_REPOSITORY",
        "BORG_REPOSITORY_LOCATION",
        "BORG_REMOTE",
        "BORG_REMOTE_URL",
        "BORG_LOCATION",
    ):
        value = str(env_map.get(key) or normalized.get(yaml_key_fingerprint(key)) or "").strip()
        lowered = value.lower()
        if not value or lowered in seen_values:
            continue
        seen_values.add(lowered)
        repository_values.append(value)
    candidate_batches = run_ordered_local_batch(
        repository_values,
        lambda repository: borg_repository_candidates(repository, normalized),
        default_factory=list,
    )
    candidates: list[str] = []
    seen_candidates: set[str] = set()
    for candidate_batch in candidate_batches:
        for candidate in candidate_batch:
            lowered = str(candidate or "").strip().lower()
            if not candidate or lowered in seen_candidates:
                continue
            seen_candidates.add(lowered)
            candidates.append(candidate)
    return candidates


def borg_structured_payload_text_for_processor(
    text: str,
    *,
    source_hint: str = "",
    borg_text_config_artifact_kind: Callable[[str], str],
    parse_key_value_entries: Callable[[str], list[tuple[Any, str, str]]],
    yaml_key_fingerprint: Callable[[str], str],
    run_ordered_local_batch: Callable[..., list[Any]],
    borg_repository_candidates: Callable[[str, dict[str, Any]], list[str]],
    borg_repository_candidates_from_env_map: Callable[[dict[str, str]], list[str]],
) -> str:
    source_kind = borg_text_config_artifact_kind(source_hint)
    source_name = Path(str(source_hint or "").replace("\\", "/")).name.lower()
    if not source_kind and source_name not in {"borg.location", "borg.repository.config"}:
        return ""

    entries = parse_key_value_entries(text)
    env_map: dict[str, str] = {}
    context: dict[str, Any] = {}
    repository_values: list[str] = []

    def _append_repository_value(value: str) -> None:
        candidate = str(value or "").strip().strip("\"'")
        if candidate and not re.search(r"\s", candidate):
            repository_values.append(candidate)

    if source_kind == "location" or source_name == "borg.location":
        for raw_line in str(text or "").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if line and "=" not in line and ":" in line:
                _append_repository_value(line)

    for _section_path, key_name, value in entries:
        normalized_key = yaml_key_fingerprint(key_name)
        if not normalized_key:
            continue
        context[normalized_key] = value
        env_name = re.sub(r"[^A-Za-z0-9]+", "_", normalized_key).strip("_").upper()
        if env_name:
            env_map[env_name] = value
        if normalized_key in {
            "location",
            "repository",
            "repositorylocation",
            "repo",
            "remote",
            "remoteurl",
            "url",
            "borgrepo",
            "borgrepository",
            "borgrepositorylocation",
        } or ("borg" in normalized_key and ("repo" in normalized_key or "repository" in normalized_key)):
            _append_repository_value(value)

    candidate_batches = run_ordered_local_batch(
        repository_values,
        lambda repository: borg_repository_candidates(repository, context),
        default_factory=list,
    )
    candidates: list[str] = []
    for candidate_batch in candidate_batches:
        candidates.extend(candidate_batch)
    candidates.extend(borg_repository_candidates_from_env_map(env_map))

    deduped: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        lowered = str(candidate or "").strip().lower()
        if not candidate or lowered in seen:
            continue
        seen.add(lowered)
        deduped.append(candidate)
    return "\n".join(deduped)


def restic_repository_candidates_from_env_map_for_processor(
    env_map: dict[str, str],
    *,
    restic_repository_candidates: Callable[[str, dict[str, str]], list[str]],
) -> list[str]:
    repository = str(env_map.get("RESTIC_REPOSITORY") or "").strip()
    if not repository:
        return []
    return restic_repository_candidates(repository, env_map)


def restic_repository_candidates_for_processor(
    repository: str,
    env_map: dict[str, str],
    *,
    artifact_managed_cloud_url_candidate: Callable[[str], str],
    restic_s3_repository_candidates: Callable[[str], list[str]],
    restic_bucket_from_pathish: Callable[[str], str],
) -> list[str]:
    value = str(repository or "").strip().strip("\"'")
    if not value:
        return []
    candidates: list[str] = []

    def _append(candidate: str) -> None:
        normalized = str(candidate or "").strip()
        if normalized:
            candidates.append(normalized)

    if value.startswith(("http://", "https://")):
        managed_url = artifact_managed_cloud_url_candidate(value)
        if managed_url:
            _append(managed_url)
    elif value.startswith("rest:"):
        managed_url = artifact_managed_cloud_url_candidate(value[5:])
        if managed_url:
            _append(managed_url)
    elif value.startswith("s3:"):
        for candidate in restic_s3_repository_candidates(value[3:]):
            _append(candidate)
    elif value.startswith("gs:"):
        bucket = restic_bucket_from_pathish(value[3:])
        if bucket:
            _append(f"gs://{bucket}")
    elif value.startswith("azure:"):
        account_name = str(
            env_map.get("AZURE_STORAGE_ACCOUNT")
            or env_map.get("AZURE_ACCOUNT_NAME")
            or env_map.get("AZURE_ACCOUNT")
            or ""
        ).strip().lower()
        container_name = restic_bucket_from_pathish(value[6:])
        if (
            re.fullmatch(r"[a-z0-9\-]{3,24}", account_name)
            and re.fullmatch(r"[^/?#]+", container_name)
        ):
            _append(f"https://{account_name}.blob.core.windows.net/{container_name}")

    deduped: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        lowered = candidate.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        deduped.append(candidate)
    return deduped


def restic_s3_repository_candidates_for_processor(
    repository_suffix: str,
    *,
    yaml_valid_bucket_name: Callable[[Any], str],
    artifact_managed_cloud_url_candidate: Callable[[str], str],
) -> list[str]:
    suffix = str(repository_suffix or "").strip().strip("/")
    if not suffix:
        return []
    candidates: list[str] = []
    if suffix.startswith(("http://", "https://")):
        managed_url = artifact_managed_cloud_url_candidate(suffix)
        if managed_url:
            candidates.append(managed_url)
        parsed = urlparse(suffix)
        path_segments = [segment for segment in parsed.path.split("/") if segment]
        bucket = yaml_valid_bucket_name(path_segments[0] if path_segments else "")
        if bucket and re.fullmatch(r"[a-z0-9.\-]{3,63}", bucket):
            candidates.append(f"s3://{bucket}")
        return candidates
    segments = [segment for segment in suffix.split("/") if segment]
    if not segments:
        return []
    bucket_candidate = segments[1] if "." in segments[0] and len(segments) > 1 else segments[0]
    bucket = yaml_valid_bucket_name(bucket_candidate)
    if bucket and re.fullmatch(r"[a-z0-9.\-]{3,63}", bucket):
        candidates.append(f"s3://{bucket}")
    if "." in segments[0]:
        managed_url = artifact_managed_cloud_url_candidate(f"https://{suffix}")
        if managed_url:
            candidates.append(managed_url)
    return candidates


def restic_bucket_from_pathish_for_processor(
    value: str,
    *,
    yaml_valid_bucket_name: Callable[[Any], str],
) -> str:
    pathish = str(value or "").strip().strip("/")
    if not pathish:
        return ""
    bucket = pathish.split(":", 1)[0].split("/", 1)[0].strip()
    return yaml_valid_bucket_name(bucket)


def yaml_env_candidate_family_for_processor(
    env_map: dict[str, str],
    family: str,
    *,
    source_hint: str = "",
    yaml_valid_project_ref: Callable[[Any], str],
    yaml_valid_bucket_name: Callable[[Any], str],
    run_ordered_local_batch: Callable[..., list[Any]],
    yaml_managed_hosting_env_entry: Callable[[tuple[str, str]], str | None],
    yaml_normalized_mapping: Callable[[dict[str, str]], dict[str, Any]],
    yaml_cloudflare_structured_candidates: Callable[[dict[str, str], dict[str, Any], str], list[str]],
    amplify_client_config_candidates: Callable[..., list[str]],
    sanity_env_urls: Callable[[dict[str, str]], list[str]],
    docker_auth_structured_candidates_from_env_map: Callable[[dict[str, str]], list[str]],
    restic_repository_candidates_from_env_map: Callable[[dict[str, str]], list[str]],
    borg_repository_candidates_from_env_map: Callable[[dict[str, str]], list[str]],
    duplicati_target_url_candidates_from_env_map: Callable[[dict[str, str]], list[str]],
    yaml_env_value_candidate_entry: Callable[[tuple[str, str]], str | None],
) -> list[str]:
    if family == "firebase":
        firebase_ref = yaml_valid_project_ref(
            env_map.get("FIREBASE_PROJECT_ID")
            or env_map.get("FIREBASE_PROJECT")
            or env_map.get("RTDB_PROJECT_ID")
            or env_map.get("FIREBASE_DATABASE_PROJECT")
            or ""
        )
        if firebase_ref:
            return [f"https://{firebase_ref}.firebaseio.com"]
        return []
    if family == "supabase":
        supabase_ref = yaml_valid_project_ref(
            env_map.get("SUPABASE_PROJECT_REF")
            or env_map.get("SUPABASE_REF")
            or env_map.get("NEXT_PUBLIC_SUPABASE_PROJECT_REF")
            or ""
        )
        if supabase_ref:
            return [f"https://{supabase_ref}.supabase.co"]
        return []
    if family == "s3":
        s3_bucket = yaml_valid_bucket_name(
            env_map.get("AWS_S3_BUCKET")
            or env_map.get("S3_BUCKET")
            or env_map.get("S3_BUCKET_NAME")
            or ""
        )
        if s3_bucket and re.fullmatch(r"[a-z0-9.\-]{3,63}", s3_bucket):
            return [f"s3://{s3_bucket}"]
        return []
    if family == "gcs":
        gcs_bucket = yaml_valid_bucket_name(
            env_map.get("GCS_BUCKET")
            or env_map.get("GOOGLE_STORAGE_BUCKET")
            or env_map.get("GCLOUD_STORAGE_BUCKET")
            or ""
        )
        if gcs_bucket:
            return [f"gs://{gcs_bucket}"]
        return []
    if family == "do_spaces":
        do_bucket = yaml_valid_bucket_name(
            env_map.get("DO_SPACES_BUCKET")
            or env_map.get("DIGITALOCEAN_SPACES_BUCKET")
            or ""
        )
        do_region = str(
            env_map.get("DO_SPACES_REGION")
            or env_map.get("DIGITALOCEAN_SPACES_REGION")
            or ""
        ).strip().lower()
        if do_bucket and re.fullmatch(r"[a-z0-9\-]{2,32}", do_region):
            return [f"https://{do_bucket}.{do_region}.digitaloceanspaces.com"]
        return []
    if family == "azure":
        azure_account = str(
            env_map.get("AZURE_STORAGE_ACCOUNT")
            or env_map.get("AZURE_BLOB_ACCOUNT")
            or ""
        ).strip().lower()
        azure_container = str(
            env_map.get("AZURE_STORAGE_CONTAINER")
            or env_map.get("AZURE_BLOB_CONTAINER")
            or ""
        ).strip().lower()
        if (
            re.fullmatch(r"[a-z0-9\-]{3,24}", azure_account)
            and re.fullmatch(r"[^/?#]+", azure_container)
        ):
            return [f"https://{azure_account}.blob.core.windows.net/{azure_container}"]
        return []
    if family == "managed_hosting":
        candidates: list[str] = []
        seen: set[str] = set()
        candidate_entries = run_ordered_local_batch(
            list(env_map.items()),
            yaml_managed_hosting_env_entry,
            default_factory=lambda: None,
        )
        for managed_url in candidate_entries:
            if not managed_url or managed_url in seen:
                continue
            seen.add(managed_url)
            candidates.append(managed_url)
        return candidates
    if family == "cloudflare":
        normalized = yaml_normalized_mapping(env_map)
        return yaml_cloudflare_structured_candidates(env_map, normalized, "env")
    if family == "amplify_client_config":
        return amplify_client_config_candidates(env_map, source_hint=source_hint)
    if family == "sanity":
        return sanity_env_urls(env_map)
    if family == "docker_auth":
        return docker_auth_structured_candidates_from_env_map(env_map)
    if family == "restic":
        return restic_repository_candidates_from_env_map(env_map)
    if family == "borg":
        return borg_repository_candidates_from_env_map(env_map)
    if family == "duplicati":
        return duplicati_target_url_candidates_from_env_map(env_map)
    if family == "env_values":
        candidate_entries = run_ordered_local_batch(
            list(env_map.items()),
            yaml_env_value_candidate_entry,
            default_factory=lambda: None,
        )
        return [candidate for candidate in candidate_entries if candidate]
    return []


def yaml_managed_hosting_env_entry_for_processor(
    entry: tuple[str, str],
    *,
    artifact_managed_cloud_url_candidate: Callable[[str], str],
) -> str | None:
    env_name, env_value = entry
    upper_name = str(env_name or "").strip().upper()
    if not any(
        marker in upper_name
        for marker in (
            "URL",
            "URI",
            "HOST",
            "HOSTNAME",
            "DOMAIN",
            "ENDPOINT",
            "VERCEL",
            "NETLIFY",
            "AMPLIFY",
            "HEROKU",
        )
    ):
        return None
    managed_url = artifact_managed_cloud_url_candidate(env_value)
    return managed_url or None


def yaml_env_value_candidate_entry_for_processor(
    entry: tuple[str, str],
    *,
    artifact_managed_cloud_url_candidate: Callable[[str], str],
) -> str | None:
    env_name, env_value = entry
    upper_name = str(env_name or "").strip().upper()
    value = str(env_value or "").strip()
    if not upper_name or not value:
        return None
    if "EMAIL" in upper_name and re.fullmatch(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", value):
        return value.lower()
    if any(
        marker in upper_name
        for marker in ("URL", "URI", "ENDPOINT", "PORTAL", "BASE_URL", "BASEURI")
    ):
        if value.startswith(("http://", "https://", "s3://", "gs://")):
            return value
        managed_url = artifact_managed_cloud_url_candidate(value)
        if managed_url:
            return managed_url
    return None


def docker_registry_url_candidate_for_processor(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw or raw == "*":
        return ""
    if raw.startswith("//"):
        raw = f"https:{raw}"
    elif "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    host = parsed.hostname.lower()
    try:
        netloc = f"{host}:{parsed.port}" if parsed.port else host
    except ValueError:
        netloc = host
    path = parsed.path.rstrip("/")
    return f"{parsed.scheme.lower()}://{netloc}{path}"


def docker_auth_principal_candidate_for_processor(
    value: Any,
    *,
    classify_seed_value: Callable[[str], str],
) -> str:
    principal = str(value or "").strip()
    if classify_seed_value(principal) == "email":
        return principal.lower()
    return ""


def docker_auth_principal_from_auth_field_for_processor(
    value: Any,
    *,
    docker_auth_principal_candidate: Callable[[Any], str],
) -> str:
    auth = str(value or "").strip()
    if not auth:
        return ""
    compact = re.sub(r"\s+", "", auth)
    if not compact:
        return ""
    padding = "=" * (-len(compact) % 4)
    try:
        decoded = base64.b64decode(compact + padding, validate=True).decode("utf-8", "ignore")
    except Exception:  # noqa: BLE001
        return ""
    principal, separator, _secret = decoded.partition(":")
    if not separator:
        return ""
    return docker_auth_principal_candidate(principal)


def docker_auth_entry_principals_for_processor(
    entry: dict[str, Any],
    *,
    docker_auth_principal_candidate: Callable[[Any], str],
    docker_auth_principal_from_auth_field: Callable[[Any], str],
) -> list[str]:
    candidates: list[str] = []
    for key in ("email", "username", "user"):
        principal = docker_auth_principal_candidate(entry.get(key))
        if principal:
            candidates.append(principal)
    auth_principal = docker_auth_principal_from_auth_field(entry.get("auth"))
    if auth_principal:
        candidates.append(auth_principal)
    return candidates


def docker_auth_config_auth_entry_candidates_for_processor(
    item: tuple[Any, Any],
    *,
    docker_registry_url_candidate: Callable[[Any], str],
    docker_auth_entry_principals: Callable[[dict[str, Any]], list[str]],
) -> list[str]:
    raw_registry, raw_entry = item
    candidates: list[str] = []
    registry_url = docker_registry_url_candidate(raw_registry)
    if registry_url:
        candidates.append(registry_url)
    if isinstance(raw_entry, dict):
        candidates.extend(docker_auth_entry_principals(raw_entry))
    return candidates


def docker_auth_config_cred_helper_candidates_for_processor(
    raw_registry: Any,
    *,
    docker_registry_url_candidate: Callable[[Any], str],
) -> list[str]:
    registry_url = docker_registry_url_candidate(raw_registry)
    return [registry_url] if registry_url else []


def docker_auth_config_legacy_entry_candidates_for_processor(
    item: tuple[Any, Any],
    *,
    docker_auth_config_auth_entry_candidates: Callable[[tuple[Any, Any]], list[str]],
) -> list[str]:
    raw_registry, raw_entry = item
    if str(raw_registry or "").strip() in {"credsStore", "credStore", "credHelpers", "credhelpers"}:
        return []
    if not isinstance(raw_entry, dict):
        return []
    return docker_auth_config_auth_entry_candidates((raw_registry, raw_entry))


def docker_auth_structured_candidates_from_env_map_for_processor(
    env_map: dict[str, str],
    *,
    run_ordered_static_batch: Callable[..., list[Any]],
    docker_auth_structured_env_entry_candidates: Callable[[tuple[str, str]], list[str]],
) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()
    candidate_batches = run_ordered_static_batch(
        list(env_map.items()),
        docker_auth_structured_env_entry_candidates,
        default_factory=list,
    )
    for candidate_batch in candidate_batches:
        for candidate in candidate_batch:
            lowered = candidate.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            candidates.append(candidate)
    return candidates


def docker_auth_structured_env_entry_candidates_for_processor(
    item: tuple[str, str],
    *,
    env_value_may_hold_docker_auth: Callable[[str, str], bool],
    docker_auth_config_candidates: Callable[[Any], list[str]],
) -> list[str]:
    raw_name, raw_value = item
    env_name = str(raw_name or "").strip().upper()
    value = str(raw_value or "").strip()
    if not value:
        return []
    if not env_value_may_hold_docker_auth(env_name, value):
        return []
    return docker_auth_config_candidates(value)


def env_value_may_hold_docker_auth_for_processor(env_name: str, value: str) -> bool:
    if "DOCKER" in env_name or "CONTAINER_REGISTRY" in env_name:
        return True
    text = str(value or "").lstrip()
    return text.startswith("{") and '"auths"' in text[:512]


def docker_auth_config_candidates_for_processor(
    value: Any,
    *,
    safe_json_loads: Callable[[str], Any],
    run_ordered_static_batch: Callable[..., list[Any]],
    docker_auth_config_auth_entry_candidates: Callable[[tuple[Any, Any]], list[str]],
    docker_auth_config_cred_helper_candidates: Callable[[Any], list[str]],
    docker_auth_config_legacy_entry_candidates: Callable[[tuple[Any, Any]], list[str]],
) -> list[str]:
    payload = value if isinstance(value, dict) else safe_json_loads(str(value or ""))
    if not isinstance(payload, dict):
        return []

    candidates: list[str] = []
    seen: set[str] = set()

    def _append_many(candidate_batch: Sequence[str]) -> None:
        for candidate in candidate_batch:
            normalized = str(candidate or "").strip()
            lowered = normalized.lower()
            if not normalized or lowered in seen:
                continue
            seen.add(lowered)
            candidates.append(normalized)

    auths = payload.get("auths")
    if isinstance(auths, dict):
        auth_entry_batches = run_ordered_static_batch(
            list(auths.items()),
            docker_auth_config_auth_entry_candidates,
            default_factory=list,
        )
        for candidate_batch in auth_entry_batches:
            _append_many(candidate_batch)

    cred_helpers = payload.get("credHelpers") or payload.get("credhelpers")
    if isinstance(cred_helpers, dict):
        helper_batches = run_ordered_static_batch(
            list(cred_helpers),
            docker_auth_config_cred_helper_candidates,
            default_factory=list,
        )
        for candidate_batch in helper_batches:
            _append_many(candidate_batch)

    if not isinstance(auths, dict):
        legacy_batches = run_ordered_static_batch(
            list(payload.items()),
            docker_auth_config_legacy_entry_candidates,
            default_factory=list,
        )
        for candidate_batch in legacy_batches:
            _append_many(candidate_batch)
    return candidates


def duplicati_bucket_from_target_url_for_processor(
    target_url: str,
    *,
    yaml_valid_bucket_name: Callable[[Any], str],
) -> str:
    parsed = urlparse(str(target_url or "").strip())
    if parsed.netloc:
        bucket = parsed.netloc
    elif parsed.path.startswith("/"):
        path_segments = [segment for segment in parsed.path.split("/") if segment]
        bucket = path_segments[0] if path_segments else ""
    else:
        bucket = parsed.path
    bucket = str(bucket or "").split("/", 1)[0].split(":", 1)[0].strip()
    return yaml_valid_bucket_name(bucket)


def duplicati_s3_target_candidates_for_processor(
    target_url: str,
    *,
    yaml_valid_bucket_name: Callable[[Any], str],
    artifact_managed_cloud_url_candidate: Callable[[str], str],
) -> list[str]:
    parsed = urlparse(str(target_url or "").strip())
    candidates: list[str] = []
    netloc = parsed.netloc.strip()
    path_segments = [segment for segment in parsed.path.split("/") if segment]
    bucket_candidate = ""
    if "@" in netloc:
        bucket_candidate = netloc.rsplit("@", 1)[1]
    elif netloc and "." in netloc and path_segments:
        bucket_candidate = path_segments[0]
        endpoint_url = artifact_managed_cloud_url_candidate(
            f"https://{netloc}/{bucket_candidate}"
        )
        if endpoint_url:
            candidates.append(endpoint_url)
    elif netloc:
        bucket_candidate = netloc
    elif path_segments:
        bucket_candidate = path_segments[0]
    bucket = yaml_valid_bucket_name(bucket_candidate)
    if bucket and re.fullmatch(r"[a-z0-9.\-]{3,63}", bucket):
        candidates.append(f"s3://{bucket}")
    return candidates


def duplicati_target_url_candidates_for_processor(
    target_url: str,
    context: dict[str, Any],
    *,
    yaml_ref_value: Callable[..., Any],
    yaml_valid_bucket_name: Callable[[Any], str],
    artifact_managed_cloud_url_candidate: Callable[[str], str],
    duplicati_s3_target_candidates: Callable[..., list[str]],
    duplicati_bucket_from_target_url: Callable[..., str],
) -> list[str]:
    value = str(target_url or "").strip().strip("\"'")
    if not value:
        return []
    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    if scheme in {"http", "https"}:
        managed_url = artifact_managed_cloud_url_candidate(value)
        return [managed_url] if managed_url else []
    if scheme == "s3":
        return duplicati_s3_target_candidates(
            value,
            yaml_valid_bucket_name=yaml_valid_bucket_name,
            artifact_managed_cloud_url_candidate=artifact_managed_cloud_url_candidate,
        )
    if scheme in {"gcd", "gcs", "gs", "google", "googlestorage", "googlecloudstorage"}:
        bucket = duplicati_bucket_from_target_url(
            value,
            yaml_valid_bucket_name=yaml_valid_bucket_name,
        )
        return [f"gs://{bucket}"] if bucket else []
    if scheme in {"azure", "az", "azureblob"}:
        account_name = str(
            yaml_ref_value(
                context,
                "storage_account_name",
                "storageAccountName",
                "account_name",
                "accountName",
                "account",
                "azure_storage_account",
                "azureStorageAccount",
                "auth_username",
                "authUsername",
                "username",
            )
        ).strip().lower()
        container_name = duplicati_bucket_from_target_url(
            value,
            yaml_valid_bucket_name=yaml_valid_bucket_name,
        )
        if (
            re.fullmatch(r"[a-z0-9\-]{3,24}", account_name)
            and re.fullmatch(r"[^/?#]+", container_name)
        ):
            return [f"https://{account_name}.blob.core.windows.net/{container_name}"]
    return []


def duplicati_target_url_candidates_from_env_map_for_processor(
    env_map: dict[str, str],
    *,
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
    duplicati_target_url_candidates: Callable[[str, dict[str, Any]], list[str]],
) -> list[str]:
    target_url = str(
        env_map.get("TARGETURL")
        or env_map.get("TARGET_URL")
        or env_map.get("TARGETURI")
        or env_map.get("TARGET_URI")
        or env_map.get("REMOTEURL")
        or env_map.get("REMOTE_URL")
        or ""
    ).strip()
    if not target_url:
        return []
    return duplicati_target_url_candidates(
        target_url,
        yaml_normalized_mapping(env_map),
    )


def duplicati_nested_option_entries_for_processor(
    value: str,
    *,
    parse_key_value_entries: Callable[[str], list[tuple[Any, str, str]]],
) -> list[tuple[str, str]]:
    option_lines: list[str] = []
    for raw_line in str(value or "").splitlines():
        line = str(raw_line or "").strip()
        if not line:
            continue
        line = re.sub(r"^-{1,2}", "", line)
        if "=" in line:
            option_lines.append(line)
    if not option_lines:
        return []
    parsed_entries = parse_key_value_entries("\n".join(option_lines))
    return [(key_name, parsed_value) for _section, key_name, parsed_value in parsed_entries]


def duplicati_env_map_from_entries_for_processor(
    entries: Sequence[tuple[tuple[str, ...], str, str]],
    *,
    yaml_key_fingerprint: Callable[[str], str],
    duplicati_nested_option_entries: Callable[[str], list[tuple[str, str]]],
) -> dict[str, str]:
    env_map: dict[str, str] = {}

    def _set_env(name: str, value: str) -> None:
        candidate_name = re.sub(r"[^A-Za-z0-9]+", "_", str(name or "")).strip("_").upper()
        candidate_value = str(value or "").strip()
        if not candidate_name or not candidate_value:
            return
        env_map[candidate_name] = candidate_value
        env_map.setdefault(candidate_name.replace("-", "_"), candidate_value)

    for _section_path, key_name, value in entries:
        _set_env(key_name, value)
        key_fingerprint = yaml_key_fingerprint(key_name)
        if key_fingerprint in {"settings", "options", "metadata", "parameters"}:
            for nested_key, nested_value in duplicati_nested_option_entries(value):
                _set_env(nested_key, nested_value)
    return env_map


def looks_like_duplicati_payload_hint_for_processor(
    source_hint: str,
    env_map: dict[str, str],
) -> bool:
    if not any(
        key in env_map
        for key in (
            "TARGETURL",
            "TARGET_URL",
            "TARGETURI",
            "TARGET_URI",
            "REMOTEURL",
            "REMOTE_URL",
        )
    ):
        return False
    lowered = str(source_hint or "").replace("\\", "/").lower()
    return "duplicati" in lowered or "#sqlite-row-backup-" in lowered or "#sqlite-row-backups-" in lowered


def duplicati_structured_payload_text_for_processor(
    text: str,
    *,
    source_hint: str = "",
    parse_key_value_entries: Callable[[str], list[tuple[tuple[str, ...], str, str]]],
    duplicati_env_map_from_entries: Callable[[Sequence[tuple[tuple[str, ...], str, str]]], dict[str, str]],
    looks_like_duplicati_payload_hint: Callable[[str, dict[str, str]], bool],
    duplicati_target_url_candidates_from_env_map: Callable[[dict[str, str]], list[str]],
) -> str:
    entries = parse_key_value_entries(text)
    if not entries:
        return ""
    env_map = duplicati_env_map_from_entries(entries)
    if not looks_like_duplicati_payload_hint(source_hint, env_map):
        return ""
    candidates = duplicati_target_url_candidates_from_env_map(env_map)
    if not candidates:
        return ""
    deduped: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        lowered = candidate.lower()
        if not candidate or lowered in seen:
            continue
        seen.add(lowered)
        deduped.append(candidate)
    return "\n".join(deduped)


def yaml_mapping_looks_like_appveyor_ci_for_processor(normalized: dict[str, Any]) -> bool:
    return any(
        key in normalized
        for key in (
            "appveyorbuildversion",
            "buildscript",
            "testscript",
            "deployscript",
            "beforescript",
            "afterbuild",
            "aftertest",
            "init",
            "install",
            "branches",
            "artifacts",
            "environment",
        )
    )


def appveyor_ci_document_candidate_for_processor(
    document: Any,
    *,
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
    yaml_mapping_looks_like_appveyor_ci: Callable[[dict[str, Any]], bool],
    yaml_external_secret_ref_segment: Callable[[Any], str],
    yaml_ref_value: Callable[..., Any],
) -> str:
    if not isinstance(document, dict):
        return ""
    normalized = yaml_normalized_mapping(document)
    if not yaml_mapping_looks_like_appveyor_ci(normalized):
        return ""
    pipeline_name = yaml_external_secret_ref_segment(yaml_ref_value(normalized, "name"))
    return f"appveyor-pipeline://{pipeline_name or 'pipeline'}"


def ci_text_structured_payload_text_for_processor(
    text: str,
    *,
    source_hint: str = "",
    appveyor_ci_config_artifact_label: Callable[[str], str],
    yaml_module: Any,
    run_ordered_local_batch: Callable[..., list[Any]],
    appveyor_ci_document_candidate: Callable[[Any], str],
) -> str:
    source_label = appveyor_ci_config_artifact_label(source_hint)
    if source_label != "appveyor" or yaml_module is None:
        return ""
    try:
        documents = list(yaml_module.safe_load_all(text))
    except Exception:  # noqa: BLE001
        return ""

    lines: list[str] = []
    seen: set[str] = set()

    def _append(value: str) -> None:
        candidate = str(value or "").strip()
        lowered = candidate.lower()
        if not candidate or lowered in seen:
            return
        seen.add(lowered)
        lines.append(candidate)

    candidate_entries = run_ordered_local_batch(
        documents,
        appveyor_ci_document_candidate,
        default_factory=str,
    )
    for candidate in candidate_entries:
        _append(candidate)
    return "\n".join(lines)


def yaml_mapping_looks_like_gitpod_config_for_processor(normalized: dict[str, Any]) -> bool:
    return any(
        key in normalized
        for key in (
            "image",
            "tasks",
            "ports",
            "vscode",
            "github",
            "jetbrains",
            "additionalrepositories",
        )
    )


def gitpod_document_structured_candidates_for_processor(
    document: Any,
    *,
    yaml_gitpod_config_structured_candidates: Callable[[dict[str, Any]], list[str]],
) -> list[str]:
    if not isinstance(document, dict):
        return []
    return yaml_gitpod_config_structured_candidates(document)


def gitpod_repository_url_candidates_for_processor(
    value: Any,
    *,
    yaml_gitops_repository_candidates: Callable[[str], list[str]],
    strip_git_repository_suffix: Callable[[str], str],
) -> list[str]:
    raw_value = str(value or "").strip().strip("\"'")
    if not raw_value:
        return []
    candidates = yaml_gitops_repository_candidates(raw_value)
    if candidates:
        return candidates

    host_match = re.fullmatch(
        r"(?P<host>(?:github\.com|gitlab\.com|bitbucket\.org))/(?P<path>[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)(?:\.git)?/?",
        raw_value,
        re.IGNORECASE,
    )
    if not host_match:
        return []
    return [
        strip_git_repository_suffix(
            f"https://{host_match.group('host').lower()}/{host_match.group('path')}"
        )
    ]


def yaml_gitpod_config_structured_candidates_for_processor(
    mapping: dict[str, Any],
    *,
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
    yaml_mapping_looks_like_gitpod_config: Callable[[dict[str, Any]], bool],
    run_ordered_local_batch: Callable[..., list[Any]],
    artifact_container_image_url_candidate: Callable[..., str],
    yaml_ref_collection: Callable[..., list[Any]],
    yaml_ref_value: Callable[[dict[str, Any], str], Any],
    gitpod_repository_url_candidates: Callable[[Any], list[str]],
) -> list[str]:
    normalized = yaml_normalized_mapping(mapping)
    if not yaml_mapping_looks_like_gitpod_config(normalized):
        return []

    candidates: list[str] = []
    seen: set[str] = set()

    def _append(value: str) -> None:
        candidate = str(value or "").strip().strip("\"'")
        if not candidate:
            return
        lowered = candidate.lower()
        if lowered in seen:
            return
        seen.add(lowered)
        candidates.append(candidate)

    image_values: list[str] = []
    image_value = normalized.get("image")
    if isinstance(image_value, str):
        image_values.append(image_value)
    for image_candidate in run_ordered_local_batch(
        image_values,
        lambda value: artifact_container_image_url_candidate(
            value,
            require_explicit_registry=True,
        ),
        default_factory=str,
    ):
        _append(image_candidate)

    repository_values: list[str] = []
    for repository_entry in yaml_ref_collection(
        mapping,
        "additionalRepositories",
        "additional_repositories",
        "additionalrepositories",
    ):
        if isinstance(repository_entry, str):
            repository_values.append(repository_entry)
            continue
        if not isinstance(repository_entry, dict):
            continue
        repository_normalized = yaml_normalized_mapping(repository_entry)
        for key in (
            "url",
            "uri",
            "repository",
            "repo",
            "repoURL",
            "repoUrl",
            "repo_url",
            "remoteUrl",
            "remote_url",
            "cloneUrl",
            "clone_url",
        ):
            repository_value = yaml_ref_value(repository_normalized, key)
            if repository_value:
                repository_values.append(repository_value)

    repository_batches = run_ordered_local_batch(
        repository_values,
        gitpod_repository_url_candidates,
        default_factory=list,
    )
    for repository_batch in repository_batches:
        for repository_candidate in repository_batch:
            _append(repository_candidate)

    return candidates


def gitpod_structured_payload_text_for_processor(
    text: str,
    *,
    source_hint: str = "",
    gitpod_config_artifact_label: Callable[[str], str],
    yaml_module: Any,
    run_ordered_local_batch: Callable[..., list[Any]],
    gitpod_document_structured_candidates: Callable[[Any], list[str]],
) -> str:
    if gitpod_config_artifact_label(source_hint) != "gitpod" or yaml_module is None:
        return ""
    try:
        documents = list(yaml_module.safe_load_all(text))
    except Exception:  # noqa: BLE001
        return ""

    candidate_batches = run_ordered_local_batch(
        documents,
        gitpod_document_structured_candidates,
        default_factory=list,
    )
    lines: list[str] = []
    seen: set[str] = set()
    for candidate_batch in candidate_batches:
        for candidate in candidate_batch:
            lowered = str(candidate or "").strip().lower()
            if not candidate or lowered in seen:
                continue
            seen.add(lowered)
            lines.append(candidate)
    return "\n".join(lines)


def iter_bicep_text_blocks_for_processor(
    text: str,
    *,
    bicep_resource_start_pattern: Any,
) -> list[tuple[str, str]]:
    lines = str(text or "").splitlines()
    blocks: list[tuple[str, str]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = bicep_resource_start_pattern.match(line)
        if not match:
            index += 1
            continue
        resource_type = str(match.group(1) or "").strip().lower()
        brace_depth = line.count("{") - line.count("}")
        block_lines = [line]
        index += 1
        while index < len(lines):
            current = lines[index]
            block_lines.append(current)
            brace_depth += current.count("{") - current.count("}")
            index += 1
            if brace_depth <= 0:
                break
        blocks.append((resource_type, "\n".join(block_lines)))
    return blocks


def bicep_block_assignments_for_processor(
    block_text: str,
    *,
    bicep_assignment_line_entry: Callable[[tuple[int, str]], tuple[str, str] | None],
    run_ordered_batch: Callable[..., list[Any]],
) -> dict[str, str]:
    assignment_entries = run_ordered_batch(
        list(enumerate(str(block_text or "").splitlines())),
        bicep_assignment_line_entry,
        default_factory=lambda: None,
    )
    assignments: dict[str, str] = {}
    for assignment_entry in assignment_entries:
        if not isinstance(assignment_entry, tuple) or len(assignment_entry) != 2:
            continue
        key, value = assignment_entry
        assignments[key] = value
    return assignments


def bicep_assignment_line_entry_for_processor(
    line_entry: tuple[int, str],
) -> tuple[str, str] | None:
    _line_index, raw_line = line_entry
    stripped = str(raw_line or "").strip()
    if not stripped or stripped.startswith(("//", "/*", "*")):
        return None
    match = re.match(r"([A-Za-z0-9_]+)\s*:\s*['\"]([^'\"\r\n]+)['\"]", stripped)
    if not match:
        return None
    key = str(match.group(1) or "").strip().lower()
    value = str(match.group(2) or "").strip()
    if not key or not value:
        return None
    return key, value


def bicep_text_structured_payload_text_for_processor(
    text: str,
    *,
    iter_bicep_text_blocks: Callable[[str], list[tuple[str, str]]],
    bicep_text_block_candidate: Callable[[tuple[str, str]], str],
    structured_candidate_entry: Callable[[tuple[int, str]], tuple[str, str] | None],
    run_ordered_batch: Callable[..., list[Any]],
) -> str:
    candidate_lines = run_ordered_batch(
        iter_bicep_text_blocks(text),
        bicep_text_block_candidate,
        default_factory=str,
    )
    prepared_candidate_entries = run_ordered_batch(
        list(enumerate(candidate_lines)),
        structured_candidate_entry,
        default_factory=lambda: None,
    )
    lines: list[str] = []
    seen: set[str] = set()
    for candidate_entry in prepared_candidate_entries:
        if not isinstance(candidate_entry, tuple) or len(candidate_entry) != 2:
            continue
        candidate, lowered = candidate_entry
        if lowered in seen:
            continue
        seen.add(lowered)
        lines.append(candidate)
    return "\n".join(lines)


def bicep_text_block_candidate_for_processor(
    block_job: tuple[str, str],
    *,
    bicep_block_assignments: Callable[[str], dict[str, str]],
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
    iac_resource_structured_candidates: Callable[[dict[str, Any], dict[str, Any]], list[str]],
) -> str:
    resource_type, block_text = block_job
    assignments = bicep_block_assignments(block_text)
    if not assignments:
        return ""
    mapping: dict[str, Any] = {
        "type": resource_type,
        "properties": dict(assignments),
    }
    mapping.update(assignments)
    candidates = iac_resource_structured_candidates(
        mapping,
        yaml_normalized_mapping(mapping),
    )
    return candidates[0] if candidates else ""


def goreleaser_scalar_values_for_processor(value: Any) -> list[str]:
    if isinstance(value, (str, int, float)):
        return [str(value)]
    if isinstance(value, list):
        values: list[str] = []
        for item in value[:64]:
            values.extend(goreleaser_scalar_values_for_processor(item))
        return values
    if isinstance(value, dict):
        values = []
        for item in list(value.values())[:64]:
            values.extend(goreleaser_scalar_values_for_processor(item))
        return values
    return []


def goreleaser_image_template_values_for_processor(
    value: Any,
    *,
    templated_container_image_url_candidate: Callable[..., str],
) -> list[str]:
    candidates: list[str] = []
    for raw_value in goreleaser_scalar_values_for_processor(value):
        image_candidate = templated_container_image_url_candidate(
            raw_value,
            require_explicit_registry=True,
        )
        if image_candidate:
            candidates.append(image_candidate)
    return candidates


def goreleaser_blob_bucket_value_for_processor(
    blob_mapping: dict[str, Any],
    *,
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
    yaml_key_fingerprint: Callable[[str], str],
    yaml_ref_value: Callable[..., str],
    yaml_valid_bucket_name: Callable[[str], str],
) -> str:
    blob_normalized = yaml_normalized_mapping(blob_mapping)
    provider = yaml_key_fingerprint(
        yaml_ref_value(blob_normalized, "provider", "type")
    )
    bucket = yaml_valid_bucket_name(
        yaml_ref_value(
            blob_normalized,
            "bucket",
            "bucketName",
            "bucket_name",
            "name",
        )
    )
    if not bucket:
        return ""
    if provider in {"s3", "aws", "awss3"} and re.fullmatch(r"[a-z0-9.\-]{3,63}", bucket):
        return f"s3://{bucket}"
    if provider in {"gs", "gcs", "googlecloudstorage", "googlestorage"}:
        return f"gs://{bucket}"
    return ""


def yaml_mapping_looks_like_goreleaser_config_for_processor(
    normalized: dict[str, Any],
    path_hint: str,
) -> bool:
    keys = set(normalized)
    root_markers = {
        "projectname",
        "before",
        "builds",
        "archives",
        "checksum",
        "snapshot",
        "changelog",
        "release",
        "brews",
        "nfpms",
    }
    if (keys & {"dockers", "dockermanifests", "blobs"}) and (keys & root_markers):
        return True
    return "goreleaser" in path_hint and bool(keys & (root_markers | {"dockers", "dockermanifests", "blobs"}))


def yaml_goreleaser_config_structured_candidates_for_processor(
    mapping: dict[str, Any],
    normalized: dict[str, Any],
    path_hint: str,
    *,
    yaml_mapping_looks_like_goreleaser_config: Callable[[dict[str, Any], dict[str, Any], str], bool],
    yaml_goreleaser_candidate_values_for_node: Callable[..., list[str]],
) -> list[str]:
    if not yaml_mapping_looks_like_goreleaser_config(mapping, normalized, path_hint):
        return []

    candidates: list[str] = []
    seen: set[str] = set()
    for value in yaml_goreleaser_candidate_values_for_node(
        mapping,
        (),
        use_workers=True,
    ):
        candidate = str(value or "").strip()
        if not candidate or candidate.lower() in seen:
            continue
        seen.add(candidate.lower())
        candidates.append(candidate)
    return candidates


def yaml_goreleaser_child_candidate_values_for_node_for_processor(
    key: Any,
    child: Any,
    path: tuple[str, ...],
    *,
    yaml_key_fingerprint: Callable[[str], str],
    yaml_goreleaser_image_template_values: Callable[[Any], list[str]],
    yaml_goreleaser_candidate_values_for_node: Callable[..., list[str]],
) -> list[str]:
    key_fingerprint = yaml_key_fingerprint(str(key or ""))
    child_path = (*path, key_fingerprint)
    candidates: list[str] = []
    if key_fingerprint in {
        "image",
        "images",
        "imagetemplate",
        "imagetemplates",
        "nametemplate",
        "nametemplates",
    } and any(part in child_path for part in ("docker", "dockers", "dockermanifests")):
        candidates.extend(yaml_goreleaser_image_template_values(child))
    candidates.extend(
        yaml_goreleaser_candidate_values_for_node(
            child,
            child_path,
            use_workers=False,
        )
    )
    return candidates


def yaml_goreleaser_child_candidate_values_for_processor(
    child_job: tuple[int, Any, Any, tuple[str, ...]],
    *,
    yaml_goreleaser_child_candidate_values_for_node: Callable[[Any, Any, tuple[str, ...]], list[str]],
) -> list[str]:
    _child_index, key, child, path = child_job
    return yaml_goreleaser_child_candidate_values_for_node(key, child, path)


def yaml_gitops_repository_child_values_for_processor(
    child_job: tuple[int, Any],
    *,
    yaml_gitops_repository_values_for_node: Callable[..., list[str]],
) -> list[str]:
    _child_index, child = child_job
    return yaml_gitops_repository_values_for_node(child, use_workers=False)


def yaml_gitops_repository_candidates_for_processor(
    value: Any,
    *,
    normalize_artifact_text_url: Callable[[str], str],
    artifact_container_image_url_candidate: Callable[[str], str],
    strip_git_repository_suffix: Callable[[str], str],
) -> list[str]:
    raw_value = str(value or "").strip().strip("\"'")
    if not raw_value:
        return []
    candidates: list[str] = []

    if raw_value.startswith(("http://", "https://")):
        normalized = normalize_artifact_text_url(raw_value)
        if normalized:
            candidates.append(strip_git_repository_suffix(normalized))
    elif raw_value.startswith(("oci://", "docker://")):
        candidate = artifact_container_image_url_candidate(raw_value)
        if candidate:
            candidates.append(candidate)
    elif raw_value.startswith("git@"):
        match = re.fullmatch(r"git@([^:]+):(.+)", raw_value)
        if match:
            candidates.append(
                strip_git_repository_suffix(
                    f"https://{match.group(1).lower()}/{match.group(2).strip('/')}"
                )
            )
    elif raw_value.startswith(("ssh://", "git://")):
        parsed = urlparse(raw_value)
        host = str(parsed.hostname or "").lower()
        path = str(parsed.path or "").strip("/")
        if host and path:
            candidates.append(strip_git_repository_suffix(f"https://{host}/{path}"))

    deduped: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate.lower() in seen:
            continue
        seen.add(candidate.lower())
        deduped.append(candidate)
    return deduped


def yaml_gitops_repository_candidates_from_mapping_for_processor(
    mapping: dict[str, Any],
    *,
    yaml_gitops_repository_values_for_node: Callable[..., list[str]],
    yaml_gitops_repository_candidates: Callable[[Any], list[str]],
    run_ordered_local_batch: Callable[..., list[Any]],
) -> list[str]:
    values = yaml_gitops_repository_values_for_node(
        mapping,
        use_workers=True,
    )
    candidates: list[str] = []
    seen: set[str] = set()
    candidate_batches = run_ordered_local_batch(
        values,
        yaml_gitops_repository_candidates,
        default_factory=list,
    )
    for candidate_batch in candidate_batches:
        for candidate in candidate_batch:
            lowered = candidate.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            candidates.append(candidate)
    return candidates


def yaml_gitops_repository_values_for_node_for_processor(
    value: Any,
    *,
    use_workers: bool,
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
    yaml_ref_value: Callable[[dict[str, Any], str], str],
    yaml_key_fingerprint: Callable[[str], str],
    yaml_gitops_repository_child_values: Callable[[tuple[int, Any]], list[str]],
    run_ordered_local_batch: Callable[..., list[Any]],
) -> list[str]:
    values: list[str] = []
    if isinstance(value, dict):
        normalized = yaml_normalized_mapping(value)
        for key in ("repoURL", "repoUrl", "repo_url", "url"):
            ref_value = yaml_ref_value(normalized, key)
            if ref_value:
                values.append(ref_value)
        name_hint = yaml_key_fingerprint(yaml_ref_value(normalized, "name"))
        value_ref = yaml_ref_value(normalized, "value")
        if value_ref and any(marker in name_hint for marker in ("repo", "repository", "sourceurl")):
            values.append(value_ref)
        child_jobs = list(enumerate(value.values()))
        child_batches = (
            run_ordered_local_batch(
                child_jobs,
                yaml_gitops_repository_child_values,
                default_factory=list,
            )
            if use_workers
            else [
                yaml_gitops_repository_values_for_node_for_processor(
                    child,
                    use_workers=False,
                    yaml_normalized_mapping=yaml_normalized_mapping,
                    yaml_ref_value=yaml_ref_value,
                    yaml_key_fingerprint=yaml_key_fingerprint,
                    yaml_gitops_repository_child_values=yaml_gitops_repository_child_values,
                    run_ordered_local_batch=run_ordered_local_batch,
                )
                for _child_index, child in child_jobs
            ]
        )
        for child_values in child_batches:
            values.extend(child_values)
        return values
    if isinstance(value, list):
        item_jobs = list(enumerate(value))
        item_batches = (
            run_ordered_local_batch(
                item_jobs,
                yaml_gitops_repository_child_values,
                default_factory=list,
            )
            if use_workers
            else [
                yaml_gitops_repository_values_for_node_for_processor(
                    item,
                    use_workers=False,
                    yaml_normalized_mapping=yaml_normalized_mapping,
                    yaml_ref_value=yaml_ref_value,
                    yaml_key_fingerprint=yaml_key_fingerprint,
                    yaml_gitops_repository_child_values=yaml_gitops_repository_child_values,
                    run_ordered_local_batch=run_ordered_local_batch,
                )
                for _item_index, item in item_jobs
            ]
        )
        for item_values in item_batches:
            values.extend(item_values)
    return values


def yaml_flux_source_ref_candidates_for_processor(
    source_ref: dict[str, Any],
    *,
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
    yaml_ref_value: Callable[..., str],
    yaml_key_fingerprint: Callable[[str], str],
    yaml_external_secret_ref_segment: Callable[[Any], str],
) -> list[str]:
    normalized = yaml_normalized_mapping(source_ref)
    kind = yaml_key_fingerprint(yaml_ref_value(normalized, "kind"))
    name = yaml_external_secret_ref_segment(yaml_ref_value(normalized, "name"))
    namespace = yaml_external_secret_ref_segment(yaml_ref_value(normalized, "namespace"))
    if not kind or not name:
        return []
    identifier = f"{namespace}/{name}" if namespace else name
    family_map = {
        "gitrepository": "flux-gitrepository",
        "helmrepository": "flux-helmrepository",
        "ocirepository": "flux-ocirepository",
        "bucket": "flux-bucket",
    }
    family = family_map.get(kind)
    return [f"{family}://{identifier}"] if family else []


def yaml_flux_bucket_structured_candidates_for_processor(
    spec: dict[str, Any],
    *,
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
    yaml_ref_value: Callable[..., str],
    yaml_valid_bucket_name: Callable[[Any], str],
    yaml_external_secret_ref_segment: Callable[[Any], str],
    do_spaces_endpoint_host_re: Any,
) -> list[str]:
    if not spec:
        return []
    normalized = yaml_normalized_mapping(spec)
    bucket = yaml_valid_bucket_name(
        yaml_ref_value(normalized, "bucketName", "bucket_name", "bucket", "name")
    )
    provider = yaml_ref_value(normalized, "provider").lower()
    endpoint = yaml_ref_value(normalized, "endpoint").lower()
    region = yaml_external_secret_ref_segment(yaml_ref_value(normalized, "region"))
    if not bucket:
        return []
    if "gcp" in provider or "google" in provider:
        return [f"gs://{bucket}"]
    if "azure" in provider:
        account_name = yaml_ref_value(normalized, "accountName", "account_name", "account")
        if re.fullmatch(r"[a-z0-9\-]{3,24}", account_name):
            return [f"https://{account_name.lower()}.blob.core.windows.net/{bucket}"]
    do_match = do_spaces_endpoint_host_re.fullmatch(endpoint)
    if do_match:
        do_region = (do_match.group("region") or region or "").lower()
        if do_region:
            return [f"https://{bucket}.{do_region}.digitaloceanspaces.com"]
    return [f"s3://{bucket}"]


def yaml_manifest_looks_like_crossplane_for_processor(api_version: str) -> bool:
    group = str(api_version or "").split("/", 1)[0].lower()
    return "crossplane.io" in group or group.endswith(".upbound.io")


def crossplane_provider_family_for_processor(api_version: str) -> str:
    group = str(api_version or "").split("/", 1)[0].lower()
    for provider in ("aws", "gcp", "azure", "kubernetes", "digitalocean", "cloudflare"):
        if provider in group:
            return provider
    return group.replace(".", "-") or "crossplane"


def yaml_crossplane_external_name_for_processor(
    mapping: dict[str, Any],
    *,
    yaml_child_mapping: Callable[..., dict[str, Any]],
    yaml_external_secret_ref_segment: Callable[[Any], str],
) -> str:
    metadata = yaml_child_mapping(mapping, "metadata")
    annotations = yaml_child_mapping(metadata, "annotations")
    if not annotations:
        return ""
    for key, value in annotations.items():
        if str(key or "").strip().lower() == "crossplane.io/external-name":
            return yaml_external_secret_ref_segment(value)
    return ""


def yaml_crossplane_cloud_candidates_for_processor(
    *,
    kind: str,
    api_version: str,
    mapping: dict[str, Any],
    spec: dict[str, Any],
    resource_name: str,
    yaml_child_mapping: Callable[..., dict[str, Any]],
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
    yaml_ref_value: Callable[..., str],
    yaml_valid_bucket_name: Callable[[Any], str],
) -> list[str]:
    del mapping
    group = str(api_version or "").split("/", 1)[0].lower()
    for_provider = yaml_child_mapping(spec, "forProvider", "for_provider")
    normalized = yaml_normalized_mapping(for_provider) if for_provider else {}
    candidates: list[str] = []

    if kind == "bucket" and ("s3.aws" in group or "aws" in group):
        bucket = yaml_valid_bucket_name(
            yaml_ref_value(normalized, "bucket", "bucketName", "bucket_name")
            or resource_name
        )
        if bucket:
            candidates.append(f"s3://{bucket}")
    elif kind == "bucket" and ("storage.gcp" in group or "gcp" in group):
        bucket = yaml_valid_bucket_name(
            yaml_ref_value(normalized, "name", "bucket", "bucketName", "bucket_name")
            or resource_name
        )
        if bucket:
            candidates.append(f"gs://{bucket}")
    elif kind in {"storageaccount", "container"} and "azure" in group:
        account_name = yaml_ref_value(
            normalized,
            "storageAccountName",
            "storage_account_name",
            "accountName",
            "account_name",
        )
        container_name = yaml_ref_value(
            normalized,
            "name",
            "containerName",
            "container_name",
        )
        if re.fullmatch(r"[a-z0-9\-]{3,24}", account_name) and container_name:
            candidates.append(f"https://{account_name.lower()}.blob.core.windows.net/{container_name.lower()}")
    return candidates


def yaml_crossplane_structured_candidates_for_processor(
    mapping: dict[str, Any],
    *,
    kind: str,
    api_version: str,
    object_identifier: str,
    crossplane_provider_family: Callable[[str], str],
    yaml_child_mapping: Callable[..., dict[str, Any]],
    yaml_external_secret_ref_segment: Callable[[Any], str],
    yaml_ref_value: Callable[..., str],
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
    yaml_crossplane_external_name: Callable[[dict[str, Any]], str],
    yaml_crossplane_cloud_candidates: Callable[..., list[str]],
) -> list[str]:
    candidates: list[str] = []
    family = crossplane_provider_family(api_version)
    spec = yaml_child_mapping(mapping, "spec")

    if kind == "providerconfig":
        if object_identifier:
            candidates.append(f"crossplane-providerconfig://{family}/{object_identifier}")
        return candidates

    if kind in {"composition", "compositeresourcedefinition"}:
        if object_identifier:
            uri_family = "crossplane-composition" if kind == "composition" else "crossplane-xrd"
            candidates.append(f"{uri_family}://{object_identifier}")
        return candidates

    provider_ref = yaml_child_mapping(spec, "providerConfigRef", "provider_config_ref")
    if provider_ref:
        ref_name = yaml_external_secret_ref_segment(
            yaml_ref_value(yaml_normalized_mapping(provider_ref), "name")
        )
        if ref_name:
            candidates.append(f"crossplane-providerconfig://{family}/{ref_name}")

    external_name = yaml_crossplane_external_name(mapping)
    resource_name = external_name or object_identifier
    if resource_name:
        candidates.append(f"crossplane-resource://{family}/{kind}/{resource_name}")

    for cloud_candidate in yaml_crossplane_cloud_candidates(
        kind=kind,
        api_version=api_version,
        mapping=mapping,
        spec=spec,
        resource_name=resource_name,
    ):
        candidates.append(cloud_candidate)
    return candidates


def yaml_kubernetes_object_identifier_for_processor(
    mapping: dict[str, Any],
    *,
    yaml_child_mapping: Callable[..., dict[str, Any]],
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
    yaml_ref_value: Callable[..., str],
    yaml_external_secret_ref_segment: Callable[[Any], str],
) -> str:
    metadata = yaml_child_mapping(mapping, "metadata")
    if not metadata:
        return ""
    normalized = yaml_normalized_mapping(metadata)
    name = yaml_external_secret_ref_segment(yaml_ref_value(normalized, "name"))
    if not name:
        return ""
    namespace = yaml_external_secret_ref_segment(yaml_ref_value(normalized, "namespace"))
    return f"{namespace}/{name}" if namespace else name


def yaml_external_secret_store_refs_for_processor(
    spec: dict[str, Any],
    object_identifier: str,
    *,
    yaml_child_mapping: Callable[..., dict[str, Any]],
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
    yaml_ref_value: Callable[..., str],
    yaml_external_secret_ref_segment: Callable[[Any], str],
    yaml_key_fingerprint: Callable[[str], str],
) -> list[str]:
    del object_identifier
    store_ref = yaml_child_mapping(spec, "secretStoreRef", "secret_store_ref")
    if not store_ref:
        return []
    normalized = yaml_normalized_mapping(store_ref)
    store_name = yaml_external_secret_ref_segment(yaml_ref_value(normalized, "name"))
    if not store_name:
        return []
    store_kind = yaml_key_fingerprint(yaml_ref_value(normalized, "kind"))
    if store_kind == "clustersecretstore":
        return [f"cluster-secret-store://{store_name}"]
    return [f"secret-store://{store_name}"]


def yaml_external_secret_remote_ref_entry_keys_for_processor(
    remote_ref_job: tuple[str, dict[str, Any]],
    *,
    yaml_child_mapping: Callable[..., dict[str, Any]],
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
    yaml_ref_value: Callable[..., str],
) -> list[str]:
    family, entry = remote_ref_job
    if family == "data":
        remote_ref = yaml_child_mapping(entry, "remoteRef", "remote_ref")
        if not remote_ref:
            return []
        normalized_remote = yaml_normalized_mapping(remote_ref)
        remote_key = yaml_ref_value(
            normalized_remote,
            "key",
            "remoteKey",
            "remote_key",
        )
        return [remote_key] if remote_key else []
    if family != "data_from":
        return []
    keys: list[str] = []
    for child_name in ("extract", "find"):
        child = yaml_child_mapping(entry, child_name)
        if not child:
            continue
        normalized_child = yaml_normalized_mapping(child)
        remote_key = yaml_ref_value(
            normalized_child,
            "key",
            "path",
            "name",
            "remoteKey",
            "remote_key",
        )
        if remote_key:
            keys.append(remote_key)
    return keys


def yaml_external_secret_remote_ref_keys_for_processor(
    spec: dict[str, Any],
    *,
    run_ordered_local_batch: Callable[..., list[Any]],
    yaml_external_secret_remote_ref_entry_keys: Callable[[tuple[str, dict[str, Any]]], list[str]],
) -> list[str]:
    remote_ref_jobs: list[tuple[str, dict[str, Any]]] = []
    data_entries = spec.get("data")
    if isinstance(data_entries, list):
        remote_ref_jobs.extend(
            ("data", entry)
            for entry in data_entries
            if isinstance(entry, dict)
        )
    data_from_entries = spec.get("dataFrom") or spec.get("datafrom")
    if isinstance(data_from_entries, list):
        remote_ref_jobs.extend(
            ("data_from", entry)
            for entry in data_from_entries
            if isinstance(entry, dict)
        )

    remote_ref_batches = run_ordered_local_batch(
        remote_ref_jobs,
        yaml_external_secret_remote_ref_entry_keys,
        default_factory=list,
    )
    keys: list[str] = []
    seen: set[str] = set()

    def _append(value: Any) -> None:
        key = str(value or "").strip().strip("\"'")
        if not key or key.lower() in seen:
            return
        seen.add(key.lower())
        keys.append(key)

    for remote_ref_batch in remote_ref_batches:
        for remote_key in remote_ref_batch:
            _append(remote_key)
    return keys


def yaml_external_secret_provider_candidates_for_processor(
    provider: dict[str, Any],
    remote_keys: Sequence[str],
    *,
    yaml_child_mapping: Callable[..., dict[str, Any]],
    yaml_normalized_mapping: Callable[[dict[str, Any]], dict[str, Any]],
    yaml_ref_value: Callable[..., str],
    yaml_external_secret_ref_segment: Callable[[Any], str],
    yaml_valid_project_ref: Callable[[Any], str],
    yaml_vault_address_candidate: Callable[[Any], str],
    normalize_artifact_text_url: Callable[[str], str],
) -> list[str]:
    if not provider:
        return []
    candidates: list[str] = []

    def _append(value: str) -> None:
        candidate = str(value or "").strip()
        if candidate:
            candidates.append(candidate)

    aws_provider = yaml_child_mapping(provider, "aws")
    if aws_provider:
        normalized_aws = yaml_normalized_mapping(aws_provider)
        region = yaml_external_secret_ref_segment(
            yaml_ref_value(normalized_aws, "region")
        )
        service = yaml_ref_value(normalized_aws, "service").lower()
        family = "aws-parameterstore" if "parameter" in service else "aws-secretsmanager"
        if region:
            _append(f"{family}://{region}")
            for remote_key in remote_keys:
                encoded_key = yaml_external_secret_ref_segment(remote_key)
                if encoded_key:
                    _append(f"{family}://{region}/{encoded_key}")

    gcp_provider = yaml_child_mapping(provider, "gcpsm", "gcp", "gcpSecretManager")
    if gcp_provider:
        normalized_gcp = yaml_normalized_mapping(gcp_provider)
        project_id = yaml_valid_project_ref(
            yaml_ref_value(
                normalized_gcp,
                "projectID",
                "projectId",
                "project_id",
                "project",
            )
        )
        if project_id:
            _append(f"gcp-secretmanager://{project_id}")
            for remote_key in remote_keys:
                encoded_key = yaml_external_secret_ref_segment(remote_key)
                if encoded_key:
                    _append(f"gcp-secretmanager://{project_id}/{encoded_key}")

    azure_provider = yaml_child_mapping(provider, "azurekv", "azureKv", "azure-kv")
    if azure_provider:
        normalized_azure = yaml_normalized_mapping(azure_provider)
        vault_url = normalize_artifact_text_url(
            yaml_ref_value(
                normalized_azure,
                "vaultUrl",
                "vault_url",
                "vault-url",
            )
        )
        if vault_url:
            _append(vault_url)

    vault_provider = yaml_child_mapping(provider, "vault")
    if vault_provider:
        normalized_vault = yaml_normalized_mapping(vault_provider)
        vault_url = yaml_vault_address_candidate(
            yaml_ref_value(
                normalized_vault,
                "server",
                "url",
                "address",
                "uri",
            )
        )
        if vault_url:
            _append(vault_url)
            parsed = urlparse(vault_url)
            vault_path = yaml_external_secret_ref_segment(
                yaml_ref_value(normalized_vault, "path")
            )
            if parsed.hostname:
                identifier = parsed.hostname.lower()
                if vault_path:
                    identifier = f"{identifier}/{vault_path}"
                _append(f"hashicorp-vault://{identifier}")

    for child_name in ("webhook", "gitlab"):
        child = yaml_child_mapping(provider, child_name)
        if not child:
            continue
        normalized_child = yaml_normalized_mapping(child)
        endpoint = normalize_artifact_text_url(
            yaml_ref_value(normalized_child, "url", "uri", "endpoint")
        )
        if endpoint:
            _append(endpoint)

    return candidates


def yaml_external_secret_ref_segment_for_processor(value: Any) -> str:
    text = str(value or "").strip().strip("\"'").strip("/")
    if not text or len(text) > 512 or re.search(r"\s", text):
        return ""
    if "{{" in text or "}}" in text:
        return ""
    return quote(text, safe="/._:@+=-")


def yaml_sops_section_entries_for_processor(
    mapping: dict[str, Any],
    *keys: str,
    yaml_key_fingerprint: Callable[[str], str],
) -> list[dict[str, Any]]:
    normalized_keys = {yaml_key_fingerprint(key) for key in keys}
    for key, value in mapping.items():
        if yaml_key_fingerprint(str(key or "")) not in normalized_keys:
            continue
        if isinstance(value, dict):
            return [value]
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
            return []
    return []


def yaml_sops_metadata_entry_candidate_for_processor(
    sops_job: tuple[str, dict[str, Any]],
    *,
    yaml_ref_value: Callable[..., str],
    aws_kms_arn_pattern: Any,
    gcp_kms_resource_pattern: Any,
    normalize_artifact_text_url: Callable[[str], str],
    yaml_vault_address_candidate: Callable[[str], str],
) -> str:
    family, entry = sops_job
    if family == "aws_kms":
        arn = yaml_ref_value(entry, "arn")
        return str(arn).strip() if aws_kms_arn_pattern.fullmatch(str(arn or "").strip()) else ""
    if family == "gcp_kms":
        resource_id = str(yaml_ref_value(entry, "resource_id", "resourceId", "resource-id") or "").strip()
        return resource_id if gcp_kms_resource_pattern.fullmatch(resource_id) else ""
    if family == "azure_kv":
        vault_url = str(yaml_ref_value(entry, "vault_url", "vaultUrl", "vault-url") or "").strip()
        return normalize_artifact_text_url(vault_url) if vault_url else ""
    if family == "hc_vault":
        vault_address = str(
            yaml_ref_value(
                entry,
                "vault_address",
                "vaultAddress",
                "vault-address",
                "address",
                "server",
                "url",
                "uri",
            )
            or ""
        ).strip()
        return yaml_vault_address_candidate(vault_address)
    return ""


def yaml_sops_metadata_structured_candidates_for_processor(
    mapping: dict[str, Any],
    normalized: dict[str, Any],
    path_hint: str,
    *,
    yaml_has_hint: Callable[..., bool],
    yaml_sops_section_entries: Callable[..., list[dict[str, Any]]],
    run_ordered_local_batch: Callable[..., list[Any]],
    yaml_sops_metadata_entry_candidate: Callable[[tuple[str, dict[str, Any]]], str],
) -> list[str]:
    sops_mapping: dict[str, Any] | None = None
    if yaml_has_hint(path_hint, "sops"):
        sops_mapping = mapping
    else:
        candidate = normalized.get("sops")
        if isinstance(candidate, dict):
            sops_mapping = candidate
    if not isinstance(sops_mapping, dict):
        return []

    sops_jobs: list[tuple[str, dict[str, Any]]] = []
    for entry in yaml_sops_section_entries(sops_mapping, "kms"):
        sops_jobs.append(("aws_kms", entry))
    for entry in yaml_sops_section_entries(sops_mapping, "gcp_kms", "gcpKms", "gcp-kms"):
        sops_jobs.append(("gcp_kms", entry))
    for entry in yaml_sops_section_entries(sops_mapping, "azure_kv", "azureKv", "azure-kv"):
        sops_jobs.append(("azure_kv", entry))
    for entry in yaml_sops_section_entries(sops_mapping, "hc_vault", "hcVault", "hc-vault"):
        sops_jobs.append(("hc_vault", entry))

    candidate_entries = run_ordered_local_batch(
        sops_jobs,
        yaml_sops_metadata_entry_candidate,
        default_factory=str,
    )
    candidates: list[str] = []
    seen: set[str] = set()

    def _append(value: str) -> None:
        candidate = str(value or "").strip().strip("\"'")
        if not candidate:
            return
        lowered = candidate.lower()
        if lowered in seen:
            return
        seen.add(lowered)
        candidates.append(candidate)

    for candidate in candidate_entries:
        _append(candidate)
    return candidates


def yaml_vault_address_candidate_for_processor(
    value: str,
    *,
    normalize_artifact_text_url: Callable[[str], str],
) -> str:
    candidate = str(value or "").strip().strip("\"'")
    if not candidate:
        return ""
    normalized_url = normalize_artifact_text_url(candidate)
    parsed = urlparse(normalized_url)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return normalized_url
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{1,253}", candidate) and "." in candidate:
        return f"https://{candidate.lower().strip('.')}"
    return ""


def cloudflare_valid_ref_for_processor(value: str) -> str:
    candidate = str(value or "").strip().strip("\"'").lower()
    if re.fullmatch(r"[a-z0-9][a-z0-9._\-]{1,127}", candidate):
        return candidate
    return ""


def cloudflare_uri_candidate_for_processor(
    family: str,
    value: str,
    *,
    cloudflare_valid_ref: Callable[[str], str],
) -> str:
    ref = cloudflare_valid_ref(value)
    if not ref:
        return ""
    return f"cloudflare-{family}://{ref}"


def cloudflare_uri_candidate_entry_for_processor(
    ref_entry: tuple[str, Any],
    *,
    cloudflare_uri_candidate: Callable[[str, str], str],
) -> str:
    family, value = ref_entry
    return cloudflare_uri_candidate(str(family or ""), str(value or ""))


def cloudflare_uri_candidate_entries_for_processor(
    candidate_refs: list[tuple[str, Any]],
    *,
    run_ordered_local_batch: Callable[..., list[Any]],
    cloudflare_uri_candidate_entry: Callable[[tuple[str, Any]], str],
) -> list[str]:
    candidate_entries = run_ordered_local_batch(
        candidate_refs,
        cloudflare_uri_candidate_entry,
        default_factory=str,
    )
    candidates: list[str] = []
    seen: set[str] = set()
    for candidate in candidate_entries:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        candidates.append(candidate)
    return candidates


def yaml_candidate_batch_entries_for_processor(
    candidate_batch: tuple[int, Sequence[str]],
) -> list[str]:
    _batch_index, batch = candidate_batch
    return [candidate for candidate in batch]


def yaml_candidate_family_entries_for_processor(
    candidate_family: tuple[int, Sequence[str]],
) -> list[str]:
    _family_index, family = candidate_family
    return [candidate for candidate in family]


def yaml_candidate_merge_entry_for_processor(
    candidate_entry: tuple[int, str],
) -> str | None:
    _candidate_index, candidate = candidate_entry
    value = str(candidate or "").strip()
    if not value:
        return None
    return value


def yaml_cloudflare_structured_marker_flags_for_processor(
    normalized: dict[str, Any],
    path_hint: str,
    *,
    yaml_has_hint: Callable[..., bool],
) -> dict[str, bool]:
    explicit_cloudflare_hint = yaml_has_hint(
        path_hint,
        "cloudflare",
        "wrangler",
        "r2",
        "d1",
        "kv",
        "workers",
        "worker",
        "pages",
    )
    return {
        "explicit_cloudflare_hint": explicit_cloudflare_hint,
        "has_worker_markers": any(
            key in normalized
            for key in (
                "main",
                "compatibility_date",
                "compatibilitydate",
                "workers_dev",
                "workersdev",
                "account_id",
                "accountid",
            )
        ),
        "has_r2_key": any(
            key in normalized
            for key in (
                "cloudflare_r2_bucket",
                "cloudflarer2bucket",
                "r2_bucket",
                "r2bucket",
                "r2_bucket_name",
                "r2bucketname",
            )
        ),
        "has_d1_key": any(
            key in normalized
            for key in (
                "cloudflare_d1_database",
                "cloudflared1database",
                "cloudflare_d1_database_name",
                "cloudflared1databasename",
                "d1_database",
                "d1database",
                "d1_database_name",
                "d1databasename",
            )
        ),
        "has_kv_key": any(
            key in normalized
            for key in (
                "cloudflare_kv_namespace",
                "cloudflarekvnamespace",
                "cloudflare_kv_namespace_id",
                "cloudflarekvnamespaceid",
                "kv_namespace",
                "kvnamespace",
                "kv_namespace_id",
                "kvnamespaceid",
                "kv_id",
                "kvid",
            )
        ),
        "has_worker_key": any(
            key in normalized
            for key in (
                "cloudflare_worker",
                "cloudflareworker",
                "cloudflare_worker_name",
                "cloudflareworkername",
                "worker_name",
                "workername",
            )
        ),
        "has_pages_key": any(
            key in normalized
            for key in (
                "cloudflare_pages_project",
                "cloudflarepagesproject",
                "cloudflare_pages_project_name",
                "cloudflarepagesprojectname",
                "pages_project",
                "pagesproject",
                "pages_project_name",
                "pagesprojectname",
                "project_name",
                "projectname",
            )
        ),
    }


def yaml_cloudflare_r2_candidate_ref_for_processor(
    normalized: dict[str, Any],
    *,
    explicit_cloudflare_hint: bool,
    has_r2_key: bool,
    yaml_ref_value: Callable[..., str],
) -> tuple[str, str] | None:
    r2_bucket = yaml_ref_value(
        normalized,
        "cloudflare_r2_bucket",
        "cloudflareR2Bucket",
        "r2_bucket",
        "r2Bucket",
        "r2_bucket_name",
        "r2BucketName",
    )
    if not r2_bucket and explicit_cloudflare_hint:
        r2_bucket = yaml_ref_value(
            normalized,
            "bucket_name",
            "bucketName",
            "bucket-name",
            "bucket",
            "name",
        )
    if r2_bucket and (explicit_cloudflare_hint or has_r2_key):
        return ("r2", r2_bucket)
    return None


def yaml_cloudflare_d1_candidate_ref_for_processor(
    normalized: dict[str, Any],
    *,
    explicit_cloudflare_hint: bool,
    has_d1_key: bool,
    yaml_ref_value: Callable[..., str],
) -> tuple[str, str] | None:
    d1_database = yaml_ref_value(
        normalized,
        "cloudflare_d1_database",
        "cloudflareD1Database",
        "cloudflare_d1_database_name",
        "cloudflareD1DatabaseName",
        "d1_database",
        "d1Database",
        "d1_database_name",
        "d1DatabaseName",
    )
    if not d1_database and explicit_cloudflare_hint:
        d1_database = yaml_ref_value(
            normalized,
            "database_name",
            "databaseName",
            "database-name",
            "database_id",
            "databaseId",
            "database-id",
            "name",
        )
    if d1_database and (explicit_cloudflare_hint or has_d1_key):
        return ("d1", d1_database)
    return None


def yaml_cloudflare_kv_candidate_ref_for_processor(
    normalized: dict[str, Any],
    *,
    explicit_cloudflare_hint: bool,
    has_kv_key: bool,
    yaml_ref_value: Callable[..., str],
) -> tuple[str, str] | None:
    kv_namespace = yaml_ref_value(
        normalized,
        "cloudflare_kv_namespace",
        "cloudflareKVNamespace",
        "cloudflare_kv_namespace_id",
        "cloudflareKVNamespaceId",
        "kv_namespace",
        "kvNamespace",
        "kv_namespace_id",
        "kvNamespaceId",
        "kv_id",
        "kvId",
    )
    if not kv_namespace and explicit_cloudflare_hint:
        kv_namespace = yaml_ref_value(
            normalized,
            "namespace_id",
            "namespaceId",
            "namespace-id",
            "id",
            "name",
        )
    if kv_namespace and (explicit_cloudflare_hint or has_kv_key):
        return ("kv", kv_namespace)
    return None


def yaml_cloudflare_worker_candidate_ref_for_processor(
    normalized: dict[str, Any],
    path_hint: str,
    *,
    explicit_cloudflare_hint: bool,
    has_worker_markers: bool,
    has_worker_key: bool,
    yaml_ref_value: Callable[..., str],
    yaml_has_hint: Callable[..., bool],
) -> tuple[str, str] | None:
    worker_name = yaml_ref_value(
        normalized,
        "cloudflare_worker",
        "cloudflareWorker",
        "cloudflare_worker_name",
        "cloudflareWorkerName",
        "worker_name",
        "workerName",
    )
    if not worker_name and (explicit_cloudflare_hint or has_worker_markers):
        worker_name = yaml_ref_value(normalized, "name")
    if worker_name and (
        has_worker_key
        or has_worker_markers
        or yaml_has_hint(path_hint, "worker", "workers", "wrangler")
    ):
        return ("worker", worker_name)
    return None


def yaml_cloudflare_pages_candidate_ref_for_processor(
    normalized: dict[str, Any],
    path_hint: str,
    *,
    has_pages_key: bool,
    yaml_ref_value: Callable[..., str],
    yaml_has_hint: Callable[..., bool],
) -> tuple[str, str] | None:
    pages_project = yaml_ref_value(
        normalized,
        "cloudflare_pages_project",
        "cloudflarePagesProject",
        "cloudflare_pages_project_name",
        "cloudflarePagesProjectName",
        "pages_project",
        "pagesProject",
        "pages_project_name",
        "pagesProjectName",
        "project_name",
        "projectName",
    )
    has_pages_hint = yaml_has_hint(path_hint, "pages")
    has_pages_build_output = any(
        key in normalized for key in ("pages_build_output_dir", "pagesbuildoutputdir")
    )
    if not pages_project and (has_pages_hint or has_pages_build_output):
        pages_project = yaml_ref_value(normalized, "name")
    if pages_project and (has_pages_key or has_pages_hint or has_pages_build_output):
        return ("pages", pages_project)
    return None


def yaml_cloudflare_structured_candidates_for_processor(
    normalized: dict[str, Any],
    path_hint: str,
    *,
    yaml_has_hint: Callable[..., bool],
    yaml_ref_value: Callable[..., str],
    run_ordered_local_batch: Callable[..., list[Any]],
    cloudflare_uri_candidate_entry: Callable[[tuple[str, Any]], str],
) -> list[str]:
    candidate_refs: list[tuple[str, Any]] = []
    marker_flags = yaml_cloudflare_structured_marker_flags_for_processor(
        normalized,
        path_hint,
        yaml_has_hint=yaml_has_hint,
    )
    explicit_cloudflare_hint = marker_flags["explicit_cloudflare_hint"]

    r2_ref = yaml_cloudflare_r2_candidate_ref_for_processor(
        normalized,
        explicit_cloudflare_hint=explicit_cloudflare_hint,
        has_r2_key=marker_flags["has_r2_key"],
        yaml_ref_value=yaml_ref_value,
    )
    if r2_ref:
        candidate_refs.append(r2_ref)

    d1_ref = yaml_cloudflare_d1_candidate_ref_for_processor(
        normalized,
        explicit_cloudflare_hint=explicit_cloudflare_hint,
        has_d1_key=marker_flags["has_d1_key"],
        yaml_ref_value=yaml_ref_value,
    )
    if d1_ref:
        candidate_refs.append(d1_ref)

    kv_ref = yaml_cloudflare_kv_candidate_ref_for_processor(
        normalized,
        explicit_cloudflare_hint=explicit_cloudflare_hint,
        has_kv_key=marker_flags["has_kv_key"],
        yaml_ref_value=yaml_ref_value,
    )
    if kv_ref:
        candidate_refs.append(kv_ref)

    worker_ref = yaml_cloudflare_worker_candidate_ref_for_processor(
        normalized,
        path_hint,
        explicit_cloudflare_hint=explicit_cloudflare_hint,
        has_worker_markers=marker_flags["has_worker_markers"],
        has_worker_key=marker_flags["has_worker_key"],
        yaml_ref_value=yaml_ref_value,
        yaml_has_hint=yaml_has_hint,
    )
    if worker_ref:
        candidate_refs.append(worker_ref)

    pages_ref = yaml_cloudflare_pages_candidate_ref_for_processor(
        normalized,
        path_hint,
        has_pages_key=marker_flags["has_pages_key"],
        yaml_ref_value=yaml_ref_value,
        yaml_has_hint=yaml_has_hint,
    )
    if pages_ref:
        candidate_refs.append(pages_ref)

    return cloudflare_uri_candidate_entries_for_processor(
        candidate_refs,
        run_ordered_local_batch=run_ordered_local_batch,
        cloudflare_uri_candidate_entry=cloudflare_uri_candidate_entry,
    )


def yaml_goreleaser_candidate_values_for_node_for_processor(
    value: Any,
    path: tuple[str, ...],
    *,
    use_workers: bool,
    yaml_goreleaser_blob_bucket_value: Callable[[dict[str, Any]], str],
    yaml_goreleaser_child_candidate_values: Callable[[tuple[int, Any, Any, tuple[str, ...]]], list[str]],
    yaml_goreleaser_child_candidate_values_for_node: Callable[[Any, Any, tuple[str, ...]], list[str]],
    run_ordered_local_batch: Callable[..., list[Any]],
) -> list[str]:
    candidates: list[str] = []
    if isinstance(value, dict):
        if "blobs" in path:
            blob_candidate = yaml_goreleaser_blob_bucket_value(value)
            if blob_candidate:
                candidates.append(blob_candidate)
        child_jobs = [
            (child_index, key, child, path)
            for child_index, (key, child) in enumerate(value.items())
        ]
        child_batches = (
            run_ordered_local_batch(
                child_jobs,
                yaml_goreleaser_child_candidate_values,
                default_factory=list,
            )
            if use_workers
            else [
                yaml_goreleaser_child_candidate_values_for_node(
                    key,
                    child,
                    path,
                )
                for _child_index, key, child, path in child_jobs
            ]
        )
        for child_values in child_batches:
            candidates.extend(child_values)
        return candidates
    if isinstance(value, list):
        for item in value[:256]:
            candidates.extend(
                yaml_goreleaser_candidate_values_for_node_for_processor(
                    item,
                    path,
                    use_workers=False,
                    yaml_goreleaser_blob_bucket_value=yaml_goreleaser_blob_bucket_value,
                    yaml_goreleaser_child_candidate_values=yaml_goreleaser_child_candidate_values,
                    yaml_goreleaser_child_candidate_values_for_node=yaml_goreleaser_child_candidate_values_for_node,
                    run_ordered_local_batch=run_ordered_local_batch,
                )
        )
    return candidates


def strip_git_repository_suffix_for_processor(value: str) -> str:
    candidate = str(value or "").strip().rstrip("/")
    if candidate.lower().endswith(".git"):
        return candidate[:-4]
    return candidate


def artifact_discovery_payloads_for_processor(
    parsed: ParsedArtifact,
) -> list[tuple[str, str, str]]:
    return artifact_discovery_payloads(
        source_url=parsed.source_url,
        payloads=parsed.payloads,
    )


def expand_structured_discovery_jobs_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    payloads: list[tuple[str, str, str]],
) -> list[tuple[str, str, str]]:
    return expand_artifact_structured_discovery_jobs(
        payloads,
        run_ordered_batch=adapter._run_ordered_local_batch,
        structured_discovery_payload_job=adapter._structured_discovery_payload_job,
        structured_discovery_jobs_for_payload=adapter._structured_discovery_jobs_for_payload,
        structured_discovery_result_entry=adapter._structured_discovery_result_entry,
    )


def structured_discovery_payload_job_for_processor(
    payload: tuple[str, str, str],
) -> tuple[str, str, str] | None:
    return artifact_structured_discovery_payload_job(payload)


def structured_discovery_result_entry_for_processor(
    result_entry: tuple[int, list[tuple[str, str, str]] | None],
) -> list[tuple[str, str, str]] | None:
    return artifact_structured_discovery_result_entry(result_entry)


def structured_discovery_jobs_for_payload_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    payload: tuple[str, str, str],
) -> list[tuple[str, str, str]]:
    return artifact_structured_discovery_jobs_for_payload(
        payload,
        structured_discovery_families=adapter._STRUCTURED_DISCOVERY_FAMILIES,
        run_ordered_batch=adapter._run_ordered_local_batch,
        build_structured_discovery_payload_fragment=adapter._build_structured_discovery_payload_fragment,
        structured_discovery_payload_entry=adapter._structured_discovery_payload_entry,
    )


def structured_discovery_payload_entry_for_processor(
    payload_batch: tuple[int, str],
    *,
    source_file: str,
    source_hint: str,
) -> tuple[str, str, str] | None:
    return artifact_structured_discovery_payload_entry(
        payload_batch,
        source_file=source_file,
        source_hint=source_hint,
    )


def decode_data_uri_bytes_for_processor(meta: str, raw_data: str) -> bytes:
    return decode_artifact_data_uri_bytes(meta, raw_data)


def data_uri_payload_entry_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    match_entry: tuple[str, str],
    *,
    max_artifact_member_bytes: int,
) -> str:
    return artifact_data_uri_payload_entry(
        match_entry,
        max_artifact_member_bytes=max_artifact_member_bytes,
        decode_text_artifact_bytes=adapter._decode_text_artifact_bytes,
    )


def data_uri_structured_payload_text_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    text: str,
    *,
    data_uri_pattern: Any,
) -> str:
    return artifact_data_uri_structured_payload_text(
        text,
        data_uri_pattern=data_uri_pattern,
        run_ordered_batch=adapter._run_ordered_local_batch,
        data_uri_payload_entry=adapter._data_uri_payload_entry,
    )


def data_uri_image_payload_entry_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    match_entry: tuple[int, str, str],
    *,
    ocr_image_suffixes: set[str],
    max_ocr_image_bytes: int,
    suffix_from_content_type: Callable[[str], str],
) -> str:
    return artifact_data_uri_image_payload_entry(
        match_entry,
        ocr_image_suffixes=ocr_image_suffixes,
        max_ocr_image_bytes=max_ocr_image_bytes,
        suffix_from_content_type=suffix_from_content_type,
        ocr_image_bytes=adapter._ocr_image_bytes,
        barcode_image_bytes_payload=adapter._barcode_image_bytes_payload,
        image_metadata_payload=adapter._image_metadata_payload,
    )


def data_uri_image_structured_payload_text_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    text: str,
    *,
    data_uri_pattern: Any,
) -> str:
    return artifact_data_uri_image_structured_payload_text(
        text,
        data_uri_pattern=data_uri_pattern,
        run_ordered_batch=adapter._run_ordered_local_batch,
        data_uri_image_payload_entry=adapter._data_uri_image_payload_entry,
    )


def iac_text_structured_payload_text_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    text: str,
    *,
    source_hint: str = "",
    iac_structured_payload_families: tuple[str, ...],
) -> str:
    payload_fragments = adapter._run_ordered_local_batch(
        iac_structured_payload_families,
        lambda family: adapter._iac_text_structured_payload_family(
            family,
            text=text,
            source_hint=source_hint,
        ),
        default_factory=str,
    )
    lines: list[str] = []
    seen: set[str] = set()
    for payload_fragment in payload_fragments:
        for raw_line in str(payload_fragment or "").splitlines():
            candidate = raw_line.strip()
            lowered = candidate.lower()
            if not candidate or lowered in seen:
                continue
            seen.add(lowered)
            lines.append(candidate)
    return "\n".join(lines)


def iac_text_structured_payload_family_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    family: str,
    *,
    text: str,
    source_hint: str,
    cloudformation_template_candidates: Callable[..., list[str]],
    serverless_framework_candidates: Callable[..., list[str]],
    sam_config_candidates: Callable[..., list[str]],
    pulumi_config_candidates: Callable[..., list[str]],
    sst_config_candidates: Callable[..., list[str]],
    aws_cdk_candidates: Callable[..., list[str]],
) -> str:
    if family == "terraform":
        return adapter._terraform_text_structured_payload_text(
            text,
            source_hint=source_hint,
        )
    if family == "bicep":
        return adapter._bicep_text_structured_payload_text(text)
    if family == "cloudformation":
        return "\n".join(
            cloudformation_template_candidates(
                text,
                source_hint=source_hint,
            )
        )
    if family == "serverless":
        return "\n".join(
            serverless_framework_candidates(
                text,
                source_hint=source_hint,
            )
        )
    if family == "sam_config":
        return "\n".join(
            sam_config_candidates(
                text,
                source_hint=source_hint,
            )
        )
    if family == "pulumi_config":
        return "\n".join(
            pulumi_config_candidates(
                text,
                source_hint=source_hint,
            )
        )
    if family == "sst_config":
        return "\n".join(
            sst_config_candidates(
                text,
                source_hint=source_hint,
            )
        )
    if family == "aws_cdk":
        return "\n".join(
            aws_cdk_candidates(
                text,
                source_hint=source_hint,
            )
        )
    return ""


def store_firebase_projects_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    con: sqlite3.Connection,
    firebase_projects: list[Any],
    *,
    source_seed_id: int | None = None,
    source_url: str = "",
    artifact_context: dict[str, Any] | None = None,
) -> tuple[int, int]:
    return store_firebase_projects(
        con,
        firebase_projects,
        source_seed_id=source_seed_id,
        source_url=source_url,
        artifact_context=artifact_context,
        artifact_child_seed_depth=adapter._artifact_child_seed_depth,
        run_ordered_batch=adapter._run_ordered_local_batch,
        firebase_project_persistence_entry=adapter._firebase_project_persistence_entry,
        store_cloud_asset_reference=adapter._store_cloud_asset_reference,
        artifact_cloud_asset_metadata=adapter._artifact_cloud_asset_metadata,
        insert_seed=adapter._insert_seed,
        link_artifact_source_seed=adapter._link_artifact_source_seed,
        merge_artifact_relation_context_fn=adapter._merge_artifact_relation_context,
        store_artifact_url_seed=adapter._store_artifact_url_seed,
        store_key_finding=adapter._store_key_finding,
    )


def store_supabase_configs_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    con: sqlite3.Connection,
    supabase_configs: list[Any],
    *,
    source_seed_id: int | None = None,
    source_url: str = "",
    artifact_context: dict[str, Any] | None = None,
) -> tuple[int, int]:
    return store_supabase_configs(
        con,
        supabase_configs,
        source_seed_id=source_seed_id,
        source_url=source_url,
        artifact_context=artifact_context,
        artifact_child_seed_depth=adapter._artifact_child_seed_depth,
        run_ordered_batch=adapter._run_ordered_local_batch,
        supabase_config_persistence_entry=adapter._supabase_config_persistence_entry,
        store_cloud_asset_reference=adapter._store_cloud_asset_reference,
        artifact_cloud_asset_metadata=adapter._artifact_cloud_asset_metadata,
        store_artifact_url_seed=adapter._store_artifact_url_seed,
        merge_artifact_relation_context_fn=adapter._merge_artifact_relation_context,
        insert_seed=adapter._insert_seed,
        link_artifact_source_seed=adapter._link_artifact_source_seed,
        store_key_finding=adapter._store_key_finding,
    )


def firebase_project_persistence_entry_for_processor(
    project: Any,
    *,
    source_url: str,
) -> dict[str, Any] | None:
    return firebase_project_persistence_entry(project, source_url=source_url)


def supabase_config_persistence_entry_for_processor(
    config: Any,
    *,
    source_url: str,
    redact_secret: Callable[[Any], str],
    encrypt_secret_material: Callable[[Any], str | None],
) -> dict[str, Any] | None:
    return supabase_config_persistence_entry(
        config,
        source_url=source_url,
        redact_secret=redact_secret,
        encrypt_secret_material=encrypt_secret_material,
    )


def collect_generic_text_discovery_batches_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    discovery_jobs: list[tuple[str, str, str]],
) -> list[ArtifactTextDiscoveryBatch]:
    return collect_artifact_text_discovery_batches(
        discovery_jobs,
        run_ordered_batch=adapter._run_ordered_local_batch,
        artifact_text_discovery_job=adapter._generic_text_discovery_job,
        collect_artifact_text_discovery_job_result=adapter._collect_generic_text_discovery_job_result,
    )


def generic_text_discovery_job_for_processor(
    discovery_job: tuple[str, str, str],
) -> tuple[str, str, str] | None:
    return artifact_text_discovery_job(discovery_job)


def collect_generic_text_discovery_job_result_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    discovery_job: tuple[str, str, str],
) -> ArtifactTextDiscoveryBatch:
    return collect_artifact_text_discovery_job_result(
        discovery_job,
        collect_artifact_text_discoveries=adapter._collect_generic_text_discoveries,
    )


def collect_generic_text_discoveries_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    text: str,
    *,
    source_file: str,
    source_hint: str = "",
) -> ArtifactTextDiscoveryBatch:
    return collect_artifact_text_discoveries(
        text,
        source_file=source_file,
        source_hint=source_hint,
        run_ordered_batch=adapter._run_ordered_local_batch,
        collect_generic_text_discovery_family=adapter._collect_generic_text_discovery_family,
        artifact_text_discovery_family_entry=adapter._artifact_text_discovery_family_entry,
        artifact_text_discovery_merge_entry=adapter._artifact_text_discovery_merge_entry,
        merge_artifact_text_discovery_batch_fn=adapter._merge_artifact_text_discovery_batch,
    )


def artifact_text_discovery_family_entry_for_processor(
    family_batch_entry: tuple[int, ArtifactTextDiscoveryBatch],
) -> ArtifactTextDiscoveryBatch:
    return artifact_text_discovery_batch_entry(family_batch_entry)


def collect_generic_text_discovery_family_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    family: str,
    *,
    text: str,
    source_file: str,
    source_hint: str = "",
    email_pattern: Any,
    phone_pattern: Any,
    strip_artifact_url_userinfo_in_text: Callable[[str], str],
    artifact_email_seed_entry: Callable[[str], str],
    artifact_phone_seed_entry: Callable[[str], str],
    extract_artifact_ip_seeds: Callable[[str], list[tuple[str, str]]],
    extract_artifact_network_endpoint_seeds: Callable[..., list[tuple[str, str]]],
    looks_like_gitreview_text_config_name: Callable[[str], bool],
    extract_artifact_gitreview_host_seeds: Callable[[str], list[tuple[str, str]]],
    artifact_format_label: Callable[[str], str],
    mta_sts_mx_hosts: Callable[[str], list[str]],
    matrix_server_delegated_hosts: Callable[[str], list[str]],
    did_web_hosts: Callable[[str], list[str]],
    did_web_hosts_from_lines: Callable[[str], list[str]],
    nostr_relay_hosts: Callable[[str], list[str]],
    terraform_dns_record_hosts: Callable[[str], list[str]],
    artifact_network_host_seed_entries_for_host: Callable[[str], list[tuple[str, str]]],
    redact_secret: Callable[[Any], str],
    parse_azure_storage_connection_string: Callable[[str], dict[str, Any]],
    redact_azure_storage_connection_string: Callable[[str], str],
    encrypt_secret_material_for_finding: Callable[[str], tuple[str | None, str | None]],
) -> ArtifactTextDiscoveryBatch:
    source_label = source_hint or source_file
    batch = ArtifactTextDiscoveryBatch(source_file=source_file)
    simple_batch = collect_artifact_simple_text_discovery_family(
        family,
        text=text,
        source_file=source_file,
        run_ordered_batch=adapter._run_ordered_local_batch,
        email_pattern=email_pattern,
        phone_pattern=phone_pattern,
        strip_artifact_url_userinfo_in_text=strip_artifact_url_userinfo_in_text,
        artifact_email_seed_entry=artifact_email_seed_entry,
        artifact_phone_seed_entry=artifact_phone_seed_entry,
        extract_artifact_ip_seeds=extract_artifact_ip_seeds,
    )
    if simple_batch is not None:
        return simple_batch
    network_host_batch = collect_artifact_network_host_text_discovery_family(
        family,
        text=text,
        source_file=source_file,
        source_label=source_label,
        extract_artifact_network_endpoint_seeds=extract_artifact_network_endpoint_seeds,
        looks_like_gitreview_text_config_name=looks_like_gitreview_text_config_name,
        extract_artifact_gitreview_host_seeds=extract_artifact_gitreview_host_seeds,
        artifact_format_label=artifact_format_label,
        mta_sts_mx_hosts=mta_sts_mx_hosts,
        matrix_server_delegated_hosts=matrix_server_delegated_hosts,
        did_web_hosts=did_web_hosts,
        did_web_hosts_from_lines=did_web_hosts_from_lines,
        nostr_relay_hosts=nostr_relay_hosts,
        terraform_dns_record_hosts=terraform_dns_record_hosts,
        artifact_network_host_seed_entries_for_host=artifact_network_host_seed_entries_for_host,
    )
    if network_host_batch is not None:
        return network_host_batch
    url_batch = collect_artifact_url_text_discovery_family(
        family,
        text=text,
        source_file=source_file,
        run_ordered_batch=adapter._run_ordered_local_batch,
        artifact_text_url_family_candidates=adapter._artifact_text_url_family_candidates,
    )
    if url_batch is not None:
        return url_batch
    identity_batch = collect_artifact_identity_text_discovery_family(
        family,
        text=text,
        source_file=source_file,
        artifact_text_contact_identity_candidates=adapter._artifact_text_contact_identity_candidates,
    )
    if identity_batch is not None:
        return identity_batch
    if family == "keys":
        key_batch = collect_artifact_key_text_discovery_family(
            family,
            text=text,
            source_file=source_file,
            artifact_key_patterns=adapter._artifact_key_patterns,
            run_ordered_batch=adapter._run_ordered_local_batch,
            artifact_text_key_pattern_findings=adapter._artifact_text_key_pattern_findings,
            redact_secret=redact_secret,
            parse_azure_storage_connection_string=parse_azure_storage_connection_string,
            redact_azure_storage_connection_string=redact_azure_storage_connection_string,
            encrypt_secret_material_for_finding=encrypt_secret_material_for_finding,
        )
        if key_batch is not None:
            return key_batch
    cloud_asset_batch = collect_artifact_cloud_asset_text_discovery_family(
        family,
        text=text,
        source_file=source_file,
        run_ordered_batch=adapter._run_ordered_local_batch,
        artifact_text_cloud_asset_family_candidates=adapter._artifact_text_cloud_asset_family_candidates,
    )
    if cloud_asset_batch is not None:
        return cloud_asset_batch
    return batch


def artifact_text_key_pattern_findings_for_processor(
    pattern: Any,
    patterns: list[Any],
    text: str,
    *,
    source_file: str,
    contextual_findings_for_content: Callable[..., list[dict[str, object]]],
) -> list[dict[str, object]]:
    match = pattern.regex.search(text)
    if not match:
        return []
    try:
        key_value = match.group(pattern.group) if pattern.group else match.group(0)
    except IndexError:
        return []
    if not key_value:
        return []
    base_context = {
        "source_url": source_file,
        "repo_name": Path(source_file).name,
        "file_path": source_file,
        "backend": "artifact_text_extract",
    }
    base_finding = {
        "pattern": pattern,
        "key_value": str(key_value),
        **base_context,
    }
    findings: list[dict[str, object]] = [base_finding]
    findings.extend(
        contextual_findings_for_content(
            pattern,
            patterns,
            text,
            dict(base_context),
        )
    )
    return findings


def artifact_text_url_family_candidates_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    family: str,
    *,
    text: str,
    source_file: str,
    artifact_url_pattern: Any,
    artifact_format_label: Callable[[str], str],
    source_looks_like_helm_index: Callable[[str], bool],
    url_looks_like_helm_chart_archive: Callable[[str], bool],
    extract_artifact_relative_route_urls: Callable[..., list[str]],
    public_metadata_document_urls: Callable[..., list[str]],
    host_meta_href_urls: Callable[..., list[str]],
    well_known_link_urls: Callable[..., list[str]],
    api_catalog_urls: Callable[..., list[str]],
    passkey_endpoint_urls: Callable[..., list[str]],
    agent_card_urls: Callable[..., list[str]],
    open_resource_discovery_urls: Callable[..., list[str]],
    mercure_urls: Callable[..., list[str]],
    jmap_urls: Callable[..., list[str]],
    webweaver_urls: Callable[..., list[str]],
    oauth_metadata_urls: Callable[..., list[str]],
    jwks_urls: Callable[..., list[str]],
    feed_urls: Callable[..., list[str]],
    json_feed_urls: Callable[..., list[str]],
    opensearch_description_urls: Callable[..., list[str]],
    saml_metadata_urls: Callable[..., list[str]],
    web_manifest_urls: Callable[..., list[str]],
    helm_index_chart_package_urls: Callable[..., list[str]],
    redocly_config_urls: Callable[..., list[str]],
    extract_artifact_package_registry_urls: Callable[[str], list[str]],
    extract_artifact_container_image_urls: Callable[..., list[str]],
) -> list[str]:
    source_label = artifact_format_label(source_file)
    if family == "direct":
        urls: list[str] = []
        seen_urls: set[str] = set()
        strip_fragment = source_label in {"manifest.json", "webmanifest"}
        helm_index_source = source_looks_like_helm_index(source_file)
        url_entries = adapter._run_ordered_local_batch(
            [url_match.group(0) for url_match in artifact_url_pattern.finditer(text)],
            adapter._artifact_text_direct_url_candidate,
            default_factory=str,
        )
        for url in url_entries:
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc or url in seen_urls:
                continue
            if strip_fragment and parsed.fragment:
                url = parsed._replace(fragment="").geturl()
                parsed = urlparse(url)
                if url in seen_urls:
                    continue
            if helm_index_source and url_looks_like_helm_chart_archive(url):
                continue
            seen_urls.add(url)
            urls.append(url)
        return urls
    if family == "relative_routes":
        return extract_artifact_relative_route_urls(text, base_url=source_file)
    if family == "public_metadata_links":
        return public_metadata_document_urls(
            text,
            source_label=source_label,
            base_url=source_file,
        )
    if family == "host_meta_metadata":
        if source_label != "host-meta":
            return []
        return host_meta_href_urls(text, base_url=source_file)
    if family == "well_known_link_metadata":
        if source_label not in {"host-meta.json", "nodeinfo", "webfinger"}:
            return []
        return well_known_link_urls(text, base_url=source_file)
    if family == "api_catalog_metadata":
        if source_label != "api-catalog":
            return []
        return api_catalog_urls(text, base_url=source_file)
    if family == "passkey_metadata":
        if source_label != "passkey-endpoints":
            return []
        return passkey_endpoint_urls(text, base_url=source_file)
    if family == "agent_card_metadata":
        if source_label != "agent-card.json":
            return []
        return agent_card_urls(text, base_url=source_file)
    if family == "open_resource_discovery":
        if source_label != "open-resource-discovery":
            return []
        return open_resource_discovery_urls(text, base_url=source_file)
    if family == "mercure_metadata":
        if source_label != "mercure":
            return []
        return mercure_urls(text, base_url=source_file)
    if family == "jmap_metadata":
        if source_label != "jmap":
            return []
        return jmap_urls(text, base_url=source_file)
    if family == "webweaver_metadata":
        if source_label != "webweaver.json":
            return []
        return webweaver_urls(text, base_url=source_file)
    if family == "oauth_metadata":
        return oauth_metadata_urls(
            text,
            source_label=source_label,
            base_url=source_file,
        )
    if family == "jwks_metadata":
        return jwks_urls(
            text,
            source_label=source_label,
            base_url=source_file,
        )
    if family == "feed_metadata":
        return feed_urls(
            text,
            source_label=source_label,
            base_url=source_file,
        )
    if family == "json_feed_metadata":
        return json_feed_urls(
            text,
            source_label=source_label,
            base_url=source_file,
        )
    if family == "opensearch_description":
        return opensearch_description_urls(
            text,
            source_label=source_label,
            base_url=source_file,
        )
    if family == "saml_metadata":
        return saml_metadata_urls(
            text,
            source_label=source_label,
            base_url=source_file,
        )
    if family == "web_manifest_metadata":
        return web_manifest_urls(
            text,
            source_label=source_label,
            base_url=source_file,
        )
    if family == "helm_index":
        return helm_index_chart_package_urls(
            text,
            source_hint=source_file,
            base_url=source_file,
        )
    if family == "redocly_config":
        if source_label != "redocly-config":
            return []
        return redocly_config_urls(text, base_url=source_file)
    if family == "package_registry":
        return extract_artifact_package_registry_urls(text)
    if family == "container_images":
        return extract_artifact_container_image_urls(text, source_hint=source_file)
    return []


def artifact_text_direct_url_candidate_for_processor(
    raw_url: str,
    *,
    normalize_artifact_text_url: Callable[[str], str],
) -> str:
    return normalize_artifact_text_url(str(raw_url or ""))


def artifact_text_contact_identity_candidates_for_processor(
    text: str,
    *,
    source_file: str = "",
    artifact_format_label: Callable[[str], str],
    calendar_contact_title_line_value: Callable[[str], str],
    calendar_contact_identity_line_entry: Callable[[str], tuple[str, str, str] | None],
) -> list[tuple[str, str, str, str]]:
    source_label = artifact_format_label(source_file)
    marker_text = str(text or "")
    lowered_marker_text = marker_text.lower()
    if source_label not in {"calendar", "vcard", "vcf"} and not re.search(
        r"(?im)^\s*begin\s*[:=]\s*v(?:card|calendar)\b",
        lowered_marker_text,
    ):
        return []
    title = ""
    title_values = [calendar_contact_title_line_value(line) for line in marker_text.splitlines()]
    for value in title_values:
        if value:
            title = value
            break
    candidates: list[tuple[str, str, str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for raw_line in marker_text.splitlines():
        entry = calendar_contact_identity_line_entry(raw_line)
        if entry is None:
            continue
        enriched_entry = (entry[0], entry[1], entry[2], title)
        if enriched_entry in seen:
            continue
        seen.add(enriched_entry)
        candidates.append(enriched_entry)
        if len(candidates) >= 40:
            break
    return candidates


def calendar_contact_identity_line_entry_for_processor(
    raw_line: str,
    *,
    calendar_contact_identity_value: Callable[[str, str], str],
    looks_like_person_name: Callable[[str], bool],
) -> tuple[str, str, str] | None:
    line = str(raw_line or "").strip()
    if not line:
        return None
    separator = ""
    if ":" in line:
        raw_key = line.split(":", 1)[0].split(";", 1)[0].strip().lower()
        if raw_key in {"fn", "n", "org", "title"}:
            separator = ":"
    if not separator and "=" in line:
        separator = "="
    if not separator:
        return None
    key_part, raw_value = line.split(separator, 1)
    key = key_part.split(";", 1)[0].strip().lower()
    if key not in {"fn", "n", "org"}:
        return None
    value = calendar_contact_identity_value(key, raw_value)
    if not value:
        return None
    if key in {"fn", "n"}:
        if not looks_like_person_name(value):
            return None
        return (value, "name", key)
    if key == "org":
        return (value, "company", key)
    return None


def calendar_contact_title_line_value_for_processor(
    raw_line: str,
    *,
    calendar_contact_identity_value: Callable[[str, str], str],
) -> str:
    line = str(raw_line or "").strip()
    if not line:
        return ""
    separator = ""
    if ":" in line:
        raw_key = line.split(":", 1)[0].split(";", 1)[0].strip().lower()
        if raw_key == "title":
            separator = ":"
    if not separator and "=" in line and line.split("=", 1)[0].strip().lower() == "title":
        separator = "="
    if not separator:
        return ""
    _key_part, raw_value = line.split(separator, 1)
    return calendar_contact_identity_value("title", raw_value)


def calendar_contact_identity_value_for_processor(
    key: str,
    raw_value: str,
    *,
    clean_calendar_contact_identity_value: Callable[[str], str],
) -> str:
    value = str(raw_value or "").strip()
    if key == "n":
        parts = [clean_calendar_contact_identity_value(part) for part in value.split(";")]
        family = parts[0] if len(parts) > 0 else ""
        given = parts[1] if len(parts) > 1 else ""
        additional = parts[2] if len(parts) > 2 else ""
        prefix = parts[3] if len(parts) > 3 else ""
        suffix = parts[4] if len(parts) > 4 else ""
        value = " ".join(part for part in (prefix, given, additional, family, suffix) if part)
    elif key == "org":
        value = next(
            (
                clean_calendar_contact_identity_value(part)
                for part in value.split(";")
                if clean_calendar_contact_identity_value(part)
            ),
            "",
        )
    else:
        value = clean_calendar_contact_identity_value(value)
    return clean_calendar_contact_identity_value(value)


def clean_calendar_contact_identity_value_for_processor(value: str) -> str:
    text = str(value or "").strip()
    text = (
        text.replace("\\n", " ")
        .replace("\\N", " ")
        .replace("\\,", ",")
        .replace("\\;", ";")
        .replace("\\\\", "\\")
    )
    text = re.sub(r"\s+", " ", text).strip(" \t\r\n,;")
    if len(text) < 2 or len(text) > 96:
        return ""
    if "@" in text or "://" in text or any(char in text for char in "<>{}[]"):
        return ""
    if not any(char.isalpha() for char in text):
        return ""
    return text


def artifact_text_aws_cloud_asset_family_candidates_for_processor(
    family: str,
    *,
    text: str,
    aws_s3_uri_pattern: Any,
    aws_s3_arn_pattern: Any,
    aws_kms_arn_pattern: Any,
    aws_generic_arn_cloud_asset_candidates: Callable[[str], list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]] | None:
    if family == "aws_s3":
        candidates: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for match in aws_s3_uri_pattern.finditer(text):
            candidate = ("aws_s3", match.group(1).lower(), "artifact_s3_uri")
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
        for match in aws_s3_arn_pattern.finditer(text):
            candidate = ("aws_s3", match.group("bucket").lower(), "artifact_s3_arn")
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
        return candidates
    if family == "aws_kms":
        candidates: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for match in aws_kms_arn_pattern.finditer(text):
            candidate = ("aws_kms", match.group(0).lower(), "artifact_aws_kms_arn")
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
        return candidates
    if family == "aws_arns":
        return aws_generic_arn_cloud_asset_candidates(text)
    return None


def artifact_text_gcp_cloud_asset_family_candidates_for_processor(
    family: str,
    *,
    text: str,
    gcs_uri_pattern: Any,
    gcs_resource_bucket_pattern: Any,
    gcp_kms_resource_pattern: Any,
) -> list[tuple[str, str, str]] | None:
    if family == "gcs":
        candidates: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for match in gcs_uri_pattern.finditer(text):
            candidate = ("gcs", match.group(1).lower(), "artifact_gcs_uri")
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
        for match in gcs_resource_bucket_pattern.finditer(text):
            candidate = ("gcs", match.group("bucket").lower(), "artifact_gcs_resource")
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
        return candidates
    if family == "gcp_kms":
        candidates: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for match in gcp_kms_resource_pattern.finditer(text):
            candidate = ("gcp_kms", match.group(0), "artifact_gcp_kms_resource")
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
        return candidates
    return None


def artifact_text_azure_cloud_asset_family_candidates_for_processor(
    family: str,
    *,
    text: str,
    azure_blob_resource_id_pattern: Any,
    azure_key_vault_url_pattern: Any,
    microsoft_identity_association_app_id_pattern: Any,
) -> list[tuple[str, str, str]] | None:
    if family == "azure_blob":
        return [
            (
                "azure_blob",
                f"{match.group('account').lower()}/{match.group('container').lower()}",
                "artifact_azure_resource",
            )
            for match in azure_blob_resource_id_pattern.finditer(text)
        ]
    if family == "azure_key_vault":
        candidates: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for match in azure_key_vault_url_pattern.finditer(text):
            vault = str(match.group("vault") or "").lower()
            family_name = str(match.group("family") or "").lower()
            key_name = unquote(str(match.group("name") or "")).strip().lower()
            identifier = vault
            if family_name and key_name:
                identifier = f"{vault}/{family_name}/{key_name}"
            candidate = ("azure_key_vault", identifier, "artifact_azure_key_vault_url")
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
        return candidates
    if family == "azure_ad_app":
        candidates: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for match in microsoft_identity_association_app_id_pattern.finditer(text):
            app_id = str(match.group("app_id") or "").lower()
            candidate = ("azure_ad_app", app_id, "artifact_microsoft_identity_association")
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
        return candidates
    return None


def artifact_text_app_manifest_family_candidates_for_processor(
    family: str,
    *,
    text: str,
    source_file: str,
    artifact_format_label: Callable[[str], str],
    ads_txt_publisher_account_assets: Callable[..., list[tuple[str, str, str]]],
    sellers_json_seller_account_assets: Callable[[str], list[tuple[str, str, str]]],
    ai_plugin_manifest_assets: Callable[[str], list[tuple[str, str, str]]],
    assetlinks_android_packages: Callable[[str], list[str]],
    android_manifest_package_names: Callable[[str], list[str]],
    aasa_ios_app_ids: Callable[[str], list[str]],
    web_manifest_related_application_assets: Callable[[str], list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]] | None:
    source_label = artifact_format_label(source_file)
    if family == "ads_txt_publisher_accounts":
        if source_label != "ads.txt":
            return []
        return ads_txt_publisher_account_assets(text)
    if family == "app_ads_txt_publisher_accounts":
        if source_label != "app-ads.txt":
            return []
        return ads_txt_publisher_account_assets(text, app_ads=True)
    if family == "sellers_json_seller_accounts":
        if source_label != "sellers.json":
            return []
        return sellers_json_seller_account_assets(text)
    if family == "ai_plugin_manifests":
        if source_label != "ai-plugin.json":
            return []
        return ai_plugin_manifest_assets(text)
    if family == "android_assetlinks":
        if source_label != "assetlinks.json":
            return []
        return [
            (
                "mobile_android_package",
                package_name,
                "artifact_assetlinks_android_package",
            )
            for package_name in assetlinks_android_packages(text)
        ]
    if family == "android_manifest":
        if source_label != "android-manifest" and "<manifest" not in text[:2048].lower():
            return []
        return [
            (
                "mobile_android_package",
                package_name,
                "artifact_android_manifest_package",
            )
            for package_name in android_manifest_package_names(text)
        ]
    if family == "apple_app_site_association":
        if source_label != "apple-app-site-association":
            return []
        return [
            ("mobile_ios_app", app_id, "artifact_apple_app_site_association")
            for app_id in aasa_ios_app_ids(text)
        ]
    if family == "web_manifest_related_applications":
        if source_label not in {"manifest.json", "webmanifest"}:
            return []
        return web_manifest_related_application_assets(text)
    return None


def artifact_text_orchestration_manifest_family_candidates_for_processor(
    family: str,
    *,
    text: str,
    kubernetes_secret_manifest_asset_uri_pattern: Any,
    gitops_manifest_asset_uri_pattern: Any,
    workflow_manifest_asset_uri_pattern: Any,
) -> list[tuple[str, str, str]] | None:
    if family == "kubernetes_secret_manifests":
        candidates: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        asset_type_map = {
            "external-secret": "external_secret",
            "secret-store": "external_secret_store",
            "cluster-secret-store": "cluster_secret_store",
            "sealed-secret": "sealed_secret",
            "secret-provider-class": "secret_provider_class",
            "aws-cognito-user-pool": "aws_cognito_user_pool",
            "aws-cognito-identity-pool": "aws_cognito_identity_pool",
            "aws-cognito-app-client": "aws_cognito_app_client",
            "aws-appsync-api": "aws_appsync_api",
            "aws-pinpoint-app": "aws_pinpoint_app",
            "aws-ecs-task-definition": "aws_ecs_task_definition",
            "aws-lambda-function": "aws_lambda_function",
            "aws-lambda-layer": "aws_lambda_layer",
            "aws-iam-role": "aws_iam_role",
            "aws-kms-key": "aws_kms_key",
            "aws-efs-access-point": "aws_efs_access_point",
            "aws-sqs-queue": "aws_sqs_queue",
            "aws-sns-topic": "aws_sns_topic",
            "aws-secretsmanager": "aws_secretsmanager",
            "aws-parameterstore": "aws_parameterstore",
            "gcp-secretmanager": "gcp_secretmanager",
            "hashicorp-vault": "hashicorp_vault",
        }
        amplify_uri_families = {
            "aws-cognito-user-pool",
            "aws-cognito-identity-pool",
            "aws-cognito-app-client",
            "aws-appsync-api",
            "aws-pinpoint-app",
        }
        for match in kubernetes_secret_manifest_asset_uri_pattern.finditer(text):
            family_name = str(match.group("family") or "").lower()
            asset_type = asset_type_map.get(family_name)
            raw_identifier = unquote(str(match.group("identifier") or "")).strip().strip("/")
            identifier = (
                raw_identifier
                if family_name in amplify_uri_families
                else raw_identifier.lower()
            )
            if not asset_type or not identifier:
                continue
            source = (
                "artifact_amplify_client_config"
                if family_name in amplify_uri_families
                else "artifact_kubernetes_secret_manifest"
            )
            candidate = (asset_type, identifier, source)
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
        return candidates
    if family == "gitops_manifests":
        candidates: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        asset_type_map = {
            "argo-application": "argo_application",
            "argo-applicationset": "argo_applicationset",
            "flux-gitrepository": "flux_gitrepository",
            "flux-helmrepository": "flux_helmrepository",
            "flux-ocirepository": "flux_ocirepository",
            "flux-kustomization": "flux_kustomization",
            "flux-bucket": "flux_bucket",
            "crossplane-providerconfig": "crossplane_providerconfig",
            "crossplane-resource": "crossplane_resource",
            "crossplane-composition": "crossplane_composition",
            "crossplane-xrd": "crossplane_xrd",
        }
        for match in gitops_manifest_asset_uri_pattern.finditer(text):
            family_name = str(match.group("family") or "").lower()
            asset_type = asset_type_map.get(family_name)
            identifier = unquote(str(match.group("identifier") or "")).strip().lower().strip("/")
            if not asset_type or not identifier:
                continue
            candidate = (asset_type, identifier, "artifact_gitops_manifest")
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
        return candidates
    if family == "workflow_manifests":
        candidates: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        asset_type_map = {
            "appveyor-pipeline": "appveyor_pipeline",
            "azure-pipeline": "azure_pipeline",
            "bitbucket-pipeline": "bitbucket_pipeline",
            "buildkite-pipeline": "buildkite_pipeline",
            "circleci-pipeline": "circleci_pipeline",
            "drone-pipeline": "drone_pipeline",
            "gitlab-pipeline": "gitlab_pipeline",
            "github-workflow": "github_workflow",
            "github-action": "github_action",
            "tekton-pipeline": "tekton_pipeline",
            "tekton-task": "tekton_task",
            "tekton-pipelinerun": "tekton_pipelinerun",
            "tekton-taskrun": "tekton_taskrun",
            "woodpecker-pipeline": "woodpecker_pipeline",
            "argo-workflow": "argo_workflow",
            "argo-workflowtemplate": "argo_workflowtemplate",
            "argo-cronworkflow": "argo_cronworkflow",
            "argo-clusterworkflowtemplate": "argo_clusterworkflowtemplate",
        }
        for match in workflow_manifest_asset_uri_pattern.finditer(text):
            family_name = str(match.group("family") or "").lower()
            asset_type = asset_type_map.get(family_name)
            identifier = unquote(str(match.group("identifier") or "")).strip().lower().strip("/")
            if not asset_type or not identifier:
                continue
            candidate = (asset_type, identifier, "artifact_workflow_manifest")
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
        return candidates
    return None


def artifact_text_cloudflare_asset_family_candidates_for_processor(
    family: str,
    *,
    text: str,
    cloudflare_structured_asset_uri_pattern: Any,
) -> list[tuple[str, str, str]] | None:
    if family != "cloudflare":
        return None
    return [
        (
            f"cloudflare_{match.group(1).lower()}",
            match.group(2).lower(),
            "artifact_cloudflare_config",
        )
        for match in cloudflare_structured_asset_uri_pattern.finditer(text)
    ]


def artifact_processor_progress_stage_label(progress_label: str | None, stage: str) -> str:
    return artifact_progress_stage_label(progress_label, stage)


def emit_artifact_processor_stage_progress(
    stage: str,
    *,
    total: int,
    workers: int,
    completed: int,
    failed: int,
    started_at: float,
    progress_label: str | None = None,
    progress_callback: Callable[[str, dict[str, object]], None] | None = None,
) -> None:
    if progress_callback is None:
        return
    label = artifact_processor_progress_stage_label(progress_label, stage)
    if not label:
        return
    progress_callback(
        label,
        artifact_progress_snapshot(
            total=total,
            workers=workers,
            completed=completed,
            failed=failed,
            started_at=started_at,
        ),
    )


def artifact_processor_callbacks(
    con: sqlite3.Connection,
    *,
    services: ArtifactProcessorRuntimeServices,
    progress_label: str | None,
    progress_callback: Callable[[str, dict[str, object]], None] | None,
) -> ArtifactQueueRowsProcessCallbacks:
    return artifact_queue_rows_process_callbacks_from_services(
        context=con,
        run_ordered_batch=services.run_ordered_batch,
        dispatch_one=services.dispatch_one,
        download_remote_artifacts=services.download_remote_artifacts,
        reconcile_one=services.reconcile_one,
        update_artifact_status=services.update_artifact_status,
        set_artifact_local_path=services.set_artifact_local_path,
        parse_local_artifacts=services.parse_local_artifacts,
        persist_parsed_artifact=services.persist_parsed_artifact,
        commit=con.commit,
        progress_label=progress_label,
        progress_callback=progress_callback,
    )


def artifact_processor_callbacks_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    con: sqlite3.Connection,
    *,
    progress_label: str | None,
    progress_callback: Callable[[str, dict[str, object]], None] | None,
) -> ArtifactQueueRowsProcessCallbacks:
    return artifact_processor_callbacks(
        con,
        services=artifact_processor_runtime_services(adapter),
        progress_label=progress_label,
        progress_callback=progress_callback,
    )


def ingest_local_artifacts_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    search_roots: list[Path] | None = None,
) -> int:
    return ingest_local_artifacts_with_runtime_services(
        adapter._db_path,
        adapter._engagement_id,
        services=artifact_processor_runtime_services(adapter),
        search_roots=search_roots,
    )


def ingest_local_artifacts_with_runtime_services(
    db_path: Path,
    engagement_id: int,
    *,
    services: ArtifactProcessorRuntimeServices,
    search_roots: list[Path] | None = None,
) -> int:
    con = direct_connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        return ingest_local_artifacts_for_engagement(
            con,
            engagement_id,
            search_roots=search_roots,
            run_ordered_batch=services.run_ordered_batch,
            record_local_artifact=services.local_artifact_record,
            local_artifact_metadata_matches=services.local_artifact_metadata_matches,
            commit_after_ingest=con.commit,
        )
    finally:
        con.close()


def process_artifact_queue_for_processor(
    adapter: ArtifactProcessorRuntimeAdapter,
    *,
    progress_label: str | None = None,
    progress_callback: Callable[[str, dict[str, object]], None] | None = None,
) -> ArtifactProcessingSummary:
    return process_artifact_queue_with_runtime_services(
        adapter._db_path,
        adapter._engagement_id,
        services=artifact_processor_runtime_services(adapter),
        progress_label=progress_label,
        progress_callback=progress_callback,
    )


def process_artifact_queue_with_runtime_services(
    db_path: Path,
    engagement_id: int,
    *,
    services: ArtifactProcessorRuntimeServices,
    progress_label: str | None = None,
    progress_callback: Callable[[str, dict[str, object]], None] | None = None,
) -> ArtifactProcessingSummary:
    con = direct_connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.row_factory = sqlite3.Row
        processed_queue = process_artifact_queue_for_engagement(
            con,
            engagement_id,
            callbacks=artifact_processor_callbacks(
                con,
                services=services,
                progress_label=progress_label,
                progress_callback=progress_callback,
            ),
            commit_after_attempt_mark=con.commit,
        )
        return processed_queue.summary
    finally:
        con.close()


__all__ = [
    "ArtifactProcessorRuntimeAdapter",
    "ArtifactProcessorRuntimeServices",
    "artifact_processor_callbacks",
    "artifact_processor_callbacks_for_processor",
    "artifact_processor_dispatch_entry",
    "artifact_processor_local_artifact_metadata",
    "artifact_processor_local_artifact_metadata_matches",
    "artifact_processor_local_artifact_record",
    "artifact_processor_progress_stage_label",
    "artifact_cloud_asset_metadata_for_processor",
    "artifact_relation_context_for_processor",
    "persist_generic_text_discovery_batch_for_processor",
    "store_generic_text_discoveries_for_processor",
    "artifact_url_seed_persistence_entry_for_processor",
    "artifact_url_seed_family_entry_for_processor",
    "artifact_url_related_seed_entries_for_processor",
    "artifact_url_social_pivot_entries_for_processor",
    "artifact_url_cloud_asset_entries_for_processor",
    "artifact_url_cloud_asset_family_entries_for_processor",
    "store_social_profile_url_pivots_for_processor",
    "store_cloud_assets_from_url_entries_for_processor",
    "artifact_social_profile_url_pivot_entry_for_processor",
    "artifact_cloud_asset_url_entry_for_processor",
    "store_artifact_cloud_asset_reference_for_processor",
    "firebase_match_entry_for_processor",
    "extract_firebase_from_text_for_processor",
    "terraform_state_payload_family_for_processor",
    "terraform_state_text_payloads_for_processor",
    "terraform_state_structured_payloads_for_processor",
    "terraform_state_structured_payload_text_for_processor",
    "terraform_block_assignments_for_processor",
    "terraform_assignment_line_entry_for_processor",
    "iter_terraform_text_blocks_for_processor",
    "terraform_structured_candidate_entry_for_processor",
    "terraform_text_structured_payload_text_for_processor",
    "terraform_text_block_candidate_for_processor",
    "digitalocean_spaces_url_from_endpoint_for_processor",
    "azure_blob_url_from_parts_for_processor",
    "azure_blob_parts_from_composite_name_for_processor",
    "iac_resource_azure_blob_candidate_for_processor",
    "iac_resource_firebase_candidate_for_processor",
    "iac_resource_supabase_candidate_for_processor",
    "iac_resource_s3_candidate_for_processor",
    "iac_resource_gcs_candidate_for_processor",
    "iac_resource_digitalocean_spaces_candidate_for_processor",
    "iac_resource_structured_candidates_for_processor",
    "terraform_backend_config_candidates_for_processor",
    "iter_terragrunt_remote_state_blocks_for_processor",
    "terragrunt_remote_state_backend_candidates_for_processor",
    "parse_key_value_scalar_for_processor",
    "key_value_section_path_for_processor",
    "key_value_line_entry_for_processor",
    "parse_key_value_entries_for_processor",
    "key_value_structured_inputs_for_processor",
    "key_value_structured_payload_lines_for_processor",
    "key_value_structured_payload_text_for_processor",
    "strip_jsonc_comments_for_processor",
    "json_document_from_line_for_processor",
    "json_documents_from_text_for_processor",
    "json_structured_payload_text_for_processor",
    "json_document_looks_like_docker_auth_config_for_processor",
    "firebaserc_project_ref_url_for_processor",
    "firebaserc_structured_payload_text_for_processor",
    "observability_structured_document_candidates_for_processor",
    "observability_child_candidate_values_for_processor",
    "observability_endpoint_jobs_for_processor",
    "observability_scheme_candidate_for_processor",
    "observability_target_url_candidate_for_processor",
    "observability_structured_payload_text_for_processor",
    "edge_proxy_structured_payload_text_for_processor",
    "edge_proxy_endpoint_url_candidate_for_processor",
    "edge_proxy_line_url_candidates_for_processor",
    "orchestration_annotation_endpointish_key_for_processor",
    "orchestration_endpoint_values_for_processor",
    "orchestration_text_values_for_processor",
    "kopia_structured_payload_text_for_processor",
    "duplicacy_structured_payload_text_for_processor",
    "duplicacy_preference_entry_has_hint_for_processor",
    "duplicacy_preference_entry_candidates_for_processor",
    "duplicacy_storage_url_candidates_for_processor",
    "duplicacy_s3_storage_candidates_for_processor",
    "duplicacy_bucket_from_storage_url_for_processor",
    "borg_repository_candidates_for_processor",
    "borg_repository_candidates_from_env_map_for_processor",
    "borg_structured_payload_text_for_processor",
    "borg_s3_repository_candidates_for_processor",
    "borg_bucket_from_repository_url_for_processor",
    "borg_network_repository_candidate_for_processor",
    "restic_repository_candidates_from_env_map_for_processor",
    "restic_repository_candidates_for_processor",
    "restic_s3_repository_candidates_for_processor",
    "restic_bucket_from_pathish_for_processor",
    "yaml_env_candidate_family_for_processor",
    "yaml_managed_hosting_env_entry_for_processor",
    "yaml_env_value_candidate_entry_for_processor",
    "docker_registry_url_candidate_for_processor",
    "docker_auth_principal_candidate_for_processor",
    "docker_auth_principal_from_auth_field_for_processor",
    "docker_auth_entry_principals_for_processor",
    "docker_auth_config_auth_entry_candidates_for_processor",
    "docker_auth_config_cred_helper_candidates_for_processor",
    "docker_auth_config_legacy_entry_candidates_for_processor",
    "docker_auth_structured_candidates_from_env_map_for_processor",
    "docker_auth_structured_env_entry_candidates_for_processor",
    "env_value_may_hold_docker_auth_for_processor",
    "docker_auth_config_candidates_for_processor",
    "duplicati_target_url_candidates_from_env_map_for_processor",
    "duplicati_target_url_candidates_for_processor",
    "duplicati_s3_target_candidates_for_processor",
    "duplicati_bucket_from_target_url_for_processor",
    "duplicati_structured_payload_text_for_processor",
    "duplicati_env_map_from_entries_for_processor",
    "looks_like_duplicati_payload_hint_for_processor",
    "duplicati_nested_option_entries_for_processor",
    "ci_text_structured_payload_text_for_processor",
    "appveyor_ci_document_candidate_for_processor",
    "yaml_mapping_looks_like_appveyor_ci_for_processor",
    "gitpod_structured_payload_text_for_processor",
    "gitpod_document_structured_candidates_for_processor",
    "gitpod_repository_url_candidates_for_processor",
    "yaml_gitpod_config_structured_candidates_for_processor",
    "yaml_mapping_looks_like_gitpod_config_for_processor",
    "iter_bicep_text_blocks_for_processor",
    "bicep_block_assignments_for_processor",
    "bicep_assignment_line_entry_for_processor",
    "bicep_text_structured_payload_text_for_processor",
    "bicep_text_block_candidate_for_processor",
    "goreleaser_blob_bucket_value_for_processor",
    "goreleaser_image_template_values_for_processor",
    "goreleaser_scalar_values_for_processor",
    "yaml_mapping_looks_like_goreleaser_config_for_processor",
    "yaml_goreleaser_config_structured_candidates_for_processor",
    "yaml_goreleaser_child_candidate_values_for_node_for_processor",
    "yaml_goreleaser_child_candidate_values_for_processor",
    "yaml_gitops_repository_child_values_for_processor",
    "yaml_gitops_repository_candidates_for_processor",
    "yaml_gitops_repository_candidates_from_mapping_for_processor",
    "yaml_gitops_repository_values_for_node_for_processor",
    "yaml_flux_source_ref_candidates_for_processor",
    "yaml_flux_bucket_structured_candidates_for_processor",
    "yaml_manifest_looks_like_crossplane_for_processor",
    "crossplane_provider_family_for_processor",
    "yaml_crossplane_external_name_for_processor",
    "yaml_crossplane_cloud_candidates_for_processor",
    "yaml_crossplane_structured_candidates_for_processor",
    "yaml_kubernetes_object_identifier_for_processor",
    "yaml_external_secret_store_refs_for_processor",
    "yaml_external_secret_remote_ref_entry_keys_for_processor",
    "yaml_external_secret_remote_ref_keys_for_processor",
    "yaml_external_secret_provider_candidates_for_processor",
    "yaml_external_secret_ref_segment_for_processor",
    "yaml_sops_section_entries_for_processor",
    "yaml_sops_metadata_entry_candidate_for_processor",
    "yaml_sops_metadata_structured_candidates_for_processor",
    "yaml_vault_address_candidate_for_processor",
    "cloudflare_valid_ref_for_processor",
    "cloudflare_uri_candidate_for_processor",
    "cloudflare_uri_candidate_entry_for_processor",
    "cloudflare_uri_candidate_entries_for_processor",
    "yaml_cloudflare_structured_marker_flags_for_processor",
    "yaml_cloudflare_r2_candidate_ref_for_processor",
    "yaml_cloudflare_d1_candidate_ref_for_processor",
    "yaml_cloudflare_kv_candidate_ref_for_processor",
    "yaml_cloudflare_worker_candidate_ref_for_processor",
    "yaml_cloudflare_pages_candidate_ref_for_processor",
    "yaml_cloudflare_structured_candidates_for_processor",
    "yaml_goreleaser_candidate_values_for_node_for_processor",
    "strip_git_repository_suffix_for_processor",
    "artifact_processor_remote_download_reconciliation_entry",
    "artifact_processor_runtime_services",
    "artifact_discovery_payloads_for_processor",
    "artifact_text_discovery_family_entry_for_processor",
    "artifact_text_direct_url_candidate_for_processor",
    "artifact_text_key_pattern_findings_for_processor",
    "artifact_text_url_family_candidates_for_processor",
    "artifact_text_contact_identity_candidates_for_processor",
    "artifact_text_app_manifest_family_candidates_for_processor",
    "artifact_text_orchestration_manifest_family_candidates_for_processor",
    "artifact_text_cloudflare_asset_family_candidates_for_processor",
    "calendar_contact_identity_line_entry_for_processor",
    "calendar_contact_title_line_value_for_processor",
    "calendar_contact_identity_value_for_processor",
    "clean_calendar_contact_identity_value_for_processor",
    "artifact_text_aws_cloud_asset_family_candidates_for_processor",
    "artifact_text_gcp_cloud_asset_family_candidates_for_processor",
    "artifact_text_azure_cloud_asset_family_candidates_for_processor",
    "collect_generic_text_discovery_family_for_processor",
    "collect_generic_text_discoveries_for_processor",
    "collect_generic_text_discovery_batches_for_processor",
    "collect_generic_text_discovery_job_result_for_processor",
    "data_uri_image_payload_entry_for_processor",
    "data_uri_image_structured_payload_text_for_processor",
    "data_uri_payload_entry_for_processor",
    "data_uri_structured_payload_text_for_processor",
    "decode_data_uri_bytes_for_processor",
    "download_remote_artifacts_for_processor",
    "emit_artifact_processor_stage_progress",
    "expand_structured_discovery_jobs_for_processor",
    "extract_cloud_config_family_for_processor",
    "extract_cloud_configs_from_payload_for_processor",
    "extract_cloud_configs_from_payloads_for_processor",
    "extract_mobile_bundle_family_for_processor",
    "extract_mobile_bundle_text_payloads_for_processor",
    "extract_mobile_configs_from_member_bytes_for_processor",
    "extract_nested_mobile_bundle_configs_for_processor",
    "extract_nested_mobile_configs_from_7z_for_processor",
    "extract_nested_mobile_configs_from_member_jobs_for_processor",
    "extract_nested_mobile_configs_from_tar_for_processor",
    "extract_nested_mobile_configs_from_zip_for_processor",
    "extract_text_artifact_stage_for_processor",
    "firebase_project_persistence_entry_for_processor",
    "generic_text_discovery_job_for_processor",
    "ingest_local_artifacts_for_processor",
    "ingest_local_artifacts_with_runtime_services",
    "iac_text_structured_payload_family_for_processor",
    "iac_text_structured_payload_text_for_processor",
    "parse_artifact_work_item_for_processor",
    "parse_local_artifacts_for_processor",
    "payload_cloud_config_job_for_processor",
    "payload_cloud_config_result_entry_for_processor",
    "persist_parsed_artifact_for_processor",
    "process_artifact_queue_for_processor",
    "process_artifact_queue_with_runtime_services",
    "rebased_mobile_member_config_entry_for_processor",
    "rebased_mobile_member_payload_entry_for_processor",
    "rebased_mobile_member_project_entry_for_processor",
    "merge_artifact_relation_context_for_processor",
    "nested_mobile_7z_member_entry_for_processor",
    "nested_mobile_member_job_for_processor",
    "nested_mobile_member_result_entry_for_processor",
    "nested_mobile_tar_member_entry_for_processor",
    "nested_mobile_zip_member_entry_for_processor",
    "run_ordered_local_batch_for_processor",
    "scan_mobile_bundle_artifact_for_processor",
    "scan_text_artifact_for_processor",
    "safe_artifact_relation_context_for_processor",
    "store_firebase_projects_for_processor",
    "store_supabase_configs_for_processor",
    "structured_discovery_jobs_for_payload_for_processor",
    "structured_discovery_payload_entry_for_processor",
    "structured_discovery_payload_job_for_processor",
    "structured_discovery_result_entry_for_processor",
    "supabase_config_persistence_entry_for_processor",
]
