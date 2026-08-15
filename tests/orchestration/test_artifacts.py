from __future__ import annotations

import base64
import bz2
import gzip
import io
import json
import lzma
import mailbox
import re
import sqlite3
import struct
import tarfile
import zipfile
from email.message import EmailMessage
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Sequence

import pytest

from forge.orchestration.artifacts import (
    ARTIFACT_TEXT_CLOUD_ASSET_DISCOVERY_FAMILIES,
    ARTIFACT_TEXT_DISCOVERY_FAMILIES,
    ARTIFACT_TEXT_URL_DISCOVERY_FAMILIES,
    ARTIFACT_URL_CLOUD_ASSET_FAMILIES,
    AR_ARCHIVE_MAGIC,
    BINARY_STRING_ASCII_RE,
    BINARY_STRING_CANDIDATE_FAMILIES,
    BINARY_STRING_UTF16LE_RE,
    CPIO_NEWC_MAGICS,
    DEFAULT_MAX_ASAR_VISIT_DEPTH,
    EMBEDDED_ARCHIVE_SIGNATURES,
    EMBEDDED_IMAGE_SIGNATURES,
    IMAGE_PAYLOAD_FAMILIES,
    OLE_METADATA_KEYS,
    SEVEN_Z_ARCHIVE_MAGIC,
    XML_MEMBER_PAYLOAD_FAMILIES,
    XML_MEMBER_SUFFIXES,
    ArtifactDownloadRequest,
    ArtifactDownloadResult,
    ArtifactParsedResultAction,
    ArtifactProcessingSummary,
    ArtifactQueueAcquisitionStageResult,
    ArtifactQueueEngagementProcessResult,
    ArtifactQueueDispatchAction,
    ArtifactQueueDispatchEntry,
    ArtifactQueueDispatchStageResult,
    ArtifactQueueParseStageResult,
    ArtifactQueueProcessPlan,
    ArtifactQueueProcessingCycleResult,
    ArtifactQueueReconciliationApplyResult,
    ArtifactQueueReconciliationWriteAction,
    ArtifactQueueRemoteStageResult,
    ArtifactQueueRowsProcessCallbacks,
    ArtifactQueueRowsProcessResult,
    ArtifactQueueRowsPreparationResult,
    ArtifactQueueSkippedStageResult,
    ArtifactQueueStatusWriteAction,
    ArtifactQueueMetadataUpdate,
    ArtifactRemoteDownloadReconciliationAction,
    ArtifactRemoteDownloadReconciliationEntry,
    ArtifactRemoteDownloadScopeDecision,
    ArtifactTextDiscoveredUrlQueueEntry,
    ArtifactTextDiscoveryBatch,
    ArtifactTextScanStageResult,
    ArtifactWorkItem,
    EmbeddedArchiveExtractionJob,
    ParsedArtifact,
    artifact_child_seed_depth,
    artifact_data_uri_image_payload_entry,
    artifact_data_uri_image_structured_payload_text,
    artifact_data_uri_payload_entry,
    artifact_data_uri_structured_payload_text,
    artifact_cloud_asset_metadata,
    artifact_cloud_asset_url_entry,
    artifact_discovery_payloads,
    apply_artifact_queue_total_item,
    apply_artifact_source_candidate_item,
    apply_artifact_parsed_result_actions,
    apply_artifact_queue_reconciliation_writes,
    apply_artifact_queue_status_actions,
    apply_remote_artifact_download_result,
    audit_artifact_lineage,
    process_artifact_queue_acquisition_stage,
    process_artifact_queue_dispatch_stage,
    process_artifact_queue_for_engagement,
    process_artifact_queue_parse_stage,
    process_artifact_queue_processing_cycle,
    process_artifact_queue_remote_stage,
    process_artifact_queue_rows,
    process_artifact_queue_skipped_stage,
    prepare_artifact_classification_reduction_item,
    prepare_artifact_queue_processing_rows,
    prepare_artifact_source_candidate_item,
    prepare_artifact_source_reduction_item,
    queue_discovered_artifact_candidates,
    artifact_local_ingest_decision,
    artifact_local_path_metadata_update,
    artifact_parsed_result_actions,
    artifact_processing_summary_log_message,
    artifact_payload_summary,
    artifact_progress_snapshot,
    artifact_progress_stage_label,
    artifact_queue_candidate_entry,
    discovered_artifact_queue_log_message,
    local_artifact_intake_log_message,
    artifact_queue_dispatch_action,
    artifact_queue_dispatch_actions,
    artifact_queue_process_plan,
    artifact_queue_reconciled_process_plan,
    artifact_queue_skipped_status_actions,
    artifact_queue_processing_rows,
    artifact_queue_rows_process_callbacks_from_services,
    artifact_queue_dispatch_entry,
    artifact_queue_dispatch_result_from_row,
    artifact_source_metadata,
    artifact_relation_context_from_queue,
    artifact_remote_download_reconciliation_action,
    artifact_remote_download_reconciliation_actions,
    artifact_remote_download_reconciliation_entry,
    artifact_remote_download_reconciliation_result_from_item,
    artifact_remote_download_scope_decision,
    remote_artifact_url_scope_decision,
    artifact_seed_metadata_from_evidence,
    artifact_social_profile_url_pivot_entry,
    artifact_source_seed_id,
    artifact_source_seed_provenance,
    artifact_structured_discovery_jobs_for_payload,
    build_artifact_structured_discovery_payload_fragment,
    artifact_structured_discovery_payload_entry,
    artifact_structured_discovery_payload_job,
    artifact_structured_discovery_result_entry,
    artifact_status_metadata_update,
    artifact_text_cloud_asset_persistence_entry,
    artifact_text_discovery_batch_entry,
    artifact_text_discovery_job,
    artifact_text_discovery_merge_family_entry,
    artifact_text_email_persistence_entry,
    artifact_text_host_persistence_entry,
    artifact_text_identity_seed_persistence_entry,
    artifact_text_ip_persistence_entry,
    artifact_text_key_finding_persistence_entry,
    artifact_text_phone_persistence_entry,
    artifact_text_scan_stage,
    artifact_text_url_persistence_entry,
    artifact_text_discovered_url_queue_entry,
    artifact_url_cloud_asset_entries,
    artifact_url_cloud_asset_family_entries,
    artifact_url_related_seed_entries,
    artifact_url_seed_family_merge_entry,
    artifact_url_seed_persistence_entry,
    artifact_url_social_pivot_entries,
    ar_archive_member_jobs,
    asar_archive_member_jobs,
    asar_header_and_content_base,
    asar_non_negative_int,
    archive_stream_kind,
    binary_string_ascii_candidate,
    binary_string_ascii_candidates,
    binary_string_candidate_family,
    binary_string_family_entries,
    binary_string_payload,
    binary_string_utf16_candidate,
    binary_string_utf16_candidates,
    binary_string_value_entry,
    collect_artifact_text_discovery_batches,
    collect_artifact_text_discovery_job_result,
    collect_artifact_text_discoveries,
    collect_artifact_cloud_asset_text_discovery_family,
    collect_artifact_identity_text_discovery_family,
    collect_artifact_key_text_discovery_family,
    collect_artifact_network_host_text_discovery_family,
    collect_artifact_simple_text_discovery_family,
    collect_artifact_url_text_discovery_family,
    cpio_newc_member_jobs,
    crx_zip_payload_bytes,
    decode_artifact_data_uri_bytes,
    decode_email_part_entry,
    decode_email_part_text,
    decode_text_artifact_bytes,
    decode_text_artifact_entry,
    decompress_archive_stream_bytes,
    dedupe_firebase_projects,
    dedupe_supabase_configs,
    default_local_artifact_roots,
    download_remote_artifact_batch,
    download_remote_artifact_request,
    download_remote_artifact_for_queue_record,
    email_message_metadata_line,
    email_message_metadata_lines,
    extract_email_part_job,
    extract_email_part_job_payload_entry,
    extract_email_message_payloads,
    extract_email_message_payload_family,
    extract_email_message_part_payloads,
    extract_email_message_summary_payloads,
    nested_email_message_job,
    MboxRawMessageJobsResult,
    mbox_message_job,
    mbox_raw_message_jobs,
    extract_mbox_payload_family,
    extract_mbox_bytes_payloads,
    extract_mbox_message_payloads,
    extract_mbox_summary_payloads,
    extract_rtf_bytes_payloads,
    extract_rtf_embedded_archive_payloads,
    extract_rtf_payload_family,
    extract_rtf_text_payloads,
    rtf_to_text,
    embedded_archive_match_entry,
    embedded_archive_offsets,
    embedded_archive_job_entry,
    embedded_archive_signature_matches,
    embedded_image_bytes,
    embedded_image_entries,
    embedded_image_payload_batch,
    embedded_image_signature_matches,
    ensure_local_artifact_source_seed,
    extract_archive_7z_payloads,
    extract_archive_ar_payloads,
    extract_archive_asar_payloads,
    extract_archive_bytes_payloads,
    extract_archive_cpio_payloads,
    extract_archive_crx_payloads,
    extract_archive_decompressed_payloads,
    extract_archive_payload_family,
    extract_archive_tar_payloads,
    extract_archive_zip_payloads,
    extract_embedded_archive_payloads,
    extract_embedded_image_payloads,
    extract_image_payload_family,
    extract_image_member_payload_family,
    extract_image_member_payloads,
    extract_image_payloads,
    image_metadata_payload,
    barcode_image_path_payload,
    barcode_image_bytes_payload,
    ocr_image_path,
    ocr_image_bytes,
    pdf_ocr_page_job,
    retained_pdf_ocr_image_path,
    render_pdf_pages_for_ocr,
    extract_legacy_binary_embedded_archive_payloads,
    extract_legacy_binary_ole_payloads,
    extract_legacy_binary_payloads,
    extract_legacy_binary_payload_family,
    extract_legacy_binary_string_payloads,
    extract_member_payload_family,
    extract_ole_metadata_payloads,
    extract_ole_payload_family,
    extract_ole_payloads_from_stream_entries,
    extract_ole_stream_embedded_archive_payloads,
    extract_ole_stream_job_payloads,
    extract_ole_stream_nested_archive_payloads,
    extract_ole_stream_payload_family,
    extract_ole_stream_payloads,
    extract_ole_stream_string_payloads,
    extract_parquet_bytes_payloads,
    extract_parquet_path_payloads,
    extract_pdf_payload_fragment,
    extract_pdf_payloads,
    extract_pdf_bytes_ocr_payloads,
    extract_pdf_ocr_payloads_from_path,
    extract_pdf_text_payloads_from_bytes,
    extract_pdf_text_payloads_from_path,
    extract_sqlite_connection_object_payloads_from_jobs,
    extract_sqlite_connection_payload_family,
    extract_sqlite_connection_payloads_from_jobs,
    extract_sqlite_object_payload_family,
    extract_sqlite_object_payloads_from_connection,
    extract_sqlite_object_row_payloads,
    extract_sqlite_row_cell_line,
    extract_sqlite_row_payload,
    extract_saz_session_pairing_payloads,
    extract_cloud_config_family,
    extract_cloud_configs_from_payload,
    extract_cloud_configs_from_payloads,
    extract_mobile_bundle_family,
    extract_mobile_bundle_family_results,
    extract_mobile_bundle_text_payloads,
    extract_mobile_configs_from_member_bytes,
    extract_nested_mobile_bundle_configs,
    extract_nested_mobile_configs_from_member_jobs,
    extract_nested_mobile_configs_from_7z,
    extract_nested_mobile_configs_from_tar,
    extract_nested_mobile_configs_from_zip,
    extract_text_member_payloads_from_jobs,
    expand_artifact_structured_discovery_jobs,
    firebase_project_persistence_entry,
    ingest_local_artifact_queue_record,
    ingest_local_artifacts_for_engagement,
    interesting_binary_string,
    insert_artifact_email,
    insert_artifact_seed,
    insert_artifact_seed_relation,
    link_artifact_source_seed,
    lookup_artifact_seed_id,
    local_artifact_candidate_paths,
    local_artifact_metadata,
    local_artifact_metadata_matches,
    local_artifact_record,
    local_artifact_source_seed_metadata,
    looks_like_archive_bytes,
    mark_artifact_attempts,
    merge_artifact_processing_summary,
    merge_artifact_metadata_into_seed,
    merge_artifact_relation_context,
    merge_artifact_relation_evidence,
    merge_artifact_seed_metadata,
    merge_artifact_text_discovery_batch,
    member_payloads,
    mobile_member_artifact_type,
    nested_mobile_7z_member_entry,
    nested_mobile_member_job,
    nested_mobile_member_result_entry,
    nested_mobile_tar_member_entry,
    nested_mobile_zip_member_entry,
    normalize_xml_tag,
    ole_metadata_line,
    ole_metadata_lines,
    ole_raw_stream_entries,
    ole_stream_entry,
    ole_stream_job,
    ordered_line_batch_entries,
    ordered_line_entry,
    parquet_cell_text,
    parquet_interesting_value,
    parquet_summary_lines,
    parquet_table_lines,
    pdf_metadata_lines,
    pdf_metadata_lines_for_key,
    pdf_xmp_payload,
    parse_artifact_work_item,
    parse_local_artifact_batch,
    persist_generic_text_discovery_batch,
    persist_parsed_artifact,
    payload_cloud_config_job,
    payload_cloud_config_result_entry,
    queue_artifact_candidate,
    queue_artifact_text_discovered_url,
    rebase_mobile_member_discoveries,
    rebased_mobile_member_config_entry,
    rebased_mobile_member_payload_entry,
    rebased_mobile_member_project_entry,
    safe_artifact_relation_context,
    safe_archive_member_name,
    relationship_payload,
    relationship_line,
    resolve_local_artifact_path,
    run_ordered_local_artifact_batch,
    run_ordered_static_batch,
    static_batch_worker_count,
    saz_raw_session_member_entry,
    saz_request_origin_url,
    saz_response_relative_locations,
    saz_session_pairing_payload,
    scan_mobile_bundle_artifact,
    scan_text_artifact,
    set_artifact_local_path,
    sweep_completed_artifact_metadata,
    store_artifact_url_seed,
    store_artifact_cloud_asset_reference,
    store_artifact_key_finding,
    store_cloud_assets_from_url_entries,
    store_firebase_projects,
    store_social_profile_url_pivots,
    store_supabase_configs,
    supabase_config_persistence_entry,
    text_7z_member_entry,
    text_member_job,
    text_tar_member_entry,
    text_zip_member_entry,
    update_artifact_status,
    xml_property_payload,
    xml_property_line,
    xml_text_payload,
    xml_text_value,
)
from forge.phase4.mobile_config_parse import FirebaseProject, SupabaseConfig


def _run_ordered_batch(items: Any, func: Any, *, default_factory: Any) -> list[Any]:
    del default_factory
    return [func(item) for item in items]


def _cloud_matcher_kwargs() -> dict[str, Any]:
    return {
        "aws_s3_url_patterns": (
            re.compile(r"https?://([a-z0-9.\-]{3,63})\.s3\.amazonaws\.com(?:/|$)", re.IGNORECASE),
        ),
        "do_spaces_url_patterns": (
            re.compile(
                r"https?://([a-z0-9.\-]{3,63})\.([a-z0-9\-]+)\.digitaloceanspaces\.com(?:/|$)",
                re.IGNORECASE,
            ),
            re.compile(
                r"https?://([a-z0-9\-]+)\.digitaloceanspaces\.com/([a-z0-9.\-]{3,63})(?:/|$)",
                re.IGNORECASE,
            ),
        ),
        "gcs_url_patterns": (
            re.compile(r"https?://storage\.googleapis\.com/([a-z0-9._\-]{3,222})(?:/|$)", re.IGNORECASE),
        ),
        "azure_blob_url_patterns": (
            re.compile(r"https?://([a-z0-9\-]{3,24})\.blob\.core\.windows\.net/([^/?#]+)", re.IGNORECASE),
        ),
        "azure_static_website_host_re": re.compile(
            r"^(?P<account>[a-z0-9\-]{3,24})(?:\.[a-z0-9\-]+)?\.web\.core\.windows\.net$",
            re.IGNORECASE,
        ),
        "azure_key_vault_url_re": re.compile(
            r"https?://(?P<vault>[a-z0-9][a-z0-9-]{1,22}[a-z0-9])\.vault\.azure\.net"
            r"(?:/(?P<family>keys|secrets|certificates)/(?P<name>[^/?#\s\"'`<>,;)\]}]+))?",
            re.IGNORECASE,
        ),
        "cloudflare_workers_host_re": re.compile(
            r"^[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)+\.workers\.dev$",
            re.IGNORECASE,
        ),
        "cloudflare_pages_host_re": re.compile(r"^([a-z0-9][a-z0-9\-]{1,62})\.pages\.dev$", re.IGNORECASE),
        "cloudflare_r2_host_re": re.compile(
            r"^(?:[a-z0-9][a-z0-9\-]*\.)?(?:r2\.dev|r2\.cloudflarestorage\.com)$",
            re.IGNORECASE,
        ),
    }


def _cloud_family(family: str, url: str, hostname: str) -> list[dict[str, Any]]:
    return artifact_url_cloud_asset_family_entries(
        family,
        url=url,
        hostname=hostname,
        source="artifact_url_extract",
        **_cloud_matcher_kwargs(),
    )


_DATA_URI_RE = re.compile(
    r"""(?ix)\bdata:
    (?P<meta>[^,\s"'<>]{0,256})
    ,
    (?P<data>[^"'<>\s]{1,8192})
    """
)


def test_artifact_queue_dtos_have_expected_defaults(tmp_path: Path) -> None:
    artifact_path = tmp_path / "artifact.env"
    summary = ArtifactProcessingSummary()
    request = ArtifactDownloadRequest(
        artifact_id=7,
        source_url="https://cdn.acme.example/artifact.env",
        artifact_type="config",
    )
    result = ArtifactDownloadResult(
        artifact_id=7,
        source_url=request.source_url,
        artifact_type=request.artifact_type,
    )
    work_item = ArtifactWorkItem(
        artifact_id=7,
        source_url=request.source_url,
        artifact_type=request.artifact_type,
        path=artifact_path,
    )
    parsed = ParsedArtifact(
        artifact_id=7,
        source_url=request.source_url,
        artifact_type=request.artifact_type,
        path=artifact_path,
    )

    assert summary == ArtifactProcessingSummary(
        queued_local=0,
        processed=0,
        failed=0,
        skipped=0,
        firebase_projects=0,
        supabase_configs=0,
        discovered_seeds=0,
    )
    assert result.path is None
    assert result.metadata_extra == {}
    assert result.error is None
    assert work_item.path == artifact_path
    assert parsed.payloads == []
    assert parsed.firebase_projects == []
    assert parsed.supabase_configs == []
    assert parsed.parse_metadata == {}
    assert parsed.error is None


def test_merge_artifact_processing_summary_adds_all_counters() -> None:
    summary = ArtifactProcessingSummary(
        queued_local=1,
        processed=2,
        failed=3,
        skipped=4,
        firebase_projects=5,
        supabase_configs=6,
        discovered_seeds=7,
    )
    delta = ArtifactProcessingSummary(
        queued_local=10,
        processed=20,
        failed=30,
        skipped=40,
        firebase_projects=50,
        supabase_configs=60,
        discovered_seeds=70,
    )

    result = merge_artifact_processing_summary(summary, delta)

    assert result is summary
    assert summary == ArtifactProcessingSummary(
        queued_local=11,
        processed=22,
        failed=33,
        skipped=44,
        firebase_projects=55,
        supabase_configs=66,
        discovered_seeds=77,
    )


def test_artifact_processing_summary_log_message_only_reports_processed_or_skipped() -> None:
    assert artifact_processing_summary_log_message(None) is None
    assert artifact_processing_summary_log_message(ArtifactProcessingSummary()) is None
    assert (
        artifact_processing_summary_log_message(
            ArtifactProcessingSummary(
                processed=2,
                skipped=1,
                firebase_projects=3,
                supabase_configs=4,
            )
        )
        == "processed=2 firebase=3 supabase=4 skipped=1"
    )
    assert (
        artifact_processing_summary_log_message(
            ArtifactProcessingSummary(firebase_projects=3, supabase_configs=4)
        )
        is None
    )


def test_artifact_queue_count_log_messages_only_report_positive_counts() -> None:
    assert local_artifact_intake_log_message(0) is None
    assert local_artifact_intake_log_message(-1) is None
    assert local_artifact_intake_log_message(3) == (
        "[green]3 local artifact(s) queued[/green]"
    )

    assert discovered_artifact_queue_log_message(0) is None
    assert discovered_artifact_queue_log_message(-1) is None
    assert discovered_artifact_queue_log_message(4) == (
        "[green]4 artifact URL(s) queued for static analysis[/green]"
    )


def test_artifact_queue_dtos_remain_legacy_import_compatible() -> None:
    from forge.engagement_orchestrator import (  # noqa: PLC0415
        ArtifactDownloadRequest as LegacyArtifactDownloadRequest,
        ArtifactDownloadResult as LegacyArtifactDownloadResult,
        ArtifactProcessingSummary as LegacyArtifactProcessingSummary,
        ArtifactWorkItem as LegacyArtifactWorkItem,
        ParsedArtifact as LegacyParsedArtifact,
    )

    assert LegacyArtifactProcessingSummary is ArtifactProcessingSummary
    assert LegacyArtifactWorkItem is ArtifactWorkItem
    assert LegacyArtifactDownloadRequest is ArtifactDownloadRequest
    assert LegacyArtifactDownloadResult is ArtifactDownloadResult
    assert LegacyParsedArtifact is ParsedArtifact


def test_artifact_persistence_helpers_have_direct_module_exports() -> None:
    from forge import orchestration as orchestration_package  # noqa: PLC0415
    from forge.orchestration import artifact_persistence as persistence_module  # noqa: PLC0415

    assert orchestration_package.ArtifactParsedResultAction is ArtifactParsedResultAction
    assert orchestration_package.ArtifactProcessingSummary is ArtifactProcessingSummary
    assert (
        orchestration_package.artifact_processing_summary_log_message
        is artifact_processing_summary_log_message
    )
    assert (
        orchestration_package.discovered_artifact_queue_log_message
        is discovered_artifact_queue_log_message
    )
    assert (
        orchestration_package.local_artifact_intake_log_message
        is local_artifact_intake_log_message
    )
    assert orchestration_package.ArtifactTextDiscoveryBatch is ArtifactTextDiscoveryBatch
    assert orchestration_package.ParsedArtifact is ParsedArtifact
    assert (
        orchestration_package.apply_artifact_parsed_result_actions
        is apply_artifact_parsed_result_actions
    )
    assert orchestration_package.artifact_parsed_result_actions is artifact_parsed_result_actions
    assert (
        orchestration_package.merge_artifact_processing_summary
        is merge_artifact_processing_summary
    )
    assert orchestration_package.persist_parsed_artifact is persist_parsed_artifact
    assert persistence_module.ArtifactParsedResultAction is ArtifactParsedResultAction
    assert persistence_module.ArtifactProcessingSummary is ArtifactProcessingSummary
    assert persistence_module.ArtifactTextDiscoveryBatch is ArtifactTextDiscoveryBatch
    assert persistence_module.ParsedArtifact is ParsedArtifact
    assert (
        persistence_module.apply_artifact_parsed_result_actions
        is apply_artifact_parsed_result_actions
    )
    assert persistence_module.artifact_parsed_result_actions is artifact_parsed_result_actions
    assert (
        persistence_module.merge_artifact_processing_summary
        is merge_artifact_processing_summary
    )
    assert persistence_module.persist_parsed_artifact is persist_parsed_artifact
    for helper in (
        persist_generic_text_discovery_batch,
        merge_artifact_seed_metadata,
        store_artifact_cloud_asset_reference,
        store_artifact_key_finding,
        store_artifact_url_seed,
        artifact_text_cloud_asset_persistence_entry,
        artifact_text_email_persistence_entry,
        artifact_text_host_persistence_entry,
        artifact_text_identity_seed_persistence_entry,
        artifact_text_ip_persistence_entry,
        artifact_text_key_finding_persistence_entry,
        artifact_text_phone_persistence_entry,
        artifact_text_url_persistence_entry,
        firebase_project_persistence_entry,
        store_firebase_projects,
        store_supabase_configs,
        supabase_config_persistence_entry,
    ):
        assert getattr(orchestration_package, helper.__name__) is helper
        assert getattr(persistence_module, helper.__name__) is helper


def test_artifact_queue_helpers_have_direct_module_exports() -> None:
    from forge.orchestration import artifact_queue as queue_module  # noqa: PLC0415

    assert queue_module.ArtifactQueueMetadataUpdate is ArtifactQueueMetadataUpdate
    assert queue_module.ArtifactTextDiscoveredUrlQueueEntry is ArtifactTextDiscoveredUrlQueueEntry
    assert queue_module.artifact_local_path_metadata_update is artifact_local_path_metadata_update
    assert queue_module.artifact_queue_candidate_entry is artifact_queue_candidate_entry
    assert queue_module.artifact_status_metadata_update is artifact_status_metadata_update
    assert (
        queue_module.artifact_text_discovered_url_queue_entry
        is artifact_text_discovered_url_queue_entry
    )
    assert queue_module.queue_artifact_candidate is queue_artifact_candidate
    assert queue_module.queue_artifact_text_discovered_url is queue_artifact_text_discovered_url
    assert queue_module.set_artifact_local_path is set_artifact_local_path
    assert queue_module.update_artifact_status is update_artifact_status


def test_artifact_static_helpers_have_package_and_direct_module_exports() -> None:
    import forge.orchestration as orchestration_package  # noqa: PLC0415
    from forge.orchestration import artifacts as artifacts_module  # noqa: PLC0415

    assert orchestration_package.EMBEDDED_IMAGE_SIGNATURES is EMBEDDED_IMAGE_SIGNATURES
    assert artifacts_module.EMBEDDED_IMAGE_SIGNATURES is EMBEDDED_IMAGE_SIGNATURES
    assert orchestration_package.IMAGE_PAYLOAD_FAMILIES is IMAGE_PAYLOAD_FAMILIES
    assert artifacts_module.IMAGE_PAYLOAD_FAMILIES is IMAGE_PAYLOAD_FAMILIES
    assert (
        orchestration_package.BINARY_STRING_CANDIDATE_FAMILIES
        is BINARY_STRING_CANDIDATE_FAMILIES
    )
    assert artifacts_module.BINARY_STRING_CANDIDATE_FAMILIES is BINARY_STRING_CANDIDATE_FAMILIES
    assert orchestration_package.BINARY_STRING_ASCII_RE is BINARY_STRING_ASCII_RE
    assert artifacts_module.BINARY_STRING_ASCII_RE is BINARY_STRING_ASCII_RE
    assert orchestration_package.BINARY_STRING_UTF16LE_RE is BINARY_STRING_UTF16LE_RE
    assert artifacts_module.BINARY_STRING_UTF16LE_RE is BINARY_STRING_UTF16LE_RE
    assert orchestration_package.OLE_METADATA_KEYS is OLE_METADATA_KEYS
    assert artifacts_module.OLE_METADATA_KEYS is OLE_METADATA_KEYS
    assert orchestration_package.XML_MEMBER_PAYLOAD_FAMILIES is XML_MEMBER_PAYLOAD_FAMILIES
    assert artifacts_module.XML_MEMBER_PAYLOAD_FAMILIES is XML_MEMBER_PAYLOAD_FAMILIES
    assert orchestration_package.XML_MEMBER_SUFFIXES is XML_MEMBER_SUFFIXES
    assert artifacts_module.XML_MEMBER_SUFFIXES is XML_MEMBER_SUFFIXES

    for helper in (
        archive_stream_kind,
        decode_email_part_entry,
        decode_email_part_text,
        decode_text_artifact_bytes,
        decode_text_artifact_entry,
        decompress_archive_stream_bytes,
        ar_archive_member_jobs,
        asar_archive_member_jobs,
        asar_header_and_content_base,
        asar_non_negative_int,
        cpio_newc_member_jobs,
        email_message_metadata_line,
        email_message_metadata_lines,
        extract_email_part_job,
        extract_email_part_job_payload_entry,
        extract_email_message_payloads,
        extract_email_message_payload_family,
        extract_email_message_part_payloads,
        extract_email_message_summary_payloads,
        nested_email_message_job,
        MboxRawMessageJobsResult,
        mbox_message_job,
        mbox_raw_message_jobs,
        extract_mbox_payload_family,
        extract_mbox_bytes_payloads,
        extract_mbox_message_payloads,
        extract_mbox_summary_payloads,
        extract_rtf_bytes_payloads,
        extract_rtf_embedded_archive_payloads,
        extract_rtf_payload_family,
        extract_rtf_text_payloads,
        rtf_to_text,
        binary_string_ascii_candidate,
        binary_string_ascii_candidates,
        binary_string_candidate_family,
        binary_string_family_entries,
        binary_string_payload,
        binary_string_utf16_candidate,
        binary_string_utf16_candidates,
        binary_string_value_entry,
        embedded_archive_match_entry,
        embedded_archive_offsets,
        embedded_archive_job_entry,
        embedded_archive_signature_matches,
        embedded_image_bytes,
        embedded_image_entries,
        embedded_image_payload_batch,
        embedded_image_signature_matches,
        extract_archive_7z_payloads,
        extract_archive_ar_payloads,
        extract_archive_asar_payloads,
        extract_archive_cpio_payloads,
        extract_archive_decompressed_payloads,
        extract_archive_tar_payloads,
        extract_archive_zip_payloads,
        extract_embedded_archive_payloads,
        extract_embedded_image_payloads,
        extract_image_payload_family,
        extract_image_member_payload_family,
        extract_image_member_payloads,
        extract_image_payloads,
        image_metadata_payload,
        barcode_image_path_payload,
        barcode_image_bytes_payload,
        ocr_image_path,
        ocr_image_bytes,
        pdf_ocr_page_job,
        retained_pdf_ocr_image_path,
        render_pdf_pages_for_ocr,
        extract_legacy_binary_embedded_archive_payloads,
        extract_legacy_binary_ole_payloads,
        extract_legacy_binary_payloads,
        extract_legacy_binary_payload_family,
        extract_legacy_binary_string_payloads,
        extract_member_payload_family,
        extract_ole_metadata_payloads,
        extract_ole_payload_family,
        extract_ole_payloads_from_stream_entries,
        extract_ole_stream_embedded_archive_payloads,
        extract_ole_stream_job_payloads,
        extract_ole_stream_nested_archive_payloads,
        extract_ole_stream_payload_family,
        extract_ole_stream_payloads,
        extract_ole_stream_string_payloads,
        extract_parquet_bytes_payloads,
        extract_parquet_path_payloads,
        extract_pdf_payload_fragment,
        extract_pdf_payloads,
        extract_pdf_bytes_ocr_payloads,
        extract_pdf_ocr_payloads_from_path,
        extract_pdf_text_payloads_from_bytes,
        extract_pdf_text_payloads_from_path,
        extract_sqlite_connection_object_payloads_from_jobs,
        extract_sqlite_connection_payload_family,
        extract_sqlite_connection_payloads_from_jobs,
        extract_sqlite_object_payload_family,
        extract_sqlite_object_payloads_from_connection,
        extract_sqlite_object_row_payloads,
        extract_sqlite_row_cell_line,
        extract_sqlite_row_payload,
        interesting_binary_string,
        looks_like_archive_bytes,
        member_payloads,
        normalize_xml_tag,
        ole_metadata_line,
        ole_metadata_lines,
        ole_raw_stream_entries,
        ole_stream_entry,
        ole_stream_job,
        ordered_line_batch_entries,
        ordered_line_entry,
        parquet_cell_text,
        parquet_interesting_value,
        parquet_summary_lines,
        parquet_table_lines,
        pdf_metadata_lines,
        pdf_metadata_lines_for_key,
        pdf_xmp_payload,
        relationship_payload,
        relationship_line,
        resolve_local_artifact_path,
        download_remote_artifact_request,
        run_ordered_static_batch,
        safe_archive_member_name,
        static_batch_worker_count,
        xml_property_payload,
        xml_property_line,
        xml_text_payload,
        xml_text_value,
    ):
        assert getattr(orchestration_package, helper.__name__) is helper
        assert getattr(artifacts_module, helper.__name__) is helper


def test_artifact_text_discovery_batch_entry_copies_nested_lists() -> None:
    original = ArtifactTextDiscoveryBatch(
        source_file="artifact.txt",
        emails=["owner@acme.example"],
        phones=["+15551234567"],
        ip_seeds=[("203.0.113.10", "ipv4")],
        host_seeds=[("api.acme.example", "subdomain")],
        urls=["https://portal.acme.example"],
        identity_seeds=[("Acme Labs", "company", "ORG", "Operations")],
        key_findings=[{"pattern_name": "github_pat", "key_redacted": "ghp_****"}],
        cloud_assets=[("aws_s3", "ops-bucket", "artifact_s3_uri")],
    )

    copied = artifact_text_discovery_batch_entry((0, original))
    copied.emails.append("security@acme.example")
    copied.key_findings[0]["pattern_name"] = "mutated"

    assert copied.source_file == "artifact.txt"
    assert original.emails == ["owner@acme.example"]
    assert original.key_findings == [{"pattern_name": "github_pat", "key_redacted": "ghp_****"}]


def test_collect_artifact_text_discoveries_coordinates_family_batches_in_order() -> None:
    family_calls: list[str] = []

    def _collect_family(
        family: str,
        *,
        text: str,
        source_file: str,
        source_hint: str,
    ) -> ArtifactTextDiscoveryBatch:
        assert text == "payload-text"
        assert source_file == "artifact.txt"
        assert source_hint == "source-hint"
        family_calls.append(family)
        batch = ArtifactTextDiscoveryBatch(source_file=source_file)
        if family == "emails":
            batch.emails = ["owner@acme.example"]
        elif family == "phones":
            batch.phones = ["+15551234567"]
        elif family == "ips":
            batch.ip_seeds = [("203.0.113.10", "ipv4")]
        elif family == "network_hosts":
            batch.host_seeds = [("api.acme.example", "subdomain")]
        elif family == "urls":
            batch.urls = ["https://portal.acme.example"]
        elif family == "contact_identities":
            batch.identity_seeds = [("Acme Labs", "company", "ORG", "")]
        elif family == "keys":
            batch.key_findings = [{"pattern_name": "github_pat", "key_redacted": "ghp_****"}]
        elif family == "cloud_assets":
            batch.cloud_assets = [("aws_s3", "ops-bucket", "artifact_s3_uri")]
        return batch

    def _merge_batch(target: ArtifactTextDiscoveryBatch, source: ArtifactTextDiscoveryBatch) -> None:
        merge_artifact_text_discovery_batch(
            target,
            source,
            run_ordered_batch=_run_ordered_batch,
            artifact_text_discovery_merge_family_entry=artifact_text_discovery_merge_family_entry,
        )

    batch = collect_artifact_text_discoveries(
        "payload-text",
        source_file="artifact.txt",
        source_hint="source-hint",
        run_ordered_batch=_run_ordered_batch,
        collect_generic_text_discovery_family=_collect_family,
        artifact_text_discovery_family_entry=artifact_text_discovery_batch_entry,
        artifact_text_discovery_merge_entry=artifact_text_discovery_batch_entry,
        merge_artifact_text_discovery_batch_fn=_merge_batch,
    )

    assert family_calls == list(ARTIFACT_TEXT_DISCOVERY_FAMILIES)
    assert batch == ArtifactTextDiscoveryBatch(
        source_file="artifact.txt",
        emails=["owner@acme.example"],
        phones=["+15551234567"],
        ip_seeds=[("203.0.113.10", "ipv4")],
        host_seeds=[("api.acme.example", "subdomain")],
        urls=["https://portal.acme.example"],
        identity_seeds=[("Acme Labs", "company", "ORG", "")],
        key_findings=[{"pattern_name": "github_pat", "key_redacted": "ghp_****"}],
        cloud_assets=[("aws_s3", "ops-bucket", "artifact_s3_uri")],
    )


def test_collect_artifact_simple_text_discovery_family_handles_email_phone_and_ip() -> None:
    def _strip_userinfo(text: str) -> str:
        return text.replace("https://token@example.test/path", "")

    common_kwargs = {
        "source_file": "artifact.txt",
        "run_ordered_batch": _run_ordered_batch,
        "email_pattern": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+"),
        "phone_pattern": re.compile(r"(\+?[0-9][0-9 -]{6,})"),
        "strip_artifact_url_userinfo_in_text": _strip_userinfo,
        "artifact_email_seed_entry": lambda value: value.lower(),
        "artifact_phone_seed_entry": lambda value: re.sub(r"\D+", "", value),
    }

    result = collect_artifact_simple_text_discovery_family(
        "emails",
        text="owner@example.test https://token@example.test/path owner@example.test",
        extract_artifact_ip_seeds=lambda _text: [],
        **common_kwargs,
    )

    assert result is not None
    assert result.source_file == "artifact.txt"
    assert result.emails == ["owner@example.test"]

    phone_result = collect_artifact_simple_text_discovery_family(
        "phones",
        text="Call +1 555 0100 or +1 555 0100",
        extract_artifact_ip_seeds=lambda _text: [],
        **common_kwargs,
    )

    assert phone_result is not None
    assert phone_result.phones == ["15550100"]

    ip_result = collect_artifact_simple_text_discovery_family(
        "ips",
        text="ignored",
        extract_artifact_ip_seeds=lambda _text: [
            ("192.0.2.10", "ip"),
            ("192.0.2.10", "ip"),
            ("2001:db8::1", "ip"),
        ],
        **common_kwargs,
    )

    assert ip_result is not None
    assert ip_result.ip_seeds == [("192.0.2.10", "ip"), ("2001:db8::1", "ip")]


def test_collect_artifact_simple_text_discovery_family_returns_none_for_complex_family() -> None:
    assert collect_artifact_simple_text_discovery_family(
        "urls",
        text="https://example.test",
        source_file="artifact.txt",
        run_ordered_batch=_run_ordered_batch,
        email_pattern=re.compile(r".+"),
        phone_pattern=re.compile(r"(.+)"),
        strip_artifact_url_userinfo_in_text=lambda text: text,
        artifact_email_seed_entry=str,
        artifact_phone_seed_entry=str,
        extract_artifact_ip_seeds=lambda _text: [],
    ) is None


def test_collect_artifact_network_host_text_discovery_family_merges_and_dedupes_sources() -> None:
    result = collect_artifact_network_host_text_discovery_family(
        "network_hosts",
        text="payload",
        source_file=".gitreview",
        source_label=".gitreview",
        extract_artifact_network_endpoint_seeds=lambda text, *, source_file: [
            ("api.example.test", "subdomain"),
            ("api.example.test", "subdomain"),
        ],
        looks_like_gitreview_text_config_name=lambda source_label: source_label == ".gitreview",
        extract_artifact_gitreview_host_seeds=lambda text: [
            ("review.example.test", "subdomain"),
            ("api.example.test", "subdomain"),
        ],
        artifact_format_label=lambda source_label: "",
        mta_sts_mx_hosts=lambda text: [],
        matrix_server_delegated_hosts=lambda text: [],
        did_web_hosts=lambda text: [],
        did_web_hosts_from_lines=lambda text: [],
        nostr_relay_hosts=lambda text: [],
        terraform_dns_record_hosts=lambda text: [],
        artifact_network_host_seed_entries_for_host=lambda host: [(host, "subdomain")],
    )

    assert result is not None
    assert result.host_seeds == [
        ("api.example.test", "subdomain"),
        ("review.example.test", "subdomain"),
    ]


def test_collect_artifact_network_host_text_discovery_family_handles_format_specific_hosts() -> None:
    format_hosts = {
        "mta-sts.txt": ["mx.example.test"],
        "matrix-server": ["matrix.example.test"],
        "did.json": ["did.example.test"],
        "atproto-did": ["atproto.example.test"],
        "nostr.json": ["relay.example.test"],
        "terraform": ["terraform.example.test"],
    }

    for format_label, expected_hosts in format_hosts.items():
        result = collect_artifact_network_host_text_discovery_family(
            "network_hosts",
            text="payload",
            source_file="artifact.txt",
            source_label=format_label,
            extract_artifact_network_endpoint_seeds=lambda text, *, source_file: [],
            looks_like_gitreview_text_config_name=lambda source_label: False,
            extract_artifact_gitreview_host_seeds=lambda text: [],
            artifact_format_label=lambda source_label, label=format_label: label,
            mta_sts_mx_hosts=lambda text, hosts=expected_hosts: hosts if format_label == "mta-sts.txt" else [],
            matrix_server_delegated_hosts=lambda text, hosts=expected_hosts: (
                hosts if format_label == "matrix-server" else []
            ),
            did_web_hosts=lambda text, hosts=expected_hosts: (
                hosts if format_label == "did.json" else []
            ),
            did_web_hosts_from_lines=lambda text, hosts=expected_hosts: (
                hosts if format_label == "atproto-did" else []
            ),
            nostr_relay_hosts=lambda text, hosts=expected_hosts: (
                hosts if format_label == "nostr.json" else []
            ),
            terraform_dns_record_hosts=lambda text, hosts=expected_hosts: (
                hosts if format_label == "terraform" else []
            ),
            artifact_network_host_seed_entries_for_host=lambda host: [(host, "subdomain")],
        )

        assert result is not None
        assert result.host_seeds == [(expected_hosts[0], "subdomain")]


def test_collect_artifact_network_host_text_discovery_family_returns_none_for_other_family() -> None:
    assert collect_artifact_network_host_text_discovery_family(
        "urls",
        text="payload",
        source_file="artifact.txt",
        source_label="artifact.txt",
        extract_artifact_network_endpoint_seeds=lambda text, *, source_file: [],
        looks_like_gitreview_text_config_name=lambda source_label: False,
        extract_artifact_gitreview_host_seeds=lambda text: [],
        artifact_format_label=lambda source_label: "",
        mta_sts_mx_hosts=lambda text: [],
        matrix_server_delegated_hosts=lambda text: [],
        did_web_hosts=lambda text: [],
        did_web_hosts_from_lines=lambda text: [],
        nostr_relay_hosts=lambda text: [],
        terraform_dns_record_hosts=lambda text: [],
        artifact_network_host_seed_entries_for_host=lambda host: [],
    ) is None


def test_collect_artifact_url_text_discovery_family_preserves_order_and_dedupes() -> None:
    calls: list[str] = []

    def _url_candidates(
        url_family: str,
        *,
        text: str,
        source_file: str,
    ) -> list[str]:
        assert text == "payload"
        assert source_file == "artifact.txt"
        calls.append(url_family)
        if url_family == "direct":
            return ["https://one.example.test", "https://shared.example.test"]
        if url_family == "relative_routes":
            return ["https://two.example.test", "https://shared.example.test"]
        return []

    result = collect_artifact_url_text_discovery_family(
        "urls",
        text="payload",
        source_file="artifact.txt",
        run_ordered_batch=_run_ordered_batch,
        artifact_text_url_family_candidates=_url_candidates,
    )

    assert result is not None
    assert calls == list(ARTIFACT_TEXT_URL_DISCOVERY_FAMILIES)
    assert result.urls == [
        "https://one.example.test",
        "https://shared.example.test",
        "https://two.example.test",
    ]


def test_collect_artifact_url_text_discovery_family_allows_custom_family_list() -> None:
    result = collect_artifact_url_text_discovery_family(
        "urls",
        text="payload",
        source_file="artifact.txt",
        run_ordered_batch=_run_ordered_batch,
        artifact_text_url_family_candidates=lambda family, **_kwargs: [f"https://{family}.example.test"],
        url_discovery_families=("alpha", "beta"),
    )

    assert result is not None
    assert result.urls == [
        "https://alpha.example.test",
        "https://beta.example.test",
    ]


def test_collect_artifact_url_text_discovery_family_returns_none_for_other_family() -> None:
    assert collect_artifact_url_text_discovery_family(
        "keys",
        text="payload",
        source_file="artifact.txt",
        run_ordered_batch=_run_ordered_batch,
        artifact_text_url_family_candidates=lambda family, **_kwargs: [family],
    ) is None


def test_collect_artifact_cloud_asset_text_discovery_family_preserves_order_and_dedupes() -> None:
    calls: list[str] = []

    def _cloud_asset_candidates(
        cloud_family: str,
        *,
        text: str,
        source_file: str,
    ) -> list[tuple[str, str, str]]:
        assert text == "payload"
        assert source_file == "artifact.txt"
        calls.append(cloud_family)
        if cloud_family == "aws_s3":
            return [
                ("aws_s3", "one", "rule"),
                ("aws_s3", "shared", "rule"),
            ]
        if cloud_family == "gcs":
            return [
                ("gcs", "two", "rule"),
                ("aws_s3", "shared", "rule"),
            ]
        return []

    result = collect_artifact_cloud_asset_text_discovery_family(
        "cloud_assets",
        text="payload",
        source_file="artifact.txt",
        run_ordered_batch=_run_ordered_batch,
        artifact_text_cloud_asset_family_candidates=_cloud_asset_candidates,
    )

    assert result is not None
    assert calls == list(ARTIFACT_TEXT_CLOUD_ASSET_DISCOVERY_FAMILIES)
    assert result.cloud_assets == [
        ("aws_s3", "one", "rule"),
        ("aws_s3", "shared", "rule"),
        ("gcs", "two", "rule"),
    ]


def test_collect_artifact_cloud_asset_text_discovery_family_allows_custom_family_list() -> None:
    result = collect_artifact_cloud_asset_text_discovery_family(
        "cloud_assets",
        text="payload",
        source_file="artifact.txt",
        run_ordered_batch=_run_ordered_batch,
        artifact_text_cloud_asset_family_candidates=lambda family, **_kwargs: [
            (family, f"{family}-asset", "test")
        ],
        cloud_asset_discovery_families=("alpha", "beta"),
    )

    assert result is not None
    assert result.cloud_assets == [
        ("alpha", "alpha-asset", "test"),
        ("beta", "beta-asset", "test"),
    ]


def test_collect_artifact_cloud_asset_text_discovery_family_returns_none_for_other_family() -> None:
    assert collect_artifact_cloud_asset_text_discovery_family(
        "keys",
        text="payload",
        source_file="artifact.txt",
        run_ordered_batch=_run_ordered_batch,
        artifact_text_cloud_asset_family_candidates=lambda family, **_kwargs: [(family, "asset", "test")],
    ) is None


def test_collect_artifact_identity_text_discovery_family_collects_candidates() -> None:
    calls: list[tuple[str, str]] = []

    def _identity_candidates(
        text: str,
        *,
        source_file: str,
    ) -> list[tuple[str, str, str, str]]:
        calls.append((text, source_file))
        return [
            ("Acme Labs", "company", "ORG", "artifact.txt"),
            ("alice", "username", "PERSON", ""),
        ]

    result = collect_artifact_identity_text_discovery_family(
        "contact_identities",
        text="payload",
        source_file="artifact.txt",
        artifact_text_contact_identity_candidates=_identity_candidates,
    )

    assert result is not None
    assert calls == [("payload", "artifact.txt")]
    assert result.identity_seeds == [
        ("Acme Labs", "company", "ORG", "artifact.txt"),
        ("alice", "username", "PERSON", ""),
    ]


def test_collect_artifact_identity_text_discovery_family_returns_none_for_other_family() -> None:
    assert collect_artifact_identity_text_discovery_family(
        "keys",
        text="payload",
        source_file="artifact.txt",
        artifact_text_contact_identity_candidates=lambda text, **_kwargs: [("unused", "username", "", "")],
    ) is None


def test_collect_artifact_key_text_discovery_family_shapes_findings_and_dedupes() -> None:
    github_pattern = SimpleNamespace(
        name="github_pat",
        service="github",
        context_required=False,
        confidence="high",
    )
    skipped_pattern = SimpleNamespace(
        name="low_confidence",
        service="skip",
        context_required=False,
        confidence="low",
    )
    calls: list[str] = []

    def _findings(
        pattern: Any,
        patterns: list[Any],
        text: str,
        *,
        source_file: str,
    ) -> list[dict[str, Any]]:
        calls.append(pattern.name)
        assert patterns == [github_pattern, skipped_pattern]
        assert text == "payload"
        assert source_file == "artifact.txt"
        return [
            {
                "pattern": pattern,
                "key_value": " ghp_secret ",
                "source_url": "nested/config.txt",
                "backend": "artifact_text_extract",
            },
            {
                "pattern": pattern,
                "key_value": "duplicate",
            },
        ]

    result = collect_artifact_key_text_discovery_family(
        "keys",
        text="payload",
        source_file="artifact.txt",
        artifact_key_patterns=[github_pattern, skipped_pattern],
        run_ordered_batch=_run_ordered_batch,
        artifact_text_key_pattern_findings=_findings,
        redact_secret=lambda value: f"redacted:{value}",
        parse_azure_storage_connection_string=lambda value: {},
        redact_azure_storage_connection_string=lambda value: f"azure-redacted:{value}",
        encrypt_secret_material_for_finding=lambda value: (f"enc:{value}", "encrypted"),
    )

    assert result is not None
    assert calls == ["github_pat"]
    assert result.key_findings == [
        {
            "service": "github",
            "domain": "",
            "source_url": "nested/config.txt",
            "pattern_name": "github_pat",
            "key_redacted": "redacted:ghp_secret",
            "key_enc": "enc:ghp_secret",
            "source_backend": "artifact_text_extract",
            "repo_name": "config.txt",
            "validation_detail": "encrypted",
        }
    ]


def test_collect_artifact_key_text_discovery_family_handles_azure_storage_keys() -> None:
    azure_pattern = SimpleNamespace(
        name="azure_storage_key",
        service="azure_storage",
        context_required=False,
        confidence="medium",
    )

    result = collect_artifact_key_text_discovery_family(
        "keys",
        text="payload",
        source_file="artifact.txt",
        artifact_key_patterns=[azure_pattern],
        run_ordered_batch=_run_ordered_batch,
        artifact_text_key_pattern_findings=lambda pattern, *_args, **_kwargs: [
            {
                "pattern": pattern,
                "key_value": "DefaultEndpointsProtocol=https;AccountName=OpsStore;AccountKey=secret",
            }
        ],
        redact_secret=lambda value: f"redacted:{value}",
        parse_azure_storage_connection_string=lambda value: {"accountname": "OpsStore"},
        redact_azure_storage_connection_string=lambda value: "AccountName=OpsStore;AccountKey=***",
        encrypt_secret_material_for_finding=lambda value: (None, "missing-key"),
    )

    assert result is not None
    assert result.key_findings == [
        {
            "service": "azure_storage",
            "domain": "opsstore",
            "source_url": "artifact.txt",
            "pattern_name": "azure_storage_key",
            "key_redacted": "AccountName=OpsStore;AccountKey=***",
            "key_enc": None,
            "source_backend": "artifact_text_extract",
            "repo_name": "artifact.txt",
            "validation_detail": "missing-key",
        }
    ]


def test_collect_artifact_key_text_discovery_family_returns_none_for_other_family() -> None:
    assert collect_artifact_key_text_discovery_family(
        "cloud_assets",
        text="payload",
        source_file="artifact.txt",
        artifact_key_patterns=[],
        run_ordered_batch=_run_ordered_batch,
        artifact_text_key_pattern_findings=lambda *_args, **_kwargs: [],
        redact_secret=str,
        parse_azure_storage_connection_string=lambda value: {},
        redact_azure_storage_connection_string=str,
        encrypt_secret_material_for_finding=lambda value: (None, ""),
    ) is None


def test_artifact_text_discovery_job_filters_blank_text_and_normalizes_hint() -> None:
    assert artifact_text_discovery_job(("artifact.txt", "", "payload")) == (
        "artifact.txt",
        "artifact.txt",
        "payload",
    )
    assert artifact_text_discovery_job(("artifact.txt", "hint.txt", "payload")) == (
        "artifact.txt",
        "hint.txt",
        "payload",
    )
    assert artifact_text_discovery_job(("artifact.txt", "hint.txt", "   ")) is None


def test_collect_artifact_text_discovery_job_result_falls_back_to_empty_batch() -> None:
    def _raise(_text: str, *, source_file: str, source_hint: str) -> ArtifactTextDiscoveryBatch:
        del source_file, source_hint
        raise RuntimeError("bad payload")

    assert collect_artifact_text_discovery_job_result(
        ("artifact.txt", "hint.txt", "payload"),
        collect_artifact_text_discoveries=_raise,
    ) == ArtifactTextDiscoveryBatch(source_file="artifact.txt")


def test_collect_artifact_text_discovery_batches_filters_and_preserves_order() -> None:
    planned_jobs: list[tuple[str, str, str]] = []
    collected_jobs: list[tuple[str, str, str]] = []

    def _plan(discovery_job: tuple[str, str, str]) -> tuple[str, str, str] | None:
        planned = artifact_text_discovery_job(discovery_job)
        if planned is not None:
            planned_jobs.append(planned)
        return planned

    def _collect(discovery_job: tuple[str, str, str]) -> ArtifactTextDiscoveryBatch:
        collected_jobs.append(discovery_job)
        source_file, _source_hint, text = discovery_job
        return ArtifactTextDiscoveryBatch(source_file=source_file, emails=[f"{text}@acme.example"])

    batches = collect_artifact_text_discovery_batches(
        [
            ("one.txt", "one-source", "one"),
            ("blank.txt", "blank-source", "   "),
            ("two.txt", "", "two"),
        ],
        run_ordered_batch=_run_ordered_batch,
        artifact_text_discovery_job=_plan,
        collect_artifact_text_discovery_job_result=_collect,
    )

    assert planned_jobs == [
        ("one.txt", "one-source", "one"),
        ("two.txt", "two.txt", "two"),
    ]
    assert collected_jobs == planned_jobs
    assert batches == [
        ArtifactTextDiscoveryBatch(source_file="one.txt", emails=["one@acme.example"]),
        ArtifactTextDiscoveryBatch(source_file="two.txt", emails=["two@acme.example"]),
    ]


def test_artifact_structured_discovery_payload_helpers_normalize_three_tuple_jobs() -> None:
    assert artifact_structured_discovery_payload_job(("artifact.txt", "payload.txt", "body")) == (
        "artifact.txt",
        "payload.txt",
        "body",
    )
    assert artifact_structured_discovery_payload_job(("artifact.txt", "payload.txt", "  ")) is None
    assert artifact_structured_discovery_payload_entry(
        (0, " structured body "),
        source_file="artifact.txt",
        source_hint="artifact.txt/payload.txt",
    ) == ("artifact.txt", "artifact.txt/payload.txt", "structured body")
    assert artifact_structured_discovery_payload_entry(
        (1, "  "),
        source_file="artifact.txt",
        source_hint="artifact.txt/payload.txt",
    ) is None
    assert artifact_structured_discovery_result_entry((0, None)) is None
    assert artifact_structured_discovery_result_entry(
        (1, [("artifact.txt", "artifact.txt/payload.txt", "body")])
    ) == [("artifact.txt", "artifact.txt/payload.txt", "body")]


def _structured_fragment_callbacks(**overrides: Any) -> dict[str, Any]:
    def _text_handler(name: str) -> Callable[..., str]:
        def _inner(text: str, *, source_hint: str = "", base_url: str = "") -> str:
            suffix = f":{base_url}" if base_url else ""
            return f"{name}:{text}:{source_hint}{suffix}"

        return _inner

    callbacks: dict[str, Any] = {
        "tunnel_config_artifact_label": lambda _source_hint: False,
        "tunnel_config_public_payload_text": lambda text: f"tunnel-public:{text}",
        "storage_client_config_artifact_label": lambda _source_hint: False,
        "storage_client_config_public_payload_text": lambda text: f"storage-public:{text}",
        "iac_text_structured_payload_text": _text_handler("iac"),
        "kopia_structured_payload_text": _text_handler("kopia"),
        "duplicacy_structured_payload_text": _text_handler("duplicacy"),
        "duplicati_structured_payload_text": _text_handler("duplicati"),
        "borg_structured_payload_text": _text_handler("borg"),
        "json_structured_payload_text": _text_handler("json"),
        "sanity_config_urls": lambda text, *, source_hint: [f"sanity:{text}:{source_hint}"],
        "firebaserc_structured_payload_text": _text_handler("firebaserc"),
        "observability_structured_payload_text": _text_handler("observability"),
        "edge_proxy_structured_payload_text": _text_handler("edge-proxy"),
        "orchestration_structured_payload_text": _text_handler("orchestration"),
        "api_spec_text_structured_payload_text": _text_handler("api-spec"),
        "api_client_text_structured_payload_text": _text_handler("api-client"),
        "http_request_text_structured_payload_text": _text_handler("http-request"),
        "http_transcript_text_structured_payload_text": _text_handler("http-transcript"),
        "connection_client_structured_payload_text": _text_handler("connection-client"),
        "database_client_structured_payload_text": _text_handler("database-client"),
        "storage_client_config_structured_payload_text": _text_handler("storage-client"),
        "supabase_cli_config_urls": lambda text, *, source_hint: [f"supabase:{text}:{source_hint}"],
        "amplify_client_config_structured_payload_text": _text_handler("amplify-client"),
        "hashicorp_config_candidates": lambda text, *, source_hint: [f"hashicorp:{text}:{source_hint}"],
        "framework_config_structured_payload_text": _text_handler("framework"),
        "orm_config_structured_payload_text": _text_handler("orm"),
        "tunnel_config_structured_payload_text": _text_handler("tunnel"),
        "browser_state_structured_payload_text": _text_handler("browser-state"),
        "charles_session_json_structured_payload_text": _text_handler("charles"),
        "burp_site_map_xml_structured_payload_text": _text_handler("burp"),
        "recon_tool_output_structured_payload_text": _text_handler("recon"),
        "graphql_config_text_structured_payload_text": _text_handler("graphql"),
        "interface_definition_text_structured_payload_text": _text_handler("interface"),
        "android_manifest_urls": lambda text: [f"android:{text}"],
        "key_value_structured_payload_text": _text_handler("key-value"),
        "ci_text_structured_payload_text": _text_handler("ci"),
        "yaml_structured_payload_text": _text_handler("yaml"),
        "data_uri_image_structured_payload_text": lambda text: f"data-uri-image:{text}",
        "data_uri_structured_payload_text": lambda text: f"data-uri:{text}",
        "renovate_text_structured_payload_text": _text_handler("renovate"),
        "security_scanner_config_structured_payload_text": _text_handler("security-scanner"),
        "maven_xml_structured_payload_text": _text_handler("maven"),
        "gradle_text_structured_payload_text": _text_handler("gradle"),
        "js_runtime_text_structured_payload_text": _text_handler("js-runtime"),
        "static_hosting_control_text_structured_payload_text": _text_handler("static-hosting"),
        "electron_update_metadata_candidates": (
            lambda text, *, source_hint, base_url: [f"electron:{text}:{source_hint}:{base_url}"]
        ),
        "starlark_container_image_values": lambda _text, *, source_hint: [
            f"{source_hint}/image",
            f"{source_hint}/image",
            "skip",
        ],
        "artifact_container_image_url_candidate": (
            lambda value, *, require_explicit_registry=False: (
                f"oci://{value}" if value != "skip" and require_explicit_registry else None
            )
        ),
        "gitpod_structured_payload_text": _text_handler("gitpod"),
    }
    callbacks.update(overrides)
    return callbacks


def test_build_artifact_structured_discovery_payload_fragment_preserves_routing() -> None:
    callbacks = _structured_fragment_callbacks()

    assert build_artifact_structured_discovery_payload_fragment(
        "iac",
        text="body",
        extract_path="payload.txt",
        source_file="artifact.zip",
        **callbacks,
    ) == "iac:body:artifact.zip/payload.txt"
    assert build_artifact_structured_discovery_payload_fragment(
        "json",
        text="body",
        extract_path="payload.txt",
        source_file="artifact.zip",
        **callbacks,
    ) == "json:body:payload.txt"
    assert build_artifact_structured_discovery_payload_fragment(
        "js_runtime_text",
        text="body",
        extract_path="payload.txt",
        source_file="https://assets.acme.example/app.js",
        **callbacks,
    ) == "js-runtime:body:https://assets.acme.example/app.js/payload.txt:https://assets.acme.example/app.js"
    assert build_artifact_structured_discovery_payload_fragment(
        "sanity_config_text",
        text="body",
        extract_path="payload.txt",
        source_file="artifact.zip",
        **callbacks,
    ) == "sanity:body:artifact.zip/payload.txt"
    assert build_artifact_structured_discovery_payload_fragment(
        "android_manifest_text",
        text="body",
        extract_path="AndroidManifest.xml",
        source_file="",
        **callbacks,
    ) == "android:body"


def test_build_artifact_structured_discovery_payload_fragment_preprocesses_and_falls_back() -> None:
    tunnel_callbacks = _structured_fragment_callbacks(
        tunnel_config_artifact_label=lambda source_hint: source_hint.endswith(".ovpn"),
    )
    storage_callbacks = _structured_fragment_callbacks(
        storage_client_config_artifact_label=lambda source_hint: "storage" in source_hint,
    )

    assert build_artifact_structured_discovery_payload_fragment(
        "raw",
        text="secret",
        extract_path="client.ovpn",
        source_file="artifact.zip",
        **tunnel_callbacks,
    ) == "tunnel-public:secret"
    assert build_artifact_structured_discovery_payload_fragment(
        "raw",
        text="secret",
        extract_path="storage/config.json",
        source_file="artifact.zip",
        **storage_callbacks,
    ) == "storage-public:secret"
    assert build_artifact_structured_discovery_payload_fragment(
        "storage_client_config_text",
        text="secret",
        extract_path="storage/config.json",
        source_file="artifact.zip",
        **storage_callbacks,
    ) == "storage-client:secret:artifact.zip/storage/config.json"
    assert build_artifact_structured_discovery_payload_fragment(
        "unknown",
        text="body",
        extract_path="payload.txt",
        source_file="artifact.zip",
        **storage_callbacks,
    ) == ""


def test_build_artifact_structured_discovery_payload_fragment_dedupes_starlark_images() -> None:
    callbacks = _structured_fragment_callbacks()

    assert build_artifact_structured_discovery_payload_fragment(
        "starlark_container_images",
        text="body",
        extract_path="BUILD.bazel",
        source_file="artifact.zip",
        **callbacks,
    ) == "oci://artifact.zip/BUILD.bazel/image"


def test_artifact_structured_discovery_jobs_for_payload_preserves_source_hint_and_family_order() -> None:
    calls: list[str] = []

    def _build(
        family: str,
        *,
        text: str,
        extract_path: str,
        source_file: str,
    ) -> str:
        assert text == "payload"
        assert extract_path == "payload.txt"
        assert source_file == "artifact.txt"
        calls.append(family)
        return "" if family == "empty" else f"{text}-{family}"

    jobs = artifact_structured_discovery_jobs_for_payload(
        ("artifact.txt", "payload.txt", "payload"),
        structured_discovery_families=("iac", "json", "empty"),
        run_ordered_batch=_run_ordered_batch,
        build_structured_discovery_payload_fragment=_build,
        structured_discovery_payload_entry=artifact_structured_discovery_payload_entry,
    )

    assert calls == ["iac", "json", "empty"]
    assert jobs == [
        ("artifact.txt", "artifact.txt/payload.txt", "payload-iac"),
        ("artifact.txt", "artifact.txt/payload.txt", "payload-json"),
    ]


def test_expand_artifact_structured_discovery_jobs_filters_and_flattens_ordered_results() -> None:
    payload_calls: list[tuple[str, str, str]] = []

    def _jobs_for_payload(payload: tuple[str, str, str]) -> list[tuple[str, str, str]]:
        payload_calls.append(payload)
        source_file, extract_path, text = payload
        source_hint = f"{source_file}/{extract_path}"
        return [
            (source_file, source_hint, f"{text}-iac"),
            (source_file, source_hint, f"{text}-json"),
        ]

    jobs = expand_artifact_structured_discovery_jobs(
        [
            ("one.txt", "payload-one.txt", "one"),
            ("blank.txt", "payload-blank.txt", " "),
            ("two.txt", "payload-two.txt", "two"),
        ],
        run_ordered_batch=_run_ordered_batch,
        structured_discovery_payload_job=artifact_structured_discovery_payload_job,
        structured_discovery_jobs_for_payload=_jobs_for_payload,
        structured_discovery_result_entry=artifact_structured_discovery_result_entry,
    )

    assert payload_calls == [
        ("one.txt", "payload-one.txt", "one"),
        ("two.txt", "payload-two.txt", "two"),
    ]
    assert jobs == [
        ("one.txt", "one.txt/payload-one.txt", "one-iac"),
        ("one.txt", "one.txt/payload-one.txt", "one-json"),
        ("two.txt", "two.txt/payload-two.txt", "two-iac"),
        ("two.txt", "two.txt/payload-two.txt", "two-json"),
    ]


def test_safe_artifact_relation_context_filters_and_bounds_metadata() -> None:
    context = safe_artifact_relation_context(
        parse_metadata={
            "parser": "json",
            "format": "config",
            "payload_count": 3,
            "metadata_payload_count": 0,
            "ignored": "drop",
        },
        artifact_type="x" * 80,
        artifact_metadata={
            "content_type": "application/json",
            "download_filename": " config.json ",
            "downloaded_from_remote": True,
            "helm_index_url": "https://charts.acme.example/index.yaml",
            "source_rule": "remote_artifact",
            "unsafe": ["drop"],
        },
    )

    assert context == {
        "parser": "json",
        "format": "config",
        "payload_count": 3,
        "metadata_payload_count": 0,
        "artifact_type": "x" * 64,
        "content_type": "application/json",
        "download_filename": "config.json",
        "downloaded_from_remote": True,
        "helm_index_url": "https://charts.acme.example/index.yaml",
        "source_rule": "remote_artifact",
    }


def test_artifact_relation_context_from_queue_loads_sanitized_metadata() -> None:
    con = sqlite3.connect(":memory:")
    con.execute(
        """
        CREATE TABLE artifact_queue (
            id INTEGER,
            engagement_id INTEGER,
            metadata_json TEXT
        )
        """,
    )
    con.execute(
        "INSERT INTO artifact_queue (id, engagement_id, metadata_json) VALUES (?, ?, ?)",
        (
            7,
            99,
            json.dumps(
                {
                    "content_type": "application/json",
                    "download_filename": " config.json ",
                    "downloaded_from_remote": True,
                    "source_rule": "remote_artifact",
                    "unsafe": ["drop"],
                },
            ),
        ),
    )
    con.execute(
        "INSERT INTO artifact_queue (id, engagement_id, metadata_json) VALUES (?, ?, ?)",
        (8, 99, "{malformed"),
    )

    context = artifact_relation_context_from_queue(
        con,
        99,
        ParsedArtifact(
            artifact_id=7,
            source_url="https://assets.acme.example/config.json",
            artifact_type="json",
            path=Path("config.json"),
            parse_metadata={"parser": "json", "payload_count": 2},
        ),
    )
    malformed_context = artifact_relation_context_from_queue(
        con,
        99,
        ParsedArtifact(
            artifact_id=8,
            source_url="https://assets.acme.example/archive.zip",
            artifact_type="zip",
            path=Path("archive.zip"),
            parse_metadata={"parser": "archive"},
        ),
    )
    missing_context = artifact_relation_context_from_queue(
        con,
        99,
        ParsedArtifact(
            artifact_id=9,
            source_url="https://assets.acme.example/missing.txt",
            artifact_type="text",
            path=Path("missing.txt"),
            parse_metadata={"format": "plain"},
        ),
    )

    assert context == {
        "parser": "json",
        "payload_count": 2,
        "artifact_type": "json",
        "content_type": "application/json",
        "download_filename": "config.json",
        "downloaded_from_remote": True,
        "source_rule": "remote_artifact",
    }
    assert malformed_context == {"parser": "archive", "artifact_type": "zip"}
    assert missing_context == {"format": "plain", "artifact_type": "text"}


def test_merge_artifact_relation_context_overrides_context_and_drops_empty_values() -> None:
    merged = merge_artifact_relation_context(
        {
            "rule": "artifact_s3_uri",
            "source_file": "artifact.txt",
            "empty": "",
            7: "numeric-key",
        },
        {
            "rule": "artifact_text_extract",
            "parser": "json",
            "source_file": "original.txt",
        },
    )

    assert merged == {
        "rule": "artifact_s3_uri",
        "parser": "json",
        "source_file": "artifact.txt",
        "7": "numeric-key",
    }


def test_artifact_cloud_asset_metadata_scrubs_and_preserves_provenance() -> None:
    provenance_calls: list[int] = []

    def _provenance(seed_id: int) -> dict[str, Any]:
        provenance_calls.append(seed_id)
        return {
            "source_url": "https://seed.acme.example/app",
            "root_domain": "acme.example",
            "rule": "seed_rule_should_not_replace_cloud_rule",
        }

    metadata = artifact_cloud_asset_metadata(
        source_seed_id=42,
        relation_metadata={
            "rule": "artifact_s3_uri",
            "source_file": "artifact.txt",
            "relationship_payload_count": "2",
            "ocr_payload_count": "0",
            "archive_sources": [" zip-one ", "", "zip-two"],
            "unsafe": "drop",
        },
        artifact_context={
            "parser": "json",
            "payload_count": 4,
            "source_url": "artifact://queue/9",
        },
        artifact_source_seed_provenance=_provenance,
    )

    assert provenance_calls == [42]
    assert metadata == {
        "artifact_provenance": True,
        "rule": "artifact_cloud_asset_provenance",
        "artifact_source_seed_id": 42,
        "source_url": "artifact://queue/9",
        "root_domain": "acme.example",
        "parser": "json",
        "payload_count": 4,
        "extract_rule": "artifact_s3_uri",
        "source_file": "artifact.txt",
        "relationship_payload_count": "2",
        "archive_sources": ["zip-one", "zip-two"],
    }


def test_local_artifact_source_seed_metadata_filters_context_and_bounds_type() -> None:
    metadata = local_artifact_source_seed_metadata(
        artifact_id=17,
        artifact_type="x" * 80,
        artifact_context={
            "parser": "json",
            "payload_count": 2,
            "downloaded_from_remote": True,
            "ignored": "drop",
            "metadata_payload_count": {"bad": "drop"},
        },
        seed_value="artifact://queue/17",
    )

    assert metadata == {
        "artifact_provenance": True,
        "artifact_source_seed": True,
        "artifact_queue_id": 17,
        "source_url": "artifact://queue/17",
        "artifact_type": "x" * 64,
        "parser": "json",
        "payload_count": 2,
        "downloaded_from_remote": True,
    }


def test_artifact_source_seed_provenance_filters_allowlist_and_normalizes_sources() -> None:
    provenance = artifact_source_seed_provenance(
        {
            "archive_sources": [" one.zip ", "", "two.zip", "one.zip"],
            "provider_sources": "not-a-list",
            "source_url": "https://seed.acme.example/app",
            "payload_count": 3,
            "secret": "drop",
            "root_domain": "",
        }
    )

    assert provenance == {
        "archive_sources": ["one.zip", "two.zip"],
        "source_url": "https://seed.acme.example/app",
        "payload_count": 3,
    }
    assert artifact_source_seed_provenance("not-json") == {}


def test_artifact_seed_metadata_from_evidence_filters_allowlist_and_adds_source_id() -> None:
    metadata = artifact_seed_metadata_from_evidence(
        {
            "provider_sources": [f"provider-{index}" for index in range(10)],
            "source_file": "config.json",
            "extract_rule": "artifact_config",
            "hostname": "api.acme.example",
            "unsafe": "drop",
            "content_type": [],
        },
        source_seed_id=42,
    )

    assert metadata == {
        "artifact_provenance": True,
        "artifact_source_seed_id": 42,
        "provider_sources": [f"provider-{index}" for index in range(8)],
        "source_file": "config.json",
        "extract_rule": "artifact_config",
        "hostname": "api.acme.example",
    }


def test_merge_artifact_seed_metadata_preserves_existing_scalars_and_merges_sources() -> None:
    existing = {
        "source_url": "https://existing.example",
        "archive_sources": [" one.zip ", "two.zip"],
        "provider_sources": [f"existing-{index}" for index in range(9)],
        "empty": "",
    }
    incoming = {
        "source_url": "https://incoming.example",
        "archive_sources": ["two.zip", "three.zip"],
        "provider_sources": ["incoming"],
        "empty": "filled",
        "new_key": True,
    }

    assert merge_artifact_seed_metadata(existing, incoming) == {
        "source_url": "https://existing.example",
        "archive_sources": ["one.zip", "two.zip", "three.zip"],
        "provider_sources": [f"existing-{index}" for index in range(9)] + ["incoming"],
        "empty": "filled",
        "new_key": True,
    }


def test_merge_artifact_metadata_into_seed_updates_existing_seed_metadata() -> None:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute(
        """
        CREATE TABLE engagement_seeds (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER NOT NULL,
            seed_value TEXT NOT NULL,
            seed_type TEXT NOT NULL,
            metadata_json TEXT DEFAULT '{}',
            updated_at TEXT,
            UNIQUE(engagement_id, seed_type, seed_value)
        )
        """,
    )
    con.execute(
        """
        INSERT INTO engagement_seeds
            (id, engagement_id, seed_value, seed_type, metadata_json)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            20,
            1001,
            "owner",
            "username",
            json.dumps(
                {
                    "source_url": "https://existing.example/profile",
                    "archive_sources": ["existing.zip"],
                },
                sort_keys=True,
            ),
        ),
    )

    merge_artifact_metadata_into_seed(
        con,
        1001,
        "owner",
        "username",
        {
            "source_url": "https://new.example/profile",
            "archive_sources": ["existing.zip", "artifact.zip"],
            "provider_sources": ["artifact"],
            "empty": "",
            "new_key": True,
        },
    )
    merge_artifact_metadata_into_seed(
        con,
        1001,
        "missing",
        "username",
        {"new_key": "ignored"},
    )

    row = con.execute(
        """
        SELECT metadata_json, updated_at
        FROM engagement_seeds
        WHERE id=20
        """
    ).fetchone()

    assert row is not None
    assert json.loads(str(row["metadata_json"])) == {
        "archive_sources": ["existing.zip", "artifact.zip"],
        "artifact_provenance": True,
        "new_key": True,
        "provider_sources": ["artifact"],
        "source_url": "https://existing.example/profile",
    }
    assert row["updated_at"] is not None


def test_store_social_profile_url_pivots_inserts_seeds_and_relations() -> None:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute(
        """
        CREATE TABLE engagement_seeds (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER NOT NULL,
            seed_value TEXT NOT NULL,
            seed_type TEXT NOT NULL,
            source TEXT,
            status TEXT,
            depth INTEGER,
            confidence REAL,
            metadata_json TEXT DEFAULT '{}',
            updated_at TEXT,
            UNIQUE(engagement_id, seed_type, seed_value)
        )
        """,
    )
    con.execute(
        """
        CREATE TABLE seed_relations (
            engagement_id INTEGER NOT NULL,
            source_seed_id INTEGER NOT NULL,
            target_seed_id INTEGER NOT NULL,
            relation_type TEXT NOT NULL,
            confidence REAL,
            evidence_json TEXT DEFAULT '{}'
        )
        """,
    )
    con.execute(
        """
        INSERT INTO engagement_seeds
            (id, engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
        VALUES (?, ?, ?, ?, 'artifact', 'completed', 0, 0.9, '{}')
        """,
        (10, 1001, "https://bsky.app/profile/owner", "url"),
    )

    def _lookup_seed_id(inner_con: sqlite3.Connection, value: str, value_type: str) -> int | None:
        return lookup_artifact_seed_id(inner_con, 1001, value, value_type)

    def _insert_seed(
        inner_con: sqlite3.Connection,
        value: str,
        value_type: str,
        **kwargs: Any,
    ) -> bool:
        return insert_artifact_seed(inner_con, 1001, value, value_type, **kwargs)

    def _insert_relation(
        inner_con: sqlite3.Connection,
        source_id: int,
        target_id: int,
        relation_type: str,
        confidence: float,
        metadata: dict[str, Any],
    ) -> None:
        insert_artifact_seed_relation(
            inner_con,
            1001,
            source_id,
            target_id,
            relation_type,
            confidence,
            metadata,
        )

    store_social_profile_url_pivots(
        con,
        1001,
        "https://bsky.app/profile/owner",
        seed_type="url",
        pivot_entries=[
            {
                "seed_value": "owner",
                "seed_type": "username",
                "seed_confidence": 0.78,
                "relation_type": "derived_from",
                "relation_confidence": 0.78,
                "relation_metadata": {
                    "rule": "artifact_social_url_extract",
                    "platform": "bluesky",
                },
            },
            {
                "seed_value": "https://bsky.app/profile/owner",
                "seed_type": "url",
                "seed_confidence": 0.5,
                "relation_type": "derived_from",
                "relation_confidence": 0.5,
                "relation_metadata": {"rule": "self"},
            },
        ],
        depth=4,
        run_ordered_batch=_run_ordered_batch,
        social_profile_url_pivot_entry=artifact_social_profile_url_pivot_entry,
        lookup_seed_id=_lookup_seed_id,
        insert_seed=_insert_seed,
        insert_relation=_insert_relation,
    )
    store_social_profile_url_pivots(
        con,
        1001,
        "https://bsky.app/profile/missing",
        seed_type="url",
        pivot_entries=[
            {
                "seed_value": "missing",
                "seed_type": "username",
                "seed_confidence": 0.78,
                "relation_type": "derived_from",
                "relation_confidence": 0.78,
                "relation_metadata": {"rule": "missing"},
            },
        ],
        depth=4,
        run_ordered_batch=_run_ordered_batch,
        social_profile_url_pivot_entry=artifact_social_profile_url_pivot_entry,
        lookup_seed_id=_lookup_seed_id,
        insert_seed=_insert_seed,
        insert_relation=_insert_relation,
    )

    seed_rows = con.execute(
        """
        SELECT seed_value, seed_type, source, status, depth, confidence
        FROM engagement_seeds
        ORDER BY id
        """
    ).fetchall()
    relation_rows = con.execute(
        """
        SELECT source_seed_id, target_seed_id, relation_type, confidence, evidence_json
        FROM seed_relations
        ORDER BY source_seed_id, target_seed_id
        """
    ).fetchall()

    assert [dict(row) for row in seed_rows] == [
        {
            "seed_value": "https://bsky.app/profile/owner",
            "seed_type": "url",
            "source": "artifact",
            "status": "pending",
            "depth": 0,
            "confidence": 0.9,
        },
        {
            "seed_value": "owner",
            "seed_type": "username",
            "source": "artifact",
            "status": "pending",
            "depth": 4,
            "confidence": 0.78,
        },
    ]
    assert len(relation_rows) == 1
    assert dict(relation_rows[0]) | {
        "evidence_json": json.loads(str(relation_rows[0]["evidence_json"])),
    } == {
        "source_seed_id": 10,
        "target_seed_id": 11,
        "relation_type": "derived_from",
        "confidence": 0.78,
        "evidence_json": {
            "platform": "bluesky",
            "rule": "artifact_social_url_extract",
        },
    }


def test_store_cloud_assets_from_url_entries_normalizes_and_stores_metadata() -> None:
    con = sqlite3.connect(":memory:")
    metadata_calls: list[dict[str, Any]] = []
    store_calls: list[dict[str, Any]] = []

    def _artifact_cloud_asset_metadata(
        inner_con: sqlite3.Connection,
        *,
        source_seed_id: int | None,
        relation_metadata: dict[str, Any] | None,
        artifact_context: dict[str, Any] | None,
    ) -> dict[str, Any]:
        assert inner_con is con
        metadata_calls.append(
            {
                "source_seed_id": source_seed_id,
                "relation_metadata": dict(relation_metadata or {}),
                "artifact_context": artifact_context,
            }
        )
        return {
            "artifact_provenance": True,
            "artifact_source_seed_id": source_seed_id,
            "extract_rule": str((relation_metadata or {}).get("rule") or ""),
        }

    def _store_cloud_asset_reference(
        inner_con: sqlite3.Connection,
        *,
        asset_type: str,
        identifier: str,
        source: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        assert inner_con is con
        store_calls.append(
            {
                "asset_type": asset_type,
                "identifier": identifier,
                "source": source,
                "metadata": dict(metadata or {}),
            }
        )

    store_cloud_assets_from_url_entries(
        con,
        source_seed_id=55,
        relation_metadata={"rule": "artifact_text_extract"},
        cloud_asset_entries=[
            {"asset_type": "aws_s3", "identifier": "ops-bucket", "source": "artifact_url_extract"},
            {"asset_type": "", "identifier": "drop-me", "source": "artifact_url_extract"},
            {"asset_type": "gcs", "identifier": "mirror-bucket", "source": "artifact_url_extract"},
        ],
        run_ordered_batch=_run_ordered_batch,
        cloud_asset_url_entry=artifact_cloud_asset_url_entry,
        artifact_cloud_asset_metadata=_artifact_cloud_asset_metadata,
        store_cloud_asset_reference=_store_cloud_asset_reference,
    )

    assert metadata_calls == [
        {
            "source_seed_id": 55,
            "relation_metadata": {"rule": "artifact_text_extract"},
            "artifact_context": None,
        },
        {
            "source_seed_id": 55,
            "relation_metadata": {"rule": "artifact_text_extract"},
            "artifact_context": None,
        },
    ]
    assert store_calls == [
        {
            "asset_type": "aws_s3",
            "identifier": "ops-bucket",
            "source": "artifact_url_extract",
            "metadata": {
                "artifact_provenance": True,
                "artifact_source_seed_id": 55,
                "extract_rule": "artifact_text_extract",
            },
        },
        {
            "asset_type": "gcs",
            "identifier": "mirror-bucket",
            "source": "artifact_url_extract",
            "metadata": {
                "artifact_provenance": True,
                "artifact_source_seed_id": 55,
                "extract_rule": "artifact_text_extract",
            },
        },
    ]


def test_store_artifact_url_seed_coordinates_related_persistence_callbacks() -> None:
    con = sqlite3.connect(":memory:")
    insert_calls: list[dict[str, Any]] = []
    link_calls: list[dict[str, Any]] = []
    pivot_calls: list[dict[str, Any]] = []
    cloud_calls: list[dict[str, Any]] = []
    queue_calls: list[dict[str, Any]] = []

    def _entry(
        candidate_url: str,
        *,
        relation_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        if candidate_url == "skip":
            return None
        assert relation_metadata == {"rule": "artifact_text_extract", "source_file": "artifact.txt"}
        return {
            "url": candidate_url,
            "seed_type": "url",
            "relation_metadata": dict(relation_metadata or {}),
            "social_pivot_entries": [{"seed_value": "owner", "seed_type": "username"}],
            "related_seed_entries": [
                {"seed_value": "portal.example.com", "seed_type": "subdomain", "confidence": 0.62},
                "drop",
                {"seed_value": "example.com", "seed_type": "domain", "confidence": 0.59},
            ],
            "cloud_asset_entries": [
                {"asset_type": "aws_s3", "identifier": "ops-bucket", "source": "artifact_url_extract"}
            ],
        }

    def _insert_seed(
        inner_con: sqlite3.Connection,
        seed_value: str,
        seed_type: str,
        *,
        source: str,
        confidence: float,
        depth: int = 1,
    ) -> bool:
        assert inner_con is con
        insert_calls.append(
            {
                "seed_value": seed_value,
                "seed_type": seed_type,
                "source": source,
                "confidence": confidence,
                "depth": depth,
            }
        )
        return seed_value != "example.com"

    def _link_artifact_source_seed(
        inner_con: sqlite3.Connection,
        source_seed_id: int | None,
        seed_value: str,
        seed_type: str,
        *,
        confidence: float,
        metadata: dict[str, Any],
    ) -> None:
        assert inner_con is con
        link_calls.append(
            {
                "source_seed_id": source_seed_id,
                "seed_value": seed_value,
                "seed_type": seed_type,
                "confidence": confidence,
                "metadata": dict(metadata),
            }
        )

    def _store_social_profile_url_pivots(
        inner_con: sqlite3.Connection,
        url: str,
        *,
        seed_type: str,
        relation_metadata: dict[str, Any],
        pivot_entries: list[dict[str, Any]],
        depth: int = 1,
    ) -> None:
        assert inner_con is con
        pivot_calls.append(
            {
                "url": url,
                "seed_type": seed_type,
                "relation_metadata": dict(relation_metadata),
                "pivot_entries": list(pivot_entries),
                "depth": depth,
            }
        )

    def _store_cloud_asset_from_url(
        inner_con: sqlite3.Connection,
        url: str,
        *,
        source: str,
        cloud_asset_entries: list[dict[str, Any]],
        source_seed_id: int | None,
        relation_metadata: dict[str, Any],
    ) -> None:
        assert inner_con is con
        cloud_calls.append(
            {
                "url": url,
                "source": source,
                "cloud_asset_entries": list(cloud_asset_entries),
                "source_seed_id": source_seed_id,
                "relation_metadata": dict(relation_metadata),
            }
        )

    def _queue_artifact_text_discovered_url(
        inner_con: sqlite3.Connection,
        url: str,
        *,
        seed_type: str,
        relation_metadata: dict[str, Any],
    ) -> int:
        assert inner_con is con
        queue_calls.append(
            {
                "url": url,
                "seed_type": seed_type,
                "relation_metadata": dict(relation_metadata),
            }
        )
        return 1

    skipped = store_artifact_url_seed(
        con,
        "skip",
        source="artifact",
        confidence=0.68,
        source_seed_id=55,
        depth=3,
        relation_metadata={"rule": "artifact_text_extract", "source_file": "artifact.txt"},
        artifact_url_seed_persistence_entry=_entry,
        insert_seed=_insert_seed,
        link_artifact_source_seed=_link_artifact_source_seed,
        store_social_profile_url_pivots=_store_social_profile_url_pivots,
        store_cloud_asset_from_url=_store_cloud_asset_from_url,
        queue_artifact_text_discovered_url=_queue_artifact_text_discovered_url,
    )
    inserted = store_artifact_url_seed(
        con,
        "https://portal.example.com/app",
        source="artifact",
        confidence=0.68,
        source_seed_id=55,
        depth=3,
        relation_metadata={"rule": "artifact_text_extract", "source_file": "artifact.txt"},
        artifact_url_seed_persistence_entry=_entry,
        insert_seed=_insert_seed,
        link_artifact_source_seed=_link_artifact_source_seed,
        store_social_profile_url_pivots=_store_social_profile_url_pivots,
        store_cloud_asset_from_url=_store_cloud_asset_from_url,
        queue_artifact_text_discovered_url=_queue_artifact_text_discovered_url,
    )

    relation_metadata = {"rule": "artifact_text_extract", "source_file": "artifact.txt"}
    assert skipped == 0
    assert inserted == 2
    assert insert_calls == [
        {
            "seed_value": "https://portal.example.com/app",
            "seed_type": "url",
            "source": "artifact",
            "confidence": 0.68,
            "depth": 3,
        },
        {
            "seed_value": "portal.example.com",
            "seed_type": "subdomain",
            "source": "artifact",
            "confidence": 0.62,
            "depth": 3,
        },
        {
            "seed_value": "example.com",
            "seed_type": "domain",
            "source": "artifact",
            "confidence": 0.59,
            "depth": 3,
        },
    ]
    assert link_calls == [
        {
            "source_seed_id": 55,
            "seed_value": "https://portal.example.com/app",
            "seed_type": "url",
            "confidence": 0.68,
            "metadata": relation_metadata,
        },
        {
            "source_seed_id": 55,
            "seed_value": "portal.example.com",
            "seed_type": "subdomain",
            "confidence": 0.62,
            "metadata": relation_metadata,
        },
        {
            "source_seed_id": 55,
            "seed_value": "example.com",
            "seed_type": "domain",
            "confidence": 0.59,
            "metadata": relation_metadata,
        },
    ]
    assert pivot_calls == [
        {
            "url": "https://portal.example.com/app",
            "seed_type": "url",
            "relation_metadata": relation_metadata,
            "pivot_entries": [{"seed_value": "owner", "seed_type": "username"}],
            "depth": 4,
        }
    ]
    assert cloud_calls == [
        {
            "url": "https://portal.example.com/app",
            "source": "artifact_url_extract",
            "cloud_asset_entries": [
                {"asset_type": "aws_s3", "identifier": "ops-bucket", "source": "artifact_url_extract"}
            ],
            "source_seed_id": 55,
            "relation_metadata": relation_metadata,
        }
    ]
    assert queue_calls == [
        {
            "url": "https://portal.example.com/app",
            "seed_type": "url",
            "relation_metadata": relation_metadata,
        }
    ]


def test_persist_generic_text_discovery_batch_coordinates_persistence_callbacks() -> None:
    con = sqlite3.connect(":memory:")
    batch = ArtifactTextDiscoveryBatch(
        source_file="artifact.txt",
        emails=["Owner@ACME.EXAMPLE"],
        phones=["+15550100"],
        ip_seeds=[("192.0.2.10", "ip")],
        host_seeds=[("portal.example.com", "subdomain")],
        urls=["https://portal.example.com/app"],
        identity_seeds=[("Acme Labs", "company", "ORG", "")],
        key_findings=[{"service": "slack"}],
        cloud_assets=[("aws_s3", "ops-bucket", "artifact_s3_uri")],
    )
    artifact_context = {"parser": "json", "payload_count": 2}
    child_depth_calls: list[int | None] = []
    insert_email_calls: list[dict[str, Any]] = []
    insert_seed_calls: list[dict[str, Any]] = []
    link_calls: list[dict[str, Any]] = []
    store_url_calls: list[dict[str, Any]] = []
    metadata_merge_calls: list[dict[str, Any]] = []
    key_calls: list[dict[str, Any]] = []
    cloud_metadata_calls: list[dict[str, Any]] = []
    cloud_calls: list[dict[str, Any]] = []

    def _child_depth(inner_con: sqlite3.Connection, source_seed_id: int | None) -> int:
        assert inner_con is con
        child_depth_calls.append(source_seed_id)
        return 4

    def _email_entry(email: str, *, source_file: str) -> dict[str, Any]:
        return {
            "email": email.lower(),
            "metadata": {"rule": "artifact_email", "source_file": source_file},
        }

    def _phone_entry(phone: str, *, source_file: str) -> dict[str, Any]:
        return {
            "phone": phone,
            "metadata": {"rule": "artifact_phone", "source_file": source_file},
        }

    def _ip_entry(ip_seed: tuple[str, str], *, source_file: str) -> dict[str, Any]:
        value, seed_type = ip_seed
        return {
            "ip_value": value,
            "ip_seed_type": seed_type,
            "metadata": {"rule": "artifact_ip", "source_file": source_file},
        }

    def _host_entry(host_seed: tuple[str, str], *, source_file: str) -> dict[str, Any]:
        value, seed_type = host_seed
        return {
            "host_value": value,
            "host_seed_type": seed_type,
            "confidence": 0.65,
            "metadata": {"rule": "artifact_host", "source_file": source_file},
        }

    def _url_entry(url: str, *, source_file: str) -> dict[str, Any]:
        return {
            "url": url,
            "relation_metadata": {"rule": "artifact_url", "source_file": source_file},
        }

    def _identity_entry(
        identity_seed: tuple[str, str, str, str],
        *,
        source_file: str,
    ) -> dict[str, Any]:
        value, seed_type, label, _context = identity_seed
        return {
            "seed_value": value,
            "seed_type": seed_type,
            "confidence": 0.76,
            "metadata": {
                "rule": "artifact_identity",
                "source_file": source_file,
                "identity_label": label,
            },
        }

    def _key_entry(_finding: dict[str, object]) -> dict[str, Any]:
        return {
            "service": "slack",
            "domain": "acme.example",
            "source_url": "artifact.txt",
            "pattern_name": "slack_token",
            "key_redacted": "xoxb-...",
            "key_enc": None,
            "source_backend": "artifact_queue_ingest",
            "repo_name": "",
            "validation_detail": "",
        }

    def _cloud_entry(cloud_asset: tuple[str, str, str], *, source_file: str) -> dict[str, Any]:
        asset_type, identifier, source = cloud_asset
        return {
            "asset_type": asset_type,
            "identifier": identifier,
            "source": source,
            "relation_metadata": {"rule": source, "source_file": source_file},
        }

    def _insert_email(
        inner_con: sqlite3.Connection,
        email: str,
        *,
        source: str,
        depth: int,
    ) -> bool:
        assert inner_con is con
        insert_email_calls.append({"email": email, "source": source, "depth": depth})
        return True

    def _insert_seed(
        inner_con: sqlite3.Connection,
        seed_value: str,
        seed_type: str,
        *,
        source: str,
        confidence: float,
        depth: int,
    ) -> bool:
        assert inner_con is con
        insert_seed_calls.append(
            {
                "seed_value": seed_value,
                "seed_type": seed_type,
                "source": source,
                "confidence": confidence,
                "depth": depth,
            }
        )
        return True

    def _link_seed(
        inner_con: sqlite3.Connection,
        source_seed_id: int | None,
        seed_value: str,
        seed_type: str,
        *,
        confidence: float,
        metadata: dict[str, Any],
    ) -> None:
        assert inner_con is con
        link_calls.append(
            {
                "source_seed_id": source_seed_id,
                "seed_value": seed_value,
                "seed_type": seed_type,
                "confidence": confidence,
                "metadata": dict(metadata),
            }
        )

    def _store_url(
        inner_con: sqlite3.Connection,
        url: str,
        *,
        source: str,
        confidence: float,
        source_seed_id: int | None,
        depth: int,
        relation_metadata: dict[str, Any],
    ) -> int:
        assert inner_con is con
        store_url_calls.append(
            {
                "url": url,
                "source": source,
                "confidence": confidence,
                "source_seed_id": source_seed_id,
                "depth": depth,
                "relation_metadata": dict(relation_metadata),
            }
        )
        return 2

    def _merge_metadata(
        inner_con: sqlite3.Connection,
        seed_value: str,
        seed_type: str,
        metadata: dict[str, Any],
    ) -> None:
        assert inner_con is con
        metadata_merge_calls.append(
            {
                "seed_value": seed_value,
                "seed_type": seed_type,
                "metadata": dict(metadata),
            }
        )

    def _store_key(inner_con: sqlite3.Connection, **kwargs: Any) -> None:
        assert inner_con is con
        key_calls.append(dict(kwargs))

    def _cloud_metadata(inner_con: sqlite3.Connection, **kwargs: Any) -> dict[str, Any]:
        assert inner_con is con
        cloud_metadata_calls.append(dict(kwargs))
        return {"artifact_provenance": True, "source_seed_id": kwargs["source_seed_id"]}

    def _store_cloud(inner_con: sqlite3.Connection, **kwargs: Any) -> None:
        assert inner_con is con
        cloud_calls.append(dict(kwargs))

    inserted = persist_generic_text_discovery_batch(
        con,
        batch,
        source_seed_id=55,
        artifact_context=artifact_context,
        artifact_child_seed_depth=_child_depth,
        run_ordered_batch=_run_ordered_batch,
        artifact_text_email_persistence_entry=_email_entry,
        artifact_text_phone_persistence_entry=_phone_entry,
        artifact_text_ip_persistence_entry=_ip_entry,
        artifact_text_host_persistence_entry=_host_entry,
        artifact_text_url_persistence_entry=_url_entry,
        artifact_text_identity_seed_persistence_entry=_identity_entry,
        artifact_text_key_finding_persistence_entry=_key_entry,
        artifact_text_cloud_asset_persistence_entry=_cloud_entry,
        insert_email=_insert_email,
        insert_seed=_insert_seed,
        link_artifact_source_seed=_link_seed,
        store_artifact_url_seed=_store_url,
        merge_artifact_relation_context_fn=merge_artifact_relation_context,
        merge_artifact_metadata_into_seed=_merge_metadata,
        store_key_finding=_store_key,
        artifact_cloud_asset_metadata=_cloud_metadata,
        store_cloud_asset_reference=_store_cloud,
    )

    assert child_depth_calls == [55]
    assert inserted == 7
    assert insert_email_calls == [{"email": "owner@acme.example", "source": "artifact", "depth": 4}]
    assert [call["seed_type"] for call in insert_seed_calls] == [
        "phone",
        "ip",
        "subdomain",
        "company",
    ]
    assert len(link_calls) == 5
    assert link_calls[0]["metadata"] == {
        "parser": "json",
        "payload_count": 2,
        "rule": "artifact_email",
        "source_file": "artifact.txt",
    }
    assert store_url_calls == [
        {
            "url": "https://portal.example.com/app",
            "source": "artifact",
            "confidence": 0.68,
            "source_seed_id": 55,
            "depth": 4,
            "relation_metadata": {
                "parser": "json",
                "payload_count": 2,
                "rule": "artifact_url",
                "source_file": "artifact.txt",
            },
        }
    ]
    assert metadata_merge_calls == [
        {
            "seed_value": "Acme Labs",
            "seed_type": "company",
            "metadata": {
                "parser": "json",
                "payload_count": 2,
                "rule": "artifact_identity",
                "source_file": "artifact.txt",
                "identity_label": "ORG",
            },
        }
    ]
    assert key_calls == [
        {
            "service": "slack",
            "domain": "acme.example",
            "source_url": "artifact.txt",
            "pattern_name": "slack_token",
            "key_redacted": "xoxb-...",
            "key_enc": None,
            "source_backend": "artifact_queue_ingest",
            "repo_name": "",
            "validation_detail": "artifact_queue_ingest",
        }
    ]
    assert cloud_metadata_calls == [
        {
            "source_seed_id": 55,
            "relation_metadata": {"rule": "artifact_s3_uri", "source_file": "artifact.txt"},
            "artifact_context": artifact_context,
        }
    ]
    assert cloud_calls == [
        {
            "asset_type": "aws_s3",
            "identifier": "ops-bucket",
            "source": "artifact_s3_uri",
            "metadata": {"artifact_provenance": True, "source_seed_id": 55},
        }
    ]


def test_persist_parsed_artifact_coordinates_discovery_and_mobile_config_callbacks() -> None:
    con = sqlite3.connect(":memory:")
    parsed = ParsedArtifact(
        artifact_id=7,
        source_url="artifact://queue/7",
        artifact_type="json",
        path=Path("config.json"),
        payloads=[("config.json", "config", "payload")],
        firebase_projects=["firebase-one", "firebase-one"],
        supabase_configs=["supabase-one", "supabase-one"],
        parse_metadata={"parser": "json", "payload_count": 1},
    )
    calls: list[tuple[str, Any]] = []
    artifact_context = {"artifact_type": "json", "parser": "json"}

    def _artifact_relation_context(
        inner_con: sqlite3.Connection,
        parsed_artifact: ParsedArtifact,
    ) -> dict[str, Any]:
        assert inner_con is con
        assert parsed_artifact is parsed
        calls.append(("context", parsed_artifact.artifact_id))
        return artifact_context

    def _artifact_source_seed_id(inner_con: sqlite3.Connection, source_url: str) -> int | None:
        assert inner_con is con
        calls.append(("source_seed_lookup", source_url))
        return None

    def _ensure_local_artifact_source_seed(
        inner_con: sqlite3.Connection,
        parsed_artifact: ParsedArtifact,
        *,
        artifact_context: dict[str, Any],
    ) -> int:
        assert inner_con is con
        assert parsed_artifact is parsed
        calls.append(("ensure_local_source_seed", dict(artifact_context)))
        return 55

    def _artifact_discovery_payloads(parsed_artifact: ParsedArtifact) -> list[tuple[str, str, str]]:
        assert parsed_artifact is parsed
        calls.append(("payloads", parsed_artifact.payloads))
        return [("config.json", "config", "payload")]

    def _expand_structured_discovery_jobs(
        payloads: list[tuple[str, str, str]],
    ) -> list[tuple[str, str, str]]:
        calls.append(("expand", list(payloads)))
        return [("config.json", "config/json", "payload")]

    def _collect_generic_text_discovery_batches(
        discovery_jobs: list[tuple[str, str, str]],
    ) -> list[ArtifactTextDiscoveryBatch]:
        calls.append(("collect", list(discovery_jobs)))
        return [
            ArtifactTextDiscoveryBatch(source_file="config.json"),
            ArtifactTextDiscoveryBatch(source_file="config/json"),
        ]

    def _persist_generic_text_discovery_batch(
        inner_con: sqlite3.Connection,
        batch: ArtifactTextDiscoveryBatch,
        *,
        source_seed_id: int | None,
        artifact_context: dict[str, Any],
    ) -> int:
        assert inner_con is con
        calls.append(("persist_batch", batch.source_file, source_seed_id, dict(artifact_context)))
        return 2 if batch.source_file == "config.json" else 3

    def _dedupe_firebase_projects(projects: list[Any]) -> list[Any]:
        calls.append(("dedupe_firebase", list(projects)))
        return ["firebase-one"]

    def _store_firebase_projects(
        inner_con: sqlite3.Connection,
        projects: list[Any],
        *,
        source_seed_id: int | None,
        source_url: str,
        artifact_context: dict[str, Any],
    ) -> tuple[int, int]:
        assert inner_con is con
        calls.append(
            (
                "store_firebase",
                list(projects),
                source_seed_id,
                source_url,
                dict(artifact_context),
            )
        )
        return 1, 2

    def _dedupe_supabase_configs(configs: list[Any]) -> list[Any]:
        calls.append(("dedupe_supabase", list(configs)))
        return ["supabase-one"]

    def _store_supabase_configs(
        inner_con: sqlite3.Connection,
        configs: list[Any],
        *,
        source_seed_id: int | None,
        source_url: str,
        artifact_context: dict[str, Any],
    ) -> tuple[int, int]:
        assert inner_con is con
        calls.append(
            (
                "store_supabase",
                list(configs),
                source_seed_id,
                source_url,
                dict(artifact_context),
            )
        )
        return 1, 4

    result = persist_parsed_artifact(
        con,
        parsed,
        artifact_relation_context=_artifact_relation_context,
        artifact_source_seed_id=_artifact_source_seed_id,
        ensure_local_artifact_source_seed=_ensure_local_artifact_source_seed,
        artifact_discovery_payloads=_artifact_discovery_payloads,
        expand_structured_discovery_jobs=_expand_structured_discovery_jobs,
        collect_generic_text_discovery_batches=_collect_generic_text_discovery_batches,
        persist_generic_text_discovery_batch=_persist_generic_text_discovery_batch,
        dedupe_firebase_projects=_dedupe_firebase_projects,
        store_firebase_projects=_store_firebase_projects,
        dedupe_supabase_configs=_dedupe_supabase_configs,
        store_supabase_configs=_store_supabase_configs,
    )

    assert result == (1, 1, 12, {"parser": "json", "payload_count": 1})
    assert calls == [
        ("context", 7),
        ("source_seed_lookup", "artifact://queue/7"),
        ("ensure_local_source_seed", artifact_context),
        ("payloads", [("config.json", "config", "payload")]),
        ("expand", [("config.json", "config", "payload")]),
        ("collect", [("config.json", "config/json", "payload")]),
        ("persist_batch", "config.json", 55, artifact_context),
        ("persist_batch", "config/json", 55, artifact_context),
        ("dedupe_firebase", ["firebase-one", "firebase-one"]),
        ("store_firebase", ["firebase-one"], 55, "artifact://queue/7", artifact_context),
        ("dedupe_supabase", ["supabase-one", "supabase-one"]),
        ("store_supabase", ["supabase-one"], 55, "artifact://queue/7", artifact_context),
    ]


def test_store_firebase_projects_coordinates_cloud_seed_url_and_key_callbacks() -> None:
    con = sqlite3.connect(":memory:")
    artifact_context = {"parser": "json", "payload_count": 1}
    child_depth_calls: list[int | None] = []
    cloud_metadata_calls: list[dict[str, Any]] = []
    cloud_calls: list[dict[str, Any]] = []
    insert_calls: list[dict[str, Any]] = []
    link_calls: list[dict[str, Any]] = []
    url_calls: list[dict[str, Any]] = []
    key_calls: list[dict[str, Any]] = []

    project_entry = {
        "project_id": "acme-prod",
        "source_file": "app/google-services.json",
        "storage_bucket": "acme-prod.appspot.com",
        "storage_bucket_url": "https://storage.googleapis.com/acme-prod.appspot.com",
        "rtdb_url": "https://acme-prod.firebaseio.com",
        "api_key_enc": "encrypted-key",
        "project_relation_metadata": {
            "rule": "artifact_mobile_config",
            "source_file": "app/google-services.json",
        },
        "storage_relation_metadata": {
            "rule": "firebase_storage_bucket",
            "source_file": "app/google-services.json",
        },
    }

    def _child_depth(inner_con: sqlite3.Connection, source_seed_id: int | None) -> int:
        assert inner_con is con
        child_depth_calls.append(source_seed_id)
        return 4

    def _entry(project: Any, *, source_url: str) -> dict[str, Any] | None:
        assert project == "firebase-one"
        assert source_url == "artifact://queue/7"
        return dict(project_entry)

    def _cloud_metadata(inner_con: sqlite3.Connection, **kwargs: Any) -> dict[str, Any]:
        assert inner_con is con
        cloud_metadata_calls.append(dict(kwargs))
        return {"metadata_index": len(cloud_metadata_calls)}

    def _store_cloud(inner_con: sqlite3.Connection, **kwargs: Any) -> None:
        assert inner_con is con
        cloud_calls.append(dict(kwargs))

    def _insert_seed(
        inner_con: sqlite3.Connection,
        seed_value: str,
        seed_type: str,
        *,
        source: str,
        confidence: float,
        depth: int,
    ) -> bool:
        assert inner_con is con
        insert_calls.append(
            {
                "seed_value": seed_value,
                "seed_type": seed_type,
                "source": source,
                "confidence": confidence,
                "depth": depth,
            }
        )
        return True

    def _link_seed(
        inner_con: sqlite3.Connection,
        source_seed_id: int | None,
        seed_value: str,
        seed_type: str,
        *,
        confidence: float,
        metadata: dict[str, Any],
    ) -> None:
        assert inner_con is con
        link_calls.append(
            {
                "source_seed_id": source_seed_id,
                "seed_value": seed_value,
                "seed_type": seed_type,
                "confidence": confidence,
                "metadata": dict(metadata),
            }
        )

    def _store_url(
        inner_con: sqlite3.Connection,
        url: str,
        *,
        source: str,
        confidence: float,
        source_seed_id: int | None,
        depth: int,
        relation_metadata: dict[str, Any],
    ) -> int:
        assert inner_con is con
        url_calls.append(
            {
                "url": url,
                "source": source,
                "confidence": confidence,
                "source_seed_id": source_seed_id,
                "depth": depth,
                "relation_metadata": dict(relation_metadata),
            }
        )
        return 2 if "storage.googleapis.com" in url else 0

    def _store_key(inner_con: sqlite3.Connection, **kwargs: Any) -> None:
        assert inner_con is con
        key_calls.append(dict(kwargs))

    result = store_firebase_projects(
        con,
        ["firebase-one"],
        source_seed_id=55,
        source_url="artifact://queue/7",
        artifact_context=artifact_context,
        artifact_child_seed_depth=_child_depth,
        run_ordered_batch=_run_ordered_batch,
        firebase_project_persistence_entry=_entry,
        store_cloud_asset_reference=_store_cloud,
        artifact_cloud_asset_metadata=_cloud_metadata,
        insert_seed=_insert_seed,
        link_artifact_source_seed=_link_seed,
        merge_artifact_relation_context_fn=merge_artifact_relation_context,
        store_artifact_url_seed=_store_url,
        store_key_finding=_store_key,
    )

    assert result == (1, 1)
    assert child_depth_calls == [55]
    assert cloud_metadata_calls == [
        {
            "source_seed_id": 55,
            "relation_metadata": project_entry["project_relation_metadata"],
            "artifact_context": artifact_context,
        },
        {
            "source_seed_id": 55,
            "relation_metadata": project_entry["storage_relation_metadata"],
            "artifact_context": artifact_context,
        },
    ]
    assert cloud_calls == [
        {
            "asset_type": "firebase",
            "identifier": "acme-prod",
            "source": "firebase_extract",
            "metadata": {"metadata_index": 1},
        },
        {
            "asset_type": "gcs",
            "identifier": "acme-prod.appspot.com",
            "source": "firebase_extract_storage_bucket",
            "metadata": {"metadata_index": 2},
        },
    ]
    assert insert_calls == [
        {
            "seed_value": "acme-prod",
            "seed_type": "other",
            "source": "artifact",
            "confidence": 0.8,
            "depth": 4,
        }
    ]
    assert link_calls == [
        {
            "source_seed_id": 55,
            "seed_value": "acme-prod",
            "seed_type": "other",
            "confidence": 0.8,
            "metadata": {
                "parser": "json",
                "payload_count": 1,
                "rule": "artifact_mobile_config",
                "source_file": "app/google-services.json",
            },
        }
    ]
    assert url_calls == [
        {
            "url": "https://storage.googleapis.com/acme-prod.appspot.com",
            "source": "artifact",
            "confidence": 0.7,
            "source_seed_id": 55,
            "depth": 4,
            "relation_metadata": {
                "parser": "json",
                "payload_count": 1,
                "rule": "firebase_storage_bucket",
                "source_file": "app/google-services.json",
            },
        },
        {
            "url": "https://acme-prod.firebaseio.com",
            "source": "artifact",
            "confidence": 0.72,
            "source_seed_id": 55,
            "depth": 4,
            "relation_metadata": {
                "parser": "json",
                "payload_count": 1,
                "rule": "artifact_mobile_config",
                "source_file": "app/google-services.json",
            },
        },
    ]
    assert key_calls == [
        {
            "service": "firebase",
            "domain": "acme-prod",
            "source_url": "app/google-services.json",
            "pattern_name": "firebase_mobile_config",
            "key_redacted": "<age-encrypted>",
            "key_enc": "encrypted-key",
        }
    ]


def test_payload_cloud_config_job_filters_blank_payloads_and_normalizes_fields() -> None:
    assert payload_cloud_config_job(("app.apk", "assets/config.json", "  ")) is None
    assert payload_cloud_config_job((123, 456, "payload")) == (
        "123",
        "456",
        "payload",
    )


def test_payload_cloud_config_result_entry_copies_projects_and_configs() -> None:
    projects = ["firebase-one"]
    configs = ["supabase-one"]

    result = payload_cloud_config_result_entry((2, (projects, configs)))

    assert result == (["firebase-one"], ["supabase-one"])
    assert result is not None
    assert result[0] is not projects
    assert result[1] is not configs
    assert payload_cloud_config_result_entry((3, None)) is None


def test_extract_cloud_configs_from_payload_dispatches_families_in_order() -> None:
    calls: list[tuple[str, str, str, str]] = []

    def _extract_family(
        family: str,
        *,
        source_file: str,
        extract_path: str,
        text: str,
    ) -> list[str]:
        calls.append((family, source_file, extract_path, text))
        return [f"{family}:{extract_path}"]

    result = extract_cloud_configs_from_payload(
        "app.apk",
        "assets/config.json",
        "payload",
        run_ordered_batch=_run_ordered_batch,
        extract_cloud_config_family=_extract_family,
    )

    assert result == (
        ["firebase:assets/config.json"],
        ["supabase:assets/config.json"],
    )
    assert calls == [
        ("firebase", "app.apk", "assets/config.json", "payload"),
        ("supabase", "app.apk", "assets/config.json", "payload"),
    ]


def test_extract_cloud_config_family_dispatches_direct_extractors() -> None:
    calls: list[tuple[str, str, str, str]] = []

    def _extract(name: str) -> Callable[[str, str, str], list[str]]:
        def _inner(text: str, source_file: str, extract_path: str) -> list[str]:
            calls.append((name, text, source_file, extract_path))
            return [name]

        return _inner

    kwargs = {
        "source_file": "app.apk",
        "extract_path": "assets/config.json",
        "text": "payload",
        "extract_firebase_from_text": _extract("firebase"),
        "extract_supabase_from_text": _extract("supabase"),
    }

    assert extract_cloud_config_family("firebase", **kwargs) == ["firebase"]
    assert extract_cloud_config_family("supabase", **kwargs) == ["supabase"]
    assert extract_cloud_config_family("unknown", **kwargs) == []
    assert calls == [
        ("firebase", "payload", "app.apk", "assets/config.json"),
        ("supabase", "payload", "app.apk", "assets/config.json"),
    ]


def test_extract_cloud_configs_from_payloads_filters_jobs_and_merges_results() -> None:
    calls: list[tuple[str, str, str]] = []

    def _extract_payload(
        source_file: str,
        extract_path: str,
        text: str,
    ) -> tuple[list[str], list[str]]:
        calls.append((source_file, extract_path, text))
        return ([f"firebase:{extract_path}"], [f"supabase:{extract_path}"])

    result = extract_cloud_configs_from_payloads(
        [
            ("app.apk", "assets/firebase.json", "firebase payload"),
            ("app.apk", "assets/blank.json", " "),
            ("app.apk", "assets/supabase.js", "supabase payload"),
        ],
        run_ordered_batch=_run_ordered_batch,
        payload_cloud_config_job=payload_cloud_config_job,
        extract_cloud_configs_from_payload=_extract_payload,
        payload_cloud_config_result_entry=payload_cloud_config_result_entry,
    )

    assert result == (
        ["firebase:assets/firebase.json", "firebase:assets/supabase.js"],
        ["supabase:assets/firebase.json", "supabase:assets/supabase.js"],
    )
    assert calls == [
        ("app.apk", "assets/firebase.json", "firebase payload"),
        ("app.apk", "assets/supabase.js", "supabase payload"),
    ]


def test_nested_mobile_member_entries_filter_supported_members() -> None:
    suffixes = {".apk", ".ipa", ".apkm"}
    zip_member = zipfile.ZipInfo("packages/client.apk")
    zip_member.file_size = 10
    large_zip_member = zipfile.ZipInfo("packages/large.apk")
    large_zip_member.file_size = 11

    assert nested_mobile_zip_member_entry(
        zip_member,
        nested_mobile_artifact_suffixes=suffixes,
        remote_artifact_max_bytes=10,
    ) == {"name": "packages/client.apk"}
    assert nested_mobile_zip_member_entry(
        zipfile.ZipInfo("packages/"),
        nested_mobile_artifact_suffixes=suffixes,
        remote_artifact_max_bytes=10,
    ) is None
    assert nested_mobile_zip_member_entry(
        large_zip_member,
        nested_mobile_artifact_suffixes=suffixes,
        remote_artifact_max_bytes=10,
    ) is None

    tar_member = tarfile.TarInfo("packages/client.ipa")
    tar_member.size = 10
    tar_dir = tarfile.TarInfo("packages")
    tar_dir.type = tarfile.DIRTYPE

    assert nested_mobile_tar_member_entry(
        tar_member,
        nested_mobile_artifact_suffixes=suffixes,
        remote_artifact_max_bytes=10,
    ) == {"name": "packages/client.ipa"}
    assert nested_mobile_tar_member_entry(
        tar_dir,
        nested_mobile_artifact_suffixes=suffixes,
        remote_artifact_max_bytes=10,
    ) is None

    def _safe_member_name(raw_name: str) -> str:
        return "" if raw_name.startswith("../") else raw_name

    assert nested_mobile_7z_member_entry(
        SimpleNamespace(
            filename="packages/client.apkm",
            is_directory=False,
            is_symlink=False,
            is_file=True,
            uncompressed=10,
        ),
        safe_archive_member_name=_safe_member_name,
        nested_mobile_artifact_suffixes=suffixes,
        remote_artifact_max_bytes=10,
    ) == {"name": "packages/client.apkm", "target": "packages/client.apkm"}
    assert nested_mobile_7z_member_entry(
        SimpleNamespace(
            filename="../client.apk",
            is_directory=False,
            is_symlink=False,
            is_file=True,
            uncompressed=10,
        ),
        safe_archive_member_name=_safe_member_name,
        nested_mobile_artifact_suffixes=suffixes,
        remote_artifact_max_bytes=10,
    ) is None


def test_nested_mobile_member_job_and_result_entry_normalize_and_copy() -> None:
    payloads = [("archive.zip", "client.apk!payload.txt", "payload")]
    projects = ["firebase-one"]
    configs = ["supabase-one"]

    assert nested_mobile_member_job((" packages/client.apk ", b"payload")) == (
        "packages/client.apk",
        b"payload",
    )
    assert nested_mobile_member_job((" ", b"payload")) is None
    assert nested_mobile_member_job(("packages/client.apk", b"")) is None

    result = nested_mobile_member_result_entry((2, (payloads, projects, configs)))

    assert result == (payloads, projects, configs)
    assert result is not None
    assert result[0] is not payloads
    assert result[1] is not projects
    assert result[2] is not configs
    assert nested_mobile_member_result_entry((1, None)) is None


def test_extract_nested_mobile_configs_from_member_jobs_merges_results_in_order(tmp_path: Path) -> None:
    source_path = tmp_path / "bundle.zip"
    calls: list[tuple[bytes, Path, str]] = []

    def _extract_member(
        data: bytes,
        path: Path,
        member_name: str,
    ) -> tuple[list[tuple[str, str, str]], list[str], list[str]]:
        calls.append((data, path, member_name))
        label = Path(member_name).stem
        return (
            [(str(path), f"{member_name}!payload.txt", label)],
            [f"firebase:{label}"],
            [f"supabase:{label}"],
        )

    result = extract_nested_mobile_configs_from_member_jobs(
        [
            ("packages/client-1.apk", b"one"),
            ("packages/client-2.ipa", b"two"),
        ],
        source_path,
        run_ordered_batch=_run_ordered_batch,
        extract_mobile_configs_from_member_bytes=_extract_member,
        nested_mobile_member_result_entry=nested_mobile_member_result_entry,
    )

    assert result == (
        [
            (str(source_path), "packages/client-1.apk!payload.txt", "client-1"),
            (str(source_path), "packages/client-2.ipa!payload.txt", "client-2"),
        ],
        ["firebase:client-1", "firebase:client-2"],
        ["supabase:client-1", "supabase:client-2"],
        2,
    )
    assert calls == [
        (b"one", source_path, "packages/client-1.apk"),
        (b"two", source_path, "packages/client-2.ipa"),
    ]


def test_extract_nested_mobile_configs_from_zip_filters_reads_and_merges(tmp_path: Path) -> None:
    source_path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(source_path, "w") as zf:
        zf.writestr("packages/client.apk", b"apk-bytes")
        zf.writestr("notes.txt", b"ignored")
        zf.writestr("packages/client.ipa", b"ipa-bytes")

    calls: list[tuple[str, str]] = []

    def _zip_member_entry(member: zipfile.ZipInfo) -> dict[str, str] | None:
        calls.append(("entry", member.filename))
        if not member.filename.endswith((".apk", ".ipa")):
            return None
        return {"name": member.filename}

    def _member_job(job: tuple[str, bytes]) -> tuple[str, bytes] | None:
        calls.append(("job", f"{job[0]}:{job[1].decode()}"))
        return job if job[1] else None

    def _merge_jobs(
        member_jobs: list[tuple[str, bytes]],
        merge_source_path: Path,
    ) -> tuple[list[tuple[str, str, str]], list[str], list[str], int]:
        calls.append(("merge", ",".join(name for name, _data in member_jobs)))
        assert merge_source_path == source_path
        return (
            [
                (str(source_path), name, data.decode())
                for name, data in member_jobs
            ],
            ["firebase"],
            ["supabase"],
            len(member_jobs),
        )

    with zipfile.ZipFile(source_path) as zf:
        result = extract_nested_mobile_configs_from_zip(
            zf,
            source_path,
            run_ordered_batch=_run_ordered_batch,
            nested_mobile_zip_member_entry=_zip_member_entry,
            nested_mobile_member_job=_member_job,
            extract_nested_mobile_configs_from_member_jobs=_merge_jobs,
        )

    assert result == (
        [
            (str(source_path), "packages/client.apk", "apk-bytes"),
            (str(source_path), "packages/client.ipa", "ipa-bytes"),
        ],
        ["firebase"],
        ["supabase"],
        2,
    )
    assert calls == [
        ("entry", "packages/client.apk"),
        ("entry", "notes.txt"),
        ("entry", "packages/client.ipa"),
        ("job", "packages/client.apk:apk-bytes"),
        ("job", "packages/client.ipa:ipa-bytes"),
        ("merge", "packages/client.apk,packages/client.ipa"),
    ]


def test_extract_nested_mobile_configs_from_tar_filters_reads_and_merges(tmp_path: Path) -> None:
    source_path = tmp_path / "bundle.tar"
    with tarfile.open(source_path, "w") as tf:
        dir_info = tarfile.TarInfo("packages")
        dir_info.type = tarfile.DIRTYPE
        tf.addfile(dir_info)
        apk_data = b"apk-bytes"
        apk_info = tarfile.TarInfo("packages/client.apk")
        apk_info.size = len(apk_data)
        tf.addfile(apk_info, io.BytesIO(apk_data))
        ignored_data = b"ignored"
        ignored_info = tarfile.TarInfo("notes.txt")
        ignored_info.size = len(ignored_data)
        tf.addfile(ignored_info, io.BytesIO(ignored_data))
        ipa_data = b"ipa-bytes"
        ipa_info = tarfile.TarInfo("packages/client.ipa")
        ipa_info.size = len(ipa_data)
        tf.addfile(ipa_info, io.BytesIO(ipa_data))

    calls: list[tuple[str, str]] = []

    def _tar_member_entry(member: tarfile.TarInfo) -> dict[str, str] | None:
        calls.append(("entry", member.name))
        if not member.name.endswith((".apk", ".ipa")):
            return None
        return {"name": member.name}

    def _member_job(job: tuple[str, bytes]) -> tuple[str, bytes] | None:
        calls.append(("job", f"{job[0]}:{job[1].decode()}"))
        return job if job[1] else None

    def _merge_jobs(
        member_jobs: list[tuple[str, bytes]],
        merge_source_path: Path,
    ) -> tuple[list[tuple[str, str, str]], list[str], list[str], int]:
        calls.append(("merge", ",".join(name for name, _data in member_jobs)))
        assert merge_source_path == source_path
        return (
            [
                (str(source_path), name, data.decode())
                for name, data in member_jobs
            ],
            ["firebase"],
            ["supabase"],
            len(member_jobs),
        )

    with tarfile.open(source_path) as tf:
        result = extract_nested_mobile_configs_from_tar(
            tf,
            source_path,
            run_ordered_batch=_run_ordered_batch,
            nested_mobile_tar_member_entry=_tar_member_entry,
            nested_mobile_member_job=_member_job,
            extract_nested_mobile_configs_from_member_jobs=_merge_jobs,
        )

    assert result == (
        [
            (str(source_path), "packages/client.apk", "apk-bytes"),
            (str(source_path), "packages/client.ipa", "ipa-bytes"),
        ],
        ["firebase"],
        ["supabase"],
        2,
    )
    assert calls == [
        ("entry", "packages"),
        ("entry", "packages/client.apk"),
        ("entry", "notes.txt"),
        ("entry", "packages/client.ipa"),
        ("job", "packages/client.apk:apk-bytes"),
        ("job", "packages/client.ipa:ipa-bytes"),
        ("merge", "packages/client.apk,packages/client.ipa"),
    ]


def test_extract_nested_mobile_configs_from_7z_gates_dependency_and_magic(tmp_path: Path) -> None:
    assert extract_nested_mobile_configs_from_7z(
        SEVEN_Z_ARCHIVE_MAGIC + b"payload",
        tmp_path / "bundle.7z",
        seven_zip_file_factory=None,
        run_ordered_batch=_run_ordered_batch,
        nested_mobile_7z_member_entry=lambda _member: {"name": "packages/client.apk", "target": "packages/client.apk"},
        nested_mobile_member_job=nested_mobile_member_job,
        extract_nested_mobile_configs_from_member_jobs=lambda _jobs, _path: ([("bad", "bad", "bad")], [], [], 1),
        remote_artifact_max_bytes=32,
    ) == ([], [], [], 0)
    assert extract_nested_mobile_configs_from_7z(
        b"not-7z",
        tmp_path / "bundle.7z",
        seven_zip_file_factory=lambda *_args, **_kwargs: None,
        run_ordered_batch=_run_ordered_batch,
        nested_mobile_7z_member_entry=lambda _member: {"name": "packages/client.apk", "target": "packages/client.apk"},
        nested_mobile_member_job=nested_mobile_member_job,
        extract_nested_mobile_configs_from_member_jobs=lambda _jobs, _path: ([("bad", "bad", "bad")], [], [], 1),
        remote_artifact_max_bytes=32,
    ) == ([], [], [], 0)


def test_extract_nested_mobile_configs_from_7z_extracts_selected_members_and_merges(tmp_path: Path) -> None:
    source_path = tmp_path / "bundle.7z"
    calls: list[tuple[str, str]] = []

    class _FakeArchive:
        def __init__(self, _data: Any, *, mode: str) -> None:
            assert mode == "r"

        def __enter__(self) -> "_FakeArchive":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def needs_password(self) -> bool:
            return False

        def list(self) -> list[str]:
            return ["packages/client.apk", "notes.txt", "packages/client.ipa"]

        def extract(self, *, path: str, targets: list[str]) -> None:
            calls.append(("extract", ",".join(targets)))
            root = Path(path)
            payloads = {
                "packages/client.apk": b"apk-bytes",
                "packages/client.ipa": b"ipa-bytes",
            }
            for target in targets:
                target_path = root / Path(*target.split("/"))
                target_path.parent.mkdir(parents=True, exist_ok=True)
                target_path.write_bytes(payloads[target])

    def _member_entry(member: str) -> dict[str, str] | None:
        calls.append(("entry", member))
        if not member.endswith((".apk", ".ipa")):
            return None
        return {"name": member, "target": member}

    def _member_job(job: tuple[str, bytes]) -> tuple[str, bytes] | None:
        calls.append(("job", f"{job[0]}:{job[1].decode()}"))
        return job

    def _merge_jobs(
        member_jobs: list[tuple[str, bytes]],
        merge_source_path: Path,
    ) -> tuple[list[tuple[str, str, str]], list[str], list[str], int]:
        calls.append(("merge", ",".join(name for name, _data in member_jobs)))
        assert merge_source_path == source_path
        return (
            [
                (str(source_path), name, data.decode())
                for name, data in member_jobs
            ],
            ["firebase"],
            ["supabase"],
            len(member_jobs),
        )

    assert extract_nested_mobile_configs_from_7z(
        SEVEN_Z_ARCHIVE_MAGIC + b"payload",
        source_path,
        seven_zip_file_factory=_FakeArchive,
        run_ordered_batch=_run_ordered_batch,
        nested_mobile_7z_member_entry=_member_entry,
        nested_mobile_member_job=_member_job,
        extract_nested_mobile_configs_from_member_jobs=_merge_jobs,
        remote_artifact_max_bytes=32,
    ) == (
        [
            (str(source_path), "packages/client.apk", "apk-bytes"),
            (str(source_path), "packages/client.ipa", "ipa-bytes"),
        ],
        ["firebase"],
        ["supabase"],
        2,
    )
    assert calls == [
        ("entry", "packages/client.apk"),
        ("entry", "notes.txt"),
        ("entry", "packages/client.ipa"),
        ("extract", "packages/client.apk,packages/client.ipa"),
        ("job", "packages/client.apk:apk-bytes"),
        ("job", "packages/client.ipa:ipa-bytes"),
        ("merge", "packages/client.apk,packages/client.ipa"),
    ]


def test_extract_nested_mobile_bundle_configs_dispatches_zip_7z_tar_and_skips(
    tmp_path: Path,
) -> None:
    zip_path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("packages/client.apk", "zip")

    seven_path = tmp_path / "bundle.7z"
    seven_path.write_bytes(SEVEN_Z_ARCHIVE_MAGIC + b"payload")

    tar_path = tmp_path / "bundle.tar"
    with tarfile.open(tar_path, "w") as tf:
        payload = b"tar"
        info = tarfile.TarInfo("packages/client.apk")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))

    calls: list[tuple[str, str]] = []

    def _zip(zf: zipfile.ZipFile, path: Path) -> tuple[list[tuple[str, str, str]], list[str], list[str], int]:
        calls.append(("zip", f"{path.name}:{zf.namelist()[0]}"))
        return ([(str(path), "zip", "payload")], ["firebase-zip"], ["supabase-zip"], 1)

    def _seven(data: bytes, path: Path) -> tuple[list[tuple[str, str, str]], list[str], list[str], int]:
        calls.append(("7z", f"{path.name}:{data[:6].hex()}"))
        return ([(str(path), "7z", "payload")], ["firebase-7z"], ["supabase-7z"], 1)

    def _tar(tf: tarfile.TarFile, path: Path) -> tuple[list[tuple[str, str, str]], list[str], list[str], int]:
        calls.append(("tar", f"{path.name}:{tf.getmembers()[0].name}"))
        return ([(str(path), "tar", "payload")], ["firebase-tar"], ["supabase-tar"], 1)

    assert extract_nested_mobile_bundle_configs(
        tmp_path / "missing.zip",
        "archive",
        py7zr_available=True,
        extract_nested_mobile_configs_from_zip=_zip,
        extract_nested_mobile_configs_from_7z=_seven,
        extract_nested_mobile_configs_from_tar=_tar,
    ) == ([], [], [], 0)
    assert extract_nested_mobile_bundle_configs(
        zip_path,
        "config",
        py7zr_available=True,
        extract_nested_mobile_configs_from_zip=_zip,
        extract_nested_mobile_configs_from_7z=_seven,
        extract_nested_mobile_configs_from_tar=_tar,
    ) == ([], [], [], 0)
    assert extract_nested_mobile_bundle_configs(
        zip_path,
        "archive",
        py7zr_available=True,
        extract_nested_mobile_configs_from_zip=_zip,
        extract_nested_mobile_configs_from_7z=_seven,
        extract_nested_mobile_configs_from_tar=_tar,
    ) == ([(str(zip_path), "zip", "payload")], ["firebase-zip"], ["supabase-zip"], 1)
    assert extract_nested_mobile_bundle_configs(
        seven_path,
        "archive",
        py7zr_available=True,
        extract_nested_mobile_configs_from_zip=_zip,
        extract_nested_mobile_configs_from_7z=_seven,
        extract_nested_mobile_configs_from_tar=_tar,
    ) == ([(str(seven_path), "7z", "payload")], ["firebase-7z"], ["supabase-7z"], 1)
    assert extract_nested_mobile_bundle_configs(
        tar_path,
        "archive",
        py7zr_available=False,
        extract_nested_mobile_configs_from_zip=_zip,
        extract_nested_mobile_configs_from_7z=_seven,
        extract_nested_mobile_configs_from_tar=_tar,
    ) == ([(str(tar_path), "tar", "payload")], ["firebase-tar"], ["supabase-tar"], 1)
    assert calls == [
        ("zip", "bundle.zip:packages/client.apk"),
        ("7z", f"bundle.7z:{SEVEN_Z_ARCHIVE_MAGIC.hex()}"),
        ("tar", "bundle.tar:packages/client.apk"),
    ]


def test_rebased_mobile_member_entries_preserve_outer_archive_provenance(tmp_path: Path) -> None:
    source_path = tmp_path / "bundle.zip"
    member_name = "packages/client.apk"
    project = FirebaseProject(
        project_id="client-firebase",
        api_key_enc="enc",
        rtdb_url="https://client.firebaseio.com",
        bundle_id="com.acme.client",
        source_file="client.apk",
        extract_path="google-services.json",
        storage_bucket="client.appspot.com",
    )
    config = SupabaseConfig(
        project_ref="client",
        project_url="https://client.supabase.co",
        anon_key="anon",
        source_file="client.apk",
        extract_path="supabase.js",
    )

    assert rebased_mobile_member_payload_entry(
        ("client.apk", "payload.txt", "payload"),
        source_path=source_path,
        member_name=member_name,
    ) == (str(source_path), "packages/client.apk!payload.txt", "payload")

    rebased_project = rebased_mobile_member_project_entry(
        project,
        source_path=source_path,
        member_name=member_name,
        firebase_project_type=FirebaseProject,
    )
    assert rebased_project == FirebaseProject(
        project_id="client-firebase",
        api_key_enc="enc",
        rtdb_url="https://client.firebaseio.com",
        bundle_id="com.acme.client",
        source_file=str(source_path),
        extract_path="packages/client.apk!google-services.json",
        storage_bucket="client.appspot.com",
    )

    rebased_config = rebased_mobile_member_config_entry(
        config,
        source_path=source_path,
        member_name=member_name,
        supabase_config_type=SupabaseConfig,
    )
    assert rebased_config == SupabaseConfig(
        project_ref="client",
        project_url="https://client.supabase.co",
        anon_key="anon",
        source_file=str(source_path),
        extract_path="packages/client.apk!supabase.js",
    )


def test_mobile_member_artifact_type_routes_supported_suffixes() -> None:
    assert mobile_member_artifact_type(
        "client.apk",
        nested_mobile_artifact_suffixes={".apk", ".ipa", ".aab", ".apkm"},
        archive_style_mobile_artifact_suffixes={".apkm"},
    ) == "apk"
    assert mobile_member_artifact_type(
        "client.aab",
        nested_mobile_artifact_suffixes={".apk", ".ipa", ".aab", ".apkm"},
        archive_style_mobile_artifact_suffixes={".apkm"},
    ) == "apk"
    assert mobile_member_artifact_type(
        "client.ipa",
        nested_mobile_artifact_suffixes={".apk", ".ipa", ".aab", ".apkm"},
        archive_style_mobile_artifact_suffixes={".apkm"},
    ) == "ipa"
    assert mobile_member_artifact_type(
        "client.apkm",
        nested_mobile_artifact_suffixes={".apk", ".ipa", ".aab", ".apkm"},
        archive_style_mobile_artifact_suffixes={".apkm"},
    ) == "archive"
    assert mobile_member_artifact_type(
        "client.txt",
        nested_mobile_artifact_suffixes={".apk", ".ipa", ".aab", ".apkm"},
        archive_style_mobile_artifact_suffixes={".apkm"},
    ) is None


def test_extract_mobile_bundle_family_results_dispatches_families_in_order(tmp_path: Path) -> None:
    path = tmp_path / "client.apk"
    calls: list[tuple[str, Path, str]] = []

    def _extract_family(
        family: str,
        *,
        path: Path,
        artifact_type: str,
    ) -> list[str]:
        calls.append((family, path, artifact_type))
        return [f"{family}:{artifact_type}"]

    result = extract_mobile_bundle_family_results(
        path,
        "apk",
        run_ordered_batch=_run_ordered_batch,
        extract_mobile_bundle_family=_extract_family,
    )

    assert result == (
        ["payloads:apk"],
        ["firebase:apk"],
        ["supabase:apk"],
    )
    assert calls == [
        ("payloads", path, "apk"),
        ("firebase", path, "apk"),
        ("supabase", path, "apk"),
    ]


def test_extract_mobile_bundle_family_dispatches_direct_extractors(tmp_path: Path) -> None:
    path = tmp_path / "client.apk"
    calls: list[tuple[str, Path]] = []

    def _extract(name: str) -> Callable[[Path], list[str]]:
        def _inner(target: Path) -> list[str]:
            calls.append((name, target))
            return [name]

        return _inner

    kwargs = {
        "path": path,
        "extract_mobile_bundle_text_payloads": _extract("payloads"),
        "extract_apk": _extract("apk-firebase"),
        "extract_supabase_apk": _extract("apk-supabase"),
        "extract_ipa": _extract("ipa-firebase"),
        "extract_supabase_ipa": _extract("ipa-supabase"),
    }

    assert extract_mobile_bundle_family("payloads", artifact_type="apk", **kwargs) == ["payloads"]
    assert extract_mobile_bundle_family("firebase", artifact_type="apk", **kwargs) == ["apk-firebase"]
    assert extract_mobile_bundle_family("supabase", artifact_type="apk", **kwargs) == ["apk-supabase"]
    assert extract_mobile_bundle_family("firebase", artifact_type="ipa", **kwargs) == ["ipa-firebase"]
    assert extract_mobile_bundle_family("supabase", artifact_type="ipa", **kwargs) == ["ipa-supabase"]
    assert extract_mobile_bundle_family("unknown", artifact_type="apk", **kwargs) == []
    assert extract_mobile_bundle_family("unknown", artifact_type="ipa", **kwargs) == []

    assert calls == [
        ("payloads", path),
        ("apk-firebase", path),
        ("apk-supabase", path),
        ("ipa-firebase", path),
        ("ipa-supabase", path),
    ]


def test_extract_mobile_bundle_text_payloads_prefers_zip_then_tar_and_ignores_missing(
    tmp_path: Path,
) -> None:
    zip_path = tmp_path / "client.apk"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("assets/config.txt", "owner@example.test")

    tar_path = tmp_path / "client.tar"
    tar_member_data = b"nested-owner@example.test"
    with tarfile.open(tar_path, "w") as tf:
        info = tarfile.TarInfo("payload.txt")
        info.size = len(tar_member_data)
        tf.addfile(info, io.BytesIO(tar_member_data))

    calls: list[tuple[str, str, int]] = []

    def _zip_payloads(zf: zipfile.ZipFile, source_file: str, *, depth: int) -> list[tuple[str, str, str]]:
        calls.append(("zip", source_file, depth))
        return [(source_file, zf.namelist()[0], "zip-payload")]

    def _tar_payloads(tf: tarfile.TarFile, source_file: str, *, depth: int) -> list[tuple[str, str, str]]:
        calls.append(("tar", source_file, depth))
        first_member = tf.getmembers()[0]
        return [(source_file, first_member.name, "tar-payload")]

    assert extract_mobile_bundle_text_payloads(
        zip_path,
        extract_text_payloads_from_zip=_zip_payloads,
        extract_text_payloads_from_tar=_tar_payloads,
    ) == [(str(zip_path), "assets/config.txt", "zip-payload")]
    assert extract_mobile_bundle_text_payloads(
        tar_path,
        extract_text_payloads_from_zip=_zip_payloads,
        extract_text_payloads_from_tar=_tar_payloads,
    ) == [(str(tar_path), "payload.txt", "tar-payload")]
    assert extract_mobile_bundle_text_payloads(
        tmp_path / "missing.apk",
        extract_text_payloads_from_zip=_zip_payloads,
        extract_text_payloads_from_tar=_tar_payloads,
    ) == []
    assert calls == [
        ("zip", str(zip_path), 1),
        ("tar", str(tar_path), 1),
    ]


def test_extract_mobile_configs_from_member_bytes_routes_archive_and_direct_mobile(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "outer.zip"
    calls: list[tuple[str, str]] = []

    def _scan_text_artifact(
        path: Path,
        artifact_type: str,
    ) -> tuple[list[tuple[str, str, str]], list[FirebaseProject], list[SupabaseConfig], dict[str, Any]]:
        calls.append(("scan", f"{artifact_type}:{path.name}:{path.read_bytes().decode()}"))
        return (
            [(str(path), "archive-payload.txt", "archive-owner@example.test")],
            [FirebaseProject("archive-firebase", None, None, None, str(path), "firebase.json")],
            [SupabaseConfig("archive-supa", "https://archive-supa.supabase.co", "anon", str(path), "supa.js")],
            {"parser": "archive"},
        )

    def _family(
        family: str,
        *,
        path: Path,
        artifact_type: str,
    ) -> list[tuple[str, str, str]] | list[FirebaseProject] | list[SupabaseConfig]:
        calls.append(("family", f"{family}:{artifact_type}:{path.name}:{path.read_bytes().decode()}"))
        if family == "payloads":
            return [(str(path), "payload.txt", "direct-owner@example.test")]
        if family == "firebase":
            return [FirebaseProject("direct-firebase", None, None, None, str(path), "firebase.json")]
        return [SupabaseConfig("direct-supa", "https://direct-supa.supabase.co", "anon", str(path), "supa.js")]

    def _project_entry(
        project: FirebaseProject,
        *,
        source_path: Path,
        member_name: str,
    ) -> FirebaseProject:
        return rebased_mobile_member_project_entry(
            project,
            source_path=source_path,
            member_name=member_name,
            firebase_project_type=FirebaseProject,
        )

    def _config_entry(
        config: SupabaseConfig,
        *,
        source_path: Path,
        member_name: str,
    ) -> SupabaseConfig:
        return rebased_mobile_member_config_entry(
            config,
            source_path=source_path,
            member_name=member_name,
            supabase_config_type=SupabaseConfig,
        )

    archive_result = extract_mobile_configs_from_member_bytes(
        b"archive-bytes",
        source_path,
        "packages/client.xapk",
        nested_mobile_artifact_suffixes={".apk", ".ipa", ".xapk"},
        archive_style_mobile_artifact_suffixes={".xapk"},
        remote_artifact_max_bytes=8,
        run_ordered_batch=_run_ordered_batch,
        scan_text_artifact=_scan_text_artifact,
        extract_mobile_bundle_family=_family,
        rebased_mobile_member_payload_entry=rebased_mobile_member_payload_entry,
        rebased_mobile_member_project_entry=_project_entry,
        rebased_mobile_member_config_entry=_config_entry,
        firebase_project_type=FirebaseProject,
        supabase_config_type=SupabaseConfig,
    )
    direct_result = extract_mobile_configs_from_member_bytes(
        b"direct-bytes",
        source_path,
        "packages/client.apk",
        nested_mobile_artifact_suffixes={".apk", ".ipa", ".xapk"},
        archive_style_mobile_artifact_suffixes={".xapk"},
        remote_artifact_max_bytes=64,
        run_ordered_batch=_run_ordered_batch,
        scan_text_artifact=_scan_text_artifact,
        extract_mobile_bundle_family=_family,
        rebased_mobile_member_payload_entry=rebased_mobile_member_payload_entry,
        rebased_mobile_member_project_entry=_project_entry,
        rebased_mobile_member_config_entry=_config_entry,
        firebase_project_type=FirebaseProject,
        supabase_config_type=SupabaseConfig,
    )

    assert archive_result[0] == [
        (str(source_path), "packages/client.xapk!archive-payload.txt", "archive-owner@example.test")
    ]
    assert [project.extract_path for project in archive_result[1]] == [
        "packages/client.xapk!firebase.json"
    ]
    assert [config.extract_path for config in archive_result[2]] == [
        "packages/client.xapk!supa.js"
    ]
    assert direct_result[0] == [
        (str(source_path), "packages/client.apk!payload.txt", "direct-owner@example.test")
    ]
    assert [project.extract_path for project in direct_result[1]] == [
        "packages/client.apk!firebase.json"
    ]
    assert [config.extract_path for config in direct_result[2]] == [
        "packages/client.apk!supa.js"
    ]
    assert calls == [
        ("scan", "archive:client.xapk:archive-"),
        ("family", "payloads:apk:client.apk:direct-bytes"),
        ("family", "firebase:apk:client.apk:direct-bytes"),
        ("family", "supabase:apk:client.apk:direct-bytes"),
    ]


def test_extract_mobile_configs_from_member_bytes_skips_unsupported_and_empty_members(
    tmp_path: Path,
) -> None:
    def _unexpected_scan(
        _path: Path,
        _artifact_type: str,
    ) -> tuple[list[tuple[str, str, str]], list[Any], list[Any], dict[str, Any]]:
        raise AssertionError("scan should not be called")

    assert extract_mobile_configs_from_member_bytes(
        b"",
        tmp_path / "outer.zip",
        "packages/client.apk",
        nested_mobile_artifact_suffixes={".apk"},
        archive_style_mobile_artifact_suffixes=set(),
        remote_artifact_max_bytes=64,
        run_ordered_batch=_run_ordered_batch,
        scan_text_artifact=_unexpected_scan,
        extract_mobile_bundle_family=lambda *_args, **_kwargs: [],
        rebased_mobile_member_payload_entry=rebased_mobile_member_payload_entry,
        rebased_mobile_member_project_entry=rebased_mobile_member_project_entry,
        rebased_mobile_member_config_entry=rebased_mobile_member_config_entry,
        firebase_project_type=FirebaseProject,
        supabase_config_type=SupabaseConfig,
    ) == ([], [], [])
    assert extract_mobile_configs_from_member_bytes(
        b"payload",
        tmp_path / "outer.zip",
        "packages/readme.txt",
        nested_mobile_artifact_suffixes={".apk"},
        archive_style_mobile_artifact_suffixes=set(),
        remote_artifact_max_bytes=64,
        run_ordered_batch=_run_ordered_batch,
        scan_text_artifact=_unexpected_scan,
        extract_mobile_bundle_family=lambda *_args, **_kwargs: [],
        rebased_mobile_member_payload_entry=rebased_mobile_member_payload_entry,
        rebased_mobile_member_project_entry=rebased_mobile_member_project_entry,
        rebased_mobile_member_config_entry=rebased_mobile_member_config_entry,
        firebase_project_type=FirebaseProject,
        supabase_config_type=SupabaseConfig,
    ) == ([], [], [])


def test_rebase_mobile_member_discoveries_batches_and_filters_entries(tmp_path: Path) -> None:
    source_path = tmp_path / "bundle.zip"
    member_name = "packages/client.apk"
    project = FirebaseProject("client-firebase", None, None, None, "client.apk", "firebase.json")
    config = SupabaseConfig("client", "https://client.supabase.co", "anon", "client.apk", "supabase.js")
    calls: list[tuple[str, str]] = []

    def _payload_entry(
        payload: tuple[str, str, str],
        *,
        source_path: Path,
        member_name: str,
    ) -> tuple[str, str, str] | None:
        calls.append(("payload", payload[1]))
        return rebased_mobile_member_payload_entry(
            payload,
            source_path=source_path,
            member_name=member_name,
        )

    def _project_entry(
        project: Any,
        *,
        source_path: Path,
        member_name: str,
    ) -> Any:
        calls.append(("project", getattr(project, "project_id", "")))
        if not isinstance(project, FirebaseProject):
            return None
        return rebased_mobile_member_project_entry(
            project,
            source_path=source_path,
            member_name=member_name,
            firebase_project_type=FirebaseProject,
        )

    def _config_entry(
        config: Any,
        *,
        source_path: Path,
        member_name: str,
    ) -> Any:
        calls.append(("config", getattr(config, "project_ref", "")))
        if not isinstance(config, SupabaseConfig):
            return None
        return rebased_mobile_member_config_entry(
            config,
            source_path=source_path,
            member_name=member_name,
            supabase_config_type=SupabaseConfig,
        )

    rebased_payloads, rebased_projects, rebased_configs = rebase_mobile_member_discoveries(
        [("client.apk", "payload.txt", "payload")],
        [project, "not-a-project"],
        [config, "not-a-config"],
        source_path=source_path,
        member_name=member_name,
        run_ordered_batch=_run_ordered_batch,
        rebased_mobile_member_payload_entry=_payload_entry,
        rebased_mobile_member_project_entry=_project_entry,
        rebased_mobile_member_config_entry=_config_entry,
        firebase_project_type=FirebaseProject,
        supabase_config_type=SupabaseConfig,
    )

    assert rebased_payloads == [(str(source_path), "packages/client.apk!payload.txt", "payload")]
    assert rebased_projects == [
        FirebaseProject("client-firebase", None, None, None, str(source_path), "packages/client.apk!firebase.json")
    ]
    assert rebased_configs == [
        SupabaseConfig("client", "https://client.supabase.co", "anon", str(source_path), "packages/client.apk!supabase.js")
    ]
    assert calls == [
        ("payload", "payload.txt"),
        ("project", "client-firebase"),
        ("project", ""),
        ("config", "client"),
        ("config", ""),
    ]


def test_artifact_payload_summary_counts_payload_families(tmp_path: Path) -> None:
    summary = artifact_payload_summary(
        tmp_path / "bundle.zip",
        "archive",
        [
            ("bundle.zip", "member.txt", "plain"),
            ("bundle.zip", "doc.xml#metadata", "meta"),
            ("bundle.zip", "doc.xml#relationships", "rels"),
            ("bundle.zip", "image.png#ocr", "ocr"),
            ("bundle.zip", "image.png#barcode", "barcode"),
        ],
        artifact_format_label=lambda path: path.suffix.lstrip("."),
        barcode_decoder_backends=("zbar", "opencv"),
    )

    assert summary == {
        "parser": "archive",
        "format": "zip",
        "payload_count": 5,
        "metadata_payload_count": 4,
        "relationship_payload_count": 1,
        "ocr_payload_count": 1,
        "barcode_payload_count": 1,
        "barcode_decoder_backends": ["zbar", "opencv"],
    }


def test_artifact_text_scan_stage_dispatches_payload_nested_and_default(tmp_path: Path) -> None:
    path = tmp_path / "bundle.zip"

    payload_stage = artifact_text_scan_stage(
        "payloads",
        path=path,
        artifact_type="archive",
        extract_text_payloads=lambda stage_path, artifact_type: [
            (str(stage_path), artifact_type, "payload")
        ],
        extract_nested_mobile_bundle_configs=lambda _path, _artifact_type: ([], [], [], 0),
    )
    assert payload_stage == ArtifactTextScanStageResult(
        payloads=[(str(path), "archive", "payload")]
    )

    nested_stage = artifact_text_scan_stage(
        "nested_mobile",
        path=path,
        artifact_type="archive",
        extract_text_payloads=lambda _path, _artifact_type: [],
        extract_nested_mobile_bundle_configs=lambda _path, _artifact_type: (
            [(str(path), "client.apk!payload.txt", "nested")],
            ["firebase-nested"],
            ["supabase-nested"],
            2,
        ),
    )
    assert nested_stage == ArtifactTextScanStageResult(
        payloads=[(str(path), "client.apk!payload.txt", "nested")],
        firebase_projects=["firebase-nested"],
        supabase_configs=["supabase-nested"],
        nested_mobile_member_count=2,
    )

    assert artifact_text_scan_stage(
        "unknown",
        path=path,
        artifact_type="archive",
        extract_text_payloads=lambda _path, _artifact_type: [("unexpected", "", "")],
        extract_nested_mobile_bundle_configs=lambda _path, _artifact_type: (
            [("unexpected", "", "")],
            ["unexpected"],
            ["unexpected"],
            1,
        ),
    ) == ArtifactTextScanStageResult()


def test_scan_text_artifact_merges_stages_cloud_configs_and_summary(tmp_path: Path) -> None:
    path = tmp_path / "bundle.zip"
    base_payload = (str(path), "base.txt", "base")
    nested_payload = (str(path), "client.apk!payload.txt", "nested")
    calls: list[str] = []

    def _stage(
        family: str,
        *,
        path: Path,
        artifact_type: str,
    ) -> ArtifactTextScanStageResult:
        calls.append(f"stage:{family}:{artifact_type}:{path.name}")
        if family == "payloads":
            return ArtifactTextScanStageResult(payloads=[base_payload])
        return ArtifactTextScanStageResult(
            payloads=[nested_payload],
            firebase_projects=["firebase-nested"],
            supabase_configs=["supabase-nested"],
            nested_mobile_member_count=2,
        )

    def _cloud(payloads: list[tuple[str, str, str]]) -> tuple[list[str], list[str]]:
        calls.append(f"cloud:{len(payloads)}")
        assert payloads == [base_payload]
        return ["firebase-base"], ["supabase-base"]

    def _summary(
        summary_path: Path,
        artifact_type: str,
        payloads: list[tuple[str, str, str]],
    ) -> dict[str, Any]:
        calls.append(f"summary:{len(payloads)}")
        return {
            "parser": artifact_type,
            "format": summary_path.suffix.lstrip("."),
            "payload_count": len(payloads),
        }

    result = scan_text_artifact(
        path,
        "archive",
        run_ordered_batch=_run_ordered_batch,
        extract_text_artifact_stage=_stage,
        extract_cloud_configs_from_payloads=_cloud,
        artifact_payload_summary=_summary,
        dedupe_firebase_projects=lambda projects: list(dict.fromkeys(projects)),
        dedupe_supabase_configs=lambda configs: list(dict.fromkeys(configs)),
    )

    assert result == (
        [base_payload, nested_payload],
        ["firebase-base", "firebase-nested"],
        ["supabase-base", "supabase-nested"],
        {
            "parser": "archive",
            "format": "zip",
            "payload_count": 2,
            "nested_mobile_member_count": 2,
        },
    )
    assert calls == [
        "stage:payloads:archive:bundle.zip",
        "stage:nested_mobile:archive:bundle.zip",
        "cloud:1",
        "summary:2",
    ]


def test_scan_mobile_bundle_artifact_merges_family_and_payload_cloud_configs(tmp_path: Path) -> None:
    path = tmp_path / "client.apk"
    payload = (str(path), "assets/config.js", "payload")
    calls: list[str] = []

    def _family(
        family: str,
        *,
        path: Path,
        artifact_type: str,
    ) -> list[str] | list[tuple[str, str, str]]:
        calls.append(f"family:{family}:{artifact_type}:{path.name}")
        if family == "payloads":
            return [payload]
        if family == "firebase":
            return ["firebase-direct", "firebase-direct"]
        return ["supabase-direct", "supabase-direct"]

    def _cloud(payloads: list[tuple[str, str, str]]) -> tuple[list[str], list[str]]:
        calls.append(f"cloud:{len(payloads)}")
        assert payloads == [payload]
        return ["firebase-from-payload"], ["supabase-from-payload"]

    def _summary(
        summary_path: Path,
        artifact_type: str,
        payloads: list[tuple[str, str, str]],
    ) -> dict[str, Any]:
        calls.append(f"summary:{len(payloads)}")
        return {
            "parser": artifact_type,
            "format": summary_path.suffix.lstrip("."),
            "payload_count": len(payloads),
        }

    result = scan_mobile_bundle_artifact(
        path,
        "apk",
        run_ordered_batch=_run_ordered_batch,
        extract_mobile_bundle_family=_family,
        extract_cloud_configs_from_payloads=_cloud,
        artifact_payload_summary=_summary,
        dedupe_firebase_projects=lambda projects: list(dict.fromkeys(projects)),
        dedupe_supabase_configs=lambda configs: list(dict.fromkeys(configs)),
    )

    assert result == (
        [payload],
        ["firebase-direct", "firebase-from-payload"],
        ["supabase-direct", "supabase-from-payload"],
        {
            "parser": "apk",
            "format": "apk",
            "payload_count": 1,
        },
    )
    assert calls == [
        "family:payloads:apk:client.apk",
        "family:firebase:apk:client.apk",
        "family:supabase:apk:client.apk",
        "cloud:1",
        "summary:1",
    ]


def test_safe_archive_member_name_rejects_traversal_and_absolute_paths() -> None:
    assert safe_archive_member_name(" ./configs/app.yml ") == "configs/app.yml"
    assert safe_archive_member_name("nested\\member.txt") == "nested/member.txt"
    assert safe_archive_member_name("../secret.txt") == ""
    assert safe_archive_member_name("/etc/passwd") == ""
    assert safe_archive_member_name("C:\\Windows\\win.ini") == ""
    assert safe_archive_member_name("") == ""


def test_run_ordered_static_batch_preserves_order_and_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORGE_STATIC_ARTIFACT_MAX_WORKERS", "3")

    def _worker(value: int) -> str:
        if value == 2:
            raise RuntimeError("boom")
        return f"item-{value}"

    assert static_batch_worker_count(0) == 0
    assert static_batch_worker_count(1) == 1
    assert static_batch_worker_count(5, max_static_batch_workers=4) == 3
    assert run_ordered_static_batch(
        [3, 2, 1],
        _worker,
        default_factory=lambda: "fallback",
    ) == ["item-3", "fallback", "item-1"]


def test_run_ordered_local_artifact_batch_preserves_order_and_defaults() -> None:
    def _worker(value: int) -> str:
        if value == 2:
            raise RuntimeError("boom")
        return f"item-{value}"

    assert run_ordered_local_artifact_batch(
        [3, 2, 1],
        _worker,
        default_factory=lambda: "fallback",
        max_workers=3,
    ) == ["item-3", "fallback", "item-1"]


def test_run_ordered_local_artifact_batch_uses_serial_path_for_low_worker_limits() -> None:
    calls: list[int] = []

    def _worker(value: int) -> str:
        calls.append(value)
        if value == 2:
            raise RuntimeError("boom")
        return f"item-{value}"

    assert run_ordered_local_artifact_batch(
        [1, 2, 3],
        _worker,
        default_factory=lambda: "fallback",
        max_workers=0,
    ) == ["item-1", "fallback", "item-3"]
    assert calls == [1, 2, 3]


def test_decode_text_artifact_bytes_prefers_semantic_decoding() -> None:
    assert decode_text_artifact_entry(("utf-8", b"a\x00b")) == "ab"
    assert decode_text_artifact_bytes("https://example.test\n".encode("utf-16"), limit=128).startswith(
        "https://example.test"
    )
    assert decode_text_artifact_bytes(b"\xff\xfeA\x00=\x00B\x00", limit=8) == "A=B"


def test_decode_email_part_entry_decodes_valid_entries_and_skips_invalid_codecs() -> None:
    assert decode_email_part_entry(("utf-8", "owner@example.test".encode("utf-8"))) == "owner@example.test"
    assert decode_email_part_entry(("x-invalid-charset", b"payload")) is None


def test_decode_email_part_text_uses_ordered_candidates_and_fallback() -> None:
    class _Part:
        def __init__(self, charset: str | None) -> None:
            self._charset = charset

        def get_content_charset(self) -> str | None:
            return self._charset

    calls: list[list[str]] = []

    def _run_ordered_static_batch(
        entries: Sequence[tuple[str, bytes]],
        worker: Callable[[tuple[str, bytes]], str | None],
        *,
        default_factory: Callable[[], Any],
        max_workers: int,
    ) -> list[Any]:
        assert max_workers == len(entries)
        calls.append([encoding for encoding, _data in entries])
        results: list[Any] = []
        for entry in entries:
            value = worker(entry)
            results.append(value if value is not None else default_factory())
        return results

    def _decode(entry: tuple[str, bytes]) -> str | None:
        encoding, bounded = entry
        assert bounded == b"payload"
        if encoding == "utf-8":
            return "decoded"
        return None

    assert decode_email_part_text(
        _Part("x-invalid-charset"),
        b"payload",
        max_artifact_member_bytes=16,
        run_ordered_static_batch=_run_ordered_static_batch,
        decode_email_part_entry=_decode,
    ) == "decoded"
    assert calls == [["x-invalid-charset", "utf-8", "latin-1"]]

    def _none(_entry: tuple[str, bytes]) -> str | None:
        return None

    assert decode_email_part_text(
        _Part(None),
        "fallback text".encode("utf-8"),
        max_artifact_member_bytes=8,
        run_ordered_static_batch=_run_ordered_static_batch,
        decode_email_part_entry=_none,
    ) == "fallback"


def test_archive_stream_helpers_detect_and_decompress_common_formats() -> None:
    payload = b"owner@acme.example https://archive.acme.example"

    assert archive_stream_kind(gzip.compress(payload), "nested/member.bin") == "gz"
    assert archive_stream_kind(b"BZh" + b"not-real", "member.bin") == "bz2"
    assert archive_stream_kind(b"", "bundle.tar.xz") == "xz"
    assert archive_stream_kind(b"", "plain.txt") == ""

    assert decompress_archive_stream_bytes(
        gzip.compress(payload),
        "member.gz",
        remote_artifact_max_bytes=1024,
    ) == ("gz", payload)
    assert decompress_archive_stream_bytes(
        bz2.compress(payload),
        "member.bz2",
        remote_artifact_max_bytes=1024,
    ) == ("bz2", payload)
    assert decompress_archive_stream_bytes(
        lzma.compress(payload),
        "member.xz",
        remote_artifact_max_bytes=1024,
    ) == ("xz", payload)
    assert decompress_archive_stream_bytes(
        gzip.compress(payload),
        "member.gz",
        remote_artifact_max_bytes=4,
    ) == ("gz", payload)
    assert decompress_archive_stream_bytes(b"not-compressed", "plain.txt", remote_artifact_max_bytes=1024) is None


def test_text_member_entry_helpers_filter_dirs_and_oversized_members() -> None:
    limit_calls: list[str] = []

    def _limit(member_name: str) -> int:
        limit_calls.append(member_name)
        return 4

    zip_file = zipfile.ZipInfo("app/config.yml")
    zip_file.file_size = 4
    zip_large = zipfile.ZipInfo("app/large.yml")
    zip_large.file_size = 5

    assert text_zip_member_entry(zip_file, artifact_member_scan_byte_limit=_limit) == {
        "name": "app/config.yml",
    }
    assert text_zip_member_entry(zipfile.ZipInfo("app/"), artifact_member_scan_byte_limit=_limit) is None
    assert text_zip_member_entry(zip_large, artifact_member_scan_byte_limit=_limit) is None

    tar_file = tarfile.TarInfo("app/config.yml")
    tar_file.size = 4
    tar_dir = tarfile.TarInfo("app")
    tar_dir.type = tarfile.DIRTYPE
    tar_large = tarfile.TarInfo("app/large.yml")
    tar_large.size = 5

    assert text_tar_member_entry(tar_file, artifact_member_scan_byte_limit=_limit) == {
        "name": "app/config.yml",
    }
    assert text_tar_member_entry(tar_dir, artifact_member_scan_byte_limit=_limit) is None
    assert text_tar_member_entry(tar_large, artifact_member_scan_byte_limit=_limit) is None
    assert limit_calls == [
        "app/config.yml",
        "app/large.yml",
        "app/config.yml",
        "app/large.yml",
    ]


def test_text_7z_member_entry_normalizes_target_and_rejects_unsafe_members() -> None:
    def _limit(_member_name: str) -> int:
        return 10

    assert text_7z_member_entry(
        SimpleNamespace(
            filename="nested\\config.json",
            is_directory=False,
            is_symlink=False,
            is_file=True,
            uncompressed="10",
        ),
        artifact_member_scan_byte_limit=_limit,
    ) == {"name": "nested/config.json", "target": "nested\\config.json"}
    assert text_7z_member_entry(
        SimpleNamespace(filename="../secret.txt", is_directory=False, is_symlink=False, is_file=True, uncompressed=1),
        artifact_member_scan_byte_limit=_limit,
    ) is None
    assert text_7z_member_entry(
        SimpleNamespace(filename="nested/link", is_directory=False, is_symlink=True, is_file=True, uncompressed=1),
        artifact_member_scan_byte_limit=_limit,
    ) is None
    assert text_7z_member_entry(
        SimpleNamespace(filename="nested/large.txt", is_directory=False, is_symlink=False, is_file=True, uncompressed=11),
        artifact_member_scan_byte_limit=_limit,
    ) is None


def test_text_member_job_normalizes_name_and_rejects_empty_payloads() -> None:
    assert text_member_job((" member.txt ", b"payload")) == ("member.txt", b"payload")
    assert text_member_job(("", b"payload")) is None
    assert text_member_job(("member.txt", b"")) is None


def test_extract_text_member_payloads_from_jobs_filters_extracts_and_flattens_in_order() -> None:
    calls: list[str] = []

    def _run_ordered_batch(items: Any, worker: Any, *, default_factory: Any) -> list[Any]:
        del default_factory
        return [worker(item) for item in items]

    def _text_member_job(member_job: tuple[str, bytes]) -> tuple[str, bytes] | None:
        calls.append(f"job:{member_job[0]}")
        return text_member_job(member_job)

    def _extract_member_data_payloads(
        data: bytes,
        source_file: str,
        member_name: str,
        *,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"extract:{member_name}:{depth}")
        return [(source_file, member_name, data.decode("utf-8"))]

    def _artifact_payload_tuple_batch_entries(
        entry: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        member_index, payloads = entry
        calls.append(f"flatten:{member_index}")
        return payloads

    payloads = extract_text_member_payloads_from_jobs(
        [
            (" member-1.txt ", b"one"),
            ("", b"skip"),
            ("member-2.txt", b"two"),
        ],
        source_file="archive.zip",
        depth=2,
        run_ordered_batch=_run_ordered_batch,
        text_member_job=_text_member_job,
        extract_member_data_payloads=_extract_member_data_payloads,
        artifact_payload_tuple_batch_entries=_artifact_payload_tuple_batch_entries,
    )

    assert payloads == [
        ("archive.zip", "member-1.txt", "one"),
        ("archive.zip", "member-2.txt", "two"),
    ]
    assert calls == [
        "job: member-1.txt ",
        "job:",
        "job:member-2.txt",
        "extract:member-1.txt:2",
        "extract:member-2.txt:2",
        "flatten:0",
        "flatten:1",
    ]


def test_extract_archive_bytes_payloads_short_circuits_warc_and_pcap() -> None:
    calls: list[str] = []

    def _run_ordered_batch(_items: Any, _worker: Any, *, default_factory: Any) -> list[Any]:
        calls.append("batch")
        return [default_factory()]

    def _warc(data: bytes, source_file: str, member_name: str) -> list[tuple[str, str, str]]:
        calls.append(f"warc:{len(data)}:{source_file}:{member_name}")
        return [(source_file, member_name, "warc")]

    def _pcap(data: bytes, source_file: str, member_name: str) -> list[tuple[str, str, str]]:
        calls.append(f"pcap:{len(data)}:{source_file}:{member_name}")
        return [(source_file, member_name, "pcap")]

    assert extract_archive_bytes_payloads(
        b"warc-payload",
        "archive.bin",
        "member.warc",
        depth=0,
        max_artifact_member_bytes=4,
        run_ordered_batch=_run_ordered_batch,
        looks_like_warc_bytes=lambda _data, _name: True,
        extract_warc_bytes_payloads=_warc,
        looks_like_pcap_bytes=lambda _data, _name: True,
        extract_pcap_bytes_payloads=_pcap,
        extract_archive_payload_family=lambda *_args, **_kwargs: [],
    ) == [("archive.bin", "member.warc", "warc")]
    assert calls == ["warc:4:archive.bin:member.warc"]

    calls.clear()
    assert extract_archive_bytes_payloads(
        b"pcap-payload",
        "archive.bin",
        "member.pcap",
        depth=0,
        max_artifact_member_bytes=5,
        run_ordered_batch=_run_ordered_batch,
        looks_like_warc_bytes=lambda _data, _name: False,
        extract_warc_bytes_payloads=_warc,
        looks_like_pcap_bytes=lambda _data, _name: True,
        extract_pcap_bytes_payloads=_pcap,
        extract_archive_payload_family=lambda *_args, **_kwargs: [],
    ) == [("archive.bin", "member.pcap", "pcap")]
    assert calls == ["pcap:5:archive.bin:member.pcap"]


def test_extract_archive_bytes_payloads_uses_ordered_family_precedence() -> None:
    calls: list[str] = []

    def _run_ordered_batch(items: Any, worker: Any, *, default_factory: Any) -> list[Any]:
        del default_factory
        return [worker(item) for item in items]

    def _family(
        family: str,
        *,
        data: bytes,
        source_file: str,
        member_name: str,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"{family}:{len(data)}:{source_file}:{member_name}:{depth}")
        if family == "tar":
            return [(source_file, "tar/member.txt", "tar-payload")]
        if family == "asar":
            return [(source_file, "asar/member.txt", "asar-payload")]
        return []

    assert extract_archive_bytes_payloads(
        b"archive",
        "archive.bin",
        "member.bin",
        depth=1,
        max_artifact_member_bytes=1024,
        run_ordered_batch=_run_ordered_batch,
        looks_like_warc_bytes=lambda _data, _name: False,
        extract_warc_bytes_payloads=lambda *_args: [],
        looks_like_pcap_bytes=lambda _data, _name: False,
        extract_pcap_bytes_payloads=lambda *_args: [],
        extract_archive_payload_family=_family,
    ) == [("archive.bin", "tar/member.txt", "tar-payload")]
    assert calls == [
        "crx:7:archive.bin:member.bin:1",
        "zip:7:archive.bin:member.bin:1",
        "7z:7:archive.bin:member.bin:1",
        "ar:7:archive.bin:member.bin:1",
        "tar:7:archive.bin:member.bin:1",
        "cpio:7:archive.bin:member.bin:1",
        "asar:7:archive.bin:member.bin:1",
        "decompress:7:archive.bin:member.bin:1",
    ]


def test_extract_archive_payload_family_dispatches_callbacks() -> None:
    calls: list[str] = []

    def _payload_callback(name: str) -> Any:
        def _callback(
            data: bytes,
            *,
            source_file: str,
            depth: int,
        ) -> list[tuple[str, str, str]]:
            calls.append(f"{name}:{data.decode()}:{source_file}:{depth}")
            return [(source_file, f"{name}/member.txt", name)]

        return _callback

    def _decompress(
        data: bytes,
        *,
        source_file: str,
        member_name: str,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"decompress:{data.decode()}:{source_file}:{member_name}:{depth}")
        return [(source_file, f"{member_name}#decompressed", "decompress")]

    callbacks = {
        "extract_archive_crx_payloads": _payload_callback("crx"),
        "extract_archive_zip_payloads": _payload_callback("zip"),
        "extract_archive_7z_payloads": _payload_callback("7z"),
        "extract_archive_ar_payloads": _payload_callback("ar"),
        "extract_archive_tar_payloads": _payload_callback("tar"),
        "extract_archive_cpio_payloads": _payload_callback("cpio"),
        "extract_archive_asar_payloads": _payload_callback("asar"),
        "extract_archive_decompressed_payloads": _decompress,
    }

    assert extract_archive_payload_family(
        "zip",
        data=b"data",
        source_file="archive.bin",
        member_name="member.zip",
        depth=2,
        **callbacks,
    ) == [("archive.bin", "zip/member.txt", "zip")]
    assert extract_archive_payload_family(
        "decompress",
        data=b"data",
        source_file="archive.bin",
        member_name="member.gz",
        depth=2,
        **callbacks,
    ) == [("archive.bin", "member.gz#decompressed", "decompress")]
    assert extract_archive_payload_family(
        "unknown",
        data=b"data",
        source_file="archive.bin",
        member_name="member.bin",
        depth=2,
        **callbacks,
    ) == []
    assert calls == [
        "zip:data:archive.bin:2",
        "decompress:data:archive.bin:member.gz:2",
    ]


def test_extract_archive_7z_payloads_gates_on_py7zr_and_magic() -> None:
    calls: list[str] = []

    def _extract_text_payloads(data: bytes, source_file: str) -> list[tuple[str, str, str]]:
        calls.append(f"extract:{data.hex()}:{source_file}")
        return [(source_file, "member.txt", "payload")]

    assert extract_archive_7z_payloads(
        SEVEN_Z_ARCHIVE_MAGIC + b"payload",
        source_file="archive.7z",
        depth=1,
        py7zr_available=False,
        extract_text_payloads_from_7z=_extract_text_payloads,
    ) == []
    assert extract_archive_7z_payloads(
        b"not-7z",
        source_file="archive.bin",
        depth=1,
        py7zr_available=True,
        extract_text_payloads_from_7z=_extract_text_payloads,
    ) == []
    assert extract_archive_7z_payloads(
        SEVEN_Z_ARCHIVE_MAGIC + b"payload",
        source_file="archive.7z",
        depth=3,
        py7zr_available=True,
        extract_text_payloads_from_7z=_extract_text_payloads,
    ) == [("archive.7z", "member.txt", "payload")]
    assert calls == [f"extract:{(SEVEN_Z_ARCHIVE_MAGIC + b'payload').hex()}:archive.7z"]


def test_looks_like_archive_bytes_recognizes_common_archive_signatures() -> None:
    assert looks_like_archive_bytes(
        b"PK\x03\x04zip",
        asar_header_and_content_base=lambda _data: None,
    )
    assert looks_like_archive_bytes(
        b"\x1f\x8b\x08gz",
        asar_header_and_content_base=lambda _data: None,
    )
    assert looks_like_archive_bytes(
        SEVEN_Z_ARCHIVE_MAGIC + b"payload",
        asar_header_and_content_base=lambda _data: None,
    )
    assert looks_like_archive_bytes(
        AR_ARCHIVE_MAGIC + b"payload",
        asar_header_and_content_base=lambda _data: None,
    )
    assert looks_like_archive_bytes(
        CPIO_NEWC_MAGICS[0] + b"payload",
        asar_header_and_content_base=lambda _data: None,
    )
    assert looks_like_archive_bytes(
        b"\x00" * 257 + b"ustar" + b"\x00",
        asar_header_and_content_base=lambda _data: None,
    )
    assert looks_like_archive_bytes(
        b"custom-asar",
        asar_header_and_content_base=lambda _data: ({}, 12),
    )
    assert not looks_like_archive_bytes(
        b"plain text",
        asar_header_and_content_base=lambda _data: None,
    )


def test_embedded_archive_signature_and_match_helpers_normalize_entries() -> None:
    data = b"root" + b"PK\x03\x04" + b"x" * 4 + b"PK\x03\x04"

    assert embedded_archive_signature_matches(
        ("zip", b"PK\x03\x04"),
        data=data,
        max_scan=len(data),
    ) == [("zip", 4), ("zip", 12)]
    assert embedded_archive_signature_matches(
        ("zip", b"PK\x03\x04"),
        data=b"PK\x03\x04root",
        max_scan=8,
    ) == []
    assert embedded_archive_match_entry((0, ("zip", "4"))) == ("zip", 4)
    assert embedded_archive_match_entry((0, ("", 4))) is None
    assert embedded_archive_match_entry((0, ("zip", 0))) is None
    assert embedded_archive_match_entry((0, ("zip", "bad"))) is None
    assert embedded_archive_match_entry((0, ("zip",))) is None


def test_embedded_archive_offsets_dedupes_and_sorts_matches() -> None:
    data = bytearray(b"x" * 96)
    data[11:15] = b"PK\x03\x04"
    data[23:26] = b"\x1f\x8b\x08"
    data[37:40] = b"BZh"
    data[49:55] = b"\xfd7zXZ\x00"
    calls: list[str] = []

    def _signature_matches(
        signature_job: tuple[str, bytes],
        *,
        data: bytes,
        max_scan: int,
    ) -> list[tuple[str, int]]:
        calls.append(f"signature:{signature_job[0]}:{max_scan}")
        if signature_job[0] == "zip":
            return [("zip", 11), ("zip", 11)]
        return embedded_archive_signature_matches(signature_job, data=data, max_scan=max_scan)

    def _match_entry(match_entry: tuple[int, tuple[str, int]]) -> tuple[str, int] | None:
        calls.append(f"match:{match_entry[0]}")
        return embedded_archive_match_entry(match_entry)

    assert embedded_archive_offsets(
        bytes(data),
        max_artifact_member_bytes=64,
        run_ordered_batch=_run_ordered_batch,
        embedded_archive_signature_matches=_signature_matches,
        embedded_archive_match_entry=_match_entry,
        signatures=EMBEDDED_ARCHIVE_SIGNATURES[:4],
    ) == [
        ("zip", 11),
        ("gz", 23),
        ("bz2", 37),
        ("xz", 49),
    ]
    assert embedded_archive_offsets(
        b"short",
        max_artifact_member_bytes=64,
        run_ordered_batch=_run_ordered_batch,
        embedded_archive_signature_matches=_signature_matches,
        embedded_archive_match_entry=_match_entry,
    ) == []
    assert calls[:4] == [
        "signature:zip:64",
        "signature:gz:64",
        "signature:bz2:64",
        "signature:xz:64",
    ]


def test_embedded_archive_job_entry_slices_blob_and_increments_depth() -> None:
    data = b"prefixPK\x03\x04payload"

    job = embedded_archive_job_entry(
        ("zip", 6),
        source_file="source.doc",
        member_name="word/document.xml",
        data=data,
        depth=1,
    )

    assert job == EmbeddedArchiveExtractionJob(
        "source.doc",
        "word/document.xml",
        "zip",
        6,
        b"PK\x03\x04payload",
        2,
    )
    assert embedded_archive_job_entry(
        ("zip", -1),
        source_file="source.doc",
        member_name="word/document.xml",
        data=data,
        depth=1,
    ) is None


def test_extract_embedded_archive_payloads_coordinates_jobs_in_order() -> None:
    data = b"prefix" + b"archive-markers" * 4
    calls: list[str] = []

    def _offsets(payload: bytes) -> list[tuple[str, int]]:
        calls.append(f"offsets:{len(payload)}")
        return [("zip", 6), ("gz", 13), ("xz", 21), ("7z", 29)]

    def _extract_job(job: EmbeddedArchiveExtractionJob) -> list[tuple[str, str, str]]:
        calls.append(f"extract:{job.archive_kind}:{job.offset}:{job.depth}")
        return [
            (
                job.source_file,
                f"{job.member_name}#carved-{job.archive_kind}-{job.offset}",
                job.blob[:3].hex(),
            )
        ]

    def _tuple_entries(
        item: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        calls.append(f"batch:{item[0]}:{len(item[1])}")
        return item[1]

    assert extract_embedded_archive_payloads(
        data,
        "source.doc",
        "word/document.xml",
        depth=0,
        embedded_archive_offsets=_offsets,
        run_ordered_batch=_run_ordered_batch,
        embedded_archive_job_entry=embedded_archive_job_entry,
        extract_embedded_archive_job=_extract_job,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == [
        ("source.doc", "word/document.xml#carved-zip-6", data[6:9].hex()),
        ("source.doc", "word/document.xml#carved-gz-13", data[13:16].hex()),
        ("source.doc", "word/document.xml#carved-xz-21", data[21:24].hex()),
    ]
    assert extract_embedded_archive_payloads(
        data,
        "source.doc",
        "word/document.xml",
        depth=2,
        embedded_archive_offsets=_offsets,
        run_ordered_batch=_run_ordered_batch,
        embedded_archive_job_entry=embedded_archive_job_entry,
        extract_embedded_archive_job=_extract_job,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == []
    assert calls == [
        f"offsets:{len(data)}",
        "extract:zip:6:1",
        "extract:gz:13:1",
        "extract:xz:21:1",
        "batch:0:1",
        "batch:1:1",
        "batch:2:1",
    ]


def test_embedded_image_signature_and_byte_helpers_filter_and_slice_images() -> None:
    png = b"\x89PNG\r\n\x1a\nbodyIENDcrc!"
    jpeg = b"\xff\xd8\xffbody\xff\xd9"
    gif = b"GIF89abody;"
    webp = b"RIFF" + (8).to_bytes(4, "little") + b"WEBPdata"
    tiff = b"II*\x00payload"
    data = b"bad-RIFFxxxxNOPE" + webp

    assert embedded_image_signature_matches(
        ("webp", ".webp", b"RIFF"),
        data=data,
        max_scan=len(data),
    ) == [("webp", ".webp", 16)]
    assert embedded_image_bytes(
        "png",
        png,
        0,
        max_ocr_image_bytes=64,
    ) == png
    assert embedded_image_bytes(
        "jpeg",
        jpeg,
        0,
        max_ocr_image_bytes=64,
    ) == jpeg
    assert embedded_image_bytes(
        "gif",
        gif,
        0,
        max_ocr_image_bytes=64,
    ) == gif
    assert embedded_image_bytes(
        "webp",
        webp,
        0,
        max_ocr_image_bytes=64,
    ) == webp
    assert embedded_image_bytes(
        "tiff",
        tiff,
        0,
        next_offset=len(tiff),
        max_ocr_image_bytes=64,
    ) == tiff
    assert embedded_image_bytes("png", png, -1, max_ocr_image_bytes=64) == b""
    assert embedded_image_bytes("png", png, 0, max_ocr_image_bytes=8) == b""
    assert embedded_image_bytes("webp", data, 0, max_ocr_image_bytes=64) == b""
    assert embedded_image_bytes("unknown", png, 0, max_ocr_image_bytes=64) == b""


def test_embedded_image_entries_dedupes_sorts_caps_and_skips_overlaps() -> None:
    png = b"\x89PNG\r\n\x1a\nbodyIENDcrc!"
    jpeg = b"\xff\xd8\xffbody\xff\xd9"
    gif = b"GIF89abody;"
    data = b"prefix" + jpeg + b"middle" + png + gif
    jpeg_offset = data.index(jpeg)
    png_offset = data.index(png)
    gif_offset = data.index(gif)
    calls: list[str] = []

    def _signature_matches(
        signature_job: tuple[str, str, bytes],
        *,
        data: bytes,
        max_scan: int,
    ) -> list[tuple[str, str, int]]:
        calls.append(f"signature:{signature_job[0]}:{max_scan}")
        return embedded_image_signature_matches(
            signature_job,
            data=data,
            max_scan=max_scan,
        )

    def _bytes(
        image_kind: str,
        data: bytes,
        offset: int,
        *,
        next_offset: int = 0,
        max_ocr_image_bytes: int,
    ) -> bytes:
        calls.append(f"bytes:{image_kind}:{offset}:{next_offset}:{max_ocr_image_bytes}")
        return embedded_image_bytes(
            image_kind,
            data,
            offset,
            next_offset=next_offset,
            max_ocr_image_bytes=max_ocr_image_bytes,
        )

    entries = embedded_image_entries(
        data,
        max_artifact_member_bytes=128,
        max_ocr_image_bytes=64,
        embedded_image_max_candidates=2,
        run_ordered_batch=_run_ordered_batch,
        embedded_image_signature_matches=_signature_matches,
        embedded_image_bytes=_bytes,
        signatures=(
            ("png", ".png", b"\x89PNG\r\n\x1a\n"),
            ("png-duplicate", ".png", b"\x89PNG\r\n\x1a\n"),
            ("jpeg", ".jpg", b"\xff\xd8\xff"),
            ("gif", ".gif", b"GIF89a"),
        ),
    )

    assert entries == [
        ("jpeg", ".jpg", jpeg_offset, jpeg),
        ("png", ".png", png_offset, png),
    ]
    assert calls[:4] == [
        f"signature:png:{len(data)}",
        f"signature:png-duplicate:{len(data)}",
        f"signature:jpeg:{len(data)}",
        f"signature:gif:{len(data)}",
    ]
    assert f"bytes:gif:{gif_offset}:0:64" not in calls

    assert embedded_image_entries(
        b"short",
        max_artifact_member_bytes=128,
        max_ocr_image_bytes=64,
        embedded_image_max_candidates=2,
        run_ordered_batch=_run_ordered_batch,
        embedded_image_signature_matches=_signature_matches,
        embedded_image_bytes=_bytes,
    ) == []


def test_extract_image_payloads_coordinates_families_and_flattens_batches() -> None:
    path = Path("screenshot.png")
    calls: list[str] = []

    def _family(family: str, image_path: Path) -> list[tuple[str, str, str]]:
        calls.append(f"family:{family}:{image_path.name}")
        if family == "barcode":
            return []
        return [(str(image_path), f"{image_path.name}#{family}", family)]

    def _tuple_entries(
        item: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        index, payloads = item
        calls.append(f"batch:{index}:{len(payloads)}")
        return payloads

    assert extract_image_payloads(
        path,
        run_ordered_batch=_run_ordered_batch,
        extract_image_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == [
        ("screenshot.png", "screenshot.png#ocr", "ocr"),
        ("screenshot.png", "screenshot.png#metadata", "metadata"),
    ]
    assert calls == [
        "family:ocr:screenshot.png",
        "family:barcode:screenshot.png",
        "family:metadata:screenshot.png",
        "batch:0:1",
        "batch:1:0",
        "batch:2:1",
    ]


def test_extract_image_member_payloads_coordinates_families_and_flattens_batches() -> None:
    calls: list[str] = []

    def _family(
        family: str,
        *,
        source_file: str,
        member_name: str,
        data: bytes,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"family:{family}:{source_file}:{member_name}:{data.decode()}")
        if family == "metadata":
            return []
        return [(source_file, f"{member_name}#{family}", family)]

    def _tuple_entries(
        item: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        index, payloads = item
        calls.append(f"batch:{index}:{len(payloads)}")
        return payloads

    assert extract_image_member_payloads(
        "archive.zip",
        "images/logo.png",
        b"image",
        run_ordered_batch=_run_ordered_batch,
        extract_image_member_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == [
        ("archive.zip", "images/logo.png#ocr", "ocr"),
        ("archive.zip", "images/logo.png#barcode", "barcode"),
    ]
    assert calls == [
        "family:ocr:archive.zip:images/logo.png:image",
        "family:barcode:archive.zip:images/logo.png:image",
        "family:metadata:archive.zip:images/logo.png:image",
        "batch:0:1",
        "batch:1:1",
        "batch:2:0",
    ]


def test_extract_image_payload_family_dispatches_ocr_barcode_metadata_and_unknown(tmp_path: Path) -> None:
    image_path = tmp_path / "screenshot.png"
    image_path.write_bytes(b"metadata-owner@example.test-extra")
    calls: list[str] = []

    def _ocr(path: Path) -> str:
        calls.append(f"ocr:{path.name}")
        return " owner@example.test "

    def _barcode(path: Path) -> str:
        calls.append(f"barcode:{path.name}")
        return "https://barcode.example.test"

    def _metadata(data: bytes) -> str:
        calls.append(f"metadata:{data.decode()}")
        return "metadata@example.test"

    assert extract_image_payload_family(
        "ocr",
        image_path,
        ocr_image_path=_ocr,
        barcode_image_path_payload=_barcode,
        image_metadata_payload=_metadata,
        max_ocr_image_bytes=8,
    ) == [(str(image_path), "screenshot.png#ocr", " owner@example.test ")]
    assert extract_image_payload_family(
        "barcode",
        image_path,
        ocr_image_path=_ocr,
        barcode_image_path_payload=_barcode,
        image_metadata_payload=_metadata,
        max_ocr_image_bytes=8,
    ) == [(str(image_path), "screenshot.png#barcode", "https://barcode.example.test")]
    assert extract_image_payload_family(
        "metadata",
        image_path,
        ocr_image_path=_ocr,
        barcode_image_path_payload=_barcode,
        image_metadata_payload=_metadata,
        max_ocr_image_bytes=8,
    ) == [(str(image_path), "screenshot.png#image-metadata", "metadata@example.test")]
    assert extract_image_payload_family(
        "unknown",
        image_path,
        ocr_image_path=_ocr,
        barcode_image_path_payload=_barcode,
        image_metadata_payload=_metadata,
        max_ocr_image_bytes=8,
    ) == []
    assert extract_image_payload_family(
        "metadata",
        tmp_path / "missing.png",
        ocr_image_path=_ocr,
        barcode_image_path_payload=_barcode,
        image_metadata_payload=_metadata,
        max_ocr_image_bytes=8,
    ) == []
    assert calls == [
        "ocr:screenshot.png",
        "barcode:screenshot.png",
        "metadata:metadata",
    ]


def test_extract_image_member_payload_family_dispatches_ocr_barcode_metadata_and_unknown() -> None:
    calls: list[str] = []

    def _ocr(data: bytes, suffix: str) -> str:
        calls.append(f"ocr:{data.decode()}:{suffix}")
        return "member-owner@example.test"

    def _barcode(data: bytes) -> str:
        calls.append(f"barcode:{data.decode()}")
        return "https://member-barcode.example.test"

    def _metadata(data: bytes) -> str:
        calls.append(f"metadata:{data.decode()}")
        return "member-metadata@example.test"

    assert extract_image_member_payload_family(
        "ocr",
        source_file="archive.zip",
        member_name="images/logo.png",
        data=b"member-image-data",
        ocr_image_bytes=_ocr,
        barcode_image_bytes_payload=_barcode,
        image_metadata_payload=_metadata,
        max_ocr_image_bytes=6,
    ) == [("archive.zip", "images/logo.png#ocr", "member-owner@example.test")]
    assert extract_image_member_payload_family(
        "barcode",
        source_file="archive.zip",
        member_name="images/logo.png",
        data=b"member-image-data",
        ocr_image_bytes=_ocr,
        barcode_image_bytes_payload=_barcode,
        image_metadata_payload=_metadata,
        max_ocr_image_bytes=6,
    ) == [("archive.zip", "images/logo.png#barcode", "https://member-barcode.example.test")]
    assert extract_image_member_payload_family(
        "metadata",
        source_file="archive.zip",
        member_name="images/logo.png",
        data=b"member-image-data",
        ocr_image_bytes=_ocr,
        barcode_image_bytes_payload=_barcode,
        image_metadata_payload=_metadata,
        max_ocr_image_bytes=6,
    ) == [("archive.zip", "images/logo.png#image-metadata", "member-metadata@example.test")]
    assert extract_image_member_payload_family(
        "unknown",
        source_file="archive.zip",
        member_name="images/logo.png",
        data=b"member-image-data",
        ocr_image_bytes=_ocr,
        barcode_image_bytes_payload=_barcode,
        image_metadata_payload=_metadata,
        max_ocr_image_bytes=6,
    ) == []
    assert calls == [
        "ocr:member-image-data:.png",
        "barcode:member-image-data",
        "metadata:member",
    ]


def test_image_metadata_and_barcode_payload_helpers_delegate_join_and_bound_bytes(tmp_path: Path) -> None:
    image_path = tmp_path / "poster.png"
    image_path.write_bytes(b"image")
    calls: list[str] = []

    def _binary_payload(data: bytes) -> str:
        calls.append(f"binary:{data.decode()}")
        return "metadata-owner@example.test"

    def _barcodes_from_path(path: Path, *, max_bytes: int) -> list[str]:
        calls.append(f"path:{path.name}:{max_bytes}")
        return ["https://qr-one.example.test", "https://qr-two.example.test"]

    def _barcodes_from_bytes(data: bytes) -> list[str]:
        calls.append(f"bytes:{data.decode()}")
        return ["https://bytes.example.test"]

    assert image_metadata_payload(
        b"metadata",
        binary_string_payload=_binary_payload,
    ) == "metadata-owner@example.test"
    assert barcode_image_path_payload(
        image_path,
        barcode_payloads_from_path=_barcodes_from_path,
        max_ocr_image_bytes=16,
    ) == "https://qr-one.example.test\nhttps://qr-two.example.test"
    assert barcode_image_bytes_payload(
        b"barcode-bytes",
        barcode_payloads_from_bytes=_barcodes_from_bytes,
        max_ocr_image_bytes=7,
    ) == "https://bytes.example.test"
    assert calls == [
        "binary:metadata",
        "path:poster.png:16",
        "bytes:barcode",
    ]


def test_ocr_image_path_runs_binary_cleans_text_and_handles_failures(tmp_path: Path) -> None:
    image_path = tmp_path / "scan.png"
    image_path.write_bytes(b"image")
    calls: list[str] = []

    class _Proc:
        def __init__(self, returncode: int, stdout: str) -> None:
            self.returncode = returncode
            self.stdout = stdout

    def _run(command: list[str], **kwargs: Any) -> _Proc:
        calls.append(
            "|".join(command)
            + f":{kwargs['capture_output']}:{kwargs['text']}:{kwargs['timeout']}:{kwargs['check']}"
        )
        return _Proc(0, "  owner@example.test\x0c\nsecond-line  ")

    assert ocr_image_path(
        image_path,
        ocr_binary="tesseract",
        ocr_timeout_seconds=7,
        ocr_text_limit=18,
        subprocess_run=_run,
    ) == "owner@example.test"
    assert calls == [
        f"tesseract|{image_path}|stdout|--psm|6:True:True:7:False",
    ]

    assert ocr_image_path(
        image_path,
        ocr_binary=None,
        ocr_timeout_seconds=7,
        ocr_text_limit=18,
        subprocess_run=_run,
    ) == ""
    assert ocr_image_path(
        tmp_path / "missing.png",
        ocr_binary="tesseract",
        ocr_timeout_seconds=7,
        ocr_text_limit=18,
        subprocess_run=_run,
    ) == ""

    def _failed_run(*_args: Any, **_kwargs: Any) -> _Proc:
        return _Proc(1, "ignored")

    def _raising_run(*_args: Any, **_kwargs: Any) -> _Proc:
        raise OSError("boom")

    assert ocr_image_path(
        image_path,
        ocr_binary="tesseract",
        ocr_timeout_seconds=7,
        ocr_text_limit=18,
        subprocess_run=_failed_run,
    ) == ""
    assert ocr_image_path(
        image_path,
        ocr_binary="tesseract",
        ocr_timeout_seconds=7,
        ocr_text_limit=18,
        subprocess_run=_raising_run,
    ) == ""


def test_ocr_image_bytes_writes_bounded_temp_file_uses_suffix_fallback_and_cleans_up() -> None:
    calls: list[str] = []
    temp_paths: list[Path] = []

    def _ocr_path(path: Path) -> str:
        temp_paths.append(path)
        calls.append(f"path:{path.suffix}:{path.exists()}:{path.read_bytes().decode()}")
        return "bytes-owner@example.test"

    assert ocr_image_bytes(
        b"image-bytes",
        ".png",
        max_ocr_image_bytes=5,
        ocr_image_path=_ocr_path,
    ) == "bytes-owner@example.test"
    assert temp_paths
    assert not temp_paths[-1].exists()

    assert ocr_image_bytes(
        b"fallback-bytes",
        "",
        max_ocr_image_bytes=8,
        ocr_image_path=_ocr_path,
    ) == "bytes-owner@example.test"
    assert not temp_paths[-1].exists()
    assert calls == [
        "path:.png:True:image",
        "path:.img:True:fallback",
    ]


def test_pdf_ocr_page_helpers_shape_jobs_and_retain_rendered_images(tmp_path: Path) -> None:
    source = tmp_path / "rendered-page-1.png"
    source.write_bytes(b"rendered-page")

    assert pdf_ocr_page_job((1, source)) == (1, source)
    assert pdf_ocr_page_job((0, source)) is None

    retained = retained_pdf_ocr_image_path(source)
    assert retained is not None
    try:
        assert retained.exists()
        assert retained.suffix == ".png"
        assert retained.read_bytes() == b"rendered-page"
        assert retained != source
    finally:
        retained.unlink(missing_ok=True)

    assert retained_pdf_ocr_image_path(tmp_path / "missing.png") is None


def test_render_pdf_pages_for_ocr_runs_raster_retains_pages_and_cleans_temp(tmp_path: Path) -> None:
    pdf_path = tmp_path / "briefing.pdf"
    pdf_path.write_bytes(b"%PDF")
    calls: list[str] = []
    raster_temp_root: Path | None = None

    class _Proc:
        returncode = 0

    def _run(command: list[str], **kwargs: Any) -> _Proc:
        nonlocal raster_temp_root
        output_prefix = Path(command[-1])
        raster_temp_root = output_prefix.parent
        calls.append(
            "run:"
            + "|".join(command[:-1])
            + f"|{output_prefix.name}:"
            + f"{kwargs['capture_output']}:{kwargs['text']}:{kwargs['timeout']}:{kwargs['check']}"
        )
        (output_prefix.parent / "page-2.png").write_bytes(b"two")
        (output_prefix.parent / "page-1.png").write_bytes(b"one")
        (output_prefix.parent / "page-3.png").write_bytes(b"three")
        return _Proc()

    def _retain(path: Path) -> Path | None:
        calls.append(f"retain:{path.name}")
        if path.name == "page-2.png":
            return None
        retained = tmp_path / f"retained-{path.name}"
        retained.write_bytes(path.read_bytes())
        return retained

    retained_paths = render_pdf_pages_for_ocr(
        pdf_path,
        pdf_raster_binary="pdftoppm",
        pdf_ocr_max_pages=2,
        pdf_render_timeout_seconds=9,
        run_ordered_batch=_run_ordered_batch,
        retained_pdf_ocr_image_path=_retain,
        subprocess_run=_run,
    )

    assert retained_paths == [tmp_path / "retained-page-1.png"]
    assert retained_paths[0].read_bytes() == b"one"
    assert raster_temp_root is not None
    assert not raster_temp_root.exists()
    assert calls == [
        f"run:pdftoppm|-png|-f|1|-l|2|{pdf_path}|page:True:True:9:False",
        "retain:page-1.png",
        "retain:page-2.png",
    ]


def test_render_pdf_pages_for_ocr_handles_disabled_missing_and_failed_raster(tmp_path: Path) -> None:
    pdf_path = tmp_path / "briefing.pdf"
    pdf_path.write_bytes(b"%PDF")
    calls: list[str] = []

    class _Proc:
        returncode = 1

    def _run(*_args: Any, **_kwargs: Any) -> _Proc:
        calls.append("run")
        return _Proc()

    def _retain(_path: Path) -> Path | None:
        raise AssertionError("failed raster should not retain images")

    assert render_pdf_pages_for_ocr(
        pdf_path,
        pdf_raster_binary=None,
        pdf_ocr_max_pages=2,
        pdf_render_timeout_seconds=9,
        run_ordered_batch=_run_ordered_batch,
        retained_pdf_ocr_image_path=_retain,
        subprocess_run=_run,
    ) == []
    assert render_pdf_pages_for_ocr(
        tmp_path / "missing.pdf",
        pdf_raster_binary="pdftoppm",
        pdf_ocr_max_pages=2,
        pdf_render_timeout_seconds=9,
        run_ordered_batch=_run_ordered_batch,
        retained_pdf_ocr_image_path=_retain,
        subprocess_run=_run,
    ) == []
    assert render_pdf_pages_for_ocr(
        pdf_path,
        pdf_raster_binary="pdftoppm",
        pdf_ocr_max_pages=2,
        pdf_render_timeout_seconds=9,
        run_ordered_batch=_run_ordered_batch,
        retained_pdf_ocr_image_path=_retain,
        subprocess_run=_run,
    ) == []
    assert calls == ["run"]


def test_extract_embedded_image_payloads_names_members_and_preserves_order() -> None:
    image_entries = [
        ("jpeg", ".jpg", 4, b"first"),
        ("png", ".png", 20, b"second"),
    ]
    calls: list[str] = []

    def _entries(data: bytes) -> list[tuple[str, str, int, bytes]]:
        calls.append(f"entries:{data.decode()}")
        return image_entries

    def _member_payloads(
        source_file: str,
        image_member_name: str,
        image_data: bytes,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"member:{image_member_name}:{image_data.decode()}")
        return [(source_file, f"{image_member_name}#ocr", image_data.decode())]

    assert embedded_image_payload_batch(
        (3, ("gif", ".gif", 11, b"third")),
        source_file="source.doc",
        member_name="word/media.bin",
        extract_image_member_payloads=_member_payloads,
    ) == [
        ("source.doc", "word/media.bin#embedded-image-3.gif#ocr", "third"),
    ]

    assert extract_embedded_image_payloads(
        b"blob",
        "source.doc",
        "word/media.bin",
        embedded_image_entries=_entries,
        run_ordered_batch=_run_ordered_batch,
        embedded_image_payload_batch=lambda entry, **kwargs: embedded_image_payload_batch(
            entry,
            extract_image_member_payloads=_member_payloads,
            **kwargs,
        ),
    ) == [
        ("source.doc", "word/media.bin#embedded-image-0.jpg#ocr", "first"),
        ("source.doc", "word/media.bin#embedded-image-1.png#ocr", "second"),
    ]
    assert extract_embedded_image_payloads(
        b"empty",
        "source.doc",
        "word/media.bin",
        embedded_image_entries=lambda _data: [],
        run_ordered_batch=_run_ordered_batch,
        embedded_image_payload_batch=lambda entry, **kwargs: embedded_image_payload_batch(
            entry,
            extract_image_member_payloads=_member_payloads,
            **kwargs,
        ),
    ) == []
    assert calls == [
        "member:word/media.bin#embedded-image-3.gif:third",
        "entries:blob",
        "member:word/media.bin#embedded-image-0.jpg:first",
        "member:word/media.bin#embedded-image-1.png:second",
    ]


def test_binary_string_payload_coordinates_families_dedupes_and_caps_values() -> None:
    calls: list[str] = []

    def _candidate_family(data: bytes, family: str) -> list[str]:
        calls.append(f"family:{family}:{data.decode()}")
        if family == "ascii":
            return ["owner@example.com", "duplicate.example", ""]
        if family == "utf16":
            return ["duplicate.example", "portal.example", "drop-me"]
        return []

    def _family_entries(item: tuple[int, list[str]]) -> list[str]:
        index, candidates = item
        calls.append(f"entries:{index}:{len(candidates)}")
        return candidates

    def _value_entry(item: tuple[int, str]) -> str | None:
        index, candidate = item
        calls.append(f"value:{index}:{candidate}")
        if candidate == "drop-me":
            return None
        return candidate.strip() or None

    assert binary_string_payload(
        b"binary",
        run_ordered_batch=_run_ordered_batch,
        binary_string_candidate_family=_candidate_family,
        binary_string_family_entries=_family_entries,
        binary_string_value_entry=_value_entry,
        max_values=2,
    ) == "owner@example.com\nduplicate.example"
    assert calls == [
        "family:ascii:binary",
        "family:utf16:binary",
        "entries:0:3",
        "entries:1:3",
        "value:0:owner@example.com",
        "value:1:duplicate.example",
        "value:2:",
        "value:3:duplicate.example",
        "value:4:portal.example",
        "value:5:drop-me",
    ]


def test_binary_string_helper_entries_dispatch_and_filter_values() -> None:
    calls: list[str] = []

    def _ascii(data: bytes) -> list[str]:
        calls.append(f"ascii:{data.decode()}")
        return [" owner@example.com "]

    def _utf16(data: bytes) -> list[str]:
        calls.append(f"utf16:{data.decode()}")
        return [" portal.example "]

    assert binary_string_candidate_family(
        b"blob",
        "ascii",
        binary_string_ascii_candidates=_ascii,
        binary_string_utf16_candidates=_utf16,
    ) == [" owner@example.com "]
    assert binary_string_candidate_family(
        b"blob",
        "utf16",
        binary_string_ascii_candidates=_ascii,
        binary_string_utf16_candidates=_utf16,
    ) == [" portal.example "]
    assert binary_string_candidate_family(
        b"blob",
        "unknown",
        binary_string_ascii_candidates=_ascii,
        binary_string_utf16_candidates=_utf16,
    ) == []
    assert calls == ["ascii:blob", "utf16:blob"]

    assert binary_string_family_entries(
        (0, [" owner@example.com ", "", None, " https://portal.example "]),  # type: ignore[list-item]
    ) == ["owner@example.com", "https://portal.example"]
    assert binary_string_value_entry((0, " owner@example.com ")) == "owner@example.com"
    assert binary_string_value_entry((1, "  ")) is None
    assert interesting_binary_string("owner@example.com")
    assert interesting_binary_string("https://portal.example")
    assert interesting_binary_string("C:/Users/bryan")
    assert not interesting_binary_string("123456")
    assert not interesting_binary_string("short")
    assert not interesting_binary_string("x" * 513)


def test_binary_string_scanners_decode_filter_and_preserve_order() -> None:
    calls: list[bytes] = []

    def _ascii_candidate(raw_match: bytes) -> str:
        calls.append(raw_match)
        return binary_string_ascii_candidate(
            raw_match,
            interesting_binary_string=lambda value: "skip" not in value,
        )

    assert binary_string_ascii_candidate(b" owner@example.com ") == "owner@example.com"
    assert binary_string_ascii_candidate(b"123456") == ""
    assert binary_string_ascii_candidates(
        b"\x00owner@example.com\x00skip-value.example\x00https://portal.example\x00",
        run_ordered_batch=_run_ordered_batch,
        binary_string_ascii_candidate=_ascii_candidate,
    ) == [
        "owner@example.com",
        "https://portal.example",
    ]
    assert calls == [
        b"owner@example.com",
        b"skip-value.example",
        b"https://portal.example",
    ]

    utf16_calls: list[bytes] = []

    def _utf16_candidate(raw_match: bytes) -> str:
        utf16_calls.append(raw_match)
        return binary_string_utf16_candidate(
            raw_match,
            interesting_binary_string=lambda value: "skip" not in value,
        )

    first = "owner@example.com".encode("utf-16le")
    second = "skip-value.example".encode("utf-16le")
    third = "https://portal.example".encode("utf-16le")
    assert binary_string_utf16_candidate(first) == "owner@example.com"
    assert binary_string_utf16_candidate("123456".encode("utf-16le")) == ""
    assert binary_string_utf16_candidates(
        b"\xff\x00" + first + b"\x00\x00" + second + b"\x00\x00" + third,
        run_ordered_batch=_run_ordered_batch,
        binary_string_utf16_candidate=_utf16_candidate,
    ) == [
        "owner@example.com",
        "https://portal.example",
    ]
    assert utf16_calls == [first, second, third]


def test_ole_metadata_helpers_read_ordered_deduped_lines_and_handle_failures() -> None:
    class _Metadata:
        title = " Dossier "
        subject = "Dossier"
        author = ""
        last_saved_by = None
        comments = "Review"

        @property
        def keywords(self) -> str:
            raise RuntimeError("bad property")

        company = "Acme"
        manager = "Acme"

    class _Ole:
        def get_metadata(self) -> _Metadata:
            return _Metadata()

    class _FailingOle:
        def get_metadata(self) -> _Metadata:
            raise RuntimeError("bad metadata")

    calls: list[str] = []

    def _line(metadata: Any, key: str) -> str:
        calls.append(key)
        return ole_metadata_line(metadata, key)

    assert ole_metadata_line(_Metadata(), "title") == "title=Dossier"
    assert ole_metadata_line(_Metadata(), "author") == ""
    assert ole_metadata_line(_Metadata(), "keywords") == ""
    assert ole_metadata_lines(
        _Ole(),
        run_ordered_batch=_run_ordered_batch,
        ole_metadata_line=_line,
        max_lines=4,
    ) == [
        "title=Dossier",
        "subject=Dossier",
        "comments=Review",
        "company=Acme",
    ]
    assert calls == list(OLE_METADATA_KEYS)
    assert ole_metadata_lines(
        _FailingOle(),
        run_ordered_batch=_run_ordered_batch,
        ole_metadata_line=_line,
    ) == []


def test_extract_ole_metadata_payloads_joins_metadata_lines() -> None:
    assert extract_ole_metadata_payloads(
        ["title=Dossier", "author=Analyst"],
        source_file="artifact.doc",
        member_name="artifact.doc",
    ) == [
        (
            "artifact.doc",
            "artifact.doc#ole-metadata",
            "title=Dossier\nauthor=Analyst",
        )
    ]
    assert extract_ole_metadata_payloads(
        [],
        source_file="artifact.doc",
        member_name="artifact.doc",
    ) == []


def test_ole_raw_stream_entries_reads_bounded_streams_and_skips_failures() -> None:
    class _Stream:
        def __init__(self, payload: bytes) -> None:
            self.payload = payload

        def read(self, limit: int) -> bytes:
            return self.payload[:limit]

    class _Ole:
        def listdir(self, *, streams: bool, storages: bool) -> list[tuple[str, ...]]:
            assert streams is True
            assert storages is False
            return [("Workbook",), ("Broken",), ("Summary", "Info")]

        def openstream(self, stream_parts: tuple[str, ...]) -> _Stream:
            if stream_parts == ("Broken",):
                raise RuntimeError("bad stream")
            return _Stream("/".join(stream_parts).encode())

    assert ole_raw_stream_entries(
        _Ole(),
        max_artifact_member_bytes=8,
    ) == [
        (("Workbook",), b"Workbook"),
        (("Summary", "Info"), b"Summary/"),
    ]


def test_ole_stream_entry_normalizes_parts_and_filters_blank_names() -> None:
    assert ole_stream_entry((("Workbook", "Summary"), b"payload")) == (
        ("Workbook", "Summary"),
        b"payload",
    )
    assert ole_stream_entry((("", "  "), b"payload")) is None
    assert ole_stream_entry(((None, "", "  "), b"payload")) == (
        (None, "", "  "),
        b"payload",
    )
    assert ole_stream_entry((["One", "Two"], bytearray(b"payload"))) == (
        ("One", "Two"),
        b"payload",
    )


def test_ole_stream_job_builds_injected_job_type() -> None:
    def _job_type(**kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(**kwargs)

    job = ole_stream_job(
        (("Workbook", "Summary"), b"payload"),
        source_file="artifact.xls",
        member_name="artifact.xls",
        depth=1,
        ole_stream_extraction_job=_job_type,
    )

    assert job == SimpleNamespace(
        source_file="artifact.xls",
        member_name="artifact.xls",
        stream_name="Workbook/Summary",
        stream_data=b"payload",
        depth=1,
    )
    assert ole_stream_job(
        (("", " "), b"payload"),
        source_file="artifact.xls",
        member_name="artifact.xls",
        depth=1,
        ole_stream_extraction_job=_job_type,
    ) is None


def test_extract_ole_payload_family_dispatches_summary_streams_and_unknown() -> None:
    stream_jobs = [SimpleNamespace(stream_name="Workbook")]
    calls: list[str] = []

    def _metadata(
        metadata_lines: Sequence[str],
        *,
        source_file: str,
        member_name: str,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"summary:{source_file}:{member_name}:{len(metadata_lines)}")
        return [(source_file, f"{member_name}#summary", "\n".join(metadata_lines))]

    def _streams(jobs: Sequence[Any]) -> list[tuple[str, str, str]]:
        calls.append(f"streams:{len(jobs)}")
        return [("artifact.xls", "Workbook", "stream")]

    kwargs = {
        "metadata_lines": ["title=Dossier"],
        "stream_jobs": stream_jobs,
        "source_file": "artifact.xls",
        "member_name": "artifact.xls",
        "extract_ole_metadata_payloads": _metadata,
        "extract_ole_stream_job_payloads": _streams,
    }
    assert extract_ole_payload_family("summary", **kwargs) == [
        ("artifact.xls", "artifact.xls#summary", "title=Dossier")
    ]
    assert extract_ole_payload_family("streams", **kwargs) == [
        ("artifact.xls", "Workbook", "stream")
    ]
    assert extract_ole_payload_family("unknown", **kwargs) == []
    assert calls == [
        "summary:artifact.xls:artifact.xls:1",
        "streams:1",
    ]


def test_extract_ole_payloads_from_stream_entries_coordinates_jobs_and_families() -> None:
    class _OleStreamJob:
        def __init__(
            self,
            *,
            source_file: str,
            member_name: str,
            stream_name: str,
            stream_data: bytes,
            depth: int,
        ) -> None:
            self.source_file = source_file
            self.member_name = member_name
            self.stream_name = stream_name
            self.stream_data = stream_data
            self.depth = depth

    batch_sizes: list[int] = []
    family_calls: list[str] = []

    def _run_ordered_batch(
        items: Sequence[Any],
        worker: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        batch_sizes.append(len(items))
        results: list[Any] = []
        for item in items:
            value = worker(item)
            results.append(value if value is not None else default_factory())
        return results

    def _family(
        family: str,
        *,
        metadata_lines: Sequence[str],
        stream_jobs: Sequence[Any],
        source_file: str,
        member_name: str,
    ) -> list[tuple[str, str, str]]:
        family_calls.append(
            f"{family}:{source_file}:{member_name}:{len(metadata_lines)}:{len(stream_jobs)}"
        )
        if family == "summary":
            return [(source_file, f"{member_name}#summary", "\n".join(metadata_lines))]
        if family == "streams":
            return [
                (source_file, job.stream_name, job.stream_data.decode())
                for job in stream_jobs
            ] + [("", "ignored", "ignored")]
        return []

    def _tuple_entries(
        item: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        _index, payloads = item
        return [
            payload
            for payload in payloads
            if len(payload) == 3 and all(str(part or "").strip() for part in payload)
        ]

    assert extract_ole_payloads_from_stream_entries(
        [
            (("Workbook",), b"workbook"),
            (("", " "), b"blank"),
            (("Summary", "Info"), b"summary"),
        ],
        metadata_lines=["title=Dossier"],
        source_file="artifact.xls",
        member_name="artifact.xls",
        depth=1,
        ole_stream_extraction_job=_OleStreamJob,
        run_ordered_batch=_run_ordered_batch,
        ole_stream_entry=ole_stream_entry,
        ole_stream_job=ole_stream_job,
        extract_ole_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == [
        ("artifact.xls", "artifact.xls#summary", "title=Dossier"),
        ("artifact.xls", "Workbook", "workbook"),
        ("artifact.xls", "Summary/Info", "summary"),
    ]
    assert batch_sizes == [3, 2, 2, 2]
    assert family_calls == [
        "summary:artifact.xls:artifact.xls:1:2",
        "streams:artifact.xls:artifact.xls:1:2",
    ]


def test_extract_ole_stream_payload_family_dispatches_known_families() -> None:
    job = SimpleNamespace(stream_name="Workbook")
    calls: list[str] = []

    def _strings(received_job: Any) -> list[tuple[str, str, str]]:
        calls.append(f"strings:{received_job.stream_name}")
        return [("artifact.xls", "Workbook#strings", "strings")]

    def _nested(received_job: Any) -> list[tuple[str, str, str]]:
        calls.append(f"nested:{received_job.stream_name}")
        return [("artifact.xls", "Workbook#nested", "nested")]

    def _embedded(received_job: Any) -> list[tuple[str, str, str]]:
        calls.append(f"embedded:{received_job.stream_name}")
        return [("artifact.xls", "Workbook#embedded", "embedded")]

    kwargs = {
        "job": job,
        "extract_ole_stream_string_payloads": _strings,
        "extract_ole_stream_nested_archive_payloads": _nested,
        "extract_ole_stream_embedded_archive_payloads": _embedded,
    }
    assert extract_ole_stream_payload_family("strings", **kwargs) == [
        ("artifact.xls", "Workbook#strings", "strings")
    ]
    assert extract_ole_stream_payload_family("nested_archive", **kwargs) == [
        ("artifact.xls", "Workbook#nested", "nested")
    ]
    assert extract_ole_stream_payload_family("embedded_archive", **kwargs) == [
        ("artifact.xls", "Workbook#embedded", "embedded")
    ]
    assert extract_ole_stream_payload_family("unknown", **kwargs) == []
    assert calls == ["strings:Workbook", "nested:Workbook", "embedded:Workbook"]


def test_extract_ole_stream_string_payloads_builds_stream_payload() -> None:
    job = SimpleNamespace(
        source_file="artifact.xls",
        member_name="artifact.xls",
        stream_name="Workbook",
        stream_data=b"binary",
    )

    assert extract_ole_stream_string_payloads(
        job,
        binary_string_payload=lambda data: f"strings:{data.decode()}",
    ) == [
        (
            "artifact.xls",
            "artifact.xls#ole-stream:Workbook",
            "strings:binary",
        )
    ]
    assert extract_ole_stream_string_payloads(
        job,
        binary_string_payload=lambda _data: "",
    ) == []


def test_extract_ole_stream_nested_archive_payloads_respects_depth_and_magic_check() -> None:
    job = SimpleNamespace(
        source_file="artifact.xls",
        member_name="artifact.xls",
        stream_name="Workbook",
        stream_data=b"PK\x03\x04nested",
        depth=1,
    )
    calls: list[str] = []

    def _nested(
        data: bytes,
        source_file: str,
        member_name: str,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"{data[:2].decode(errors='ignore')}:{source_file}:{member_name}:{depth}")
        return [(source_file, member_name, "nested")]

    assert extract_ole_stream_nested_archive_payloads(
        job,
        looks_like_archive_bytes=lambda data: data.startswith(b"PK"),
        extract_nested_archive_bytes=_nested,
    ) == [("artifact.xls", "artifact.xls/Workbook", "nested")]
    assert extract_ole_stream_nested_archive_payloads(
        SimpleNamespace(**{**job.__dict__, "depth": 2}),
        looks_like_archive_bytes=lambda _data: True,
        extract_nested_archive_bytes=_nested,
    ) == []
    assert extract_ole_stream_nested_archive_payloads(
        SimpleNamespace(**{**job.__dict__, "stream_data": b"plain"}),
        looks_like_archive_bytes=lambda _data: False,
        extract_nested_archive_bytes=_nested,
    ) == []
    assert calls == ["PK:artifact.xls:artifact.xls/Workbook:2"]


def test_extract_ole_stream_embedded_archive_payloads_combines_archive_and_image_payloads() -> None:
    job = SimpleNamespace(
        source_file="artifact.xls",
        member_name="artifact.xls",
        stream_name="Workbook",
        stream_data=b"embedded",
        depth=1,
    )
    calls: list[str] = []

    def _embedded_archives(
        data: bytes,
        source_file: str,
        member_name: str,
        *,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"archives:{data.decode()}:{source_file}:{member_name}:{depth}")
        return [(source_file, f"{member_name}#archive", "archive")]

    def _embedded_images(
        data: bytes,
        source_file: str,
        member_name: str,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"images:{data.decode()}:{source_file}:{member_name}")
        return [(source_file, f"{member_name}#image", "image")]

    assert extract_ole_stream_embedded_archive_payloads(
        job,
        extract_embedded_archive_payloads=_embedded_archives,
        extract_embedded_image_payloads=_embedded_images,
    ) == [
        ("artifact.xls", "artifact.xls/Workbook#archive", "archive"),
        ("artifact.xls", "artifact.xls/Workbook#image", "image"),
    ]
    assert extract_ole_stream_embedded_archive_payloads(
        SimpleNamespace(**{**job.__dict__, "depth": 2}),
        extract_embedded_archive_payloads=_embedded_archives,
        extract_embedded_image_payloads=_embedded_images,
    ) == []
    assert calls == [
        "archives:embedded:artifact.xls:artifact.xls/Workbook:1",
        "images:embedded:artifact.xls:artifact.xls/Workbook",
    ]


def test_extract_ole_stream_payloads_coordinates_families_and_filters_entries() -> None:
    job = SimpleNamespace(stream_name="Workbook")
    batch_sizes: list[int] = []

    def _run_ordered_batch(
        items: Sequence[Any],
        worker: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        batch_sizes.append(len(items))
        results: list[Any] = []
        for item in items:
            value = worker(item)
            results.append(value if value is not None else default_factory())
        return results

    def _family(family: str, *, job: Any) -> list[tuple[str, str, str]]:
        assert job.stream_name == "Workbook"
        if family == "strings":
            return [("artifact.xls", "Workbook#strings", "strings")]
        if family == "nested_archive":
            return [
                ("artifact.xls", "Workbook#nested", "nested"),
                ("", "ignored", "ignored"),
            ]
        if family == "embedded_archive":
            return [("artifact.xls", "Workbook#embedded", "")]
        return []

    def _tuple_entries(
        item: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        _index, payloads = item
        return [
            payload
            for payload in payloads
            if len(payload) == 3 and all(str(part or "").strip() for part in payload)
        ]

    assert extract_ole_stream_payloads(
        job,
        run_ordered_batch=_run_ordered_batch,
        extract_ole_stream_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == [
        ("artifact.xls", "Workbook#strings", "strings"),
        ("artifact.xls", "Workbook#nested", "nested"),
    ]
    assert batch_sizes == [3, 3]


def test_extract_ole_stream_job_payloads_preserves_stream_order() -> None:
    jobs = [
        SimpleNamespace(stream_name="one"),
        SimpleNamespace(stream_name="two"),
    ]
    calls: list[str] = []

    def _payloads(job: Any) -> list[tuple[str, str, str]]:
        calls.append(f"payload:{job.stream_name}")
        return [("artifact.xls", job.stream_name, job.stream_name)]

    def _tuple_entries(
        item: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        calls.append(f"batch:{item[0]}:{len(item[1])}")
        return item[1]

    assert extract_ole_stream_job_payloads(
        jobs,
        run_ordered_batch=_run_ordered_batch,
        extract_ole_stream_payloads=_payloads,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == [
        ("artifact.xls", "one", "one"),
        ("artifact.xls", "two", "two"),
    ]
    assert extract_ole_stream_job_payloads(
        [],
        run_ordered_batch=_run_ordered_batch,
        extract_ole_stream_payloads=_payloads,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == []
    assert calls == [
        "payload:one",
        "payload:two",
        "batch:0:1",
        "batch:1:1",
    ]


def test_parquet_cell_text_normalizes_values_and_interesting_markers() -> None:
    def _decode(data: bytes, *, limit: int) -> str:
        return data[:limit].decode("utf-8", errors="ignore")

    assert parquet_cell_text(None, decode_text_artifact_bytes=_decode) == ""
    assert parquet_cell_text(b"owner@acme.example", decode_text_artifact_bytes=_decode) == (
        "owner@acme.example"
    )
    assert parquet_cell_text(
        {"url": "https://portal.acme.example"},
        decode_text_artifact_bytes=_decode,
    ) == '{"url": "https://portal.acme.example"}'
    assert parquet_cell_text("  s3://bucket/path  ", decode_text_artifact_bytes=_decode) == (
        "s3://bucket/path"
    )

    assert parquet_interesting_value("owner@acme.example") is True
    assert parquet_interesting_value("https://portal.acme.example") is True
    assert parquet_interesting_value("no relevant marker") is False


def test_parquet_table_lines_filters_uninteresting_values_and_caps_rows() -> None:
    class _Column:
        def __init__(self, values: list[str]) -> None:
            self._values = values

        def slice(self, _start: int, row_count: int) -> _Column:
            return _Column(self._values[:row_count])

        def to_pylist(self) -> list[str]:
            return list(self._values)

    class _Table:
        column_names = ["email", "plain"]
        num_rows = 3

        def __getitem__(self, column_name: str) -> _Column:
            values = {
                "email": ["owner@acme.example", "plain", "s3://bucket/export"],
                "plain": ["note", "none", "also none"],
            }
            return _Column(values[column_name])

    assert parquet_table_lines(
        _Table(),
        2,
        parquet_cell_text=str,
        parquet_interesting_value=parquet_interesting_value,
    ) == [
        "row_group[2].row[0].email=owner@acme.example",
        "row_group[2].row[2].email=s3://bucket/export",
    ]


def test_parquet_summary_lines_includes_metadata_and_limited_row_groups() -> None:
    class _Schema:
        names = ["email", "url"]

    class _Metadata:
        metadata = {b"owner": b"analyst@acme.example"}

    class _ParquetFile:
        schema_arrow = _Schema()
        metadata = _Metadata()
        num_row_groups = 2

        def read_row_group(self, row_group_index: int, *, columns: list[str]) -> Any:
            assert columns == ["email", "url"]
            return SimpleNamespace(row_group_index=row_group_index)

    def _cell(value: Any) -> str:
        if isinstance(value, bytes):
            return value.decode()
        return str(value)

    def _table(table: Any, row_group_index: int) -> list[str]:
        return [f"row_group[{row_group_index}].row[0].email=owner{table.row_group_index}@acme.example"]

    assert parquet_summary_lines(
        _ParquetFile(),
        parquet_cell_text=_cell,
        parquet_table_lines=_table,
    ) == [
        "format=parquet",
        "columns=email,url",
        "metadata.owner=analyst@acme.example",
        "row_group[0].row[0].email=owner0@acme.example",
        "row_group[1].row[0].email=owner1@acme.example",
    ]


def test_extract_parquet_bytes_payloads_adds_summary_and_legacy_payloads() -> None:
    calls: list[str] = []

    def _factory(data: bytes) -> str:
        calls.append(f"factory:{data.decode()}")
        return "parquet-file"

    def _summary(parquet_file: str) -> list[str]:
        calls.append(f"summary:{parquet_file}")
        return ["format=parquet", "columns=email,url"]

    def _legacy(
        data: bytes,
        source_file: str,
        member_name: str,
        *,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"legacy:{data.decode()}:{source_file}:{member_name}:{depth}")
        return [(source_file, f"{member_name}#binary-strings", "legacy")]

    assert extract_parquet_bytes_payloads(
        b"parquet-bytes",
        "customers.parquet",
        "customers.parquet",
        depth=1,
        max_artifact_member_bytes=7,
        parquet_file_factory=_factory,
        parquet_summary_lines=_summary,
        extract_legacy_binary_payloads=_legacy,
    ) == [
        (
            "customers.parquet",
            "customers.parquet#parquet-table",
            "format=parquet\ncolumns=email,url",
        ),
        (
            "customers.parquet",
            "customers.parquet#binary-strings",
            "legacy",
        ),
    ]
    assert calls == [
        "factory:parquet-bytes",
        "summary:parquet-file",
        "legacy:parquet:customers.parquet:customers.parquet:1",
    ]


def test_extract_parquet_bytes_payloads_falls_back_to_legacy_on_parse_error() -> None:
    calls: list[str] = []

    def _legacy(
        data: bytes,
        source_file: str,
        member_name: str,
        *,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"legacy:{data.decode()}:{source_file}:{member_name}:{depth}")
        return [(source_file, member_name, "legacy")]

    assert extract_parquet_bytes_payloads(
        b"bad-parquet",
        "bad.parquet",
        "bad.parquet",
        depth=2,
        max_artifact_member_bytes=3,
        parquet_file_factory=lambda _data: (_ for _ in ()).throw(RuntimeError("bad parquet")),
        parquet_summary_lines=lambda _parquet_file: ["unused"],
        extract_legacy_binary_payloads=_legacy,
    ) == [("bad.parquet", "bad.parquet", "legacy")]
    assert calls == ["legacy:bad:bad.parquet:bad.parquet:2"]


def test_extract_parquet_path_payloads_reads_file_and_dispatches_bytes(tmp_path: Path) -> None:
    path = tmp_path / "customers.parquet"
    path.write_bytes(b"parquet-bytes")
    calls: list[str] = []

    def _parquet_bytes(
        data: bytes,
        source_file: str,
        member_name: str,
        *,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"parquet:{data.decode()}:{Path(source_file).name}:{member_name}:{depth}")
        return [(source_file, f"{member_name}#parquet-table", "summary")]

    def _legacy(
        data: bytes,
        source_file: str,
        member_name: str,
        *,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"legacy:{data.decode()}:{Path(source_file).name}:{member_name}:{depth}")
        return [(source_file, member_name, "legacy")]

    assert extract_parquet_path_payloads(
        path,
        depth=1,
        max_artifact_member_bytes=64,
        extract_parquet_bytes_payloads=_parquet_bytes,
        extract_legacy_binary_payloads=_legacy,
    ) == [(str(path), "customers.parquet#parquet-table", "summary")]
    assert calls == ["parquet:parquet-bytes:customers.parquet:customers.parquet:1"]


def test_extract_parquet_path_payloads_falls_back_to_bounded_legacy_for_large_or_missing_files(
    tmp_path: Path,
) -> None:
    path = tmp_path / "large.parquet"
    path.write_bytes(b"large-parquet")
    missing_path = tmp_path / "missing.parquet"
    calls: list[str] = []

    def _parquet_bytes(*_args: Any, **_kwargs: Any) -> list[tuple[str, str, str]]:
        raise AssertionError("oversized or missing parquet should not parse")

    def _legacy(
        data: bytes,
        source_file: str,
        member_name: str,
        *,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"legacy:{data.decode()}:{Path(source_file).name}:{member_name}:{depth}")
        return [(source_file, member_name, "legacy")]

    assert extract_parquet_path_payloads(
        path,
        depth=2,
        max_artifact_member_bytes=5,
        extract_parquet_bytes_payloads=_parquet_bytes,
        extract_legacy_binary_payloads=_legacy,
    ) == [(str(path), "large.parquet", "legacy")]
    assert extract_parquet_path_payloads(
        missing_path,
        depth=3,
        max_artifact_member_bytes=5,
        extract_parquet_bytes_payloads=_parquet_bytes,
        extract_legacy_binary_payloads=_legacy,
    ) == [(str(missing_path), "missing.parquet", "legacy")]
    assert calls == [
        "legacy:large:large.parquet:large.parquet:2",
        "legacy::missing.parquet:missing.parquet:3",
    ]


def test_extract_member_payload_family_routes_relationship_text_and_meta_payloads() -> None:
    calls: list[str] = []

    def _relationship_payload(text: str) -> str:
        calls.append(f"relationships:{text}")
        return "hyperlink=https://portal.example"

    def _xml_text_payload(text: str) -> str:
        calls.append(f"text:{text}")
        return "body text"

    def _xml_property_payload(member_name: str, text: str) -> str:
        calls.append(f"meta:{member_name}:{text}")
        return "title=Dossier"

    assert extract_member_payload_family(
        "relationships",
        source_file="docx.zip",
        member_name="_rels/document.xml.rels",
        lowered="_rels/document.xml.rels",
        text="rels",
        relationship_payload=_relationship_payload,
        xml_text_payload=_xml_text_payload,
        xml_property_payload=_xml_property_payload,
    ) == [
        ("docx.zip", "_rels/document.xml.rels#relationships", "hyperlink=https://portal.example"),
    ]
    assert extract_member_payload_family(
        "text",
        source_file="docx.zip",
        member_name="word/document.xml",
        lowered="word/document.xml",
        text="xml",
        relationship_payload=_relationship_payload,
        xml_text_payload=_xml_text_payload,
        xml_property_payload=_xml_property_payload,
    ) == [("docx.zip", "word/document.xml", "body text")]
    assert extract_member_payload_family(
        "meta",
        source_file="docx.zip",
        member_name="docProps/core.xml",
        lowered="docprops/core.xml",
        text="props",
        relationship_payload=_relationship_payload,
        xml_text_payload=_xml_text_payload,
        xml_property_payload=_xml_property_payload,
    ) == [("docx.zip", "docProps/core.xml#meta", "title=Dossier")]
    assert extract_member_payload_family(
        "unknown",
        source_file="docx.zip",
        member_name="word/document.xml",
        lowered="word/document.xml",
        text="xml",
        relationship_payload=_relationship_payload,
        xml_text_payload=_xml_text_payload,
        xml_property_payload=_xml_property_payload,
    ) == []
    assert calls == [
        "relationships:rels",
        "text:xml",
        "meta:docProps/core.xml:props",
    ]


def test_member_payloads_routes_shortcuts_and_flattens_xml_family_payloads() -> None:
    calls: list[str] = []

    def _decode(data: bytes) -> str:
        calls.append(f"decode:{data.decode()}")
        return data.decode()

    def _android(member_name: str) -> str:
        return "AndroidManifest.xml" if member_name == "AndroidManifest.xml" else ""

    def _db_client(member_name: str) -> str:
        return "database" if member_name == "config/database.xml" else ""

    def _family(
        family: str,
        *,
        source_file: str,
        member_name: str,
        lowered: str,
        text: str,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"family:{family}:{source_file}:{member_name}:{lowered}:{text}")
        if family == "relationships":
            return [(source_file, f"{member_name}#relationships", "rels")]
        if family == "text":
            return [(source_file, member_name, "body")]
        if family == "meta":
            return [(source_file, f"{member_name}#meta", "meta")]
        return []

    def _tuple_entries(
        item: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        index, payloads = item
        calls.append(f"batch:{index}:{len(payloads)}")
        return payloads

    assert member_payloads(
        source_file="apk",
        member_name="AndroidManifest.xml",
        data=b"manifest",
        run_ordered_batch=_run_ordered_batch,
        decode_text_artifact_bytes=_decode,
        android_manifest_artifact_label=_android,
        database_client_config_artifact_label=_db_client,
        extract_member_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == [("apk", "AndroidManifest.xml", "manifest")]
    assert member_payloads(
        source_file="docx.zip",
        member_name="_rels/document.xml.rels",
        data=b"rels",
        run_ordered_batch=_run_ordered_batch,
        decode_text_artifact_bytes=_decode,
        android_manifest_artifact_label=_android,
        database_client_config_artifact_label=_db_client,
        extract_member_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == [("docx.zip", "_rels/document.xml.rels#relationships", "rels")]
    assert member_payloads(
        source_file="zip",
        member_name="config/database.xml",
        data=b"db",
        run_ordered_batch=_run_ordered_batch,
        decode_text_artifact_bytes=_decode,
        android_manifest_artifact_label=_android,
        database_client_config_artifact_label=_db_client,
        extract_member_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == [("zip", "config/database.xml", "db")]
    assert member_payloads(
        source_file="docx.zip",
        member_name="word/document.xml",
        data=b"xml",
        run_ordered_batch=_run_ordered_batch,
        decode_text_artifact_bytes=_decode,
        android_manifest_artifact_label=_android,
        database_client_config_artifact_label=_db_client,
        extract_member_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == [
        ("docx.zip", "word/document.xml", "body"),
        ("docx.zip", "word/document.xml#meta", "meta"),
    ]
    assert member_payloads(
        source_file="archive",
        member_name="notes.txt",
        data=b"plain",
        run_ordered_batch=_run_ordered_batch,
        decode_text_artifact_bytes=_decode,
        android_manifest_artifact_label=_android,
        database_client_config_artifact_label=_db_client,
        extract_member_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == [("archive", "notes.txt", "plain")]
    assert "batch:0:1" in calls
    assert "batch:1:1" in calls


def test_xml_and_ordered_line_helpers_normalize_and_filter_values() -> None:
    from xml.etree import ElementTree  # noqa: PLC0415

    assert normalize_xml_tag("{urn:test}title") == "title"
    assert normalize_xml_tag("plain") == "plain"
    assert xml_text_value("  hello  ") == "hello"
    assert xml_text_value(None) == "None"

    leaf = ElementTree.fromstring(
        "<ns:title xmlns:ns='urn:test'>  Dossier </ns:title>"
    )
    assert xml_property_line(leaf) == "title=Dossier"
    parent = ElementTree.fromstring("<root><title>Dossier</title></root>")
    assert xml_property_line(parent) == ""
    empty = ElementTree.fromstring("<title> </title>")
    assert xml_property_line(empty) == ""

    rel = ElementTree.fromstring(
        "<Relationship Type='https://schemas.example/hyperlink' "
        "Target=' https://portal.example ' />"
    )
    assert relationship_line(rel) == "hyperlink=https://portal.example"
    rel_no_type = ElementTree.fromstring("<Relationship Target='doc.xml' />")
    assert relationship_line(rel_no_type) == "doc.xml"
    rel_no_target = ElementTree.fromstring(
        "<Relationship Type='https://schemas.example/image' />"
    )
    assert relationship_line(rel_no_target) == ""

    assert ordered_line_batch_entries((0, ["a", "", "b"])) == ["a", "b"]
    assert ordered_line_entry((0, "a")) == "a"
    assert ordered_line_entry((1, "")) is None


def test_xml_payload_helpers_parse_dedupe_cap_and_fallbacks() -> None:
    def _run_ordered_batch(
        items: Any,
        func: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        results: list[Any] = []
        for item in list(items):
            try:
                results.append(func(item))
            except Exception:
                results.append(default_factory())
        return results

    xml = (
        "<root><title> Owner </title><empty />"
        "<title> Owner </title><url>https://portal.example.test</url></root>"
    )
    assert (
        xml_text_payload(
            xml,
            run_ordered_batch=_run_ordered_batch,
            xml_text_value=xml_text_value,
        )
        == "Owner\nOwner\nhttps://portal.example.test"
    )
    assert (
        xml_text_payload(
            "not<xml",
            run_ordered_batch=_run_ordered_batch,
            xml_text_value=xml_text_value,
        )
        == "not<xml"
    )
    assert (
        xml_property_payload(
            "docProps/core.xml",
            xml,
            run_ordered_batch=_run_ordered_batch,
            xml_property_line=xml_property_line,
            ordered_line_entry=ordered_line_entry,
        )
        == "title=Owner\nurl=https://portal.example.test"
    )
    assert (
        xml_property_payload(
            "notes.txt",
            xml,
            run_ordered_batch=_run_ordered_batch,
            xml_property_line=xml_property_line,
            ordered_line_entry=ordered_line_entry,
        )
        == ""
    )
    assert (
        xml_property_payload(
            "docProps/core.xml",
            "not<xml",
            run_ordered_batch=_run_ordered_batch,
            xml_property_line=xml_property_line,
            ordered_line_entry=ordered_line_entry,
        )
        == ""
    )

    many = "<root>" + "".join(f"<v>{index}</v>" for index in range(70)) + "</root>"
    capped_payload = xml_property_payload(
        "word/document.xml",
        many,
        run_ordered_batch=_run_ordered_batch,
        xml_property_line=xml_property_line,
        ordered_line_entry=ordered_line_entry,
    )
    assert len(capped_payload.splitlines()) == 64

    rels = (
        "<Relationships>"
        "<Relationship Type='http://schemas/x/comments' Target='comments.xml' />"
        "<Relationship Target='slides/slide1.xml' />"
        "<Relationship />"
        "</Relationships>"
    )
    assert (
        relationship_payload(
            rels,
            run_ordered_batch=_run_ordered_batch,
            relationship_line=relationship_line,
            ordered_line_entry=ordered_line_entry,
        )
        == "comments=comments.xml\nslides/slide1.xml"
    )
    assert (
        relationship_payload(
            "not<xml",
            run_ordered_batch=_run_ordered_batch,
            relationship_line=relationship_line,
            ordered_line_entry=ordered_line_entry,
        )
        == ""
    )


def test_pdf_metadata_helpers_parse_and_dedupe_ordered_lines() -> None:
    text = (
        "%PDF-1.4\n"
        "/Title ( Dossier Final )\n"
        "/Author ( Analyst )\n"
        "/Title ( Dossier Final )\n"
        "/URI ( https://portal.example/report )\n"
        "%%EOF"
    )
    assert pdf_metadata_lines_for_key(text, "Title") == [
        "title=Dossier Final",
        "title=Dossier Final",
    ]
    assert pdf_metadata_lines_for_key(text, "Author") == ["author=Analyst"]
    assert pdf_metadata_lines_for_key(text, "URI") == [
        "uri=https://portal.example/report"
    ]
    assert pdf_metadata_lines_for_key(text, "Keywords") == []

    calls: list[str] = []

    def _run_ordered_batch(items: Any, func: Any, *, default_factory: Any) -> list[Any]:
        del default_factory
        values = list(items)
        calls.append(",".join(str(item[0] if isinstance(item, tuple) else item) for item in values))
        return [func(item) for item in values]

    assert pdf_metadata_lines(
        text.encode("latin-1"),
        run_ordered_batch=_run_ordered_batch,
        pdf_metadata_lines_for_key=pdf_metadata_lines_for_key,
        ordered_line_batch_entries=ordered_line_batch_entries,
    ) == [
        "title=Dossier Final",
        "author=Analyst",
        "uri=https://portal.example/report",
    ]
    assert calls == [
        "Title,Author,Creator,Producer,Subject,Keywords,URI",
        "0,1,2,3,4,5,6",
    ]


def test_pdf_xmp_payload_extracts_first_xmp_block_with_xml_text_callback() -> None:
    seen: list[str] = []

    def _xml_text_payload(text: str) -> str:
        seen.append(text)
        return "Title\nOwner"

    data = (
        b"%PDF-1.4\n"
        b"<x:xmpmeta xmlns:x='adobe:ns:meta/'>"
        b"<dc:title>Title</dc:title><dc:creator>Owner</dc:creator>"
        b"</x:xmpmeta>\n"
        b"<x:xmpmeta><dc:title>Second</dc:title></x:xmpmeta>\n"
        b"%%EOF"
    )
    assert pdf_xmp_payload(data, xml_text_payload=_xml_text_payload) == "Title\nOwner"
    assert seen == [
        (
            "<x:xmpmeta xmlns:x='adobe:ns:meta/'>"
            "<dc:title>Title</dc:title><dc:creator>Owner</dc:creator>"
            "</x:xmpmeta>"
        )
    ]
    assert pdf_xmp_payload(
        b"%PDF-1.4\n<metadata>none</metadata>",
        xml_text_payload=_xml_text_payload,
    ) == ""
    assert len(seen) == 1


def test_extract_pdf_payloads_orders_families_and_filters_payload_entries() -> None:
    calls: list[str] = []

    def _run_ordered_batch(items: Any, func: Any, *, default_factory: Any) -> list[Any]:
        del default_factory
        values = list(items)
        calls.append(",".join(str(item[0] if isinstance(item, tuple) else item) for item in values))
        return [func(item) for item in values]

    def _fragment(
        family: str,
        data: bytes,
        source_file: str,
        member_name: str,
    ) -> list[tuple[str, str, str] | tuple[str, str]]:
        assert data == b"%PDF-1.4 payload"
        assert source_file == "briefing.pdf"
        assert member_name == "briefing.pdf"
        return [
            (source_file, f"{member_name}#{family}", f"{family}-payload"),
            ("", f"{member_name}#empty-source-{family}", "skip"),
            (source_file, "", "skip"),
            (source_file, f"{member_name}#empty-text-{family}", ""),
            (source_file, f"{member_name}#short-{family}"),
        ]

    def _tuple_entries(
        item: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        _index, payloads = item
        return [
            payload
            for payload in payloads
            if len(payload) == 3 and all(str(part or "").strip() for part in payload)
        ]

    assert extract_pdf_payloads(
        b"%PDF-1.4 payload",
        source_file="briefing.pdf",
        member_name="briefing.pdf",
        run_ordered_batch=_run_ordered_batch,
        extract_pdf_payload_fragment=_fragment,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == [
        ("briefing.pdf", "briefing.pdf#text", "text-payload"),
        ("briefing.pdf", "briefing.pdf#metadata", "metadata-payload"),
        ("briefing.pdf", "briefing.pdf#xmp", "xmp-payload"),
        ("briefing.pdf", "briefing.pdf#ocr", "ocr-payload"),
    ]
    assert calls == [
        "text,metadata,xmp,ocr",
        "0,1,2,3",
    ]


def test_extract_pdf_payload_fragment_routes_text_metadata_xmp_and_ocr() -> None:
    calls: list[str] = []

    def _text(data: bytes, source_file: str, member_name: str) -> list[tuple[str, str, str]]:
        calls.append(f"text:{source_file}:{member_name}:{data.decode()}")
        return [(source_file, member_name, "body")]

    def _metadata(data: bytes) -> list[str]:
        calls.append(f"metadata:{data.decode()}")
        return ["author=analyst", "title=Dossier"]

    def _xmp(data: bytes) -> str:
        calls.append(f"xmp:{data.decode()}")
        return "xmp body"

    def _ocr(data: bytes, source_file: str, member_name: str) -> list[tuple[str, str, str]]:
        calls.append(f"ocr:{source_file}:{member_name}:{data.decode()}")
        return [(source_file, f"{member_name}#ocr-page-1", "ocr")]

    kwargs = {
        "data": b"pdf",
        "source_file": "briefing.pdf",
        "member_name": "briefing.pdf",
        "extract_pdf_text_payloads": _text,
        "pdf_metadata_lines": _metadata,
        "pdf_xmp_payload": _xmp,
        "extract_pdf_ocr_payloads": _ocr,
    }
    assert extract_pdf_payload_fragment("text", **kwargs) == [
        ("briefing.pdf", "briefing.pdf", "body")
    ]
    assert extract_pdf_payload_fragment("metadata", **kwargs) == [
        ("briefing.pdf", "briefing.pdf#pdf-metadata", "author=analyst\ntitle=Dossier")
    ]
    assert extract_pdf_payload_fragment("xmp", **kwargs) == [
        ("briefing.pdf", "briefing.pdf#pdf-xmp", "xmp body")
    ]
    assert extract_pdf_payload_fragment("ocr", **kwargs) == [
        ("briefing.pdf", "briefing.pdf#ocr-page-1", "ocr")
    ]
    assert extract_pdf_payload_fragment("unknown", **kwargs) == []
    assert calls == [
        "text:briefing.pdf:briefing.pdf:pdf",
        "metadata:pdf",
        "xmp:pdf",
        "ocr:briefing.pdf:briefing.pdf:pdf",
    ]


def test_extract_pdf_ocr_payloads_from_path_coordinates_pages_payloads_and_cleanup(tmp_path: Path) -> None:
    pdf_path = tmp_path / "briefing.pdf"
    pdf_path.write_bytes(b"%PDF")
    page_one = tmp_path / "page-1.png"
    page_two = tmp_path / "page-2.png"
    page_one.write_bytes(b"one")
    page_two.write_bytes(b"two")
    calls: list[str] = []

    def _render(path: Path) -> list[Path]:
        calls.append(f"render:{path.name}")
        return [page_one, page_two]

    def _page_job(page_job: tuple[int, Path]) -> tuple[int, Path] | None:
        index, image_path = page_job
        calls.append(f"job:{index}:{image_path.name}")
        return page_job if index == 1 else None

    def _ocr(path: Path) -> str:
        calls.append(f"ocr:{path.name}:{path.exists()}")
        return "page-one@example.test"

    def _barcode(path: Path) -> str:
        calls.append(f"barcode:{path.name}:{path.exists()}")
        return "https://barcode.example.test"

    def _tuple_entries(
        item: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        index, payloads = item
        calls.append(f"batch:{index}:{len(payloads)}")
        return payloads

    assert extract_pdf_ocr_payloads_from_path(
        pdf_path,
        source_file="source.pdf",
        member_name="briefing.pdf",
        pdf_raster_available=True,
        render_pdf_pages_for_ocr=_render,
        pdf_ocr_page_job=_page_job,
        ocr_image_path=_ocr,
        barcode_image_path_payload=_barcode,
        run_ordered_batch=_run_ordered_batch,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == [
        ("source.pdf", "briefing.pdf#ocr-page-1", "page-one@example.test"),
        ("source.pdf", "briefing.pdf#barcode-page-1", "https://barcode.example.test"),
    ]
    assert not page_one.exists()
    assert page_two.exists()
    assert calls == [
        "render:briefing.pdf",
        "job:1:page-1.png",
        "job:2:page-2.png",
        "ocr:page-1.png:True",
        "barcode:page-1.png:True",
        "batch:0:2",
    ]

    assert extract_pdf_ocr_payloads_from_path(
        pdf_path,
        source_file="source.pdf",
        member_name="briefing.pdf",
        pdf_raster_available=False,
        render_pdf_pages_for_ocr=_render,
        pdf_ocr_page_job=_page_job,
        ocr_image_path=_ocr,
        barcode_image_path_payload=_barcode,
        run_ordered_batch=_run_ordered_batch,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == []
    assert extract_pdf_ocr_payloads_from_path(
        tmp_path / "missing.pdf",
        source_file="source.pdf",
        member_name="briefing.pdf",
        pdf_raster_available=True,
        render_pdf_pages_for_ocr=_render,
        pdf_ocr_page_job=_page_job,
        ocr_image_path=_ocr,
        barcode_image_path_payload=_barcode,
        run_ordered_batch=_run_ordered_batch,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == []


def test_extract_pdf_bytes_ocr_payloads_writes_bounded_temp_pdf_and_handles_fallbacks() -> None:
    calls: list[str] = []

    def _from_path(
        path: Path,
        *,
        source_file: str,
        member_name: str,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"path:{path.name}:{path.exists()}:{path.read_bytes().decode()}:{source_file}:{member_name}")
        return [(source_file, f"{member_name}#ocr-page-1", "embedded-owner@example.test")]

    assert extract_pdf_bytes_ocr_payloads(
        b"embedded-pdf-bytes",
        source_file="archive.zip",
        member_name="docs/briefing.pdf",
        pdf_raster_available=True,
        max_artifact_member_bytes=8,
        extract_pdf_ocr_payloads_from_path=_from_path,
    ) == [("archive.zip", "docs/briefing.pdf#ocr-page-1", "embedded-owner@example.test")]
    assert calls == ["path:embedded.pdf:True:embedded:archive.zip:docs/briefing.pdf"]

    assert extract_pdf_bytes_ocr_payloads(
        b"embedded-pdf-bytes",
        source_file="archive.zip",
        member_name="docs/briefing.pdf",
        pdf_raster_available=False,
        max_artifact_member_bytes=8,
        extract_pdf_ocr_payloads_from_path=_from_path,
    ) == []
    assert extract_pdf_bytes_ocr_payloads(
        b"",
        source_file="archive.zip",
        member_name="docs/briefing.pdf",
        pdf_raster_available=True,
        max_artifact_member_bytes=8,
        extract_pdf_ocr_payloads_from_path=_from_path,
    ) == []

    def _failing_from_path(*_args: Any, **_kwargs: Any) -> list[tuple[str, str, str]]:
        raise OSError("boom")

    assert extract_pdf_bytes_ocr_payloads(
        b"embedded-pdf-bytes",
        source_file="archive.zip",
        member_name="docs/briefing.pdf",
        pdf_raster_available=True,
        max_artifact_member_bytes=8,
        extract_pdf_ocr_payloads_from_path=_failing_from_path,
    ) == []


def test_extract_pdf_text_payload_helpers_shape_path_and_byte_payloads() -> None:
    path = Path("briefing.pdf")
    calls: list[str] = []

    def _path_exists(candidate: Path) -> bool:
        calls.append(f"exists:{candidate}")
        return str(candidate) == "briefing.pdf"

    def _read_text(candidate: Path) -> str:
        calls.append(f"read:{candidate}")
        return "pdf text"

    assert extract_pdf_text_payloads_from_path(
        path,
        path_exists=_path_exists,
        read_text=_read_text,
    ) == [("briefing.pdf", "briefing.pdf", "pdf text")]
    assert extract_pdf_text_payloads_from_path(
        Path("missing.pdf"),
        path_exists=_path_exists,
        read_text=_read_text,
    ) == []
    assert calls == [
        "exists:briefing.pdf",
        "read:briefing.pdf",
        "exists:missing.pdf",
    ]

    assert extract_pdf_text_payloads_from_bytes(
        "åßçpayload".encode("latin-1"),
        source_file="archive.zip",
        member_name="nested.pdf",
        max_artifact_member_bytes=3,
    ) == [("archive.zip", "nested.pdf", "åßç")]


def test_extract_sqlite_connection_payload_family_routes_summary_and_objects() -> None:
    calls: list[str] = []
    jobs = ["alpha", "beta"]

    def _summary(
        summary_jobs: Sequence[Any],
        source_file: str,
        member_name: str,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"summary:{','.join(str(job) for job in summary_jobs)}")
        return [(source_file, f"{member_name}#sqlite-meta", "alpha\nbeta")]

    def _objects(object_jobs: Sequence[Any]) -> list[tuple[str, str, str]]:
        calls.append(f"objects:{','.join(str(job) for job in object_jobs)}")
        return [
            ("database.sqlite", "database.sqlite#sqlite-schema-alpha", "alpha-schema")
        ]

    kwargs = {
        "jobs": jobs,
        "source_file": "database.sqlite",
        "member_name": "database.sqlite",
        "extract_sqlite_connection_summary_payloads": _summary,
        "extract_sqlite_connection_object_payloads": _objects,
    }
    assert extract_sqlite_connection_payload_family("summary", **kwargs) == [
        ("database.sqlite", "database.sqlite#sqlite-meta", "alpha\nbeta")
    ]
    assert extract_sqlite_connection_payload_family("objects", **kwargs) == [
        ("database.sqlite", "database.sqlite#sqlite-schema-alpha", "alpha-schema")
    ]
    assert extract_sqlite_connection_payload_family("unknown", **kwargs) == []
    assert calls == ["summary:alpha,beta", "objects:alpha,beta"]


def test_extract_sqlite_connection_payloads_from_jobs_orders_and_filters_families() -> None:
    calls: list[str] = []
    jobs = ["alpha", "beta"]

    def _run_ordered_batch(items: Any, func: Any, *, default_factory: Any) -> list[Any]:
        del default_factory
        values = list(items)
        calls.append(",".join(str(item[0] if isinstance(item, tuple) else item) for item in values))
        return [func(item) for item in values]

    def _family(
        family: str,
        family_jobs: Sequence[Any],
        source_file: str,
        member_name: str,
    ) -> list[tuple[str, str, str] | tuple[str, str]]:
        assert list(family_jobs) == jobs
        assert source_file == "database.sqlite"
        assert member_name == "database.sqlite"
        return [
            (source_file, f"{member_name}#{family}", f"{family}-payload"),
            ("", f"{member_name}#empty-source-{family}", "skip"),
            (source_file, "", "skip"),
            (source_file, f"{member_name}#empty-text-{family}", ""),
            (source_file, f"{member_name}#short-{family}"),
        ]

    def _tuple_entries(
        item: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        _index, payloads = item
        return [
            payload
            for payload in payloads
            if len(payload) == 3 and all(str(part or "").strip() for part in payload)
        ]

    assert extract_sqlite_connection_payloads_from_jobs(
        jobs,
        source_file="database.sqlite",
        member_name="database.sqlite",
        run_ordered_batch=_run_ordered_batch,
        extract_sqlite_connection_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == [
        ("database.sqlite", "database.sqlite#summary", "summary-payload"),
        ("database.sqlite", "database.sqlite#objects", "objects-payload"),
    ]
    assert calls == [
        "summary,objects",
        "0,1",
    ]


def test_extract_sqlite_connection_object_payloads_from_jobs_orders_and_filters_payloads() -> None:
    calls: list[str] = []
    jobs = ["alpha", "beta", "gamma"]

    def _run_ordered_batch(items: Any, func: Any, *, default_factory: Any) -> list[Any]:
        del default_factory
        values = list(items)
        calls.append(",".join(str(item[0] if isinstance(item, tuple) else item) for item in values))
        return [func(item) for item in values]

    def _object_payloads(job: str) -> list[tuple[str, str, str] | tuple[str, str]]:
        return [
            ("database.sqlite", f"database.sqlite#sqlite-schema-{job}", f"{job}-schema"),
            ("", f"database.sqlite#empty-source-{job}", "skip"),
            ("database.sqlite", "", "skip"),
            ("database.sqlite", f"database.sqlite#empty-text-{job}", ""),
            ("database.sqlite", f"database.sqlite#short-{job}"),
        ]

    def _tuple_entries(
        item: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        _index, payloads = item
        return [
            payload
            for payload in payloads
            if len(payload) == 3 and all(str(part or "").strip() for part in payload)
        ]

    assert extract_sqlite_connection_object_payloads_from_jobs(
        jobs,
        run_ordered_batch=_run_ordered_batch,
        extract_sqlite_object_payloads=_object_payloads,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == [
        ("database.sqlite", "database.sqlite#sqlite-schema-alpha", "alpha-schema"),
        ("database.sqlite", "database.sqlite#sqlite-schema-beta", "beta-schema"),
        ("database.sqlite", "database.sqlite#sqlite-schema-gamma", "gamma-schema"),
    ]
    assert calls == [
        "alpha,beta,gamma",
        "0,1,2",
    ]
    assert extract_sqlite_connection_object_payloads_from_jobs(
        [],
        run_ordered_batch=_run_ordered_batch,
        extract_sqlite_object_payloads=_object_payloads,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == []


def test_extract_sqlite_object_payloads_from_connection_orders_families_and_limits_rows() -> None:
    calls: list[str] = []
    con = sqlite3.connect(":memory:")
    try:
        con.execute("CREATE TABLE credentials (email TEXT, token TEXT)")
        con.executemany(
            "INSERT INTO credentials (email, token) VALUES (?, ?)",
            [
                ("owner@acme.example", "tok-123"),
                ("backup@acme.example", "tok-456"),
            ],
        )

        def _run_ordered_batch(items: Any, func: Any, *, default_factory: Any) -> list[Any]:
            del default_factory
            values = list(items)
            calls.append(",".join(str(item[0] if isinstance(item, tuple) else item) for item in values))
            return [func(item) for item in values]

        def _family(
            family: str,
            *,
            source_file: str,
            member_name: str,
            object_name: str,
            sql_text: str,
            column_names: Sequence[str],
            sample_rows: Sequence[Sequence[Any]],
        ) -> list[tuple[str, str, str] | tuple[str, str]]:
            assert source_file == "database.sqlite"
            assert member_name == "database.sqlite"
            assert object_name == "credentials"
            assert sql_text == "CREATE TABLE credentials (email TEXT, token TEXT)"
            assert list(column_names) == ["email", "token"]
            assert list(sample_rows) == [("owner@acme.example", "tok-123")]
            return [
                (source_file, f"{member_name}#sqlite-{family}", f"{family}-payload"),
                ("", f"{member_name}#empty-source-{family}", "skip"),
                (source_file, "", "skip"),
                (source_file, f"{member_name}#empty-text-{family}", ""),
                (source_file, f"{member_name}#short-{family}"),
            ]

        def _tuple_entries(
            item: tuple[int, list[tuple[str, str, str]]],
        ) -> list[tuple[str, str, str]]:
            _index, payloads = item
            return [
                payload
                for payload in payloads
                if len(payload) == 3 and all(str(part or "").strip() for part in payload)
            ]

        assert extract_sqlite_object_payloads_from_connection(
            con,
            source_file="database.sqlite",
            member_name="database.sqlite",
            object_name=" credentials ",
            object_sql=" CREATE TABLE credentials (email TEXT, token TEXT) ",
            max_sqlite_rows_per_table=1,
            sqlite_identifier=lambda name: f'"{name}"',
            run_ordered_batch=_run_ordered_batch,
            extract_sqlite_object_payload_family=_family,
            artifact_payload_tuple_batch_entries=_tuple_entries,
        ) == [
            ("database.sqlite", "database.sqlite#sqlite-schema", "schema-payload"),
            ("database.sqlite", "database.sqlite#sqlite-columns", "columns-payload"),
            ("database.sqlite", "database.sqlite#sqlite-rows", "rows-payload"),
        ]
        assert calls == [
            "schema,columns,rows",
            "0,1,2",
        ]
        assert extract_sqlite_object_payloads_from_connection(
            con,
            source_file="database.sqlite",
            member_name="database.sqlite",
            object_name=" ",
            object_sql="",
            max_sqlite_rows_per_table=1,
            sqlite_identifier=lambda name: f'"{name}"',
            run_ordered_batch=_run_ordered_batch,
            extract_sqlite_object_payload_family=_family,
            artifact_payload_tuple_batch_entries=_tuple_entries,
        ) == []
    finally:
        con.close()


def test_extract_sqlite_object_payload_family_dispatches_to_payload_builders() -> None:
    calls: list[str] = []
    common_kwargs = {
        "source_file": "database.sqlite",
        "member_name": "database.sqlite",
        "object_name": "credentials",
        "sql_text": "CREATE TABLE credentials (email TEXT)",
        "column_names": ["email"],
        "sample_rows": [("owner@acme.example",)],
    }

    def _schema(
        *,
        source_file: str,
        member_name: str,
        object_name: str,
        sql_text: str,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"schema:{source_file}:{member_name}:{object_name}:{sql_text}")
        return [(source_file, f"{member_name}#schema", sql_text)]

    def _columns(
        *,
        source_file: str,
        member_name: str,
        object_name: str,
        column_names: Sequence[str],
    ) -> list[tuple[str, str, str]]:
        calls.append(f"columns:{source_file}:{member_name}:{object_name}:{','.join(column_names)}")
        return [(source_file, f"{member_name}#columns", ",".join(column_names))]

    def _rows(
        *,
        source_file: str,
        member_name: str,
        object_name: str,
        column_names: Sequence[str],
        sample_rows: Sequence[Sequence[Any]],
    ) -> list[tuple[str, str, str]]:
        calls.append(
            f"rows:{source_file}:{member_name}:{object_name}:"
            f"{','.join(column_names)}:{len(sample_rows)}"
        )
        return [(source_file, f"{member_name}#rows", str(len(sample_rows)))]

    kwargs = {
        **common_kwargs,
        "extract_sqlite_object_schema_payloads": _schema,
        "extract_sqlite_object_column_payloads": _columns,
        "extract_sqlite_object_row_payloads": _rows,
    }

    assert extract_sqlite_object_payload_family("schema", **kwargs) == [
        (
            "database.sqlite",
            "database.sqlite#schema",
            "CREATE TABLE credentials (email TEXT)",
        )
    ]
    assert extract_sqlite_object_payload_family("columns", **kwargs) == [
        ("database.sqlite", "database.sqlite#columns", "email")
    ]
    assert extract_sqlite_object_payload_family("rows", **kwargs) == [
        ("database.sqlite", "database.sqlite#rows", "1")
    ]
    assert extract_sqlite_object_payload_family("unknown", **kwargs) == []
    assert calls == [
        "schema:database.sqlite:database.sqlite:credentials:CREATE TABLE credentials (email TEXT)",
        "columns:database.sqlite:database.sqlite:credentials:email",
        "rows:database.sqlite:database.sqlite:credentials:email:1",
    ]


def test_extract_sqlite_object_row_payloads_orders_rows_and_filters_empty_payloads() -> None:
    calls: list[str] = []
    sample_rows = [
        ("owner@acme.example", "tok-123"),
        ("", ""),
        ("backup@acme.example", "tok-456"),
    ]

    def _run_ordered_batch(items: Any, func: Any, *, default_factory: Any) -> list[Any]:
        assert default_factory() is None
        values = list(items)
        calls.append(",".join(str(item[0]) for item in values))
        return [func(item) for item in values]

    def _row_payload(
        row_job: tuple[int, Sequence[Any]],
        *,
        source_file: str,
        member_name: str,
        object_name: str,
        column_names: Sequence[str],
    ) -> tuple[str, str, str] | None:
        index, row = row_job
        assert source_file == "database.sqlite"
        assert member_name == "database.sqlite"
        assert object_name == "credentials"
        assert list(column_names) == ["email", "token"]
        if not any(str(value or "").strip() for value in row):
            return None
        return (
            source_file,
            f"{member_name}#sqlite-row-{object_name}-{index}",
            "|".join(str(value or "") for value in row),
        )

    assert extract_sqlite_object_row_payloads(
        source_file="database.sqlite",
        member_name="database.sqlite",
        object_name="credentials",
        column_names=["email", "token"],
        sample_rows=sample_rows,
        run_ordered_batch=_run_ordered_batch,
        extract_sqlite_row_payload=_row_payload,
    ) == [
        (
            "database.sqlite",
            "database.sqlite#sqlite-row-credentials-1",
            "owner@acme.example|tok-123",
        ),
        (
            "database.sqlite",
            "database.sqlite#sqlite-row-credentials-3",
            "backup@acme.example|tok-456",
        ),
    ]
    assert calls == ["1,2,3"]


def test_extract_sqlite_row_payload_orders_cells_and_returns_none_for_empty_rows() -> None:
    calls: list[str] = []

    def _run_ordered_batch(items: Any, func: Any, *, default_factory: Any) -> list[str]:
        assert default_factory() == ""
        values = list(items)
        calls.append(",".join(str(item[0]) for item in values))
        return [func(item) for item in values]

    def _cell_line(cell_job: tuple[int, Any]) -> str:
        cell_index, value = cell_job
        if not str(value or "").strip():
            return ""
        column_name = ["email", "token"][cell_index] if cell_index < 2 else f"col_{cell_index + 1}"
        return f"{column_name}={value}"

    assert extract_sqlite_row_payload(
        (7, ("owner@acme.example", "", "overflow")),
        source_file="database.sqlite",
        member_name="database.sqlite",
        object_name="credentials",
        run_ordered_batch=_run_ordered_batch,
        extract_sqlite_row_cell_line=_cell_line,
    ) == (
        "database.sqlite",
        "database.sqlite#sqlite-row-credentials-7",
        "email=owner@acme.example\ncol_3=overflow",
    )
    assert extract_sqlite_row_payload(
        (8, ("", None)),
        source_file="database.sqlite",
        member_name="database.sqlite",
        object_name="credentials",
        run_ordered_batch=_run_ordered_batch,
        extract_sqlite_row_cell_line=_cell_line,
    ) is None
    assert calls == ["0,1,2", "0,1"]


def test_extract_sqlite_row_cell_line_formats_named_and_fallback_columns() -> None:
    def _sqlite_cell_text(value: Any) -> str:
        return str(value or "").strip()

    assert extract_sqlite_row_cell_line(
        (0, " owner@acme.example "),
        column_names=["email", "token"],
        sqlite_cell_text=_sqlite_cell_text,
    ) == "email=owner@acme.example"
    assert extract_sqlite_row_cell_line(
        (2, "overflow"),
        column_names=["email", "token"],
        sqlite_cell_text=_sqlite_cell_text,
    ) == "col_3=overflow"
    assert extract_sqlite_row_cell_line(
        (1, "tok-123"),
        column_names=["email", ""],
        sqlite_cell_text=_sqlite_cell_text,
    ) == "col_2=tok-123"
    assert extract_sqlite_row_cell_line(
        (0, " "),
        column_names=["email"],
        sqlite_cell_text=_sqlite_cell_text,
    ) == ""


def test_email_message_metadata_helpers_format_and_dedupe_ordered_headers() -> None:
    class _Message:
        values = {
            "subject": " Dossier ",
            "from": " analyst@acme.example ",
            "to": "",
            "cc": None,
            "bcc": " ",
            "reply-to": "reply@acme.example",
            "date": "Tue, 14 Jul 2026 10:00:00 +0000",
            "message-id": "<msg-1@acme.example>",
            "x-mailer": "FORGE Mail",
        }

        def get(self, header_name: str) -> str | None:
            return self.values.get(header_name)

    assert email_message_metadata_line(_Message(), "subject") == "subject=Dossier"
    assert email_message_metadata_line(_Message(), "to") == ""
    assert email_message_metadata_line(_Message(), "cc") == ""

    calls: list[str] = []

    def _run_ordered_batch(items: Any, func: Any, *, default_factory: Any) -> list[Any]:
        del default_factory
        values = list(items)
        calls.append(",".join(str(item) for item in values))
        lines = [func(item) for item in values]
        lines.append("SUBJECT=Dossier")
        return lines

    assert email_message_metadata_lines(
        _Message(),
        run_ordered_batch=_run_ordered_batch,
        email_message_metadata_line=email_message_metadata_line,
    ) == [
        "subject=Dossier",
        "from=analyst@acme.example",
        "reply-to=reply@acme.example",
        "date=Tue, 14 Jul 2026 10:00:00 +0000",
        "message-id=<msg-1@acme.example>",
        "x-mailer=FORGE Mail",
    ]
    assert calls == [
        "subject,from,to,cc,bcc,reply-to,date,message-id,x-mailer",
    ]


def test_extract_email_message_payloads_orders_families_and_handles_parse_fallback() -> None:
    calls: list[str] = []

    class _Part:
        def __init__(self, text: str) -> None:
            self.text = text

        def is_multipart(self) -> bool:
            return False

    class _Message:
        def walk(self) -> list[Any]:
            return [_Part("body"), _Part("attachment")]

    def _parse_email_message(data: bytes) -> _Message:
        if data == b"bad-message":
            raise ValueError("bad")
        return _Message()

    def _metadata_lines(message: Any) -> list[str]:
        assert isinstance(message, _Message)
        return ["subject=Demo", "from=owner@acme.example"]

    def _run_ordered_batch(items: Any, func: Any, *, default_factory: Any) -> list[Any]:
        del default_factory
        values = list(items)
        calls.append(",".join(str(item[0] if isinstance(item, tuple) else item) for item in values))
        return [func(item) for item in values]

    def _family(
        family: str,
        *,
        metadata_lines: Sequence[str],
        leaf_parts: Sequence[Any],
        source_file: str,
        member_name: str,
        depth: int,
    ) -> list[tuple[str, str, str] | tuple[str, str]]:
        assert metadata_lines == ["subject=Demo", "from=owner@acme.example"]
        assert [part.text for part in leaf_parts] == ["body", "attachment"]
        assert source_file == "message.eml"
        assert member_name == "message.eml"
        assert depth == 1
        return [
            (source_file, f"{member_name}#{family}", f"{family}-payload"),
            ("", f"{member_name}#empty-source-{family}", "skip"),
            (source_file, "", "skip"),
            (source_file, f"{member_name}#empty-text-{family}", ""),
            (source_file, f"{member_name}#short-{family}"),
        ]

    def _tuple_entries(
        item: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        _index, payloads = item
        return [
            payload
            for payload in payloads
            if len(payload) == 3 and all(str(part or "").strip() for part in payload)
        ]

    assert extract_email_message_payloads(
        b"ok-message",
        source_file="message.eml",
        member_name="message.eml",
        depth=1,
        max_artifact_member_bytes=6,
        parse_email_message=_parse_email_message,
        email_message_metadata_lines=_metadata_lines,
        extract_email_message_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
        run_ordered_batch=_run_ordered_batch,
    ) == [
        ("message.eml", "message.eml#summary", "summary-payload"),
        ("message.eml", "message.eml#parts", "parts-payload"),
    ]
    assert calls == [
        "summary,parts",
        "0,1",
    ]
    assert extract_email_message_payloads(
        b"bad-message",
        source_file="message.eml",
        member_name="message.eml",
        depth=0,
        max_artifact_member_bytes=6,
        parse_email_message=_parse_email_message,
        email_message_metadata_lines=_metadata_lines,
        extract_email_message_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
        run_ordered_batch=_run_ordered_batch,
    ) == [("message.eml", "message.eml", "bad-me")]
    assert extract_email_message_payloads(
        b"ok-message",
        source_file="message.eml",
        member_name="message.eml",
        depth=3,
        max_artifact_member_bytes=6,
        parse_email_message=_parse_email_message,
        email_message_metadata_lines=_metadata_lines,
        extract_email_message_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
        run_ordered_batch=_run_ordered_batch,
    ) == []
    assert extract_email_message_payloads(
        b"",
        source_file="message.eml",
        member_name="message.eml",
        depth=0,
        max_artifact_member_bytes=6,
        parse_email_message=_parse_email_message,
        email_message_metadata_lines=_metadata_lines,
        extract_email_message_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
        run_ordered_batch=_run_ordered_batch,
    ) == []


def test_extract_email_message_payload_family_dispatches_to_summary_and_parts() -> None:
    calls: list[str] = []
    leaf_parts = ["plain", "attachment"]
    metadata_lines = ["subject=Demo"]

    def _summary(
        lines: Sequence[str],
        source_file: str,
        member_name: str,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"summary:{','.join(lines)}:{source_file}:{member_name}")
        return [(source_file, f"{member_name}#message-meta", "\n".join(lines))]

    def _parts(
        parts: Sequence[Any],
        source_file: str,
        member_name: str,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"parts:{','.join(str(part) for part in parts)}:{source_file}:{member_name}:{depth}")
        return [(source_file, f"{member_name}.part-1.txt", "body")]

    kwargs = {
        "metadata_lines": metadata_lines,
        "leaf_parts": leaf_parts,
        "source_file": "message.eml",
        "member_name": "message.eml",
        "depth": 1,
        "extract_email_message_summary_payloads": _summary,
        "extract_email_message_part_payloads": _parts,
    }

    assert extract_email_message_payload_family("summary", **kwargs) == [
        ("message.eml", "message.eml#message-meta", "subject=Demo")
    ]
    assert extract_email_message_payload_family("parts", **kwargs) == [
        ("message.eml", "message.eml.part-1.txt", "body")
    ]
    assert extract_email_message_payload_family("unknown", **kwargs) == []
    assert calls == [
        "summary:subject=Demo:message.eml:message.eml",
        "parts:plain,attachment:message.eml:message.eml:1",
    ]


def test_extract_email_message_summary_payloads_formats_metadata_payload() -> None:
    assert extract_email_message_summary_payloads(
        ["subject=Demo", "from=owner@acme.example"],
        source_file="message.eml",
        member_name="message.eml",
    ) == [
        (
            "message.eml",
            "message.eml#message-meta",
            "subject=Demo\nfrom=owner@acme.example",
        )
    ]
    assert extract_email_message_summary_payloads(
        [],
        source_file="message.eml",
        member_name="message.eml",
    ) == []


def test_extract_email_message_part_payloads_orders_inline_and_deferred_payloads() -> None:
    calls: list[str] = []
    leaf_parts = ["plain", "attachment", "skip", "deferred"]

    class _PlanningEntry:
        def __init__(
            self,
            *,
            payloads: list[tuple[str, str, str]] | None = None,
            extraction_job: str | None = None,
        ) -> None:
            self.payloads = payloads or []
            self.extraction_job = extraction_job

    def _run_ordered_batch(items: Any, func: Any, *, default_factory: Any) -> list[Any]:
        del default_factory
        values = list(items)
        calls.append(",".join(str(item[0]) for item in values))
        return [func(item) for item in values]

    def _part_entry(
        part_job: tuple[int, str],
        *,
        source_file: str,
        member_name: str,
        depth: int,
    ) -> _PlanningEntry | object | None:
        index, part = part_job
        assert source_file == "message.eml"
        assert member_name == "message.eml"
        assert depth == 1
        if part == "plain":
            return _PlanningEntry(
                payloads=[
                    (source_file, f"{member_name}.part-{index}.txt", "plain-body"),
                    ("", "ignored", "ignored"),
                ]
            )
        if part == "attachment":
            return _PlanningEntry(extraction_job=f"job-{index}")
        if part == "deferred":
            return _PlanningEntry(extraction_job=f"job-{index}")
        return object()

    def _extract_job(job_entry: tuple[int, str]) -> tuple[int, list[tuple[str, str, str]]] | tuple[str] | None:
        result_index, job = job_entry
        if job == "job-2":
            return (
                result_index,
                [
                    ("message.eml", "message.eml.attachment-2", "attachment-body"),
                    ("message.eml", "", "skip"),
                ],
            )
        if job == "job-4":
            return ("bad",)
        return None

    def _tuple_entries(
        item: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        _index, payloads = item
        return [
            payload
            for payload in payloads
            if len(payload) == 3 and all(str(part or "").strip() for part in payload)
        ]

    assert extract_email_message_part_payloads(
        leaf_parts,
        source_file="message.eml",
        member_name="message.eml",
        depth=1,
        run_ordered_batch=_run_ordered_batch,
        email_message_part_entry=_part_entry,
        is_email_part_planning_entry=lambda entry: isinstance(entry, _PlanningEntry),
        email_part_entry_payloads=lambda entry: list(entry.payloads),
        email_part_entry_extraction_job=lambda entry: entry.extraction_job,
        extract_email_part_job_payload_entry=_extract_job,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == [
        ("message.eml", "message.eml.part-1.txt", "plain-body"),
        ("message.eml", "message.eml.attachment-2", "attachment-body"),
    ]
    assert calls == [
        "1,2,3,4",
        "1,2",
        "0,1,2",
    ]


def test_extract_email_part_job_payload_entry_delegates_valid_jobs_and_skips_negative_index() -> None:
    calls: list[str] = []

    def _extract_email_part_job(job: str) -> list[tuple[str, str, str]]:
        calls.append(job)
        return [("message.eml", f"message.eml.{job}", "payload")]

    assert extract_email_part_job_payload_entry(
        (2, "attachment"),
        extract_email_part_job=_extract_email_part_job,
    ) == (2, [("message.eml", "message.eml.attachment", "payload")])
    assert extract_email_part_job_payload_entry(
        (-1, "ignored"),
        extract_email_part_job=_extract_email_part_job,
    ) is None
    assert calls == ["attachment"]


def test_extract_email_part_job_expands_nested_messages_in_order() -> None:
    batch_sizes: list[int] = []

    def _run_ordered_batch(
        items: Sequence[Any],
        worker: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        batch_sizes.append(len(items))
        results: list[Any] = []
        for item in items:
            value = worker(item)
            results.append(value if value is not None else default_factory())
        return results

    def _extract_email_message_payloads(
        data: bytes,
        source_file: str,
        member_name: str,
        *,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        return [(source_file, f"{member_name}.depth-{depth}.txt", data.decode("utf-8"))]

    def _artifact_payload_tuple_batch_entries(
        item: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        _index, payloads = item
        return list(payloads)

    def _extract_member_data_payloads(*_args: Any, **_kwargs: Any) -> list[tuple[str, str, str]]:
        raise AssertionError("nested messages should not call member payload extraction")

    job = SimpleNamespace(
        source_file="message.eml",
        member_name="message.eml",
        depth=2,
        nested_messages=[
            ("first.eml", b"first"),
            ("second.eml", b"second"),
        ],
        payload_bytes=b"ignored",
    )

    assert extract_email_part_job(
        job,
        run_ordered_batch=_run_ordered_batch,
        extract_email_message_payloads=_extract_email_message_payloads,
        artifact_payload_tuple_batch_entries=_artifact_payload_tuple_batch_entries,
        extract_member_data_payloads=_extract_member_data_payloads,
    ) == [
        ("message.eml", "first.eml.depth-3.txt", "first"),
        ("message.eml", "second.eml.depth-3.txt", "second"),
    ]
    assert batch_sizes == [2, 2]


def test_extract_email_part_job_delegates_payload_bytes_and_skips_empty_payloads() -> None:
    calls: list[tuple[bytes, str, str, int]] = []

    def _run_ordered_batch(*_args: Any, **_kwargs: Any) -> list[Any]:
        raise AssertionError("plain payload jobs should not run nested batches")

    def _extract_email_message_payloads(*_args: Any, **_kwargs: Any) -> list[tuple[str, str, str]]:
        raise AssertionError("plain payload jobs should not extract nested messages")

    def _artifact_payload_tuple_batch_entries(*_args: Any, **_kwargs: Any) -> list[tuple[str, str, str]]:
        raise AssertionError("plain payload jobs should not flatten nested payloads")

    def _extract_member_data_payloads(
        data: bytes,
        source_file: str,
        member_name: str,
        *,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append((data, source_file, member_name, depth))
        return [(source_file, member_name, data.decode("utf-8"))]

    job = SimpleNamespace(
        source_file="message.eml",
        member_name="attachment.txt",
        depth=1,
        nested_messages=[],
        payload_bytes=b"payload",
    )
    assert extract_email_part_job(
        job,
        run_ordered_batch=_run_ordered_batch,
        extract_email_message_payloads=_extract_email_message_payloads,
        artifact_payload_tuple_batch_entries=_artifact_payload_tuple_batch_entries,
        extract_member_data_payloads=_extract_member_data_payloads,
    ) == [("message.eml", "attachment.txt", "payload")]
    empty_job = SimpleNamespace(
        source_file="message.eml",
        member_name="empty.txt",
        depth=1,
        nested_messages=[],
        payload_bytes=b"",
    )
    assert extract_email_part_job(
        empty_job,
        run_ordered_batch=_run_ordered_batch,
        extract_email_message_payloads=_extract_email_message_payloads,
        artifact_payload_tuple_batch_entries=_artifact_payload_tuple_batch_entries,
        extract_member_data_payloads=_extract_member_data_payloads,
    ) == []
    assert calls == [(b"payload", "message.eml", "attachment.txt", 1)]


def test_nested_email_message_job_normalizes_name_and_bounds_bytes() -> None:
    assert nested_email_message_job(
        (" attached.eml ", b"0123456789"),
        max_artifact_member_bytes=4,
    ) == ("attached.eml", b"0123")
    assert nested_email_message_job(
        (" ", b"payload"),
        max_artifact_member_bytes=4,
    ) is None
    assert nested_email_message_job(
        ("attached.eml", b""),
        max_artifact_member_bytes=4,
    ) is None


def test_mbox_message_job_bounds_bytes_and_skips_invalid_entries() -> None:
    assert mbox_message_job(
        (2, b"0123456789"),
        max_artifact_member_bytes=4,
    ) == (2, b"0123")
    assert mbox_message_job(
        (0, b"payload"),
        max_artifact_member_bytes=4,
    ) is None
    assert mbox_message_job(
        (1, b""),
        max_artifact_member_bytes=4,
    ) is None


def test_mbox_raw_message_jobs_extracts_ordered_message_bytes(tmp_path: Path) -> None:
    mbox_path = tmp_path / "messages.mbox"
    box = mailbox.mbox(str(mbox_path), create=True)
    try:
        for index in range(1, 3):
            message = EmailMessage()
            message["From"] = f"sender-{index}@example.test"
            message["To"] = "ops@example.test"
            message["Subject"] = f"Message {index}"
            message.set_content(f"Body {index}")
            box.add(message)
        box.flush()
    finally:
        box.close()

    result = mbox_raw_message_jobs(
        mbox_path.read_bytes(),
        max_artifact_member_bytes=4096,
    )

    assert isinstance(result, MboxRawMessageJobsResult)
    assert result.bounded == mbox_path.read_bytes()[:4096]
    assert result.message_count == 2
    assert not result.parse_failed
    assert [index for index, _message_bytes in result.raw_message_jobs] == [1, 2]
    assert b"sender-1@example.test" in result.raw_message_jobs[0][1]
    assert b"sender-2@example.test" in result.raw_message_jobs[1][1]


def test_extract_mbox_summary_payloads_reports_positive_message_counts() -> None:
    assert extract_mbox_summary_payloads(
        3,
        source_file="mailbox.mbox",
        member_name="mailbox.mbox",
    ) == [("mailbox.mbox", "mailbox.mbox#mbox-meta", "message_count=3")]
    assert extract_mbox_summary_payloads(
        0,
        source_file="mailbox.mbox",
        member_name="mailbox.mbox",
    ) == []


def test_extract_mbox_payload_family_dispatches_summary_messages_and_unknown_family() -> None:
    calls: list[str] = []
    message_jobs = [(1, b"one"), (2, b"two")]

    def _summary(
        message_count: int,
        *,
        source_file: str,
        member_name: str,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"summary:{message_count}:{source_file}:{member_name}")
        return [(source_file, f"{member_name}#mbox-meta", f"message_count={message_count}")]

    def _messages(
        jobs: Sequence[tuple[int, bytes]],
        *,
        source_file: str,
        member_name: str,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"messages:{len(jobs)}:{source_file}:{member_name}:{depth}")
        return [
            (source_file, f"{member_name}.message-{index}.eml", data.decode("utf-8"))
            for index, data in jobs
        ]

    assert extract_mbox_payload_family(
        "summary",
        message_jobs=message_jobs,
        message_count=2,
        source_file="mailbox.mbox",
        member_name="mailbox.mbox",
        depth=1,
        extract_mbox_summary_payloads=_summary,
        extract_mbox_message_payloads=_messages,
    ) == [("mailbox.mbox", "mailbox.mbox#mbox-meta", "message_count=2")]
    assert extract_mbox_payload_family(
        "messages",
        message_jobs=message_jobs,
        message_count=2,
        source_file="mailbox.mbox",
        member_name="mailbox.mbox",
        depth=1,
        extract_mbox_summary_payloads=_summary,
        extract_mbox_message_payloads=_messages,
    ) == [
        ("mailbox.mbox", "mailbox.mbox.message-1.eml", "one"),
        ("mailbox.mbox", "mailbox.mbox.message-2.eml", "two"),
    ]
    assert extract_mbox_payload_family(
        "unknown",
        message_jobs=message_jobs,
        message_count=2,
        source_file="mailbox.mbox",
        member_name="mailbox.mbox",
        depth=1,
        extract_mbox_summary_payloads=_summary,
        extract_mbox_message_payloads=_messages,
    ) == []
    assert calls == [
        "summary:2:mailbox.mbox:mailbox.mbox",
        "messages:2:mailbox.mbox:mailbox.mbox:1",
    ]


def test_extract_mbox_message_payloads_extracts_and_flattens_ordered_message_payloads() -> None:
    batch_sizes: list[int] = []
    message_jobs = [(1, b"one"), (2, b"two"), (3, b"three")]

    def _run_ordered_batch(
        items: Sequence[Any],
        worker: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        batch_sizes.append(len(items))
        results: list[Any] = []
        for item in items:
            value = worker(item)
            results.append(value if value is not None else default_factory())
        return results

    def _extract_email_message_payloads(
        data: bytes,
        source_file: str,
        message_name: str,
        *,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        return [
            (source_file, message_name, f"{data.decode('utf-8')}:{depth}"),
            (source_file, f"{message_name}#empty", ""),
        ]

    def _artifact_payload_tuple_batch_entries(
        item: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        _index, payloads = item
        return [
            payload
            for payload in payloads
            if len(payload) == 3 and all(str(part or "").strip() for part in payload)
        ]

    assert extract_mbox_message_payloads(
        message_jobs,
        source_file="mailbox.mbox",
        member_name="mailbox.mbox",
        depth=2,
        run_ordered_batch=_run_ordered_batch,
        extract_email_message_payloads=_extract_email_message_payloads,
        artifact_payload_tuple_batch_entries=_artifact_payload_tuple_batch_entries,
    ) == [
        ("mailbox.mbox", "mailbox.mbox.message-1.eml", "one:2"),
        ("mailbox.mbox", "mailbox.mbox.message-2.eml", "two:2"),
        ("mailbox.mbox", "mailbox.mbox.message-3.eml", "three:2"),
    ]
    assert batch_sizes == [3, 3]


def test_extract_mbox_bytes_payloads_coordinates_message_jobs_and_payload_families() -> None:
    batch_sizes: list[int] = []

    def _run_ordered_batch(
        items: Sequence[Any],
        worker: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        batch_sizes.append(len(items))
        results: list[Any] = []
        for item in items:
            value = worker(item)
            results.append(value if value is not None else default_factory())
        return results

    def _raw_messages(
        data: bytes,
        *,
        max_artifact_member_bytes: int,
    ) -> MboxRawMessageJobsResult:
        assert data == b"mailbox"
        assert max_artifact_member_bytes == 4
        return MboxRawMessageJobsResult(
            bounded=b"mail",
            message_count=2,
            raw_message_jobs=[(1, b"one"), (2, b"two")],
        )

    def _message_job(job: tuple[int, bytes]) -> tuple[int, bytes] | None:
        index, payload = job
        return index, payload.upper()

    def _family(
        family: str,
        *,
        message_jobs: Sequence[tuple[int, bytes]],
        message_count: int,
        source_file: str,
        member_name: str,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        assert list(message_jobs) == [(1, b"ONE"), (2, b"TWO")]
        assert message_count == 2
        assert source_file == "mailbox.mbox"
        assert member_name == "mailbox.mbox"
        assert depth == 1
        if family == "summary":
            return [(source_file, f"{member_name}#mbox-meta", "message_count=2")]
        if family == "messages":
            return [
                (source_file, f"{member_name}.message-1.eml", "one@example.test"),
                ("", "ignored", "ignored"),
            ]
        return []

    def _tuple_entries(
        item: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        _index, payloads = item
        return [
            payload
            for payload in payloads
            if len(payload) == 3 and all(str(part or "").strip() for part in payload)
        ]

    def _summary(*_args: Any, **_kwargs: Any) -> list[tuple[str, str, str]]:
        raise AssertionError("message jobs should use payload families")

    assert extract_mbox_bytes_payloads(
        b"mailbox",
        source_file="mailbox.mbox",
        member_name="mailbox.mbox",
        depth=1,
        max_artifact_member_bytes=4,
        run_ordered_batch=_run_ordered_batch,
        mbox_raw_message_jobs=_raw_messages,
        mbox_message_job=_message_job,
        extract_mbox_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
        extract_mbox_summary_payloads=_summary,
    ) == [
        ("mailbox.mbox", "mailbox.mbox#mbox-meta", "message_count=2"),
        ("mailbox.mbox", "mailbox.mbox.message-1.eml", "one@example.test"),
    ]
    assert batch_sizes == [2, 2, 2]


def test_extract_mbox_bytes_payloads_handles_parse_failure_and_plain_fallbacks() -> None:
    def _run_ordered_batch(*_args: Any, **_kwargs: Any) -> list[Any]:
        raise AssertionError("fallback branches should not run batches")

    def _message_job(*_args: Any, **_kwargs: Any) -> tuple[int, bytes] | None:
        raise AssertionError("fallback branches should not normalize message jobs")

    def _family(*_args: Any, **_kwargs: Any) -> list[tuple[str, str, str]]:
        raise AssertionError("fallback branches should not extract families")

    def _tuple_entries(*_args: Any, **_kwargs: Any) -> list[tuple[str, str, str]]:
        raise AssertionError("fallback branches should not flatten payloads")

    def _summary(
        message_count: int,
        *,
        source_file: str,
        member_name: str,
    ) -> list[tuple[str, str, str]]:
        return [(source_file, f"{member_name}#mbox-meta", f"message_count={message_count}")]

    def _parse_failed(
        _data: bytes,
        *,
        max_artifact_member_bytes: int,
    ) -> MboxRawMessageJobsResult:
        return MboxRawMessageJobsResult(
            bounded=b"not-mail"[:max_artifact_member_bytes],
            message_count=0,
            raw_message_jobs=[],
            parse_failed=True,
        )

    assert extract_mbox_bytes_payloads(
        b"not-mail",
        source_file="raw.mbox",
        member_name="raw.mbox",
        depth=0,
        max_artifact_member_bytes=4,
        run_ordered_batch=_run_ordered_batch,
        mbox_raw_message_jobs=_parse_failed,
        mbox_message_job=_message_job,
        extract_mbox_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
        extract_mbox_summary_payloads=_summary,
    ) == [("raw.mbox", "raw.mbox", "not-")]

    def _no_jobs_with_count(
        _data: bytes,
        *,
        max_artifact_member_bytes: int,
    ) -> MboxRawMessageJobsResult:
        return MboxRawMessageJobsResult(
            bounded=b"mail"[:max_artifact_member_bytes],
            message_count=2,
            raw_message_jobs=[],
        )

    assert extract_mbox_bytes_payloads(
        b"mail",
        source_file="empty-jobs.mbox",
        member_name="empty-jobs.mbox",
        depth=0,
        max_artifact_member_bytes=4,
        run_ordered_batch=lambda *_args, **_kwargs: [],
        mbox_raw_message_jobs=_no_jobs_with_count,
        mbox_message_job=_message_job,
        extract_mbox_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
        extract_mbox_summary_payloads=_summary,
    ) == [("empty-jobs.mbox", "empty-jobs.mbox#mbox-meta", "message_count=2")]

    def _empty(
        _data: bytes,
        *,
        max_artifact_member_bytes: int,
    ) -> MboxRawMessageJobsResult:
        return MboxRawMessageJobsResult(
            bounded=b"plain text"[:max_artifact_member_bytes],
            message_count=0,
            raw_message_jobs=[],
        )

    assert extract_mbox_bytes_payloads(
        b"plain text",
        source_file="plain.mbox",
        member_name="plain.mbox",
        depth=0,
        max_artifact_member_bytes=5,
        run_ordered_batch=lambda *_args, **_kwargs: [],
        mbox_raw_message_jobs=_empty,
        mbox_message_job=_message_job,
        extract_mbox_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
        extract_mbox_summary_payloads=_summary,
    ) == [("plain.mbox", "plain.mbox", "plain")]
    assert extract_mbox_bytes_payloads(
        b"mail",
        source_file="too-deep.mbox",
        member_name="too-deep.mbox",
        depth=3,
        max_artifact_member_bytes=4,
        run_ordered_batch=_run_ordered_batch,
        mbox_raw_message_jobs=_empty,
        mbox_message_job=_message_job,
        extract_mbox_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
        extract_mbox_summary_payloads=_summary,
    ) == []


def test_extract_rtf_payload_family_dispatches_text_embedded_archive_and_unknown_family() -> None:
    calls: list[str] = []

    def _text(
        text_payload: str,
        *,
        source_file: str,
        member_name: str,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"text:{text_payload}:{source_file}:{member_name}")
        return [(source_file, f"{member_name}#rtf-text", text_payload)]

    def _embedded(
        data: bytes,
        *,
        source_file: str,
        member_name: str,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"embedded:{data.decode('utf-8')}:{source_file}:{member_name}:{depth}")
        return [(source_file, f"{member_name}#embedded", "embedded")]

    assert extract_rtf_payload_family(
        "text",
        data=b"{\\rtf1}",
        source_file="document.rtf",
        member_name="document.rtf",
        text_payload="owner@example.test",
        depth=1,
        extract_rtf_text_payloads=_text,
        extract_rtf_embedded_archive_payloads=_embedded,
    ) == [("document.rtf", "document.rtf#rtf-text", "owner@example.test")]
    assert extract_rtf_payload_family(
        "embedded_archive",
        data=b"{\\rtf1}",
        source_file="document.rtf",
        member_name="document.rtf",
        text_payload="owner@example.test",
        depth=1,
        extract_rtf_text_payloads=_text,
        extract_rtf_embedded_archive_payloads=_embedded,
    ) == [("document.rtf", "document.rtf#embedded", "embedded")]
    assert extract_rtf_payload_family(
        "unknown",
        data=b"{\\rtf1}",
        source_file="document.rtf",
        member_name="document.rtf",
        text_payload="owner@example.test",
        depth=1,
        extract_rtf_text_payloads=_text,
        extract_rtf_embedded_archive_payloads=_embedded,
    ) == []
    assert calls == [
        "text:owner@example.test:document.rtf:document.rtf",
        "embedded:{\\rtf1}:document.rtf:document.rtf:1",
    ]


def test_extract_rtf_text_payloads_skips_blank_text_and_shapes_payload() -> None:
    assert extract_rtf_text_payloads(
        " owner@example.test ",
        source_file="document.rtf",
        member_name="document.rtf",
    ) == [("document.rtf", "document.rtf#rtf-text", " owner@example.test ")]
    assert extract_rtf_text_payloads(
        "   ",
        source_file="document.rtf",
        member_name="document.rtf",
    ) == []


def test_rtf_to_text_decodes_controls_hex_and_unicode_fallback() -> None:
    assert rtf_to_text(
        rb"{\rtf1\ansi Owner: rtf\'2downer\'40acme\'2eexample\par "
        rb"Portal:\tab https://rtf\'2eacme\'2eexample\par "
        rb"Dash:\emdash Bullet:\bullet Unicode:\u8211?}"
    ) == (
        "Owner: rtf-owner@acme.example\n"
        "Portal:\thttps://rtf.acme.example\n"
        "Dash:-Bullet:*Unicode:\u2013"
    )
    assert rtf_to_text(b"") == ""


def test_extract_rtf_embedded_archive_payloads_gates_depth_and_delegates_extraction() -> None:
    calls: list[tuple[bytes, str, str, int]] = []

    def _extract_embedded_archive_payloads(
        data: bytes,
        source_file: str,
        member_name: str,
        *,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append((data, source_file, member_name, depth))
        return [(source_file, f"{member_name}#embedded", data.decode("utf-8"))]

    assert extract_rtf_embedded_archive_payloads(
        b"archive",
        source_file="document.rtf",
        member_name="document.rtf",
        depth=1,
        extract_embedded_archive_payloads=_extract_embedded_archive_payloads,
    ) == [("document.rtf", "document.rtf#embedded", "archive")]
    assert extract_rtf_embedded_archive_payloads(
        b"archive",
        source_file="document.rtf",
        member_name="document.rtf",
        depth=2,
        extract_embedded_archive_payloads=_extract_embedded_archive_payloads,
    ) == []
    assert calls == [(b"archive", "document.rtf", "document.rtf", 1)]


def test_extract_rtf_bytes_payloads_coordinates_families_and_flattens_payloads() -> None:
    batch_sizes: list[int] = []

    def _run_ordered_batch(
        items: Sequence[Any],
        worker: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        batch_sizes.append(len(items))
        results: list[Any] = []
        for item in items:
            value = worker(item)
            results.append(value if value is not None else default_factory())
        return results

    def _family(
        family: str,
        *,
        data: bytes,
        source_file: str,
        member_name: str,
        text_payload: str,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        assert data == b"{\\rtf1 fake}"
        assert source_file == "document.rtf"
        assert member_name == "document.rtf"
        assert text_payload == "owner@example.test"
        assert depth == 1
        if family == "text":
            return [(source_file, f"{member_name}#rtf-text", text_payload)]
        if family == "embedded_archive":
            return [
                (source_file, f"{member_name}#embedded", "embedded"),
                (source_file, f"{member_name}#empty", ""),
            ]
        return []

    def _tuple_entries(
        item: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        _index, payloads = item
        return [
            payload
            for payload in payloads
            if len(payload) == 3 and all(str(part or "").strip() for part in payload)
        ]

    def _legacy(*_args: Any, **_kwargs: Any) -> list[tuple[str, str, str]]:
        raise AssertionError("nonblank RTF text should not use legacy fallback")

    assert extract_rtf_bytes_payloads(
        b"{\\rtf1 fake}",
        source_file="document.rtf",
        member_name="document.rtf",
        depth=1,
        rtf_to_text=lambda _data: "owner@example.test",
        run_ordered_batch=_run_ordered_batch,
        extract_rtf_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
        extract_legacy_binary_payloads=_legacy,
    ) == [
        ("document.rtf", "document.rtf#rtf-text", "owner@example.test"),
        ("document.rtf", "document.rtf#embedded", "embedded"),
    ]
    assert batch_sizes == [2, 2]


def test_extract_rtf_bytes_payloads_uses_legacy_fallback_for_blank_text() -> None:
    calls: list[tuple[bytes, str, str, int]] = []

    def _run_ordered_batch(*_args: Any, **_kwargs: Any) -> list[Any]:
        raise AssertionError("blank RTF text should not run family batches")

    def _family(*_args: Any, **_kwargs: Any) -> list[tuple[str, str, str]]:
        raise AssertionError("blank RTF text should not extract RTF families")

    def _tuple_entries(*_args: Any, **_kwargs: Any) -> list[tuple[str, str, str]]:
        raise AssertionError("blank RTF text should not flatten RTF families")

    def _legacy(
        data: bytes,
        source_file: str,
        member_name: str,
        *,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append((data, source_file, member_name, depth))
        return [(source_file, member_name, "legacy")]

    assert extract_rtf_bytes_payloads(
        b"{\\rtf1 fake}",
        source_file="document.rtf",
        member_name="document.rtf",
        depth=2,
        rtf_to_text=lambda _data: "   ",
        run_ordered_batch=_run_ordered_batch,
        extract_rtf_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
        extract_legacy_binary_payloads=_legacy,
    ) == [("document.rtf", "document.rtf", "legacy")]
    assert calls == [(b"{\\rtf1 fake}", "document.rtf", "document.rtf", 2)]


def test_extract_legacy_binary_payload_family_dispatches_strings_archives_ole_and_unknown() -> None:
    calls: list[str] = []

    def _strings(
        data: bytes,
        *,
        source_file: str,
        member_name: str,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"strings:{data.decode()}:{source_file}:{member_name}")
        return [(source_file, f"{member_name}#strings", "strings")]

    def _embedded(
        data: bytes,
        *,
        source_file: str,
        member_name: str,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"embedded:{data.decode()}:{source_file}:{member_name}:{depth}")
        return [(source_file, f"{member_name}#embedded", "embedded")]

    def _ole(
        data: bytes,
        *,
        source_file: str,
        member_name: str,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"ole:{data.decode()}:{source_file}:{member_name}:{depth}")
        return [(source_file, f"{member_name}#ole", "ole")]

    kwargs = {
        "data": b"binary",
        "source_file": "artifact.bin",
        "member_name": "artifact.bin",
        "depth": 1,
        "extract_legacy_binary_string_payloads": _strings,
        "extract_legacy_binary_embedded_archive_payloads": _embedded,
        "extract_legacy_binary_ole_payloads": _ole,
    }
    assert extract_legacy_binary_payload_family("strings", **kwargs) == [
        ("artifact.bin", "artifact.bin#strings", "strings")
    ]
    assert extract_legacy_binary_payload_family("embedded_archive", **kwargs) == [
        ("artifact.bin", "artifact.bin#embedded", "embedded")
    ]
    assert extract_legacy_binary_payload_family("ole", **kwargs) == [
        ("artifact.bin", "artifact.bin#ole", "ole")
    ]
    assert extract_legacy_binary_payload_family("unknown", **kwargs) == []
    assert calls == [
        "strings:binary:artifact.bin:artifact.bin",
        "embedded:binary:artifact.bin:artifact.bin:1",
        "ole:binary:artifact.bin:artifact.bin:1",
    ]


def test_extract_legacy_binary_string_payloads_builds_binary_string_payload() -> None:
    assert extract_legacy_binary_string_payloads(
        b"binary",
        source_file="artifact.bin",
        member_name="artifact.bin",
        binary_string_payload=lambda data: f"strings:{data.decode()}",
    ) == [
        ("artifact.bin", "artifact.bin#binary-strings", "strings:binary")
    ]
    assert extract_legacy_binary_string_payloads(
        b"binary",
        source_file="artifact.bin",
        member_name="artifact.bin",
        binary_string_payload=lambda _data: "",
    ) == []


def test_extract_legacy_binary_embedded_archive_payloads_combines_archives_and_images() -> None:
    calls: list[str] = []

    def _archives(
        data: bytes,
        source_file: str,
        member_name: str,
        *,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"archives:{data.decode()}:{source_file}:{member_name}:{depth}")
        return [(source_file, f"{member_name}#archive", "archive")]

    def _images(
        data: bytes,
        source_file: str,
        member_name: str,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"images:{data.decode()}:{source_file}:{member_name}")
        return [(source_file, f"{member_name}#image", "image")]

    assert extract_legacy_binary_embedded_archive_payloads(
        b"binary",
        source_file="artifact.bin",
        member_name="artifact.bin",
        depth=1,
        extract_embedded_archive_payloads=_archives,
        extract_embedded_image_payloads=_images,
    ) == [
        ("artifact.bin", "artifact.bin#archive", "archive"),
        ("artifact.bin", "artifact.bin#image", "image"),
    ]
    assert extract_legacy_binary_embedded_archive_payloads(
        b"binary",
        source_file="artifact.bin",
        member_name="artifact.bin",
        depth=2,
        extract_embedded_archive_payloads=_archives,
        extract_embedded_image_payloads=_images,
    ) == []
    assert calls == [
        "archives:binary:artifact.bin:artifact.bin:1",
        "images:binary:artifact.bin:artifact.bin",
    ]


def test_extract_legacy_binary_ole_payloads_dispatches_only_ole_magic() -> None:
    calls: list[str] = []

    def _ole(
        data: bytes,
        source_file: str,
        member_name: str,
        *,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"ole:{data[:3].decode(errors='ignore')}:{source_file}:{member_name}:{depth}")
        return [(source_file, f"{member_name}#ole", "ole")]

    assert extract_legacy_binary_ole_payloads(
        b"OLEpayload",
        source_file="artifact.bin",
        member_name="artifact.bin",
        depth=1,
        ole_magic=b"OLE",
        extract_ole_payloads=_ole,
    ) == [("artifact.bin", "artifact.bin#ole", "ole")]
    assert extract_legacy_binary_ole_payloads(
        b"ZIPpayload",
        source_file="artifact.bin",
        member_name="artifact.bin",
        depth=1,
        ole_magic=b"OLE",
        extract_ole_payloads=_ole,
    ) == []
    assert calls == ["ole:OLE:artifact.bin:artifact.bin:1"]


def test_extract_legacy_binary_payloads_coordinates_families_and_flattens_payloads() -> None:
    batch_sizes: list[int] = []

    def _run_ordered_batch(
        items: Sequence[Any],
        worker: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        batch_sizes.append(len(items))
        results: list[Any] = []
        for item in items:
            value = worker(item)
            results.append(value if value is not None else default_factory())
        return results

    def _family(
        family: str,
        *,
        data: bytes,
        source_file: str,
        member_name: str,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        assert data == b"binary"
        assert source_file == "artifact.bin"
        assert member_name == "artifact.bin"
        assert depth == 1
        if family == "strings":
            return [(source_file, f"{member_name}#strings", "strings")]
        if family == "embedded_archive":
            return [
                (source_file, f"{member_name}#embedded", "embedded"),
                ("", "ignored", "ignored"),
            ]
        if family == "ole":
            return [(source_file, f"{member_name}#ole", "")]
        return []

    def _tuple_entries(
        item: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        _index, payloads = item
        return [
            payload
            for payload in payloads
            if len(payload) == 3 and all(str(part or "").strip() for part in payload)
        ]

    assert extract_legacy_binary_payloads(
        b"binary",
        source_file="artifact.bin",
        member_name="artifact.bin",
        depth=1,
        run_ordered_batch=_run_ordered_batch,
        extract_legacy_binary_payload_family=_family,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == [
        ("artifact.bin", "artifact.bin#strings", "strings"),
        ("artifact.bin", "artifact.bin#embedded", "embedded"),
    ]
    assert batch_sizes == [3, 3]


def _ar_member(raw_name: bytes, payload: bytes) -> bytes:
    if len(raw_name) > 16:
        raise ValueError("AR member names are limited to 16 header bytes")
    header = (
        raw_name.ljust(16, b" ")
        + b"0".ljust(12, b" ")
        + b"0".ljust(6, b" ")
        + b"0".ljust(6, b" ")
        + b"100644".ljust(8, b" ")
        + str(len(payload)).encode("ascii").ljust(10, b" ")
        + b"`\n"
    )
    padding = b"\n" if len(payload) % 2 else b""
    return header + payload + padding


def test_ar_archive_member_jobs_handles_standard_bsd_and_gnu_names() -> None:
    gnu_names = b"nested/config.txt/\n"
    archive = (
        AR_ARCHIVE_MAGIC
        + _ar_member(b"short.txt/", b"short payload")
        + _ar_member(b"#1/15", b"bsd/config.json" + b"bsd payload")
        + _ar_member(b"//", gnu_names)
        + _ar_member(b"/0", b"gnu payload")
        + _ar_member(b"tiny.txt/", b"tiny")
        + _ar_member(b"../unsafe.txt/", b"unsafe")
        + _ar_member(b"empty.txt/", b"")
    )

    assert ar_archive_member_jobs(
        archive,
        remote_artifact_max_bytes=32,
    ) == [
        ("short.txt", b"short payload"),
        ("bsd/config.json", b"bsd payload"),
        ("nested/config.txt", b"gnu payload"),
        ("tiny.txt", b"tiny"),
    ]
    assert ar_archive_member_jobs(
        archive,
        remote_artifact_max_bytes=8,
    ) == [
        ("tiny.txt", b"tiny"),
    ]
    assert ar_archive_member_jobs(b"not-an-ar", remote_artifact_max_bytes=32) == []


def test_extract_archive_ar_payloads_coordinates_member_payloads_in_order() -> None:
    archive = AR_ARCHIVE_MAGIC + _ar_member(b"one.txt/", b"one") + _ar_member(
        b"two.txt/",
        b"two",
    )
    calls: list[str] = []

    def _extract_member(
        data: bytes,
        source_file: str,
        member_name: str,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"extract:{member_name}:{data.decode()}:{source_file}")
        return [(source_file, member_name, data.decode())]

    def _tuple_entries(
        item: tuple[int, list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        calls.append(f"batch:{item[0]}:{len(item[1])}")
        return item[1]

    assert extract_archive_ar_payloads(
        archive,
        source_file="lib.a",
        depth=1,
        ar_archive_member_jobs=lambda data: ar_archive_member_jobs(
            data,
            remote_artifact_max_bytes=32,
        ),
        run_ordered_batch=_run_ordered_batch,
        extract_member_data_payloads=_extract_member,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == [
        ("lib.a", "one.txt", "one"),
        ("lib.a", "two.txt", "two"),
    ]
    assert extract_archive_ar_payloads(
        b"bad",
        source_file="bad.a",
        depth=1,
        ar_archive_member_jobs=lambda data: ar_archive_member_jobs(
            data,
            remote_artifact_max_bytes=32,
        ),
        run_ordered_batch=_run_ordered_batch,
        extract_member_data_payloads=_extract_member,
        artifact_payload_tuple_batch_entries=_tuple_entries,
    ) == []
    assert calls == [
        "extract:one.txt:one:lib.a",
        "extract:two.txt:two:lib.a",
        "batch:0:1",
        "batch:1:1",
    ]


def _cpio_newc_entry(name: str, payload: bytes, *, mode: int = 0o100644) -> bytes:
    encoded_name = name.encode("utf-8") + b"\x00"
    fields = (
        CPIO_NEWC_MAGICS[0],
        f"{1:08x}".encode("ascii"),
        f"{mode:08x}".encode("ascii"),
        f"{0:08x}".encode("ascii"),
        f"{0:08x}".encode("ascii"),
        f"{1:08x}".encode("ascii"),
        f"{0:08x}".encode("ascii"),
        f"{len(payload):08x}".encode("ascii"),
        f"{0:08x}".encode("ascii"),
        f"{0:08x}".encode("ascii"),
        f"{0:08x}".encode("ascii"),
        f"{0:08x}".encode("ascii"),
        f"{len(encoded_name):08x}".encode("ascii"),
        f"{0:08x}".encode("ascii"),
    )
    header = b"".join(fields)
    name_padding = b"\x00" * ((4 - ((len(header) + len(encoded_name)) % 4)) % 4)
    data_padding = b"\x00" * ((4 - (len(payload) % 4)) % 4)
    return header + encoded_name + name_padding + payload + data_padding


def test_cpio_newc_member_jobs_filters_and_bounds_members() -> None:
    archive = (
        _cpio_newc_entry("config/app.env", b"owner@acme.example")
        + _cpio_newc_entry("nested/", b"", mode=0o040755)
        + _cpio_newc_entry("../unsafe.env", b"unsafe")
        + _cpio_newc_entry("tiny.txt", b"tiny")
        + _cpio_newc_entry("large.txt", b"larger payload")
        + _cpio_newc_entry("TRAILER!!!", b"")
    )

    assert cpio_newc_member_jobs(
        archive,
        max_artifact_member_bytes=64,
        remote_artifact_max_bytes=32,
    ) == [
        ("config/app.env", b"owner@acme.example"),
        ("tiny.txt", b"tiny"),
        ("large.txt", b"larger payload"),
    ]
    assert cpio_newc_member_jobs(
        archive,
        max_artifact_member_bytes=64,
        remote_artifact_max_bytes=8,
    ) == [
        ("tiny.txt", b"tiny"),
    ]
    assert cpio_newc_member_jobs(
        b"not-cpio",
        max_artifact_member_bytes=64,
        remote_artifact_max_bytes=32,
    ) == []


def test_extract_archive_cpio_payloads_delegates_member_jobs() -> None:
    archive = _cpio_newc_entry("one.txt", b"one") + _cpio_newc_entry("TRAILER!!!", b"")
    calls: list[str] = []

    def _extract_jobs(
        jobs: list[tuple[str, bytes]],
        source_file: str,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"jobs:{source_file}:{depth}:{len(jobs)}")
        return [(source_file, member_name, payload.decode()) for member_name, payload in jobs]

    assert extract_archive_cpio_payloads(
        archive,
        source_file="archive.cpio",
        depth=2,
        cpio_newc_member_jobs=lambda data: cpio_newc_member_jobs(
            data,
            max_artifact_member_bytes=64,
            remote_artifact_max_bytes=32,
        ),
        extract_text_member_payloads_from_jobs=_extract_jobs,
    ) == [("archive.cpio", "one.txt", "one")]
    assert extract_archive_cpio_payloads(
        b"bad",
        source_file="bad.cpio",
        depth=2,
        cpio_newc_member_jobs=lambda data: cpio_newc_member_jobs(
            data,
            max_artifact_member_bytes=64,
            remote_artifact_max_bytes=32,
        ),
        extract_text_member_payloads_from_jobs=_extract_jobs,
    ) == []
    assert calls == ["jobs:archive.cpio:2:1"]


def _asar_fixture(files: dict[str, Any], payloads: bytes) -> bytes:
    header_json = json.dumps({"files": files}, separators=(",", ":")).encode("utf-8")
    header_size = len(header_json) + 4
    return struct.pack("<II", header_size, len(header_json)) + header_json + b"\x00" * 4 + payloads


def test_asar_header_and_int_helpers_validate_inputs() -> None:
    payload = b"secret"
    archive = _asar_fixture(
        {"app.env": {"size": len(payload), "offset": "0"}},
        payload,
    )
    header_info = asar_header_and_content_base(archive, max_asar_header_bytes=256)

    assert header_info is not None
    header, content_base = header_info
    assert isinstance(header["files"], dict)
    assert archive[content_base:] == payload
    assert asar_header_and_content_base(b"short", max_asar_header_bytes=256) is None
    assert asar_header_and_content_base(archive, max_asar_header_bytes=4) is None
    assert asar_non_negative_int(0) == 0
    assert asar_non_negative_int("7") == 7
    assert asar_non_negative_int(True) is None
    assert asar_non_negative_int("-1") is None
    assert asar_non_negative_int("abc") is None


def test_asar_archive_member_jobs_filters_and_bounds_members() -> None:
    payloads = b"env-data" + b"image-bytes" + b"tiny" + b"oversized"
    files = {
        "config": {"files": {"app.env": {"size": 8, "offset": "0"}}},
        "image.png": {"size": 11, "offset": 8},
        "tiny.txt": {"size": 4, "offset": 19},
        "large.txt": {"size": 9, "offset": 23},
        "unpacked.txt": {"size": 4, "offset": 19, "unpacked": True},
        "../unsafe.txt": {"size": 4, "offset": 19},
        "empty.txt": {"size": 0, "offset": 0},
    }
    archive = _asar_fixture(files, payloads)

    assert asar_archive_member_jobs(
        archive,
        max_asar_header_bytes=512,
        max_asar_members=8,
        max_artifact_member_bytes=8,
        max_ocr_image_bytes=16,
        ocr_image_suffixes=(".png",),
    ) == [
        ("config/app.env", b"env-data"),
        ("image.png", b"image-bytes"),
        ("tiny.txt", b"tiny"),
    ]
    assert asar_archive_member_jobs(
        archive,
        max_asar_header_bytes=512,
        max_asar_members=2,
        max_artifact_member_bytes=8,
        max_ocr_image_bytes=16,
        ocr_image_suffixes=(".png",),
    ) == [
        ("config/app.env", b"env-data"),
        ("image.png", b"image-bytes"),
    ]
    assert asar_archive_member_jobs(
        archive,
        max_asar_header_bytes=512,
        max_asar_members=8,
        max_artifact_member_bytes=8,
        max_ocr_image_bytes=16,
        ocr_image_suffixes=(".png",),
        max_visit_depth=0,
    ) == [
        ("image.png", b"image-bytes"),
        ("tiny.txt", b"tiny"),
    ]
    assert asar_archive_member_jobs(
        b"not-asar",
        max_asar_header_bytes=512,
        max_asar_members=8,
        max_artifact_member_bytes=8,
        max_ocr_image_bytes=16,
        ocr_image_suffixes=(".png",),
    ) == []
    assert DEFAULT_MAX_ASAR_VISIT_DEPTH == 32


def test_extract_archive_asar_payloads_delegates_member_jobs() -> None:
    archive = _asar_fixture({"one.txt": {"size": 3, "offset": 0}}, b"one")
    calls: list[str] = []

    def _extract_jobs(
        jobs: list[tuple[str, bytes]],
        source_file: str,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"jobs:{source_file}:{depth}:{len(jobs)}")
        return [(source_file, member_name, payload.decode()) for member_name, payload in jobs]

    assert extract_archive_asar_payloads(
        archive,
        source_file="app.asar",
        depth=3,
        asar_archive_member_jobs=lambda data: asar_archive_member_jobs(
            data,
            max_asar_header_bytes=256,
            max_asar_members=8,
            max_artifact_member_bytes=8,
            max_ocr_image_bytes=16,
            ocr_image_suffixes=(".png",),
        ),
        extract_text_member_payloads_from_jobs=_extract_jobs,
    ) == [("app.asar", "one.txt", "one")]
    assert extract_archive_asar_payloads(
        b"bad",
        source_file="bad.asar",
        depth=3,
        asar_archive_member_jobs=lambda data: asar_archive_member_jobs(
            data,
            max_asar_header_bytes=256,
            max_asar_members=8,
            max_artifact_member_bytes=8,
            max_ocr_image_bytes=16,
            ocr_image_suffixes=(".png",),
        ),
        extract_text_member_payloads_from_jobs=_extract_jobs,
    ) == []
    assert calls == ["jobs:app.asar:3:1"]


def test_extract_archive_decompressed_payloads_recurses_or_falls_back_to_text() -> None:
    calls: list[str] = []

    def _decompress(data: bytes, member_name: str) -> tuple[str, bytes] | None:
        calls.append(f"decompress:{data.decode()}:{member_name}")
        if data == b"none":
            return None
        return "gz", b"nested-data"

    def _extract_archive_bytes(
        data: bytes,
        source_file: str,
        member_name: str,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"archive:{data.decode()}:{source_file}:{member_name}")
        if source_file == "archive.bin":
            return [(source_file, f"{member_name}/child.txt", "child")]
        return []

    assert extract_archive_decompressed_payloads(
        b"payload",
        source_file="archive.bin",
        member_name="member.gz",
        depth=2,
        decompress_archive_stream=_decompress,
        extract_archive_bytes=_extract_archive_bytes,
        decode_text_artifact_bytes=lambda data: f"text:{data.decode()}",
    ) == [("archive.bin", "member.gz#decompressed-gz/child.txt", "child")]
    assert extract_archive_decompressed_payloads(
        b"payload",
        source_file="fallback.bin",
        member_name="member.gz",
        depth=2,
        decompress_archive_stream=_decompress,
        extract_archive_bytes=_extract_archive_bytes,
        decode_text_artifact_bytes=lambda data: f"text:{data.decode()}",
    ) == [("fallback.bin", "member.gz#decompressed-gz.txt", "text:nested-data")]
    assert extract_archive_decompressed_payloads(
        b"none",
        source_file="archive.bin",
        member_name="member.gz",
        depth=2,
        decompress_archive_stream=_decompress,
        extract_archive_bytes=_extract_archive_bytes,
        decode_text_artifact_bytes=lambda data: f"text:{data.decode()}",
    ) == []
    assert calls == [
        "decompress:payload:member.gz",
        "archive:nested-data:archive.bin:member.gz#decompressed-gz",
        "decompress:payload:member.gz",
        "archive:nested-data:fallback.bin:member.gz#decompressed-gz",
        "decompress:none:member.gz",
    ]


def test_extract_archive_zip_payloads_combines_text_and_saz_payloads() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("app/config.txt", "owner@acme.example")
        zf.writestr("raw/1_c.txt", "GET / HTTP/1.1")
    data = buffer.getvalue()
    calls: list[str] = []

    def _text_payloads(zf: zipfile.ZipFile, source_file: str) -> list[tuple[str, str, str]]:
        calls.append(f"text:{source_file}:{len(zf.infolist())}")
        return [(source_file, "app/config.txt", "owner@acme.example")]

    def _saz_payloads(zf: zipfile.ZipFile, source_file: str) -> list[tuple[str, str, str]]:
        calls.append(f"saz:{source_file}:{len(zf.infolist())}")
        return [(source_file, "raw/1_c.txt#saz", "https://saz.acme.example")]

    assert extract_archive_zip_payloads(
        data,
        source_file="bundle.zip",
        depth=1,
        extract_text_payloads_from_zip=_text_payloads,
        extract_saz_session_pairing_payloads=_saz_payloads,
    ) == [
        ("bundle.zip", "app/config.txt", "owner@acme.example"),
        ("bundle.zip", "raw/1_c.txt#saz", "https://saz.acme.example"),
    ]
    assert extract_archive_zip_payloads(
        b"not-a-zip",
        source_file="bundle.bin",
        depth=1,
        extract_text_payloads_from_zip=_text_payloads,
        extract_saz_session_pairing_payloads=_saz_payloads,
    ) == []
    assert calls == ["text:bundle.zip:2", "saz:bundle.zip:2"]


def test_extract_archive_tar_payloads_preserves_image_and_text_precedence() -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        member_data = b"owner@acme.example\n"
        member = tarfile.TarInfo("app/config.txt")
        member.size = len(member_data)
        tf.addfile(member, io.BytesIO(member_data))
    data = buffer.getvalue()
    calls: list[str] = []

    def _oci_payloads(
        tf: tarfile.TarFile,
        members: Any,
        source_file: str,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"oci:{source_file}:{len(list(members))}:{tf.name is None}")
        if source_file == "oci.tar":
            return [(source_file, "oci/layer.txt", "oci")]
        return []

    def _docker_payloads(
        tf: tarfile.TarFile,
        members: Any,
        source_file: str,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"docker:{source_file}:{len(list(members))}:{tf.name is None}")
        if source_file == "docker.tar":
            return [(source_file, "docker/layer.txt", "docker")]
        return []

    def _text_payloads(
        tf: tarfile.TarFile,
        source_file: str,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"text:{source_file}:{len(tf.getmembers())}")
        return [(source_file, "app/config.txt", "owner@acme.example")]

    callbacks = {
        "extract_oci_image_layout_tar_payloads": _oci_payloads,
        "extract_docker_save_image_tar_payloads": _docker_payloads,
        "extract_text_payloads_from_tar": _text_payloads,
    }

    assert extract_archive_tar_payloads(
        data,
        source_file="oci.tar",
        depth=1,
        **callbacks,
    ) == [("oci.tar", "oci/layer.txt", "oci")]
    assert extract_archive_tar_payloads(
        data,
        source_file="docker.tar",
        depth=1,
        **callbacks,
    ) == [("docker.tar", "docker/layer.txt", "docker")]
    assert extract_archive_tar_payloads(
        data,
        source_file="plain.tar",
        depth=1,
        **callbacks,
    ) == [("plain.tar", "app/config.txt", "owner@acme.example")]
    assert extract_archive_tar_payloads(
        b"not-a-tar",
        source_file="bad.tar",
        depth=1,
        **callbacks,
    ) == []
    assert calls == [
        "oci:oci.tar:1:True",
        "oci:docker.tar:1:True",
        "docker:docker.tar:1:True",
        "oci:plain.tar:1:True",
        "docker:plain.tar:1:True",
        "text:plain.tar:1",
    ]


def test_extract_archive_tar_payloads_ignores_archives_without_files() -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        directory = tarfile.TarInfo("empty/")
        directory.type = tarfile.DIRTYPE
        tf.addfile(directory)
    calls: list[str] = []

    assert extract_archive_tar_payloads(
        buffer.getvalue(),
        source_file="empty.tar",
        depth=1,
        extract_oci_image_layout_tar_payloads=lambda *_args: calls.append("oci") or [],
        extract_docker_save_image_tar_payloads=lambda *_args: calls.append("docker") or [],
        extract_text_payloads_from_tar=lambda *_args: calls.append("text") or [],
    ) == []
    assert calls == []


def test_crx_zip_payload_bytes_strips_crx2_and_crx3_headers() -> None:
    zip_payload = b"PK\x03\x04zip-data"
    crx2 = b"Cr24" + struct.pack("<III", 2, 3, 4) + b"key" + b"sig!" + zip_payload
    crx3 = b"Cr24" + struct.pack("<II", 3, 5) + b"hdr!!" + zip_payload

    assert crx_zip_payload_bytes(crx2) == zip_payload
    assert crx_zip_payload_bytes(crx3) == zip_payload
    assert crx_zip_payload_bytes(b"Cr24" + struct.pack("<II", 99, 0) + zip_payload) == b""
    assert crx_zip_payload_bytes(b"Cr24" + struct.pack("<II", 3, 0) + b"not-a-zip") == b""
    assert crx_zip_payload_bytes(b"nope" + zip_payload) == b""


def test_extract_archive_crx_payloads_delegates_embedded_zip_payload() -> None:
    calls: list[str] = []

    def _zip_payload(data: bytes) -> bytes:
        calls.append(f"strip:{data.decode()}")
        return b"PK\x03\x04zip"

    def _extract_zip(
        data: bytes,
        *,
        source_file: str,
        depth: int,
    ) -> list[tuple[str, str, str]]:
        calls.append(f"zip:{data.decode(errors='ignore')}:{source_file}:{depth}")
        return [(source_file, "manifest.json", "payload")]

    assert extract_archive_crx_payloads(
        b"crx-data",
        source_file="extension.crx",
        depth=1,
        crx_zip_payload_bytes=_zip_payload,
        extract_archive_zip_payloads=_extract_zip,
    ) == [("extension.crx", "manifest.json", "payload")]
    assert calls == ["strip:crx-data", "zip:PK\x03\x04zip:extension.crx:1"]

    calls.clear()
    assert extract_archive_crx_payloads(
        b"bad-crx",
        source_file="extension.crx",
        depth=1,
        crx_zip_payload_bytes=lambda _data: b"",
        extract_archive_zip_payloads=_extract_zip,
    ) == []
    assert calls == []


def test_saz_raw_session_member_entry_normalizes_and_filters_members() -> None:
    member = zipfile.ZipInfo("captures/raw/12_C.txt")
    member.file_size = 10
    large_member = zipfile.ZipInfo("raw/13_s.txt")
    large_member.file_size = 11

    assert saz_raw_session_member_entry(member, max_artifact_member_bytes=10) == (
        "12",
        "c",
        "captures/raw/12_C.txt",
    )
    assert saz_raw_session_member_entry(
        zipfile.ZipInfo("raw/"),
        max_artifact_member_bytes=10,
    ) is None
    assert saz_raw_session_member_entry(large_member, max_artifact_member_bytes=10) is None
    assert saz_raw_session_member_entry(
        zipfile.ZipInfo("../raw/13_c.txt"),
        max_artifact_member_bytes=10,
    ) is None
    assert saz_raw_session_member_entry(
        zipfile.ZipInfo("raw/13_x.txt"),
        max_artifact_member_bytes=10,
    ) is None


def test_saz_request_origin_and_relative_locations_are_derived_from_transcripts() -> None:
    header_re = re.compile(
        r"""(?im)^\s*
        (?P<name>:?[A-Za-z0-9_.\-]+)
        \s*:\s*
        (?P<value>[^\r\n]+)
        """,
        re.VERBOSE,
    )

    assert saz_request_origin_url(
        "GET /ignored HTTP/1.1",
        http_transcript_text_candidate_values=lambda _text: [
            "not-a-url",
            "https://app.example.test/start?token=abc",
        ],
        http_transcript_url_candidate_entry=lambda value: value,
    ) == "https://app.example.test"
    assert saz_response_relative_locations(
        "\n".join(
            [
                "HTTP/1.1 302 Found",
                "Location: /next",
                "Content-Location: '/content'",
                "Location: //external.example.test/ignored",
                "Location: https://external.example.test/ignored",
                "Location: /next",
            ]
        ),
        http_transcript_header_re=header_re,
    ) == ["/next", "/content"]


def test_saz_session_pairing_payload_builds_synthetic_redirect_payload() -> None:
    header_re = re.compile(r"(?im)^\s*(?P<name>[A-Za-z0-9_.\-]+)\s*:\s*(?P<value>[^\r\n]+)")
    payload = saz_session_pairing_payload(
        (
            "7",
            ("raw/7_c.txt", b"request"),
            ("raw/7_s.txt", b"HTTP/1.1 302 Found\r\nLocation: /finish\r\n"),
        ),
        source_file="traffic.saz",
        max_artifact_member_bytes=1024,
        decode_text_artifact_bytes=lambda data: data.decode("utf-8"),
        http_transcript_text_candidate_values=lambda _text: ["https://app.example.test/login"],
        http_transcript_url_candidate_entry=lambda value: value,
        http_transcript_header_re=header_re,
    )

    assert payload == (
        "traffic.saz",
        "raw/7_c+s.txt#saz-session-pair",
        "\n".join(
            [
                "request.member=raw/7_c.txt",
                "response.member=raw/7_s.txt",
                "https://app.example.test/finish",
            ]
        ),
    )


def test_extract_saz_session_pairing_payloads_pairs_complete_sessions_in_order() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("raw/2_s.txt", "response-2")
        zf.writestr("raw/1_c.txt", "request-1")
        zf.writestr("raw/2_c.txt", "request-2")
        zf.writestr("raw/3_c.txt", "request-3")
        zf.writestr("raw/1_s.txt", "response-1")
        zf.writestr("notes.txt", "ignored")
    buffer.seek(0)
    calls: list[str] = []

    def _run_ordered_batch(items: Any, worker: Any, *, default_factory: Any) -> list[Any]:
        del default_factory
        return [worker(item) for item in items]

    def _pair(job: tuple[str, tuple[str, bytes], tuple[str, bytes]]) -> tuple[str, str, str] | None:
        session_id, request_member, response_member = job
        calls.append(session_id)
        return (
            "traffic.saz",
            f"raw/{session_id}_c+s.txt#saz-session-pair",
            f"{request_member[0]} -> {response_member[0]}",
        )

    with zipfile.ZipFile(buffer) as zf:
        payloads = extract_saz_session_pairing_payloads(
            zf,
            source_file="traffic.saz",
            max_artifact_member_bytes=1024,
            run_ordered_batch=_run_ordered_batch,
            saz_raw_session_member_entry=lambda member: saz_raw_session_member_entry(
                member,
                max_artifact_member_bytes=1024,
            ),
            saz_session_pairing_payload=_pair,
        )

    assert calls == ["1", "2"]
    assert payloads == [
        (
            "traffic.saz",
            "raw/1_c+s.txt#saz-session-pair",
            "raw/1_c.txt -> raw/1_s.txt",
        ),
        (
            "traffic.saz",
            "raw/2_c+s.txt#saz-session-pair",
            "raw/2_c.txt -> raw/2_s.txt",
        ),
    ]


def test_store_supabase_configs_coordinates_cloud_seed_url_and_key_callbacks() -> None:
    con = sqlite3.connect(":memory:")
    artifact_context = {"parser": "json", "payload_count": 1}
    child_depth_calls: list[int | None] = []
    cloud_metadata_calls: list[dict[str, Any]] = []
    cloud_calls: list[dict[str, Any]] = []
    url_calls: list[dict[str, Any]] = []
    insert_calls: list[dict[str, Any]] = []
    link_calls: list[dict[str, Any]] = []
    key_calls: list[dict[str, Any]] = []

    config_entry = {
        "project_ref": "abcxyz",
        "project_url": "https://abcxyz.supabase.co",
        "source_file": "lib/supabase.ts",
        "key_redacted": "sb-anon-...",
        "key_enc": "encrypted-key",
        "relation_metadata": {
            "rule": "supabase_mobile_config",
            "source_file": "lib/supabase.ts",
        },
    }

    def _child_depth(inner_con: sqlite3.Connection, source_seed_id: int | None) -> int:
        assert inner_con is con
        child_depth_calls.append(source_seed_id)
        return 5

    def _entry(config: Any, *, source_url: str) -> dict[str, Any] | None:
        assert config == "supabase-one"
        assert source_url == "artifact://queue/8"
        return dict(config_entry)

    def _cloud_metadata(inner_con: sqlite3.Connection, **kwargs: Any) -> dict[str, Any]:
        assert inner_con is con
        cloud_metadata_calls.append(dict(kwargs))
        return {"artifact_provenance": True, "source_seed_id": kwargs["source_seed_id"]}

    def _store_cloud(inner_con: sqlite3.Connection, **kwargs: Any) -> None:
        assert inner_con is con
        cloud_calls.append(dict(kwargs))

    def _store_url(
        inner_con: sqlite3.Connection,
        url: str,
        *,
        source: str,
        confidence: float,
        source_seed_id: int | None,
        depth: int,
        relation_metadata: dict[str, Any],
    ) -> int:
        assert inner_con is con
        url_calls.append(
            {
                "url": url,
                "source": source,
                "confidence": confidence,
                "source_seed_id": source_seed_id,
                "depth": depth,
                "relation_metadata": dict(relation_metadata),
            }
        )
        return 3

    def _insert_seed(
        inner_con: sqlite3.Connection,
        seed_value: str,
        seed_type: str,
        *,
        source: str,
        confidence: float,
        depth: int,
    ) -> bool:
        assert inner_con is con
        insert_calls.append(
            {
                "seed_value": seed_value,
                "seed_type": seed_type,
                "source": source,
                "confidence": confidence,
                "depth": depth,
            }
        )
        return True

    def _link_seed(
        inner_con: sqlite3.Connection,
        source_seed_id: int | None,
        seed_value: str,
        seed_type: str,
        *,
        confidence: float,
        metadata: dict[str, Any],
    ) -> None:
        assert inner_con is con
        link_calls.append(
            {
                "source_seed_id": source_seed_id,
                "seed_value": seed_value,
                "seed_type": seed_type,
                "confidence": confidence,
                "metadata": dict(metadata),
            }
        )

    def _store_key(inner_con: sqlite3.Connection, **kwargs: Any) -> None:
        assert inner_con is con
        key_calls.append(dict(kwargs))

    result = store_supabase_configs(
        con,
        ["supabase-one"],
        source_seed_id=66,
        source_url="artifact://queue/8",
        artifact_context=artifact_context,
        artifact_child_seed_depth=_child_depth,
        run_ordered_batch=_run_ordered_batch,
        supabase_config_persistence_entry=_entry,
        store_cloud_asset_reference=_store_cloud,
        artifact_cloud_asset_metadata=_cloud_metadata,
        store_artifact_url_seed=_store_url,
        merge_artifact_relation_context_fn=merge_artifact_relation_context,
        insert_seed=_insert_seed,
        link_artifact_source_seed=_link_seed,
        store_key_finding=_store_key,
    )

    assert result == (1, 2)
    assert child_depth_calls == [66]
    assert cloud_metadata_calls == [
        {
            "source_seed_id": 66,
            "relation_metadata": config_entry["relation_metadata"],
            "artifact_context": artifact_context,
        }
    ]
    assert cloud_calls == [
        {
            "asset_type": "supabase",
            "identifier": "abcxyz",
            "source": "mobile_config_parse",
            "metadata": {"artifact_provenance": True, "source_seed_id": 66},
        }
    ]
    assert url_calls == [
        {
            "url": "https://abcxyz.supabase.co",
            "source": "artifact",
            "confidence": 0.8,
            "source_seed_id": 66,
            "depth": 5,
            "relation_metadata": {
                "parser": "json",
                "payload_count": 1,
                "rule": "supabase_mobile_config",
                "source_file": "lib/supabase.ts",
            },
        }
    ]
    assert insert_calls == [
        {
            "seed_value": "abcxyz",
            "seed_type": "other",
            "source": "artifact",
            "confidence": 0.72,
            "depth": 5,
        }
    ]
    assert link_calls == [
        {
            "source_seed_id": 66,
            "seed_value": "abcxyz",
            "seed_type": "other",
            "confidence": 0.72,
            "metadata": {
                "parser": "json",
                "payload_count": 1,
                "rule": "supabase_mobile_config",
                "source_file": "lib/supabase.ts",
            },
        }
    ]
    assert key_calls == [
        {
            "service": "supabase",
            "domain": "abcxyz",
            "source_url": "lib/supabase.ts",
            "pattern_name": "supabase_mobile_config",
            "key_redacted": "sb-anon-...",
            "key_enc": "encrypted-key",
        }
    ]


def test_merge_artifact_relation_evidence_drops_empty_values_and_overwrites_scalars() -> None:
    merged = merge_artifact_relation_evidence(
        {"rule": "old", "source_file": "artifact.txt", "keep": True},
        {"rule": "new", "source_file": "", "payload_count": 2, "empty": []},
    )

    assert merged == {
        "rule": "new",
        "source_file": "artifact.txt",
        "keep": True,
        "payload_count": 2,
    }


def test_link_artifact_source_seed_merges_seed_metadata_and_relation_evidence(tmp_path: Path) -> None:
    db_path = tmp_path / "provenance.db"
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        con.execute(
            """
            CREATE TABLE engagement_seeds (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER NOT NULL,
                seed_value TEXT NOT NULL,
                seed_type TEXT NOT NULL,
                source TEXT,
                status TEXT,
                depth INTEGER,
                confidence REAL,
                metadata_json TEXT DEFAULT '{}',
                updated_at TEXT,
                UNIQUE(engagement_id, seed_type, seed_value)
            )
            """
        )
        con.execute(
            """
            CREATE TABLE seed_relations (
                engagement_id INTEGER NOT NULL,
                source_seed_id INTEGER NOT NULL,
                target_seed_id INTEGER NOT NULL,
                relation_type TEXT NOT NULL,
                confidence REAL,
                evidence_json TEXT DEFAULT '{}'
            )
            """
        )
        con.executemany(
            """
            INSERT INTO engagement_seeds
                (id, engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
            VALUES (?, 1001, ?, ?, 'artifact', 'completed', 0, 0.9, ?)
            """,
            [
                (
                    10,
                    "https://id.acme.example/.well-known/webfinger",
                    "url",
                    json.dumps(
                        {
                            "archive_sources": ["wayback", "commoncrawl"],
                            "provider_sources": ["wayback"],
                            "root_domain": "acme.example",
                            "source_url": "https://id.acme.example/.well-known/webfinger",
                            "unsafe": "drop",
                        },
                        sort_keys=True,
                    ),
                ),
                (
                    20,
                    "owner@acme.example",
                    "email",
                    json.dumps(
                        {
                            "source_url": "existing://owner",
                            "archive_sources": ["existing.zip"],
                        },
                        sort_keys=True,
                    ),
                ),
            ],
        )

        link_artifact_source_seed(
            con,
            1001,
            10,
            "owner@acme.example",
            "email",
            confidence=0.74,
            metadata={
                "rule": "artifact_text_extract",
                "source_file": "webfinger.json",
                "payload_count": 3,
            },
        )
        link_artifact_source_seed(
            con,
            1001,
            10,
            "owner@acme.example",
            "email",
            confidence=0.91,
            metadata={"source_rule": "followup", "payload_count": 4},
        )

        target = con.execute("SELECT metadata_json FROM engagement_seeds WHERE id=20").fetchone()
        assert target is not None
        target_metadata = json.loads(str(target["metadata_json"]))
        assert target_metadata == {
            "archive_sources": ["existing.zip", "wayback", "commoncrawl"],
            "artifact_provenance": True,
            "artifact_source_seed_id": 10,
            "extract_rule": "artifact_text_extract",
            "payload_count": 3,
            "provider_sources": ["wayback"],
            "root_domain": "acme.example",
            "source_file": "webfinger.json",
            "source_rule": "followup",
            "source_url": "existing://owner",
        }

        relation = con.execute(
            """
            SELECT confidence, evidence_json
            FROM seed_relations
            WHERE engagement_id=1001
              AND source_seed_id=10
              AND target_seed_id=20
              AND relation_type='derived_from'
            """
        ).fetchone()
        assert relation is not None
        assert float(relation["confidence"]) == 0.91
        assert json.loads(str(relation["evidence_json"])) == {
            "archive_sources": ["wayback", "commoncrawl"],
            "extract_rule": "artifact_text_extract",
            "payload_count": 4,
            "provider_sources": ["wayback"],
            "root_domain": "acme.example",
            "rule": "artifact_seed_provenance",
            "source_file": "webfinger.json",
            "source_rule": "followup",
            "source_url": "https://id.acme.example/.well-known/webfinger",
        }
    finally:
        con.close()


def test_local_artifact_record_uses_classifier_and_metadata_callback(tmp_path: Path) -> None:
    artifact_path = tmp_path / "artifact.json"
    artifact_path.write_text("{}", encoding="utf-8")

    assert local_artifact_record(
        artifact_path,
        classify_artifact=lambda _path: None,
        local_artifact_metadata=lambda _path: {"unused": True},
    ) is None

    record = local_artifact_record(
        artifact_path,
        classify_artifact=lambda path: "config" if path == artifact_path else None,
        local_artifact_metadata=lambda path: {"size": path.stat().st_size},
    )

    assert record == (artifact_path.resolve().as_posix(), "config", {"size": 2})


def test_default_local_artifact_roots_preserve_expected_order(tmp_path: Path) -> None:
    roots = default_local_artifact_roots(tmp_path)

    assert roots == [
        tmp_path / "data" / "mobile",
        tmp_path / "data" / "artifacts",
        tmp_path / "data" / "evidence",
        tmp_path / "data" / "uploads",
    ]


def test_default_local_artifact_roots_remain_legacy_import_compatible(tmp_path: Path) -> None:
    from forge.engagement_orchestrator import default_local_artifact_roots as legacy_default_roots  # noqa: PLC0415

    assert legacy_default_roots(tmp_path) == default_local_artifact_roots(tmp_path)


def test_local_artifact_candidate_paths_collects_files_only(tmp_path: Path) -> None:
    root = tmp_path / "root"
    nested = root / "nested"
    nested.mkdir(parents=True)
    first = root / "config.json"
    second = nested / "mobile.apk"
    first.write_text("{}", encoding="utf-8")
    second.write_bytes(b"apk")

    candidates = local_artifact_candidate_paths([tmp_path / "missing", root])

    assert {path.resolve() for path in candidates} == {first.resolve(), second.resolve()}
    assert nested not in candidates


def test_resolve_local_artifact_path_prefers_local_then_source(tmp_path: Path) -> None:
    local_path = tmp_path / "local.json"
    source_path = tmp_path / "source.json"
    source_path.write_text("source", encoding="utf-8")

    assert resolve_local_artifact_path("", "") is None
    assert (
        resolve_local_artifact_path(str(tmp_path / "missing.json"), str(source_path))
        == source_path
    )

    local_path.write_text("local", encoding="utf-8")
    assert resolve_local_artifact_path(str(local_path), str(source_path)) == local_path


def test_local_artifact_metadata_reports_size_and_mtime(tmp_path: Path) -> None:
    artifact_path = tmp_path / "artifact.txt"
    artifact_path.write_text("payload", encoding="utf-8")

    metadata = local_artifact_metadata(artifact_path)

    assert metadata["local_file_size"] == 7
    assert isinstance(metadata["local_file_mtime_ns"], int)
    assert metadata["local_file_mtime_ns"] > 0


def test_local_artifact_metadata_matches_exact_stat_values() -> None:
    current = {
        "local_file_size": 10,
        "local_file_mtime_ns": 20,
    }

    assert local_artifact_metadata_matches(dict(current), current) is True
    assert local_artifact_metadata_matches({"local_file_size": "10", "local_file_mtime_ns": "20"}, current) is True
    assert local_artifact_metadata_matches({"local_file_size": 11, "local_file_mtime_ns": 20}, current) is False
    assert local_artifact_metadata_matches("not-metadata", current) is False


def test_artifact_local_ingest_decision_inserts_new_artifact() -> None:
    decision = artifact_local_ingest_decision(
        normalized_path="C:/evidence/mobile.apk",
        artifact_type="mobile_bundle",
        current_metadata={"local_file_mtime_ns": 20, "local_file_size": 10},
    )

    assert decision.action == "insert"
    assert decision.artifact_id is None
    assert decision.source_url == "C:/evidence/mobile.apk"
    assert decision.local_path == "C:/evidence/mobile.apk"
    assert decision.artifact_type == "mobile_bundle"
    assert json.loads(decision.metadata_json) == {
        "local_file_mtime_ns": 20,
        "local_file_size": 10,
    }


def test_artifact_local_ingest_decision_skips_unchanged_parsed_artifact() -> None:
    metadata = {"local_file_mtime_ns": 20, "local_file_size": 10, "owner": "platform"}
    decision = artifact_local_ingest_decision(
        normalized_path="C:/evidence/mobile.apk",
        artifact_type="mobile_bundle",
        current_metadata={"local_file_mtime_ns": 20, "local_file_size": 10},
        existing_artifact_id=42,
        existing_status=" parsed ",
        existing_metadata=metadata,
        existing_local_path="C:/evidence/mobile.apk",
        existing_artifact_type="mobile_bundle",
    )

    assert decision.action == "skip"
    assert decision.artifact_id == 42
    assert decision.metadata == metadata
    assert json.loads(decision.metadata_json) == metadata


def test_artifact_local_ingest_decision_updates_changed_artifact_metadata() -> None:
    decision = artifact_local_ingest_decision(
        normalized_path="C:/evidence/mobile.apk",
        artifact_type="mobile_bundle",
        current_metadata={"local_file_mtime_ns": 21, "local_file_size": 10},
        existing_artifact_id=42,
        existing_status="parsed",
        existing_metadata={"local_file_mtime_ns": 20, "local_file_size": 10, "owner": "platform"},
        existing_local_path="C:/evidence/mobile.apk",
        existing_artifact_type="mobile_bundle",
    )

    assert decision.action == "update"
    assert decision.artifact_id == 42
    assert decision.metadata == {
        "local_file_mtime_ns": 21,
        "local_file_size": 10,
        "owner": "platform",
    }
    assert json.loads(decision.metadata_json) == decision.metadata


def test_ingest_local_artifact_queue_record_applies_insert_skip_and_update(tmp_path: Path) -> None:
    db_path = tmp_path / "local-ingest.db"
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        con.execute(
            """
            CREATE TABLE artifact_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                source_url TEXT NOT NULL,
                local_path TEXT,
                artifact_type TEXT NOT NULL,
                discovered_from TEXT NOT NULL,
                status TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                updated_at TIMESTAMP,
                UNIQUE (engagement_id, source_url)
            )
            """
        )
        record = (
            "C:/evidence/mobile.apk",
            "mobile_bundle",
            {"local_file_mtime_ns": 20, "local_file_size": 10},
        )

        assert ingest_local_artifact_queue_record(con, 1001, object()) is False
        assert ingest_local_artifact_queue_record(con, 1001, record) is True
        inserted_row = con.execute("SELECT * FROM artifact_queue WHERE engagement_id=1001").fetchone()
        assert inserted_row is not None
        assert str(inserted_row["source_url"]) == "C:/evidence/mobile.apk"
        assert str(inserted_row["local_path"]) == "C:/evidence/mobile.apk"
        assert str(inserted_row["artifact_type"]) == "mobile_bundle"
        assert str(inserted_row["discovered_from"]) == "local_filesystem"
        assert str(inserted_row["status"]) == "downloaded"
        assert json.loads(str(inserted_row["metadata_json"])) == {
            "local_file_mtime_ns": 20,
            "local_file_size": 10,
        }

        con.execute(
            """
            UPDATE artifact_queue
            SET status='parsed',
                metadata_json=?
            WHERE engagement_id=1001
            """,
            (
                json.dumps(
                    {
                        "local_file_mtime_ns": 20,
                        "local_file_size": 10,
                        "owner": "platform",
                    },
                    sort_keys=True,
                ),
            ),
        )
        assert ingest_local_artifact_queue_record(con, 1001, record) is False
        parsed_row = con.execute("SELECT status, metadata_json FROM artifact_queue WHERE engagement_id=1001").fetchone()
        assert parsed_row is not None
        assert tuple(parsed_row) == (
            "parsed",
            json.dumps(
                {
                    "local_file_mtime_ns": 20,
                    "local_file_size": 10,
                    "owner": "platform",
                },
                sort_keys=True,
            ),
        )

        changed_record = (
            "C:/evidence/mobile.apk",
            "config",
            {"local_file_mtime_ns": 21, "local_file_size": 11},
        )
        assert ingest_local_artifact_queue_record(con, 1001, changed_record) is True
        updated_row = con.execute("SELECT * FROM artifact_queue WHERE engagement_id=1001").fetchone()
        assert updated_row is not None
        assert str(updated_row["artifact_type"]) == "config"
        assert str(updated_row["status"]) == "downloaded"
        assert json.loads(str(updated_row["metadata_json"])) == {
            "local_file_mtime_ns": 21,
            "local_file_size": 11,
            "owner": "platform",
        }
    finally:
        con.close()


def test_ingest_local_artifacts_for_engagement_collects_records_and_commits(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    config_path = artifact_root / "app-config.json"
    ignored_path = artifact_root / "notes.txt"
    config_path.write_text("{}", encoding="utf-8")
    ignored_path.write_text("ignore", encoding="utf-8")
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    commits = 0
    observed_batch: list[Path] = []
    try:
        con.execute(
            """
            CREATE TABLE artifact_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                source_url TEXT NOT NULL,
                local_path TEXT,
                artifact_type TEXT NOT NULL,
                discovered_from TEXT NOT NULL,
                status TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                updated_at TIMESTAMP,
                UNIQUE (engagement_id, source_url)
            )
            """
        )

        def run_ordered_batch(
            items: list[Path],
            callback: Callable[[Path], tuple[str, str, dict[str, Any]] | None],
            *,
            default_factory: Callable[[], None],
        ) -> list[tuple[str, str, dict[str, Any]] | None]:
            observed_batch.extend(items)
            return [callback(item) for item in items] + [default_factory()]

        def record_local_artifact(path: Path) -> tuple[str, str, dict[str, Any]] | None:
            if path.suffix != ".json":
                return None
            return (
                path.resolve().as_posix(),
                "config",
                {"local_file_size": path.stat().st_size},
            )

        def commit_after_ingest() -> None:
            nonlocal commits
            commits += 1
            con.commit()

        queued = ingest_local_artifacts_for_engagement(
            con,
            1001,
            search_roots=[tmp_path / "missing", artifact_root],
            run_ordered_batch=run_ordered_batch,
            record_local_artifact=record_local_artifact,
            commit_after_ingest=commit_after_ingest,
        )

        assert queued == 1
        assert commits == 1
        assert {path.resolve() for path in observed_batch} == {
            config_path.resolve(),
            ignored_path.resolve(),
        }
        row = con.execute("SELECT * FROM artifact_queue WHERE engagement_id=1001").fetchone()
        assert row is not None
        assert str(row["source_url"]) == config_path.resolve().as_posix()
        assert str(row["artifact_type"]) == "config"
        assert str(row["status"]) == "downloaded"
        assert json.loads(str(row["metadata_json"])) == {"local_file_size": 2}
    finally:
        con.close()


def test_artifact_progress_snapshot_bounds_counts_and_eta() -> None:
    assert artifact_progress_snapshot(
        total=5,
        workers=2,
        completed=2,
        failed=5,
        started_at=90.0,
        now=100.0,
    ) == {
        "total": 5,
        "workers": 2,
        "running": 2,
        "pending": 1,
        "queue_depth": 1,
        "completed": 2,
        "failed": 2,
        "eta_seconds": 15.0,
    }

    assert artifact_progress_snapshot(
        total=0,
        workers=4,
        completed=9,
        failed=3,
        started_at=100.0,
        now=100.0,
    ) == {
        "total": 0,
        "workers": 0,
        "running": 0,
        "pending": 0,
        "queue_depth": 0,
        "completed": 0,
        "failed": 0,
        "eta_seconds": None,
    }


def test_artifact_progress_snapshot_marks_complete_eta_zero() -> None:
    assert artifact_progress_snapshot(
        total=3,
        workers=2,
        completed=5,
        failed=1,
        started_at=90.0,
        now=100.0,
    ) == {
        "total": 3,
        "workers": 2,
        "running": 0,
        "pending": 0,
        "queue_depth": 0,
        "completed": 3,
        "failed": 1,
        "eta_seconds": 0.0,
    }


def test_artifact_progress_stage_label_normalizes_blank_values() -> None:
    assert artifact_progress_stage_label("1.K3 artifact processing", "parse") == "1.K3 artifact processing / parse"
    assert artifact_progress_stage_label("1.K3 artifact processing", " ") == "1.K3 artifact processing"
    assert artifact_progress_stage_label("", "parse") == ""


def test_parse_artifact_work_item_routes_by_artifact_type(tmp_path: Path) -> None:
    mobile_path = tmp_path / "client.apk"
    config_path = tmp_path / "settings.json"
    raw_path = tmp_path / "firmware.bin"
    mobile_path.write_bytes(b"apk")
    config_path.write_text("{}", encoding="utf-8")
    raw_path.write_bytes(b"raw")
    mobile_project = SimpleNamespace(project_id="mobile")
    text_config = SimpleNamespace(ref="text")
    calls: list[tuple[str, str]] = []

    def _scan_mobile(
        path: Path,
        artifact_type: str,
    ) -> tuple[list[tuple[str, str, str]], list[Any], list[Any], dict[str, Any]]:
        calls.append(("mobile", artifact_type))
        return (
            [(path.as_posix(), "mobile.txt", "payload")],
            [mobile_project],
            [],
            {"parser": artifact_type, "payload_count": 1},
        )

    def _scan_text(
        path: Path,
        artifact_type: str,
    ) -> tuple[list[tuple[str, str, str]], list[Any], list[Any], dict[str, Any]]:
        calls.append(("text", artifact_type))
        return (
            [(path.as_posix(), "settings.json", "payload")],
            [],
            [text_config],
            {"parser": artifact_type, "payload_count": 1},
        )

    mobile_result = parse_artifact_work_item(
        ArtifactWorkItem(
            artifact_id=1,
            source_url="file:///client.apk",
            artifact_type="apk",
            path=mobile_path,
        ),
        scan_mobile_bundle_artifact=_scan_mobile,
        scan_text_artifact=_scan_text,
        artifact_format_label=lambda path: path.suffix.lstrip("."),
    )
    text_result = parse_artifact_work_item(
        ArtifactWorkItem(
            artifact_id=2,
            source_url="file:///settings.json",
            artifact_type="config",
            path=config_path,
        ),
        scan_mobile_bundle_artifact=_scan_mobile,
        scan_text_artifact=_scan_text,
        artifact_format_label=lambda path: path.suffix.lstrip("."),
    )
    unsupported_result = parse_artifact_work_item(
        ArtifactWorkItem(
            artifact_id=3,
            source_url="file:///firmware.bin",
            artifact_type="firmware",
            path=raw_path,
        ),
        scan_mobile_bundle_artifact=_scan_mobile,
        scan_text_artifact=_scan_text,
        artifact_format_label=lambda path: path.suffix.lstrip("."),
    )

    assert calls == [("mobile", "apk"), ("text", "config")]
    assert mobile_result.payloads == [(mobile_path.as_posix(), "mobile.txt", "payload")]
    assert mobile_result.firebase_projects == [mobile_project]
    assert mobile_result.parse_metadata == {"parser": "apk", "payload_count": 1}
    assert text_result.payloads == [(config_path.as_posix(), "settings.json", "payload")]
    assert text_result.supabase_configs == [text_config]
    assert text_result.parse_metadata == {"parser": "config", "payload_count": 1}
    assert unsupported_result == ParsedArtifact(
        artifact_id=3,
        source_url="file:///firmware.bin",
        artifact_type="firmware",
        path=raw_path,
        parse_metadata={
            "format": "bin",
            "parser": "firmware",
            "payload_count": 0,
            "metadata_payload_count": 0,
            "relationship_payload_count": 0,
        },
    )


def test_parse_local_artifact_batch_preserves_order_wraps_parallel_errors_and_emits_progress(
    tmp_path: Path,
) -> None:
    work_items = [
        ArtifactWorkItem(
            artifact_id=1,
            source_url="file:///one.env",
            artifact_type="config",
            path=tmp_path / "one.env",
        ),
        ArtifactWorkItem(
            artifact_id=2,
            source_url="file:///two.env",
            artifact_type="config",
            path=tmp_path / "two.env",
        ),
        ArtifactWorkItem(
            artifact_id=3,
            source_url="file:///three.env",
            artifact_type="config",
            path=tmp_path / "three.env",
        ),
    ]
    parsed_calls: list[int] = []
    progress_events: list[tuple[str, dict[str, object]]] = []

    def _parse_one(work_item: ArtifactWorkItem) -> ParsedArtifact:
        parsed_calls.append(work_item.artifact_id)
        if work_item.artifact_id == 2:
            raise RuntimeError("parse boom")
        return ParsedArtifact(
            artifact_id=work_item.artifact_id,
            source_url=work_item.source_url,
            artifact_type=work_item.artifact_type,
            path=work_item.path,
            payloads=[(work_item.source_url, "body", "payload")],
        )

    results = parse_local_artifact_batch(
        work_items,
        max_workers=3,
        parse_one=_parse_one,
        progress_label="artifact processing",
        progress_callback=lambda label, metrics: progress_events.append((label, dict(metrics))),
    )

    assert [result.artifact_id for result in results] == [1, 2, 3]
    assert results[0].payloads == [("file:///one.env", "body", "payload")]
    assert results[1] == ParsedArtifact(
        artifact_id=2,
        source_url="file:///two.env",
        artifact_type="config",
        path=tmp_path / "two.env",
        error="parse boom",
    )
    assert results[2].payloads == [("file:///three.env", "body", "payload")]
    assert sorted(parsed_calls) == [1, 2, 3]
    assert progress_events[0][0] == "artifact processing / parse"
    assert int(progress_events[0][1]["completed"]) == 0
    assert int(progress_events[0][1]["total"]) == 3
    assert int(progress_events[-1][1]["completed"]) == 3
    assert int(progress_events[-1][1]["failed"]) == 1
    assert int(progress_events[-1][1]["queue_depth"]) == 0
    assert float(progress_events[-1][1]["eta_seconds"] or 0.0) == 0.0


def test_parse_local_artifact_batch_preserves_single_worker_exception_behavior(
    tmp_path: Path,
) -> None:
    work_item = ArtifactWorkItem(
        artifact_id=1,
        source_url="file:///one.env",
        artifact_type="config",
        path=tmp_path / "one.env",
    )

    def _parse_one(_work_item: ArtifactWorkItem) -> ParsedArtifact:
        raise RuntimeError("serial parse boom")

    with pytest.raises(RuntimeError, match="serial parse boom"):
        parse_local_artifact_batch([work_item], max_workers=1, parse_one=_parse_one)


def test_artifact_parsed_result_actions_shape_status_and_summary_deltas(tmp_path: Path) -> None:
    parsed_ok = ParsedArtifact(
        artifact_id=10,
        source_url="artifact://queue/10",
        artifact_type="config",
        path=tmp_path / "ok.env",
        parse_metadata={"parser": "config", "payload_count": 2},
    )
    parsed_failed = ParsedArtifact(
        artifact_id=11,
        source_url="artifact://queue/11",
        artifact_type="config",
        path=tmp_path / "fail.env",
        error="parse failed",
    )
    persisted: list[int] = []

    def _persist(parsed: ParsedArtifact) -> tuple[int, int, int, dict[str, Any]]:
        persisted.append(parsed.artifact_id)
        return 2, 3, 5, dict(parsed.parse_metadata)

    actions = artifact_parsed_result_actions(
        [parsed_failed, parsed_ok],
        persist_parsed_artifact=_persist,
    )

    assert actions == [
        ArtifactParsedResultAction(
            artifact_id=11,
            status="failed",
            notes="parse failed",
            failed_delta=1,
        ),
        ArtifactParsedResultAction(
            artifact_id=10,
            status="parsed",
            notes="firebase=2 supabase=3 seeds=5",
            metadata={"parser": "config", "payload_count": 2},
            processed_delta=1,
            firebase_projects_delta=2,
            supabase_configs_delta=3,
            discovered_seeds_delta=5,
        ),
    ]
    assert persisted == [10]


def test_apply_artifact_parsed_result_actions_updates_status_and_summary() -> None:
    calls: list[tuple[int, str, str, dict[str, Any] | None]] = []

    def _update_artifact_status(
        artifact_id: int,
        status: str,
        notes: str,
        metadata: dict[str, Any] | None,
    ) -> None:
        calls.append((artifact_id, status, notes, metadata))

    summary = apply_artifact_parsed_result_actions(
        [
            ArtifactParsedResultAction(
                artifact_id=11,
                status="failed",
                notes="parse failed",
                failed_delta=1,
            ),
            ArtifactParsedResultAction(
                artifact_id=10,
                status="parsed",
                notes="firebase=2 supabase=3 seeds=5",
                metadata={"parser": "config", "payload_count": 2},
                processed_delta=1,
                firebase_projects_delta=2,
                supabase_configs_delta=3,
                discovered_seeds_delta=5,
            ),
        ],
        update_artifact_status=_update_artifact_status,
    )

    assert summary == ArtifactProcessingSummary(
        processed=1,
        failed=1,
        firebase_projects=2,
        supabase_configs=3,
        discovered_seeds=5,
    )
    assert calls == [
        (11, "failed", "parse failed", None),
        (
            10,
            "parsed",
            "firebase=2 supabase=3 seeds=5",
            {"parser": "config", "payload_count": 2},
        ),
    ]


def test_process_artifact_queue_parse_stage_parses_persists_and_updates(
    tmp_path: Path,
) -> None:
    ok_path = tmp_path / "ok.env"
    ok_path.write_text("CONTACT=owner@acme.example\n", encoding="utf-8")
    fail_path = tmp_path / "fail.env"
    fail_path.write_text("broken", encoding="utf-8")
    work_items = [
        ArtifactWorkItem(
            artifact_id=10,
            source_url="artifact://queue/10",
            artifact_type="config",
            path=ok_path,
        ),
        ArtifactWorkItem(
            artifact_id=11,
            source_url="artifact://queue/11",
            artifact_type="config",
            path=fail_path,
        ),
    ]
    parse_calls: list[int] = []
    persist_calls: list[int] = []
    status_calls: list[tuple[int, str, str, dict[str, Any] | None]] = []

    def _parse_local_artifacts(
        items: list[ArtifactWorkItem],
    ) -> list[ParsedArtifact]:
        parse_calls.extend(item.artifact_id for item in items)
        return [
            ParsedArtifact(
                artifact_id=10,
                source_url="artifact://queue/10",
                artifact_type="config",
                path=ok_path,
                parse_metadata={"parser": "config"},
            ),
            ParsedArtifact(
                artifact_id=11,
                source_url="artifact://queue/11",
                artifact_type="config",
                path=fail_path,
                error="parse failed",
            ),
        ]

    def _persist_parsed_artifact(
        parsed: ParsedArtifact,
    ) -> tuple[int, int, int, dict[str, Any]]:
        persist_calls.append(parsed.artifact_id)
        return 2, 3, 5, dict(parsed.parse_metadata)

    def _update_artifact_status(
        artifact_id: int,
        status: str,
        notes: str,
        metadata: dict[str, Any] | None,
    ) -> None:
        status_calls.append((artifact_id, status, notes, metadata))

    result = process_artifact_queue_parse_stage(
        work_items,
        parse_local_artifacts=_parse_local_artifacts,
        persist_parsed_artifact=_persist_parsed_artifact,
        update_artifact_status=_update_artifact_status,
    )

    assert isinstance(result, ArtifactQueueParseStageResult)
    assert result.summary == ArtifactProcessingSummary(
        processed=1,
        failed=1,
        firebase_projects=2,
        supabase_configs=3,
        discovered_seeds=5,
    )
    assert parse_calls == [10, 11]
    assert persist_calls == [10]
    assert status_calls == [
        (
            10,
            "parsed",
            "firebase=2 supabase=3 seeds=5",
            {"parser": "config"},
        ),
        (11, "failed", "parse failed", None),
    ]


def test_artifact_parsed_result_actions_preserve_persistence_exception(tmp_path: Path) -> None:
    parsed = ParsedArtifact(
        artifact_id=10,
        source_url="artifact://queue/10",
        artifact_type="config",
        path=tmp_path / "ok.env",
    )

    def _persist(_parsed: ParsedArtifact) -> tuple[int, int, int, dict[str, Any]]:
        raise RuntimeError("persist failed")

    with pytest.raises(RuntimeError, match="persist failed"):
        artifact_parsed_result_actions([parsed], persist_parsed_artifact=_persist)


def test_artifact_local_path_metadata_update_merges_download_context(tmp_path: Path) -> None:
    download_path = tmp_path / "downloaded.json"
    update = artifact_local_path_metadata_update(
        {"source_rule": "crawl_result", "downloaded_from_remote": False},
        download_path,
        metadata_extra={"content_type": "application/json"},
    )

    assert isinstance(update, ArtifactQueueMetadataUpdate)
    assert update.metadata == {
        "source_rule": "crawl_result",
        "downloaded_from_remote": True,
        "download_path": download_path.as_posix(),
        "content_type": "application/json",
    }
    assert json.loads(update.metadata_json) == update.metadata

    empty_update = artifact_local_path_metadata_update("not-metadata", download_path)
    assert empty_update.metadata == {
        "downloaded_from_remote": True,
        "download_path": download_path.as_posix(),
    }


def test_artifact_status_metadata_update_merges_metadata_and_bounds_notes() -> None:
    update = artifact_status_metadata_update(
        {"existing": True, "skip_reason": "old"},
        notes="x" * 1100,
        metadata={"skip_reason": "new", "skip_status": "skipped"},
    )

    assert update.metadata == {
        "existing": True,
        "skip_reason": "new",
        "skip_status": "skipped",
    }
    assert json.loads(update.metadata_json) == update.metadata
    assert update.notes == "x" * 1024

    empty_update = artifact_status_metadata_update("not-metadata", notes="ok")
    assert empty_update.metadata == {}
    assert empty_update.notes == "ok"


def test_artifact_queue_db_update_helpers_merge_metadata(tmp_path: Path) -> None:
    db_path = tmp_path / "artifacts.db"
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        con.execute(
            """
            CREATE TABLE artifact_queue (
                id INTEGER PRIMARY KEY,
                local_path TEXT DEFAULT '',
                artifact_type TEXT DEFAULT '',
                status TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                metadata_json TEXT DEFAULT '{}',
                updated_at TEXT
            )
            """
        )
        con.execute(
            """
            INSERT INTO artifact_queue
                (id, local_path, artifact_type, status, notes, metadata_json)
            VALUES (7, '', 'config', 'queued', '', ?)
            """,
            (json.dumps({"source_rule": "crawl_result"}),),
        )

        download_path = tmp_path / "remote.apk"
        set_artifact_local_path(
            con,
            7,
            download_path,
            artifact_type="apk",
            metadata_extra={"content_type": "application/vnd.android.package-archive"},
        )
        row = con.execute("SELECT * FROM artifact_queue WHERE id=7").fetchone()
        assert row is not None
        assert str(row["local_path"]) == download_path.as_posix()
        assert str(row["artifact_type"]) == "apk"
        assert str(row["status"]) == "downloaded"
        assert json.loads(str(row["metadata_json"])) == {
            "content_type": "application/vnd.android.package-archive",
            "download_path": download_path.as_posix(),
            "downloaded_from_remote": True,
            "source_rule": "crawl_result",
        }

        con.execute("UPDATE artifact_queue SET metadata_json='not-json' WHERE id=7")
        update_artifact_status(
            con,
            7,
            "skipped",
            "x" * 1100,
            metadata={"skip_reason": "scope_manifest_denied"},
        )
        row = con.execute("SELECT * FROM artifact_queue WHERE id=7").fetchone()
        assert row is not None
        assert str(row["status"]) == "skipped"
        assert str(row["notes"]) == "x" * 1024
        assert json.loads(str(row["metadata_json"])) == {
            "skip_reason": "scope_manifest_denied",
        }
    finally:
        con.close()


def test_audit_artifact_lineage_bounds_fields_and_ignores_sqlite_errors(tmp_path: Path) -> None:
    db_path = tmp_path / "artifact-audit.db"
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        audit_artifact_lineage(
            con,
            1001,
            action="ignored_missing_table",
            target="https://downloads.acme.example/app.apk",
            result="ok",
        )
        con.execute(
            """
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                phase TEXT,
                module TEXT,
                action TEXT NOT NULL,
                target TEXT,
                result TEXT,
                operator TEXT,
                logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        audit_artifact_lineage(
            con,
            1001,
            action="artifact_text_url_queued:" + ("a" * 120),
            target="https://downloads.acme.example/" + ("b" * 600),
            result="rule=artifact_text_discovered_artifact_queue " + ("c" * 1100),
        )

        row = con.execute("SELECT * FROM audit_log WHERE engagement_id=1001").fetchone()
        assert row is not None
        assert str(row["phase"]) == "artifact_analysis"
        assert str(row["module"]) == "artifact_queue"
        assert str(row["operator"]) == "forge"
        assert len(str(row["action"])) == 96
        assert str(row["action"]).startswith("artifact_text_url_queued:")
        assert len(str(row["target"])) == 512
        assert str(row["target"]).startswith("https://downloads.acme.example/")
        assert len(str(row["result"])) == 1024
        assert str(row["result"]).startswith("rule=artifact_text_discovered_artifact_queue")
    finally:
        con.close()


def test_artifact_queue_processing_rows_and_attempt_marking_respect_retry_policy(tmp_path: Path) -> None:
    db_path = tmp_path / "artifact-processing.db"
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        con.execute(
            """
            CREATE TABLE artifact_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                source_url TEXT NOT NULL,
                local_path TEXT,
                artifact_type TEXT NOT NULL,
                status TEXT NOT NULL,
                attempt_count INTEGER DEFAULT 0,
                max_attempts INTEGER DEFAULT 3,
                queued_at TEXT NOT NULL,
                updated_at TEXT
            )
            """
        )
        rows = [
            (1001, "https://downloads.acme.example/old.apk", "", "apk", "queued", 0, 3, "2026-08-10 00:00:01"),
            (1001, "C:/evidence/local.json", "C:/evidence/local.json", "config", "downloaded", 1, 3, "2026-08-10 00:00:02"),
            (1001, "https://downloads.acme.example/retry.zip", "", "archive", "failed", 1, 3, "2026-08-10 00:00:03"),
            (1001, "https://downloads.acme.example/exhausted.zip", "", "archive", "failed", 3, 3, "2026-08-10 00:00:04"),
            (1001, "https://downloads.acme.example/disabled.zip", "", "archive", "failed", 0, 0, "2026-08-10 00:00:05"),
            (1001, "https://downloads.acme.example/parsed.apk", "", "apk", "parsed", 0, 3, "2026-08-10 00:00:06"),
            (1002, "https://downloads.other.example/other.apk", "", "apk", "queued", 0, 3, "2026-08-10 00:00:00"),
        ]
        con.executemany(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, local_path, artifact_type, status, attempt_count, max_attempts, queued_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )

        processing_rows = artifact_queue_processing_rows(con, 1001)
        assert [
            (int(row["id"]), str(row["source_url"]), str(row["status"]))
            for row in processing_rows
        ] == [
            (1, "https://downloads.acme.example/old.apk", "queued"),
            (2, "C:/evidence/local.json", "downloaded"),
            (3, "https://downloads.acme.example/retry.zip", "failed"),
        ]

        mark_artifact_attempts(con, [int(row["id"]) for row in processing_rows])
        mark_artifact_attempts(con, [])
        attempts = {
            int(row["id"]): int(row["attempt_count"])
            for row in con.execute(
                """
                SELECT id, attempt_count
                FROM artifact_queue
                ORDER BY id ASC
                """
            ).fetchall()
        }
        assert attempts == {
            1: 1,
            2: 2,
            3: 2,
            4: 3,
            5: 0,
            6: 0,
            7: 0,
        }
    finally:
        con.close()


def test_prepare_artifact_queue_processing_rows_marks_attempts_and_commits(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "artifact-processing-prepare.db"
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    commits: list[str] = []
    try:
        con.execute(
            """
            CREATE TABLE artifact_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                source_url TEXT NOT NULL,
                local_path TEXT,
                artifact_type TEXT NOT NULL,
                status TEXT NOT NULL,
                attempt_count INTEGER DEFAULT 0,
                max_attempts INTEGER DEFAULT 3,
                queued_at TEXT NOT NULL,
                updated_at TEXT
            )
            """
        )
        con.executemany(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, local_path, artifact_type, status, attempt_count, max_attempts, queued_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (1001, "https://downloads.acme.example/old.apk", "", "apk", "queued", 0, 3, "2026-08-10 00:00:01"),
                (1001, "C:/evidence/local.json", "C:/evidence/local.json", "config", "downloaded", 1, 3, "2026-08-10 00:00:02"),
                (1001, "https://downloads.acme.example/retry.zip", "", "archive", "failed", 1, 3, "2026-08-10 00:00:03"),
                (1001, "https://downloads.acme.example/exhausted.zip", "", "archive", "failed", 3, 3, "2026-08-10 00:00:04"),
            ],
        )

        result = prepare_artifact_queue_processing_rows(
            con,
            1001,
            commit_after_attempt_mark=lambda: commits.append("committed"),
        )

        assert result == ArtifactQueueRowsPreparationResult(
            rows=result.rows,
            artifact_ids=[1, 2, 3],
        )
        assert [
            (int(row["id"]), str(row["source_url"]), str(row["status"]))
            for row in result.rows
        ] == [
            (1, "https://downloads.acme.example/old.apk", "queued"),
            (2, "C:/evidence/local.json", "downloaded"),
            (3, "https://downloads.acme.example/retry.zip", "failed"),
        ]
        assert commits == ["committed"]
        attempts = {
            int(row["id"]): int(row["attempt_count"])
            for row in con.execute(
                """
                SELECT id, attempt_count
                FROM artifact_queue
                ORDER BY id ASC
                """
            ).fetchall()
        }
        assert attempts == {1: 1, 2: 2, 3: 2, 4: 3}
    finally:
        con.close()


def test_ensure_local_artifact_source_seed_upserts_local_only_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "seeds.db"
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        con.execute(
            """
            CREATE TABLE engagement_seeds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                seed_value TEXT NOT NULL,
                seed_type TEXT NOT NULL,
                source TEXT,
                status TEXT,
                depth INTEGER,
                confidence REAL,
                metadata_json TEXT DEFAULT '{}',
                updated_at TEXT,
                UNIQUE(engagement_id, seed_type, seed_value)
            )
            """
        )
        parsed = ParsedArtifact(
            artifact_id=22,
            source_url=(tmp_path / "local.env").as_posix(),
            artifact_type="config",
            path=tmp_path / "local.env",
        )

        seed_id = ensure_local_artifact_source_seed(
            con,
            1001,
            parsed,
            artifact_context={"payload_count": 3, "ignored": ["not", "scalar"]},
        )
        same_seed_id = ensure_local_artifact_source_seed(
            con,
            1001,
            parsed,
            artifact_context={"content_type": "text/plain"},
        )

        assert seed_id is not None
        assert same_seed_id == seed_id
        row = con.execute("SELECT * FROM engagement_seeds WHERE id=?", (seed_id,)).fetchone()
        assert row is not None
        assert str(row["seed_value"]) == "artifact://queue/22"
        assert str(row["seed_type"]) == "other"
        assert str(row["source"]) == "artifact"
        assert str(row["status"]) == "completed"
        assert int(row["depth"]) == 0
        assert float(row["confidence"]) == 0.9
        assert json.loads(str(row["metadata_json"])) == {
            "artifact_provenance": True,
            "artifact_queue_id": 22,
            "artifact_source_seed": True,
            "artifact_type": "config",
            "content_type": "text/plain",
            "source_url": "artifact://queue/22",
        }

        remote_seed_id = ensure_local_artifact_source_seed(
            con,
            1001,
            ParsedArtifact(
                artifact_id=23,
                source_url="https://downloads.acme.example/app.apk",
                artifact_type="apk",
                path=tmp_path / "app.apk",
            ),
            artifact_context={},
        )
        assert remote_seed_id is None
        assert con.execute("SELECT COUNT(*) FROM engagement_seeds").fetchone()[0] == 1
    finally:
        con.close()


def test_insert_artifact_seed_preserves_lowest_depth_and_highest_confidence(tmp_path: Path) -> None:
    db_path = tmp_path / "seed-insert.db"
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        con.execute(
            """
            CREATE TABLE engagement_seeds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                seed_value TEXT NOT NULL,
                seed_type TEXT NOT NULL,
                source TEXT,
                status TEXT,
                depth INTEGER,
                confidence REAL,
                metadata_json TEXT DEFAULT '{}',
                updated_at TEXT,
                UNIQUE(engagement_id, seed_type, seed_value)
            )
            """
        )

        assert insert_artifact_seed(
            con,
            1001,
            "api.acme.example",
            "subdomain",
            source="artifact",
            confidence=0.6,
            depth=4,
        )
        assert insert_artifact_seed(
            con,
            1001,
            "api.acme.example",
            "subdomain",
            source="artifact_text",
            confidence=0.8,
            depth=2,
        )

        row = con.execute("SELECT * FROM engagement_seeds WHERE seed_value='api.acme.example'").fetchone()
        assert row is not None
        assert str(row["source"]) == "artifact_text"
        assert str(row["status"]) == "pending"
        assert int(row["depth"]) == 2
        assert float(row["confidence"]) == 0.8
        assert json.loads(str(row["metadata_json"])) == {}
    finally:
        con.close()


def test_artifact_child_depth_and_source_seed_lookup_use_engagement_scope(tmp_path: Path) -> None:
    db_path = tmp_path / "source-lookup.db"
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        con.execute(
            """
            CREATE TABLE engagement_seeds (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER NOT NULL,
                seed_value TEXT NOT NULL,
                seed_type TEXT NOT NULL,
                source TEXT,
                status TEXT,
                depth INTEGER,
                confidence REAL,
                metadata_json TEXT DEFAULT '{}',
                updated_at TEXT,
                UNIQUE(engagement_id, seed_type, seed_value)
            )
            """
        )
        con.executemany(
            """
            INSERT INTO engagement_seeds
                (id, engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
            VALUES (?, ?, ?, ?, 'operator', 'completed', ?, 1.0, '{}')
            """,
            [
                (1, 1001, "https://downloads.acme.example/app.apk", "url", 3),
                (2, 1001, "https://downloads.acme.example/mobile.apk", "apk_url", 1),
                (3, 2002, "https://downloads.acme.example/app.apk", "apk_url", 0),
            ],
        )

        assert artifact_child_seed_depth(con, 1001, None) == 1
        assert artifact_child_seed_depth(con, 1001, 1) == 4
        assert artifact_child_seed_depth(con, 1001, 3) == 1
        assert (
            lookup_artifact_seed_id(
                con,
                1001,
                "https://downloads.acme.example/app.apk",
                "url",
            )
            == 1
        )
        assert (
            lookup_artifact_seed_id(
                con,
                1001,
                "https://downloads.acme.example/app.apk",
                "domain",
            )
            is None
        )
        assert (
            lookup_artifact_seed_id(
                con,
                2002,
                "https://downloads.acme.example/app.apk",
                "url",
            )
            is None
        )
        assert artifact_source_seed_id(
            con,
            1001,
            "https://downloads.acme.example/app.apk",
            classify_seed_value=lambda _value: "url",
            is_mobile_bundle_url=lambda _value: True,
        ) == 1
        assert artifact_source_seed_id(
            con,
            1001,
            "https://downloads.acme.example/mobile.apk",
            classify_seed_value=lambda _value: "url",
            is_mobile_bundle_url=lambda _value: True,
        ) == 2
        assert artifact_source_seed_id(
            con,
            1001,
            "owner@acme.example",
            classify_seed_value=lambda _value: "email",
            is_mobile_bundle_url=lambda _value: False,
        ) is None
    finally:
        con.close()


def test_insert_artifact_email_normalizes_email_and_creates_seed(tmp_path: Path) -> None:
    db_path = tmp_path / "email.db"
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        con.execute(
            """
            CREATE TABLE emails (
                engagement_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                domain TEXT NOT NULL,
                source TEXT,
                UNIQUE(engagement_id, email)
            )
            """
        )
        con.execute(
            """
            CREATE TABLE engagement_seeds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                seed_value TEXT NOT NULL,
                seed_type TEXT NOT NULL,
                source TEXT,
                status TEXT,
                depth INTEGER,
                confidence REAL,
                metadata_json TEXT DEFAULT '{}',
                updated_at TEXT,
                UNIQUE(engagement_id, seed_type, seed_value)
            )
            """
        )

        assert not insert_artifact_email(con, 1001, "not-an-email", source="artifact")
        assert insert_artifact_email(con, 1001, " Owner@Acme.Example ", source="artifact_text", depth=5)
        assert insert_artifact_email(con, 1001, "owner@acme.example", source="artifact_text", depth=2)

        email_row = con.execute("SELECT * FROM emails WHERE email='owner@acme.example'").fetchone()
        assert email_row is not None
        assert str(email_row["domain"]) == "acme.example"
        assert str(email_row["source"]) == "artifact_text"
        seed_row = con.execute(
            "SELECT * FROM engagement_seeds WHERE seed_value='owner@acme.example' AND seed_type='email'"
        ).fetchone()
        assert seed_row is not None
        assert str(seed_row["source"]) == "artifact"
        assert str(seed_row["status"]) == "pending"
        assert int(seed_row["depth"]) == 2
        assert float(seed_row["confidence"]) == 0.74
    finally:
        con.close()


def test_store_artifact_key_finding_preserves_insert_or_ignore_and_repo_fallback(tmp_path: Path) -> None:
    db_path = tmp_path / "keys.db"
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        con.execute(
            """
            CREATE TABLE key_scanner_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                service TEXT NOT NULL,
                pattern_name TEXT NOT NULL,
                source_backend TEXT NOT NULL DEFAULT 'github',
                source_url TEXT NOT NULL,
                repo_name TEXT,
                key_redacted TEXT NOT NULL,
                key_enc TEXT,
                validation_state TEXT NOT NULL DEFAULT 'UNCONFIRMED',
                validation_detail TEXT,
                found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                validated_at TIMESTAMP,
                UNIQUE (engagement_id, source_url, pattern_name)
            )
            """
        )

        store_artifact_key_finding(
            con,
            1001,
            service="firebase",
            domain="firebase-one",
            source_url="https://downloads.acme.example/mobile/google-services.json",
            pattern_name="firebase_api_key",
            key_redacted="AIza****",
            key_enc="enc-one",
        )
        store_artifact_key_finding(
            con,
            1001,
            service="firebase",
            domain="firebase-one",
            source_url="https://downloads.acme.example/mobile/google-services.json",
            pattern_name="firebase_api_key",
            key_redacted="ignored",
            key_enc="ignored",
            repo_name="ignored-repo",
            validation_detail="ignored_detail",
        )
        store_artifact_key_finding(
            con,
            1001,
            service="supabase",
            domain="supabase-one",
            source_url="artifact://queue/22",
            pattern_name="supabase_anon_key",
            key_redacted="eyJ****",
            key_enc=None,
            source_backend="artifact_text",
            repo_name="local.env",
            validation_detail="artifact_text_discovery",
        )

        rows = con.execute(
            """
            SELECT domain, service, pattern_name, source_backend, source_url, repo_name,
                   key_redacted, key_enc, validation_state, validation_detail
            FROM key_scanner_findings
            ORDER BY id ASC
            """
        ).fetchall()
        assert [tuple(row) for row in rows] == [
            (
                "firebase-one",
                "firebase",
                "firebase_api_key",
                "mobile_config_parse",
                "https://downloads.acme.example/mobile/google-services.json",
                "google-services.json",
                "AIza****",
                "enc-one",
                "UNCONFIRMED",
                "artifact_queue_ingest",
            ),
            (
                "supabase-one",
                "supabase",
                "supabase_anon_key",
                "artifact_text",
                "artifact://queue/22",
                "local.env",
                "eyJ****",
                None,
                "UNCONFIRMED",
                "artifact_text_discovery",
            ),
        ]
    finally:
        con.close()


def test_store_artifact_cloud_asset_reference_merges_metadata_and_audits_new_assets(tmp_path: Path) -> None:
    db_path = tmp_path / "cloud-assets.db"
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    audit_calls: list[dict[str, str]] = []
    try:
        con.execute(
            """
            CREATE TABLE cloud_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                asset_type TEXT NOT NULL,
                identifier TEXT NOT NULL,
                provider_identifier TEXT,
                source TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                discovered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (engagement_id, asset_type, identifier)
            )
            """
        )

        def _audit_lineage(*, action: str, target: str, result: str) -> None:
            audit_calls.append({"action": action, "target": target, "result": result})

        store_artifact_cloud_asset_reference(
            con,
            1001,
            asset_type=" Firebase ",
            identifier="Acme-Prod",
            source="artifact_url_extract",
            metadata={
                "archive_sources": ["apk", "ipa"],
                "provider_sources": ["remote"],
                "source_url": "https://downloads.acme.example/app.apk",
            },
            audit_artifact_lineage=_audit_lineage,
        )
        store_artifact_cloud_asset_reference(
            con,
            1001,
            asset_type="firebase",
            identifier="acme-prod",
            source="ignored_source",
            metadata={
                "archive_sources": ["apk", "source-map"],
                "provider_sources": ["remote", "local"],
                "source_backend": "artifact_text",
                "source_url": "ignored",
            },
            audit_artifact_lineage=_audit_lineage,
        )

        row = con.execute("SELECT * FROM cloud_assets WHERE asset_type='firebase'").fetchone()
        assert row is not None
        assert str(row["identifier"]) == "acme-prod"
        assert str(row["provider_identifier"]) == "Acme-Prod"
        assert str(row["source"]) == "artifact_url_extract"
        assert json.loads(str(row["metadata_json"])) == {
            "archive_sources": ["apk", "ipa", "source-map"],
            "provider_sources": ["remote", "local"],
            "source_backend": "artifact_text",
            "source_url": "https://downloads.acme.example/app.apk",
        }
        assert audit_calls == [
            {
                "action": "artifact_cloud_asset_inventoried",
                "target": "acme-prod",
                "result": (
                    "asset_type=firebase source=artifact_url_extract "
                    "validation_status=UNVALIDATED reportable=no"
                ),
            }
        ]

        con.execute(
            """
            INSERT INTO cloud_assets
                (engagement_id, asset_type, identifier, provider_identifier, source, metadata_json)
            VALUES (1001, 'aws_s3', 'teambucket', 'teambucket', 'manual', 'not-json')
            """
        )
        store_artifact_cloud_asset_reference(
            con,
            1001,
            asset_type="aws_s3",
            identifier="TeamBucket",
            source="artifact_url_extract",
            metadata={"source_url": "s3://TeamBucket/reports"},
            audit_artifact_lineage=_audit_lineage,
        )
        store_artifact_cloud_asset_reference(
            con,
            1001,
            asset_type="",
            identifier="ignored",
            source="artifact_url_extract",
            audit_artifact_lineage=_audit_lineage,
        )
        store_artifact_cloud_asset_reference(
            con,
            1001,
            asset_type="gcs",
            identifier="",
            source="artifact_url_extract",
            audit_artifact_lineage=_audit_lineage,
        )

        rows = con.execute(
            """
            SELECT asset_type, identifier, provider_identifier, metadata_json
            FROM cloud_assets
            ORDER BY asset_type ASC
            """
        ).fetchall()
        assert [(row["asset_type"], row["identifier"], row["provider_identifier"]) for row in rows] == [
            ("aws_s3", "teambucket", "TeamBucket"),
            ("firebase", "acme-prod", "Acme-Prod"),
        ]
        assert json.loads(str(rows[0]["metadata_json"])) == {"source_url": "s3://TeamBucket/reports"}
        assert len(audit_calls) == 1
    finally:
        con.close()


def test_artifact_remote_download_scope_decision_allows_when_no_checker_or_checker_allows() -> None:
    without_checker = artifact_remote_download_scope_decision(
        index=0,
        source_url="https://downloads.acme.example/app.apk",
    )
    assert without_checker == ArtifactRemoteDownloadScopeDecision(
        index=0,
        source_url="https://downloads.acme.example/app.apk",
    )

    with_checker = artifact_remote_download_scope_decision(
        index=1,
        source_url="https://downloads.acme.example/app.apk",
        remote_url_scope_checker=lambda url: url.endswith(".apk"),
    )
    assert with_checker.allowed is True
    assert with_checker.denial_reason == ""


def test_artifact_remote_download_scope_decision_denies_when_checker_rejects() -> None:
    decision = artifact_remote_download_scope_decision(
        index=2,
        source_url="https://evil.example/app.apk",
        remote_url_scope_checker=lambda _url: False,
    )

    assert decision == ArtifactRemoteDownloadScopeDecision(
        index=2,
        source_url="https://evil.example/app.apk",
        allowed=False,
        denial_reason="scope_manifest_denied_remote_artifact",
    )


def test_artifact_remote_download_scope_decision_reports_checker_error() -> None:
    decision = artifact_remote_download_scope_decision(
        index=3,
        source_url="https://downloads.acme.example/app.apk",
        remote_url_scope_checker=lambda _url: (_ for _ in ()).throw(ValueError("bad manifest")),
    )

    assert decision.allowed is False
    assert decision.denial_reason == "scope_checker_error:ValueError"


def test_remote_artifact_url_scope_decision_rejects_empty_and_invalid_urls() -> None:
    validator_calls: list[object] = []

    def _validate(
        manifest: dict[str, Any],
        entries: list[dict[str, str]],
    ) -> dict[str, object]:
        validator_calls.append((manifest, entries))
        return {"authorized": entries}

    assert remote_artifact_url_scope_decision(
        "",
        scope_manifest_metadata=None,
        dry_run_all=True,
        validate_scope_manifest_seed_values=_validate,
    ) == {"allowed": False, "reason": "empty"}
    assert remote_artifact_url_scope_decision(
        "ftp://files.acme.example/app.apk",
        scope_manifest_metadata=None,
        dry_run_all=True,
        validate_scope_manifest_seed_values=_validate,
    ) == {"allowed": False, "reason": "invalid_url"}
    assert validator_calls == []


def test_remote_artifact_url_scope_decision_handles_missing_manifest_modes() -> None:
    def _validate(
        _manifest: dict[str, Any],
        _entries: list[dict[str, str]],
    ) -> dict[str, object]:
        raise AssertionError("validator should not run without a manifest")

    assert remote_artifact_url_scope_decision(
        "https://Downloads.Acme.Example/app.apk",
        scope_manifest_metadata=None,
        dry_run_all=False,
        validate_scope_manifest_seed_values=_validate,
    ) == {
        "allowed": False,
        "reason": "scope_manifest_required",
        "hostname": "downloads.acme.example",
    }
    assert remote_artifact_url_scope_decision(
        "https://Downloads.Acme.Example/app.apk",
        scope_manifest_metadata={},
        dry_run_all=True,
        validate_scope_manifest_seed_values=_validate,
    ) == {
        "allowed": True,
        "reason": "no_scope_manifest",
        "hostname": "downloads.acme.example",
    }


def test_remote_artifact_url_scope_decision_delegates_manifest_authorization() -> None:
    calls: list[tuple[dict[str, Any], list[dict[str, str]]]] = []

    def _validate(
        manifest: dict[str, Any],
        entries: list[dict[str, str]],
    ) -> dict[str, object]:
        calls.append((manifest, entries))
        return {"authorized": entries}

    manifest = {"source": "scope.json", "entries": ["downloads.acme.example"]}
    assert remote_artifact_url_scope_decision(
        "https://Downloads.Acme.Example/app.apk",
        scope_manifest_metadata=manifest,
        dry_run_all=False,
        validate_scope_manifest_seed_values=_validate,
    ) == {
        "allowed": True,
        "reason": "allowed",
        "hostname": "downloads.acme.example",
    }
    assert calls == [
        (
            manifest,
            [{"value": "https://Downloads.Acme.Example/app.apk", "seed_type": "url"}],
        )
    ]


def test_remote_artifact_url_scope_decision_reports_manifest_denial() -> None:
    def _validate(
        _manifest: dict[str, Any],
        _entries: list[dict[str, str]],
    ) -> dict[str, object]:
        return {"denied": [{"value": "https://evil.example/app.apk"}]}

    assert remote_artifact_url_scope_decision(
        "https://evil.example/app.apk",
        scope_manifest_metadata={"source": "scope.json"},
        dry_run_all=True,
        validate_scope_manifest_seed_values=_validate,
    ) == {
        "allowed": False,
        "reason": "scope_manifest_denied",
        "hostname": "evil.example",
        "scope_manifest_source": "scope.json",
    }


def test_download_remote_artifact_batch_preserves_order_and_scope_denials(tmp_path: Path) -> None:
    allowed_path = tmp_path / "allowed.apk"
    requests = [
        ArtifactDownloadRequest(
            artifact_id=1,
            source_url="https://downloads.acme.example/app.apk",
            artifact_type="apk",
        ),
        ArtifactDownloadRequest(
            artifact_id=2,
            source_url="https://evil.example/config.json",
            artifact_type="config",
        ),
        ArtifactDownloadRequest(
            artifact_id=3,
            source_url="https://downloads.acme.example/fail.json",
            artifact_type="config",
        ),
    ]
    denied: list[tuple[int, str]] = []
    downloaded: list[int] = []
    progress_events: list[tuple[str, dict[str, object]]] = []

    def _download_one(request: ArtifactDownloadRequest) -> ArtifactDownloadResult:
        downloaded.append(request.artifact_id)
        if request.artifact_id == 3:
            raise RuntimeError("transient fetch failure")
        return ArtifactDownloadResult(
            artifact_id=request.artifact_id,
            source_url=request.source_url,
            artifact_type=request.artifact_type,
            path=allowed_path,
            metadata_extra={"download_filename": allowed_path.name},
        )

    results = download_remote_artifact_batch(
        requests,
        max_workers=3,
        remote_url_scope_checker=lambda url: "evil.example" not in url,
        remote_scope_denied_callback=lambda request, reason: denied.append(
            (request.artifact_id, reason)
        ),
        download_one=_download_one,
        progress_label="artifact processing",
        progress_callback=lambda label, metrics: progress_events.append((label, dict(metrics))),
    )

    assert [result.artifact_id for result in results] == [1, 2, 3]
    assert results[0].path == allowed_path
    assert results[0].metadata_extra == {"download_filename": allowed_path.name}
    assert results[1].error == "scope_manifest_denied_remote_artifact"
    assert results[1].metadata_extra == {
        "skip_status": "skipped",
        "skip_reason": "scope_manifest_denied_remote_artifact",
    }
    assert str(results[2].error).startswith(
        "remote acquisition failed: RuntimeError: transient fetch failure"
    )
    assert sorted(downloaded) == [1, 3]
    assert denied == [(2, "scope_manifest_denied_remote_artifact")]
    assert progress_events[0][0] == "artifact processing / remote download"
    assert int(progress_events[0][1]["completed"]) == 0
    assert int(progress_events[0][1]["total"]) == 2
    assert int(progress_events[-1][1]["completed"]) == 2
    assert int(progress_events[-1][1]["failed"]) == 1
    assert int(progress_events[-1][1]["queue_depth"]) == 0
    assert float(progress_events[-1][1]["eta_seconds"] or 0.0) == 0.0


def test_download_remote_artifact_request_handles_non_http_cache_and_success(
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, Any]] = []

    def _select_filename(
        artifact_id: int,
        source_url: str,
        artifact_type: str,
        **kwargs: Any,
    ) -> str:
        calls.append(("filename", artifact_id, source_url, artifact_type, dict(kwargs)))
        if kwargs.get("content_type") == "application/json":
            return "downloaded.json"
        return "cached.json"

    def _classify(path: Path) -> str | None:
        return "json-config" if path.suffix == ".json" else None

    def _base_kwargs() -> dict[str, Any]:
        return {
            "select_remote_artifact_filename": _select_filename,
            "classify_artifact": _classify,
            "remote_artifact_max_bytes": 32,
            "rate_limit_retries": lambda: 0,
            "sleep_rate_limit_cooldown": lambda scope, url: calls.append(("cooldown", scope, url)),
            "web_fetch_request_delay_seconds": lambda: 0.0,
            "web_fetch_retry_after_seconds": lambda _exc: 0.0,
            "record_rate_limit_cooldown": lambda scope, url, seconds: calls.append(("record", scope, url, seconds)),
            "sleep": lambda seconds: calls.append(("sleep", seconds)),
        }

    non_http = download_remote_artifact_request(
        ArtifactDownloadRequest(artifact_id=1, source_url="file:///tmp/config.json", artifact_type="config"),
        cache_dir=tmp_path,
        **_base_kwargs(),
    )
    assert non_http == ArtifactDownloadResult(
        artifact_id=1,
        source_url="file:///tmp/config.json",
        artifact_type="config",
    )

    cached_path = tmp_path / "2-cached.json"
    cached_path.write_text("cached", encoding="utf-8")
    cached = download_remote_artifact_request(
        ArtifactDownloadRequest(artifact_id=2, source_url="https://cdn.example/cached", artifact_type="config"),
        cache_dir=tmp_path,
        **_base_kwargs(),
    )
    assert cached.path == cached_path
    assert cached.artifact_type == "json-config"
    assert cached.metadata_extra == {"download_filename": "2-cached.json"}

    class _Response:
        headers = {
            "Content-Type": " application/json ",
            "Content-Disposition": " attachment; filename=downloaded.json ",
        }

        def __init__(self) -> None:
            self._chunks = [b'{"ok":', b"true}", b""]

        def __enter__(self) -> "_Response":
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def read(self, _size: int) -> bytes:
            return self._chunks.pop(0)

    opened: list[tuple[Any, float]] = []
    downloaded = download_remote_artifact_request(
        ArtifactDownloadRequest(artifact_id=3, source_url="https://cdn.example/config", artifact_type="config"),
        cache_dir=tmp_path,
        request_factory=lambda url, headers: {"url": url, "headers": headers},
        urlopen_fn=lambda request, timeout: opened.append((request, timeout)) or _Response(),
        **_base_kwargs(),
    )
    assert downloaded.path == tmp_path / "3-downloaded.json"
    assert downloaded.artifact_type == "json-config"
    assert downloaded.metadata_extra == {
        "content_disposition": "attachment; filename=downloaded.json",
        "content_type": "application/json",
        "download_filename": "3-downloaded.json",
    }
    assert downloaded.path.read_bytes() == b'{"ok":true}'
    assert opened == [
        (
            {
                "url": "https://cdn.example/config",
                "headers": {"User-Agent": "FORGE/1.0 artifact-fetch"},
            },
            20.0,
        )
    ]


def test_download_remote_artifact_request_bounds_oversized_payload(tmp_path: Path) -> None:
    class _Response:
        headers: dict[str, str] = {}

        def __enter__(self) -> "_Response":
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def read(self, _size: int) -> bytes:
            return b"abcdef"

    result = download_remote_artifact_request(
        ArtifactDownloadRequest(artifact_id=4, source_url="https://cdn.example/large.bin", artifact_type="document"),
        cache_dir=tmp_path,
        select_remote_artifact_filename=lambda *_args, **_kwargs: "large.bin",
        classify_artifact=lambda _path: None,
        remote_artifact_max_bytes=5,
        rate_limit_retries=lambda: 0,
        sleep_rate_limit_cooldown=lambda _scope, _url: None,
        web_fetch_request_delay_seconds=lambda: 0.0,
        web_fetch_retry_after_seconds=lambda _exc: 0.0,
        record_rate_limit_cooldown=lambda _scope, _url, _seconds: None,
        request_factory=lambda url, headers: {"url": url, "headers": headers},
        urlopen_fn=lambda _request, timeout: _Response(),
    )

    assert result.path is None
    assert result.error.startswith("remote acquisition failed: ValueError")
    assert (tmp_path / "4-large.bin").read_bytes() == b""


def test_remote_artifact_download_result_helpers_apply_legacy_side_effects(
    tmp_path: Path,
) -> None:
    ok_path = tmp_path / "downloaded.json"
    ok_path.write_text("{}", encoding="utf-8")
    status_updates: list[tuple[int, str, str]] = []
    local_updates: list[tuple[int, Path, str, dict[str, Any]]] = []
    seen_requests: list[ArtifactDownloadRequest] = []
    request = ArtifactDownloadRequest(
        artifact_id=7,
        source_url="https://downloads.acme.example/config.json",
        artifact_type="config",
    )

    assert apply_remote_artifact_download_result(
        request,
        ArtifactDownloadResult(
            artifact_id=7,
            source_url=request.source_url,
            artifact_type="json-config",
            path=ok_path,
            metadata_extra={"download_filename": ok_path.name},
        ),
        update_artifact_status=lambda artifact_id, status, notes: status_updates.append(
            (artifact_id, status, notes)
        ),
        set_artifact_local_path=lambda artifact_id, path, artifact_type, metadata: local_updates.append(
            (artifact_id, path, artifact_type, metadata)
        ),
    ) == ok_path
    assert local_updates == [(7, ok_path, "json-config", {"download_filename": ok_path.name})]
    assert status_updates == []

    assert apply_remote_artifact_download_result(
        request,
        ArtifactDownloadResult(
            artifact_id=7,
            source_url=request.source_url,
            artifact_type="config",
            error="remote acquisition failed: HTTPError",
        ),
        update_artifact_status=lambda artifact_id, status, notes: status_updates.append(
            (artifact_id, status, notes)
        ),
        set_artifact_local_path=lambda artifact_id, path, artifact_type, metadata: local_updates.append(
            (artifact_id, path, artifact_type, metadata)
        ),
    ) is None
    assert status_updates == [(7, "failed", "remote acquisition failed: HTTPError")]

    assert apply_remote_artifact_download_result(
        request,
        ArtifactDownloadResult(
            artifact_id=7,
            source_url=request.source_url,
            artifact_type="config",
        ),
        update_artifact_status=lambda artifact_id, status, notes: status_updates.append(
            (artifact_id, status, notes)
        ),
        set_artifact_local_path=lambda artifact_id, path, artifact_type, metadata: local_updates.append(
            (artifact_id, path, artifact_type, metadata)
        ),
    ) is None
    assert local_updates == [(7, ok_path, "json-config", {"download_filename": ok_path.name})]

    def _download_one(download_request: ArtifactDownloadRequest) -> ArtifactDownloadResult:
        seen_requests.append(download_request)
        return ArtifactDownloadResult(
            artifact_id=download_request.artifact_id,
            source_url=download_request.source_url,
            artifact_type="config",
            path=ok_path,
        )

    assert download_remote_artifact_for_queue_record(
        artifact_id=11,
        source_url="https://downloads.acme.example/next.json",
        artifact_type="config",
        download_one=_download_one,
        update_artifact_status=lambda artifact_id, status, notes: status_updates.append(
            (artifact_id, status, notes)
        ),
        set_artifact_local_path=lambda artifact_id, path, artifact_type, metadata: local_updates.append(
            (artifact_id, path, artifact_type, metadata)
        ),
    ) == ok_path
    assert seen_requests == [
        ArtifactDownloadRequest(
            artifact_id=11,
            source_url="https://downloads.acme.example/next.json",
            artifact_type="config",
        )
    ]
    assert local_updates[-1] == (11, ok_path, "config", {})


def test_artifact_discovery_payloads_rebases_http_sources_only() -> None:
    payloads = [
        ("local.txt", "payload.txt", "one"),
        ("local.txt", "nested/config.json", "two"),
    ]

    assert artifact_discovery_payloads(source_url="", payloads=payloads) == payloads
    assert artifact_discovery_payloads(source_url="file:///artifact.txt", payloads=payloads) == payloads
    assert artifact_discovery_payloads(
        source_url="https://downloads.acme.example/app.apk",
        payloads=payloads,
    ) == [
        ("https://downloads.acme.example/app.apk", "payload.txt", "one"),
        ("https://downloads.acme.example/app.apk", "nested/config.json", "two"),
    ]


def test_decode_artifact_data_uri_bytes_supports_base64_and_percent_encoding() -> None:
    encoded = base64.b64encode(b"owner=analyst@acme.example").decode("ascii")

    assert decode_artifact_data_uri_bytes("text/plain;base64", encoded) == b"owner=analyst@acme.example"
    assert decode_artifact_data_uri_bytes("text/plain", "url%3Dhttps%3A//portal.acme.example") == (
        b"url=https://portal.acme.example"
    )
    assert decode_artifact_data_uri_bytes("text/plain;base64", "%%not-base64%%") == b""
    assert decode_artifact_data_uri_bytes("text/plain", "") == b""


def test_artifact_data_uri_payload_entry_filters_noise_and_bounds_decoding() -> None:
    decoded_inputs: list[bytes] = []

    def _decode(data: bytes) -> str:
        decoded_inputs.append(data)
        return data.decode("utf-8", "ignore")

    encoded = base64.b64encode(b"api=https://portal.acme.example\nignored-tail").decode("ascii")

    assert artifact_data_uri_payload_entry(
        ("text/plain;base64", encoded),
        max_artifact_member_bytes=31,
        decode_text_artifact_bytes=_decode,
    ) == "api=https://portal.acme.example"
    assert decoded_inputs == [b"api=https://portal.acme.example"]
    assert artifact_data_uri_payload_entry(
        ("text/plain", "ordinary-not-signal"),
        max_artifact_member_bytes=128,
        decode_text_artifact_bytes=_decode,
    ) == ""


def test_artifact_data_uri_structured_payload_text_dedupes_lines_in_order() -> None:
    first = base64.b64encode(
        b"URL=https://portal.acme.example\nurl=https://portal.acme.example\nowner@acme.example"
    ).decode("ascii")
    second = base64.b64encode(b"token=value\nowner@acme.example").decode("ascii")

    payload = artifact_data_uri_structured_payload_text(
        f"prefix data:text/plain;base64,{first} middle data:text/plain;base64,{second}",
        data_uri_pattern=_DATA_URI_RE,
        run_ordered_batch=_run_ordered_batch,
        data_uri_payload_entry=lambda entry: artifact_data_uri_payload_entry(
            entry,
            max_artifact_member_bytes=512,
            decode_text_artifact_bytes=lambda data: data.decode("utf-8", "ignore"),
        ),
    )

    assert payload.splitlines() == [
        "URL=https://portal.acme.example",
        "owner@acme.example",
        "token=value",
    ]


def test_artifact_data_uri_image_helpers_collect_ocr_barcode_and_metadata() -> None:
    calls: list[tuple[str, str]] = []

    def _suffix_from_content_type(mime_type: str) -> str:
        calls.append(("suffix", mime_type))
        return ".png" if mime_type == "image/png" else ""

    def _ocr_image_bytes(data: bytes, suffix: str) -> str:
        calls.append(("ocr", suffix))
        assert data == b"png-bytes"
        return "owner@acme.example"

    def _barcode_image_bytes_payload(data: bytes) -> str:
        assert data == b"png-bytes"
        return "https://barcode.acme.example"

    def _image_metadata_payload(data: bytes) -> str:
        assert data == b"png-bytes"
        return "metadata=ok"

    encoded = base64.b64encode(b"png-bytes").decode("ascii")
    entry_payload = artifact_data_uri_image_payload_entry(
        (3, "image/png;base64", encoded),
        ocr_image_suffixes={".png"},
        max_ocr_image_bytes=64,
        suffix_from_content_type=_suffix_from_content_type,
        ocr_image_bytes=_ocr_image_bytes,
        barcode_image_bytes_payload=_barcode_image_bytes_payload,
        image_metadata_payload=_image_metadata_payload,
    )

    assert calls == [("suffix", "image/png"), ("ocr", ".png")]
    assert entry_payload.splitlines() == [
        "data_uri_image_3#ocr",
        "owner@acme.example",
        "data_uri_image_3#barcode",
        "https://barcode.acme.example",
        "data_uri_image_3#image-metadata",
        "metadata=ok",
    ]
    assert artifact_data_uri_image_payload_entry(
        (0, "text/plain;base64", encoded),
        ocr_image_suffixes={".png"},
        max_ocr_image_bytes=64,
        suffix_from_content_type=_suffix_from_content_type,
        ocr_image_bytes=_ocr_image_bytes,
        barcode_image_bytes_payload=_barcode_image_bytes_payload,
        image_metadata_payload=_image_metadata_payload,
    ) == ""


def test_artifact_data_uri_image_structured_payload_text_dedupes_lines_in_order() -> None:
    first = base64.b64encode(b"png-one").decode("ascii")
    second = base64.b64encode(b"png-two").decode("ascii")

    payload = artifact_data_uri_image_structured_payload_text(
        f"data:image/png;base64,{first} data:image/png;base64,{second}",
        data_uri_pattern=_DATA_URI_RE,
        run_ordered_batch=_run_ordered_batch,
        data_uri_image_payload_entry=lambda entry: (
            "owner@acme.example\nhttps://image.acme.example"
            if entry[0] == 0
            else "OWNER@acme.example\nmetadata=second"
        ),
    )

    assert payload.splitlines() == [
        "owner@acme.example",
        "https://image.acme.example",
        "metadata=second",
    ]


def test_dedupe_firebase_projects_preserves_first_project_source_extract_tuple() -> None:
    projects = [
        SimpleNamespace(project_id="alpha", source_file="one.apk", extract_path="base/google-services.json"),
        SimpleNamespace(project_id="alpha", source_file="one.apk", extract_path="base/google-services.json"),
        SimpleNamespace(project_id="alpha", source_file="two.apk", extract_path="base/google-services.json"),
        SimpleNamespace(project_id="bravo", source_file="one.apk", extract_path="base/google-services.json"),
    ]

    deduped = dedupe_firebase_projects(projects)

    assert deduped == [projects[0], projects[2], projects[3]]


def test_dedupe_supabase_configs_preserves_first_project_source_extract_tuple() -> None:
    configs = [
        SimpleNamespace(project_ref="alpha", source_file="one.apk", extract_path="supabase.js"),
        SimpleNamespace(project_ref="alpha", source_file="one.apk", extract_path="supabase.js"),
        SimpleNamespace(project_ref="alpha", source_file="two.apk", extract_path="supabase.js"),
        SimpleNamespace(project_ref="bravo", source_file="one.apk", extract_path="supabase.js"),
    ]

    deduped = dedupe_supabase_configs(configs)

    assert deduped == [configs[0], configs[2], configs[3]]


def test_firebase_project_persistence_entry_shapes_storage_and_project_metadata() -> None:
    project = SimpleNamespace(
        project_id="acme-mobile",
        source_file="app.apk",
        extract_path="res/google-services.json",
        storage_bucket="acme-mobile.appspot.com",
        rtdb_url="https://acme-mobile.firebaseio.com",
        api_key_enc="enc-key",
    )

    entry = firebase_project_persistence_entry(
        project,
        source_url="https://downloads.acme.example/app.apk",
    )

    assert entry == {
        "project_id": "acme-mobile",
        "source_file": "app.apk",
        "extract_path": "res/google-services.json",
        "storage_bucket": "acme-mobile.appspot.com",
        "storage_bucket_url": "https://storage.googleapis.com/acme-mobile.appspot.com",
        "storage_relation_metadata": {
            "rule": "artifact_mobile_config_storage_bucket",
            "source_url": "https://downloads.acme.example/app.apk",
            "source_file": "app.apk",
            "extract_path": "res/google-services.json",
        },
        "rtdb_url": "https://acme-mobile.firebaseio.com",
        "api_key_enc": "enc-key",
        "project_relation_metadata": {
            "rule": "artifact_mobile_config",
            "source_url": "https://downloads.acme.example/app.apk",
            "source_file": "app.apk",
            "extract_path": "res/google-services.json",
        },
    }


def test_supabase_config_persistence_entry_uses_secret_callbacks_and_metadata() -> None:
    callback_inputs: list[str] = []
    config = SimpleNamespace(
        project_ref="acme",
        project_url="https://acme.supabase.co",
        anon_key="anon-key",
        source_file="app.apk",
        extract_path="assets/supabase.js",
    )

    def _redact_secret(secret: str) -> str:
        callback_inputs.append(f"redact:{secret}")
        return "anon-****"

    def _encrypt_secret_material(secret: str) -> str:
        callback_inputs.append(f"encrypt:{secret}")
        return "enc-anon"

    entry = supabase_config_persistence_entry(
        config,
        source_url="https://downloads.acme.example/app.apk",
        redact_secret=_redact_secret,
        encrypt_secret_material=_encrypt_secret_material,
    )

    assert callback_inputs == ["redact:anon-key", "encrypt:anon-key"]
    assert entry == {
        "project_ref": "acme",
        "project_url": "https://acme.supabase.co",
        "source_file": "app.apk",
        "relation_metadata": {
            "rule": "artifact_mobile_config",
            "source_url": "https://downloads.acme.example/app.apk",
            "source_file": "app.apk",
            "extract_path": "assets/supabase.js",
        },
        "key_redacted": "anon-****",
        "key_enc": "enc-anon",
    }


def test_merge_artifact_text_discovery_batch_normalizes_and_dedupes_families() -> None:
    target = ArtifactTextDiscoveryBatch(
        source_file="target.txt",
        emails=["owner@acme.example"],
        ip_seeds=[("203.0.113.10", "ipv4")],
        key_findings=[{"pattern_name": "github_pat", "key_redacted": "ghp_****"}],
        cloud_assets=[("aws_s3", "ops-bucket", "artifact_s3_uri")],
    )
    source = ArtifactTextDiscoveryBatch(
        source_file="source.txt",
        emails=[" owner@acme.example ", " security@acme.example "],
        phones=[" +15551234567 ", ""],
        ip_seeds=[("203.0.113.10", "ipv4"), (" 2001:db8::10 ", " ipv6 "), ("", "ipv4")],
        host_seeds=[(" api.acme.example ", " subdomain "), ("api.acme.example", "subdomain")],
        urls=[" https://portal.acme.example ", "https://portal.acme.example"],
        identity_seeds=[
            (" Acme Labs ", " company ", " ORG ", " Operations "),
            ("", "name", "FN", ""),
        ],
        key_findings=[
            {"pattern_name": "github_pat", "key_redacted": "duplicate"},
            {"pattern_name": "stripe_live", "key_redacted": "sk_live_****"},
        ],
        cloud_assets=[
            ("aws_s3", "ops-bucket", "artifact_s3_uri"),
            (" gcs ", " mirror-bucket ", " artifact_gcs_uri "),
        ],
    )

    merge_artifact_text_discovery_batch(
        target,
        source,
        run_ordered_batch=_run_ordered_batch,
        artifact_text_discovery_merge_family_entry=artifact_text_discovery_merge_family_entry,
    )

    assert target.emails == ["owner@acme.example", "security@acme.example"]
    assert target.phones == ["+15551234567"]
    assert target.ip_seeds == [("203.0.113.10", "ipv4"), ("2001:db8::10", "ipv6")]
    assert target.host_seeds == [("api.acme.example", "subdomain")]
    assert target.urls == ["https://portal.acme.example"]
    assert target.identity_seeds == [("Acme Labs", "company", "ORG", "Operations")]
    assert target.key_findings == [
        {"pattern_name": "github_pat", "key_redacted": "ghp_****"},
        {"pattern_name": "stripe_live", "key_redacted": "sk_live_****"},
    ]
    assert target.cloud_assets == [
        ("aws_s3", "ops-bucket", "artifact_s3_uri"),
        ("gcs", "mirror-bucket", "artifact_gcs_uri"),
    ]


def test_artifact_text_persistence_entries_preserve_metadata_and_defaults() -> None:
    source_file = "artifact.txt"

    assert artifact_text_email_persistence_entry("owner@acme.example", source_file=source_file) == {
        "email": "owner@acme.example",
        "metadata": {"rule": "artifact_text_extract", "source_file": source_file},
    }
    assert artifact_text_phone_persistence_entry("+15551234567", source_file=source_file) == {
        "phone": "+15551234567",
        "metadata": {"rule": "artifact_text_extract", "source_file": source_file},
    }
    assert artifact_text_ip_persistence_entry(("203.0.113.10", "ipv4"), source_file=source_file) == {
        "ip_value": "203.0.113.10",
        "ip_seed_type": "ipv4",
        "metadata": {"rule": "artifact_text_extract", "source_file": source_file},
    }
    assert artifact_text_host_persistence_entry(("api.acme.example", "subdomain"), source_file=source_file) == {
        "host_value": "api.acme.example",
        "host_seed_type": "subdomain",
        "confidence": 0.64,
        "metadata": {"rule": "artifact_network_dsn_extract", "source_file": source_file},
    }
    assert artifact_text_identity_seed_persistence_entry(
        ("Acme Labs", "company", "ORG", "Operations"),
        source_file=source_file,
    ) == {
        "seed_value": "Acme Labs",
        "seed_type": "company",
        "confidence": 0.72,
        "metadata": {
            "rule": "calendar_contact_explicit_field",
            "source_file": source_file,
            "contact_field": "ORG",
            "normalized_value": "Acme Labs",
            "artifact_contact_identity": True,
            "contact_title": "Operations",
        },
    }
    assert artifact_text_identity_seed_persistence_entry(("Ops", "role", "TITLE", ""), source_file=source_file) is None

    def _helm_metadata(url: str, *, source_file: str) -> dict[str, Any]:
        return {"rule": "helm_index_chart_url", "url": url, "source_file": source_file}

    assert artifact_text_url_persistence_entry(
        "https://charts.acme.example/app.tgz",
        source_file=source_file,
        helm_index_chart_url_metadata=_helm_metadata,
    ) == {
        "url": "https://charts.acme.example/app.tgz",
        "relation_metadata": {
            "rule": "helm_index_chart_url",
            "url": "https://charts.acme.example/app.tgz",
            "source_file": source_file,
        },
    }
    assert artifact_text_key_finding_persistence_entry(
        {
            "service": "github",
            "domain": "",
            "source_url": source_file,
            "pattern_name": "github_pat",
            "key_redacted": "ghp_****",
            "source_backend": "artifact_text_extract",
            "repo_name": "artifact.txt",
        }
    ) == {
        "service": "github",
        "domain": "",
        "source_url": source_file,
        "pattern_name": "github_pat",
        "key_redacted": "ghp_****",
        "key_enc": None,
        "source_backend": "artifact_text_extract",
        "repo_name": "artifact.txt",
        "validation_detail": "artifact_queue_ingest",
    }
    assert artifact_text_cloud_asset_persistence_entry(
        ("aws_s3", "ops-bucket", "artifact_s3_uri"),
        source_file=source_file,
    ) == {
        "asset_type": "aws_s3",
        "identifier": "ops-bucket",
        "source": "artifact_s3_uri",
        "relation_metadata": {"rule": "artifact_s3_uri", "source_file": source_file},
    }


def test_artifact_url_social_pivot_entries_promotes_handle_domain_company_and_name() -> None:
    url = "https://bsky.app/profile/Acme.Example"

    def _platform(profile_stub: dict[str, Any]) -> str:
        assert profile_stub == {"profile_url": url}
        return "bluesky"

    def _handle(candidate_url: str) -> str:
        assert candidate_url == url
        return "Acme.Example"

    def _classify(seed_value: str) -> str:
        return "domain" if seed_value == "acme.example" else "username"

    def _company(profile_stub: dict[str, Any], *, source_label: str, platform: str) -> str:
        assert profile_stub == {"profile_url": url}
        assert source_label == "artifact_social_url"
        assert platform == "bluesky"
        return "Acme Labs"

    def _name(profile_stub: dict[str, Any]) -> str:
        assert profile_stub == {"profile_url": url}
        return "Alice Example"

    entries = artifact_url_social_pivot_entries(
        url,
        relation_metadata={"rule": "artifact_text_extract", "source_file": "links.txt"},
        social_profile_platform_hint=_platform,
        extract_social_profile_handle_from_url=_handle,
        classify_seed_value=_classify,
        social_profile_company_name=_company,
        social_profile_name=_name,
    )

    assert entries == [
        {
            "seed_value": "Acme.Example",
            "seed_type": "username",
            "seed_confidence": 0.78,
            "relation_type": "derived_from",
            "relation_confidence": 0.78,
            "relation_metadata": {
                "rule": "artifact_social_url_extract",
                "platform": "bluesky",
                "source_file": "links.txt",
            },
        },
        {
            "seed_value": "acme.example",
            "seed_type": "domain",
            "seed_confidence": 0.77,
            "relation_type": "derived_from",
            "relation_confidence": 0.77,
            "relation_metadata": {
                "rule": "social_profile_domain_handle",
                "platform": "bluesky",
                "source_file": "links.txt",
            },
        },
        {
            "seed_value": "Acme Labs",
            "seed_type": "company",
            "seed_confidence": 0.76,
            "relation_type": "derived_from",
            "relation_confidence": 0.76,
            "relation_metadata": {
                "rule": "artifact_social_url_extract",
                "platform": "bluesky",
                "source_file": "links.txt",
            },
        },
        {
            "seed_value": "Alice Example",
            "seed_type": "name",
            "seed_confidence": 0.74,
            "relation_type": "derived_from",
            "relation_confidence": 0.74,
            "relation_metadata": {
                "rule": "artifact_social_url_extract",
                "platform": "bluesky",
                "source_file": "links.txt",
            },
        },
    ]


def test_artifact_social_profile_url_pivot_entry_normalizes_values() -> None:
    assert artifact_social_profile_url_pivot_entry(
        (
            3,
            {
                "seed_value": " acme ",
                "seed_type": " username ",
                "seed_confidence": "0.7",
                "relation_type": " derived_from ",
                "relation_confidence": "0.6",
                "relation_metadata": {"rule": "artifact_social_url_extract"},
            },
        )
    ) == {
        "seed_value": "acme",
        "seed_type": "username",
        "seed_confidence": 0.7,
        "relation_type": "derived_from",
        "relation_confidence": 0.6,
        "relation_metadata": {"rule": "artifact_social_url_extract"},
    }
    assert artifact_social_profile_url_pivot_entry((0, object())) is None  # type: ignore[arg-type]


def test_artifact_cloud_asset_url_entry_normalizes_required_fields() -> None:
    assert artifact_cloud_asset_url_entry(
        (
            1,
            {
                "asset_type": " aws_s3 ",
                "identifier": " logs-bucket ",
                "source": " artifact_url_extract ",
            },
        )
    ) == {
        "asset_type": "aws_s3",
        "identifier": "logs-bucket",
        "source": "artifact_url_extract",
    }
    assert artifact_cloud_asset_url_entry((0, {"asset_type": "aws_s3", "source": "artifact"})) is None
    assert artifact_cloud_asset_url_entry((1, object())) is None  # type: ignore[arg-type]


def test_artifact_url_seed_persistence_entry_merges_family_entries_in_order() -> None:
    relation_metadata = {"rule": "artifact_text_extract", "source_file": "artifact.txt"}
    calls: list[str] = []

    def _family_entry(
        family: str,
        *,
        url: str,
        hostname: str,
        relation_metadata: dict[str, Any] | None,
    ) -> dict[str, Any]:
        calls.append(family)
        assert url == "https://Portal.Example.com/app"
        assert hostname == "portal.example.com"
        assert relation_metadata == {"rule": "artifact_text_extract", "source_file": "artifact.txt"}
        if family == "social_pivots":
            return {"social_pivot_entries": [{"seed_value": "acme-labs", "seed_type": "username"}]}
        if family == "related_seeds":
            return {"related_seed_entries": [{"seed_value": "portal.example.com", "seed_type": "subdomain"}]}
        if family == "cloud_assets":
            return {"cloud_asset_entries": [{"asset_type": "aws_s3", "identifier": "ops-bucket"}]}
        return {}

    entry = artifact_url_seed_persistence_entry(
        "https://Portal.Example.com/app",
        relation_metadata=relation_metadata,
        artifact_url_looks_templated=lambda _url: False,
        artifact_url_looks_standards_namespace=lambda _url: False,
        is_mobile_bundle_url=lambda _url: False,
        run_ordered_batch=_run_ordered_batch,
        artifact_url_seed_family_entry=_family_entry,
        artifact_url_seed_family_merge_entry=artifact_url_seed_family_merge_entry,
    )

    assert calls == ["social_pivots", "related_seeds", "cloud_assets"]
    assert entry == {
        "url": "https://Portal.Example.com/app",
        "seed_type": "url",
        "relation_metadata": relation_metadata,
        "social_pivot_entries": [{"seed_value": "acme-labs", "seed_type": "username"}],
        "related_seed_entries": [{"seed_value": "portal.example.com", "seed_type": "subdomain"}],
        "cloud_asset_entries": [{"asset_type": "aws_s3", "identifier": "ops-bucket"}],
    }


def test_artifact_url_seed_persistence_entry_filters_unsupported_urls_and_marks_apks() -> None:
    common_kwargs = {
        "relation_metadata": None,
        "run_ordered_batch": _run_ordered_batch,
        "artifact_url_seed_family_entry": lambda *_args, **_kwargs: {},
        "artifact_url_seed_family_merge_entry": artifact_url_seed_family_merge_entry,
    }

    assert artifact_url_seed_persistence_entry(
        "https://example.com/{tenant}/config",
        artifact_url_looks_templated=lambda _url: True,
        artifact_url_looks_standards_namespace=lambda _url: False,
        is_mobile_bundle_url=lambda _url: False,
        **common_kwargs,
    ) is None
    assert artifact_url_seed_persistence_entry(
        "https://schema.org/Thing",
        artifact_url_looks_templated=lambda _url: False,
        artifact_url_looks_standards_namespace=lambda _url: True,
        is_mobile_bundle_url=lambda _url: False,
        **common_kwargs,
    ) is None
    assert artifact_url_seed_persistence_entry(
        "ftp://example.com/app.apk",
        artifact_url_looks_templated=lambda _url: False,
        artifact_url_looks_standards_namespace=lambda _url: False,
        is_mobile_bundle_url=lambda _url: True,
        **common_kwargs,
    ) is None

    apk_entry = artifact_url_seed_persistence_entry(
        "https://downloads.example.com/app.apk",
        artifact_url_looks_templated=lambda _url: False,
        artifact_url_looks_standards_namespace=lambda _url: False,
        is_mobile_bundle_url=lambda _url: True,
        **common_kwargs,
    )
    assert apk_entry is not None
    assert apk_entry["seed_type"] == "apk_url"


def test_artifact_url_seed_family_merge_entry_normalizes_missing_families() -> None:
    assert artifact_url_seed_family_merge_entry((0, object())) is None  # type: ignore[arg-type]
    assert artifact_url_seed_family_merge_entry((1, {"related_seed_entries": [{"seed_value": "example.com"}]})) == {
        "social_pivot_entries": [],
        "related_seed_entries": [{"seed_value": "example.com"}],
        "cloud_asset_entries": [],
    }


def test_artifact_text_discovered_url_queue_entry_shapes_metadata() -> None:
    def _classify(url: str, seed_type: str) -> str | None:
        assert url == "https://downloads.acme.example/config.json"
        assert seed_type == "url"
        return "config"

    entry = artifact_text_discovered_url_queue_entry(
        "https://downloads.acme.example/config.json",
        seed_type="url",
        relation_metadata={"rule": "artifact_text_url", "source_file": "root.txt"},
        classify_remote_artifact_candidate=_classify,
        remote_url_scope_checker=lambda url: url.endswith(".json"),
    )

    assert isinstance(entry, ArtifactTextDiscoveredUrlQueueEntry)
    assert entry.denied is False
    assert entry.artifact_type == "config"
    assert entry.metadata == {
        "rule": "artifact_text_discovered_artifact_queue",
        "source_rule": "artifact_text_url",
        "source_file": "root.txt",
        "source_seed_type": "url",
    }
    assert json.loads(entry.metadata_json) == entry.metadata


def test_artifact_text_discovered_url_queue_entry_filters_non_artifacts() -> None:
    assert (
        artifact_text_discovered_url_queue_entry(
            "https://downloads.acme.example/dashboard",
            seed_type="url",
            classify_remote_artifact_candidate=lambda _url, _seed_type: None,
        )
        is None
    )


def test_artifact_text_discovered_url_queue_entry_reports_scope_denial_reason() -> None:
    denied = artifact_text_discovered_url_queue_entry(
        "https://downloads.acme.example/config.json",
        seed_type="url",
        classify_remote_artifact_candidate=lambda _url, _seed_type: "config",
        remote_url_scope_checker=lambda _url: False,
    )
    assert isinstance(denied, ArtifactTextDiscoveredUrlQueueEntry)
    assert denied.denied is True
    assert denied.denial_reason == "scope_manifest_denied_remote_artifact"
    assert denied.metadata_json == "{}"

    errored = artifact_text_discovered_url_queue_entry(
        "https://downloads.acme.example/config.json",
        seed_type="url",
        classify_remote_artifact_candidate=lambda _url, _seed_type: "config",
        remote_url_scope_checker=lambda _url: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    assert isinstance(errored, ArtifactTextDiscoveredUrlQueueEntry)
    assert errored.denied is True
    assert errored.denial_reason == "scope_checker_error:RuntimeError"


def test_queue_artifact_text_discovered_url_inserts_idempotently_and_audits(tmp_path: Path) -> None:
    db_path = tmp_path / "artifact-urls.db"
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    audit_calls: list[dict[str, str]] = []
    try:
        con.execute(
            """
            CREATE TABLE artifact_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                source_url TEXT NOT NULL,
                local_path TEXT,
                artifact_type TEXT NOT NULL,
                discovered_from TEXT NOT NULL,
                status TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                queued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (engagement_id, source_url)
            )
            """
        )

        def _audit_lineage(*, action: str, target: str, result: str) -> None:
            audit_calls.append({"action": action, "target": target, "result": result})

        queued_entry = ArtifactTextDiscoveredUrlQueueEntry(
            url="https://downloads.acme.example/mobile/config.json",
            seed_type="url",
            artifact_type="config",
            metadata={"rule": "artifact_text_discovered_artifact_queue"},
            metadata_json=json.dumps({"rule": "artifact_text_discovered_artifact_queue"}, sort_keys=True),
        )

        assert (
            queue_artifact_text_discovered_url(
                con,
                1001,
                queued_entry,
                audit_artifact_lineage=_audit_lineage,
            )
            == 1
        )
        assert (
            queue_artifact_text_discovered_url(
                con,
                1001,
                queued_entry,
                audit_artifact_lineage=_audit_lineage,
            )
            == 0
        )
        assert queue_artifact_text_discovered_url(con, 1001, None, audit_artifact_lineage=_audit_lineage) == 0

        denied_entry = ArtifactTextDiscoveredUrlQueueEntry(
            url="https://evil.example/mobile/config.json",
            seed_type="url",
            artifact_type="config",
            metadata={},
            metadata_json="{}",
            denied=True,
            denial_reason="scope_manifest_denied_remote_artifact",
        )
        assert (
            queue_artifact_text_discovered_url(
                con,
                1001,
                denied_entry,
                audit_artifact_lineage=_audit_lineage,
            )
            == 0
        )

        rows = con.execute("SELECT * FROM artifact_queue ORDER BY id ASC").fetchall()
        assert len(rows) == 1
        assert str(rows[0]["source_url"]) == queued_entry.url
        assert str(rows[0]["artifact_type"]) == "config"
        assert str(rows[0]["discovered_from"]) == "artifact_text"
        assert str(rows[0]["status"]) == "queued"
        assert json.loads(str(rows[0]["metadata_json"])) == queued_entry.metadata
        assert audit_calls == [
            {
                "action": "artifact_text_url_queued",
                "target": "https://downloads.acme.example/mobile/config.json",
                "result": (
                    "rule=artifact_text_discovered_artifact_queue "
                    "artifact_type=config seed_type=url"
                ),
            },
            {
                "action": "artifact_text_url_scope_denied",
                "target": "https://evil.example/mobile/config.json",
                "result": (
                    "rule=artifact_text_discovered_artifact_queue "
                    "artifact_type=config seed_type=url "
                    "reason=scope_manifest_denied_remote_artifact"
                ),
            },
        ]
    finally:
        con.close()


def test_artifact_queue_candidate_entry_dedupes_by_url() -> None:
    queue_candidates: list[dict[str, object]] = []
    seen_urls: set[str] = set()
    first = {"raw_url": "https://downloads.acme.example/app.js", "artifact_type": "config"}
    duplicate = {"raw_url": " https://downloads.acme.example/app.js ", "artifact_type": "config"}

    assert (
        artifact_queue_candidate_entry(
            first,
            queue_candidates_out=queue_candidates,
            seen_urls_out=seen_urls,
        )
        == "https://downloads.acme.example/app.js"
    )
    assert (
        artifact_queue_candidate_entry(
            duplicate,
            queue_candidates_out=queue_candidates,
            seen_urls_out=seen_urls,
        )
        is None
    )
    assert artifact_queue_candidate_entry(None, queue_candidates_out=queue_candidates, seen_urls_out=seen_urls) is None
    assert queue_candidates == [first]


def test_artifact_source_metadata_filters_aliases_and_bounds_lists() -> None:
    metadata = artifact_source_metadata(
        json.dumps(
            {
                "Content-Type": "application/vnd.android.package-archive",
                "filename": "app.apk",
                "archive_sources": [
                    " one ",
                    "",
                    "two",
                    "three",
                    "four",
                    "five",
                    "six",
                    "seven",
                    "eight",
                    "nine",
                ],
                "root_domain": "acme.example",
                "ignored": "secret",
                "port": 443,
                "provider_sources": [{"bad": True}],
            }
        )
    )

    assert metadata == {
        "archive_sources": ["one", "two", "three", "four", "five", "six", "seven"],
        "content_type": "application/vnd.android.package-archive",
        "download_filename": "app.apk",
        "port": 443,
        "provider_sources": ["{'bad': True}"],
        "root_domain": "acme.example",
    }
    assert artifact_source_metadata("{bad") == {}
    assert artifact_source_metadata("[1, 2]") == {}


def test_prepare_artifact_source_candidate_item_normalizes_sources() -> None:
    crawl_item = prepare_artifact_source_candidate_item(
        (
            "crawl_results",
            (
                " https://downloads.acme.example/app.apk ",
                json.dumps({"content-type": "application/apk"}),
            ),
        )
    )
    seed_item = prepare_artifact_source_candidate_item(
        (
            "engagement_seed",
            (
                " https://cdn.acme.example/config.json ",
                " APK_URL ",
                json.dumps({"filename": "config.json"}),
            ),
        )
    )

    assert crawl_item == (
        "https://downloads.acme.example/app.apk",
        "crawl_results",
        None,
        {"content_type": "application/apk"},
    )
    assert seed_item == (
        "https://cdn.acme.example/config.json",
        "engagement_seed",
        "apk_url",
        {"download_filename": "config.json"},
    )
    assert prepare_artifact_source_candidate_item(("crawl_results", ("", "{}"))) is None
    assert prepare_artifact_source_candidate_item(("unknown", ("https://x.example",))) is None


def test_artifact_source_and_classification_reduction_helpers() -> None:
    reduced_source = prepare_artifact_source_reduction_item(
        (
            " https://downloads.acme.example/app.apk ",
            " crawl_results ",
            " APK_URL ",
            {"content_type": "application/apk"},
        )
    )
    assert reduced_source == (
        "https://downloads.acme.example/app.apk",
        "crawl_results",
        "apk_url",
        {"content_type": "application/apk"},
    )
    assert prepare_artifact_source_reduction_item(None) is None
    assert prepare_artifact_source_reduction_item(("", "crawl_results", None, {})) is None

    candidate = prepare_artifact_classification_reduction_item(
        (
            " https://downloads.acme.example/app.apk ",
            " crawl_results ",
            " APK_URL ",
            {"content_type": "application/apk"},
            " apk ",
        )
    )
    assert candidate == {
        "raw_url": "https://downloads.acme.example/app.apk",
        "discovered_from": "crawl_results",
        "seed_type": "apk_url",
        "artifact_type": "apk",
        "metadata": {"content_type": "application/apk"},
    }
    assert prepare_artifact_classification_reduction_item(("https://x.example", "", None, {}, "apk")) is None

    candidates: list[tuple[str, str, str | None, dict[str, Any]]] = []
    assert apply_artifact_source_candidate_item(reduced_source, candidates_out=candidates) == (
        "https://downloads.acme.example/app.apk"
    )
    assert candidates == [reduced_source]
    assert apply_artifact_source_candidate_item(None, candidates_out=candidates) is None


def test_apply_artifact_queue_total_item_preserves_halt_semantics() -> None:
    queued_total = [2]
    halted = [False]

    assert apply_artifact_queue_total_item(3, queued_total_out=queued_total, halted_out=halted) == 3
    assert queued_total == [5]
    assert halted == [False]
    assert apply_artifact_queue_total_item(-1, queued_total_out=queued_total, halted_out=halted) == -1
    assert queued_total == [5]
    assert halted == [True]
    assert apply_artifact_queue_total_item(9, queued_total_out=queued_total, halted_out=halted) == 9
    assert queued_total == [5]


def test_queue_discovered_artifact_candidates_coordinates_batches_and_dedupe() -> None:
    source_rows = [
        (
            "crawl_results",
            (
                " https://downloads.acme.example/app.apk ",
                json.dumps({"content-type": "application/apk"}),
            ),
        ),
        (
            "engagement_seed",
            (
                "https://downloads.acme.example/app.apk",
                "APK_URL",
                json.dumps({"filename": "app.apk"}),
            ),
        ),
        (
            "engagement_seed",
            (
                "https://cdn.acme.example/config.json",
                "url",
                json.dumps({"content_type": "application/json"}),
            ),
        ),
    ]
    events: list[tuple[str, object, dict[str, object]]] = []
    logs: list[tuple[str, str]] = []
    queued: list[dict[str, object]] = []

    def _run_batch(items: list[object], func: object, **kwargs: object) -> list[object]:
        events.append(("batch", list(items), kwargs))
        return [func(item) for item in items]  # type: ignore[misc]

    def _run_apply(items: list[object], func: object, **kwargs: object) -> list[object]:
        events.append(("apply", list(items), kwargs))
        return [func(item) for item in items]  # type: ignore[misc]

    def _classify(
        raw_url: str,
        seed_type: str | None,
        metadata: dict[str, Any] | None,
    ) -> str | None:
        if raw_url.endswith(".apk"):
            assert seed_type in {None, "apk_url"}
            return "apk"
        if metadata and metadata.get("content_type") == "application/json":
            return "config"
        return None

    def _apply_queue_candidate(candidate: dict[str, object]) -> int:
        queued.append(candidate)
        return -1 if str(candidate.get("raw_url")).endswith("config.json") else 1

    total = queue_discovered_artifact_candidates(
        source_rows,
        last_iteration=4,
        parallel_workers=3,
        classify_artifact_type=_classify,
        apply_queue_candidate=_apply_queue_candidate,
        run_inprocess_batch=_run_batch,
        run_ordered_inprocess_apply_batch=_run_apply,
        progress_callback=lambda *_args, **_kwargs: None,
        log=lambda label, message: logs.append((label, message)),
        derive_reduction_progress_label=lambda label: f"{label} reduce" if label else None,
        derive_apply_progress_label=lambda label: f"{label} apply" if label else None,
    )

    assert total == 1
    assert [item["raw_url"] for item in queued] == [
        "https://downloads.acme.example/app.apk",
        "https://cdn.acme.example/config.json",
    ]
    assert logs == [
        ("4.K2 artifact source prep", "[dim]parallel parse x3[/dim]"),
        ("4.K2 artifact source prep reduce", "[dim]parallel parse x3[/dim]"),
        ("4.K2 artifact classify", "[dim]parallel parse x3[/dim]"),
        ("4.K2 artifact classify reduce", "[dim]parallel parse x3[/dim]"),
    ]
    assert events[0][2]["progress_label"] == "4.K2 artifact source prep"
    assert events[1][2]["progress_label"] == "4.K2 artifact source prep reduce"
    assert events[2][2]["order_note"] == "artifact source order preserved"
    assert events[3][2]["progress_label"] == "4.K2 artifact classify"
    assert events[4][2]["progress_label"] == "4.K2 artifact classify reduce"
    assert events[5][2]["order_note"] == "artifact candidate order preserved"
    assert events[6][2]["order_note"] == "artifact queue write order preserved"
    assert events[7][2]["progress_label"] == "4.K2 artifact queue total apply"


def test_sweep_completed_artifact_metadata_updates_completed_local_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "artifact-metadata.db"
    artifact_path = tmp_path / "app.apk"
    missing_path = tmp_path / "missing.apk"
    none_path = tmp_path / "unknown.bin"
    artifact_path.write_text("artifact", encoding="utf-8")
    none_path.write_text("unknown", encoding="utf-8")
    con = sqlite3.connect(db_path)
    con.execute(
        """
        CREATE TABLE artifact_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            local_path TEXT,
            status TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        )
        """
    )
    con.executemany(
        """
        INSERT INTO artifact_queue (engagement_id, local_path, status, metadata_json)
        VALUES (?, ?, ?, '{}')
        """,
        [
            (7, artifact_path.as_posix(), "completed"),
            (7, missing_path.as_posix(), "completed"),
            (7, none_path.as_posix(), "completed"),
            (7, artifact_path.as_posix(), "queued"),
            (8, artifact_path.as_posix(), "completed"),
        ],
    )
    con.commit()
    con.close()

    logs: list[tuple[str, str]] = []

    class _Metadata:
        def as_dict(self) -> dict[str, object]:
            return {"kind": "apk", "size": 8}

    def _parse(path: Path) -> object | None:
        if path == artifact_path:
            return _Metadata()
        return None

    parsed = sweep_completed_artifact_metadata(
        db_path,
        7,
        connect=sqlite3.connect,
        parse_artifact=_parse,
        log=lambda label, message: logs.append((label, message)),
    )

    assert parsed == 1
    assert logs == [("artifact parse", "[green]1 artifact(s) metadata extracted[/green]")]
    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            "SELECT engagement_id, status, metadata_json FROM artifact_queue ORDER BY id"
        ).fetchall()
    finally:
        con.close()
    assert json.loads(rows[0][2]) == {"kind": "apk", "size": 8}
    assert rows[1][2] == "{}"
    assert rows[2][2] == "{}"
    assert rows[3][2] == "{}"
    assert rows[4][2] == "{}"


def test_sweep_completed_artifact_metadata_is_best_effort(tmp_path: Path) -> None:
    debug_events: list[tuple[str, object]] = []

    def _connect(_db_path: Path) -> sqlite3.Connection:
        raise sqlite3.OperationalError("locked")

    parsed = sweep_completed_artifact_metadata(
        tmp_path / "missing.db",
        7,
        connect=_connect,
        parse_artifact=lambda _path: None,
        debug=lambda message, value: debug_events.append((message, value)),
    )

    assert parsed == 0
    assert debug_events
    assert debug_events[0][0] == "artifact parser sweep skipped: %s"
    assert isinstance(debug_events[0][1], sqlite3.OperationalError)


def test_queue_artifact_candidate_inserts_and_upserts_crawl_seed_callback(tmp_path: Path) -> None:
    db_path = tmp_path / "artifact-candidates.db"
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    seed_callbacks: list[tuple[str, str, dict[str, Any]]] = []
    try:
        con.execute(
            """
            CREATE TABLE artifact_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                source_url TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                discovered_from TEXT NOT NULL,
                status TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                queued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (engagement_id, source_url)
            )
            """
        )
        candidate = {
            "raw_url": "https://downloads.acme.example/mobile/app.xapk",
            "artifact_type": "apk",
            "discovered_from": "crawl_results",
            "metadata": {"source": "crawl", "depth": 1},
        }

        def _seed_upsert(seed_value: str, seed_type: str, metadata: dict[str, Any]) -> None:
            seed_callbacks.append((seed_value, seed_type, metadata))

        assert (
            queue_artifact_candidate(
                con,
                1001,
                candidate,
                crawl_seed_upsert=_seed_upsert,
                mobile_bundle_url_checker=lambda value: value.endswith(".xapk"),
            )
            == 1
        )
        assert (
            queue_artifact_candidate(
                con,
                1001,
                candidate,
                crawl_seed_upsert=_seed_upsert,
                mobile_bundle_url_checker=lambda value: value.endswith(".xapk"),
            )
            == 0
        )

        row = con.execute("SELECT * FROM artifact_queue WHERE engagement_id=1001").fetchone()
        assert str(row["source_url"]) == "https://downloads.acme.example/mobile/app.xapk"
        assert str(row["artifact_type"]) == "apk"
        assert str(row["discovered_from"]) == "crawl_results"
        assert str(row["status"]) == "queued"
        assert json.loads(str(row["metadata_json"])) == {"depth": 1, "source": "crawl"}
        assert seed_callbacks == [
            (
                "https://downloads.acme.example/mobile/app.xapk",
                "apk_url",
                {"source": "crawl", "depth": 1},
            )
        ]
    finally:
        con.close()


def test_queue_artifact_candidate_reports_db_halt_on_missing_queue_table() -> None:
    con = sqlite3.connect(":memory:")
    try:
        assert (
            queue_artifact_candidate(
                con,
                1001,
                {
                    "raw_url": "https://downloads.acme.example/config.json",
                    "artifact_type": "config",
                    "discovered_from": "engagement_seed",
                    "metadata": {},
                },
            )
            == -1
        )
    finally:
        con.close()


def test_artifact_queue_dispatch_entry_builds_local_work_decision(tmp_path: Path) -> None:
    artifact_path = tmp_path / "config.json"
    artifact_path.write_text("{}", encoding="utf-8")

    dispatch = artifact_queue_dispatch_entry(
        index=2,
        artifact_id=17,
        artifact_type="config",
        source_url=artifact_path.as_posix(),
        local_path=artifact_path.as_posix(),
        resolve_local_path=lambda local_path, _source_url: Path(local_path),
        classify_artifact=lambda path: "json-config" if path == artifact_path else None,
    )

    assert isinstance(dispatch, ArtifactQueueDispatchEntry)
    assert dispatch == ArtifactQueueDispatchEntry(
        index=2,
        artifact_id=17,
        source_url=artifact_path.as_posix(),
        artifact_type="json-config",
        path=artifact_path,
    )


def test_artifact_queue_dispatch_entry_builds_remote_download_decision() -> None:
    dispatch = artifact_queue_dispatch_entry(
        index=1,
        artifact_id=9,
        artifact_type="apk",
        source_url="https://downloads.acme.example/app.apk",
        local_path="",
        resolve_local_path=lambda _local_path, _source_url: None,
        classify_artifact=lambda _path: None,
    )

    assert dispatch.path is None
    assert dispatch.download_requested is True
    assert dispatch.skipped_reason == ""
    assert dispatch.artifact_id == 9
    assert dispatch.artifact_type == "apk"


def test_artifact_queue_dispatch_entry_marks_nonlocal_nonremote_pending() -> None:
    dispatch = artifact_queue_dispatch_entry(
        index=0,
        artifact_id=4,
        artifact_type="config",
        source_url="artifact://queue/4",
        local_path="",
        resolve_local_path=lambda _local_path, _source_url: None,
        classify_artifact=lambda _path: "ignored",
    )

    assert dispatch.download_requested is False
    assert dispatch.path is None
    assert dispatch.skipped_reason == "remote acquisition pending"


def test_artifact_queue_dispatch_result_from_row_shapes_work_units(tmp_path: Path) -> None:
    artifact_path = tmp_path / "config.json"
    artifact_path.write_text("{}", encoding="utf-8")

    local_result = artifact_queue_dispatch_result_from_row(
        (
            2,
            {
                "id": 17,
                "artifact_type": "config",
                "source_url": artifact_path.as_posix(),
                "local_path": artifact_path.as_posix(),
            },
        ),
        resolve_local_path=lambda local_path, _source_url: Path(local_path),
        classify_artifact=lambda path: "json-config" if path == artifact_path else None,
    )
    remote_result = artifact_queue_dispatch_result_from_row(
        (
            1,
            {
                "id": 9,
                "artifact_type": "apk",
                "source_url": "https://downloads.acme.example/app.apk",
                "local_path": "",
            },
        ),
        resolve_local_path=lambda _local_path, _source_url: None,
        classify_artifact=lambda _path: None,
    )
    skipped_result = artifact_queue_dispatch_result_from_row(
        (
            0,
            {
                "id": 4,
                "artifact_type": "config",
                "source_url": "artifact://queue/4",
                "local_path": "",
            },
        ),
        resolve_local_path=lambda _local_path, _source_url: None,
        classify_artifact=lambda _path: "ignored",
    )

    assert local_result == (
        2,
        ArtifactWorkItem(
            artifact_id=17,
            source_url=artifact_path.as_posix(),
            artifact_type="json-config",
            path=artifact_path,
        ),
        None,
        None,
    )
    assert remote_result == (
        1,
        None,
        ArtifactDownloadRequest(
            artifact_id=9,
            source_url="https://downloads.acme.example/app.apk",
            artifact_type="apk",
        ),
        None,
    )
    assert skipped_result == (0, None, None, (4, "remote acquisition pending"))


def test_artifact_queue_dispatch_actions_preserve_order_and_shapes(tmp_path: Path) -> None:
    local_path = tmp_path / "config.json"
    local_path.write_text("{}", encoding="utf-8")
    ready_item = ArtifactWorkItem(
        artifact_id=17,
        source_url=local_path.as_posix(),
        artifact_type="config",
        path=local_path,
    )
    remote_request = ArtifactDownloadRequest(
        artifact_id=18,
        source_url="https://downloads.acme.example/app.apk",
        artifact_type="apk",
    )

    def _dispatch_one(item: str) -> object:
        if item == "local":
            return 2, ready_item, None, None
        if item == "remote":
            return 5, None, remote_request, None
        if item == "skipped":
            return 7, None, None, (19, "remote acquisition pending")
        if item == "typed":
            return ArtifactQueueDispatchAction(
                index=11,
                skipped_row=(20, "scope denied"),
            )
        return "not-a-dispatch-entry"

    actions = artifact_queue_dispatch_actions(
        ["local", "remote", "skipped", "bad", "typed"],
        run_ordered_batch=_run_ordered_batch,
        dispatch_one=_dispatch_one,
    )

    assert actions == [
        ArtifactQueueDispatchAction(index=2, ready_item=ready_item),
        ArtifactQueueDispatchAction(index=5, remote_request=remote_request),
        ArtifactQueueDispatchAction(index=7, skipped_row=(19, "remote acquisition pending")),
        ArtifactQueueDispatchAction(index=11, skipped_row=(20, "scope denied")),
    ]
    assert artifact_queue_dispatch_action("not-a-tuple") is None
    assert artifact_queue_dispatch_action(("bad-index", None, None, None)) is None


def test_artifact_queue_process_plan_applies_dispatch_state(tmp_path: Path) -> None:
    local_path = tmp_path / "config.json"
    local_path.write_text("{}", encoding="utf-8")
    ready_item = ArtifactWorkItem(
        artifact_id=17,
        source_url=local_path.as_posix(),
        artifact_type="config",
        path=local_path,
    )
    remote_request = ArtifactDownloadRequest(
        artifact_id=18,
        source_url="https://downloads.acme.example/app.apk",
        artifact_type="apk",
    )

    plan = artifact_queue_process_plan(
        4,
        dispatch_actions=[
            ArtifactQueueDispatchAction(index=1, ready_item=ready_item),
            ArtifactQueueDispatchAction(index=2, remote_request=remote_request),
            ArtifactQueueDispatchAction(index=3, skipped_row=(19, "remote acquisition pending")),
        ],
    )

    assert isinstance(plan, ArtifactQueueProcessPlan)
    assert plan.ready_slots == [None, ready_item, None, None]
    assert plan.ready_items == [ready_item]
    assert plan.remote_requests == [(2, remote_request)]
    assert plan.skipped_rows == [(19, "remote acquisition pending")]


def test_process_artifact_queue_dispatch_stage_builds_initial_plan(
    tmp_path: Path,
) -> None:
    local_path = tmp_path / "config.json"
    local_path.write_text("{}", encoding="utf-8")
    ready_item = ArtifactWorkItem(
        artifact_id=17,
        source_url=local_path.as_posix(),
        artifact_type="config",
        path=local_path,
    )
    remote_request = ArtifactDownloadRequest(
        artifact_id=18,
        source_url="https://downloads.acme.example/app.apk",
        artifact_type="apk",
    )

    def _dispatch_one(item: tuple[int, str]) -> object:
        index, value = item
        if value == "local":
            return index, ready_item, None, None
        if value == "remote":
            return index, None, remote_request, None
        return index, None, None, (19, "remote acquisition pending")

    result = process_artifact_queue_dispatch_stage(
        ["local", "remote", "skipped"],
        run_ordered_batch=_run_ordered_batch,
        dispatch_one=_dispatch_one,
    )

    assert result == ArtifactQueueDispatchStageResult(
        process_plan=ArtifactQueueProcessPlan(
            ready_slots=[ready_item, None, None],
            remote_requests=[(1, remote_request)],
            skipped_rows=[(19, "remote acquisition pending")],
        )
    )


def test_artifact_queue_reconciled_process_plan_applies_remote_state(
    tmp_path: Path,
) -> None:
    local_path = tmp_path / "local.json"
    local_path.write_text("{}", encoding="utf-8")
    remote_path = tmp_path / "remote.json"
    remote_path.write_text("{}", encoding="utf-8")
    local_ready = ArtifactWorkItem(
        artifact_id=17,
        source_url=local_path.as_posix(),
        artifact_type="config",
        path=local_path,
    )
    remote_ready = ArtifactWorkItem(
        artifact_id=20,
        source_url="https://downloads.acme.example/remote.json",
        artifact_type="config",
        path=remote_path,
    )
    remote_request = ArtifactDownloadRequest(
        artifact_id=20,
        source_url="https://downloads.acme.example/remote.json",
        artifact_type="config",
    )
    process_plan = artifact_queue_process_plan(
        5,
        dispatch_actions=[
            ArtifactQueueDispatchAction(index=0, ready_item=local_ready),
            ArtifactQueueDispatchAction(index=1, remote_request=remote_request),
            ArtifactQueueDispatchAction(index=2, skipped_row=(18, "remote acquisition pending")),
        ],
    )

    reconciled_plan = artifact_queue_reconciled_process_plan(
        process_plan,
        reconciliation_actions=[
            ArtifactRemoteDownloadReconciliationAction(
                index=3,
                failed_row=(19, "remote acquisition failed: HTTPError"),
            ),
            ArtifactRemoteDownloadReconciliationAction(
                index=1,
                local_path_update=(20, remote_path, "config", {"etag": "abc"}),
                ready_item=remote_ready,
            ),
            ArtifactRemoteDownloadReconciliationAction(
                index=4,
                skipped_row=(21, "scope_manifest_denied_remote_artifact"),
            ),
        ],
    )

    assert reconciled_plan.ready_slots == [local_ready, remote_ready, None, None, None]
    assert reconciled_plan.ready_items == [local_ready, remote_ready]
    assert reconciled_plan.remote_requests == [(1, remote_request)]
    assert reconciled_plan.skipped_rows == [
        (18, "remote acquisition pending"),
        (21, "scope_manifest_denied_remote_artifact"),
    ]
    assert reconciled_plan.reconciliation_writes == [
        ArtifactQueueReconciliationWriteAction(
            failed_row=(19, "remote acquisition failed: HTTPError")
        ),
        ArtifactQueueReconciliationWriteAction(
            local_path_update=(20, remote_path, "config", {"etag": "abc"})
        ),
    ]
    assert process_plan.ready_slots == [local_ready, None, None, None, None]


def test_apply_artifact_queue_reconciliation_writes_preserves_order(
    tmp_path: Path,
) -> None:
    local_path = tmp_path / "downloaded.env"
    local_path.write_text("CONTACT=owner@acme.example\n", encoding="utf-8")
    calls: list[tuple[Any, ...]] = []

    result = apply_artifact_queue_reconciliation_writes(
        [
            ArtifactQueueReconciliationWriteAction(
                failed_row=(19, "remote acquisition failed: HTTPError")
            ),
            ArtifactQueueReconciliationWriteAction(
                local_path_update=(20, local_path, "config", {"etag": "abc"})
            ),
            ArtifactQueueReconciliationWriteAction(),
        ],
        update_artifact_status=lambda artifact_id, status, notes: calls.append(
            ("status", artifact_id, status, notes)
        ),
        set_artifact_local_path=(
            lambda artifact_id, path, artifact_type, metadata_extra: calls.append(
                ("local_path", artifact_id, path, artifact_type, metadata_extra)
            )
        ),
    )

    assert result == ArtifactQueueReconciliationApplyResult(failed_delta=1)
    assert calls == [
        ("status", 19, "failed", "remote acquisition failed: HTTPError"),
        ("local_path", 20, local_path, "config", {"etag": "abc"}),
    ]


def test_process_artifact_queue_remote_stage_reconciles_and_applies_writes(
    tmp_path: Path,
) -> None:
    ok_path = tmp_path / "downloaded.env"
    ok_path.write_text("CONTACT=owner@acme.example\n", encoding="utf-8")
    ok_request = ArtifactDownloadRequest(
        artifact_id=21,
        source_url="https://downloads.acme.example/ok.env",
        artifact_type="config",
    )
    failed_request = ArtifactDownloadRequest(
        artifact_id=22,
        source_url="https://downloads.acme.example/fail.env",
        artifact_type="config",
    )
    pending_request = ArtifactDownloadRequest(
        artifact_id=23,
        source_url="https://downloads.acme.example/pending.env",
        artifact_type="config",
    )
    process_plan = artifact_queue_process_plan(
        3,
        dispatch_actions=[
            ArtifactQueueDispatchAction(index=0, remote_request=ok_request),
            ArtifactQueueDispatchAction(index=1, remote_request=failed_request),
            ArtifactQueueDispatchAction(index=2, remote_request=pending_request),
        ],
    )
    downloaded_batches: list[list[int]] = []
    reconcile_calls: list[tuple[int, int, int]] = []
    write_calls: list[tuple[Any, ...]] = []

    def _download_remote_artifacts(
        requests: list[ArtifactDownloadRequest],
    ) -> list[ArtifactDownloadResult]:
        downloaded_batches.append([request.artifact_id for request in requests])
        return [
            ArtifactDownloadResult(
                artifact_id=21,
                source_url=ok_request.source_url,
                artifact_type="document",
                path=ok_path,
                metadata_extra={"etag": "abc"},
            ),
            ArtifactDownloadResult(
                artifact_id=22,
                source_url=failed_request.source_url,
                artifact_type="config",
                error="remote acquisition failed: HTTPError",
            ),
            ArtifactDownloadResult(
                artifact_id=23,
                source_url=pending_request.source_url,
                artifact_type="config",
                path=None,
            ),
        ]

    def _reconcile_one(
        item: tuple[int, ArtifactDownloadRequest, ArtifactDownloadResult],
    ) -> ArtifactRemoteDownloadReconciliationAction:
        index, request, result = item
        reconcile_calls.append((index, request.artifact_id, result.artifact_id))
        if result.error:
            return ArtifactRemoteDownloadReconciliationAction(
                index=index,
                failed_row=(request.artifact_id, result.error),
            )
        if result.path is None:
            return ArtifactRemoteDownloadReconciliationAction(
                index=index,
                skipped_row=(request.artifact_id, "remote acquisition pending"),
            )
        return ArtifactRemoteDownloadReconciliationAction(
            index=index,
            local_path_update=(
                request.artifact_id,
                result.path,
                "config",
                result.metadata_extra,
            ),
            ready_item=ArtifactWorkItem(
                artifact_id=request.artifact_id,
                source_url=request.source_url,
                artifact_type="config",
                path=result.path,
            ),
        )

    def _update_artifact_status(artifact_id: int, status: str, notes: str) -> None:
        write_calls.append(("status", artifact_id, status, notes))

    def _set_artifact_local_path(
        artifact_id: int,
        path: Path,
        artifact_type: str,
        metadata_extra: dict[str, Any],
    ) -> None:
        write_calls.append(
            ("local_path", artifact_id, path, artifact_type, metadata_extra)
        )

    result = process_artifact_queue_remote_stage(
        process_plan,
        download_remote_artifacts=_download_remote_artifacts,
        run_ordered_batch=_run_ordered_batch,
        reconcile_one=_reconcile_one,
        update_artifact_status=_update_artifact_status,
        set_artifact_local_path=_set_artifact_local_path,
    )

    assert isinstance(result, ArtifactQueueRemoteStageResult)
    assert result.summary == ArtifactProcessingSummary(failed=1)
    assert downloaded_batches == [[21, 22, 23]]
    assert reconcile_calls == [(0, 21, 21), (1, 22, 22), (2, 23, 23)]
    assert result.process_plan.ready_items == [
        ArtifactWorkItem(
            artifact_id=21,
            source_url=ok_request.source_url,
            artifact_type="config",
            path=ok_path,
        )
    ]
    assert result.process_plan.skipped_rows == [(23, "remote acquisition pending")]
    assert write_calls == [
        ("local_path", 21, ok_path, "config", {"etag": "abc"}),
        ("status", 22, "failed", "remote acquisition failed: HTTPError"),
    ]


def test_process_artifact_queue_acquisition_stage_reconciles_and_marks_skips(
    tmp_path: Path,
) -> None:
    ok_path = tmp_path / "downloaded.env"
    ok_path.write_text("CONTACT=owner@acme.example\n", encoding="utf-8")
    ok_request = ArtifactDownloadRequest(
        artifact_id=21,
        source_url="https://downloads.acme.example/ok.env",
        artifact_type="config",
    )
    failed_request = ArtifactDownloadRequest(
        artifact_id=22,
        source_url="https://downloads.acme.example/fail.env",
        artifact_type="config",
    )
    process_plan = artifact_queue_process_plan(
        3,
        dispatch_actions=[
            ArtifactQueueDispatchAction(index=0, remote_request=ok_request),
            ArtifactQueueDispatchAction(index=1, remote_request=failed_request),
            ArtifactQueueDispatchAction(
                index=2,
                skipped_row=(23, "remote acquisition pending"),
            ),
        ],
    )
    downloaded_batches: list[list[int]] = []
    write_calls: list[tuple[Any, ...]] = []

    def _download_remote_artifacts(
        requests: list[ArtifactDownloadRequest],
    ) -> list[ArtifactDownloadResult]:
        downloaded_batches.append([request.artifact_id for request in requests])
        return [
            ArtifactDownloadResult(
                artifact_id=21,
                source_url=ok_request.source_url,
                artifact_type="config",
                path=ok_path,
                metadata_extra={"etag": "abc"},
            ),
            ArtifactDownloadResult(
                artifact_id=22,
                source_url=failed_request.source_url,
                artifact_type="config",
                error="remote acquisition failed: HTTPError",
            ),
        ]

    def _reconcile_one(
        item: tuple[int, ArtifactDownloadRequest, ArtifactDownloadResult],
    ) -> ArtifactRemoteDownloadReconciliationAction:
        index, request, result = item
        if result.error:
            return ArtifactRemoteDownloadReconciliationAction(
                index=index,
                failed_row=(request.artifact_id, result.error),
            )
        assert result.path is not None
        return ArtifactRemoteDownloadReconciliationAction(
            index=index,
            local_path_update=(
                request.artifact_id,
                result.path,
                "config",
                result.metadata_extra,
            ),
            ready_item=ArtifactWorkItem(
                artifact_id=request.artifact_id,
                source_url=request.source_url,
                artifact_type="config",
                path=result.path,
            ),
        )

    result = process_artifact_queue_acquisition_stage(
        process_plan,
        download_remote_artifacts=_download_remote_artifacts,
        run_ordered_batch=_run_ordered_batch,
        reconcile_one=_reconcile_one,
        update_remote_failure_status=(
            lambda artifact_id, status, notes: write_calls.append(
                ("status", artifact_id, status, notes)
            )
        ),
        set_artifact_local_path=(
            lambda artifact_id, path, artifact_type, metadata_extra: write_calls.append(
                ("local_path", artifact_id, path, artifact_type, metadata_extra)
            )
        ),
        update_skipped_status=(
            lambda artifact_id, status, notes, metadata: write_calls.append(
                ("status", artifact_id, status, notes, metadata)
            )
        ),
    )

    assert result == ArtifactQueueAcquisitionStageResult(
        process_plan=ArtifactQueueProcessPlan(
            ready_slots=[
                ArtifactWorkItem(
                    artifact_id=21,
                    source_url=ok_request.source_url,
                    artifact_type="config",
                    path=ok_path,
                ),
                None,
                None,
            ],
            remote_requests=[(0, ok_request), (1, failed_request)],
            skipped_rows=[(23, "remote acquisition pending")],
            reconciliation_writes=[
                ArtifactQueueReconciliationWriteAction(
                    local_path_update=(21, ok_path, "config", {"etag": "abc"})
                ),
                ArtifactQueueReconciliationWriteAction(
                    failed_row=(22, "remote acquisition failed: HTTPError")
                ),
            ],
        ),
        summary=ArtifactProcessingSummary(failed=1, skipped=1),
    )
    assert downloaded_batches == [[21, 22]]
    assert write_calls == [
        ("local_path", 21, ok_path, "config", {"etag": "abc"}),
        ("status", 22, "failed", "remote acquisition failed: HTTPError"),
        (
            "status",
            23,
            "skipped",
            "remote acquisition pending",
            {
                "skip_status": "skipped",
                "skip_reason": "remote acquisition pending",
            },
        ),
    ]


def test_process_artifact_queue_processing_cycle_commits_before_parse(
    tmp_path: Path,
) -> None:
    local_path = tmp_path / "local.env"
    local_path.write_text("LOCAL=1\n", encoding="utf-8")
    remote_path = tmp_path / "remote.env"
    remote_path.write_text("REMOTE=1\n", encoding="utf-8")
    local_ready = ArtifactWorkItem(
        artifact_id=11,
        source_url=local_path.as_posix(),
        artifact_type="config",
        path=local_path,
    )
    remote_ready = ArtifactWorkItem(
        artifact_id=12,
        source_url="https://downloads.acme.example/remote.env",
        artifact_type="config",
        path=remote_path,
    )
    remote_request = ArtifactDownloadRequest(
        artifact_id=12,
        source_url=remote_ready.source_url,
        artifact_type="config",
    )
    process_plan = artifact_queue_process_plan(
        3,
        dispatch_actions=[
            ArtifactQueueDispatchAction(index=0, ready_item=local_ready),
            ArtifactQueueDispatchAction(index=1, remote_request=remote_request),
            ArtifactQueueDispatchAction(index=2, skipped_row=(13, "remote pending")),
        ],
    )
    events: list[tuple[Any, ...]] = []

    def _download_remote_artifacts(
        requests: list[ArtifactDownloadRequest],
    ) -> list[ArtifactDownloadResult]:
        events.append(("download", [request.artifact_id for request in requests]))
        return [
            ArtifactDownloadResult(
                artifact_id=12,
                source_url=remote_request.source_url,
                artifact_type="config",
                path=remote_path,
                metadata_extra={"etag": "abc"},
            )
        ]

    def _reconcile_one(
        item: tuple[int, ArtifactDownloadRequest, ArtifactDownloadResult],
    ) -> ArtifactRemoteDownloadReconciliationAction:
        index, request, result = item
        assert result.path is not None
        return ArtifactRemoteDownloadReconciliationAction(
            index=index,
            local_path_update=(
                request.artifact_id,
                result.path,
                "config",
                result.metadata_extra,
            ),
            ready_item=remote_ready,
        )

    def _parse_local_artifacts(
        ready_items: list[ArtifactWorkItem],
    ) -> list[ParsedArtifact]:
        assert ("commit",) in events
        events.append(("parse", [item.artifact_id for item in ready_items]))
        return [
            ParsedArtifact(
                artifact_id=item.artifact_id,
                source_url=item.source_url,
                artifact_type=item.artifact_type,
                path=item.path,
            )
            for item in ready_items
        ]

    def _persist_parsed_artifact(
        parsed: ParsedArtifact,
    ) -> tuple[int, int, int, dict[str, Any]]:
        events.append(("persist", parsed.artifact_id))
        return 1, 2, 3, {"artifact_id": parsed.artifact_id}

    result = process_artifact_queue_processing_cycle(
        process_plan,
        download_remote_artifacts=_download_remote_artifacts,
        run_ordered_batch=_run_ordered_batch,
        reconcile_one=_reconcile_one,
        update_remote_failure_status=(
            lambda artifact_id, status, notes: events.append(
                ("remote_status", artifact_id, status, notes)
            )
        ),
        set_artifact_local_path=(
            lambda artifact_id, path, artifact_type, metadata_extra: events.append(
                ("local_path", artifact_id, path, artifact_type, metadata_extra)
            )
        ),
        update_skipped_status=(
            lambda artifact_id, status, notes, metadata: events.append(
                ("skipped_status", artifact_id, status, notes, metadata)
            )
        ),
        commit_after_acquisition=lambda: events.append(("commit",)),
        parse_local_artifacts=_parse_local_artifacts,
        persist_parsed_artifact=_persist_parsed_artifact,
        update_parsed_status=(
            lambda artifact_id, status, notes, metadata: events.append(
                ("parsed_status", artifact_id, status, notes, metadata)
            )
        ),
    )

    assert result == ArtifactQueueProcessingCycleResult(
        process_plan=ArtifactQueueProcessPlan(
            ready_slots=[local_ready, remote_ready, None],
            remote_requests=[(1, remote_request)],
            skipped_rows=[(13, "remote pending")],
            reconciliation_writes=[
                ArtifactQueueReconciliationWriteAction(
                    local_path_update=(12, remote_path, "config", {"etag": "abc"})
                )
            ],
        ),
        summary=ArtifactProcessingSummary(
            processed=2,
            skipped=1,
            firebase_projects=2,
            supabase_configs=4,
            discovered_seeds=6,
        ),
    )
    assert events[:4] == [
        ("download", [12]),
        ("local_path", 12, remote_path, "config", {"etag": "abc"}),
        (
            "skipped_status",
            13,
            "skipped",
            "remote pending",
            {"skip_status": "skipped", "skip_reason": "remote pending"},
        ),
        ("commit",),
    ]
    assert events[4:] == [
        ("parse", [11, 12]),
        ("persist", 11),
        ("persist", 12),
        ("parsed_status", 11, "parsed", "firebase=1 supabase=2 seeds=3", {"artifact_id": 11}),
        ("parsed_status", 12, "parsed", "firebase=1 supabase=2 seeds=3", {"artifact_id": 12}),
    ]


def test_artifact_queue_rows_process_callbacks_from_services_binds_adapters(
    tmp_path: Path,
) -> None:
    context = SimpleNamespace(name="db")
    calls: list[tuple[Any, ...]] = []
    progress_events: list[tuple[str, dict[str, object]]] = []
    progress_label = "1.K3 artifact processing"
    request = ArtifactDownloadRequest(
        artifact_id=7,
        source_url="https://downloads.acme.example/app.apk",
        artifact_type="apk",
    )
    result = ArtifactDownloadResult(
        artifact_id=7,
        source_url=request.source_url,
        artifact_type="apk",
        path=tmp_path / "app.apk",
    )
    ready = ArtifactWorkItem(
        artifact_id=8,
        source_url="file:///config.json",
        artifact_type="config",
        path=tmp_path / "config.json",
    )
    parsed = ParsedArtifact(
        artifact_id=8,
        source_url=ready.source_url,
        artifact_type=ready.artifact_type,
        path=ready.path,
    )

    def _progress_callback(label: str, metrics: dict[str, object]) -> None:
        progress_events.append((label, dict(metrics)))

    def _run_ordered_batch(
        items: list[Any],
        worker: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        calls.append(("run", list(items), default_factory()))
        return [worker(item) for item in items]

    def _dispatch_one(item: Any) -> tuple[str, Any]:
        calls.append(("dispatch", item))
        return "dispatch", item

    def _download_remote_artifacts(
        requests: list[ArtifactDownloadRequest],
        *,
        progress_label: str | None = None,
        progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    ) -> list[ArtifactDownloadResult]:
        calls.append(("download", list(requests), progress_label, progress_callback))
        if progress_callback is not None and progress_label:
            progress_callback(progress_label, {"stage": "download"})
        return [result]

    def _reconcile_one(
        item: tuple[int, ArtifactDownloadRequest, ArtifactDownloadResult],
    ) -> tuple[str, int]:
        calls.append(("reconcile", item[0]))
        return "reconcile", item[0]

    def _update_artifact_status(
        ctx: Any,
        artifact_id: int,
        status: str,
        notes: str,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        calls.append(("status", ctx, artifact_id, status, notes, metadata))

    def _set_artifact_local_path(
        ctx: Any,
        artifact_id: int,
        path: Path,
        *,
        artifact_type: str | None = None,
        metadata_extra: dict[str, Any] | None = None,
    ) -> None:
        calls.append(("local", ctx, artifact_id, path, artifact_type, metadata_extra))

    def _parse_local_artifacts(
        ready_items: list[ArtifactWorkItem],
        *,
        progress_label: str | None = None,
        progress_callback: Callable[[str, dict[str, object]], None] | None = None,
    ) -> list[ParsedArtifact]:
        calls.append(("parse", list(ready_items), progress_label, progress_callback))
        if progress_callback is not None and progress_label:
            progress_callback(progress_label, {"stage": "parse"})
        return [parsed]

    def _persist_parsed_artifact(
        ctx: Any,
        parsed_artifact: ParsedArtifact,
    ) -> tuple[int, int, int, dict[str, Any]]:
        calls.append(("persist", ctx, parsed_artifact.artifact_id))
        return 1, 2, 3, {"parser": "config"}

    def _commit() -> None:
        calls.append(("commit",))

    callbacks = artifact_queue_rows_process_callbacks_from_services(
        context=context,
        run_ordered_batch=_run_ordered_batch,
        dispatch_one=_dispatch_one,
        download_remote_artifacts=_download_remote_artifacts,
        reconcile_one=_reconcile_one,
        update_artifact_status=_update_artifact_status,
        set_artifact_local_path=_set_artifact_local_path,
        parse_local_artifacts=_parse_local_artifacts,
        persist_parsed_artifact=_persist_parsed_artifact,
        commit=_commit,
        progress_label=progress_label,
        progress_callback=_progress_callback,
    )

    assert callbacks.run_ordered_batch(
        ["row"],
        callbacks.dispatch_one,
        default_factory=lambda: "fallback",
    ) == [("dispatch", "row")]
    assert callbacks.download_remote_artifacts([request]) == [result]
    assert callbacks.reconcile_one((5, request, result)) == ("reconcile", 5)
    callbacks.update_remote_failure_status(7, "failed", "boom")
    callbacks.set_artifact_local_path(
        7,
        result.path,
        "apk",
        {"download_filename": "app.apk"},
    )
    callbacks.update_skipped_status(7, "skipped", "pending", {"skip_reason": "pending"})
    callbacks.update_parsed_status(8, "parsed", "ok", {"parser": "config"})
    assert callbacks.parse_local_artifacts([ready]) == [parsed]
    assert callbacks.persist_parsed_artifact(parsed) == (1, 2, 3, {"parser": "config"})
    callbacks.commit_after_acquisition()
    callbacks.commit_after_processing()

    assert ("run", ["row"], "fallback") in calls
    assert ("download", [request], progress_label, _progress_callback) in calls
    assert ("parse", [ready], progress_label, _progress_callback) in calls
    assert ("status", context, 7, "failed", "boom", None) in calls
    assert (
        "local",
        context,
        7,
        result.path,
        "apk",
        {"download_filename": "app.apk"},
    ) in calls
    assert ("status", context, 7, "skipped", "pending", {"skip_reason": "pending"}) in calls
    assert ("status", context, 8, "parsed", "ok", {"parser": "config"}) in calls
    assert ("persist", context, 8) in calls
    assert calls.count(("commit",)) == 2
    assert progress_events == [
        (progress_label, {"stage": "download"}),
        (progress_label, {"stage": "parse"}),
    ]


def test_process_artifact_queue_rows_dispatches_commits_and_parses(
    tmp_path: Path,
) -> None:
    local_path = tmp_path / "local.env"
    local_path.write_text("LOCAL=1\n", encoding="utf-8")
    remote_path = tmp_path / "remote.env"
    remote_path.write_text("REMOTE=1\n", encoding="utf-8")
    local_ready = ArtifactWorkItem(
        artifact_id=31,
        source_url=local_path.as_posix(),
        artifact_type="config",
        path=local_path,
    )
    remote_request = ArtifactDownloadRequest(
        artifact_id=32,
        source_url="https://downloads.acme.example/remote.env",
        artifact_type="config",
    )
    remote_ready = ArtifactWorkItem(
        artifact_id=32,
        source_url=remote_request.source_url,
        artifact_type="config",
        path=remote_path,
    )
    events: list[tuple[Any, ...]] = []

    def _dispatch_one(item: tuple[int, str]) -> object:
        index, row = item
        events.append(("dispatch", index, row))
        if row == "local":
            return index, local_ready, None, None
        if row == "remote":
            return index, None, remote_request, None
        return index, None, None, (33, "remote pending")

    def _download_remote_artifacts(
        requests: list[ArtifactDownloadRequest],
    ) -> list[ArtifactDownloadResult]:
        events.append(("download", [request.artifact_id for request in requests]))
        return [
            ArtifactDownloadResult(
                artifact_id=32,
                source_url=remote_request.source_url,
                artifact_type="config",
                path=remote_path,
                metadata_extra={"etag": "abc"},
            )
        ]

    def _reconcile_one(
        item: tuple[int, ArtifactDownloadRequest, ArtifactDownloadResult],
    ) -> ArtifactRemoteDownloadReconciliationAction:
        index, request, result = item
        assert result.path is not None
        return ArtifactRemoteDownloadReconciliationAction(
            index=index,
            local_path_update=(
                request.artifact_id,
                result.path,
                "config",
                result.metadata_extra,
            ),
            ready_item=remote_ready,
        )

    def _parse_local_artifacts(
        ready_items: list[ArtifactWorkItem],
    ) -> list[ParsedArtifact]:
        assert ("commit_acquisition",) in events
        events.append(("parse", [item.artifact_id for item in ready_items]))
        return [
            ParsedArtifact(
                artifact_id=item.artifact_id,
                source_url=item.source_url,
                artifact_type=item.artifact_type,
                path=item.path,
            )
            for item in ready_items
        ]

    def _persist_parsed_artifact(
        parsed: ParsedArtifact,
    ) -> tuple[int, int, int, dict[str, Any]]:
        events.append(("persist", parsed.artifact_id))
        return 0, 0, 1, {"artifact_id": parsed.artifact_id}

    result = process_artifact_queue_rows(
        ["local", "remote", "skipped"],
        callbacks=ArtifactQueueRowsProcessCallbacks(
            run_ordered_batch=_run_ordered_batch,
            dispatch_one=_dispatch_one,
            download_remote_artifacts=_download_remote_artifacts,
            reconcile_one=_reconcile_one,
            update_remote_failure_status=(
                lambda artifact_id, status, notes: events.append(
                    ("remote_status", artifact_id, status, notes)
                )
            ),
            set_artifact_local_path=(
                lambda artifact_id, path, artifact_type, metadata_extra: events.append(
                    ("local_path", artifact_id, path, artifact_type, metadata_extra)
                )
            ),
            update_skipped_status=(
                lambda artifact_id, status, notes, metadata: events.append(
                    ("skipped_status", artifact_id, status, notes, metadata)
                )
            ),
            commit_after_acquisition=lambda: events.append(("commit_acquisition",)),
            parse_local_artifacts=_parse_local_artifacts,
            persist_parsed_artifact=_persist_parsed_artifact,
            update_parsed_status=(
                lambda artifact_id, status, notes, metadata: events.append(
                    ("parsed_status", artifact_id, status, notes, metadata)
                )
            ),
            commit_after_processing=lambda: events.append(("commit_processing",)),
        ),
    )

    assert result == ArtifactQueueRowsProcessResult(
        process_plan=ArtifactQueueProcessPlan(
            ready_slots=[local_ready, remote_ready, None],
            remote_requests=[(1, remote_request)],
            skipped_rows=[(33, "remote pending")],
            reconciliation_writes=[
                ArtifactQueueReconciliationWriteAction(
                    local_path_update=(32, remote_path, "config", {"etag": "abc"})
                )
            ],
        ),
        summary=ArtifactProcessingSummary(processed=2, skipped=1, discovered_seeds=2),
    )
    assert events == [
        ("dispatch", 0, "local"),
        ("dispatch", 1, "remote"),
        ("dispatch", 2, "skipped"),
        ("download", [32]),
        ("local_path", 32, remote_path, "config", {"etag": "abc"}),
        (
            "skipped_status",
            33,
            "skipped",
            "remote pending",
            {"skip_status": "skipped", "skip_reason": "remote pending"},
        ),
        ("commit_acquisition",),
        ("parse", [31, 32]),
        ("persist", 31),
        ("persist", 32),
        ("parsed_status", 31, "parsed", "firebase=0 supabase=0 seeds=1", {"artifact_id": 31}),
        ("parsed_status", 32, "parsed", "firebase=0 supabase=0 seeds=1", {"artifact_id": 32}),
        ("commit_processing",),
    ]


def test_process_artifact_queue_for_engagement_prepares_processes_and_commits(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "artifact-engagement-process.db"
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    local_path = tmp_path / "local.env"
    local_path.write_text("LOCAL=1\n", encoding="utf-8")
    remote_path = tmp_path / "remote.env"
    remote_path.write_text("REMOTE=1\n", encoding="utf-8")
    remote_request = ArtifactDownloadRequest(
        artifact_id=2,
        source_url="https://downloads.acme.example/remote.env",
        artifact_type="config",
    )
    remote_ready = ArtifactWorkItem(
        artifact_id=2,
        source_url=remote_request.source_url,
        artifact_type="config",
        path=remote_path,
    )
    events: list[tuple[Any, ...]] = []
    try:
        con.execute(
            """
            CREATE TABLE artifact_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                source_url TEXT NOT NULL,
                local_path TEXT,
                artifact_type TEXT NOT NULL,
                status TEXT NOT NULL,
                attempt_count INTEGER DEFAULT 0,
                max_attempts INTEGER DEFAULT 3,
                queued_at TEXT NOT NULL,
                updated_at TEXT
            )
            """
        )
        con.executemany(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, local_path, artifact_type, status, attempt_count, max_attempts, queued_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (1001, local_path.as_posix(), local_path.as_posix(), "config", "downloaded", 0, 3, "2026-08-10 00:00:01"),
                (1001, remote_request.source_url, "", "config", "queued", 0, 3, "2026-08-10 00:00:02"),
                (1001, "https://downloads.acme.example/skipped.env", "", "config", "queued", 0, 3, "2026-08-10 00:00:03"),
                (1002, "https://downloads.other.example/other.env", "", "config", "queued", 0, 3, "2026-08-10 00:00:00"),
            ],
        )

        def _dispatch_one(item: tuple[int, sqlite3.Row]) -> object:
            index, row = item
            assert ("commit_attempts",) in events
            source_url = str(row["source_url"])
            artifact_id = int(row["id"])
            if source_url == local_path.as_posix():
                return (
                    index,
                    ArtifactWorkItem(
                        artifact_id=artifact_id,
                        source_url=source_url,
                        artifact_type="config",
                        path=local_path,
                    ),
                    None,
                    None,
                )
            if source_url == remote_request.source_url:
                return index, None, remote_request, None
            return index, None, None, (artifact_id, "remote pending")

        def _download_remote_artifacts(
            requests: list[ArtifactDownloadRequest],
        ) -> list[ArtifactDownloadResult]:
            events.append(("download", [request.artifact_id for request in requests]))
            return [
                ArtifactDownloadResult(
                    artifact_id=2,
                    source_url=remote_request.source_url,
                    artifact_type="config",
                    path=remote_path,
                    metadata_extra={"etag": "abc"},
                )
            ]

        def _reconcile_one(
            item: tuple[int, ArtifactDownloadRequest, ArtifactDownloadResult],
        ) -> ArtifactRemoteDownloadReconciliationAction:
            index, request, result = item
            assert result.path is not None
            return ArtifactRemoteDownloadReconciliationAction(
                index=index,
                local_path_update=(
                    request.artifact_id,
                    result.path,
                    "config",
                    result.metadata_extra,
                ),
                ready_item=remote_ready,
            )

        def _parse_local_artifacts(
            ready_items: list[ArtifactWorkItem],
        ) -> list[ParsedArtifact]:
            assert ("commit_acquisition",) in events
            events.append(("parse", [item.artifact_id for item in ready_items]))
            return [
                ParsedArtifact(
                    artifact_id=item.artifact_id,
                    source_url=item.source_url,
                    artifact_type=item.artifact_type,
                    path=item.path,
                )
                for item in ready_items
            ]

        result = process_artifact_queue_for_engagement(
            con,
            1001,
            callbacks=ArtifactQueueRowsProcessCallbacks(
                run_ordered_batch=_run_ordered_batch,
                dispatch_one=_dispatch_one,
                download_remote_artifacts=_download_remote_artifacts,
                reconcile_one=_reconcile_one,
                update_remote_failure_status=(
                    lambda artifact_id, status, notes: events.append(
                        ("remote_status", artifact_id, status, notes)
                    )
                ),
                set_artifact_local_path=(
                    lambda artifact_id, path, artifact_type, metadata_extra: events.append(
                        ("local_path", artifact_id, path, artifact_type, metadata_extra)
                    )
                ),
                update_skipped_status=(
                    lambda artifact_id, status, notes, metadata: events.append(
                        ("skipped_status", artifact_id, status, notes, metadata)
                    )
                ),
                commit_after_acquisition=lambda: events.append(("commit_acquisition",)),
                parse_local_artifacts=_parse_local_artifacts,
                persist_parsed_artifact=(
                    lambda parsed: (0, 0, 1, {"artifact_id": parsed.artifact_id})
                ),
                update_parsed_status=(
                    lambda artifact_id, status, notes, metadata: events.append(
                        ("parsed_status", artifact_id, status, notes, metadata)
                    )
                ),
                commit_after_processing=lambda: events.append(("commit_processing",)),
            ),
            commit_after_attempt_mark=lambda: events.append(("commit_attempts",)),
        )

        assert result == ArtifactQueueEngagementProcessResult(
            preparation=ArtifactQueueRowsPreparationResult(
                rows=result.preparation.rows,
                artifact_ids=[1, 2, 3],
            ),
            rows_process=ArtifactQueueRowsProcessResult(
                process_plan=ArtifactQueueProcessPlan(
                    ready_slots=[
                        ArtifactWorkItem(
                            artifact_id=1,
                            source_url=local_path.as_posix(),
                            artifact_type="config",
                            path=local_path,
                        ),
                        remote_ready,
                        None,
                    ],
                    remote_requests=[(1, remote_request)],
                    skipped_rows=[(3, "remote pending")],
                    reconciliation_writes=[
                        ArtifactQueueReconciliationWriteAction(
                            local_path_update=(2, remote_path, "config", {"etag": "abc"})
                        )
                    ],
                ),
                summary=ArtifactProcessingSummary(
                    processed=2,
                    skipped=1,
                    discovered_seeds=2,
                ),
            ),
        )
        assert result.summary == result.rows_process.summary
        assert events[0] == ("commit_attempts",)
        assert events[-1] == ("commit_processing",)
        attempts = {
            int(row["id"]): int(row["attempt_count"])
            for row in con.execute(
                "SELECT id, attempt_count FROM artifact_queue ORDER BY id ASC"
            ).fetchall()
        }
        assert attempts == {1: 1, 2: 1, 3: 1, 4: 0}
    finally:
        con.close()


def test_artifact_queue_skipped_status_actions_shape_metadata() -> None:
    actions = artifact_queue_skipped_status_actions(
        [
            (18, "remote acquisition pending"),
            (21, "scope_manifest_denied_remote_artifact"),
        ]
    )

    assert actions == [
        ArtifactQueueStatusWriteAction(
            artifact_id=18,
            status="skipped",
            notes="remote acquisition pending",
            metadata={
                "skip_status": "skipped",
                "skip_reason": "remote acquisition pending",
            },
            skipped_delta=1,
        ),
        ArtifactQueueStatusWriteAction(
            artifact_id=21,
            status="skipped",
            notes="scope_manifest_denied_remote_artifact",
            metadata={
                "skip_status": "skipped",
                "skip_reason": "scope_manifest_denied_remote_artifact",
            },
            skipped_delta=1,
        ),
    ]


def test_apply_artifact_queue_status_actions_updates_status_and_summary() -> None:
    calls: list[tuple[int, str, str, dict[str, Any] | None]] = []

    def _update_artifact_status(
        artifact_id: int,
        status: str,
        notes: str,
        metadata: dict[str, Any] | None,
    ) -> None:
        calls.append((artifact_id, status, notes, metadata))

    summary = apply_artifact_queue_status_actions(
        [
            ArtifactQueueStatusWriteAction(
                artifact_id=18,
                status="skipped",
                notes="remote acquisition pending",
                metadata={
                    "skip_status": "skipped",
                    "skip_reason": "remote acquisition pending",
                },
                skipped_delta=1,
            ),
            ArtifactQueueStatusWriteAction(
                artifact_id=21,
                status="skipped",
                notes="scope_manifest_denied_remote_artifact",
                metadata={
                    "skip_status": "skipped",
                    "skip_reason": "scope_manifest_denied_remote_artifact",
                },
                skipped_delta=1,
            ),
        ],
        update_artifact_status=_update_artifact_status,
    )

    assert summary == ArtifactProcessingSummary(skipped=2)
    assert calls == [
        (
            18,
            "skipped",
            "remote acquisition pending",
            {
                "skip_status": "skipped",
                "skip_reason": "remote acquisition pending",
            },
        ),
        (
            21,
            "skipped",
            "scope_manifest_denied_remote_artifact",
            {
                "skip_status": "skipped",
                "skip_reason": "scope_manifest_denied_remote_artifact",
            },
        ),
    ]


def test_process_artifact_queue_skipped_stage_updates_status_and_summary() -> None:
    calls: list[tuple[int, str, str, dict[str, Any] | None]] = []

    def _update_artifact_status(
        artifact_id: int,
        status: str,
        notes: str,
        metadata: dict[str, Any] | None,
    ) -> None:
        calls.append((artifact_id, status, notes, metadata))

    result = process_artifact_queue_skipped_stage(
        [
            (18, "remote acquisition pending"),
            (21, "scope_manifest_denied_remote_artifact"),
        ],
        update_artifact_status=_update_artifact_status,
    )

    assert result == ArtifactQueueSkippedStageResult(
        summary=ArtifactProcessingSummary(skipped=2)
    )
    assert calls == [
        (
            18,
            "skipped",
            "remote acquisition pending",
            {
                "skip_status": "skipped",
                "skip_reason": "remote acquisition pending",
            },
        ),
        (
            21,
            "skipped",
            "scope_manifest_denied_remote_artifact",
            {
                "skip_status": "skipped",
                "skip_reason": "scope_manifest_denied_remote_artifact",
            },
        ),
    ]


def test_artifact_remote_download_reconciliation_entry_marks_skip_error() -> None:
    reconciliation = artifact_remote_download_reconciliation_entry(
        index=3,
        artifact_id=19,
        source_url="https://downloads.acme.example/config.json",
        request_artifact_type="config",
        result_artifact_type="config",
        result_path=None,
        result_error="scope_manifest_denied_remote_artifact",
        result_metadata_extra={
            "skip_status": "skipped",
            "skip_reason": "scope_manifest_denied_remote_artifact",
        },
        classify_artifact=lambda _path: "ignored",
    )

    assert isinstance(reconciliation, ArtifactRemoteDownloadReconciliationEntry)
    assert reconciliation == ArtifactRemoteDownloadReconciliationEntry(
        index=3,
        artifact_id=19,
        source_url="https://downloads.acme.example/config.json",
        artifact_type="config",
        skipped_reason="scope_manifest_denied_remote_artifact",
    )


def test_artifact_remote_download_reconciliation_entry_marks_failure_error() -> None:
    reconciliation = artifact_remote_download_reconciliation_entry(
        index=1,
        artifact_id=20,
        source_url="https://downloads.acme.example/config.json",
        request_artifact_type="config",
        result_artifact_type="config",
        result_path=None,
        result_error="remote acquisition failed: HTTPError",
        result_metadata_extra={},
        classify_artifact=lambda _path: "ignored",
    )

    assert reconciliation.failed_error == "remote acquisition failed: HTTPError"
    assert reconciliation.skipped_reason == ""
    assert reconciliation.local_path is None


def test_artifact_remote_download_reconciliation_entry_marks_pending_without_path() -> None:
    reconciliation = artifact_remote_download_reconciliation_entry(
        index=2,
        artifact_id=21,
        source_url="https://downloads.acme.example/config.json",
        request_artifact_type="config",
        result_artifact_type="config",
        result_path=None,
        result_error=None,
        result_metadata_extra={},
        classify_artifact=lambda _path: "ignored",
    )

    assert reconciliation.failed_error == ""
    assert reconciliation.skipped_reason == "remote acquisition pending"
    assert reconciliation.local_path is None


def test_artifact_remote_download_reconciliation_entry_builds_local_update(tmp_path: Path) -> None:
    download_path = tmp_path / "downloaded.bin"
    download_path.write_bytes(b"payload")

    reconciliation = artifact_remote_download_reconciliation_entry(
        index=4,
        artifact_id=22,
        source_url="https://downloads.acme.example/archive.bin",
        request_artifact_type="document",
        result_artifact_type="binary",
        result_path=download_path,
        result_error=None,
        result_metadata_extra={"download_filename": "downloaded.bin"},
        classify_artifact=lambda path: "firmware" if path == download_path else None,
    )

    assert reconciliation == ArtifactRemoteDownloadReconciliationEntry(
        index=4,
        artifact_id=22,
        source_url="https://downloads.acme.example/archive.bin",
        artifact_type="firmware",
        local_path=download_path,
        metadata_extra={"download_filename": "downloaded.bin"},
    )


def test_artifact_remote_download_reconciliation_result_from_item_shapes_work_units(
    tmp_path: Path,
) -> None:
    ok_path = tmp_path / "downloaded.env"
    ok_path.write_text("CONTACT=owner@acme.example\n", encoding="utf-8")
    local_result = artifact_remote_download_reconciliation_result_from_item(
        (
            4,
            ArtifactDownloadRequest(
                artifact_id=21,
                source_url="https://downloads.acme.example/ok.env",
                artifact_type="config",
            ),
            ArtifactDownloadResult(
                artifact_id=21,
                source_url="https://downloads.acme.example/ok.env",
                artifact_type="document",
                path=ok_path,
                metadata_extra={"etag": "abc"},
            ),
        ),
        classify_artifact=lambda path: "config" if path == ok_path else None,
    )
    failed_result = artifact_remote_download_reconciliation_result_from_item(
        (
            8,
            ArtifactDownloadRequest(
                artifact_id=22,
                source_url="https://downloads.acme.example/fail.env",
                artifact_type="config",
            ),
            ArtifactDownloadResult(
                artifact_id=22,
                source_url="https://downloads.acme.example/fail.env",
                artifact_type="config",
                error="remote acquisition failed: HTTPError",
            ),
        ),
        classify_artifact=lambda _path: None,
    )
    skipped_result = artifact_remote_download_reconciliation_result_from_item(
        (
            9,
            ArtifactDownloadRequest(
                artifact_id=23,
                source_url="https://downloads.acme.example/denied.env",
                artifact_type="config",
            ),
            ArtifactDownloadResult(
                artifact_id=23,
                source_url="https://downloads.acme.example/denied.env",
                artifact_type="config",
                error="scope_manifest_denied_remote_artifact",
                metadata_extra={
                    "skip_status": "skipped",
                    "skip_reason": "scope_manifest_denied_remote_artifact",
                },
            ),
        ),
        classify_artifact=lambda _path: None,
    )

    assert local_result == (
        4,
        None,
        None,
        (21, ok_path, "config", {"etag": "abc"}),
        ArtifactWorkItem(
            artifact_id=21,
            source_url="https://downloads.acme.example/ok.env",
            artifact_type="config",
            path=ok_path,
        ),
    )
    assert failed_result == (
        8,
        (22, "remote acquisition failed: HTTPError"),
        None,
        None,
        None,
    )
    assert skipped_result == (
        9,
        None,
        (23, "scope_manifest_denied_remote_artifact"),
        None,
        None,
    )


def test_artifact_remote_download_reconciliation_actions_preserve_order_and_shapes(
    tmp_path: Path,
) -> None:
    ok_path = tmp_path / "ok.env"
    ok_path.write_text("CONTACT=owner@acme.example\n", encoding="utf-8")
    requests = [
        (
            4,
            ArtifactDownloadRequest(
                artifact_id=21,
                source_url="https://downloads.acme.example/ok.env",
                artifact_type="config",
            ),
        ),
        (
            8,
            ArtifactDownloadRequest(
                artifact_id=22,
                source_url="https://downloads.acme.example/fail.env",
                artifact_type="config",
            ),
        ),
        (
            9,
            ArtifactDownloadRequest(
                artifact_id=23,
                source_url="https://downloads.acme.example/pending.env",
                artifact_type="config",
            ),
        ),
    ]
    download_results = [
        ArtifactDownloadResult(
            artifact_id=21,
            source_url="https://downloads.acme.example/ok.env",
            artifact_type="document",
            path=ok_path,
            metadata_extra={"etag": "abc"},
        ),
        ArtifactDownloadResult(
            artifact_id=22,
            source_url="https://downloads.acme.example/fail.env",
            artifact_type="config",
            error="remote acquisition failed: HTTPError",
        ),
        ArtifactDownloadResult(
            artifact_id=23,
            source_url="https://downloads.acme.example/pending.env",
            artifact_type="config",
            path=None,
        ),
    ]

    def _reconcile_one(
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
            classify_artifact=lambda path: "config" if path == ok_path else None,
        )

    actions = artifact_remote_download_reconciliation_actions(
        requests,
        download_results,
        run_ordered_batch=_run_ordered_batch,
        reconcile_one=_reconcile_one,
    )

    assert actions == [
        ArtifactRemoteDownloadReconciliationAction(
            index=4,
            local_path_update=(21, ok_path, "config", {"etag": "abc"}),
            ready_item=ArtifactWorkItem(
                artifact_id=21,
                source_url="https://downloads.acme.example/ok.env",
                artifact_type="config",
                path=ok_path,
            ),
        ),
        ArtifactRemoteDownloadReconciliationAction(
            index=8,
            failed_row=(22, "remote acquisition failed: HTTPError"),
        ),
        ArtifactRemoteDownloadReconciliationAction(
            index=9,
            skipped_row=(23, "remote acquisition pending"),
        ),
    ]
    assert artifact_remote_download_reconciliation_action("not-a-tuple") is None
    assert artifact_remote_download_reconciliation_action(("bad-index", None, None, None, None)) is None


def test_artifact_url_related_seed_entries_promotes_non_provider_hosts_only() -> None:
    def _is_social(hostname: str) -> bool:
        return hostname.endswith("github.com")

    def _is_managed_cloud(hostname: str) -> bool:
        return hostname.endswith("cloudfront.net")

    def _root_domain(hostname: str) -> str:
        parts = hostname.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else ""

    kwargs = {
        "is_social_platform_host": _is_social,
        "is_managed_cloud_provider_host": _is_managed_cloud,
        "normalize_root_domain": _root_domain,
    }
    assert artifact_url_related_seed_entries("Portal.Example.com.", **kwargs) == [
        {"seed_value": "portal.example.com", "seed_type": "subdomain", "confidence": 0.64},
        {"seed_value": "example.com", "seed_type": "domain", "confidence": 0.6},
    ]
    assert artifact_url_related_seed_entries("example.com", **kwargs) == [
        {"seed_value": "example.com", "seed_type": "domain", "confidence": 0.6}
    ]
    assert artifact_url_related_seed_entries("github.com", **kwargs) == []
    assert artifact_url_related_seed_entries("app.cloudfront.net", **kwargs) == []


def test_artifact_url_cloud_asset_entries_dispatches_matcher_families_in_order() -> None:
    calls: list[tuple[str, str, str, str]] = []

    def _family_entry(family: str, *, url: str, hostname: str, source: str) -> list[dict[str, Any]]:
        calls.append((family, url, hostname, source))
        if family == "supabase":
            return [{"asset_type": "supabase", "identifier": "acme"}]
        if family == "gcs":
            return [{"asset_type": "gcs", "identifier": "mirror"}]
        return []

    entries = artifact_url_cloud_asset_entries(
        "https://Acme.Supabase.co/rest/v1",
        source="artifact_url_extract",
        run_ordered_batch=_run_ordered_batch,
        artifact_url_cloud_asset_family_entries=_family_entry,
    )

    assert [call[0] for call in calls] == list(ARTIFACT_URL_CLOUD_ASSET_FAMILIES)
    assert {call[2] for call in calls} == {"acme.supabase.co"}
    assert entries == [
        {"asset_type": "supabase", "identifier": "acme"},
        {"asset_type": "gcs", "identifier": "mirror"},
    ]


def test_artifact_url_cloud_asset_family_entries_maps_provider_families() -> None:
    source = "artifact_url_extract"
    assert _cloud_family("supabase", "https://acme.supabase.co/rest/v1", "acme.supabase.co") == [
        {"asset_type": "supabase", "identifier": "acme", "source": source}
    ]
    assert _cloud_family("firebase", "https://acme.web.app/login", "acme.web.app") == [
        {"asset_type": "firebase", "identifier": "acme", "source": source}
    ]
    assert _cloud_family(
        "managed_hosting",
        "https://us-central1-acme.cloudfunctions.net/run/path",
        "us-central1-acme.cloudfunctions.net",
    ) == [
        {
            "asset_type": "gcp_cloudfunctions",
            "identifier": "https://us-central1-acme.cloudfunctions.net/run/path",
            "source": source,
        }
    ]
    assert _cloud_family("managed_hosting", "https://portal.vercel.app", "portal.vercel.app") == [
        {"asset_type": "vercel", "identifier": "portal", "source": source}
    ]
    assert _cloud_family("aws_s3", "https://ops-bucket.s3.amazonaws.com/report.txt", "ops-bucket.s3.amazonaws.com") == [
        {"asset_type": "aws_s3", "identifier": "ops-bucket", "source": source}
    ]
    assert _cloud_family(
        "do_spaces",
        "https://assets.nyc3.digitaloceanspaces.com/report.txt",
        "assets.nyc3.digitaloceanspaces.com",
    ) == [
        {"asset_type": "do_spaces", "identifier": "nyc3/assets", "source": source}
    ]
    assert _cloud_family("gcs", "https://storage.googleapis.com/mirror-bucket/report.txt", "storage.googleapis.com") == [
        {"asset_type": "gcs", "identifier": "mirror-bucket", "source": source}
    ]
    assert _cloud_family(
        "azure_blob",
        "https://auditblob.blob.core.windows.net/public/report.txt",
        "auditblob.blob.core.windows.net",
    ) == [
        {"asset_type": "azure_blob", "identifier": "auditblob/public", "source": source}
    ]
    assert _cloud_family(
        "azure_blob",
        "https://staticacct.z13.web.core.windows.net/index.html",
        "staticacct.z13.web.core.windows.net",
    ) == [
        {"asset_type": "azure_blob", "identifier": "staticacct/$web", "source": source}
    ]
    assert _cloud_family(
        "azure_key_vault",
        "https://teamvault.vault.azure.net/secrets/API%2DToken",
        "teamvault.vault.azure.net",
    ) == [
        {"asset_type": "azure_key_vault", "identifier": "teamvault/secrets/api-token", "source": source}
    ]
    assert _cloud_family("cloudflare", "https://portal.pages.dev", "portal.pages.dev") == [
        {"asset_type": "cloudflare_pages", "identifier": "portal", "source": source}
    ]
    assert _cloud_family("unknown", "https://example.com", "example.com") == []
