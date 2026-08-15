from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

from forge.orchestration import artifact_processor_runtime as runtime
from forge.orchestration.artifacts import (
    ArtifactDownloadRequest,
    ArtifactDownloadResult,
    ArtifactProcessingSummary,
    ArtifactTextDiscoveryBatch,
    ArtifactTextScanStageResult,
    ArtifactWorkItem,
    ParsedArtifact,
)
from forge.orchestration.artifact_processor_runtime import (
    ArtifactProcessorRuntimeServices,
    artifact_processor_callbacks,
    artifact_processor_callbacks_for_processor,
    artifact_processor_dispatch_entry,
    artifact_processor_local_artifact_metadata,
    artifact_processor_local_artifact_metadata_matches,
    artifact_processor_local_artifact_record,
    artifact_processor_progress_stage_label,
    artifact_cloud_asset_metadata_for_processor,
    artifact_relation_context_for_processor,
    artifact_processor_remote_download_reconciliation_entry,
    artifact_processor_runtime_services,
    artifact_discovery_payloads_for_processor,
    artifact_url_seed_persistence_entry_for_processor,
    artifact_url_seed_family_entry_for_processor,
    artifact_url_related_seed_entries_for_processor,
    artifact_url_social_pivot_entries_for_processor,
    artifact_url_cloud_asset_entries_for_processor,
    artifact_url_cloud_asset_family_entries_for_processor,
    store_social_profile_url_pivots_for_processor,
    store_cloud_assets_from_url_entries_for_processor,
    artifact_social_profile_url_pivot_entry_for_processor,
    artifact_cloud_asset_url_entry_for_processor,
    store_artifact_cloud_asset_reference_for_processor,
    firebase_match_entry_for_processor,
    extract_firebase_from_text_for_processor,
    terraform_state_payload_family_for_processor,
    terraform_state_text_payloads_for_processor,
    terraform_state_structured_payloads_for_processor,
    terraform_state_structured_payload_text_for_processor,
    terraform_block_assignments_for_processor,
    terraform_assignment_line_entry_for_processor,
    iter_terraform_text_blocks_for_processor,
    terraform_structured_candidate_entry_for_processor,
    terraform_text_structured_payload_text_for_processor,
    terraform_text_block_candidate_for_processor,
    digitalocean_spaces_url_from_endpoint_for_processor,
    azure_blob_url_from_parts_for_processor,
    azure_blob_parts_from_composite_name_for_processor,
    iac_resource_azure_blob_candidate_for_processor,
    iac_resource_firebase_candidate_for_processor,
    iac_resource_supabase_candidate_for_processor,
    iac_resource_s3_candidate_for_processor,
    iac_resource_gcs_candidate_for_processor,
    iac_resource_digitalocean_spaces_candidate_for_processor,
    iac_resource_structured_candidates_for_processor,
    terraform_backend_config_candidates_for_processor,
    iter_terragrunt_remote_state_blocks_for_processor,
    terragrunt_remote_state_backend_candidates_for_processor,
    parse_key_value_scalar_for_processor,
    key_value_section_path_for_processor,
    key_value_line_entry_for_processor,
    parse_key_value_entries_for_processor,
    key_value_structured_inputs_for_processor,
    key_value_structured_payload_lines_for_processor,
    key_value_structured_payload_text_for_processor,
    strip_jsonc_comments_for_processor,
    json_document_from_line_for_processor,
    json_documents_from_text_for_processor,
    json_structured_payload_text_for_processor,
    json_document_looks_like_docker_auth_config_for_processor,
    firebaserc_project_ref_url_for_processor,
    firebaserc_structured_payload_text_for_processor,
    observability_structured_document_candidates_for_processor,
    observability_child_candidate_values_for_processor,
    observability_endpoint_jobs_for_processor,
    observability_scheme_candidate_for_processor,
    observability_target_url_candidate_for_processor,
    observability_structured_payload_text_for_processor,
    edge_proxy_structured_payload_text_for_processor,
    edge_proxy_endpoint_url_candidate_for_processor,
    edge_proxy_line_url_candidates_for_processor,
    orchestration_annotation_endpointish_key_for_processor,
    orchestration_endpoint_values_for_processor,
    orchestration_text_values_for_processor,
    kopia_structured_payload_text_for_processor,
    duplicacy_structured_payload_text_for_processor,
    duplicacy_preference_entry_has_hint_for_processor,
    duplicacy_preference_entry_candidates_for_processor,
    duplicacy_storage_url_candidates_for_processor,
    duplicacy_s3_storage_candidates_for_processor,
    duplicacy_bucket_from_storage_url_for_processor,
    borg_repository_candidates_for_processor,
    borg_repository_candidates_from_env_map_for_processor,
    borg_structured_payload_text_for_processor,
    borg_s3_repository_candidates_for_processor,
    borg_bucket_from_repository_url_for_processor,
    borg_network_repository_candidate_for_processor,
    restic_bucket_from_pathish_for_processor,
    restic_repository_candidates_for_processor,
    restic_repository_candidates_from_env_map_for_processor,
    restic_s3_repository_candidates_for_processor,
    yaml_env_candidate_family_for_processor,
    yaml_env_value_candidate_entry_for_processor,
    yaml_managed_hosting_env_entry_for_processor,
    docker_auth_config_auth_entry_candidates_for_processor,
    docker_auth_config_cred_helper_candidates_for_processor,
    docker_auth_config_legacy_entry_candidates_for_processor,
    docker_auth_config_candidates_for_processor,
    docker_auth_entry_principals_for_processor,
    docker_auth_principal_candidate_for_processor,
    docker_auth_principal_from_auth_field_for_processor,
    docker_auth_structured_candidates_from_env_map_for_processor,
    docker_auth_structured_env_entry_candidates_for_processor,
    docker_registry_url_candidate_for_processor,
    env_value_may_hold_docker_auth_for_processor,
    duplicati_target_url_candidates_from_env_map_for_processor,
    duplicati_target_url_candidates_for_processor,
    duplicati_s3_target_candidates_for_processor,
    duplicati_bucket_from_target_url_for_processor,
    duplicati_structured_payload_text_for_processor,
    duplicati_env_map_from_entries_for_processor,
    looks_like_duplicati_payload_hint_for_processor,
    duplicati_nested_option_entries_for_processor,
    ci_text_structured_payload_text_for_processor,
    appveyor_ci_document_candidate_for_processor,
    yaml_mapping_looks_like_appveyor_ci_for_processor,
    gitpod_structured_payload_text_for_processor,
    gitpod_document_structured_candidates_for_processor,
    gitpod_repository_url_candidates_for_processor,
    yaml_gitpod_config_structured_candidates_for_processor,
    yaml_mapping_looks_like_gitpod_config_for_processor,
    iter_bicep_text_blocks_for_processor,
    bicep_block_assignments_for_processor,
    bicep_assignment_line_entry_for_processor,
    bicep_text_structured_payload_text_for_processor,
    bicep_text_block_candidate_for_processor,
    goreleaser_blob_bucket_value_for_processor,
    goreleaser_image_template_values_for_processor,
    goreleaser_scalar_values_for_processor,
    yaml_goreleaser_candidate_values_for_node_for_processor,
    yaml_gitops_repository_child_values_for_processor,
    yaml_gitops_repository_candidates_for_processor,
    yaml_gitops_repository_candidates_from_mapping_for_processor,
    yaml_gitops_repository_values_for_node_for_processor,
    yaml_flux_source_ref_candidates_for_processor,
    yaml_flux_bucket_structured_candidates_for_processor,
    yaml_manifest_looks_like_crossplane_for_processor,
    crossplane_provider_family_for_processor,
    yaml_crossplane_external_name_for_processor,
    yaml_crossplane_cloud_candidates_for_processor,
    yaml_crossplane_structured_candidates_for_processor,
    yaml_kubernetes_object_identifier_for_processor,
    yaml_external_secret_store_refs_for_processor,
    yaml_external_secret_remote_ref_entry_keys_for_processor,
    yaml_external_secret_remote_ref_keys_for_processor,
    yaml_external_secret_provider_candidates_for_processor,
    yaml_external_secret_ref_segment_for_processor,
    yaml_sops_section_entries_for_processor,
    yaml_sops_metadata_entry_candidate_for_processor,
    yaml_sops_metadata_structured_candidates_for_processor,
    yaml_vault_address_candidate_for_processor,
    cloudflare_valid_ref_for_processor,
    cloudflare_uri_candidate_for_processor,
    cloudflare_uri_candidate_entry_for_processor,
    cloudflare_uri_candidate_entries_for_processor,
    yaml_candidate_batch_entries_for_processor,
    yaml_candidate_family_entries_for_processor,
    yaml_candidate_merge_entry_for_processor,
    yaml_cloudflare_structured_marker_flags_for_processor,
    yaml_cloudflare_r2_candidate_ref_for_processor,
    yaml_cloudflare_d1_candidate_ref_for_processor,
    yaml_cloudflare_kv_candidate_ref_for_processor,
    yaml_cloudflare_worker_candidate_ref_for_processor,
    yaml_cloudflare_pages_candidate_ref_for_processor,
    yaml_cloudflare_structured_candidates_for_processor,
    yaml_goreleaser_child_candidate_values_for_processor,
    yaml_goreleaser_child_candidate_values_for_node_for_processor,
    yaml_goreleaser_config_structured_candidates_for_processor,
    yaml_mapping_looks_like_goreleaser_config_for_processor,
    strip_git_repository_suffix_for_processor,
    artifact_text_discovery_family_entry_for_processor,
    artifact_text_direct_url_candidate_for_processor,
    artifact_text_contact_identity_candidates_for_processor,
    artifact_text_app_manifest_family_candidates_for_processor,
    artifact_text_orchestration_manifest_family_candidates_for_processor,
    artifact_text_cloudflare_asset_family_candidates_for_processor,
    artifact_text_aws_cloud_asset_family_candidates_for_processor,
    artifact_text_azure_cloud_asset_family_candidates_for_processor,
    artifact_text_gcp_cloud_asset_family_candidates_for_processor,
    artifact_text_key_pattern_findings_for_processor,
    artifact_text_url_family_candidates_for_processor,
    calendar_contact_identity_line_entry_for_processor,
    calendar_contact_title_line_value_for_processor,
    calendar_contact_identity_value_for_processor,
    clean_calendar_contact_identity_value_for_processor,
    collect_generic_text_discoveries_for_processor,
    collect_generic_text_discovery_batches_for_processor,
    collect_generic_text_discovery_family_for_processor,
    collect_generic_text_discovery_job_result_for_processor,
    data_uri_image_payload_entry_for_processor,
    data_uri_image_structured_payload_text_for_processor,
    data_uri_payload_entry_for_processor,
    data_uri_structured_payload_text_for_processor,
    decode_data_uri_bytes_for_processor,
    download_remote_artifacts_for_processor,
    emit_artifact_processor_stage_progress,
    expand_structured_discovery_jobs_for_processor,
    extract_cloud_config_family_for_processor,
    extract_cloud_configs_from_payload_for_processor,
    extract_cloud_configs_from_payloads_for_processor,
    extract_mobile_bundle_family_for_processor,
    extract_mobile_bundle_text_payloads_for_processor,
    extract_mobile_configs_from_member_bytes_for_processor,
    extract_nested_mobile_bundle_configs_for_processor,
    extract_nested_mobile_configs_from_7z_for_processor,
    extract_nested_mobile_configs_from_member_jobs_for_processor,
    extract_nested_mobile_configs_from_tar_for_processor,
    extract_nested_mobile_configs_from_zip_for_processor,
    extract_text_artifact_stage_for_processor,
    firebase_project_persistence_entry_for_processor,
    generic_text_discovery_job_for_processor,
    iac_text_structured_payload_family_for_processor,
    iac_text_structured_payload_text_for_processor,
    ingest_local_artifacts_for_processor,
    ingest_local_artifacts_with_runtime_services,
    parse_artifact_work_item_for_processor,
    parse_local_artifacts_for_processor,
    nested_mobile_7z_member_entry_for_processor,
    nested_mobile_member_job_for_processor,
    nested_mobile_member_result_entry_for_processor,
    nested_mobile_tar_member_entry_for_processor,
    nested_mobile_zip_member_entry_for_processor,
    payload_cloud_config_job_for_processor,
    payload_cloud_config_result_entry_for_processor,
    persist_generic_text_discovery_batch_for_processor,
    persist_parsed_artifact_for_processor,
    store_generic_text_discoveries_for_processor,
    merge_artifact_relation_context_for_processor,
    process_artifact_queue_for_processor,
    process_artifact_queue_with_runtime_services,
    rebased_mobile_member_config_entry_for_processor,
    rebased_mobile_member_payload_entry_for_processor,
    rebased_mobile_member_project_entry_for_processor,
    run_ordered_local_batch_for_processor,
    scan_mobile_bundle_artifact_for_processor,
    scan_text_artifact_for_processor,
    safe_artifact_relation_context_for_processor,
    store_firebase_projects_for_processor,
    store_supabase_configs_for_processor,
    structured_discovery_jobs_for_payload_for_processor,
    structured_discovery_payload_entry_for_processor,
    structured_discovery_payload_job_for_processor,
    structured_discovery_result_entry_for_processor,
    supabase_config_persistence_entry_for_processor,
)


class _FakeConnection:
    def __init__(self) -> None:
        self.closed = False
        self.commits = 0
        self.row_factory: Any = None

    def commit(self) -> None:
        self.commits += 1

    def close(self) -> None:
        self.closed = True


def _services(calls: list[tuple[Any, ...]] | None = None) -> ArtifactProcessorRuntimeServices:
    call_log = calls if calls is not None else []

    def _run_ordered_batch(
        items: list[Any],
        worker: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        call_log.append(("run", list(items), default_factory()))
        return [worker(item) for item in items]

    def _download_remote_artifacts(*args: Any, **kwargs: Any) -> list[Any]:
        call_log.append(("download", args, kwargs))
        return []

    def _parse_local_artifacts(*args: Any, **kwargs: Any) -> list[Any]:
        call_log.append(("parse", args, kwargs))
        return []

    def _persist_parsed_artifact(_ctx: Any, parsed: ParsedArtifact) -> tuple[int, int, int, dict[str, Any]]:
        call_log.append(("persist", parsed.artifact_id))
        return 1, 0, 0, {}

    return ArtifactProcessorRuntimeServices(
        run_ordered_batch=_run_ordered_batch,
        local_artifact_record=lambda path: ("artifact", "local", {"path": path.as_posix()}),
        local_artifact_metadata_matches=lambda existing, current: existing == current,
        dispatch_one=lambda item: ("dispatch", item),
        download_remote_artifacts=_download_remote_artifacts,
        reconcile_one=lambda item: ("reconcile", item[0]),
        update_artifact_status=lambda *args, **kwargs: call_log.append(("status", args, kwargs)),
        set_artifact_local_path=lambda *args, **kwargs: call_log.append(("local", args, kwargs)),
        parse_local_artifacts=_parse_local_artifacts,
        persist_parsed_artifact=_persist_parsed_artifact,
    )


def test_artifact_processor_runtime_helpers_have_package_exports() -> None:
    import forge.orchestration as orchestration_package

    assert orchestration_package.ArtifactProcessorRuntimeServices is ArtifactProcessorRuntimeServices
    assert orchestration_package.artifact_processor_callbacks is artifact_processor_callbacks
    assert orchestration_package.artifact_processor_callbacks_for_processor is artifact_processor_callbacks_for_processor
    assert orchestration_package.artifact_processor_dispatch_entry is artifact_processor_dispatch_entry
    assert orchestration_package.artifact_processor_local_artifact_metadata is artifact_processor_local_artifact_metadata
    assert (
        orchestration_package.artifact_processor_local_artifact_metadata_matches
        is artifact_processor_local_artifact_metadata_matches
    )
    assert orchestration_package.artifact_processor_local_artifact_record is artifact_processor_local_artifact_record
    assert orchestration_package.artifact_processor_progress_stage_label is artifact_processor_progress_stage_label
    assert orchestration_package.artifact_cloud_asset_metadata_for_processor is artifact_cloud_asset_metadata_for_processor
    assert orchestration_package.artifact_relation_context_for_processor is artifact_relation_context_for_processor
    assert (
        orchestration_package.artifact_processor_remote_download_reconciliation_entry
        is artifact_processor_remote_download_reconciliation_entry
    )
    assert orchestration_package.artifact_processor_runtime_services is artifact_processor_runtime_services
    assert orchestration_package.artifact_discovery_payloads_for_processor is artifact_discovery_payloads_for_processor
    assert (
        orchestration_package.artifact_text_discovery_family_entry_for_processor
        is artifact_text_discovery_family_entry_for_processor
    )
    assert (
        orchestration_package.artifact_text_direct_url_candidate_for_processor
        is artifact_text_direct_url_candidate_for_processor
    )
    assert (
        orchestration_package.artifact_text_key_pattern_findings_for_processor
        is artifact_text_key_pattern_findings_for_processor
    )
    assert (
        orchestration_package.artifact_text_url_family_candidates_for_processor
        is artifact_text_url_family_candidates_for_processor
    )
    assert (
        orchestration_package.artifact_text_contact_identity_candidates_for_processor
        is artifact_text_contact_identity_candidates_for_processor
    )
    assert (
        orchestration_package.artifact_text_app_manifest_family_candidates_for_processor
        is artifact_text_app_manifest_family_candidates_for_processor
    )
    assert (
        orchestration_package.artifact_text_orchestration_manifest_family_candidates_for_processor
        is artifact_text_orchestration_manifest_family_candidates_for_processor
    )
    assert (
        orchestration_package.artifact_text_cloudflare_asset_family_candidates_for_processor
        is artifact_text_cloudflare_asset_family_candidates_for_processor
    )
    assert (
        orchestration_package.artifact_text_aws_cloud_asset_family_candidates_for_processor
        is artifact_text_aws_cloud_asset_family_candidates_for_processor
    )
    assert (
        orchestration_package.artifact_text_azure_cloud_asset_family_candidates_for_processor
        is artifact_text_azure_cloud_asset_family_candidates_for_processor
    )
    assert (
        orchestration_package.artifact_text_gcp_cloud_asset_family_candidates_for_processor
        is artifact_text_gcp_cloud_asset_family_candidates_for_processor
    )
    assert (
        orchestration_package.calendar_contact_identity_line_entry_for_processor
        is calendar_contact_identity_line_entry_for_processor
    )
    assert (
        orchestration_package.calendar_contact_title_line_value_for_processor
        is calendar_contact_title_line_value_for_processor
    )
    assert (
        orchestration_package.calendar_contact_identity_value_for_processor
        is calendar_contact_identity_value_for_processor
    )
    assert (
        orchestration_package.clean_calendar_contact_identity_value_for_processor
        is clean_calendar_contact_identity_value_for_processor
    )
    assert (
        orchestration_package.collect_generic_text_discoveries_for_processor
        is collect_generic_text_discoveries_for_processor
    )
    assert (
        orchestration_package.collect_generic_text_discovery_batches_for_processor
        is collect_generic_text_discovery_batches_for_processor
    )
    assert (
        orchestration_package.collect_generic_text_discovery_family_for_processor
        is collect_generic_text_discovery_family_for_processor
    )
    assert (
        orchestration_package.collect_generic_text_discovery_job_result_for_processor
        is collect_generic_text_discovery_job_result_for_processor
    )
    assert orchestration_package.data_uri_image_payload_entry_for_processor is data_uri_image_payload_entry_for_processor
    assert (
        orchestration_package.data_uri_image_structured_payload_text_for_processor
        is data_uri_image_structured_payload_text_for_processor
    )
    assert orchestration_package.data_uri_payload_entry_for_processor is data_uri_payload_entry_for_processor
    assert (
        orchestration_package.data_uri_structured_payload_text_for_processor
        is data_uri_structured_payload_text_for_processor
    )
    assert orchestration_package.decode_data_uri_bytes_for_processor is decode_data_uri_bytes_for_processor
    assert orchestration_package.download_remote_artifacts_for_processor is download_remote_artifacts_for_processor
    assert orchestration_package.emit_artifact_processor_stage_progress is emit_artifact_processor_stage_progress
    assert (
        orchestration_package.expand_structured_discovery_jobs_for_processor
        is expand_structured_discovery_jobs_for_processor
    )
    assert orchestration_package.extract_cloud_config_family_for_processor is extract_cloud_config_family_for_processor
    assert (
        orchestration_package.extract_cloud_configs_from_payload_for_processor
        is extract_cloud_configs_from_payload_for_processor
    )
    assert (
        orchestration_package.extract_cloud_configs_from_payloads_for_processor
        is extract_cloud_configs_from_payloads_for_processor
    )
    assert (
        orchestration_package.extract_mobile_bundle_family_for_processor
        is extract_mobile_bundle_family_for_processor
    )
    assert (
        orchestration_package.extract_mobile_bundle_text_payloads_for_processor
        is extract_mobile_bundle_text_payloads_for_processor
    )
    assert (
        orchestration_package.extract_mobile_configs_from_member_bytes_for_processor
        is extract_mobile_configs_from_member_bytes_for_processor
    )
    assert (
        orchestration_package.extract_nested_mobile_bundle_configs_for_processor
        is extract_nested_mobile_bundle_configs_for_processor
    )
    assert (
        orchestration_package.extract_nested_mobile_configs_from_7z_for_processor
        is extract_nested_mobile_configs_from_7z_for_processor
    )
    assert (
        orchestration_package.extract_nested_mobile_configs_from_member_jobs_for_processor
        is extract_nested_mobile_configs_from_member_jobs_for_processor
    )
    assert (
        orchestration_package.extract_nested_mobile_configs_from_tar_for_processor
        is extract_nested_mobile_configs_from_tar_for_processor
    )
    assert (
        orchestration_package.extract_nested_mobile_configs_from_zip_for_processor
        is extract_nested_mobile_configs_from_zip_for_processor
    )
    assert orchestration_package.extract_text_artifact_stage_for_processor is extract_text_artifact_stage_for_processor
    assert (
        orchestration_package.iac_text_structured_payload_family_for_processor
        is iac_text_structured_payload_family_for_processor
    )
    assert (
        orchestration_package.iac_text_structured_payload_text_for_processor
        is iac_text_structured_payload_text_for_processor
    )
    assert (
        orchestration_package.firebase_project_persistence_entry_for_processor
        is firebase_project_persistence_entry_for_processor
    )
    assert orchestration_package.generic_text_discovery_job_for_processor is generic_text_discovery_job_for_processor
    assert orchestration_package.ingest_local_artifacts_for_processor is ingest_local_artifacts_for_processor
    assert (
        orchestration_package.ingest_local_artifacts_with_runtime_services
        is ingest_local_artifacts_with_runtime_services
    )
    assert orchestration_package.process_artifact_queue_for_processor is process_artifact_queue_for_processor
    assert (
        orchestration_package.process_artifact_queue_with_runtime_services
        is process_artifact_queue_with_runtime_services
    )
    assert (
        orchestration_package.rebased_mobile_member_config_entry_for_processor
        is rebased_mobile_member_config_entry_for_processor
    )
    assert (
        orchestration_package.rebased_mobile_member_payload_entry_for_processor
        is rebased_mobile_member_payload_entry_for_processor
    )
    assert (
        orchestration_package.rebased_mobile_member_project_entry_for_processor
        is rebased_mobile_member_project_entry_for_processor
    )
    assert orchestration_package.parse_artifact_work_item_for_processor is parse_artifact_work_item_for_processor
    assert orchestration_package.parse_local_artifacts_for_processor is parse_local_artifacts_for_processor
    assert orchestration_package.nested_mobile_7z_member_entry_for_processor is nested_mobile_7z_member_entry_for_processor
    assert orchestration_package.nested_mobile_member_job_for_processor is nested_mobile_member_job_for_processor
    assert (
        orchestration_package.nested_mobile_member_result_entry_for_processor
        is nested_mobile_member_result_entry_for_processor
    )
    assert orchestration_package.nested_mobile_tar_member_entry_for_processor is nested_mobile_tar_member_entry_for_processor
    assert orchestration_package.nested_mobile_zip_member_entry_for_processor is nested_mobile_zip_member_entry_for_processor
    assert orchestration_package.payload_cloud_config_job_for_processor is payload_cloud_config_job_for_processor
    assert (
        orchestration_package.payload_cloud_config_result_entry_for_processor
        is payload_cloud_config_result_entry_for_processor
    )
    assert (
        orchestration_package.persist_generic_text_discovery_batch_for_processor
        is persist_generic_text_discovery_batch_for_processor
    )
    assert orchestration_package.persist_parsed_artifact_for_processor is persist_parsed_artifact_for_processor
    assert orchestration_package.store_generic_text_discoveries_for_processor is store_generic_text_discoveries_for_processor
    assert (
        orchestration_package.artifact_url_seed_persistence_entry_for_processor
        is artifact_url_seed_persistence_entry_for_processor
    )
    assert orchestration_package.artifact_url_seed_family_entry_for_processor is artifact_url_seed_family_entry_for_processor
    assert (
        orchestration_package.artifact_url_related_seed_entries_for_processor
        is artifact_url_related_seed_entries_for_processor
    )
    assert (
        orchestration_package.artifact_url_social_pivot_entries_for_processor
        is artifact_url_social_pivot_entries_for_processor
    )
    assert (
        orchestration_package.artifact_url_cloud_asset_entries_for_processor
        is artifact_url_cloud_asset_entries_for_processor
    )
    assert (
        orchestration_package.artifact_url_cloud_asset_family_entries_for_processor
        is artifact_url_cloud_asset_family_entries_for_processor
    )
    assert orchestration_package.store_social_profile_url_pivots_for_processor is store_social_profile_url_pivots_for_processor
    assert (
        orchestration_package.store_cloud_assets_from_url_entries_for_processor
        is store_cloud_assets_from_url_entries_for_processor
    )
    assert (
        orchestration_package.artifact_social_profile_url_pivot_entry_for_processor
        is artifact_social_profile_url_pivot_entry_for_processor
    )
    assert orchestration_package.artifact_cloud_asset_url_entry_for_processor is artifact_cloud_asset_url_entry_for_processor
    assert (
        orchestration_package.store_artifact_cloud_asset_reference_for_processor
        is store_artifact_cloud_asset_reference_for_processor
    )
    assert orchestration_package.firebase_match_entry_for_processor is firebase_match_entry_for_processor
    assert orchestration_package.extract_firebase_from_text_for_processor is extract_firebase_from_text_for_processor
    assert orchestration_package.terraform_state_payload_family_for_processor is terraform_state_payload_family_for_processor
    assert orchestration_package.terraform_state_text_payloads_for_processor is terraform_state_text_payloads_for_processor
    assert (
        orchestration_package.terraform_state_structured_payloads_for_processor
        is terraform_state_structured_payloads_for_processor
    )
    assert (
        orchestration_package.terraform_state_structured_payload_text_for_processor
        is terraform_state_structured_payload_text_for_processor
    )
    assert orchestration_package.terraform_block_assignments_for_processor is terraform_block_assignments_for_processor
    assert (
        orchestration_package.terraform_assignment_line_entry_for_processor
        is terraform_assignment_line_entry_for_processor
    )
    assert orchestration_package.iter_terraform_text_blocks_for_processor is iter_terraform_text_blocks_for_processor
    assert (
        orchestration_package.terraform_structured_candidate_entry_for_processor
        is terraform_structured_candidate_entry_for_processor
    )
    assert (
        orchestration_package.terraform_text_structured_payload_text_for_processor
        is terraform_text_structured_payload_text_for_processor
    )
    assert orchestration_package.terraform_text_block_candidate_for_processor is terraform_text_block_candidate_for_processor
    assert (
        orchestration_package.digitalocean_spaces_url_from_endpoint_for_processor
        is digitalocean_spaces_url_from_endpoint_for_processor
    )
    assert orchestration_package.azure_blob_url_from_parts_for_processor is azure_blob_url_from_parts_for_processor
    assert (
        orchestration_package.azure_blob_parts_from_composite_name_for_processor
        is azure_blob_parts_from_composite_name_for_processor
    )
    assert orchestration_package.iac_resource_azure_blob_candidate_for_processor is iac_resource_azure_blob_candidate_for_processor
    assert orchestration_package.iac_resource_firebase_candidate_for_processor is iac_resource_firebase_candidate_for_processor
    assert orchestration_package.iac_resource_supabase_candidate_for_processor is iac_resource_supabase_candidate_for_processor
    assert orchestration_package.iac_resource_s3_candidate_for_processor is iac_resource_s3_candidate_for_processor
    assert orchestration_package.iac_resource_gcs_candidate_for_processor is iac_resource_gcs_candidate_for_processor
    assert (
        orchestration_package.iac_resource_digitalocean_spaces_candidate_for_processor
        is iac_resource_digitalocean_spaces_candidate_for_processor
    )
    assert (
        orchestration_package.iac_resource_structured_candidates_for_processor
        is iac_resource_structured_candidates_for_processor
    )
    assert orchestration_package.terraform_backend_config_candidates_for_processor is terraform_backend_config_candidates_for_processor
    assert (
        orchestration_package.iter_terragrunt_remote_state_blocks_for_processor
        is iter_terragrunt_remote_state_blocks_for_processor
    )
    assert (
        orchestration_package.terragrunt_remote_state_backend_candidates_for_processor
        is terragrunt_remote_state_backend_candidates_for_processor
    )
    assert orchestration_package.parse_key_value_scalar_for_processor is parse_key_value_scalar_for_processor
    assert orchestration_package.key_value_section_path_for_processor is key_value_section_path_for_processor
    assert orchestration_package.key_value_line_entry_for_processor is key_value_line_entry_for_processor
    assert orchestration_package.parse_key_value_entries_for_processor is parse_key_value_entries_for_processor
    assert orchestration_package.key_value_structured_inputs_for_processor is key_value_structured_inputs_for_processor
    assert (
        orchestration_package.key_value_structured_payload_lines_for_processor
        is key_value_structured_payload_lines_for_processor
    )
    assert (
        orchestration_package.key_value_structured_payload_text_for_processor
        is key_value_structured_payload_text_for_processor
    )
    assert orchestration_package.strip_jsonc_comments_for_processor is strip_jsonc_comments_for_processor
    assert orchestration_package.json_document_from_line_for_processor is json_document_from_line_for_processor
    assert orchestration_package.json_documents_from_text_for_processor is json_documents_from_text_for_processor
    assert orchestration_package.json_structured_payload_text_for_processor is json_structured_payload_text_for_processor
    assert (
        orchestration_package.json_document_looks_like_docker_auth_config_for_processor
        is json_document_looks_like_docker_auth_config_for_processor
    )
    assert orchestration_package.firebaserc_project_ref_url_for_processor is firebaserc_project_ref_url_for_processor
    assert (
        orchestration_package.firebaserc_structured_payload_text_for_processor
        is firebaserc_structured_payload_text_for_processor
    )
    assert (
        orchestration_package.observability_structured_document_candidates_for_processor
        is observability_structured_document_candidates_for_processor
    )
    assert (
        orchestration_package.observability_child_candidate_values_for_processor
        is observability_child_candidate_values_for_processor
    )
    assert orchestration_package.observability_endpoint_jobs_for_processor is observability_endpoint_jobs_for_processor
    assert (
        orchestration_package.observability_scheme_candidate_for_processor
        is observability_scheme_candidate_for_processor
    )
    assert (
        orchestration_package.observability_target_url_candidate_for_processor
        is observability_target_url_candidate_for_processor
    )
    assert (
        orchestration_package.observability_structured_payload_text_for_processor
        is observability_structured_payload_text_for_processor
    )
    assert orchestration_package.edge_proxy_structured_payload_text_for_processor is edge_proxy_structured_payload_text_for_processor
    assert (
        orchestration_package.edge_proxy_endpoint_url_candidate_for_processor
        is edge_proxy_endpoint_url_candidate_for_processor
    )
    assert (
        orchestration_package.edge_proxy_line_url_candidates_for_processor
        is edge_proxy_line_url_candidates_for_processor
    )
    assert (
        orchestration_package.orchestration_annotation_endpointish_key_for_processor
        is orchestration_annotation_endpointish_key_for_processor
    )
    assert orchestration_package.orchestration_endpoint_values_for_processor is orchestration_endpoint_values_for_processor
    assert orchestration_package.orchestration_text_values_for_processor is orchestration_text_values_for_processor
    assert orchestration_package.kopia_structured_payload_text_for_processor is kopia_structured_payload_text_for_processor
    assert (
        orchestration_package.duplicacy_structured_payload_text_for_processor
        is duplicacy_structured_payload_text_for_processor
    )
    assert (
        orchestration_package.duplicacy_preference_entry_has_hint_for_processor
        is duplicacy_preference_entry_has_hint_for_processor
    )
    assert (
        orchestration_package.duplicacy_preference_entry_candidates_for_processor
        is duplicacy_preference_entry_candidates_for_processor
    )
    assert (
        orchestration_package.duplicacy_storage_url_candidates_for_processor
        is duplicacy_storage_url_candidates_for_processor
    )
    assert (
        orchestration_package.duplicacy_s3_storage_candidates_for_processor
        is duplicacy_s3_storage_candidates_for_processor
    )
    assert (
        orchestration_package.duplicacy_bucket_from_storage_url_for_processor
        is duplicacy_bucket_from_storage_url_for_processor
    )
    assert orchestration_package.borg_repository_candidates_for_processor is borg_repository_candidates_for_processor
    assert (
        orchestration_package.borg_repository_candidates_from_env_map_for_processor
        is borg_repository_candidates_from_env_map_for_processor
    )
    assert orchestration_package.borg_structured_payload_text_for_processor is borg_structured_payload_text_for_processor
    assert orchestration_package.borg_s3_repository_candidates_for_processor is borg_s3_repository_candidates_for_processor
    assert orchestration_package.borg_bucket_from_repository_url_for_processor is borg_bucket_from_repository_url_for_processor
    assert (
        orchestration_package.borg_network_repository_candidate_for_processor
        is borg_network_repository_candidate_for_processor
    )
    assert (
        orchestration_package.restic_repository_candidates_from_env_map_for_processor
        is restic_repository_candidates_from_env_map_for_processor
    )
    assert orchestration_package.restic_repository_candidates_for_processor is restic_repository_candidates_for_processor
    assert (
        orchestration_package.restic_s3_repository_candidates_for_processor
        is restic_s3_repository_candidates_for_processor
    )
    assert orchestration_package.restic_bucket_from_pathish_for_processor is restic_bucket_from_pathish_for_processor
    assert orchestration_package.yaml_env_candidate_family_for_processor is yaml_env_candidate_family_for_processor
    assert orchestration_package.yaml_managed_hosting_env_entry_for_processor is yaml_managed_hosting_env_entry_for_processor
    assert orchestration_package.yaml_env_value_candidate_entry_for_processor is yaml_env_value_candidate_entry_for_processor
    assert orchestration_package.docker_registry_url_candidate_for_processor is docker_registry_url_candidate_for_processor
    assert (
        orchestration_package.docker_auth_principal_candidate_for_processor
        is docker_auth_principal_candidate_for_processor
    )
    assert (
        orchestration_package.docker_auth_principal_from_auth_field_for_processor
        is docker_auth_principal_from_auth_field_for_processor
    )
    assert orchestration_package.docker_auth_entry_principals_for_processor is docker_auth_entry_principals_for_processor
    assert (
        orchestration_package.docker_auth_config_auth_entry_candidates_for_processor
        is docker_auth_config_auth_entry_candidates_for_processor
    )
    assert (
        orchestration_package.docker_auth_config_cred_helper_candidates_for_processor
        is docker_auth_config_cred_helper_candidates_for_processor
    )
    assert (
        orchestration_package.docker_auth_config_legacy_entry_candidates_for_processor
        is docker_auth_config_legacy_entry_candidates_for_processor
    )
    assert (
        orchestration_package.docker_auth_structured_candidates_from_env_map_for_processor
        is docker_auth_structured_candidates_from_env_map_for_processor
    )
    assert (
        orchestration_package.docker_auth_structured_env_entry_candidates_for_processor
        is docker_auth_structured_env_entry_candidates_for_processor
    )
    assert orchestration_package.env_value_may_hold_docker_auth_for_processor is env_value_may_hold_docker_auth_for_processor
    assert orchestration_package.docker_auth_config_candidates_for_processor is docker_auth_config_candidates_for_processor
    assert (
        orchestration_package.duplicati_target_url_candidates_from_env_map_for_processor
        is duplicati_target_url_candidates_from_env_map_for_processor
    )
    assert (
        orchestration_package.duplicati_target_url_candidates_for_processor
        is duplicati_target_url_candidates_for_processor
    )
    assert orchestration_package.duplicati_s3_target_candidates_for_processor is duplicati_s3_target_candidates_for_processor
    assert (
        orchestration_package.duplicati_bucket_from_target_url_for_processor
        is duplicati_bucket_from_target_url_for_processor
    )
    assert (
        orchestration_package.duplicati_structured_payload_text_for_processor
        is duplicati_structured_payload_text_for_processor
    )
    assert (
        orchestration_package.duplicati_env_map_from_entries_for_processor
        is duplicati_env_map_from_entries_for_processor
    )
    assert (
        orchestration_package.looks_like_duplicati_payload_hint_for_processor
        is looks_like_duplicati_payload_hint_for_processor
    )
    assert (
        orchestration_package.duplicati_nested_option_entries_for_processor
        is duplicati_nested_option_entries_for_processor
    )
    assert orchestration_package.ci_text_structured_payload_text_for_processor is ci_text_structured_payload_text_for_processor
    assert orchestration_package.appveyor_ci_document_candidate_for_processor is appveyor_ci_document_candidate_for_processor
    assert (
        orchestration_package.yaml_mapping_looks_like_appveyor_ci_for_processor
        is yaml_mapping_looks_like_appveyor_ci_for_processor
    )
    assert orchestration_package.gitpod_structured_payload_text_for_processor is gitpod_structured_payload_text_for_processor
    assert (
        orchestration_package.gitpod_document_structured_candidates_for_processor
        is gitpod_document_structured_candidates_for_processor
    )
    assert (
        orchestration_package.gitpod_repository_url_candidates_for_processor
        is gitpod_repository_url_candidates_for_processor
    )
    assert (
        orchestration_package.yaml_gitpod_config_structured_candidates_for_processor
        is yaml_gitpod_config_structured_candidates_for_processor
    )
    assert (
        orchestration_package.yaml_mapping_looks_like_gitpod_config_for_processor
        is yaml_mapping_looks_like_gitpod_config_for_processor
    )
    assert orchestration_package.iter_bicep_text_blocks_for_processor is iter_bicep_text_blocks_for_processor
    assert orchestration_package.bicep_block_assignments_for_processor is bicep_block_assignments_for_processor
    assert orchestration_package.bicep_assignment_line_entry_for_processor is bicep_assignment_line_entry_for_processor
    assert (
        orchestration_package.bicep_text_structured_payload_text_for_processor
        is bicep_text_structured_payload_text_for_processor
    )
    assert orchestration_package.bicep_text_block_candidate_for_processor is bicep_text_block_candidate_for_processor
    assert (
        orchestration_package.goreleaser_blob_bucket_value_for_processor
        is goreleaser_blob_bucket_value_for_processor
    )
    assert (
        orchestration_package.goreleaser_image_template_values_for_processor
        is goreleaser_image_template_values_for_processor
    )
    assert orchestration_package.goreleaser_scalar_values_for_processor is goreleaser_scalar_values_for_processor
    assert (
        orchestration_package.yaml_goreleaser_candidate_values_for_node_for_processor
        is yaml_goreleaser_candidate_values_for_node_for_processor
    )
    assert (
        orchestration_package.yaml_gitops_repository_child_values_for_processor
        is yaml_gitops_repository_child_values_for_processor
    )
    assert (
        orchestration_package.yaml_gitops_repository_candidates_for_processor
        is yaml_gitops_repository_candidates_for_processor
    )
    assert (
        orchestration_package.yaml_gitops_repository_candidates_from_mapping_for_processor
        is yaml_gitops_repository_candidates_from_mapping_for_processor
    )
    assert (
        orchestration_package.yaml_gitops_repository_values_for_node_for_processor
        is yaml_gitops_repository_values_for_node_for_processor
    )
    assert (
        orchestration_package.yaml_flux_source_ref_candidates_for_processor
        is yaml_flux_source_ref_candidates_for_processor
    )
    assert (
        orchestration_package.yaml_flux_bucket_structured_candidates_for_processor
        is yaml_flux_bucket_structured_candidates_for_processor
    )
    assert (
        orchestration_package.yaml_manifest_looks_like_crossplane_for_processor
        is yaml_manifest_looks_like_crossplane_for_processor
    )
    assert orchestration_package.crossplane_provider_family_for_processor is crossplane_provider_family_for_processor
    assert (
        orchestration_package.yaml_crossplane_external_name_for_processor
        is yaml_crossplane_external_name_for_processor
    )
    assert (
        orchestration_package.yaml_crossplane_cloud_candidates_for_processor
        is yaml_crossplane_cloud_candidates_for_processor
    )
    assert (
        orchestration_package.yaml_crossplane_structured_candidates_for_processor
        is yaml_crossplane_structured_candidates_for_processor
    )
    assert (
        orchestration_package.yaml_kubernetes_object_identifier_for_processor
        is yaml_kubernetes_object_identifier_for_processor
    )
    assert (
        orchestration_package.yaml_external_secret_store_refs_for_processor
        is yaml_external_secret_store_refs_for_processor
    )
    assert (
        orchestration_package.yaml_external_secret_remote_ref_entry_keys_for_processor
        is yaml_external_secret_remote_ref_entry_keys_for_processor
    )
    assert (
        orchestration_package.yaml_external_secret_remote_ref_keys_for_processor
        is yaml_external_secret_remote_ref_keys_for_processor
    )
    assert (
        orchestration_package.yaml_external_secret_provider_candidates_for_processor
        is yaml_external_secret_provider_candidates_for_processor
    )
    assert (
        orchestration_package.yaml_external_secret_ref_segment_for_processor
        is yaml_external_secret_ref_segment_for_processor
    )
    assert (
        orchestration_package.yaml_sops_section_entries_for_processor
        is yaml_sops_section_entries_for_processor
    )
    assert (
        orchestration_package.yaml_sops_metadata_entry_candidate_for_processor
        is yaml_sops_metadata_entry_candidate_for_processor
    )
    assert (
        orchestration_package.yaml_sops_metadata_structured_candidates_for_processor
        is yaml_sops_metadata_structured_candidates_for_processor
    )
    assert (
        orchestration_package.yaml_vault_address_candidate_for_processor
        is yaml_vault_address_candidate_for_processor
    )
    assert (
        orchestration_package.cloudflare_valid_ref_for_processor
        is cloudflare_valid_ref_for_processor
    )
    assert (
        orchestration_package.cloudflare_uri_candidate_for_processor
        is cloudflare_uri_candidate_for_processor
    )
    assert (
        orchestration_package.cloudflare_uri_candidate_entry_for_processor
        is cloudflare_uri_candidate_entry_for_processor
    )
    assert (
        orchestration_package.cloudflare_uri_candidate_entries_for_processor
        is cloudflare_uri_candidate_entries_for_processor
    )
    assert (
        orchestration_package.yaml_cloudflare_structured_marker_flags_for_processor
        is yaml_cloudflare_structured_marker_flags_for_processor
    )
    assert (
        orchestration_package.yaml_cloudflare_r2_candidate_ref_for_processor
        is yaml_cloudflare_r2_candidate_ref_for_processor
    )
    assert (
        orchestration_package.yaml_cloudflare_d1_candidate_ref_for_processor
        is yaml_cloudflare_d1_candidate_ref_for_processor
    )
    assert (
        orchestration_package.yaml_cloudflare_kv_candidate_ref_for_processor
        is yaml_cloudflare_kv_candidate_ref_for_processor
    )
    assert (
        orchestration_package.yaml_cloudflare_worker_candidate_ref_for_processor
        is yaml_cloudflare_worker_candidate_ref_for_processor
    )
    assert (
        orchestration_package.yaml_cloudflare_pages_candidate_ref_for_processor
        is yaml_cloudflare_pages_candidate_ref_for_processor
    )
    assert (
        orchestration_package.yaml_cloudflare_structured_candidates_for_processor
        is yaml_cloudflare_structured_candidates_for_processor
    )
    assert (
        orchestration_package.yaml_candidate_batch_entries_for_processor
        is yaml_candidate_batch_entries_for_processor
    )
    assert (
        orchestration_package.yaml_candidate_family_entries_for_processor
        is yaml_candidate_family_entries_for_processor
    )
    assert (
        orchestration_package.yaml_candidate_merge_entry_for_processor
        is yaml_candidate_merge_entry_for_processor
    )
    assert (
        orchestration_package.yaml_goreleaser_child_candidate_values_for_processor
        is yaml_goreleaser_child_candidate_values_for_processor
    )
    assert (
        orchestration_package.yaml_goreleaser_child_candidate_values_for_node_for_processor
        is yaml_goreleaser_child_candidate_values_for_node_for_processor
    )
    assert (
        orchestration_package.yaml_goreleaser_config_structured_candidates_for_processor
        is yaml_goreleaser_config_structured_candidates_for_processor
    )
    assert (
        orchestration_package.yaml_mapping_looks_like_goreleaser_config_for_processor
        is yaml_mapping_looks_like_goreleaser_config_for_processor
    )
    assert orchestration_package.strip_git_repository_suffix_for_processor is strip_git_repository_suffix_for_processor
    assert (
        orchestration_package.merge_artifact_relation_context_for_processor
        is merge_artifact_relation_context_for_processor
    )
    assert orchestration_package.run_ordered_local_batch_for_processor is run_ordered_local_batch_for_processor
    assert orchestration_package.safe_artifact_relation_context_for_processor is safe_artifact_relation_context_for_processor
    assert orchestration_package.store_firebase_projects_for_processor is store_firebase_projects_for_processor
    assert orchestration_package.store_supabase_configs_for_processor is store_supabase_configs_for_processor
    assert (
        orchestration_package.structured_discovery_jobs_for_payload_for_processor
        is structured_discovery_jobs_for_payload_for_processor
    )
    assert (
        orchestration_package.structured_discovery_payload_entry_for_processor
        is structured_discovery_payload_entry_for_processor
    )
    assert (
        orchestration_package.structured_discovery_payload_job_for_processor
        is structured_discovery_payload_job_for_processor
    )
    assert (
        orchestration_package.structured_discovery_result_entry_for_processor
        is structured_discovery_result_entry_for_processor
    )
    assert (
        orchestration_package.supabase_config_persistence_entry_for_processor
        is supabase_config_persistence_entry_for_processor
    )
    assert orchestration_package.scan_mobile_bundle_artifact_for_processor is scan_mobile_bundle_artifact_for_processor
    assert orchestration_package.scan_text_artifact_for_processor is scan_text_artifact_for_processor


def test_artifact_processor_runtime_services_binds_adapter_methods(tmp_path: Path) -> None:
    class _Adapter:
        def _run_ordered_local_batch(self, *_args: Any, **_kwargs: Any) -> list[Any]:
            return ["run"]

        def _local_artifact_record(self, path: Path) -> tuple[str, str, dict[str, Any]]:
            return "artifact", "local", {"path": path.as_posix()}

        def _local_artifact_metadata_matches(self, _existing: Any, _current: dict[str, Any]) -> bool:
            return True

        def _artifact_queue_dispatch_entry(self, item: tuple[int, Any]) -> tuple[str, tuple[int, Any]]:
            return "dispatch", item

        def _download_remote_artifacts(self, _requests: list[Any]) -> list[Any]:
            return ["download"]

        def _remote_download_reconciliation_entry(self, item: tuple[int, Any, Any]) -> tuple[str, int]:
            return "reconcile", item[0]

        def _update_artifact_status(self, *_args: Any, **_kwargs: Any) -> str:
            return "status"

        def _set_artifact_local_path(self, *_args: Any, **_kwargs: Any) -> str:
            return "local"

        def _parse_local_artifacts(self, _items: list[Any]) -> list[Any]:
            return ["parse"]

        def _persist_parsed_artifact(self, _ctx: Any, _parsed: Any) -> tuple[int, int, int, dict[str, Any]]:
            return 1, 2, 3, {}

    adapter = _Adapter()
    services = artifact_processor_runtime_services(adapter)

    assert services.run_ordered_batch() == ["run"]
    assert services.local_artifact_record(tmp_path / "artifact.txt") == (
        "artifact",
        "local",
        {"path": (tmp_path / "artifact.txt").as_posix()},
    )
    assert services.local_artifact_metadata_matches({}, {}) is True
    assert services.dispatch_one((1, "row")) == ("dispatch", (1, "row"))
    assert services.download_remote_artifacts([]) == ["download"]
    assert services.reconcile_one((2, "request", "result")) == ("reconcile", 2)
    assert services.update_artifact_status() == "status"
    assert services.set_artifact_local_path() == "local"
    assert services.parse_local_artifacts([]) == ["parse"]
    assert services.persist_parsed_artifact(None, None) == (1, 2, 3, {})


def test_artifact_processor_local_artifact_record_uses_classifier_and_metadata(tmp_path: Path) -> None:
    artifact_path = tmp_path / "evidence.txt"
    artifact_path.write_text("proof", encoding="utf-8")

    class _Adapter:
        def _classify_artifact(self, path: Path) -> str | None:
            return "text" if path.suffix == ".txt" else None

    record = artifact_processor_local_artifact_record(_Adapter(), artifact_path)
    assert record is not None
    source_url, artifact_type, metadata = record

    assert source_url == artifact_path.resolve().as_posix()
    assert artifact_type == "text"
    assert metadata == artifact_processor_local_artifact_metadata(artifact_path)
    assert artifact_processor_local_artifact_metadata_matches(metadata, dict(metadata)) is True
    assert artifact_processor_local_artifact_record(_Adapter(), tmp_path / "skip.bin") is None


def test_artifact_processor_dispatch_entry_builds_local_remote_and_skipped_results(tmp_path: Path) -> None:
    local_path = tmp_path / "artifact.txt"
    local_path.write_text("payload", encoding="utf-8")

    class _Row(dict[str, Any]):
        def __getitem__(self, key: str) -> Any:
            return self.get(key)

    class _Adapter:
        def _resolve_local_path(self, local_path_value: str, _source_url: str) -> Path | None:
            return Path(local_path_value) if local_path_value else None

        def _classify_artifact(self, path: Path) -> str | None:
            return "text" if path.suffix == ".txt" else None

    local_result = artifact_processor_dispatch_entry(
        _Adapter(),
        (
            0,
            _Row(
                id=11,
                artifact_type="",
                source_url=local_path.as_posix(),
                local_path=local_path.as_posix(),
            ),
        ),
    )
    assert local_result is not None
    index, ready_item, remote_request, skipped_row = local_result
    assert index == 0
    assert ready_item is not None
    assert ready_item.artifact_id == 11
    assert ready_item.artifact_type == "text"
    assert ready_item.path == local_path
    assert remote_request is None
    assert skipped_row is None

    remote_result = artifact_processor_dispatch_entry(
        _Adapter(),
        (
            1,
            _Row(
                id=12,
                artifact_type="remote",
                source_url="https://example.test/app.apk",
                local_path="",
            ),
        ),
    )
    assert remote_result is not None
    assert remote_result[0] == 1
    assert remote_result[1] is None
    assert remote_result[2] is not None
    assert remote_result[2].artifact_id == 12
    assert remote_result[3] is None

    skipped_result = artifact_processor_dispatch_entry(
        _Adapter(),
        (
            2,
            _Row(
                id=13,
                artifact_type="local",
                source_url="",
                local_path="",
            ),
        ),
    )
    assert skipped_result == (2, None, None, (13, "remote acquisition pending"))


def test_artifact_processor_remote_download_reconciliation_entry_handles_success_failure_and_skip(
    tmp_path: Path,
) -> None:
    artifact_path = tmp_path / "download.txt"
    artifact_path.write_text("payload", encoding="utf-8")

    class _Adapter:
        def _classify_artifact(self, path: Path) -> str | None:
            return "text" if path.suffix == ".txt" else None

    request = ArtifactDownloadRequest(
        artifact_id=21,
        source_url="https://example.test/download.txt",
        artifact_type="remote",
    )

    success = artifact_processor_remote_download_reconciliation_entry(
        _Adapter(),
        (
            0,
            request,
            ArtifactDownloadResult(
                artifact_id=21,
                source_url=request.source_url,
                artifact_type="remote",
                path=artifact_path,
                metadata_extra={"sha256": "abc"},
            ),
        ),
    )
    assert success is not None
    assert success[0] == 0
    assert success[1] is None
    assert success[2] is None
    assert success[3] == (21, artifact_path, "text", {"sha256": "abc"})
    assert success[4] is not None
    assert success[4].artifact_id == 21
    assert success[4].artifact_type == "text"
    assert success[4].path == artifact_path

    failed = artifact_processor_remote_download_reconciliation_entry(
        _Adapter(),
        (
            1,
            request,
            ArtifactDownloadResult(
                artifact_id=21,
                source_url=request.source_url,
                artifact_type="remote",
                error="timeout",
            ),
        ),
    )
    assert failed == (1, (21, "timeout"), None, None, None)

    skipped = artifact_processor_remote_download_reconciliation_entry(
        _Adapter(),
        (
            2,
            request,
            ArtifactDownloadResult(
                artifact_id=21,
                source_url=request.source_url,
                artifact_type="remote",
                error="out of scope",
                metadata_extra={"skip_status": "skipped", "skip_reason": "scope denied"},
            ),
        ),
    )
    assert skipped == (2, None, (21, "scope denied"), None, None)


def test_parse_local_artifacts_for_processor_binds_worker_and_progress(monkeypatch: Any) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        _max_workers = 4

        def _parse_local_artifact(self, item: Any) -> str:
            return f"parsed:{item}"

    def _parse_batch(
        work_items: list[Any],
        *,
        max_workers: int,
        parse_one: Callable[[Any], Any],
        progress_label: str | None,
        progress_callback: Callable[[str, dict[str, object]], None] | None,
    ) -> list[Any]:
        calls.append((list(work_items), max_workers, parse_one("item"), progress_label, progress_callback))
        return ["parsed"]

    progress_callback = lambda _label, _payload: None
    monkeypatch.setattr(runtime, "parse_local_artifact_batch", _parse_batch)

    assert parse_local_artifacts_for_processor(
        _Adapter(),
        ["item"],  # type: ignore[list-item]
        progress_label="1.K artifact queue",
        progress_callback=progress_callback,
    ) == ["parsed"]
    assert calls == [(["item"], 4, "parsed:item", "1.K artifact queue", progress_callback)]


def test_download_remote_artifacts_for_processor_binds_scope_and_progress(monkeypatch: Any) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        _max_workers = 3

        def _remote_url_scope_checker(self, url: str) -> tuple[bool, str]:
            return True, url

        def _remote_scope_denied_callback(self, request: ArtifactDownloadRequest, reason: str) -> ArtifactDownloadResult:
            return ArtifactDownloadResult(
                artifact_id=request.artifact_id,
                source_url=request.source_url,
                artifact_type=request.artifact_type,
                error=reason,
            )

        def _download_remote_artifact_request(self, request: ArtifactDownloadRequest) -> ArtifactDownloadResult:
            return ArtifactDownloadResult(
                artifact_id=request.artifact_id,
                source_url=request.source_url,
                artifact_type=request.artifact_type,
            )

    def _download_batch(
        requests: list[ArtifactDownloadRequest],
        *,
        max_workers: int,
        remote_url_scope_checker: Callable[[str], tuple[bool, str]],
        remote_scope_denied_callback: Callable[[ArtifactDownloadRequest, str], ArtifactDownloadResult],
        download_one: Callable[[ArtifactDownloadRequest], ArtifactDownloadResult],
        progress_label: str | None,
        progress_callback: Callable[[str, dict[str, object]], None] | None,
    ) -> list[ArtifactDownloadResult]:
        request = requests[0]
        calls.append(
            (
                list(requests),
                max_workers,
                remote_url_scope_checker(request.source_url),
                remote_scope_denied_callback(request, "denied").error,
                download_one(request).artifact_id,
                progress_label,
                progress_callback,
            )
        )
        return [download_one(request)]

    request = ArtifactDownloadRequest(
        artifact_id=31,
        source_url="https://example.test/file.txt",
        artifact_type="remote",
    )
    progress_callback = lambda _label, _payload: None
    monkeypatch.setattr(runtime, "download_remote_artifact_batch", _download_batch)

    result = download_remote_artifacts_for_processor(
        _Adapter(),
        [request],
        progress_label="1.K artifact queue",
        progress_callback=progress_callback,
    )

    assert result[0].artifact_id == 31
    assert calls == [
        (
            [request],
            3,
            (True, request.source_url),
            "denied",
            31,
            "1.K artifact queue",
            progress_callback,
        )
    ]


def test_parse_artifact_work_item_for_processor_binds_scan_callbacks(monkeypatch: Any, tmp_path: Path) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _scan_mobile_bundle_artifact(self, path: Path, artifact_type: str) -> tuple[list[Any], list[Any], list[Any], dict[str, Any]]:
            return [], [], [], {"mobile": f"{path.name}:{artifact_type}"}

        def _scan_text_artifact(self, path: Path, artifact_type: str) -> tuple[list[Any], list[Any], list[Any], dict[str, Any]]:
            return [], [], [], {"text": f"{path.name}:{artifact_type}"}

    def _parse_work_item(
        work_item: ArtifactWorkItem,
        *,
        scan_mobile_bundle_artifact: Callable[..., Any],
        scan_text_artifact: Callable[..., Any],
        artifact_format_label: Callable[[str | Path], str],
    ) -> ParsedArtifact:
        calls.append(
            (
                work_item,
                scan_mobile_bundle_artifact(work_item.path, work_item.artifact_type)[3],
                scan_text_artifact(work_item.path, work_item.artifact_type)[3],
                artifact_format_label(work_item.path),
            )
        )
        return ParsedArtifact(
            artifact_id=work_item.artifact_id,
            source_url=work_item.source_url,
            artifact_type=work_item.artifact_type,
            path=work_item.path,
            parse_metadata={"format": artifact_format_label(work_item.path)},
        )

    artifact_path = tmp_path / "bundle.apk"
    work_item = ArtifactWorkItem(
        artifact_id=41,
        source_url="local://bundle.apk",
        artifact_type="apk",
        path=artifact_path,
    )
    monkeypatch.setattr(runtime, "parse_artifact_work_item", _parse_work_item)

    parsed = parse_artifact_work_item_for_processor(
        _Adapter(),
        work_item,
        artifact_format_label=lambda value: f"format:{Path(value).suffix}",
    )

    assert parsed.artifact_id == 41
    assert parsed.parse_metadata == {"format": "format:.apk"}
    assert calls == [
        (
            work_item,
            {"mobile": "bundle.apk:apk"},
            {"text": "bundle.apk:apk"},
            "format:.apk",
        )
    ]


def test_scan_mobile_bundle_artifact_for_processor_binds_scan_services(monkeypatch: Any, tmp_path: Path) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _run_ordered_local_batch(self, items: list[Any], worker: Callable[[Any], Any], **_kwargs: Any) -> list[Any]:
            return [worker(item) for item in items]

        def _extract_mobile_bundle_family(self, family: str, **kwargs: Any) -> list[str]:
            return [f"family:{family}:{kwargs['artifact_type']}"]

        def _extract_cloud_configs_from_payloads(self, payloads: list[Any]) -> tuple[list[str], list[str]]:
            return [f"firebase:{len(payloads)}"], [f"supabase:{len(payloads)}"]

        def _artifact_payload_summary(self, payloads: list[Any], firebase_projects: list[Any], supabase_configs: list[Any]) -> dict[str, Any]:
            return {
                "payloads": len(payloads),
                "firebase": len(firebase_projects),
                "supabase": len(supabase_configs),
            }

        def _dedupe_firebase_projects(self, projects: list[Any]) -> list[Any]:
            return [f"deduped:{project}" for project in projects]

        def _dedupe_supabase_configs(self, configs: list[Any]) -> list[Any]:
            return [f"deduped:{config}" for config in configs]

    def _scan_mobile(
        path: Path,
        artifact_type: str,
        *,
        run_ordered_batch: Callable[..., list[Any]],
        extract_mobile_bundle_family: Callable[..., list[Any]],
        extract_cloud_configs_from_payloads: Callable[[list[Any]], tuple[list[Any], list[Any]]],
        artifact_payload_summary: Callable[[list[Any], list[Any], list[Any]], dict[str, Any]],
        dedupe_firebase_projects: Callable[[list[Any]], list[Any]],
        dedupe_supabase_configs: Callable[[list[Any]], list[Any]],
    ) -> tuple[list[Any], list[Any], list[Any], dict[str, Any]]:
        family_result = extract_mobile_bundle_family("apk", path=path, artifact_type=artifact_type)
        batch_result = run_ordered_batch(["one"], lambda item: f"batch:{item}")
        firebase_projects, supabase_configs = extract_cloud_configs_from_payloads(family_result)
        deduped_firebase = dedupe_firebase_projects(firebase_projects)
        deduped_supabase = dedupe_supabase_configs(supabase_configs)
        summary = artifact_payload_summary(family_result, deduped_firebase, deduped_supabase)
        calls.append((path, artifact_type, family_result, batch_result, deduped_firebase, deduped_supabase, summary))
        return family_result, deduped_firebase, deduped_supabase, summary

    artifact_path = tmp_path / "app.apk"
    monkeypatch.setattr(runtime, "scan_mobile_bundle_artifact", _scan_mobile)

    result = scan_mobile_bundle_artifact_for_processor(_Adapter(), artifact_path, "apk")

    assert result == (
        ["family:apk:apk"],
        ["deduped:firebase:1"],
        ["deduped:supabase:1"],
        {"payloads": 1, "firebase": 1, "supabase": 1},
    )
    assert calls == [
        (
            artifact_path,
            "apk",
            ["family:apk:apk"],
            ["batch:one"],
            ["deduped:firebase:1"],
            ["deduped:supabase:1"],
            {"payloads": 1, "firebase": 1, "supabase": 1},
        )
    ]


def test_scan_text_artifact_for_processor_binds_scan_services(monkeypatch: Any, tmp_path: Path) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _run_ordered_local_batch(self, items: list[Any], worker: Callable[[Any], Any], **_kwargs: Any) -> list[Any]:
            return [worker(item) for item in items]

        def _extract_text_artifact_stage(self, family: str, **kwargs: Any) -> SimpleNamespace:
            return SimpleNamespace(
                payloads=[(kwargs["path"].name, family, kwargs["artifact_type"])],
                firebase_projects=[],
                supabase_configs=[],
            )

        def _extract_cloud_configs_from_payloads(self, payloads: list[Any]) -> tuple[list[str], list[str]]:
            return [f"firebase:{len(payloads)}"], [f"supabase:{len(payloads)}"]

        def _artifact_payload_summary(self, payloads: list[Any], firebase_projects: list[Any], supabase_configs: list[Any]) -> dict[str, Any]:
            return {
                "payloads": len(payloads),
                "firebase": len(firebase_projects),
                "supabase": len(supabase_configs),
            }

        def _dedupe_firebase_projects(self, projects: list[Any]) -> list[Any]:
            return [f"deduped:{project}" for project in projects]

        def _dedupe_supabase_configs(self, configs: list[Any]) -> list[Any]:
            return [f"deduped:{config}" for config in configs]

    def _scan_text(
        path: Path,
        artifact_type: str,
        *,
        run_ordered_batch: Callable[..., list[Any]],
        extract_text_artifact_stage: Callable[..., Any],
        extract_cloud_configs_from_payloads: Callable[[list[Any]], tuple[list[Any], list[Any]]],
        artifact_payload_summary: Callable[[list[Any], list[Any], list[Any]], dict[str, Any]],
        dedupe_firebase_projects: Callable[[list[Any]], list[Any]],
        dedupe_supabase_configs: Callable[[list[Any]], list[Any]],
    ) -> tuple[list[Any], list[Any], list[Any], dict[str, Any]]:
        stage = extract_text_artifact_stage("text", path=path, artifact_type=artifact_type)
        batch_result = run_ordered_batch(["two"], lambda item: f"batch:{item}")
        firebase_projects, supabase_configs = extract_cloud_configs_from_payloads(stage.payloads)
        deduped_firebase = dedupe_firebase_projects(firebase_projects)
        deduped_supabase = dedupe_supabase_configs(supabase_configs)
        summary = artifact_payload_summary(stage.payloads, deduped_firebase, deduped_supabase)
        calls.append((path, artifact_type, stage.payloads, batch_result, deduped_firebase, deduped_supabase, summary))
        return stage.payloads, deduped_firebase, deduped_supabase, summary

    artifact_path = tmp_path / "notes.txt"
    monkeypatch.setattr(runtime, "scan_text_artifact", _scan_text)

    result = scan_text_artifact_for_processor(_Adapter(), artifact_path, "text")

    assert result == (
        [("notes.txt", "text", "text")],
        ["deduped:firebase:1"],
        ["deduped:supabase:1"],
        {"payloads": 1, "firebase": 1, "supabase": 1},
    )
    assert calls == [
        (
            artifact_path,
            "text",
            [("notes.txt", "text", "text")],
            ["batch:two"],
            ["deduped:firebase:1"],
            ["deduped:supabase:1"],
            {"payloads": 1, "firebase": 1, "supabase": 1},
        )
    ]


def test_extract_mobile_bundle_family_for_processor_binds_extractor_callbacks(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Extractor:
        def extract_apk(self, path: Path) -> list[str]:
            return [f"apk:{path.name}"]

        def extract_supabase_apk(self, path: Path) -> list[str]:
            return [f"supabase-apk:{path.name}"]

        def extract_ipa(self, path: Path) -> list[str]:
            return [f"ipa:{path.name}"]

        def extract_supabase_ipa(self, path: Path) -> list[str]:
            return [f"supabase-ipa:{path.name}"]

    class _Adapter:
        _extractor = _Extractor()

        def _extract_mobile_bundle_text_payloads(self, path: Path) -> list[str]:
            return [f"payload:{path.name}"]

    def _extract_family(
        family: str,
        *,
        path: Path,
        artifact_type: str,
        extract_mobile_bundle_text_payloads: Callable[[Path], list[Any]],
        extract_apk: Callable[[Path], list[Any]],
        extract_supabase_apk: Callable[[Path], list[Any]],
        extract_ipa: Callable[[Path], list[Any]],
        extract_supabase_ipa: Callable[[Path], list[Any]],
    ) -> list[Any]:
        callback_results = {
            "payloads": extract_mobile_bundle_text_payloads(path),
            "apk": extract_apk(path),
            "supabase_apk": extract_supabase_apk(path),
            "ipa": extract_ipa(path),
            "supabase_ipa": extract_supabase_ipa(path),
        }
        calls.append((family, path, artifact_type, callback_results))
        return callback_results[family]

    artifact_path = tmp_path / "app.apk"
    monkeypatch.setattr(runtime, "extract_mobile_bundle_family", _extract_family)

    assert extract_mobile_bundle_family_for_processor(
        _Adapter(),
        "apk",
        path=artifact_path,
        artifact_type="apk",
    ) == ["apk:app.apk"]
    assert calls == [
        (
            "apk",
            artifact_path,
            "apk",
            {
                "payloads": ["payload:app.apk"],
                "apk": ["apk:app.apk"],
                "supabase_apk": ["supabase-apk:app.apk"],
                "ipa": ["ipa:app.apk"],
                "supabase_ipa": ["supabase-ipa:app.apk"],
            },
        )
    ]


def test_extract_text_artifact_stage_for_processor_binds_stage_callbacks(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _extract_text_payloads(self, path: Path) -> list[tuple[str, str, str]]:
            return [(path.name, "body", "payload")]

        def _extract_nested_mobile_bundle_configs(
            self,
            path: Path,
            artifact_type: str,
        ) -> tuple[list[tuple[str, str, str]], list[str], list[str], int]:
            return [(path.name, artifact_type, "nested")], ["firebase"], ["supabase"], 1

    def _artifact_text_stage(
        family: str,
        *,
        path: Path,
        artifact_type: str,
        extract_text_payloads: Callable[[Path], list[tuple[str, str, str]]],
        extract_nested_mobile_bundle_configs: Callable[..., tuple[list[Any], list[Any], list[Any], int]],
    ) -> ArtifactTextScanStageResult:
        text_payloads = extract_text_payloads(path)
        nested_payloads, firebase_projects, supabase_configs, nested_count = extract_nested_mobile_bundle_configs(
            path,
            artifact_type,
        )
        calls.append((family, path, artifact_type, text_payloads, nested_payloads, firebase_projects, supabase_configs, nested_count))
        return ArtifactTextScanStageResult(
            payloads=text_payloads + nested_payloads,
            firebase_projects=firebase_projects,
            supabase_configs=supabase_configs,
            nested_mobile_member_count=nested_count,
        )

    artifact_path = tmp_path / "notes.txt"
    monkeypatch.setattr(runtime, "artifact_text_scan_stage", _artifact_text_stage)

    stage = extract_text_artifact_stage_for_processor(
        _Adapter(),
        "nested_mobile",
        path=artifact_path,
        artifact_type="text",
    )

    assert stage.payloads == [("notes.txt", "body", "payload"), ("notes.txt", "text", "nested")]
    assert stage.firebase_projects == ["firebase"]
    assert stage.supabase_configs == ["supabase"]
    assert stage.nested_mobile_member_count == 1
    assert calls == [
        (
            "nested_mobile",
            artifact_path,
            "text",
            [("notes.txt", "body", "payload")],
            [("notes.txt", "text", "nested")],
            ["firebase"],
            ["supabase"],
            1,
        )
    ]


def test_extract_mobile_bundle_text_payloads_for_processor_binds_archive_callbacks(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _extract_text_payloads_from_zip(self, archive: Any, source: str, *, depth: int) -> list[tuple[str, str, str]]:
            return [(type(archive).__name__, source, f"zip:{depth}")]

        def _extract_text_payloads_from_tar(self, archive: Any, source: str, *, depth: int) -> list[tuple[str, str, str]]:
            return [(type(archive).__name__, source, f"tar:{depth}")]

    def _extract_payloads(
        path: Path,
        *,
        extract_text_payloads_from_zip: Callable[..., list[tuple[str, str, str]]],
        extract_text_payloads_from_tar: Callable[..., list[tuple[str, str, str]]],
    ) -> list[tuple[str, str, str]]:
        zip_result = extract_text_payloads_from_zip(SimpleNamespace(kind="zip"), str(path), depth=1)
        tar_result = extract_text_payloads_from_tar(SimpleNamespace(kind="tar"), str(path), depth=2)
        calls.append((path, zip_result, tar_result))
        return zip_result + tar_result

    artifact_path = tmp_path / "archive.apk"
    monkeypatch.setattr(runtime, "extract_mobile_bundle_text_payloads", _extract_payloads)

    assert extract_mobile_bundle_text_payloads_for_processor(_Adapter(), artifact_path) == [
        ("SimpleNamespace", str(artifact_path), "zip:1"),
        ("SimpleNamespace", str(artifact_path), "tar:2"),
    ]
    assert calls == [
        (
            artifact_path,
            [("SimpleNamespace", str(artifact_path), "zip:1")],
            [("SimpleNamespace", str(artifact_path), "tar:2")],
        )
    ]


def test_run_ordered_local_batch_for_processor_binds_max_workers(monkeypatch: Any) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        _max_workers = 7

    def _run_batch(
        items: list[str],
        worker: Callable[[str], str],
        *,
        default_factory: Callable[[], Any],
        max_workers: int,
    ) -> list[str]:
        calls.append((list(items), worker("item"), default_factory(), max_workers))
        return ["done"]

    monkeypatch.setattr(runtime, "run_ordered_local_artifact_batch", _run_batch)

    assert run_ordered_local_batch_for_processor(
        _Adapter(),
        ["item"],
        lambda item: f"worked:{item}",
        default_factory=list,
    ) == ["done"]
    assert calls == [(["item"], "worked:item", [], 7)]


def test_extract_cloud_configs_from_payloads_for_processor_binds_payload_callbacks(monkeypatch: Any) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _run_ordered_local_batch(
            self,
            items: list[Any],
            worker: Callable[[Any], Any],
            *,
            default_factory: Callable[[], Any],
        ) -> list[Any]:
            calls.append(("batch", list(items), default_factory()))
            return [worker(item) for item in items]

        def _payload_cloud_config_job(self, payload: tuple[str, str, str]) -> tuple[str, str, str] | None:
            return payload if payload[2].strip() else None

        def _extract_cloud_configs_from_payload(
            self,
            source_file: str,
            extract_path: str,
            text: str,
        ) -> tuple[list[str], list[str]]:
            return [f"firebase:{source_file}:{extract_path}:{text}"], [f"supabase:{source_file}:{extract_path}:{text}"]

        def _payload_cloud_config_result_entry(
            self,
            result_batch: tuple[int, tuple[list[str], list[str]] | None],
        ) -> tuple[list[str], list[str]] | None:
            index, result = result_batch
            if result is None:
                return None
            firebase_projects, supabase_configs = result
            return [f"{index}:{value}" for value in firebase_projects], [f"{index}:{value}" for value in supabase_configs]

    def _extract_payloads(
        payloads: list[tuple[str, str, str]],
        *,
        run_ordered_batch: Callable[..., list[Any]],
        payload_cloud_config_job: Callable[[tuple[str, str, str]], tuple[str, str, str] | None],
        extract_cloud_configs_from_payload: Callable[[str, str, str], tuple[list[Any], list[Any]]],
        payload_cloud_config_result_entry: Callable[..., tuple[list[Any], list[Any]] | None],
    ) -> tuple[list[Any], list[Any]]:
        jobs = [
            job
            for job in run_ordered_batch(payloads, payload_cloud_config_job, default_factory=lambda: None)
            if job is not None
        ]
        results = run_ordered_batch(
            jobs,
            lambda job: extract_cloud_configs_from_payload(job[0], job[1], job[2]),
            default_factory=lambda: ([], []),
        )
        entries = run_ordered_batch(
            list(enumerate(results)),
            payload_cloud_config_result_entry,
            default_factory=lambda: None,
        )
        firebase_projects: list[Any] = []
        supabase_configs: list[Any] = []
        for entry in entries:
            if entry is None:
                continue
            firebase_batch, supabase_batch = entry
            firebase_projects.extend(firebase_batch)
            supabase_configs.extend(supabase_batch)
        return firebase_projects, supabase_configs

    monkeypatch.setattr(runtime, "extract_cloud_configs_from_payloads", _extract_payloads)

    result = extract_cloud_configs_from_payloads_for_processor(
        _Adapter(),
        [("file.js", "$", "token"), ("empty.js", "$", " ")],
    )

    assert result == (
        ["0:firebase:file.js:$:token"],
        ["0:supabase:file.js:$:token"],
    )
    assert calls == [
        ("batch", [("file.js", "$", "token"), ("empty.js", "$", " ")], None),
        ("batch", [("file.js", "$", "token")], ([], [])),
        ("batch", [(0, (["firebase:file.js:$:token"], ["supabase:file.js:$:token"]))], None),
    ]


def test_payload_cloud_config_wrapper_helpers_delegate(monkeypatch: Any) -> None:
    monkeypatch.setattr(runtime, "payload_cloud_config_job", lambda payload: ("job", payload[1], payload[2]))
    monkeypatch.setattr(runtime, "payload_cloud_config_result_entry", lambda result: (["firebase"], ["supabase"]))

    assert payload_cloud_config_job_for_processor(("source", "path", "text")) == ("job", "path", "text")
    assert payload_cloud_config_result_entry_for_processor((0, ([], []))) == (["firebase"], ["supabase"])


def test_extract_cloud_configs_from_payload_for_processor_binds_family_batch(monkeypatch: Any) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _run_ordered_local_batch(
            self,
            items: tuple[str, ...],
            worker: Callable[[str], list[str]],
            *,
            default_factory: Callable[[], Any],
        ) -> list[list[str]]:
            calls.append(("batch", list(items), default_factory()))
            return [worker(item) for item in items]

        def _extract_cloud_config_family(
            self,
            family: str,
            *,
            source_file: str,
            extract_path: str,
            text: str,
        ) -> list[str]:
            return [f"{family}:{source_file}:{extract_path}:{text}"]

    def _extract_payload(
        source_file: str,
        extract_path: str,
        text: str,
        *,
        run_ordered_batch: Callable[..., list[Any]],
        extract_cloud_config_family: Callable[..., list[Any]],
    ) -> tuple[list[Any], list[Any]]:
        results = run_ordered_batch(
            ("firebase", "supabase"),
            lambda family: extract_cloud_config_family(
                family,
                source_file=source_file,
                extract_path=extract_path,
                text=text,
            ),
            default_factory=list,
        )
        return list(results[0]), list(results[1])

    monkeypatch.setattr(runtime, "extract_cloud_configs_from_payload", _extract_payload)

    assert extract_cloud_configs_from_payload_for_processor(
        _Adapter(),
        "app.js",
        "$.config",
        "secret",
    ) == (
        ["firebase:app.js:$.config:secret"],
        ["supabase:app.js:$.config:secret"],
    )
    assert calls == [("batch", ["firebase", "supabase"], [])]


def test_extract_cloud_config_family_for_processor_binds_firebase_and_supabase_extractors(
    monkeypatch: Any,
) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Extractor:
        def _extract_supabase_from_text(self, text: str, source_file: str, extract_path: str) -> list[str]:
            return [f"supabase:{source_file}:{extract_path}:{text}"]

    class _Adapter:
        _extractor = _Extractor()

        def _extract_firebase_from_text(self, text: str, source_file: str, extract_path: str) -> list[str]:
            return [f"firebase:{source_file}:{extract_path}:{text}"]

    def _extract_family(
        family: str,
        *,
        source_file: str,
        extract_path: str,
        text: str,
        extract_firebase_from_text: Callable[[str, str, str], list[Any]],
        extract_supabase_from_text: Callable[[str, str, str], list[Any]],
    ) -> list[Any]:
        firebase_result = extract_firebase_from_text(text, source_file, extract_path)
        supabase_result = extract_supabase_from_text(text, source_file, extract_path)
        calls.append((family, firebase_result, supabase_result))
        return firebase_result if family == "firebase" else supabase_result

    monkeypatch.setattr(runtime, "extract_cloud_config_family", _extract_family)

    assert extract_cloud_config_family_for_processor(
        _Adapter(),
        "supabase",
        source_file="app.js",
        extract_path="$.config",
        text="secret",
    ) == ["supabase:app.js:$.config:secret"]
    assert calls == [
        (
            "supabase",
            ["firebase:app.js:$.config:secret"],
            ["supabase:app.js:$.config:secret"],
        )
    ]


def test_extract_nested_mobile_bundle_configs_for_processor_binds_archive_handlers(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _extract_nested_mobile_configs_from_zip(self, archive: Any, source_path: Path) -> tuple[list[Any], list[Any], list[Any], int]:
            return [(source_path.name, "zip", type(archive).__name__)], ["zip-firebase"], ["zip-supabase"], 1

        def _extract_nested_mobile_configs_from_7z(self, data: bytes, source_path: Path) -> tuple[list[Any], list[Any], list[Any], int]:
            return [(source_path.name, "7z", data[:2].hex())], ["7z-firebase"], ["7z-supabase"], 2

        def _extract_nested_mobile_configs_from_tar(self, archive: Any, source_path: Path) -> tuple[list[Any], list[Any], list[Any], int]:
            return [(source_path.name, "tar", type(archive).__name__)], ["tar-firebase"], ["tar-supabase"], 3

    def _extract_nested(
        path: Path,
        artifact_type: str,
        *,
        py7zr_available: bool,
        extract_nested_mobile_configs_from_zip: Callable[..., tuple[list[Any], list[Any], list[Any], int]],
        extract_nested_mobile_configs_from_7z: Callable[..., tuple[list[Any], list[Any], list[Any], int]],
        extract_nested_mobile_configs_from_tar: Callable[..., tuple[list[Any], list[Any], list[Any], int]],
    ) -> tuple[list[Any], list[Any], list[Any], int]:
        calls.append((path, artifact_type, py7zr_available))
        zip_result = extract_nested_mobile_configs_from_zip(SimpleNamespace(kind="zip"), path)
        seven_z_result = extract_nested_mobile_configs_from_7z(b"7zpayload", path)
        tar_result = extract_nested_mobile_configs_from_tar(SimpleNamespace(kind="tar"), path)
        return (
            zip_result[0] + seven_z_result[0] + tar_result[0],
            zip_result[1] + seven_z_result[1] + tar_result[1],
            zip_result[2] + seven_z_result[2] + tar_result[2],
            zip_result[3] + seven_z_result[3] + tar_result[3],
        )

    artifact_path = tmp_path / "nested.zip"
    monkeypatch.setattr(runtime, "extract_nested_mobile_bundle_configs", _extract_nested)

    assert extract_nested_mobile_bundle_configs_for_processor(
        _Adapter(),
        artifact_path,
        "archive",
        py7zr_available=True,
    ) == (
        [("nested.zip", "zip", "SimpleNamespace"), ("nested.zip", "7z", "377a"), ("nested.zip", "tar", "SimpleNamespace")],
        ["zip-firebase", "7z-firebase", "tar-firebase"],
        ["zip-supabase", "7z-supabase", "tar-supabase"],
        6,
    )
    assert calls == [(artifact_path, "archive", True)]


def test_nested_mobile_member_entry_wrappers_bind_suffix_and_size_limits(monkeypatch: Any) -> None:
    calls: list[tuple[Any, ...]] = []

    def _zip_entry(
        member: Any,
        *,
        nested_mobile_artifact_suffixes: set[str],
        remote_artifact_max_bytes: int,
    ) -> dict[str, str]:
        calls.append(("zip", member.filename, nested_mobile_artifact_suffixes, remote_artifact_max_bytes))
        return {"name": member.filename}

    def _tar_entry(
        member: Any,
        *,
        nested_mobile_artifact_suffixes: set[str],
        remote_artifact_max_bytes: int,
    ) -> dict[str, str]:
        calls.append(("tar", member.name, nested_mobile_artifact_suffixes, remote_artifact_max_bytes))
        return {"name": member.name}

    def _seven_z_entry(
        member: Any,
        *,
        safe_archive_member_name: Callable[[str], str],
        nested_mobile_artifact_suffixes: set[str],
        remote_artifact_max_bytes: int,
    ) -> dict[str, str]:
        safe_name = safe_archive_member_name(member.filename)
        calls.append(("7z", safe_name, nested_mobile_artifact_suffixes, remote_artifact_max_bytes))
        return {"name": safe_name, "target": member.filename}

    monkeypatch.setattr(runtime, "nested_mobile_zip_member_entry", _zip_entry)
    monkeypatch.setattr(runtime, "nested_mobile_tar_member_entry", _tar_entry)
    monkeypatch.setattr(runtime, "nested_mobile_7z_member_entry", _seven_z_entry)

    suffixes = {".apk", ".ipa"}
    assert nested_mobile_zip_member_entry_for_processor(
        SimpleNamespace(filename="app.apk"),
        nested_mobile_artifact_suffixes=suffixes,
        remote_artifact_max_bytes=1024,
    ) == {"name": "app.apk"}
    assert nested_mobile_tar_member_entry_for_processor(
        SimpleNamespace(name="ios.ipa"),
        nested_mobile_artifact_suffixes=suffixes,
        remote_artifact_max_bytes=1024,
    ) == {"name": "ios.ipa"}
    assert nested_mobile_7z_member_entry_for_processor(
        SimpleNamespace(filename="../safe/app.apk"),
        safe_archive_member_name=lambda name: name.replace("../", ""),
        nested_mobile_artifact_suffixes=suffixes,
        remote_artifact_max_bytes=1024,
    ) == {"name": "safe/app.apk", "target": "../safe/app.apk"}
    assert calls == [
        ("zip", "app.apk", suffixes, 1024),
        ("tar", "ios.ipa", suffixes, 1024),
        ("7z", "safe/app.apk", suffixes, 1024),
    ]


def test_extract_nested_mobile_configs_from_zip_for_processor_binds_member_callbacks(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _run_ordered_local_batch(
            self,
            items: list[Any],
            worker: Callable[[Any], Any],
            *,
            default_factory: Callable[[], Any],
        ) -> list[Any]:
            calls.append(("batch", list(items), default_factory()))
            return [worker(item) for item in items]

        def _nested_mobile_zip_member_entry(self, member: Any) -> dict[str, str]:
            return {"name": f"zip:{member}"}

        def _nested_mobile_member_job(self, member_job: tuple[str, bytes]) -> tuple[str, bytes]:
            return member_job[0], member_job[1] + b":job"

        def _extract_nested_mobile_configs_from_member_jobs(
            self,
            member_jobs: list[tuple[str, bytes]],
            source_path: Path,
        ) -> tuple[list[Any], list[Any], list[Any], int]:
            return [(source_path.name, name, data.decode()) for name, data in member_jobs], ["firebase"], ["supabase"], len(member_jobs)

    def _extract_zip(
        zf: Any,
        source_path: Path,
        *,
        run_ordered_batch: Callable[..., list[Any]],
        nested_mobile_zip_member_entry: Callable[[Any], dict[str, str] | None],
        nested_mobile_member_job: Callable[[tuple[str, bytes]], tuple[str, bytes] | None],
        extract_nested_mobile_configs_from_member_jobs: Callable[..., tuple[list[Any], list[Any], list[Any], int]],
    ) -> tuple[list[Any], list[Any], list[Any], int]:
        member_entries = run_ordered_batch(zf.members, nested_mobile_zip_member_entry, default_factory=lambda: None)
        jobs = run_ordered_batch(
            [(entry["name"], f"bytes:{entry['name']}".encode()) for entry in member_entries],
            nested_mobile_member_job,
            default_factory=lambda: None,
        )
        return extract_nested_mobile_configs_from_member_jobs(jobs, source_path)

    monkeypatch.setattr(runtime, "extract_nested_mobile_configs_from_zip", _extract_zip)

    assert extract_nested_mobile_configs_from_zip_for_processor(
        _Adapter(),
        SimpleNamespace(members=["app.apk"]),
        tmp_path / "source.zip",
    ) == (
        [("source.zip", "zip:app.apk", "bytes:zip:app.apk:job")],
        ["firebase"],
        ["supabase"],
        1,
    )
    assert calls == [
        ("batch", ["app.apk"], None),
        ("batch", [("zip:app.apk", b"bytes:zip:app.apk")], None),
    ]


def test_extract_nested_mobile_configs_from_tar_for_processor_binds_member_callbacks(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _run_ordered_local_batch(
            self,
            items: list[Any],
            worker: Callable[[Any], Any],
            *,
            default_factory: Callable[[], Any],
        ) -> list[Any]:
            calls.append(("batch", list(items), default_factory()))
            return [worker(item) for item in items]

        def _nested_mobile_tar_member_entry(self, member: Any) -> dict[str, str]:
            return {"name": f"tar:{member}"}

        def _nested_mobile_member_job(self, member_job: tuple[str, bytes]) -> tuple[str, bytes]:
            return member_job[0], member_job[1] + b":job"

        def _extract_nested_mobile_configs_from_member_jobs(
            self,
            member_jobs: list[tuple[str, bytes]],
            source_path: Path,
        ) -> tuple[list[Any], list[Any], list[Any], int]:
            return [(source_path.name, name, data.decode()) for name, data in member_jobs], ["firebase"], ["supabase"], len(member_jobs)

    def _extract_tar(
        tf: Any,
        source_path: Path,
        *,
        run_ordered_batch: Callable[..., list[Any]],
        nested_mobile_tar_member_entry: Callable[[Any], dict[str, str] | None],
        nested_mobile_member_job: Callable[[tuple[str, bytes]], tuple[str, bytes] | None],
        extract_nested_mobile_configs_from_member_jobs: Callable[..., tuple[list[Any], list[Any], list[Any], int]],
    ) -> tuple[list[Any], list[Any], list[Any], int]:
        member_entries = run_ordered_batch(tf.members, nested_mobile_tar_member_entry, default_factory=lambda: None)
        jobs = run_ordered_batch(
            [(entry["name"], f"bytes:{entry['name']}".encode()) for entry in member_entries],
            nested_mobile_member_job,
            default_factory=lambda: None,
        )
        return extract_nested_mobile_configs_from_member_jobs(jobs, source_path)

    monkeypatch.setattr(runtime, "extract_nested_mobile_configs_from_tar", _extract_tar)

    assert extract_nested_mobile_configs_from_tar_for_processor(
        _Adapter(),
        SimpleNamespace(members=["ios.ipa"]),
        tmp_path / "source.tar",
    ) == (
        [("source.tar", "tar:ios.ipa", "bytes:tar:ios.ipa:job")],
        ["firebase"],
        ["supabase"],
        1,
    )
    assert calls == [
        ("batch", ["ios.ipa"], None),
        ("batch", [("tar:ios.ipa", b"bytes:tar:ios.ipa")], None),
    ]


def test_extract_nested_mobile_configs_from_7z_for_processor_binds_archive_callbacks(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _run_ordered_local_batch(
            self,
            items: list[Any],
            worker: Callable[[Any], Any],
            *,
            default_factory: Callable[[], Any],
        ) -> list[Any]:
            calls.append(("batch", list(items), default_factory()))
            return [worker(item) for item in items]

        def _nested_mobile_7z_member_entry(self, member: Any) -> dict[str, str]:
            return {"name": f"7z:{member}", "target": member}

        def _nested_mobile_member_job(self, member_job: tuple[str, bytes]) -> tuple[str, bytes]:
            return member_job[0], member_job[1] + b":job"

        def _extract_nested_mobile_configs_from_member_jobs(
            self,
            member_jobs: list[tuple[str, bytes]],
            source_path: Path,
        ) -> tuple[list[Any], list[Any], list[Any], int]:
            return [(source_path.name, name, data.decode()) for name, data in member_jobs], ["firebase"], ["supabase"], len(member_jobs)

    def _seven_zip_factory(*_args: Any, **_kwargs: Any) -> str:
        return "factory"

    def _extract_7z(
        data: bytes,
        source_path: Path,
        *,
        seven_zip_file_factory: Callable[..., Any] | None,
        run_ordered_batch: Callable[..., list[Any]],
        nested_mobile_7z_member_entry: Callable[[Any], dict[str, str] | None],
        nested_mobile_member_job: Callable[[tuple[str, bytes]], tuple[str, bytes] | None],
        extract_nested_mobile_configs_from_member_jobs: Callable[..., tuple[list[Any], list[Any], list[Any], int]],
        remote_artifact_max_bytes: int,
    ) -> tuple[list[Any], list[Any], list[Any], int]:
        calls.append(("7z", data, source_path, seven_zip_file_factory is _seven_zip_factory, remote_artifact_max_bytes))
        member_entries = run_ordered_batch(["app.apk"], nested_mobile_7z_member_entry, default_factory=lambda: None)
        jobs = run_ordered_batch(
            [(entry["name"], f"bytes:{entry['target']}".encode()) for entry in member_entries],
            nested_mobile_member_job,
            default_factory=lambda: None,
        )
        return extract_nested_mobile_configs_from_member_jobs(jobs, source_path)

    monkeypatch.setattr(runtime, "extract_nested_mobile_configs_from_7z", _extract_7z)

    assert extract_nested_mobile_configs_from_7z_for_processor(
        _Adapter(),
        b"7zpayload",
        tmp_path / "source.7z",
        seven_zip_file_factory=_seven_zip_factory,
        remote_artifact_max_bytes=2048,
    ) == (
        [("source.7z", "7z:app.apk", "bytes:app.apk:job")],
        ["firebase"],
        ["supabase"],
        1,
    )
    assert calls == [
        ("7z", b"7zpayload", tmp_path / "source.7z", True, 2048),
        ("batch", ["app.apk"], None),
        ("batch", [("7z:app.apk", b"bytes:app.apk")], None),
    ]


def test_extract_nested_mobile_configs_from_member_jobs_for_processor_binds_result_callbacks(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _run_ordered_local_batch(
            self,
            items: list[Any],
            worker: Callable[[Any], Any],
            *,
            default_factory: Callable[[], Any],
        ) -> list[Any]:
            calls.append(("batch", list(items), default_factory()))
            return [worker(item) for item in items]

        def _extract_mobile_configs_from_member_bytes(
            self,
            data: bytes,
            source_path: Path,
            member_name: str,
        ) -> tuple[list[Any], list[Any], list[Any]]:
            return [(source_path.name, member_name, data.decode())], ["firebase"], ["supabase"]

        def _nested_mobile_member_result_entry(
            self,
            result_entry: tuple[int, tuple[list[Any], list[Any], list[Any]] | None],
        ) -> tuple[list[Any], list[Any], list[Any]] | None:
            index, result = result_entry
            if result is None:
                return None
            payloads, firebase_projects, supabase_configs = result
            return [(index, *payloads[0])], firebase_projects, supabase_configs

    def _extract_member_jobs(
        member_jobs: list[tuple[str, bytes]],
        source_path: Path,
        *,
        run_ordered_batch: Callable[..., list[Any]],
        extract_mobile_configs_from_member_bytes: Callable[[bytes, Path, str], tuple[list[Any], list[Any], list[Any]]],
        nested_mobile_member_result_entry: Callable[..., tuple[list[Any], list[Any], list[Any]] | None],
    ) -> tuple[list[Any], list[Any], list[Any], int]:
        results = run_ordered_batch(
            member_jobs,
            lambda member_job: extract_mobile_configs_from_member_bytes(member_job[1], source_path, member_job[0]),
            default_factory=lambda: ([], [], []),
        )
        entries = run_ordered_batch(
            list(enumerate(results)),
            nested_mobile_member_result_entry,
            default_factory=lambda: None,
        )
        return entries[0][0], entries[0][1], entries[0][2], len(member_jobs)

    monkeypatch.setattr(runtime, "extract_nested_mobile_configs_from_member_jobs", _extract_member_jobs)

    assert extract_nested_mobile_configs_from_member_jobs_for_processor(
        _Adapter(),
        [("app.apk", b"bytes")],
        tmp_path / "source.zip",
    ) == (
        [(0, "source.zip", "app.apk", "bytes")],
        ["firebase"],
        ["supabase"],
        1,
    )
    assert calls == [
        ("batch", [("app.apk", b"bytes")], ([], [], [])),
        ("batch", [(0, ([("source.zip", "app.apk", "bytes")], ["firebase"], ["supabase"]))], None),
    ]


def test_nested_mobile_member_job_wrapper_helpers_delegate(monkeypatch: Any) -> None:
    monkeypatch.setattr(runtime, "nested_mobile_member_job", lambda job: (job[0].strip(), job[1] + b":normalized"))
    monkeypatch.setattr(runtime, "nested_mobile_member_result_entry", lambda result: ([("payload", "path", "text")], ["firebase"], ["supabase"]))

    assert nested_mobile_member_job_for_processor((" app.apk ", b"bytes")) == ("app.apk", b"bytes:normalized")
    assert nested_mobile_member_result_entry_for_processor((0, None)) == (
        [("payload", "path", "text")],
        ["firebase"],
        ["supabase"],
    )


def test_extract_mobile_configs_from_member_bytes_for_processor_binds_member_callbacks(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    calls: list[tuple[Any, ...]] = []

    class _FirebaseProject:
        pass

    class _SupabaseConfig:
        pass

    class _Adapter:
        def _run_ordered_local_batch(
            self,
            items: list[Any],
            worker: Callable[[Any], Any],
            *,
            default_factory: Callable[[], Any],
        ) -> list[Any]:
            calls.append(("batch", list(items), default_factory()))
            return [worker(item) for item in items]

        def _scan_text_artifact(self, path: Path, artifact_type: str) -> tuple[list[Any], list[Any], list[Any], dict[str, Any]]:
            calls.append(("scan", path, artifact_type))
            return [("text", path.name, artifact_type)], ["firebase"], ["supabase"], {"source": "scan"}

        def _extract_mobile_bundle_family(self, family: str, *, path: Path, artifact_type: str) -> list[Any]:
            calls.append(("bundle", family, path, artifact_type))
            return [(family, path.name, artifact_type)]

        def _rebased_mobile_member_payload_entry(
            self,
            payload: tuple[str, str, str],
            *,
            source_path: Path,
            member_name: str,
        ) -> tuple[str, str, str]:
            calls.append(("payload", payload, source_path, member_name))
            return (str(source_path), member_name, payload[2])

        def _rebased_mobile_member_project_entry(
            self,
            project: Any,
            *,
            source_path: Path,
            member_name: str,
        ) -> Any:
            calls.append(("project", project, source_path, member_name))
            return ("project", project)

        def _rebased_mobile_member_config_entry(
            self,
            config: Any,
            *,
            source_path: Path,
            member_name: str,
        ) -> Any:
            calls.append(("config", config, source_path, member_name))
            return ("config", config)

    def _extract_member_bytes(
        data: bytes,
        source_path: Path,
        member_name: str,
        *,
        nested_mobile_artifact_suffixes: set[str],
        archive_style_mobile_artifact_suffixes: set[str],
        remote_artifact_max_bytes: int,
        run_ordered_batch: Callable[..., list[Any]],
        scan_text_artifact: Callable[..., Any],
        extract_mobile_bundle_family: Callable[..., Any],
        rebased_mobile_member_payload_entry: Callable[..., Any],
        rebased_mobile_member_project_entry: Callable[..., Any],
        rebased_mobile_member_config_entry: Callable[..., Any],
        firebase_project_type: type[Any],
        supabase_config_type: type[Any],
    ) -> tuple[list[Any], list[Any], list[Any]]:
        calls.append(
            (
                "extract",
                data,
                source_path,
                member_name,
                nested_mobile_artifact_suffixes,
                archive_style_mobile_artifact_suffixes,
                remote_artifact_max_bytes,
                firebase_project_type,
                supabase_config_type,
            )
        )
        run_ordered_batch(["payload"], lambda item: item.upper(), default_factory=lambda: "default")
        scan_text_artifact(source_path, "mobile-member")
        extract_mobile_bundle_family("apk", path=source_path, artifact_type="mobile-member")
        payload = rebased_mobile_member_payload_entry(("file", "path", "text"), source_path=source_path, member_name=member_name)
        project = rebased_mobile_member_project_entry("firebase-project", source_path=source_path, member_name=member_name)
        config = rebased_mobile_member_config_entry("supabase-config", source_path=source_path, member_name=member_name)
        return [payload], [project], [config]

    monkeypatch.setattr(runtime, "extract_mobile_configs_from_member_bytes", _extract_member_bytes)

    source_path = tmp_path / "bundle.zip"
    assert extract_mobile_configs_from_member_bytes_for_processor(
        _Adapter(),
        b"member-bytes",
        source_path,
        "app.apk",
        nested_mobile_artifact_suffixes={".apk"},
        archive_style_mobile_artifact_suffixes={".zip"},
        remote_artifact_max_bytes=4096,
        firebase_project_type=_FirebaseProject,
        supabase_config_type=_SupabaseConfig,
    ) == (
        [(str(source_path), "app.apk", "text")],
        [("project", "firebase-project")],
        [("config", "supabase-config")],
    )
    assert calls == [
        (
            "extract",
            b"member-bytes",
            source_path,
            "app.apk",
            {".apk"},
            {".zip"},
            4096,
            _FirebaseProject,
            _SupabaseConfig,
        ),
        ("batch", ["payload"], "default"),
        ("scan", source_path, "mobile-member"),
        ("bundle", "apk", source_path, "mobile-member"),
        ("payload", ("file", "path", "text"), source_path, "app.apk"),
        ("project", "firebase-project", source_path, "app.apk"),
        ("config", "supabase-config", source_path, "app.apk"),
    ]


def test_rebased_mobile_member_wrapper_helpers_delegate(monkeypatch: Any, tmp_path: Path) -> None:
    class _FirebaseProject:
        pass

    class _SupabaseConfig:
        pass

    source_path = tmp_path / "source.zip"
    monkeypatch.setattr(
        runtime,
        "rebased_mobile_member_payload_entry",
        lambda payload, *, source_path, member_name: (str(source_path), member_name, payload[2]),
    )
    monkeypatch.setattr(
        runtime,
        "rebased_mobile_member_project_entry",
        lambda project, *, source_path, member_name, firebase_project_type: (
            project,
            source_path,
            member_name,
            firebase_project_type,
        ),
    )
    monkeypatch.setattr(
        runtime,
        "rebased_mobile_member_config_entry",
        lambda config, *, source_path, member_name, supabase_config_type: (
            config,
            source_path,
            member_name,
            supabase_config_type,
        ),
    )

    assert rebased_mobile_member_payload_entry_for_processor(
        ("source", "path", "text"),
        source_path=source_path,
        member_name="app.apk",
    ) == (str(source_path), "app.apk", "text")
    assert rebased_mobile_member_project_entry_for_processor(
        "project",
        source_path=source_path,
        member_name="app.apk",
        firebase_project_type=_FirebaseProject,
    ) == ("project", source_path, "app.apk", _FirebaseProject)
    assert rebased_mobile_member_config_entry_for_processor(
        "config",
        source_path=source_path,
        member_name="app.apk",
        supabase_config_type=_SupabaseConfig,
    ) == ("config", source_path, "app.apk", _SupabaseConfig)


def test_artifact_relation_context_wrapper_helpers_delegate(monkeypatch: Any, tmp_path: Path) -> None:
    parsed = ParsedArtifact(
        artifact_id=11,
        source_url="file:///artifact.txt",
        artifact_type="text",
        path=tmp_path / "artifact.txt",
        parse_metadata={"parser": "text", "payload_count": 2},
    )
    calls: list[tuple[Any, ...]] = []

    monkeypatch.setattr(
        runtime,
        "safe_artifact_relation_context",
        lambda *, parse_metadata, artifact_type, artifact_metadata: {
            "parse_metadata": parse_metadata,
            "artifact_type": artifact_type,
            "artifact_metadata": artifact_metadata,
        },
    )
    monkeypatch.setattr(
        runtime,
        "merge_artifact_relation_context",
        lambda relation_metadata, artifact_context: {
            "relation": relation_metadata,
            "artifact": artifact_context,
        },
    )

    assert safe_artifact_relation_context_for_processor(parsed, {"content_type": "text/plain"}) == {
        "parse_metadata": {"parser": "text", "payload_count": 2},
        "artifact_type": "text",
        "artifact_metadata": {"content_type": "text/plain"},
    }
    assert merge_artifact_relation_context_for_processor({"source": "payload"}, {"parser": "text"}) == {
        "relation": {"source": "payload"},
        "artifact": {"parser": "text"},
    }

    class _Adapter:
        _engagement_id = 42

        def _artifact_source_seed_provenance(self, con: Any, seed_id: int) -> dict[str, Any]:
            calls.append(("provenance", con, seed_id))
            return {"source_seed_url": f"https://seed/{seed_id}"}

    def _artifact_cloud_metadata(
        *,
        source_seed_id: int | None,
        relation_metadata: dict[str, Any] | None,
        artifact_context: dict[str, Any] | None,
        artifact_source_seed_provenance: Callable[[int], dict[str, Any]],
    ) -> dict[str, Any]:
        calls.append(("cloud", source_seed_id, relation_metadata, artifact_context))
        return artifact_source_seed_provenance(source_seed_id or 0)

    def _artifact_relation_context_from_queue(con: Any, engagement_id: int, queued_parsed: ParsedArtifact) -> dict[str, Any]:
        calls.append(("queue", con, engagement_id, queued_parsed))
        return {"artifact_id": queued_parsed.artifact_id, "engagement_id": engagement_id}

    monkeypatch.setattr(runtime, "artifact_cloud_asset_metadata", _artifact_cloud_metadata)
    monkeypatch.setattr(runtime, "artifact_relation_context_from_queue", _artifact_relation_context_from_queue)

    con = object()
    assert artifact_cloud_asset_metadata_for_processor(
        _Adapter(),
        con,  # type: ignore[arg-type]
        source_seed_id=7,
        relation_metadata={"source": "payload"},
        artifact_context={"parser": "text"},
    ) == {"source_seed_url": "https://seed/7"}
    assert artifact_relation_context_for_processor(_Adapter(), con, parsed) == {
        "artifact_id": 11,
        "engagement_id": 42,
    }
    assert calls == [
        ("cloud", 7, {"source": "payload"}, {"parser": "text"}),
        ("provenance", con, 7),
        ("queue", con, 42, parsed),
    ]


def test_persist_parsed_artifact_for_processor_binds_persistence_callbacks(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    parsed = ParsedArtifact(
        artifact_id=12,
        source_url="file:///artifact.txt",
        artifact_type="text",
        path=tmp_path / "artifact.txt",
        payloads=[("artifact.txt", "body", "hello")],
        firebase_projects=["firebase"],
        supabase_configs=["supabase"],
        parse_metadata={"parser": "text"},
    )
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _artifact_relation_context(self, con: Any, queued_parsed: ParsedArtifact) -> dict[str, Any]:
            calls.append(("relation", con, queued_parsed))
            return {"artifact_id": queued_parsed.artifact_id}

        def _artifact_source_seed_id(self, con: Any, source_url: str) -> int | None:
            calls.append(("source_seed", con, source_url))
            return None

        def _ensure_local_artifact_source_seed(
            self,
            con: Any,
            queued_parsed: ParsedArtifact,
            *,
            artifact_context: dict[str, Any],
        ) -> int:
            calls.append(("ensure", con, queued_parsed.artifact_id, artifact_context))
            return 101

        def _artifact_discovery_payloads(self, queued_parsed: ParsedArtifact) -> list[tuple[str, str, str]]:
            calls.append(("payloads", queued_parsed.payloads))
            return list(queued_parsed.payloads)

        def _expand_structured_discovery_jobs(
            self,
            payloads: list[tuple[str, str, str]],
        ) -> list[tuple[str, str, str]]:
            calls.append(("expand", payloads))
            return [("expanded.txt", "body", "expanded")]

        def _collect_generic_text_discovery_batches(self, jobs: list[tuple[str, str, str]]) -> list[str]:
            calls.append(("collect", jobs))
            return ["batch"]

        def _persist_generic_text_discovery_batch(
            self,
            con: Any,
            batch: str,
            *,
            source_seed_id: int | None,
            artifact_context: dict[str, Any],
        ) -> int:
            calls.append(("persist_batch", con, batch, source_seed_id, artifact_context))
            return 3

        def _dedupe_firebase_projects(self, projects: list[Any]) -> list[Any]:
            calls.append(("dedupe_firebase", projects))
            return [f"{projects[0]}:deduped"]

        def _store_firebase_projects(
            self,
            con: Any,
            projects: list[Any],
            *,
            source_seed_id: int | None,
            source_url: str,
            artifact_context: dict[str, Any],
        ) -> tuple[int, int]:
            calls.append(("store_firebase", con, projects, source_seed_id, source_url, artifact_context))
            return 5, 7

        def _dedupe_supabase_configs(self, configs: list[Any]) -> list[Any]:
            calls.append(("dedupe_supabase", configs))
            return [f"{configs[0]}:deduped"]

        def _store_supabase_configs(
            self,
            con: Any,
            configs: list[Any],
            *,
            source_seed_id: int | None,
            source_url: str,
            artifact_context: dict[str, Any],
        ) -> tuple[int, int]:
            calls.append(("store_supabase", con, configs, source_seed_id, source_url, artifact_context))
            return 11, 13

    con = object()
    assert persist_parsed_artifact_for_processor(_Adapter(), con, parsed) == (
        5,
        11,
        3 + 5 + 7 + 13,
        {"parser": "text"},
    )
    assert calls == [
        ("relation", con, parsed),
        ("source_seed", con, "file:///artifact.txt"),
        ("ensure", con, 12, {"artifact_id": 12}),
        ("payloads", [("artifact.txt", "body", "hello")]),
        ("expand", [("artifact.txt", "body", "hello")]),
        ("collect", [("expanded.txt", "body", "expanded")]),
        ("persist_batch", con, "batch", 101, {"artifact_id": 12}),
        ("dedupe_firebase", ["firebase"]),
        ("store_firebase", con, ["firebase:deduped"], 101, "file:///artifact.txt", {"artifact_id": 12}),
        ("dedupe_supabase", ["supabase"]),
        ("store_supabase", con, ["supabase:deduped"], 101, "file:///artifact.txt", {"artifact_id": 12}),
    ]


def test_persist_generic_text_discovery_batch_for_processor_binds_persistence_callbacks(
    monkeypatch: Any,
) -> None:
    calls: list[tuple[Any, ...]] = []

    def _persist_generic_text_discovery_batch(
        con: Any,
        batch: ArtifactTextDiscoveryBatch,
        **kwargs: Any,
    ) -> int:
        calls.append(("persist", con, batch, kwargs))
        return 23

    monkeypatch.setattr(
        runtime,
        "persist_generic_text_discovery_batch",
        _persist_generic_text_discovery_batch,
    )

    class _Adapter:
        def _artifact_child_seed_depth(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _run_ordered_local_batch(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _artifact_text_email_persistence_entry(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _artifact_text_phone_persistence_entry(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _artifact_text_ip_persistence_entry(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _artifact_text_host_persistence_entry(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _artifact_text_url_persistence_entry(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _artifact_text_identity_seed_persistence_entry(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _artifact_text_key_finding_persistence_entry(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _artifact_text_cloud_asset_persistence_entry(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _insert_email(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _insert_seed(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _link_artifact_source_seed(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _store_artifact_url_seed(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _merge_artifact_relation_context(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _merge_artifact_metadata_into_seed(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _store_key_finding(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _artifact_cloud_asset_metadata(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _store_cloud_asset_reference(self) -> None:
            raise AssertionError("callback should be passed, not called")

    con = object()
    batch = ArtifactTextDiscoveryBatch(source_file="artifact.txt")
    artifact_context = {"artifact_id": 14}
    adapter = _Adapter()

    assert (
        persist_generic_text_discovery_batch_for_processor(
            adapter,
            con,
            batch,
            source_seed_id=41,
            artifact_context=artifact_context,
        )
        == 23
    )
    assert len(calls) == 1
    name, called_con, called_batch, kwargs = calls[0]
    assert (name, called_con, called_batch) == ("persist", con, batch)
    assert kwargs["source_seed_id"] == 41
    assert kwargs["artifact_context"] == artifact_context

    def _assert_adapter_method(name: str, method_name: str) -> None:
        callback = kwargs[name]
        assert callback.__self__ is adapter
        assert callback.__func__ is getattr(type(adapter), method_name)

    _assert_adapter_method("artifact_child_seed_depth", "_artifact_child_seed_depth")
    _assert_adapter_method("run_ordered_batch", "_run_ordered_local_batch")
    _assert_adapter_method("artifact_text_email_persistence_entry", "_artifact_text_email_persistence_entry")
    _assert_adapter_method("artifact_text_phone_persistence_entry", "_artifact_text_phone_persistence_entry")
    _assert_adapter_method("artifact_text_ip_persistence_entry", "_artifact_text_ip_persistence_entry")
    _assert_adapter_method("artifact_text_host_persistence_entry", "_artifact_text_host_persistence_entry")
    _assert_adapter_method("artifact_text_url_persistence_entry", "_artifact_text_url_persistence_entry")
    _assert_adapter_method(
        "artifact_text_identity_seed_persistence_entry",
        "_artifact_text_identity_seed_persistence_entry",
    )
    _assert_adapter_method("artifact_text_key_finding_persistence_entry", "_artifact_text_key_finding_persistence_entry")
    _assert_adapter_method(
        "artifact_text_cloud_asset_persistence_entry",
        "_artifact_text_cloud_asset_persistence_entry",
    )
    _assert_adapter_method("insert_email", "_insert_email")
    _assert_adapter_method("insert_seed", "_insert_seed")
    _assert_adapter_method("link_artifact_source_seed", "_link_artifact_source_seed")
    _assert_adapter_method("store_artifact_url_seed", "_store_artifact_url_seed")
    _assert_adapter_method("merge_artifact_relation_context_fn", "_merge_artifact_relation_context")
    _assert_adapter_method("merge_artifact_metadata_into_seed", "_merge_artifact_metadata_into_seed")
    _assert_adapter_method("store_key_finding", "_store_key_finding")
    _assert_adapter_method("artifact_cloud_asset_metadata", "_artifact_cloud_asset_metadata")
    _assert_adapter_method("store_cloud_asset_reference", "_store_cloud_asset_reference")


def test_store_generic_text_discoveries_for_processor_collects_then_persists() -> None:
    calls: list[tuple[Any, ...]] = []
    batch = ArtifactTextDiscoveryBatch(source_file="artifact.txt", urls=["https://example.com"])

    class _Adapter:
        def _collect_generic_text_discoveries(
            self,
            text: str,
            *,
            source_file: str,
        ) -> ArtifactTextDiscoveryBatch:
            calls.append(("collect", text, source_file))
            return batch

        def _persist_generic_text_discovery_batch(
            self,
            con: Any,
            queued_batch: ArtifactTextDiscoveryBatch,
            *,
            source_seed_id: int | None,
        ) -> int:
            calls.append(("persist", con, queued_batch, source_seed_id))
            return 17

    con = object()
    assert (
        store_generic_text_discoveries_for_processor(
            _Adapter(),
            con,
            "payload",
            source_file="artifact.txt",
            source_seed_id=9,
        )
        == 17
    )
    assert calls == [
        ("collect", "payload", "artifact.txt"),
        ("persist", con, batch, 9),
    ]


def test_artifact_url_seed_persistence_entry_for_processor_binds_url_seed_callbacks(
    monkeypatch: Any,
) -> None:
    calls: list[tuple[Any, ...]] = []

    def _artifact_url_seed_persistence_entry(
        url: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        calls.append(("entry", url, kwargs))
        return {"url": url, "seed_type": "url"}

    monkeypatch.setattr(
        runtime,
        "artifact_url_seed_persistence_entry",
        _artifact_url_seed_persistence_entry,
    )

    def _looks_templated(value: object) -> bool:
        calls.append(("templated", value))
        return False

    def _looks_standards(value: str) -> bool:
        calls.append(("standards", value))
        return False

    def _is_mobile(value: str) -> bool:
        calls.append(("mobile", value))
        return False

    class _Adapter:
        def _run_ordered_local_batch(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _artifact_url_seed_family_entry(self) -> None:
            raise AssertionError("callback should be passed, not called")

        def _artifact_url_seed_family_merge_entry(self) -> None:
            raise AssertionError("callback should be passed, not called")

    adapter = _Adapter()
    relation_metadata = {"source": "artifact"}
    assert artifact_url_seed_persistence_entry_for_processor(
        adapter,
        "https://example.com/app.apk",
        relation_metadata=relation_metadata,
        artifact_url_looks_templated=_looks_templated,
        artifact_url_looks_standards_namespace=_looks_standards,
        is_mobile_bundle_url=_is_mobile,
    ) == {"url": "https://example.com/app.apk", "seed_type": "url"}
    assert len(calls) == 1
    name, url, kwargs = calls[0]
    assert (name, url) == ("entry", "https://example.com/app.apk")
    assert kwargs["relation_metadata"] == relation_metadata
    assert kwargs["artifact_url_looks_templated"] is _looks_templated
    assert kwargs["artifact_url_looks_standards_namespace"] is _looks_standards
    assert kwargs["is_mobile_bundle_url"] is _is_mobile

    def _assert_adapter_method(name: str, method_name: str) -> None:
        callback = kwargs[name]
        assert callback.__self__ is adapter
        assert callback.__func__ is getattr(type(adapter), method_name)

    _assert_adapter_method("run_ordered_batch", "_run_ordered_local_batch")
    _assert_adapter_method("artifact_url_seed_family_entry", "_artifact_url_seed_family_entry")
    _assert_adapter_method(
        "artifact_url_seed_family_merge_entry",
        "_artifact_url_seed_family_merge_entry",
    )


def test_artifact_url_seed_family_entry_for_processor_dispatches_url_families() -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _artifact_url_social_pivot_entries(
            self,
            url: str,
            *,
            relation_metadata: dict[str, Any] | None,
        ) -> list[dict[str, Any]]:
            calls.append(("social", url, relation_metadata))
            return [{"platform": "github"}]

        def _artifact_url_related_seed_entries(self, hostname: str) -> list[dict[str, Any]]:
            calls.append(("related", hostname))
            return [{"seed_value": hostname, "seed_type": "domain"}]

        def _artifact_url_cloud_asset_entries(
            self,
            url: str,
            *,
            source: str,
        ) -> list[dict[str, Any]]:
            calls.append(("cloud", url, source))
            return [{"asset_type": "aws_s3"}]

    adapter = _Adapter()
    relation_metadata = {"source": "artifact"}
    assert artifact_url_seed_family_entry_for_processor(
        adapter,
        "social_pivots",
        url="https://github.com/acme",
        hostname="github.com",
        relation_metadata=relation_metadata,
    ) == {"social_pivot_entries": [{"platform": "github"}]}
    assert artifact_url_seed_family_entry_for_processor(
        adapter,
        "related_seeds",
        url="https://app.example.com",
        hostname="app.example.com",
        relation_metadata=relation_metadata,
    ) == {"related_seed_entries": [{"seed_value": "app.example.com", "seed_type": "domain"}]}
    assert artifact_url_seed_family_entry_for_processor(
        adapter,
        "cloud_assets",
        url="https://bucket.s3.amazonaws.com",
        hostname="bucket.s3.amazonaws.com",
        relation_metadata=relation_metadata,
    ) == {"cloud_asset_entries": [{"asset_type": "aws_s3"}]}
    assert artifact_url_seed_family_entry_for_processor(
        adapter,
        "unknown",
        url="https://example.com",
        hostname="example.com",
        relation_metadata=relation_metadata,
    ) == {}
    assert calls == [
        ("social", "https://github.com/acme", relation_metadata),
        ("related", "app.example.com"),
        ("cloud", "https://bucket.s3.amazonaws.com", "artifact_url_extract"),
    ]


def test_artifact_url_related_seed_entries_for_processor_binds_host_classifiers() -> None:
    calls: list[tuple[str, str]] = []

    def _is_social(hostname: str) -> bool:
        calls.append(("social", hostname))
        return hostname == "github.com"

    def _is_managed(hostname: str) -> bool:
        calls.append(("managed", hostname))
        return hostname.endswith(".cloudfront.net")

    def _root(hostname: str) -> str:
        calls.append(("root", hostname))
        parts = hostname.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname

    common = {
        "is_social_platform_host": _is_social,
        "is_managed_cloud_provider_host": _is_managed,
        "normalize_root_domain": _root,
    }

    assert artifact_url_related_seed_entries_for_processor("Example.com.", **common) == [
        {"seed_value": "example.com", "seed_type": "domain", "confidence": 0.6}
    ]
    assert artifact_url_related_seed_entries_for_processor("App.Example.com", **common) == [
        {"seed_value": "app.example.com", "seed_type": "subdomain", "confidence": 0.64},
        {"seed_value": "example.com", "seed_type": "domain", "confidence": 0.6},
    ]
    assert artifact_url_related_seed_entries_for_processor("github.com", **common) == []
    assert artifact_url_related_seed_entries_for_processor("cdn.cloudfront.net", **common) == []
    assert calls == [
        ("social", "example.com"),
        ("managed", "example.com"),
        ("root", "example.com"),
        ("social", "app.example.com"),
        ("managed", "app.example.com"),
        ("root", "app.example.com"),
        ("social", "github.com"),
        ("social", "cdn.cloudfront.net"),
        ("managed", "cdn.cloudfront.net"),
    ]


def test_artifact_url_social_pivot_entries_for_processor_binds_profile_callbacks() -> None:
    calls: list[tuple[Any, ...]] = []
    url = "https://bsky.app/profile/Acme.Example"

    def _platform(profile_stub: dict[str, Any]) -> str:
        calls.append(("platform", profile_stub))
        return "bluesky"

    def _handle(candidate_url: str) -> str:
        calls.append(("handle", candidate_url))
        return "Acme.Example"

    def _classify(seed_value: str) -> str:
        calls.append(("classify", seed_value))
        return "domain" if seed_value == "acme.example" else "username"

    def _company(profile_stub: dict[str, Any], *, source_label: str, platform: str) -> str:
        calls.append(("company", profile_stub, source_label, platform))
        return "Acme Labs"

    def _name(profile_stub: dict[str, Any]) -> str:
        calls.append(("name", profile_stub))
        return "Alice Example"

    entries = artifact_url_social_pivot_entries_for_processor(
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
    profile_stub = {"profile_url": url}
    assert calls == [
        ("platform", profile_stub),
        ("handle", url),
        ("classify", "acme.example"),
        ("company", profile_stub, "artifact_social_url", "bluesky"),
        ("name", profile_stub),
    ]


def test_artifact_url_cloud_asset_entries_for_processor_binds_ordered_family_callbacks() -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _run_ordered_local_batch(
            self,
            items: list[str],
            worker: Callable[[str], list[dict[str, Any]]],
            *,
            default_factory: Callable[[], list[dict[str, Any]]],
        ) -> list[list[dict[str, Any]]]:
            calls.append(("batch", tuple(items), default_factory()))
            return [worker(items[0]), worker(items[1])]

        def _artifact_url_cloud_asset_family_entries(
            self,
            family: str,
            *,
            url: str,
            hostname: str,
            source: str,
        ) -> list[dict[str, Any]]:
            calls.append(("family", family, url, hostname, source))
            return [{"asset_family": family, "hostname": hostname, "source": source}]

    entries = artifact_url_cloud_asset_entries_for_processor(
        _Adapter(),
        "https://Bucket.S3.AmazonAWS.com/path",
        source="artifact_url_extract",
    )

    assert len(entries) == 2
    assert entries[0]["hostname"] == "bucket.s3.amazonaws.com"
    assert entries[1]["source"] == "artifact_url_extract"
    assert calls[0][0] == "batch"
    families = calls[0][1]
    assert isinstance(families, tuple)
    assert calls[0][2] == []
    assert calls[1:] == [
        (
            "family",
            families[0],
            "https://Bucket.S3.AmazonAWS.com/path",
            "bucket.s3.amazonaws.com",
            "artifact_url_extract",
        ),
        (
            "family",
            families[1],
            "https://Bucket.S3.AmazonAWS.com/path",
            "bucket.s3.amazonaws.com",
            "artifact_url_extract",
        ),
    ]


def test_artifact_url_cloud_asset_family_entries_for_processor_binds_matcher_patterns() -> None:
    empty_matcher = re.compile(r"$.")
    common = {
        "do_spaces_url_patterns": (empty_matcher,),
        "gcs_url_patterns": (empty_matcher,),
        "azure_blob_url_patterns": (empty_matcher,),
        "azure_static_website_host_re": empty_matcher,
        "cloudflare_workers_host_re": empty_matcher,
        "cloudflare_pages_host_re": empty_matcher,
        "cloudflare_r2_host_re": empty_matcher,
    }

    assert artifact_url_cloud_asset_family_entries_for_processor(
        "aws_s3",
        url="https://MyBucket.s3.amazonaws.com/app.js",
        hostname="mybucket.s3.amazonaws.com",
        source="artifact_url_extract",
        aws_s3_url_patterns=(re.compile(r"https?://([^.]+)\.s3\.amazonaws\.com", re.IGNORECASE),),
        azure_key_vault_url_re=empty_matcher,
        **common,
    ) == [{"asset_type": "aws_s3", "identifier": "mybucket", "source": "artifact_url_extract"}]

    assert artifact_url_cloud_asset_family_entries_for_processor(
        "azure_key_vault",
        url="https://Vault-01.vault.azure.net/secrets/ApiKey",
        hostname="vault-01.vault.azure.net",
        source="artifact_url_extract",
        aws_s3_url_patterns=(empty_matcher,),
        azure_key_vault_url_re=re.compile(
            r"https?://(?P<vault>[a-z0-9][a-z0-9-]{1,22}[a-z0-9])\.vault\.azure\.net"
            r"(?:/(?P<family>keys|secrets|certificates)/(?P<name>[^/?#\s\"'`<>,;)\]}]+))?",
            re.IGNORECASE,
        ),
        **common,
    ) == [
        {
            "asset_type": "azure_key_vault",
            "identifier": "vault-01/secrets/apikey",
            "source": "artifact_url_extract",
        }
    ]


def test_store_social_profile_url_pivots_for_processor_binds_storage_callbacks() -> None:
    calls: list[tuple[Any, ...]] = []
    con = object()
    pivot_entries = [
        {
            "seed_value": "acme",
            "seed_type": "username",
            "seed_confidence": 0.78,
            "relation_type": "derived_from",
            "relation_confidence": 0.78,
            "relation_metadata": {"platform": "github"},
        }
    ]

    class _Adapter:
        def _lookup_seed_id(self, candidate_con: Any, seed_value: str, seed_type: str) -> int | None:
            calls.append(("lookup", candidate_con, seed_value, seed_type))
            return {
                ("https://github.com/acme", "url"): 11,
                ("acme", "username"): 12,
            }.get((seed_value, seed_type))

        def _artifact_url_social_pivot_entries(
            self,
            url: str,
            *,
            relation_metadata: dict[str, Any] | None,
        ) -> list[dict[str, Any]]:
            calls.append(("extract", url, relation_metadata))
            return pivot_entries

        def _run_ordered_local_batch(
            self,
            items: list[Any],
            worker: Callable[[Any], Any],
            *,
            default_factory: Callable[[], Any],
        ) -> list[Any]:
            calls.append(("batch", list(items), default_factory()))
            return [worker(item) for item in items]

        def _social_profile_url_pivot_entry(self, pivot_entry: tuple[int, dict[str, Any]]) -> dict[str, Any]:
            calls.append(("pivot_entry", pivot_entry))
            return dict(pivot_entry[1])

        def _insert_seed(
            self,
            candidate_con: Any,
            seed_value: str,
            seed_type: str,
            *,
            source: str,
            confidence: float,
            depth: int,
        ) -> bool:
            calls.append(("insert_seed", candidate_con, seed_value, seed_type, source, confidence, depth))
            return True

        def _insert_relation(
            self,
            candidate_con: Any,
            source_seed_id: int,
            target_seed_id: int,
            relation_type: str,
            confidence: float,
            metadata: dict[str, Any],
        ) -> None:
            calls.append(
                (
                    "insert_relation",
                    candidate_con,
                    source_seed_id,
                    target_seed_id,
                    relation_type,
                    confidence,
                    metadata,
                )
            )

    store_social_profile_url_pivots_for_processor(
        _Adapter(),
        con,
        7,
        "https://github.com/acme",
        seed_type="url",
        relation_metadata={"source_file": "links.txt"},
        depth=3,
    )

    assert calls == [
        ("lookup", con, "https://github.com/acme", "url"),
        ("extract", "https://github.com/acme", {"source_file": "links.txt"}),
        ("lookup", con, "https://github.com/acme", "url"),
        ("batch", list(enumerate(pivot_entries)), None),
        ("pivot_entry", (0, pivot_entries[0])),
        ("insert_seed", con, "acme", "username", "artifact", 0.78, 3),
        ("lookup", con, "acme", "username"),
        ("insert_relation", con, 11, 12, "derived_from", 0.78, {"platform": "github"}),
    ]


def test_store_social_profile_url_pivots_for_processor_skips_lookup_miss_before_extracting() -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _lookup_seed_id(self, candidate_con: Any, seed_value: str, seed_type: str) -> int | None:
            calls.append(("lookup", candidate_con, seed_value, seed_type))
            return None

        def _artifact_url_social_pivot_entries(self, *_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
            calls.append(("extract",))
            return []

    con = object()
    store_social_profile_url_pivots_for_processor(
        _Adapter(),
        con,
        7,
        "https://github.com/acme",
        seed_type="url",
    )

    assert calls == [("lookup", con, "https://github.com/acme", "url")]


def test_store_cloud_assets_from_url_entries_for_processor_binds_storage_callbacks() -> None:
    calls: list[tuple[Any, ...]] = []
    con = object()
    generated_entries = [
        {"asset_type": "aws_s3", "identifier": "bucket", "source": "artifact_url_extract"}
    ]

    class _Adapter:
        def _artifact_url_cloud_asset_entries(self, url: str, *, source: str) -> list[dict[str, Any]]:
            calls.append(("extract", url, source))
            return generated_entries

        def _run_ordered_local_batch(
            self,
            items: list[Any],
            worker: Callable[[Any], Any],
            *,
            default_factory: Callable[[], Any],
        ) -> list[Any]:
            calls.append(("batch", list(items), default_factory()))
            return [worker(item) for item in items]

        def _cloud_asset_url_entry(self, cloud_asset_entry: tuple[int, dict[str, Any]]) -> dict[str, str]:
            calls.append(("entry", cloud_asset_entry))
            return {
                "asset_type": str(cloud_asset_entry[1]["asset_type"]),
                "identifier": str(cloud_asset_entry[1]["identifier"]),
                "source": str(cloud_asset_entry[1]["source"]),
            }

        def _artifact_cloud_asset_metadata(
            self,
            candidate_con: Any,
            *,
            source_seed_id: int | None,
            relation_metadata: dict[str, Any] | None,
            artifact_context: dict[str, Any] | None,
        ) -> dict[str, Any]:
            calls.append(("metadata", candidate_con, source_seed_id, relation_metadata, artifact_context))
            return {"source_seed_id": source_seed_id, "relation_metadata": relation_metadata}

        def _store_cloud_asset_reference(
            self,
            candidate_con: Any,
            *,
            asset_type: str,
            identifier: str,
            source: str,
            metadata: dict[str, Any],
        ) -> None:
            calls.append(("store", candidate_con, asset_type, identifier, source, metadata))

    relation_metadata = {"rule": "artifact_url_extract"}
    store_cloud_assets_from_url_entries_for_processor(
        _Adapter(),
        con,
        "https://bucket.s3.amazonaws.com/app.js",
        source="artifact_url_extract",
        source_seed_id=9,
        relation_metadata=relation_metadata,
    )

    assert calls == [
        ("extract", "https://bucket.s3.amazonaws.com/app.js", "artifact_url_extract"),
        ("batch", list(enumerate(generated_entries)), None),
        ("entry", (0, generated_entries[0])),
        ("metadata", con, 9, relation_metadata, None),
        (
            "store",
            con,
            "aws_s3",
            "bucket",
            "artifact_url_extract",
            {"source_seed_id": 9, "relation_metadata": relation_metadata},
        ),
    ]


def test_artifact_social_profile_url_pivot_entry_for_processor_normalizes_metadata() -> None:
    assert artifact_social_profile_url_pivot_entry_for_processor(
        (
            0,
            {
                "seed_value": " acme ",
                "seed_type": " username ",
                "seed_confidence": "0.78",
                "relation_type": " derived_from ",
                "relation_confidence": "0.79",
                "relation_metadata": {"platform": "github"},
            },
        )
    ) == {
        "seed_value": "acme",
        "seed_type": "username",
        "seed_confidence": 0.78,
        "relation_type": "derived_from",
        "relation_confidence": 0.79,
        "relation_metadata": {"platform": "github"},
    }
    assert artifact_social_profile_url_pivot_entry_for_processor((1, "not-a-dict")) is None  # type: ignore[arg-type]


def test_artifact_cloud_asset_url_entry_for_processor_normalizes_and_suppresses_invalid_entries() -> None:
    assert artifact_cloud_asset_url_entry_for_processor(
        (
            0,
            {
                "asset_type": " aws_s3 ",
                "identifier": " bucket ",
                "source": " artifact_url_extract ",
            },
        )
    ) == {
        "asset_type": "aws_s3",
        "identifier": "bucket",
        "source": "artifact_url_extract",
    }
    assert artifact_cloud_asset_url_entry_for_processor(
        (1, {"asset_type": "aws_s3", "identifier": "", "source": "artifact_url_extract"})
    ) is None
    assert artifact_cloud_asset_url_entry_for_processor((2, "not-a-dict")) is None  # type: ignore[arg-type]


def test_store_artifact_cloud_asset_reference_for_processor_binds_audit_callback(monkeypatch: Any) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _audit_artifact_lineage(
            self,
            con: Any,
            *,
            action: str,
            target: str,
            result: str,
        ) -> None:
            calls.append(("audit", con, action, target, result))

    def _store_reference(
        con: Any,
        engagement_id: int,
        *,
        asset_type: str,
        identifier: str,
        source: str,
        metadata: dict[str, Any] | None,
        audit_artifact_lineage: Callable[..., None],
    ) -> None:
        calls.append(("store", con, engagement_id, asset_type, identifier, source, metadata))
        audit_artifact_lineage(
            action="cloud_asset_reference",
            target=f"{asset_type}:{identifier}",
            result="stored",
        )

    monkeypatch.setattr(runtime, "store_artifact_cloud_asset_reference", _store_reference)

    con = object()
    metadata = {"rule": "artifact_url_extract"}
    store_artifact_cloud_asset_reference_for_processor(
        _Adapter(),
        con,
        7,
        asset_type="aws_s3",
        identifier="bucket",
        source="artifact_url_extract",
        metadata=metadata,
    )

    assert calls == [
        ("store", con, 7, "aws_s3", "bucket", "artifact_url_extract", metadata),
        ("audit", con, "cloud_asset_reference", "aws_s3:bucket", "stored"),
    ]


def test_firebase_match_entry_for_processor_normalizes_project_and_rtdb_url() -> None:
    assert firebase_match_entry_for_processor(
        ("https://Acme.firebaseio.com/path", " Acme ")
    ) == {
        "project_id": "acme",
        "rtdb_url": "https://Acme.firebaseio.com/path",
    }
    assert firebase_match_entry_for_processor(
        ("https://acme.firebaseapp.com", "Acme")
    ) == {
        "project_id": "acme",
        "rtdb_url": None,
    }
    assert firebase_match_entry_for_processor(("https://firebase.example", "")) is None


def test_extract_firebase_from_text_for_processor_binds_matchers_and_project_factory() -> None:
    calls: list[tuple[Any, ...]] = []
    text = (
        "apiKey=KEY123 storageBucket: acme.appspot.com "
        "https://Acme.firebaseio.com https://beta.firebaseapp.com https://ACME.firebaseapp.com"
    )

    def _encrypt(secret: str) -> str:
        calls.append(("encrypt", secret))
        return f"enc:{secret}"

    def _normalize_storage_bucket(bucket: str) -> str:
        calls.append(("bucket", bucket))
        return bucket.lower()

    def _run_ordered_batch(
        items: list[Any],
        worker: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        calls.append(("batch", list(items), default_factory()))
        return [worker(item) for item in items]

    def _match_entry(candidate: tuple[str, str]) -> dict[str, Any] | None:
        calls.append(("match", candidate))
        return firebase_match_entry_for_processor(candidate)

    def _project_factory(**kwargs: Any) -> dict[str, Any]:
        calls.append(("project", kwargs))
        return dict(kwargs)

    projects = extract_firebase_from_text_for_processor(
        text,
        "artifact.js",
        "artifact.js#text",
        firebase_url_patterns=(
            re.compile(r"https?://([a-z0-9-]+)\.firebaseio\.com", re.IGNORECASE),
            re.compile(r"https?://([a-z0-9-]+)\.firebaseapp\.com", re.IGNORECASE),
        ),
        firebase_api_key_re=re.compile(r"KEY\d+"),
        firebase_storage_bucket_re=re.compile(r"storageBucket:\s*([a-z0-9.-]+)", re.IGNORECASE),
        encrypt_secret_material=_encrypt,
        normalize_storage_bucket=_normalize_storage_bucket,
        run_ordered_batch=_run_ordered_batch,
        firebase_match_entry=_match_entry,
        firebase_project_factory=_project_factory,
    )

    assert projects == [
        {
            "project_id": "acme",
            "api_key_enc": "enc:KEY123",
            "rtdb_url": "https://Acme.firebaseio.com",
            "bundle_id": None,
            "source_file": "artifact.js",
            "extract_path": "artifact.js#text",
            "storage_bucket": "acme.appspot.com",
        },
        {
            "project_id": "beta",
            "api_key_enc": "enc:KEY123",
            "rtdb_url": "https://Acme.firebaseio.com",
            "bundle_id": None,
            "source_file": "artifact.js",
            "extract_path": "artifact.js#text",
            "storage_bucket": "acme.appspot.com",
        },
    ]
    assert calls[:3] == [
        ("encrypt", "KEY123"),
        ("bucket", "acme.appspot.com"),
        (
            "batch",
            [
                ("https://Acme.firebaseio.com", "Acme"),
                ("https://beta.firebaseapp.com", "beta"),
                ("https://ACME.firebaseapp.com", "ACME"),
            ],
            None,
        ),
    ]
    assert ("match", ("https://ACME.firebaseapp.com", "ACME")) in calls


def test_terraform_state_payload_family_for_processor_dispatches_family_callbacks() -> None:
    calls: list[tuple[Any, ...]] = []

    def _structured(
        text: str,
        *,
        source_file: str,
        member_name: str,
    ) -> list[tuple[str, str, str]]:
        calls.append(("structured", text, source_file, member_name))
        return [(source_file, f"{member_name}#tfstate-structured", "structured payload")]

    def _text(
        text: str,
        *,
        source_file: str,
        member_name: str,
    ) -> list[tuple[str, str, str]]:
        calls.append(("text", text, source_file, member_name))
        return [(source_file, member_name, text)]

    common = {
        "text": "terraform state",
        "source_file": "terraform.tfstate",
        "member_name": "state.json",
        "extract_terraform_state_structured_payloads": _structured,
        "extract_terraform_state_text_payloads": _text,
    }

    assert terraform_state_payload_family_for_processor("structured", **common) == [
        ("terraform.tfstate", "state.json#tfstate-structured", "structured payload")
    ]
    assert terraform_state_payload_family_for_processor("text", **common) == [
        ("terraform.tfstate", "state.json", "terraform state")
    ]
    assert terraform_state_payload_family_for_processor("unknown", **common) == []
    assert calls == [
        ("structured", "terraform state", "terraform.tfstate", "state.json"),
        ("text", "terraform state", "terraform.tfstate", "state.json"),
    ]


def test_terraform_state_text_payloads_for_processor_preserves_text_payload() -> None:
    assert terraform_state_text_payloads_for_processor(
        "terraform state",
        source_file="terraform.tfstate",
        member_name="state.json",
    ) == [("terraform.tfstate", "state.json", "terraform state")]
    assert terraform_state_text_payloads_for_processor(
        "   ",
        source_file="terraform.tfstate",
        member_name="state.json",
    ) == []


def test_terraform_state_structured_payloads_for_processor_wraps_nonempty_structured_payload() -> None:
    calls: list[str] = []

    def _structured_payload_text(text: str) -> str:
        calls.append(text)
        return "s3://bucket" if text.strip() else ""

    assert terraform_state_structured_payloads_for_processor(
        "terraform state",
        source_file="terraform.tfstate",
        member_name="state.json",
        terraform_state_structured_payload_text=_structured_payload_text,
    ) == [("terraform.tfstate", "state.json#tfstate-structured", "s3://bucket")]
    assert terraform_state_structured_payloads_for_processor(
        "  ",
        source_file="terraform.tfstate",
        member_name="state.json",
        terraform_state_structured_payload_text=_structured_payload_text,
    ) == []
    assert calls == ["terraform state", "  "]


def test_terraform_state_structured_payload_text_for_processor_orders_and_dedupes_candidates() -> None:
    calls: list[tuple[Any, ...]] = []

    def _json_loads(text: str) -> Any:
        calls.append(("json", text))
        return {"resources": [{"type": "aws_s3_bucket"}, {"type": "google_storage_bucket"}]}

    def _iter_values(payload: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
        calls.append(("iter", payload))
        return [
            ("aws_s3_bucket", {"bucket": "acme"}),
            ("google_storage_bucket", {"name": "Acme"}),
            ("empty", {}),
        ]

    def _resource_candidate(resource_job: tuple[str, dict[str, Any]]) -> str:
        calls.append(("candidate", resource_job))
        resource_type, values = resource_job
        if resource_type == "aws_s3_bucket":
            return f"s3://{values['bucket']}"
        if resource_type == "google_storage_bucket":
            return f"S3://{values['name']}"
        return ""

    def _structured_entry(candidate_entry: tuple[int, str]) -> tuple[str, str] | None:
        calls.append(("entry", candidate_entry))
        _index, candidate = candidate_entry
        value = str(candidate or "").strip()
        if not value:
            return None
        return value, value.lower()

    def _run_ordered_batch(
        items: list[Any],
        worker: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        calls.append(("batch", list(items), default_factory()))
        return [worker(item) for item in items]

    assert terraform_state_structured_payload_text_for_processor(
        '{"resources":[]}',
        safe_json_loads=_json_loads,
        iter_terraform_state_resource_values=_iter_values,
        terraform_state_resource_candidate=_resource_candidate,
        terraform_structured_candidate_entry=_structured_entry,
        run_ordered_batch=_run_ordered_batch,
    ) == "s3://acme"

    assert calls[0] == ("json", '{"resources":[]}')
    assert ("entry", (2, "")) in calls


def test_terraform_state_structured_payload_text_for_processor_suppresses_non_object_json() -> None:
    assert terraform_state_structured_payload_text_for_processor(
        "[]",
        safe_json_loads=lambda _text: [],
        iter_terraform_state_resource_values=lambda _payload: [("aws_s3_bucket", {})],
        terraform_state_resource_candidate=lambda _resource_job: "s3://bucket",
        terraform_structured_candidate_entry=lambda _candidate_entry: ("s3://bucket", "s3://bucket"),
        run_ordered_batch=lambda items, worker, *, default_factory: [worker(item) for item in items],
    ) == ""


def test_terraform_block_assignments_for_processor_orders_and_overwrites_assignments() -> None:
    calls: list[tuple[Any, ...]] = []

    def _assignment_entry(line_entry: tuple[int, str]) -> tuple[str, str] | None:
        calls.append(("entry", line_entry))
        _index, line = line_entry
        if "=" not in line:
            return None
        key, value = line.split("=", 1)
        return key.strip().lower(), value.strip().strip('"')

    def _run_ordered_batch(
        items: list[Any],
        worker: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        calls.append(("batch", list(items), default_factory()))
        return [worker(item) for item in items]

    assert terraform_block_assignments_for_processor(
        'name = "old"\nignored\nname = "new"\nbucket = "assets"',
        terraform_assignment_line_entry=_assignment_entry,
        run_ordered_batch=_run_ordered_batch,
    ) == {"name": "new", "bucket": "assets"}

    assert calls[0] == (
        "batch",
        [
            (0, 'name = "old"'),
            (1, "ignored"),
            (2, 'name = "new"'),
            (3, 'bucket = "assets"'),
        ],
        None,
    )
    assert ("entry", (1, "ignored")) in calls


def test_terraform_block_assignments_for_processor_suppresses_invalid_entries() -> None:
    def _run_ordered_batch(
        items: list[Any],
        worker: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        return [
            None,
            ("too", "many", "values"),
            worker((2, 'region = "us-east-1"')),
        ]

    assert terraform_block_assignments_for_processor(
        "ignored",
        terraform_assignment_line_entry=lambda _line_entry: ("region", "us-east-1"),
        run_ordered_batch=_run_ordered_batch,
    ) == {"region": "us-east-1"}


def test_terraform_assignment_line_entry_for_processor_parses_quoted_assignment() -> None:
    assert terraform_assignment_line_entry_for_processor((7, '  Bucket_Name = " Assets "  ')) == (
        "bucket_name",
        "Assets",
    )


def test_terraform_assignment_line_entry_for_processor_suppresses_non_assignments() -> None:
    assert terraform_assignment_line_entry_for_processor((0, "")) is None
    assert terraform_assignment_line_entry_for_processor((1, "# name = \"ignored\"")) is None
    assert terraform_assignment_line_entry_for_processor((2, "// name = \"ignored\"")) is None
    assert terraform_assignment_line_entry_for_processor((3, "/* name = \"ignored\"")) is None
    assert terraform_assignment_line_entry_for_processor((4, "* name = \"ignored\"")) is None
    assert terraform_assignment_line_entry_for_processor((5, "name = value")) is None
    assert terraform_assignment_line_entry_for_processor((6, 'name = ""')) is None


def test_iter_terraform_text_blocks_for_processor_collects_nested_blocks() -> None:
    pattern = re.compile(r'^\s*resource\s+"([^"]+)"\s+"[^"]+"\s*\{')

    assert iter_terraform_text_blocks_for_processor(
        '\n'.join(
            [
                'variable "ignored" {}',
                'resource "AWS_S3_BUCKET" "assets" {',
                '  bucket = "assets"',
                '  lifecycle {',
                '    prevent_destroy = true',
                '  }',
                '}',
                'resource "google_storage_bucket" "logs" {',
                '  name = "logs"',
                '}',
            ]
        ),
        terraform_block_start_pattern=pattern,
    ) == [
        (
            "aws_s3_bucket",
            '\n'.join(
                [
                    'resource "AWS_S3_BUCKET" "assets" {',
                    '  bucket = "assets"',
                    '  lifecycle {',
                    '    prevent_destroy = true',
                    '  }',
                    '}',
                ]
            ),
        ),
        (
            "google_storage_bucket",
            '\n'.join(
                [
                    'resource "google_storage_bucket" "logs" {',
                    '  name = "logs"',
                    '}',
                ]
            ),
        ),
    ]


def test_iter_terraform_text_blocks_for_processor_keeps_unclosed_block() -> None:
    pattern = re.compile(r'^\s*resource\s+"([^"]+)"\s+"[^"]+"\s*\{')

    assert iter_terraform_text_blocks_for_processor(
        'resource "aws_s3_bucket" "assets" {\n  bucket = "assets"',
        terraform_block_start_pattern=pattern,
    ) == [("aws_s3_bucket", 'resource "aws_s3_bucket" "assets" {\n  bucket = "assets"')]


def test_terraform_structured_candidate_entry_for_processor_normalizes_candidate() -> None:
    assert terraform_structured_candidate_entry_for_processor((3, "  S3://Bucket  ")) == (
        "S3://Bucket",
        "s3://bucket",
    )


def test_terraform_structured_candidate_entry_for_processor_suppresses_empty_candidate() -> None:
    assert terraform_structured_candidate_entry_for_processor((0, "")) is None
    assert terraform_structured_candidate_entry_for_processor((1, "   ")) is None
    assert terraform_structured_candidate_entry_for_processor((2, None)) is None  # type: ignore[arg-type]


def test_terraform_text_structured_payload_text_for_processor_orders_adds_and_dedupes_candidates() -> None:
    calls: list[tuple[Any, ...]] = []

    def _iter_blocks(text: str) -> list[tuple[str, str]]:
        calls.append(("iter", text))
        return [("aws_s3_bucket", "bucket block"), ("google_storage_bucket", "gcs block")]

    def _block_candidate(block: tuple[str, str]) -> str:
        calls.append(("block", block))
        resource_type, _block_text = block
        if resource_type == "aws_s3_bucket":
            return "s3://assets"
        return "GS://Logs"

    def _entry(candidate_entry: tuple[int, str]) -> tuple[str, str] | None:
        calls.append(("entry", candidate_entry))
        _index, candidate = candidate_entry
        value = str(candidate or "").strip()
        if not value:
            return None
        return value, value.lower()

    def _run_ordered_batch(
        items: list[Any],
        worker: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        calls.append(("batch", list(items), default_factory()))
        return [worker(item) for item in items]

    assert terraform_text_structured_payload_text_for_processor(
        "terraform text",
        source_hint="terragrunt.hcl",
        iter_terraform_text_blocks=_iter_blocks,
        terraform_text_block_candidate=_block_candidate,
        terraform_backend_config_candidates=lambda text: ["s3://assets", f"s3://{text}"],
        terragrunt_remote_state_backend_candidates=lambda _text: ["GS://Logs", "az://state"],
        terraform_structured_candidate_entry=_entry,
        looks_like_terraform_backend_config_name=lambda hint: hint == "backend.tfvars",
        looks_like_terragrunt_config_name=lambda hint: hint == "terragrunt.hcl",
        run_ordered_batch=_run_ordered_batch,
    ) == "s3://assets\nGS://Logs\ns3://terraform text\naz://state"

    assert calls[0] == ("iter", "terraform text")
    assert ("entry", (5, "az://state")) in calls


def test_terraform_text_structured_payload_text_for_processor_skips_backend_candidates_for_regular_source() -> None:
    assert terraform_text_structured_payload_text_for_processor(
        "terraform text",
        source_hint="main.tf",
        iter_terraform_text_blocks=lambda _text: [],
        terraform_text_block_candidate=lambda _block: "s3://assets",
        terraform_backend_config_candidates=lambda _text: ["s3://backend"],
        terragrunt_remote_state_backend_candidates=lambda _text: ["s3://terragrunt"],
        terraform_structured_candidate_entry=lambda _entry: ("s3://value", "s3://value"),
        looks_like_terraform_backend_config_name=lambda _hint: False,
        looks_like_terragrunt_config_name=lambda _hint: False,
        run_ordered_batch=lambda items, worker, *, default_factory: [worker(item) for item in items],
    ) == ""


def test_terraform_text_block_candidate_for_processor_extracts_storage_candidates() -> None:
    cases = [
        (("aws_s3_bucket_public_access_block", "aws"), {"bucket": "Assets.Bucket"}, "s3://assets.bucket"),
        (
            ("digitalocean_spaces_bucket", "do"),
            {"name": "Media", "region": "sgp1"},
            "https://media.sgp1.digitaloceanspaces.com",
        ),
        (("google_storage_bucket_iam_member", "gcs"), {"bucket": "Logs_Bucket"}, "gs://logs_bucket"),
        (
            ("azurerm_storage_container", "azure"),
            {"name": "snapshots", "storage_account_name": "acct123"},
            "https://acct123.blob.core.windows.net/snapshots",
        ),
    ]

    for block_job, assignments, expected in cases:
        assert terraform_text_block_candidate_for_processor(
            block_job,
            terraform_block_assignments=lambda _block_text, assignments=assignments: assignments,
        ) == expected


def test_terraform_text_block_candidate_for_processor_extracts_firebase_candidate() -> None:
    assert terraform_text_block_candidate_for_processor(
        ("google_firebase_web_app", "firebase"),
        terraform_block_assignments=lambda _block_text: {"project_id": "Acme-App"},
    ) == "https://acme-app.firebaseio.com"


def test_terraform_text_block_candidate_for_processor_suppresses_invalid_candidates() -> None:
    assert terraform_text_block_candidate_for_processor(
        ("aws_s3_bucket", "missing"),
        terraform_block_assignments=lambda _block_text: {},
    ) == ""
    assert terraform_text_block_candidate_for_processor(
        ("aws_s3_bucket", "invalid"),
        terraform_block_assignments=lambda _block_text: {"bucket": "NO"},
    ) == ""
    assert terraform_text_block_candidate_for_processor(
        ("digitalocean_spaces_bucket", "invalid"),
        terraform_block_assignments=lambda _block_text: {"name": "media", "region": "!"},
    ) == ""
    assert terraform_text_block_candidate_for_processor(
        ("unknown_resource", "unknown"),
        terraform_block_assignments=lambda _block_text: {"name": "assets"},
    ) == ""


def test_digitalocean_spaces_url_from_endpoint_for_processor_normalizes_spaces_endpoint() -> None:
    pattern = re.compile(r"(?P<region>[a-z0-9-]+)\.digitaloceanspaces\.com")

    assert digitalocean_spaces_url_from_endpoint_for_processor(
        " Media ",
        "https://sgp1.digitaloceanspaces.com/",
        do_spaces_endpoint_host_pattern=pattern,
    ) == "https://media.sgp1.digitaloceanspaces.com"
    assert digitalocean_spaces_url_from_endpoint_for_processor(
        "media",
        "nyc3.digitaloceanspaces.com",
        do_spaces_endpoint_host_pattern=pattern,
    ) == "https://media.nyc3.digitaloceanspaces.com"


def test_digitalocean_spaces_url_from_endpoint_for_processor_suppresses_invalid_parts() -> None:
    pattern = re.compile(r"(?P<region>[a-z0-9-]+)\.digitaloceanspaces\.com")

    assert digitalocean_spaces_url_from_endpoint_for_processor(
        "no",
        "sgp1.digitaloceanspaces.com",
        do_spaces_endpoint_host_pattern=pattern,
    ) == ""
    assert digitalocean_spaces_url_from_endpoint_for_processor(
        "media",
        "",
        do_spaces_endpoint_host_pattern=pattern,
    ) == ""
    assert digitalocean_spaces_url_from_endpoint_for_processor(
        "media",
        "example.com",
        do_spaces_endpoint_host_pattern=pattern,
    ) == ""


def test_azure_blob_url_from_parts_for_processor_normalizes_parts() -> None:
    assert (
        azure_blob_url_from_parts_for_processor(" Acct123 ", " Snapshots ")
        == "https://acct123.blob.core.windows.net/snapshots"
    )


def test_azure_blob_url_from_parts_for_processor_suppresses_invalid_parts() -> None:
    assert azure_blob_url_from_parts_for_processor("ab", "snapshots") == ""
    assert azure_blob_url_from_parts_for_processor("acct123", "") == ""
    assert azure_blob_url_from_parts_for_processor("acct123", "snap/shots") == ""
    assert azure_blob_url_from_parts_for_processor("acct123", "snapshots?x=1") == ""
    assert azure_blob_url_from_parts_for_processor("acct123", "snapshots#frag") == ""


def test_azure_blob_parts_from_composite_name_for_processor_extracts_outer_parts() -> None:
    assert azure_blob_parts_from_composite_name_for_processor(" Account / middle / Container ") == (
        "account",
        "container",
    )
    assert azure_blob_parts_from_composite_name_for_processor("acct/path/to/snapshots") == (
        "acct",
        "snapshots",
    )


def test_azure_blob_parts_from_composite_name_for_processor_suppresses_short_values() -> None:
    assert azure_blob_parts_from_composite_name_for_processor("") == ("", "")
    assert azure_blob_parts_from_composite_name_for_processor("acct/container") == ("", "")
    assert azure_blob_parts_from_composite_name_for_processor("acct//container") == ("", "")


def test_iac_resource_azure_blob_candidate_for_processor_uses_account_and_container_fields() -> None:
    calls: list[tuple[Any, ...]] = []
    lookup = {"account": "Acct123", "container": "Snapshots", "name": "ignored/path/value"}

    def _ref(mapping: dict[str, Any], *keys: str) -> Any:
        calls.append(("ref", keys))
        for key in keys:
            if key in mapping:
                return mapping[key]
        return ""

    def _url(account: str, container: str) -> str:
        calls.append(("url", account, container))
        return f"https://{account}.blob.core.windows.net/{container}" if account and container else ""

    assert (
        iac_resource_azure_blob_candidate_for_processor(
            "azurerm_storage_container",
            lookup,
            yaml_ref_value=_ref,
            azure_blob_url_from_parts=_url,
            azure_blob_parts_from_composite_name=lambda _value: ("fallback", "container"),
        )
        == "https://acct123.blob.core.windows.net/snapshots"
    )
    assert ("url", "acct123", "snapshots") in calls


def test_iac_resource_azure_blob_candidate_for_processor_uses_composite_name_fallback() -> None:
    calls: list[tuple[Any, ...]] = []
    lookup = {"name": "Acct123/providers/blobServices/Snapshots"}

    def _ref(mapping: dict[str, Any], *keys: str) -> Any:
        for key in keys:
            if key in mapping:
                return mapping[key]
        return ""

    def _url(account: str, container: str) -> str:
        calls.append(("url", account, container))
        if account == "acct123" and container == "snapshots":
            return "https://acct123.blob.core.windows.net/snapshots"
        return ""

    assert (
        iac_resource_azure_blob_candidate_for_processor(
            "microsoft.storage/storageaccounts/blobservices/containers",
            lookup,
            yaml_ref_value=_ref,
            azure_blob_url_from_parts=_url,
            azure_blob_parts_from_composite_name=azure_blob_parts_from_composite_name_for_processor,
        )
        == "https://acct123.blob.core.windows.net/snapshots"
    )
    assert calls == [("url", "", "acct123/providers/blobservices/snapshots"), ("url", "acct123", "snapshots")]


def test_iac_resource_azure_blob_candidate_for_processor_suppresses_non_azure_types() -> None:
    assert (
        iac_resource_azure_blob_candidate_for_processor(
            "aws::s3::bucket",
            {"name": "acct/providers/container"},
            yaml_ref_value=lambda mapping, *keys: mapping.get(keys[0], ""),
            azure_blob_url_from_parts=lambda _account, _container: "https://acct.blob.core.windows.net/container",
            azure_blob_parts_from_composite_name=lambda _value: ("acct", "container"),
        )
        == ""
    )


def test_iac_resource_firebase_candidate_for_processor_uses_project_lookup_order() -> None:
    calls: list[tuple[Any, ...]] = []
    lookup = {"project_id": "Acme-App", "name": "ignored"}

    def _ref(mapping: dict[str, Any], *keys: str) -> Any:
        calls.append(("ref", keys))
        for key in keys:
            if key in mapping:
                return mapping[key]
        return ""

    def _valid_project(value: Any) -> str:
        calls.append(("valid", value))
        return str(value or "").strip().lower()

    assert (
        iac_resource_firebase_candidate_for_processor(
            "google.firebase/project",
            lookup,
            yaml_ref_value=_ref,
            yaml_valid_project_ref=_valid_project,
        )
        == "https://acme-app.firebaseio.com"
    )
    assert calls == [
        ("ref", ("projectId", "project-id", "project_id", "project", "name")),
        ("valid", "Acme-App"),
    ]


def test_iac_resource_firebase_candidate_for_processor_suppresses_non_firebase_and_invalid_refs() -> None:
    assert (
        iac_resource_firebase_candidate_for_processor(
            "aws::s3::bucket",
            {"project_id": "acme"},
            yaml_ref_value=lambda mapping, *keys: mapping.get(keys[0], ""),
            yaml_valid_project_ref=lambda value: str(value or ""),
        )
        == ""
    )
    assert (
        iac_resource_firebase_candidate_for_processor(
            "firebase",
            {"project_id": "NO"},
            yaml_ref_value=lambda mapping, *keys: mapping.get("project_id", ""),
            yaml_valid_project_ref=lambda _value: "",
        )
        == ""
    )


def test_iac_resource_supabase_candidate_for_processor_uses_ref_lookup_order() -> None:
    calls: list[tuple[Any, ...]] = []
    lookup = {"project_ref": "Acme-Ref", "name": "ignored"}

    def _ref(mapping: dict[str, Any], *keys: str) -> Any:
        calls.append(("ref", keys))
        for key in keys:
            if key in mapping:
                return mapping[key]
        return ""

    def _valid_project(value: Any) -> str:
        calls.append(("valid", value))
        return str(value or "").strip().lower()

    assert (
        iac_resource_supabase_candidate_for_processor(
            "supabase_project",
            lookup,
            yaml_ref_value=_ref,
            yaml_valid_project_ref=_valid_project,
        )
        == "https://acme-ref.supabase.co"
    )
    assert calls == [
        ("ref", ("projectRef", "project-ref", "project_ref", "ref", "name")),
        ("valid", "Acme-Ref"),
    ]


def test_iac_resource_supabase_candidate_for_processor_suppresses_non_supabase_and_invalid_refs() -> None:
    assert (
        iac_resource_supabase_candidate_for_processor(
            "firebase",
            {"project_ref": "acme"},
            yaml_ref_value=lambda mapping, *keys: mapping.get(keys[0], ""),
            yaml_valid_project_ref=lambda value: str(value or ""),
        )
        == ""
    )
    assert (
        iac_resource_supabase_candidate_for_processor(
            "supabase",
            {"project_ref": "NO"},
            yaml_ref_value=lambda mapping, *keys: mapping.get("project_ref", ""),
            yaml_valid_project_ref=lambda _value: "",
        )
        == ""
    )


def test_iac_resource_s3_candidate_for_processor_uses_bucket_lookup_order() -> None:
    calls: list[tuple[Any, ...]] = []
    lookup = {"bucket_name": "Assets.Bucket", "name": "ignored"}

    def _ref(mapping: dict[str, Any], *keys: str) -> Any:
        calls.append(("ref", keys))
        for key in keys:
            if key in mapping:
                return mapping[key]
        return ""

    def _valid_bucket(value: Any) -> str:
        calls.append(("valid", value))
        return str(value or "").strip().lower()

    assert (
        iac_resource_s3_candidate_for_processor(
            "aws::s3::bucket",
            lookup,
            yaml_ref_value=_ref,
            yaml_valid_bucket_name=_valid_bucket,
        )
        == "s3://assets.bucket"
    )
    assert calls == [
        ("ref", ("bucketName", "bucket-name", "bucket_name", "bucket", "name")),
        ("valid", "Assets.Bucket"),
    ]


def test_iac_resource_s3_candidate_for_processor_suppresses_non_s3_and_invalid_buckets() -> None:
    assert (
        iac_resource_s3_candidate_for_processor(
            "google.storage.bucket",
            {"bucket": "assets"},
            yaml_ref_value=lambda mapping, *keys: mapping.get(keys[0], ""),
            yaml_valid_bucket_name=lambda value: str(value or ""),
        )
        == ""
    )
    assert (
        iac_resource_s3_candidate_for_processor(
            "aws:s3:bucket",
            {"bucket": "NO"},
            yaml_ref_value=lambda mapping, *keys: mapping.get("bucket", ""),
            yaml_valid_bucket_name=lambda _value: "no",
        )
        == ""
    )


def test_iac_resource_gcs_candidate_for_processor_uses_bucket_lookup_order() -> None:
    calls: list[tuple[Any, ...]] = []
    lookup = {"bucket-name": "Logs_Bucket", "name": "ignored"}

    def _ref(mapping: dict[str, Any], *keys: str) -> Any:
        calls.append(("ref", keys))
        for key in keys:
            if key in mapping:
                return mapping[key]
        return ""

    def _valid_bucket(value: Any) -> str:
        calls.append(("valid", value))
        return str(value or "").strip().lower()

    assert (
        iac_resource_gcs_candidate_for_processor(
            "google.storage.bucket",
            lookup,
            yaml_ref_value=_ref,
            yaml_valid_bucket_name=_valid_bucket,
        )
        == "gs://logs_bucket"
    )
    assert calls == [
        ("ref", ("bucketName", "bucket-name", "bucket_name", "bucket", "name")),
        ("valid", "Logs_Bucket"),
    ]


def test_iac_resource_gcs_candidate_for_processor_suppresses_non_gcs_and_invalid_buckets() -> None:
    assert (
        iac_resource_gcs_candidate_for_processor(
            "aws::s3::bucket",
            {"bucket": "assets"},
            yaml_ref_value=lambda mapping, *keys: mapping.get(keys[0], ""),
            yaml_valid_bucket_name=lambda value: str(value or ""),
        )
        == ""
    )
    assert (
        iac_resource_gcs_candidate_for_processor(
            "google_storage_bucket",
            {"bucket": "NO"},
            yaml_ref_value=lambda mapping, *keys: mapping.get("bucket", ""),
            yaml_valid_bucket_name=lambda _value: "",
        )
        == ""
    )


def test_iac_resource_digitalocean_spaces_candidate_for_processor_uses_bucket_and_region() -> None:
    calls: list[tuple[Any, ...]] = []
    lookup = {"bucket": "Media", "space_region": "SGP1", "name": "ignored"}

    def _ref(mapping: dict[str, Any], *keys: str) -> Any:
        calls.append(("ref", keys))
        for key in keys:
            if key in mapping:
                return mapping[key]
        return ""

    def _valid_bucket(value: Any) -> str:
        calls.append(("valid", value))
        return str(value or "").strip().lower()

    assert (
        iac_resource_digitalocean_spaces_candidate_for_processor(
            "digitalocean_spaces_bucket",
            lookup,
            yaml_ref_value=_ref,
            yaml_valid_bucket_name=_valid_bucket,
        )
        == "https://media.sgp1.digitaloceanspaces.com"
    )
    assert calls == [
        ("ref", ("bucketName", "bucket-name", "bucket_name", "bucket", "name")),
        ("valid", "Media"),
        ("ref", ("region", "spaceRegion", "space-region", "space_region")),
    ]


def test_iac_resource_digitalocean_spaces_candidate_for_processor_suppresses_non_do_and_invalid_parts() -> None:
    assert (
        iac_resource_digitalocean_spaces_candidate_for_processor(
            "aws::s3::bucket",
            {"bucket": "media", "region": "sgp1"},
            yaml_ref_value=lambda mapping, *keys: mapping.get(keys[0], ""),
            yaml_valid_bucket_name=lambda value: str(value or ""),
        )
        == ""
    )
    assert (
        iac_resource_digitalocean_spaces_candidate_for_processor(
            "digitalocean space",
            {"bucket": "media", "region": "!"},
            yaml_ref_value=lambda mapping, *keys: mapping.get("bucket" if "bucket" in keys else "region", ""),
            yaml_valid_bucket_name=lambda value: str(value or ""),
        )
        == ""
    )


def test_iac_resource_structured_candidates_for_processor_builds_lookup_and_orders_providers() -> None:
    calls: list[tuple[Any, ...]] = []

    def _yaml_ref_value(mapping: dict[str, Any], *keys: str) -> Any:
        calls.append(("ref", tuple(keys), dict(mapping)))
        for key in keys:
            if key in mapping:
                return mapping[key]
        return ""

    def _yaml_child_mapping(mapping: dict[str, Any], *keys: str) -> dict[str, Any]:
        calls.append(("child", tuple(keys)))
        return mapping["properties"]

    def _yaml_normalized_mapping(mapping: dict[str, Any]) -> dict[str, Any]:
        calls.append(("normalize", dict(mapping)))
        return {"bucket": mapping["bucket"], "region": mapping["region"]}

    def _candidate(label: str, result: str) -> Callable[..., str]:
        def _inner(type_hint: str, lookup: dict[str, Any], **kwargs: Any) -> str:
            calls.append((label, type_hint, dict(lookup), sorted(kwargs)))
            return result

        return _inner

    assert iac_resource_structured_candidates_for_processor(
        {"properties": {"bucket": "props-bucket", "region": "sgp1"}},
        {"type": "aws::s3::bucket", "bucket": "root-bucket"},
        yaml_ref_value=_yaml_ref_value,
        yaml_child_mapping=_yaml_child_mapping,
        yaml_normalized_mapping=_yaml_normalized_mapping,
        yaml_valid_bucket_name=lambda value: str(value or ""),
        yaml_valid_project_ref=lambda value: str(value or ""),
        azure_blob_url_from_parts=lambda account, container: f"{account}/{container}",
        azure_blob_parts_from_composite_name=lambda value: ("acct", str(value or "")),
        iac_resource_s3_candidate=_candidate("s3", "s3://props-bucket"),
        iac_resource_gcs_candidate=_candidate("gcs", ""),
        iac_resource_digitalocean_spaces_candidate=_candidate(
            "digitalocean",
            "https://props-bucket.sgp1.digitaloceanspaces.com",
        ),
        iac_resource_firebase_candidate=_candidate("firebase", ""),
        iac_resource_supabase_candidate=_candidate("supabase", ""),
        iac_resource_azure_blob_candidate=_candidate("azure", ""),
    ) == [
        "s3://props-bucket",
        "https://props-bucket.sgp1.digitaloceanspaces.com",
    ]
    assert [call[0] for call in calls if call[0] in {"s3", "gcs", "digitalocean", "firebase", "supabase", "azure"}] == [
        "s3",
        "gcs",
        "digitalocean",
        "firebase",
        "supabase",
        "azure",
    ]
    provider_calls = [call for call in calls if call[0] in {"s3", "gcs", "digitalocean", "firebase", "supabase", "azure"}]
    assert provider_calls[0][2]["bucket"] == "props-bucket"


def test_iac_resource_structured_candidates_for_processor_suppresses_missing_type() -> None:
    def _unexpected(*args: Any, **kwargs: Any) -> str:
        raise AssertionError("provider callbacks should not run without a type hint")

    assert (
        iac_resource_structured_candidates_for_processor(
            {"properties": {"bucket": "assets"}},
            {},
            yaml_ref_value=lambda mapping, *keys: "",
            yaml_child_mapping=lambda mapping, *keys: {"bucket": "assets"},
            yaml_normalized_mapping=lambda mapping: {"bucket": "assets"},
            yaml_valid_bucket_name=lambda value: str(value or ""),
            yaml_valid_project_ref=lambda value: str(value or ""),
            azure_blob_url_from_parts=lambda account, container: "",
            azure_blob_parts_from_composite_name=lambda value: ("", ""),
            iac_resource_s3_candidate=_unexpected,
            iac_resource_gcs_candidate=_unexpected,
            iac_resource_digitalocean_spaces_candidate=_unexpected,
            iac_resource_firebase_candidate=_unexpected,
            iac_resource_supabase_candidate=_unexpected,
            iac_resource_azure_blob_candidate=_unexpected,
        )
        == []
    )


def test_terraform_backend_config_candidates_for_processor_extracts_s3_do_and_azure_candidates() -> None:
    calls: list[tuple[Any, ...]] = []

    def _do_spaces_url(bucket: str, endpoint: str) -> str:
        calls.append(("do", bucket, endpoint))
        return "https://assets.sgp1.digitaloceanspaces.com"

    def _azure_url(account_name: str, container_name: str) -> str:
        calls.append(("azure", account_name, container_name))
        return f"https://{account_name}.blob.core.windows.net/{container_name}"

    assert terraform_backend_config_candidates_for_processor(
        "backend config",
        terraform_block_assignments=lambda text: {
            "bucket": "Assets",
            "endpoint": "sgp1.digitaloceanspaces.com",
            "container_name": "Snapshots",
            "storage_account_name": "Acct123",
            "region": "sgp1",
        }
        if text == "backend config"
        else {},
        digitalocean_spaces_url_from_endpoint=_do_spaces_url,
        azure_blob_url_from_parts=_azure_url,
    ) == [
        "https://assets.sgp1.digitaloceanspaces.com",
        "https://acct123.blob.core.windows.net/snapshots",
    ]
    assert ("do", "assets", "sgp1.digitaloceanspaces.com") in calls
    assert ("azure", "acct123", "snapshots") in calls


def test_terraform_backend_config_candidates_for_processor_extracts_fallback_s3_and_gcs_candidates() -> None:
    assert terraform_backend_config_candidates_for_processor(
        "s3 backend",
        terraform_block_assignments=lambda _text: {"bucket": "state-bucket", "region": "us-east-1"},
        digitalocean_spaces_url_from_endpoint=lambda _bucket, _endpoint: "",
        azure_blob_url_from_parts=lambda _account, _container: "",
    ) == ["s3://state-bucket"]
    assert terraform_backend_config_candidates_for_processor(
        "gcs backend",
        terraform_block_assignments=lambda _text: {"bucket": "state_bucket", "credentials": "creds.json"},
        digitalocean_spaces_url_from_endpoint=lambda _bucket, _endpoint: "",
        azure_blob_url_from_parts=lambda _account, _container: "",
    ) == ["gs://state_bucket"]


def test_terraform_backend_config_candidates_for_processor_suppresses_empty_and_invalid_bucket_assignments() -> None:
    assert terraform_backend_config_candidates_for_processor(
        "empty",
        terraform_block_assignments=lambda _text: {},
        digitalocean_spaces_url_from_endpoint=lambda _bucket, _endpoint: "ignored",
        azure_blob_url_from_parts=lambda _account, _container: "",
    ) == []
    assert terraform_backend_config_candidates_for_processor(
        "invalid",
        terraform_block_assignments=lambda _text: {"bucket": "no", "region": "us-east-1"},
        digitalocean_spaces_url_from_endpoint=lambda _bucket, _endpoint: "ignored",
        azure_blob_url_from_parts=lambda _account, _container: "",
    ) == []


def test_iter_terragrunt_remote_state_blocks_for_processor_collects_nested_blocks() -> None:
    assert iter_terragrunt_remote_state_blocks_for_processor(
        "\n".join(
            [
                "locals {}",
                "remote_state {",
                '  backend = "s3"',
                "  config = {",
                '    bucket = "state"',
                "  }",
                "}",
                "REMOTE_STATE {",
                '  backend = "gcs"',
                "}",
            ]
        )
    ) == [
        "\n".join(
            [
                "remote_state {",
                '  backend = "s3"',
                "  config = {",
                '    bucket = "state"',
                "  }",
                "}",
            ]
        ),
        "\n".join(
            [
                "REMOTE_STATE {",
                '  backend = "gcs"',
                "}",
            ]
        ),
    ]


def test_iter_terragrunt_remote_state_blocks_for_processor_keeps_unclosed_block() -> None:
    assert iter_terragrunt_remote_state_blocks_for_processor(
        'remote_state {\n  backend = "s3"'
    ) == ['remote_state {\n  backend = "s3"']


def test_terragrunt_remote_state_backend_candidates_for_processor_orders_and_dedupes_candidates() -> None:
    calls: list[tuple[Any, ...]] = []

    def _iter_blocks(text: str) -> list[str]:
        calls.append(("iter", text))
        return ["block-a", "block-b"]

    def _backend_candidates(block: str) -> list[str]:
        calls.append(("backend", block))
        if block == "block-a":
            return [" s3://state ", "", "GS://Logs"]
        return ["s3://STATE", None, "az://container"]  # type: ignore[list-item]

    def _run_ordered_batch(
        items: list[Any],
        worker: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        calls.append(("batch", list(items), default_factory()))
        return [worker(item) for item in items]

    assert terragrunt_remote_state_backend_candidates_for_processor(
        "terragrunt text",
        iter_terragrunt_remote_state_blocks=_iter_blocks,
        terraform_backend_config_candidates=_backend_candidates,
        run_ordered_batch=_run_ordered_batch,
    ) == ["s3://state", "GS://Logs", "az://container"]
    assert calls[0] == ("iter", "terragrunt text")
    assert ("batch", ["block-a", "block-b"], []) in calls


def test_terragrunt_remote_state_backend_candidates_for_processor_handles_empty_blocks() -> None:
    assert terragrunt_remote_state_backend_candidates_for_processor(
        "terragrunt text",
        iter_terragrunt_remote_state_blocks=lambda _text: [],
        terraform_backend_config_candidates=lambda _block: ["s3://state"],
        run_ordered_batch=lambda items, worker, *, default_factory: [worker(item) for item in items],
    ) == []


def test_parse_key_value_scalar_for_processor_normalizes_quotes_comments_and_commas() -> None:
    assert parse_key_value_scalar_for_processor("  'secret-value'  ") == "secret-value"
    assert parse_key_value_scalar_for_processor('  "quoted value"  ') == "quoted value"
    assert parse_key_value_scalar_for_processor('  """multi line"""  ') == "multi line"
    assert parse_key_value_scalar_for_processor("token-value # local note") == "token-value"
    assert parse_key_value_scalar_for_processor("token-value ; local note") == "token-value"
    assert parse_key_value_scalar_for_processor("token-value // local note") == "token-value"
    assert parse_key_value_scalar_for_processor("token-value,") == "token-value"
    assert parse_key_value_scalar_for_processor("   ") == ""


def test_key_value_section_path_for_processor_normalizes_sections_and_keys() -> None:
    assert key_value_section_path_for_processor(" [database.primary] ") == ("database", "primary")
    assert key_value_section_path_for_processor("[['owner/team']]") == ("owner", "team")
    assert key_value_section_path_for_processor("cloud/accounts.prod") == ("cloud", "accounts", "prod")
    assert key_value_section_path_for_processor("API Key") == ("apikey",)
    assert key_value_section_path_for_processor(" . / ") == ()
    assert key_value_section_path_for_processor("") == ()


def test_key_value_line_entry_for_processor_classifies_sections_and_assignments() -> None:
    calls: list[tuple[str, Any]] = []

    def _section_path(value: str) -> tuple[str, ...]:
        calls.append(("path", value))
        return key_value_section_path_for_processor(value)

    def _scalar(value: str) -> str:
        calls.append(("scalar", value))
        return parse_key_value_scalar_for_processor(value)

    assert key_value_line_entry_for_processor(
        (0, "[database.primary]"),
        key_value_section_path=_section_path,
        parse_key_value_scalar=_scalar,
    ) == ("section", ("database", "primary"))
    assert key_value_line_entry_for_processor(
        (1, "export API_TOKEN = 'secret-value'"),
        key_value_section_path=_section_path,
        parse_key_value_scalar=_scalar,
    ) == ("assignment", "api_token", "secret-value")
    assert key_value_line_entry_for_processor(
        (2, "cloud.account-name: prod"),
        key_value_section_path=_section_path,
        parse_key_value_scalar=_scalar,
    ) == ("assignment", "cloud.account-name", "prod")
    assert ("path", "database.primary") in calls
    assert ("scalar", "'secret-value'") in calls


def test_key_value_line_entry_for_processor_suppresses_ignored_lines() -> None:
    assert (
        key_value_line_entry_for_processor(
            (0, "# comment"),
            key_value_section_path=key_value_section_path_for_processor,
            parse_key_value_scalar=parse_key_value_scalar_for_processor,
        )
        is None
    )
    assert (
        key_value_line_entry_for_processor(
            (1, "{"),
            key_value_section_path=key_value_section_path_for_processor,
            parse_key_value_scalar=parse_key_value_scalar_for_processor,
        )
        is None
    )
    assert (
        key_value_line_entry_for_processor(
            (2, "TOKEN="),
            key_value_section_path=key_value_section_path_for_processor,
            parse_key_value_scalar=parse_key_value_scalar_for_processor,
        )
        is None
    )


def test_parse_key_value_entries_for_processor_tracks_sections_and_assignments() -> None:
    calls: list[tuple[Any, ...]] = []

    def _line_entry(line_entry: tuple[int, str]) -> tuple[str, tuple[str, ...]] | tuple[str, str, str] | None:
        calls.append(("line", line_entry))
        return key_value_line_entry_for_processor(
            line_entry,
            key_value_section_path=key_value_section_path_for_processor,
            parse_key_value_scalar=parse_key_value_scalar_for_processor,
        )

    def _run_ordered_batch(
        items: list[tuple[int, str]],
        worker: Callable[[tuple[int, str]], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        calls.append(("batch", list(items), default_factory()))
        return [worker(item) for item in items] + [None, ("ignored",), ("assignment", "bad")]

    assert parse_key_value_entries_for_processor(
        "\n".join(
            [
                "GLOBAL_TOKEN=global",
                "[database.primary]",
                "url = postgres://db",
                "# ignored",
                "[cloud]",
                "account: prod",
            ]
        ),
        key_value_line_entry=_line_entry,
        run_ordered_batch=_run_ordered_batch,
    ) == [
        ((), "global_token", "global"),
        (("database", "primary"), "url", "postgres://db"),
        (("cloud",), "account", "prod"),
    ]
    assert calls[0][0] == "batch"
    assert calls[0][2] is None


def test_parse_key_value_entries_for_processor_handles_empty_text() -> None:
    assert parse_key_value_entries_for_processor(
        "",
        key_value_line_entry=lambda line_entry: ("assignment", "unexpected", "value"),
        run_ordered_batch=lambda items, worker, *, default_factory: [worker(item) for item in items],
    ) == []


def test_key_value_structured_inputs_for_processor_builds_env_sections_and_direct_candidates() -> None:
    calls: list[str] = []

    def _fingerprint(value: str) -> str:
        calls.append(value)
        return value.replace("-", "_")

    env_map, section_maps, direct_candidates = key_value_structured_inputs_for_processor(
        [
            ((), "api-token", "secret"),
            (("database",), "url", "https://db.example.com"),
            (("database",), "owner", "Admin@Example.com"),
            (("storage", "s3"), "bucket", "s3://assets"),
            (("storage", "s3"), "bucket-copy", "S3://assets"),
        ],
        yaml_key_fingerprint=_fingerprint,
    )

    assert env_map["API_TOKEN"] == "secret"
    assert env_map["DATABASE_URL"] == "https://db.example.com"
    assert env_map["STORAGE_S3_BUCKET"] == "s3://assets"
    assert section_maps[()]["api-token"] == "secret"
    assert section_maps[()]["api_token"] == "secret"
    assert section_maps[("database",)]["url"] == "https://db.example.com"
    assert section_maps[("storage", "s3")]["bucket-copy"] == "S3://assets"
    assert direct_candidates == ["https://db.example.com", "admin@example.com", "s3://assets"]
    assert calls[:3] == ["api-token", "url", "owner"]


def test_key_value_structured_inputs_for_processor_handles_empty_entries() -> None:
    assert key_value_structured_inputs_for_processor(
        [],
        yaml_key_fingerprint=lambda value: value,
    ) == ({}, {}, [])


def test_key_value_structured_payload_lines_for_processor_orders_flattens_and_dedupes_candidates() -> None:
    calls: list[tuple[Any, ...]] = []

    def _candidate_jobs(
        env_map: dict[str, str],
        section_maps: dict[tuple[str, ...], dict[str, str]],
    ) -> list[tuple[str, tuple[str, ...], dict[str, str]]]:
        calls.append(("jobs", dict(env_map), dict(section_maps)))
        return [
            ("env", (), env_map),
            ("section", ("database",), section_maps[("database",)]),
        ]

    def _candidate_job(
        source_job: tuple[str, tuple[str, ...], dict[str, str]],
    ) -> tuple[str, tuple[str, ...], dict[str, str]] | None:
        calls.append(("job", source_job[0], source_job[1]))
        return source_job

    def _candidate_batch(job: tuple[str, tuple[str, ...], dict[str, str]]) -> list[str]:
        calls.append(("batch-worker", job[0], job[1]))
        if job[0] == "env":
            return ["https://api.example.com", "s3://assets"]
        return ["HTTPS://API.EXAMPLE.COM", "gs://logs"]

    def _family_entries(candidate_family: tuple[int, list[str]]) -> list[str]:
        calls.append(("family", candidate_family[0], list(candidate_family[1])))
        return list(candidate_family[1])

    def _direct_entry(candidate_entry: tuple[int, str]) -> str | None:
        calls.append(("direct", candidate_entry))
        return candidate_entry[1].strip() or None

    def _append_entry(candidate_entry: tuple[int, str | None]) -> tuple[str, str] | None:
        calls.append(("append", candidate_entry))
        value = str(candidate_entry[1] or "").strip()
        return (value, value.lower()) if value else None

    def _run_ordered_batch(items: list[Any], worker: Callable[[Any], Any], *, default_factory: Callable[[], Any]) -> list[Any]:
        calls.append(("ordered", list(items), default_factory()))
        entries = [worker(item) for item in items]
        if worker is _append_entry:
            entries.extend([None, ("bad",)])
        return entries

    assert key_value_structured_payload_lines_for_processor(
        {"API_URL": "https://api.example.com"},
        {("database",): {"url": "postgres://db"}},
        ["s3://assets", "https://cdn.example.com"],
        key_value_structured_candidate_jobs=_candidate_jobs,
        key_value_structured_candidate_job=_candidate_job,
        key_value_structured_candidate_batch=_candidate_batch,
        key_value_structured_candidate_family_entries=_family_entries,
        key_value_structured_direct_candidate_entry=_direct_entry,
        key_value_structured_append_entry=_append_entry,
        run_ordered_batch=_run_ordered_batch,
    ) == "\n".join(
        [
            "https://api.example.com",
            "s3://assets",
            "gs://logs",
            "https://cdn.example.com",
        ]
    )
    assert calls[0][0] == "jobs"
    assert any(call[0] == "direct" for call in calls)


def test_key_value_structured_payload_lines_for_processor_handles_empty_inputs() -> None:
    assert key_value_structured_payload_lines_for_processor(
        {},
        {},
        [],
        key_value_structured_candidate_jobs=lambda env_map, section_maps: [],
        key_value_structured_candidate_job=lambda job: job,
        key_value_structured_candidate_batch=lambda job: ["unexpected"],
        key_value_structured_candidate_family_entries=lambda family: list(family[1]),
        key_value_structured_direct_candidate_entry=lambda candidate: candidate[1],
        key_value_structured_append_entry=lambda candidate: (str(candidate[1]), str(candidate[1]).lower()),
        run_ordered_batch=lambda items, worker, *, default_factory: [worker(item) for item in items],
    ) == ""


def test_key_value_structured_payload_text_for_processor_coordinates_pipeline() -> None:
    calls: list[tuple[Any, ...]] = []

    def _looks_text_config_name(source_hint: str) -> bool:
        calls.append(("looks", source_hint))
        return source_hint.endswith(".env")

    def _parse_entries(text: str) -> list[tuple[tuple[str, ...], str, str]]:
        calls.append(("parse", text))
        return [((), "api_url", "https://api.example.com")]

    def _structured_inputs(
        entries: list[tuple[tuple[str, ...], str, str]],
    ) -> tuple[dict[str, str], dict[tuple[str, ...], dict[str, str]], list[str]]:
        calls.append(("inputs", list(entries)))
        return {"API_URL": entries[0][2]}, {(): {"api_url": entries[0][2]}}, [entries[0][2]]

    def _payload_lines(
        env_map: dict[str, str],
        section_maps: dict[tuple[str, ...], dict[str, str]],
        direct_candidates: list[str],
    ) -> str:
        calls.append(("lines", dict(env_map), dict(section_maps), list(direct_candidates)))
        return "\n".join(direct_candidates)

    assert key_value_structured_payload_text_for_processor(
        "API_URL=https://api.example.com",
        source_hint="settings.env",
        looks_text_config_name=_looks_text_config_name,
        parse_key_value_entries=_parse_entries,
        key_value_structured_inputs=_structured_inputs,
        key_value_structured_payload_lines=_payload_lines,
    ) == "https://api.example.com"
    assert [call[0] for call in calls] == ["looks", "parse", "inputs", "lines"]


def test_key_value_structured_payload_text_for_processor_suppresses_non_config_and_empty_entries() -> None:
    assert (
        key_value_structured_payload_text_for_processor(
            "API_URL=https://api.example.com",
            source_hint="settings.txt",
            looks_text_config_name=lambda source_hint: False,
            parse_key_value_entries=lambda text: [(((), "api_url", "https://api.example.com"))],  # type: ignore[list-item]
            key_value_structured_inputs=lambda entries: ({}, {}, []),
            key_value_structured_payload_lines=lambda env_map, section_maps, direct_candidates: "unexpected",
        )
        == ""
    )
    assert (
        key_value_structured_payload_text_for_processor(
            "",
            source_hint="settings.env",
            looks_text_config_name=lambda source_hint: True,
            parse_key_value_entries=lambda text: [],
            key_value_structured_inputs=lambda entries: ({}, {}, ["unexpected"]),
            key_value_structured_payload_lines=lambda env_map, section_maps, direct_candidates: "unexpected",
        )
        == ""
    )


def test_strip_jsonc_comments_for_processor_removes_line_and_block_comments() -> None:
    assert strip_jsonc_comments_for_processor(
        "{\n"
        '  "url": "https://example.com", // deployment URL\n'
        "  /* keep newlines\n"
        "     while removing comment text */\n"
        '  "bucket": "assets"\n'
        "}"
    ) == "{\n" '  "url": "https://example.com", \n' "  \n" "\n" '  "bucket": "assets"\n' "}"


def test_strip_jsonc_comments_for_processor_preserves_comment_markers_inside_strings() -> None:
    assert strip_jsonc_comments_for_processor(
        '{"url":"https://example.com/a//b","glob":"/* literal */","quote":"\\"// not comment"}'
    ) == '{"url":"https://example.com/a//b","glob":"/* literal */","quote":"\\"// not comment"}'


def test_json_document_from_line_for_processor_returns_object_and_list_documents() -> None:
    calls: list[str] = []

    def _safe_json_loads(value: str) -> Any:
        calls.append(value)
        if value == '{"url":"https://example.com"}':
            return {"url": "https://example.com"}
        if value == '["a", "b"]':
            return ["a", "b"]
        return None

    assert json_document_from_line_for_processor(
        '  {"url":"https://example.com"}  ',
        safe_json_loads=_safe_json_loads,
    ) == {"url": "https://example.com"}
    assert json_document_from_line_for_processor(
        '["a", "b"]',
        safe_json_loads=_safe_json_loads,
    ) == ["a", "b"]
    assert calls == ['{"url":"https://example.com"}', '["a", "b"]']


def test_json_document_from_line_for_processor_suppresses_empty_scalar_and_invalid_lines() -> None:
    assert (
        json_document_from_line_for_processor(
            "   ",
            safe_json_loads=lambda value: {"unexpected": value},
        )
        is None
    )
    assert (
        json_document_from_line_for_processor(
            '"scalar"',
            safe_json_loads=lambda value: "scalar",
        )
        is None
    )
    assert (
        json_document_from_line_for_processor(
            "{invalid",
            safe_json_loads=lambda value: None,
        )
        is None
    )


def test_json_documents_from_text_for_processor_prefers_direct_json_documents() -> None:
    calls: list[tuple[Any, ...]] = []

    def _safe_json_loads(value: str) -> Any:
        calls.append(("json", value))
        return {"url": "https://example.com"} if value == '{"url":"https://example.com"}' else None

    assert json_documents_from_text_for_processor(
        '  {"url":"https://example.com"}  ',
        source_hint="settings.json",
        looks_text_config_name=lambda source_hint: source_hint.endswith(".json"),
        looks_like_container_image_blob_path=lambda source_hint: False,
        strip_jsonc_comments=lambda text: text,
        safe_json_loads=_safe_json_loads,
        json_document_from_line=lambda line: {"line": line},
        run_ordered_batch=lambda items, worker, *, default_factory: [worker(item) for item in items],
    ) == [{"url": "https://example.com"}]
    assert calls == [("json", '{"url":"https://example.com"}')]


def test_json_documents_from_text_for_processor_uses_jsonc_and_jsonl_fallbacks() -> None:
    calls: list[tuple[Any, ...]] = []

    def _safe_json_loads(value: str) -> Any:
        calls.append(("json", value))
        if value == '{"url":"https://example.com"}':
            return {"url": "https://example.com"}
        return None

    assert json_documents_from_text_for_processor(
        '{"url":"https://example.com"} // comment',
        source_hint="settings.jsonc",
        looks_text_config_name=lambda source_hint: True,
        looks_like_container_image_blob_path=lambda source_hint: False,
        strip_jsonc_comments=lambda text: text.replace(" // comment", ""),
        safe_json_loads=_safe_json_loads,
        json_document_from_line=lambda line: None,
        run_ordered_batch=lambda items, worker, *, default_factory: [worker(item) for item in items],
    ) == [{"url": "https://example.com"}]
    assert calls == [
        ("json", '{"url":"https://example.com"} // comment'),
        ("json", '{"url":"https://example.com"}'),
    ]

    def _line_document(raw_line: str) -> Any:
        return {"line": raw_line} if raw_line.startswith("{") else None

    assert json_documents_from_text_for_processor(
        '{"a":1}\nnot-json\n[1,2]',
        source_hint="events.jsonl",
        looks_text_config_name=lambda source_hint: True,
        looks_like_container_image_blob_path=lambda source_hint: False,
        strip_jsonc_comments=lambda text: text,
        safe_json_loads=lambda value: None,
        json_document_from_line=_line_document,
        run_ordered_batch=lambda items, worker, *, default_factory: [worker(item) for item in items],
    ) == [{"line": '{"a":1}'}]


def test_json_documents_from_text_for_processor_suppresses_unrelated_or_empty_text() -> None:
    kwargs = {
        "looks_text_config_name": lambda source_hint: False,
        "looks_like_container_image_blob_path": lambda source_hint: False,
        "strip_jsonc_comments": lambda text: text,
        "safe_json_loads": lambda value: {"unexpected": value},
        "json_document_from_line": lambda line: {"line": line},
        "run_ordered_batch": lambda items, worker, *, default_factory: [worker(item) for item in items],
    }
    assert json_documents_from_text_for_processor("{}", source_hint="notes.txt", **kwargs) == []
    assert json_documents_from_text_for_processor(
        "   ",
        source_hint="settings.json",
        looks_text_config_name=lambda source_hint: True,
        looks_like_container_image_blob_path=lambda source_hint: False,
        strip_jsonc_comments=lambda text: text,
        safe_json_loads=lambda value: {"unexpected": value},
        json_document_from_line=lambda line: {"line": line},
        run_ordered_batch=lambda items, worker, *, default_factory: [worker(item) for item in items],
    ) == []


def test_json_structured_payload_text_for_processor_merges_and_dedupes_line_batches() -> None:
    calls: list[tuple[Any, ...]] = []
    documents = [{"auths": {}}, {"family": "task"}]

    def _json_documents_from_text(text: str, *, source_hint: str) -> list[Any]:
        calls.append(("documents", text, source_hint))
        return documents

    def _run_ordered_batch(items: list[Any], worker: Callable[[Any], Any], *, default_factory: Callable[[], Any]) -> list[Any]:
        calls.append(("batch", list(items), default_factory()))
        return [worker(item) for item in items]

    def _ordered_entries(batch_entry: tuple[int, list[str]]) -> list[str]:
        calls.append(("ordered-lines", batch_entry[0], list(batch_entry[1])))
        return list(batch_entry[1])

    assert json_structured_payload_text_for_processor(
        "json text",
        source_hint=".dockerconfigjson",
        json_documents_from_text=_json_documents_from_text,
        json_document_looks_like_docker_auth_config=lambda document, source_hint: "auths" in document,
        docker_auth_config_candidates=lambda document: ["https://registry.example.com"],
        ecs_task_definition_candidates=lambda document: ["https://ecs.example.com"] if document.get("family") else [],
        lambda_config_candidates=lambda document: ["https://lambda.example.com"] if document.get("family") else [],
        amplify_client_config_candidates=lambda document, *, source_hint: ["https://amplify.example.com"],
        structured_document_lines=lambda document: ["HTTPS://REGISTRY.EXAMPLE.COM", "https://generic.example.com"],
        ordered_line_batch_entries=_ordered_entries,
        run_ordered_batch=_run_ordered_batch,
    ) == "\n".join(
        [
            "https://registry.example.com",
            "https://ecs.example.com",
            "https://lambda.example.com",
            "https://amplify.example.com",
            "https://generic.example.com",
        ]
    )
    assert calls[0] == ("documents", "json text", ".dockerconfigjson")
    assert any(call[0] == "ordered-lines" for call in calls)


def test_json_structured_payload_text_for_processor_handles_empty_documents() -> None:
    assert json_structured_payload_text_for_processor(
        "",
        source_hint="settings.json",
        json_documents_from_text=lambda text, *, source_hint: [],
        json_document_looks_like_docker_auth_config=lambda document, source_hint: True,
        docker_auth_config_candidates=lambda document: ["unexpected"],
        ecs_task_definition_candidates=lambda document: ["unexpected"],
        lambda_config_candidates=lambda document: ["unexpected"],
        amplify_client_config_candidates=lambda document, *, source_hint: ["unexpected"],
        structured_document_lines=lambda document: ["unexpected"],
        ordered_line_batch_entries=lambda batch: list(batch[1]),
        run_ordered_batch=lambda items, worker, *, default_factory: [worker(item) for item in items],
    ) == ""


def test_json_document_looks_like_docker_auth_config_for_processor_detects_names_and_keys() -> None:
    calls: list[dict[str, Any]] = []

    def _normalized(mapping: dict[str, Any]) -> dict[str, Any]:
        calls.append(mapping)
        return {str(key).lower(): value for key, value in mapping.items()}

    assert json_document_looks_like_docker_auth_config_for_processor(
        {"anything": True},
        "C:/tmp/.dockerconfigjson",
        yaml_normalized_mapping=_normalized,
    )
    assert json_document_looks_like_docker_auth_config_for_processor(
        {"credHelpers": {"registry.example.com": "desktop"}},
        "config.json",
        yaml_normalized_mapping=_normalized,
    )
    assert calls == [{"credHelpers": {"registry.example.com": "desktop"}}]


def test_json_document_looks_like_docker_auth_config_for_processor_suppresses_non_matches() -> None:
    assert not json_document_looks_like_docker_auth_config_for_processor(
        ["auths"],
        ".dockerconfigjson",
        yaml_normalized_mapping=lambda mapping: {"auths": True},
    )
    assert not json_document_looks_like_docker_auth_config_for_processor(
        {"services": {}},
        "settings.json",
        yaml_normalized_mapping=lambda mapping: {"services": {}},
    )


def test_docker_registry_url_candidate_for_processor_normalizes_registry_values() -> None:
    assert docker_registry_url_candidate_for_processor("REGISTRY.EXAMPLE.COM/team/") == (
        "https://registry.example.com/team"
    )
    assert docker_registry_url_candidate_for_processor("//registry.example.com/v1/") == (
        "https://registry.example.com/v1"
    )
    assert docker_registry_url_candidate_for_processor("*") == ""
    assert docker_registry_url_candidate_for_processor("ftp://registry.example.com") == ""


def test_docker_auth_principal_helpers_extract_email_principals() -> None:
    classify = lambda value: "email" if "@" in str(value or "") else "domain"
    assert docker_auth_principal_candidate_for_processor(
        "Admin@Example.COM",
        classify_seed_value=classify,
    ) == "admin@example.com"
    auth_value = "QWRtaW5ARXhhbXBsZS5DT006c2VjcmV0"
    assert docker_auth_principal_from_auth_field_for_processor(
        auth_value,
        docker_auth_principal_candidate=lambda value: docker_auth_principal_candidate_for_processor(
            value,
            classify_seed_value=classify,
        ),
    ) == "admin@example.com"
    assert docker_auth_principal_from_auth_field_for_processor(
        "not base64",
        docker_auth_principal_candidate=lambda value: "unexpected",
    ) == ""


def test_docker_auth_entry_principals_for_processor_preserves_explicit_and_auth_fields() -> None:
    assert docker_auth_entry_principals_for_processor(
        {"email": "Owner@Example.COM", "username": "not-email", "auth": "VXNlckBFeGFtcGxlLmNvbTpzZWNyZXQ="},
        docker_auth_principal_candidate=lambda value: str(value).lower() if "@" in str(value or "") else "",
        docker_auth_principal_from_auth_field=lambda value: "user@example.com",
    ) == ["owner@example.com", "user@example.com"]


def test_docker_auth_config_entry_helpers_extract_registries_and_skip_metadata() -> None:
    auth_entry = ("registry.example.com", {"email": "Owner@Example.COM"})
    assert docker_auth_config_auth_entry_candidates_for_processor(
        auth_entry,
        docker_registry_url_candidate=docker_registry_url_candidate_for_processor,
        docker_auth_entry_principals=lambda entry: [str(entry["email"]).lower()],
    ) == ["https://registry.example.com", "owner@example.com"]
    assert docker_auth_config_cred_helper_candidates_for_processor(
        "registry.example.com",
        docker_registry_url_candidate=docker_registry_url_candidate_for_processor,
    ) == ["https://registry.example.com"]
    assert docker_auth_config_legacy_entry_candidates_for_processor(
        ("credHelpers", {"registry.example.com": "desktop"}),
        docker_auth_config_auth_entry_candidates=lambda item: ["unexpected"],
    ) == []
    assert docker_auth_config_legacy_entry_candidates_for_processor(
        auth_entry,
        docker_auth_config_auth_entry_candidates=lambda item: ["legacy"],
    ) == ["legacy"]


def test_env_value_may_hold_docker_auth_for_processor_detects_names_and_json() -> None:
    assert env_value_may_hold_docker_auth_for_processor("DOCKER_CONFIG", "not-json")
    assert env_value_may_hold_docker_auth_for_processor("REGISTRY", '{"auths": {}}')
    assert not env_value_may_hold_docker_auth_for_processor("REGISTRY", '{"services": {}}')


def test_docker_auth_structured_env_entry_candidates_for_processor_filters_values() -> None:
    assert docker_auth_structured_env_entry_candidates_for_processor(
        ("DOCKER_CONFIG", '{"auths": {}}'),
        env_value_may_hold_docker_auth=lambda name, value: "DOCKER" in name,
        docker_auth_config_candidates=lambda value: ["https://registry.example.com"],
    ) == ["https://registry.example.com"]
    assert docker_auth_structured_env_entry_candidates_for_processor(
        ("APP_CONFIG", '{"auths": {}}'),
        env_value_may_hold_docker_auth=lambda name, value: False,
        docker_auth_config_candidates=lambda value: ["unexpected"],
    ) == []


def test_docker_auth_structured_candidates_from_env_map_for_processor_dedupes_batches() -> None:
    assert docker_auth_structured_candidates_from_env_map_for_processor(
        {"DOCKER_CONFIG": "first", "CONTAINER_REGISTRY_AUTH": "second"},
        run_ordered_static_batch=lambda items, worker, default_factory: [worker(item) for item in items],
        docker_auth_structured_env_entry_candidates=lambda item: [
            "https://registry.example.com",
            str(item[0]).lower(),
        ],
    ) == [
        "https://registry.example.com",
        "docker_config",
        "container_registry_auth",
    ]


def test_docker_auth_config_candidates_for_processor_merges_auths_and_cred_helpers() -> None:
    payload = {
        "auths": {
            "registry.example.com": {"email": "Owner@Example.COM"},
            "REGISTRY.EXAMPLE.COM": {"email": "Owner@Example.COM"},
        },
        "credHelpers": {"helper.example.com": "desktop"},
    }
    assert docker_auth_config_candidates_for_processor(
        payload,
        safe_json_loads=lambda value: {},
        run_ordered_static_batch=lambda items, worker, default_factory: [worker(item) for item in items],
        docker_auth_config_auth_entry_candidates=lambda item: [
            docker_registry_url_candidate_for_processor(item[0]),
            "owner@example.com",
        ],
        docker_auth_config_cred_helper_candidates=lambda item: [
            docker_registry_url_candidate_for_processor(item)
        ],
        docker_auth_config_legacy_entry_candidates=lambda item: ["unexpected"],
    ) == [
        "https://registry.example.com",
        "owner@example.com",
        "https://helper.example.com",
    ]


def test_docker_auth_config_candidates_for_processor_uses_legacy_when_auths_missing() -> None:
    assert docker_auth_config_candidates_for_processor(
        '{"registry.example.com": {"email": "Owner@Example.COM"}}',
        safe_json_loads=lambda value: {"registry.example.com": {"email": "Owner@Example.COM"}},
        run_ordered_static_batch=lambda items, worker, default_factory: [worker(item) for item in items],
        docker_auth_config_auth_entry_candidates=lambda item: ["unexpected"],
        docker_auth_config_cred_helper_candidates=lambda item: ["unexpected"],
        docker_auth_config_legacy_entry_candidates=lambda item: [
            docker_registry_url_candidate_for_processor(item[0]),
            str(item[1]["email"]).lower(),
        ],
    ) == ["https://registry.example.com", "owner@example.com"]


def test_firebaserc_project_ref_url_for_processor_builds_rtdb_url() -> None:
    calls: list[str] = []

    def _valid_project_ref(value: str) -> str:
        calls.append(value)
        return "my-project"

    assert (
        firebaserc_project_ref_url_for_processor(
            " My Project ",
            yaml_valid_project_ref=_valid_project_ref,
        )
        == "https://my-project.firebaseio.com"
    )
    assert calls == [" My Project "]


def test_firebaserc_project_ref_url_for_processor_suppresses_invalid_refs() -> None:
    assert (
        firebaserc_project_ref_url_for_processor(
            "",
            yaml_valid_project_ref=lambda value: "",
        )
        == ""
    )


def test_firebaserc_structured_payload_text_for_processor_collects_project_refs() -> None:
    seen_items: list[Any] = []

    def _run_ordered_batch(
        items: list[Any],
        worker: Callable[[Any], str],
        *,
        default_factory: Callable[[], str],
    ) -> list[str]:
        del default_factory
        seen_items.extend(items)
        return [worker(item) for item in items]

    assert (
        firebaserc_structured_payload_text_for_processor(
            "ignored",
            source_hint="C:/repo/.firebaserc",
            safe_json_loads=lambda value: {
                "projects": {
                    "default": "alpha-project",
                    "staging": "alpha-project",
                },
                "targets": {"beta-project": {"hosting": ["site"]}},
            },
            firebaserc_project_ref_url=lambda value: (
                f"https://{value}.firebaseio.com"
                if value in {"alpha-project", "beta-project"}
                else ""
            ),
            run_ordered_batch=_run_ordered_batch,
        )
        == "https://alpha-project.firebaseio.com\nhttps://beta-project.firebaseio.com"
    )
    assert seen_items == ["alpha-project", "alpha-project", "beta-project"]


def test_firebaserc_structured_payload_text_for_processor_suppresses_non_firebaserc() -> None:
    assert (
        firebaserc_structured_payload_text_for_processor(
            "{}",
            source_hint="firebase.json",
            safe_json_loads=lambda value: {"projects": {"default": value}},
            firebaserc_project_ref_url=lambda value: str(value),
            run_ordered_batch=lambda items, worker, *, default_factory: [
                worker(item) for item in items
            ],
        )
        == ""
    )


def test_firebaserc_structured_payload_text_for_processor_suppresses_non_dict_payload() -> None:
    assert (
        firebaserc_structured_payload_text_for_processor(
            "[]",
            source_hint=".firebaserc",
            safe_json_loads=lambda value: [],
            firebaserc_project_ref_url=lambda value: str(value),
            run_ordered_batch=lambda items, worker, *, default_factory: [
                worker(item) for item in items
            ],
        )
        == ""
    )


def test_observability_structured_document_candidates_for_processor_dedupes_values() -> None:
    calls: list[tuple[Any, str, bool]] = []
    document = {"scrape_configs": [{"targets": ["metrics.example.com:9090"]}]}

    def _node_candidates(
        value: Any,
        *,
        inherited_scheme: str,
        use_workers: bool,
    ) -> list[str]:
        calls.append((value, inherited_scheme, use_workers))
        return [
            " http://metrics.example.com:9090 ",
            "HTTP://metrics.example.com:9090",
            "",
            None,
            "https://logs.example.com",
        ]

    assert observability_structured_document_candidates_for_processor(
        document,
        "prometheus-config",
        observability_structured_node_candidates=_node_candidates,
    ) == ["http://metrics.example.com:9090", "https://logs.example.com"]
    assert calls == [(document, "http", True)]


def test_observability_structured_document_candidates_for_processor_suppresses_empty_values() -> None:
    assert (
        observability_structured_document_candidates_for_processor(
            {"receivers": []},
            "otel-config",
            observability_structured_node_candidates=lambda value, **kwargs: [
                "",
                None,
                "   ",
            ],
        )
        == []
    )


def test_observability_child_candidate_values_for_processor_delegates_without_workers() -> None:
    calls: list[tuple[Any, str, bool]] = []
    child = {"targets": ["metrics.example.com:9090"]}

    def _node_candidates(
        value: Any,
        *,
        inherited_scheme: str,
        use_workers: bool,
    ) -> list[str]:
        calls.append((value, inherited_scheme, use_workers))
        return ["https://metrics.example.com:9090"]

    assert observability_child_candidate_values_for_processor(
        (7, child, "https"),
        observability_structured_node_candidates=_node_candidates,
    ) == ["https://metrics.example.com:9090"]
    assert calls == [(child, "https", False)]


def test_observability_endpoint_jobs_for_processor_walks_nested_lists() -> None:
    assert observability_endpoint_jobs_for_processor(
        ["metrics.example.com:9090", ["logs.example.com:3100", 4317, 3.14], {"skip": True}],
        "https",
    ) == [
        ("metrics.example.com:9090", "https"),
        ("logs.example.com:3100", "https"),
        (4317, "https"),
        (3.14, "https"),
    ]


def test_observability_endpoint_jobs_for_processor_caps_collected_jobs() -> None:
    jobs = observability_endpoint_jobs_for_processor(list(range(5000)), "http")

    assert len(jobs) == 4096
    assert jobs[0] == (0, "http")
    assert jobs[-1] == (4095, "http")


def test_observability_endpoint_jobs_for_processor_suppresses_non_scalars() -> None:
    assert observability_endpoint_jobs_for_processor({"target": "metrics"}, "http") == []


def test_observability_scheme_candidate_for_processor_normalizes_supported_schemes() -> None:
    assert observability_scheme_candidate_for_processor(" HTTPS ") == "https"
    assert observability_scheme_candidate_for_processor("http") == "http"


def test_observability_scheme_candidate_for_processor_suppresses_unsupported_values() -> None:
    assert observability_scheme_candidate_for_processor("grpc") == ""
    assert observability_scheme_candidate_for_processor(None) == ""


def test_observability_target_url_candidate_for_processor_keeps_explicit_url() -> None:
    assert (
        observability_target_url_candidate_for_processor(
            (" HTTPS://Metrics.Example.com:9090/path ", "http"),
            normalize_artifact_text_url=lambda value: value.strip().lower(),
            classify_seed_value=lambda value: "url" if value.startswith("https://") else "",
            observability_scheme_candidate=observability_scheme_candidate_for_processor,
        )
        == "https://metrics.example.com:9090/path"
    )


def test_observability_target_url_candidate_for_processor_builds_host_port_url() -> None:
    classifications: list[str] = []

    def _classify(value: str) -> str:
        classifications.append(value)
        return "subdomain"

    assert (
        observability_target_url_candidate_for_processor(
            ("Metrics.Example.com:9090/api", " HTTPS "),
            normalize_artifact_text_url=lambda value: value,
            classify_seed_value=_classify,
            observability_scheme_candidate=observability_scheme_candidate_for_processor,
        )
        == "https://metrics.example.com:9090/api"
    )
    assert classifications == ["metrics.example.com"]


def test_observability_target_url_candidate_for_processor_suppresses_invalid_targets() -> None:
    kwargs = {
        "normalize_artifact_text_url": lambda value: value,
        "classify_seed_value": lambda value: "domain",
        "observability_scheme_candidate": observability_scheme_candidate_for_processor,
    }

    assert observability_target_url_candidate_for_processor(("localhost:9090", "http"), **kwargs) == ""
    assert observability_target_url_candidate_for_processor(("example.com:9090", "http"), **kwargs) == ""
    assert observability_target_url_candidate_for_processor(("metrics.example.com:70000", "http"), **kwargs) == ""
    assert observability_target_url_candidate_for_processor(("metrics.${ENV}:9090", "http"), **kwargs) == ""


def test_observability_structured_payload_text_for_processor_collects_candidates() -> None:
    documents = [{"targets": ["metrics.example.com:9090"]}, {"targets": ["logs.example.com:3100"]}]

    def _run_ordered_batch(
        items: list[Any],
        worker: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        del default_factory
        return [worker(item) for item in items]

    assert (
        observability_structured_payload_text_for_processor(
            "ignored",
            source_hint="prometheus.yml",
            observability_text_config_artifact_label=lambda value: "prometheus-config",
            observability_structured_labels={"prometheus-config"},
            yaml_safe_load_all=lambda value: documents,
            observability_structured_document_candidates=lambda document, label: [
                "https://metrics.example.com",
                "HTTPS://METRICS.EXAMPLE.COM",
                "https://logs.example.com" if "logs" in str(document) else "",
            ],
            ordered_line_batch_entries=lambda batch: list(batch[1]),
            run_ordered_batch=_run_ordered_batch,
        )
        == "https://metrics.example.com\nhttps://logs.example.com"
    )


def test_observability_structured_payload_text_for_processor_suppresses_unsupported_inputs() -> None:
    kwargs = {
        "observability_structured_labels": {"prometheus-config"},
        "observability_structured_document_candidates": lambda document, label: ["x"],
        "ordered_line_batch_entries": lambda batch: list(batch[1]),
        "run_ordered_batch": lambda items, worker, *, default_factory: [
            worker(item) for item in items
        ],
    }

    assert (
        observability_structured_payload_text_for_processor(
            "targets: []",
            source_hint="notes.txt",
            observability_text_config_artifact_label=lambda value: "",
            yaml_safe_load_all=lambda value: [{"targets": []}],
            **kwargs,
        )
        == ""
    )
    assert (
        observability_structured_payload_text_for_processor(
            "targets: []",
            source_hint="prometheus.yml",
            observability_text_config_artifact_label=lambda value: "prometheus-config",
            yaml_safe_load_all=None,
            **kwargs,
        )
        == ""
    )


def test_observability_structured_payload_text_for_processor_suppresses_yaml_errors() -> None:
    def _raise_yaml_error(value: str) -> list[Any]:
        raise ValueError(value)

    assert (
        observability_structured_payload_text_for_processor(
            "bad: [",
            source_hint="prometheus.yml",
            observability_text_config_artifact_label=lambda value: "prometheus-config",
            observability_structured_labels={"prometheus-config"},
            yaml_safe_load_all=_raise_yaml_error,
            observability_structured_document_candidates=lambda document, label: ["x"],
            ordered_line_batch_entries=lambda batch: list(batch[1]),
            run_ordered_batch=lambda items, worker, *, default_factory: [
                worker(item) for item in items
            ],
        )
        == ""
    )


def test_edge_proxy_structured_payload_text_for_processor_collects_line_candidates() -> None:
    seen_lines: list[str] = []

    def _line_candidates(line: str) -> list[str]:
        seen_lines.append(line)
        if "one" in line:
            return [" https://proxy.example.com ", "HTTPS://PROXY.EXAMPLE.COM"]
        if "two" in line:
            return ["https://api.example.com"]
        return [""]

    assert (
        edge_proxy_structured_payload_text_for_processor(
            "one\ntwo\nthree",
            source_hint="nginx.conf",
            edge_proxy_config_artifact_label=lambda value: "nginx-config",
            edge_proxy_structured_labels={"nginx-config"},
            edge_proxy_line_url_candidates=_line_candidates,
            ordered_line_batch_entries=lambda batch: list(batch[1]),
            run_ordered_batch=lambda items, worker, *, default_factory: [
                worker(item) for item in items
            ],
        )
        == "https://proxy.example.com\nhttps://api.example.com"
    )
    assert seen_lines == ["one", "two", "three"]


def test_edge_proxy_structured_payload_text_for_processor_suppresses_unsupported_source() -> None:
    assert (
        edge_proxy_structured_payload_text_for_processor(
            "proxy_pass https://proxy.example.com;",
            source_hint="notes.txt",
            edge_proxy_config_artifact_label=lambda value: "",
            edge_proxy_structured_labels={"nginx-config"},
            edge_proxy_line_url_candidates=lambda line: [line],
            ordered_line_batch_entries=lambda batch: list(batch[1]),
            run_ordered_batch=lambda items, worker, *, default_factory: [
                worker(item) for item in items
            ],
        )
        == ""
    )


def test_edge_proxy_structured_payload_text_for_processor_limits_lines() -> None:
    processed_lines: list[str] = []

    def _line_candidates(line: str) -> list[str]:
        processed_lines.append(line)
        return [f"https://{line}.example.com"]

    result = edge_proxy_structured_payload_text_for_processor(
        "\n".join(str(index) for index in range(4100)),
        source_hint="nginx.conf",
        edge_proxy_config_artifact_label=lambda value: "nginx-config",
        edge_proxy_structured_labels={"nginx-config"},
        edge_proxy_line_url_candidates=_line_candidates,
        ordered_line_batch_entries=lambda batch: list(batch[1]),
        run_ordered_batch=lambda items, worker, *, default_factory: [
            worker(item) for item in items
        ],
    )

    assert len(processed_lines) == 4096
    assert result.splitlines()[-1] == "https://4095.example.com"


def test_edge_proxy_endpoint_url_candidate_for_processor_normalizes_schemes() -> None:
    calls: list[str] = []

    def _api_entry(value: str) -> str:
        calls.append(value)
        return value.lower()

    assert (
        edge_proxy_endpoint_url_candidate_for_processor(
            " grpc://Api.Example.com:50051 ",
            api_spec_url_candidate_entry=_api_entry,
        )
        == "http://api.example.com:50051"
    )
    assert (
        edge_proxy_endpoint_url_candidate_for_processor(
            "grpcs://Api.Example.com:50051",
            api_spec_url_candidate_entry=_api_entry,
        )
        == "https://api.example.com:50051"
    )
    assert calls == ["http://Api.Example.com:50051", "https://Api.Example.com:50051"]


def test_edge_proxy_endpoint_url_candidate_for_processor_applies_default_scheme() -> None:
    assert (
        edge_proxy_endpoint_url_candidate_for_processor(
            "api.example.com",
            "https",
            api_spec_url_candidate_entry=lambda value: value,
        )
        == "https://api.example.com"
    )
    assert (
        edge_proxy_endpoint_url_candidate_for_processor(
            "api.example.com",
            "ftp",
            api_spec_url_candidate_entry=lambda value: value,
        )
        == "http://api.example.com"
    )
    assert (
        edge_proxy_endpoint_url_candidate_for_processor(
            "//api.example.com",
            "https",
            api_spec_url_candidate_entry=lambda value: value,
        )
        == ""
    )


def test_edge_proxy_endpoint_url_candidate_for_processor_suppresses_invalid_values() -> None:
    kwargs = {"api_spec_url_candidate_entry": lambda value: value}

    assert edge_proxy_endpoint_url_candidate_for_processor("", **kwargs) == ""
    assert edge_proxy_endpoint_url_candidate_for_processor("${API_HOST}", **kwargs) == ""
    assert edge_proxy_endpoint_url_candidate_for_processor("unix:/tmp/socket", **kwargs) == ""
    assert edge_proxy_endpoint_url_candidate_for_processor("/relative/path", **kwargs) == ""


def _edge_proxy_line_test_kwargs() -> dict[str, Any]:
    host_token = (
        r"(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,63}|(?:\d{1,3}\.){3}\d{1,3})"
    )
    return {
        "edge_proxy_host_rule_pattern": re.compile(
            r"\bHost(?:SNI)?\s*\((?P<values>[^)]{1,2048})\)",
            re.IGNORECASE,
        ),
        "edge_proxy_host_rule_value_pattern": re.compile(
            r"""[`'"](?P<quoted>[^`'"]{1,512})[`'"]|(?P<bare>[A-Za-z0-9*_.-]+(?::\d{1,5})?)""",
            re.IGNORECASE,
        ),
        "edge_proxy_keyed_value_pattern": re.compile(
            r"^\s*(?:-\s*)?(?P<key>proxy_pass|to|url|target|endpoint)\b\s*(?:[:=]\s*)?(?P<value>.+?)\s*$",
            re.IGNORECASE,
        ),
        "edge_proxy_endpoint_token_pattern": re.compile(
            rf"(?:(?:https?|wss?|ws|grpc|grpcs|h2c)://[^\s\"'`),;\]}}]+|//{host_token}(?::\d{{1,5}})?(?:/[^\s\"'`),;\]}}]*)?|{host_token}(?::\d{{1,5}})?(?:/[^\s\"'`),;\]}}]*)?)",
            re.IGNORECASE,
        ),
    }


def test_edge_proxy_line_url_candidates_for_processor_extracts_host_rules() -> None:
    assert edge_proxy_line_url_candidates_for_processor(
        "acl host hdr(host) -i Host(`Api.Example.com`, api.example.com)",
        edge_proxy_endpoint_url_candidate=lambda value: f"https://{value.lower()}",
        **_edge_proxy_line_test_kwargs(),
    ) == ["https://api.example.com"]


def test_edge_proxy_line_url_candidates_for_processor_extracts_keyed_values() -> None:
    assert edge_proxy_line_url_candidates_for_processor(
        "proxy_pass https://api.example.com; # comment",
        edge_proxy_endpoint_url_candidate=lambda value: value.rstrip(";").lower(),
        **_edge_proxy_line_test_kwargs(),
    ) == ["https://api.example.com"]


def test_edge_proxy_line_url_candidates_for_processor_suppresses_comments_and_templates() -> None:
    kwargs = _edge_proxy_line_test_kwargs()
    assert (
        edge_proxy_line_url_candidates_for_processor(
            "# proxy_pass https://api.example.com",
            edge_proxy_endpoint_url_candidate=lambda value: value,
            **kwargs,
        )
        == []
    )
    assert (
        edge_proxy_line_url_candidates_for_processor(
            "proxy_pass https://${API_HOST}",
            edge_proxy_endpoint_url_candidate=lambda value: value,
            **kwargs,
        )
        == []
    )


def test_orchestration_annotation_endpointish_key_for_processor_detects_markers() -> None:
    assert orchestration_annotation_endpointish_key_for_processor("serviceendpoint")
    assert orchestration_annotation_endpointish_key_for_processor("externaldnsalpha")
    assert orchestration_annotation_endpointish_key_for_processor("backendurl")


def test_orchestration_annotation_endpointish_key_for_processor_suppresses_non_endpoint_keys() -> None:
    assert not orchestration_annotation_endpointish_key_for_processor("owner")
    assert not orchestration_annotation_endpointish_key_for_processor("hostedzone")


def test_orchestration_endpoint_values_for_processor_walks_nested_lists() -> None:
    assert orchestration_endpoint_values_for_processor(
        [" api.example.com ", ["metrics.example.com", 443, 3.14], {"skip": "dict"}]
    ) == ["api.example.com", "metrics.example.com", "443", "3.14"]


def test_orchestration_endpoint_values_for_processor_caps_collected_values() -> None:
    values = orchestration_endpoint_values_for_processor(list(range(5000)))

    assert len(values) == 4096
    assert values[0] == "0"
    assert values[-1] == "4095"


def test_orchestration_endpoint_values_for_processor_suppresses_empty_and_non_scalars() -> None:
    assert orchestration_endpoint_values_for_processor(["", "  ", {"host": "api.example.com"}]) == []


def test_orchestration_text_values_for_processor_walks_nested_lists_and_dicts() -> None:
    assert orchestration_text_values_for_processor(
        {
            "name": " api.example.com ",
            "nested": ["metrics.example.com", {"description": "keep me"}],
            "port": 443,
        }
    ) == [" api.example.com ", "metrics.example.com", "keep me"]


def test_orchestration_text_values_for_processor_caps_collected_values() -> None:
    values = orchestration_text_values_for_processor([str(value) for value in range(5000)])

    assert len(values) == 4096
    assert values[0] == "0"
    assert values[-1] == "4095"


def test_orchestration_text_values_for_processor_suppresses_empty_and_non_strings() -> None:
    assert orchestration_text_values_for_processor(["", 443, 3.14, {"empty": "", "none": None}]) == []


def _kopia_runtime_kwargs() -> dict[str, Any]:
    def _normalize(mapping: dict[str, Any]) -> dict[str, Any]:
        normalized: dict[str, Any] = {}
        for key, value in mapping.items():
            normalized[str(key).lower().replace("_", "")] = value
            normalized[str(key)] = value
        return normalized

    def _ref(mapping: dict[str, Any], *keys: str) -> Any:
        for key in keys:
            for candidate in (key, key.lower().replace("_", "")):
                if candidate in mapping:
                    return mapping[candidate]
        return ""

    return {
        "looks_like_kopia_text_config_artifact_name": lambda value: "kopia" in str(value).lower(),
        "safe_json_loads": json.loads,
        "yaml_normalized_mapping": _normalize,
        "yaml_ref_value": _ref,
        "yaml_valid_bucket_name": lambda value: str(value or "").strip().lower(),
        "artifact_managed_cloud_url_candidate": lambda value: str(value or "").strip(),
    }


def test_kopia_structured_payload_text_for_processor_extracts_s3_endpoint_and_dedupes() -> None:
    text = json.dumps(
        {
            "storage": {
                "type": "s3",
                "endpoint": " https://s3.us-east-1.amazonaws.com ",
                "config": {
                    "bucket": "acme-kopia-bucket",
                    "server": "https://s3.us-east-1.amazonaws.com",
                },
            }
        }
    )

    assert kopia_structured_payload_text_for_processor(
        text,
        source_hint=".config/kopia/repository.config",
        **_kopia_runtime_kwargs(),
    ) == "\n".join(
        [
            "https://s3.us-east-1.amazonaws.com",
            "s3://acme-kopia-bucket",
        ]
    )


def test_kopia_structured_payload_text_for_processor_extracts_gcs_and_azure() -> None:
    gcs_text = json.dumps({"storage": {"type": "googleCloudStorage", "bucketName": "team-backups"}})
    azure_text = json.dumps(
        {
            "storage": {
                "type": "azure-blob",
                "storageAccountName": "TeamVault",
                "containerName": "archives",
            }
        }
    )

    assert kopia_structured_payload_text_for_processor(
        gcs_text,
        source_hint="repository.config",
        **_kopia_runtime_kwargs(),
    ) == "gs://team-backups"
    assert kopia_structured_payload_text_for_processor(
        azure_text,
        source_hint="repository.config",
        **_kopia_runtime_kwargs(),
    ) == "https://teamvault.blob.core.windows.net/archives"


def test_kopia_structured_payload_text_for_processor_suppresses_unrelated_or_invalid_payloads() -> None:
    assert kopia_structured_payload_text_for_processor(
        json.dumps({"storage": {"type": "s3", "bucket": "acme-kopia-bucket"}}),
        source_hint="settings.json",
        **_kopia_runtime_kwargs(),
    ) == ""
    assert kopia_structured_payload_text_for_processor(
        "[]",
        source_hint="repository.config",
        **_kopia_runtime_kwargs(),
    ) == ""
    assert kopia_structured_payload_text_for_processor(
        json.dumps({"storage": "s3://bucket"}),
        source_hint="repository.config",
        **_kopia_runtime_kwargs(),
    ) == ""


def _duplicacy_runtime_kwargs() -> dict[str, Any]:
    def _normalize(mapping: dict[str, Any]) -> dict[str, Any]:
        normalized: dict[str, Any] = {}
        for key, value in mapping.items():
            normalized[str(key).lower().replace("_", "")] = value
            normalized[str(key)] = value
        return normalized

    def _ref(mapping: dict[str, Any], *keys: str) -> Any:
        for key in keys:
            for candidate in (key, key.lower().replace("_", "")):
                if candidate in mapping:
                    return mapping[candidate]
        return ""

    def _valid_bucket(value: Any) -> str:
        return str(value or "").strip().lower()

    def _storage_candidates(storage_url: str, context: dict[str, Any]) -> list[str]:
        return duplicacy_storage_url_candidates_for_processor(
            storage_url,
            context,
            yaml_ref_value=_ref,
            yaml_valid_bucket_name=_valid_bucket,
            artifact_managed_cloud_url_candidate=lambda value: str(value or "").strip(),
            duplicacy_s3_storage_candidates=duplicacy_s3_storage_candidates_for_processor,
            duplicacy_bucket_from_storage_url=duplicacy_bucket_from_storage_url_for_processor,
        )

    def _entry_candidates(entry: dict[str, Any]) -> list[str]:
        return duplicacy_preference_entry_candidates_for_processor(
            entry,
            yaml_normalized_mapping=_normalize,
            yaml_ref_value=_ref,
            run_ordered_local_batch=lambda values, func, default_factory: [func(value) for value in values],
            duplicacy_storage_url_candidates=_storage_candidates,
        )

    return {
        "looks_like_duplicacy_preferences_text_config_artifact_name": (
            lambda value: "duplicacy" in str(value).lower()
        ),
        "safe_json_loads": json.loads,
        "duplicacy_preference_entry_has_hint": (
            lambda entry: duplicacy_preference_entry_has_hint_for_processor(
                entry,
                yaml_normalized_mapping=_normalize,
            )
        ),
        "run_ordered_local_batch": lambda values, func, default_factory: [func(value) for value in values],
        "duplicacy_preference_entry_candidates": _entry_candidates,
    }


def test_duplicacy_structured_payload_text_for_processor_extracts_storage_entries() -> None:
    text = json.dumps(
        [
            {"storage": "s3://us-west-2@acme-duplicacy-bucket/prod"},
            {"storage": "gcd://acme-duplicacy-gcs/prod"},
            {"storage": "gcd://acme-duplicacy-gcs/prod"},
            {"storage": {"url": "azure://archives/prod", "account_name": "TeamBlob"}},
        ]
    )

    assert duplicacy_structured_payload_text_for_processor(
        text,
        source_hint=".duplicacy/preferences",
        **_duplicacy_runtime_kwargs(),
    ) == "\n".join(
        [
            "s3://acme-duplicacy-bucket",
            "gs://acme-duplicacy-gcs",
            "https://teamblob.blob.core.windows.net/archives",
        ]
    )


def test_duplicacy_structured_payload_text_for_processor_accepts_single_hint_entry() -> None:
    text = json.dumps({"url": "https://storage.example.com/backups"})

    assert duplicacy_structured_payload_text_for_processor(
        text,
        source_hint="preferences",
        **_duplicacy_runtime_kwargs(),
    ) == "https://storage.example.com/backups"


def test_duplicacy_structured_payload_text_for_processor_suppresses_unrelated_or_unhinted_payloads() -> None:
    assert duplicacy_structured_payload_text_for_processor(
        json.dumps({"storage": "s3://bucket"}),
        source_hint="settings.json",
        **_duplicacy_runtime_kwargs(),
    ) == ""
    assert duplicacy_structured_payload_text_for_processor(
        json.dumps({"name": "default"}),
        source_hint="preferences",
        **_duplicacy_runtime_kwargs(),
    ) == ""
    assert duplicacy_structured_payload_text_for_processor(
        "[]",
        source_hint="preferences",
        **_duplicacy_runtime_kwargs(),
    ) == ""


def test_duplicacy_storage_helpers_for_processor_normalize_bucket_forms() -> None:
    assert duplicacy_bucket_from_storage_url_for_processor(
        "gcd://bucket-name/path",
        yaml_valid_bucket_name=lambda value: str(value or "").strip().lower(),
    ) == "bucket-name"
    assert duplicacy_s3_storage_candidates_for_processor(
        "s3://s3.us-west-2.amazonaws.com/bucket-name/path",
        yaml_valid_bucket_name=lambda value: str(value or "").strip().lower(),
        artifact_managed_cloud_url_candidate=lambda value: str(value or "").strip(),
    ) == [
        "https://s3.us-west-2.amazonaws.com/bucket-name",
        "s3://bucket-name",
    ]


def _borg_repository_kwargs() -> dict[str, Any]:
    def _ref(mapping: dict[str, Any], *keys: str) -> Any:
        normalized = {str(key).lower().replace("_", ""): value for key, value in mapping.items()}
        for key in keys:
            if key in mapping:
                return mapping[key]
            candidate = key.lower().replace("_", "")
            if candidate in normalized:
                return normalized[candidate]
        return ""

    return {
        "yaml_ref_value": _ref,
        "yaml_valid_bucket_name": lambda value: str(value or "").strip().lower(),
        "artifact_managed_cloud_url_candidate": lambda value: str(value or "").strip(),
        "strip_artifact_network_dsn_userinfo": lambda value: re.sub(r"//[^/@]+@", "//", value),
        "borg_s3_repository_candidates": borg_s3_repository_candidates_for_processor,
        "borg_bucket_from_repository_url": borg_bucket_from_repository_url_for_processor,
        "borg_network_repository_candidate": borg_network_repository_candidate_for_processor,
    }


def _borg_key_fingerprint(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _borg_parse_entries(text: str) -> list[tuple[tuple[str, ...], str, str]]:
    entries: list[tuple[tuple[str, ...], str, str]] = []
    section: tuple[str, ...] = ()
    for raw_line in str(text or "").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = (line.strip("[]").strip(),)
            continue
        separator = "=" if "=" in line else ":" if ":" in line else ""
        if not separator:
            continue
        key, value = line.split(separator, 1)
        entries.append((section, key.strip(), value.strip()))
    return entries


def _borg_structured_kwargs() -> dict[str, Any]:
    def _normalize(mapping: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(mapping)
        for key, value in mapping.items():
            normalized[_borg_key_fingerprint(str(key))] = value
        return normalized

    def _repository_candidates(repository: str, context: dict[str, Any]) -> list[str]:
        return borg_repository_candidates_for_processor(
            repository,
            context,
            **_borg_repository_kwargs(),
        )

    return {
        "borg_text_config_artifact_kind": lambda value: (
            "location" if str(value).endswith("borg.location") else "repository_config"
        ),
        "parse_key_value_entries": _borg_parse_entries,
        "yaml_key_fingerprint": _borg_key_fingerprint,
        "run_ordered_local_batch": lambda values, func, default_factory: [func(value) for value in values],
        "borg_repository_candidates": _repository_candidates,
        "borg_repository_candidates_from_env_map": (
            lambda env_map: borg_repository_candidates_from_env_map_for_processor(
                env_map,
                yaml_normalized_mapping=_normalize,
                yaml_key_fingerprint=_borg_key_fingerprint,
                run_ordered_local_batch=lambda values, func, default_factory: [func(value) for value in values],
                borg_repository_candidates=_repository_candidates,
            )
        ),
    }


def test_borg_structured_payload_text_for_processor_extracts_location_file_repository() -> None:
    assert borg_structured_payload_text_for_processor(
        "ssh://borg:secret@backup.example.com:2222/./repos/prod\n",
        source_hint="borg.location",
        **_borg_structured_kwargs(),
    ) == "ssh://backup.example.com:2222/./repos/prod"


def test_borg_structured_payload_text_for_processor_extracts_config_and_env_repositories() -> None:
    text = "\n".join(
        [
            "[repository]",
            "location = s3://us-west-2@acme-borg-bucket/prod",
            "[borg]",
            "repository = gs://acme-borg-gcs/prod",
            "azure_storage_account = teamblob",
            "remote = azure://archives/prod",
            "borg_repo = gs://acme-borg-gcs/prod",
        ]
    )

    assert borg_structured_payload_text_for_processor(
        text,
        source_hint="borg.repository.config",
        **_borg_structured_kwargs(),
    ) == "\n".join(
        [
            "s3://acme-borg-bucket",
            "gs://acme-borg-gcs",
            "https://teamblob.blob.core.windows.net/archives",
        ]
    )


def test_borg_structured_payload_text_for_processor_suppresses_unrelated_sources() -> None:
    assert borg_structured_payload_text_for_processor(
        "repository = s3://acme-borg-bucket/prod",
        source_hint="settings.ini",
        borg_text_config_artifact_kind=lambda value: "",
        parse_key_value_entries=_borg_parse_entries,
        yaml_key_fingerprint=_borg_key_fingerprint,
        run_ordered_local_batch=lambda values, func, default_factory: [func(value) for value in values],
        borg_repository_candidates=lambda repository, context: [repository],
        borg_repository_candidates_from_env_map=lambda env_map: [],
    ) == ""


def test_borg_repository_candidates_from_env_map_for_processor_dedupes_borg_keys() -> None:
    assert borg_repository_candidates_from_env_map_for_processor(
        {
            "BORG_REPO": "gs://acme-borg-gcs/prod",
            "BORG_REPOSITORY": "gs://acme-borg-gcs/prod",
            "AZURE_STORAGE_ACCOUNT": "teamblob",
            "BORG_REMOTE": "azure://archives/prod",
        },
        yaml_normalized_mapping=lambda mapping: {**mapping, **{_borg_key_fingerprint(key): value for key, value in mapping.items()}},
        yaml_key_fingerprint=_borg_key_fingerprint,
        run_ordered_local_batch=lambda values, func, default_factory: [func(value) for value in values],
        borg_repository_candidates=lambda repository, context: borg_repository_candidates_for_processor(
            repository,
            context,
            **_borg_repository_kwargs(),
        ),
    ) == [
        "gs://acme-borg-gcs",
        "https://teamblob.blob.core.windows.net/archives",
    ]


def test_borg_repository_candidates_for_processor_extracts_cloud_repositories() -> None:
    assert borg_repository_candidates_for_processor(
        "s3://us-west-2@acme-borg-bucket/prod",
        {},
        **_borg_repository_kwargs(),
    ) == ["s3://acme-borg-bucket"]
    assert borg_repository_candidates_for_processor(
        "gs://acme-borg-gcs/prod",
        {},
        **_borg_repository_kwargs(),
    ) == ["gs://acme-borg-gcs"]
    assert borg_repository_candidates_for_processor(
        "azure://archives/prod",
        {"azure_storage_account": "TeamBlob"},
        **_borg_repository_kwargs(),
    ) == ["https://teamblob.blob.core.windows.net/archives"]


def test_borg_repository_candidates_for_processor_normalizes_network_repositories() -> None:
    assert borg_repository_candidates_for_processor(
        "ssh://borg:secret@backup.example.com:2222/./repos/prod",
        {},
        **_borg_repository_kwargs(),
    ) == ["ssh://backup.example.com:2222/./repos/prod"]
    assert borg_repository_candidates_for_processor(
        "borg@backup.example.com:repos/prod",
        {},
        **_borg_repository_kwargs(),
    ) == ["ssh://backup.example.com/repos/prod"]


def test_borg_repository_candidates_for_processor_suppresses_templates_and_local_paths() -> None:
    assert borg_repository_candidates_for_processor(
        "{{ borg_repo }}",
        {},
        **_borg_repository_kwargs(),
    ) == []
    assert borg_repository_candidates_for_processor(
        "C:\\backups\\repo",
        {},
        **_borg_repository_kwargs(),
    ) == []
    assert borg_network_repository_candidate_for_processor(
        "not a repository",
        strip_artifact_network_dsn_userinfo=lambda value: value,
    ) == ""


def test_borg_s3_repository_candidates_for_processor_preserves_endpoint_and_bucket() -> None:
    assert borg_s3_repository_candidates_for_processor(
        "s3://s3.us-west-2.amazonaws.com/acme-borg-bucket/prod",
        yaml_valid_bucket_name=lambda value: str(value or "").strip().lower(),
        artifact_managed_cloud_url_candidate=lambda value: str(value or "").strip(),
    ) == [
        "https://s3.us-west-2.amazonaws.com/acme-borg-bucket",
        "s3://acme-borg-bucket",
    ]


def _restic_repository_kwargs() -> dict[str, Any]:
    return {
        "artifact_managed_cloud_url_candidate": lambda value: str(value or "").strip(),
        "restic_s3_repository_candidates": lambda value: restic_s3_repository_candidates_for_processor(
            value,
            yaml_valid_bucket_name=lambda bucket: str(bucket or "").strip().lower(),
            artifact_managed_cloud_url_candidate=lambda url: str(url or "").strip(),
        ),
        "restic_bucket_from_pathish": lambda value: restic_bucket_from_pathish_for_processor(
            value,
            yaml_valid_bucket_name=lambda bucket: str(bucket or "").strip().lower(),
        ),
    }


def test_restic_repository_candidates_from_env_map_for_processor_uses_restic_repository() -> None:
    assert restic_repository_candidates_from_env_map_for_processor(
        {
            "RESTIC_REPOSITORY": "gs:acme-restic-bucket/prod",
            "AZURE_STORAGE_ACCOUNT": "ignored",
        },
        restic_repository_candidates=lambda repository, env_map: restic_repository_candidates_for_processor(
            repository,
            env_map,
            **_restic_repository_kwargs(),
        ),
    ) == ["gs://acme-restic-bucket"]


def test_restic_repository_candidates_for_processor_extracts_cloud_repositories() -> None:
    assert restic_repository_candidates_for_processor(
        "s3:s3.us-west-2.amazonaws.com/acme-restic-bucket/prod",
        {},
        **_restic_repository_kwargs(),
    ) == [
        "s3://acme-restic-bucket",
        "https://s3.us-west-2.amazonaws.com/acme-restic-bucket/prod",
    ]
    assert restic_repository_candidates_for_processor(
        "gs:acme-restic-gcs/prod",
        {},
        **_restic_repository_kwargs(),
    ) == ["gs://acme-restic-gcs"]
    assert restic_repository_candidates_for_processor(
        "azure:archives/prod",
        {"AZURE_ACCOUNT_NAME": "TeamBlob"},
        **_restic_repository_kwargs(),
    ) == ["https://teamblob.blob.core.windows.net/archives"]


def test_restic_repository_candidates_for_processor_normalizes_rest_urls_and_dedupes() -> None:
    assert restic_repository_candidates_for_processor(
        "rest:https://restic.example.com/repo",
        {},
        **_restic_repository_kwargs(),
    ) == ["https://restic.example.com/repo"]

    assert restic_repository_candidates_for_processor(
        "s3:https://s3.example.com/acme-restic-bucket",
        {},
        **_restic_repository_kwargs(),
    ) == [
        "https://s3.example.com/acme-restic-bucket",
        "s3://acme-restic-bucket",
    ]


def test_restic_bucket_from_pathish_for_processor_normalizes_first_segment() -> None:
    assert restic_bucket_from_pathish_for_processor(
        "/Acme-Restic-Bucket/prod",
        yaml_valid_bucket_name=lambda value: str(value or "").strip().lower(),
    ) == "acme-restic-bucket"


def _yaml_env_candidate_family_kwargs(**overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "yaml_valid_project_ref": lambda value: str(value or "").strip().lower(),
        "yaml_valid_bucket_name": lambda value: str(value or "").strip().lower(),
        "run_ordered_local_batch": lambda items, worker, default_factory: [worker(item) for item in items],
        "yaml_managed_hosting_env_entry": lambda entry: str(entry[1]).strip() or None,
        "yaml_normalized_mapping": lambda mapping: {str(key).lower(): value for key, value in mapping.items()},
        "yaml_cloudflare_structured_candidates": lambda mapping, normalized, path_hint: [
            f"cloudflare:{path_hint}:{normalized.get('cloudflare_r2_bucket', '')}"
        ],
        "amplify_client_config_candidates": lambda env_map, source_hint="": [f"amplify:{source_hint}"],
        "sanity_env_urls": lambda env_map: ["https://sanity.example"],
        "docker_auth_structured_candidates_from_env_map": lambda env_map: ["docker-auth"],
        "restic_repository_candidates_from_env_map": lambda env_map: ["restic-repo"],
        "borg_repository_candidates_from_env_map": lambda env_map: ["borg-repo"],
        "duplicati_target_url_candidates_from_env_map": lambda env_map: ["duplicati-target"],
        "yaml_env_value_candidate_entry": lambda entry: str(entry[1]).strip() or None,
    }
    kwargs.update(overrides)
    return kwargs


def test_yaml_env_candidate_family_for_processor_extracts_direct_cloud_envs() -> None:
    kwargs = _yaml_env_candidate_family_kwargs()
    assert yaml_env_candidate_family_for_processor(
        {"FIREBASE_PROJECT_ID": "Acme-App"},
        "firebase",
        **kwargs,
    ) == ["https://acme-app.firebaseio.com"]
    assert yaml_env_candidate_family_for_processor(
        {"AWS_S3_BUCKET": "Acme-Bucket"},
        "s3",
        **kwargs,
    ) == ["s3://acme-bucket"]
    assert yaml_env_candidate_family_for_processor(
        {"AZURE_STORAGE_ACCOUNT": "teamblob", "AZURE_STORAGE_CONTAINER": "archives"},
        "azure",
        **kwargs,
    ) == ["https://teamblob.blob.core.windows.net/archives"]


def test_yaml_env_candidate_family_for_processor_dedupes_managed_hosting_entries() -> None:
    assert yaml_env_candidate_family_for_processor(
        {"APP_URL": "https://app.example", "PUBLIC_URL": "https://app.example"},
        "managed_hosting",
        **_yaml_env_candidate_family_kwargs(),
    ) == ["https://app.example"]


def test_yaml_env_candidate_family_for_processor_filters_env_value_entries() -> None:
    assert yaml_env_candidate_family_for_processor(
        {"EMPTY_URL": "", "APP_URL": "https://app.example"},
        "env_values",
        **_yaml_env_candidate_family_kwargs(),
    ) == ["https://app.example"]


def test_yaml_env_candidate_family_for_processor_delegates_to_nested_families() -> None:
    kwargs = _yaml_env_candidate_family_kwargs()
    assert yaml_env_candidate_family_for_processor(
        {"cloudflare_r2_bucket": "assets"},
        "cloudflare",
        **kwargs,
    ) == ["cloudflare:env:assets"]
    assert yaml_env_candidate_family_for_processor({}, "restic", **kwargs) == ["restic-repo"]
    assert yaml_env_candidate_family_for_processor(
        {},
        "amplify_client_config",
        source_hint="amplify.json",
        **kwargs,
    ) == ["amplify:amplify.json"]


def test_yaml_managed_hosting_env_entry_for_processor_gates_marker_names() -> None:
    assert yaml_managed_hosting_env_entry_for_processor(
        ("APP_URL", "app.example.com"),
        artifact_managed_cloud_url_candidate=lambda value: f"https://{value}",
    ) == "https://app.example.com"
    assert yaml_managed_hosting_env_entry_for_processor(
        ("APP_TOKEN", "app.example.com"),
        artifact_managed_cloud_url_candidate=lambda value: f"https://{value}",
    ) is None


def test_yaml_env_value_candidate_entry_for_processor_extracts_email_and_urls() -> None:
    assert yaml_env_value_candidate_entry_for_processor(
        ("OWNER_EMAIL", "Admin@Example.COM"),
        artifact_managed_cloud_url_candidate=lambda value: "",
    ) == "admin@example.com"
    assert yaml_env_value_candidate_entry_for_processor(
        ("ASSET_URL", "s3://acme-assets"),
        artifact_managed_cloud_url_candidate=lambda value: "",
    ) == "s3://acme-assets"
    assert yaml_env_value_candidate_entry_for_processor(
        ("PORTAL_DOMAIN", "portal.example.com"),
        artifact_managed_cloud_url_candidate=lambda value: f"https://{value}",
    ) == "https://portal.example.com"


def test_yaml_env_value_candidate_entry_for_processor_suppresses_non_matching_values() -> None:
    assert yaml_env_value_candidate_entry_for_processor(
        ("APP_TOKEN", "secret"),
        artifact_managed_cloud_url_candidate=lambda value: f"https://{value}",
    ) is None
    assert yaml_env_value_candidate_entry_for_processor(
        ("OWNER_EMAIL", "not-an-email"),
        artifact_managed_cloud_url_candidate=lambda value: "",
    ) is None


def _duplicati_target_kwargs() -> dict[str, Any]:
    def _ref(mapping: dict[str, Any], *keys: str) -> Any:
        normalized = {str(key).lower().replace("_", ""): value for key, value in mapping.items()}
        for key in keys:
            if key in mapping:
                return mapping[key]
            candidate = key.lower().replace("_", "")
            if candidate in normalized:
                return normalized[candidate]
        return ""

    return {
        "yaml_ref_value": _ref,
        "yaml_valid_bucket_name": lambda value: str(value or "").strip().lower(),
        "artifact_managed_cloud_url_candidate": lambda value: str(value or "").strip(),
        "duplicati_s3_target_candidates": duplicati_s3_target_candidates_for_processor,
        "duplicati_bucket_from_target_url": duplicati_bucket_from_target_url_for_processor,
    }


def test_duplicati_target_url_candidates_for_processor_extracts_cloud_targets() -> None:
    assert duplicati_target_url_candidates_for_processor(
        "s3://us-west-2@acme-duplicati-bucket/prod",
        {},
        **_duplicati_target_kwargs(),
    ) == ["s3://acme-duplicati-bucket"]
    assert duplicati_target_url_candidates_for_processor(
        "googlestorage://acme-duplicati-gcs/prod",
        {},
        **_duplicati_target_kwargs(),
    ) == ["gs://acme-duplicati-gcs"]
    assert duplicati_target_url_candidates_for_processor(
        "azure://archives/prod",
        {"auth_username": "TeamBlob"},
        **_duplicati_target_kwargs(),
    ) == ["https://teamblob.blob.core.windows.net/archives"]


def test_duplicati_target_url_candidates_from_env_map_for_processor_selects_target_keys() -> None:
    assert duplicati_target_url_candidates_from_env_map_for_processor(
        {
            "TARGET_URL": "googlestorage://acme-duplicati-gcs/prod",
            "AUTH_USERNAME": "ignored",
        },
        yaml_normalized_mapping=lambda mapping: {**mapping, **{str(key).lower().replace("_", ""): value for key, value in mapping.items()}},
        duplicati_target_url_candidates=lambda target_url, context: duplicati_target_url_candidates_for_processor(
            target_url,
            context,
            **_duplicati_target_kwargs(),
        ),
    ) == ["gs://acme-duplicati-gcs"]
    assert duplicati_target_url_candidates_from_env_map_for_processor(
        {},
        yaml_normalized_mapping=lambda mapping: mapping,
        duplicati_target_url_candidates=lambda target_url, context: [target_url],
    ) == []


def test_duplicati_s3_target_candidates_for_processor_preserves_endpoint_and_bucket() -> None:
    assert duplicati_s3_target_candidates_for_processor(
        "s3://s3.us-west-2.amazonaws.com/acme-duplicati-bucket/prod",
        yaml_valid_bucket_name=lambda value: str(value or "").strip().lower(),
        artifact_managed_cloud_url_candidate=lambda value: str(value or "").strip(),
    ) == [
        "https://s3.us-west-2.amazonaws.com/acme-duplicati-bucket",
        "s3://acme-duplicati-bucket",
    ]


def test_duplicati_bucket_from_target_url_for_processor_normalizes_bucket() -> None:
    assert duplicati_bucket_from_target_url_for_processor(
        "azure://container-name/path",
        yaml_valid_bucket_name=lambda value: str(value or "").strip().lower(),
    ) == "container-name"


def test_duplicati_nested_option_entries_for_processor_extracts_option_lines() -> None:
    assert duplicati_nested_option_entries_for_processor(
        "--target-url=s3://bucket/path\n--auth-username=teamblob\nignored\n",
        parse_key_value_entries=_borg_parse_entries,
    ) == [
        ("target-url", "s3://bucket/path"),
        ("auth-username", "teamblob"),
    ]


def test_duplicati_env_map_from_entries_for_processor_merges_nested_options() -> None:
    entries = [
        ((), "TargetURL", "s3://bucket/path"),
        ((), "Settings", "--auth-username=teamblob\n--remote-url=gs://gcs-bucket/path"),
    ]

    assert duplicati_env_map_from_entries_for_processor(
        entries,
        yaml_key_fingerprint=lambda value: re.sub(r"[^a-z0-9]+", "", str(value or "").lower()),
        duplicati_nested_option_entries=lambda value: duplicati_nested_option_entries_for_processor(
            value,
            parse_key_value_entries=_borg_parse_entries,
        ),
    ) == {
        "TARGETURL": "s3://bucket/path",
        "SETTINGS": "--auth-username=teamblob\n--remote-url=gs://gcs-bucket/path",
        "AUTH_USERNAME": "teamblob",
        "REMOTE_URL": "gs://gcs-bucket/path",
    }


def test_looks_like_duplicati_payload_hint_for_processor_requires_target_and_source_hint() -> None:
    assert looks_like_duplicati_payload_hint_for_processor(
        "Duplicati-server.sqlite#sqlite-row-backup-1",
        {"TARGETURL": "s3://bucket/path"},
    )
    assert not looks_like_duplicati_payload_hint_for_processor(
        "settings.ini",
        {"TARGETURL": "s3://bucket/path"},
    )
    assert not looks_like_duplicati_payload_hint_for_processor(
        "duplicati-settings",
        {},
    )


def test_duplicati_structured_payload_text_for_processor_extracts_and_dedupes_targets() -> None:
    text = "\n".join(
        [
            "TargetURL=s3://us-west-2@acme-duplicati-bucket/prod",
            "Settings=--remote-url=s3://us-west-2@acme-duplicati-bucket/prod",
        ]
    )

    assert duplicati_structured_payload_text_for_processor(
        text,
        source_hint="Duplicati-server.sqlite#sqlite-row-backup-1",
        parse_key_value_entries=_borg_parse_entries,
        duplicati_env_map_from_entries=lambda entries: duplicati_env_map_from_entries_for_processor(
            entries,
            yaml_key_fingerprint=lambda value: re.sub(r"[^a-z0-9]+", "", str(value or "").lower()),
            duplicati_nested_option_entries=lambda value: duplicati_nested_option_entries_for_processor(
                value,
                parse_key_value_entries=_borg_parse_entries,
            ),
        ),
        looks_like_duplicati_payload_hint=looks_like_duplicati_payload_hint_for_processor,
        duplicati_target_url_candidates_from_env_map=lambda env_map: duplicati_target_url_candidates_from_env_map_for_processor(
            env_map,
            yaml_normalized_mapping=lambda mapping: {**mapping, **{str(key).lower().replace("_", ""): value for key, value in mapping.items()}},
            duplicati_target_url_candidates=lambda target_url, context: duplicati_target_url_candidates_for_processor(
                target_url,
                context,
                **_duplicati_target_kwargs(),
            ),
        ),
    ) == "s3://acme-duplicati-bucket"


def test_duplicati_structured_payload_text_for_processor_suppresses_unhinted_payloads() -> None:
    assert duplicati_structured_payload_text_for_processor(
        "TargetURL=s3://bucket/path",
        source_hint="settings.ini",
        parse_key_value_entries=_borg_parse_entries,
        duplicati_env_map_from_entries=lambda entries: {"TARGETURL": "s3://bucket/path"},
        looks_like_duplicati_payload_hint=looks_like_duplicati_payload_hint_for_processor,
        duplicati_target_url_candidates_from_env_map=lambda env_map: ["s3://bucket"],
    ) == ""


def _appveyor_normalize(mapping: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(mapping)
    for key, value in mapping.items():
        normalized[str(key).lower().replace("_", "")] = value
    return normalized


def test_yaml_mapping_looks_like_appveyor_ci_for_processor_detects_known_keys() -> None:
    assert yaml_mapping_looks_like_appveyor_ci_for_processor({"buildscript": "build.ps1"})
    assert yaml_mapping_looks_like_appveyor_ci_for_processor({"environment": {"FOO": "bar"}})
    assert not yaml_mapping_looks_like_appveyor_ci_for_processor({"name": "demo"})


def test_appveyor_ci_document_candidate_for_processor_builds_pipeline_reference() -> None:
    assert appveyor_ci_document_candidate_for_processor(
        {"name": "Release Pipeline", "build_script": "build.ps1"},
        yaml_normalized_mapping=_appveyor_normalize,
        yaml_mapping_looks_like_appveyor_ci=yaml_mapping_looks_like_appveyor_ci_for_processor,
        yaml_external_secret_ref_segment=lambda value: re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-"),
        yaml_ref_value=lambda mapping, *keys: next((mapping[key] for key in keys if key in mapping), ""),
    ) == "appveyor-pipeline://release-pipeline"
    assert appveyor_ci_document_candidate_for_processor(
        {"build_script": "build.ps1"},
        yaml_normalized_mapping=_appveyor_normalize,
        yaml_mapping_looks_like_appveyor_ci=yaml_mapping_looks_like_appveyor_ci_for_processor,
        yaml_external_secret_ref_segment=lambda value: "",
        yaml_ref_value=lambda mapping, *keys: "",
    ) == "appveyor-pipeline://pipeline"
    assert appveyor_ci_document_candidate_for_processor(
        ["build_script"],
        yaml_normalized_mapping=_appveyor_normalize,
        yaml_mapping_looks_like_appveyor_ci=yaml_mapping_looks_like_appveyor_ci_for_processor,
        yaml_external_secret_ref_segment=lambda value: "",
        yaml_ref_value=lambda mapping, *keys: "",
    ) == ""


class _AppveyorYaml:
    @staticmethod
    def safe_load_all(text: str) -> list[Any]:
        if "raise" in text:
            raise ValueError("bad yaml")
        return [
            {"name": "Release Pipeline", "build_script": "build.ps1"},
            {"name": "Release Pipeline", "build_script": "build.ps1"},
            {"name": "Other", "ignored": True},
        ]


def test_ci_text_structured_payload_text_for_processor_extracts_appveyor_pipeline() -> None:
    assert ci_text_structured_payload_text_for_processor(
        "version: 1.0",
        source_hint="appveyor.yml",
        appveyor_ci_config_artifact_label=lambda value: "appveyor" if "appveyor" in value else "",
        yaml_module=_AppveyorYaml,
        run_ordered_local_batch=lambda values, func, default_factory: [func(value) for value in values],
        appveyor_ci_document_candidate=lambda document: appveyor_ci_document_candidate_for_processor(
            document,
            yaml_normalized_mapping=_appveyor_normalize,
            yaml_mapping_looks_like_appveyor_ci=yaml_mapping_looks_like_appveyor_ci_for_processor,
            yaml_external_secret_ref_segment=lambda value: re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-"),
            yaml_ref_value=lambda mapping, *keys: next((mapping[key] for key in keys if key in mapping), ""),
        ),
    ) == "appveyor-pipeline://release-pipeline"


def test_ci_text_structured_payload_text_for_processor_suppresses_non_appveyor_or_bad_yaml() -> None:
    assert ci_text_structured_payload_text_for_processor(
        "version: 1.0",
        source_hint="ci.yml",
        appveyor_ci_config_artifact_label=lambda value: "",
        yaml_module=_AppveyorYaml,
        run_ordered_local_batch=lambda values, func, default_factory: [func(value) for value in values],
        appveyor_ci_document_candidate=lambda document: "appveyor-pipeline://pipeline",
    ) == ""
    assert ci_text_structured_payload_text_for_processor(
        "raise",
        source_hint="appveyor.yml",
        appveyor_ci_config_artifact_label=lambda value: "appveyor",
        yaml_module=_AppveyorYaml,
        run_ordered_local_batch=lambda values, func, default_factory: [func(value) for value in values],
        appveyor_ci_document_candidate=lambda document: "appveyor-pipeline://pipeline",
    ) == ""


def test_yaml_mapping_looks_like_gitpod_config_for_processor_detects_known_keys() -> None:
    assert yaml_mapping_looks_like_gitpod_config_for_processor({"image": "ghcr.io/acme/dev:latest"})
    assert yaml_mapping_looks_like_gitpod_config_for_processor({"additionalrepositories": []})
    assert not yaml_mapping_looks_like_gitpod_config_for_processor({"name": "demo"})


def test_gitpod_document_structured_candidates_for_processor_delegates_dicts() -> None:
    assert gitpod_document_structured_candidates_for_processor(
        {"image": "ghcr.io/acme/dev:latest"},
        yaml_gitpod_config_structured_candidates=lambda document: [str(document["image"])],
    ) == ["ghcr.io/acme/dev:latest"]
    assert gitpod_document_structured_candidates_for_processor(
        ["image"],
        yaml_gitpod_config_structured_candidates=lambda document: ["unused"],
    ) == []


def test_gitpod_repository_url_candidates_for_processor_normalizes_host_path() -> None:
    assert gitpod_repository_url_candidates_for_processor(
        "GitHub.com/Acme/App.git",
        yaml_gitops_repository_candidates=lambda value: [],
        strip_git_repository_suffix=lambda value: value.removesuffix(".git"),
    ) == ["https://github.com/Acme/App"]


def test_gitpod_repository_url_candidates_for_processor_prefers_gitops_and_suppresses_invalid() -> None:
    assert gitpod_repository_url_candidates_for_processor(
        "git@github.com:acme/app.git",
        yaml_gitops_repository_candidates=lambda value: ["https://github.com/acme/app"],
        strip_git_repository_suffix=lambda value: value,
    ) == ["https://github.com/acme/app"]
    assert gitpod_repository_url_candidates_for_processor(
        "not a repository",
        yaml_gitops_repository_candidates=lambda value: [],
        strip_git_repository_suffix=lambda value: value,
    ) == []


def test_yaml_gitpod_config_structured_candidates_for_processor_extracts_images_and_repositories() -> None:
    mapping = {
        "image": "ghcr.io/acme/dev:latest",
        "additionalRepositories": [
            "github.com/acme/app.git",
            {"cloneUrl": "https://gitlab.com/acme/service.git"},
            {"repo": "github.com/acme/app.git"},
        ],
    }

    assert yaml_gitpod_config_structured_candidates_for_processor(
        mapping,
        yaml_normalized_mapping=lambda value: {str(key).lower(): item for key, item in value.items()},
        yaml_mapping_looks_like_gitpod_config=yaml_mapping_looks_like_gitpod_config_for_processor,
        run_ordered_local_batch=lambda values, func, default_factory: [func(value) for value in values],
        artifact_container_image_url_candidate=lambda value, **kwargs: str(value),
        yaml_ref_collection=lambda value, *keys: value.get("additionalRepositories", []),
        yaml_ref_value=lambda value, key: value.get(str(key).lower()),
        gitpod_repository_url_candidates=lambda value: [
            str(value).removesuffix(".git").replace("github.com/", "https://github.com/")
        ]
        if "github.com/" in str(value)
        else [str(value).removesuffix(".git")],
    ) == [
        "ghcr.io/acme/dev:latest",
        "https://github.com/acme/app",
        "https://gitlab.com/acme/service",
    ]


def test_yaml_gitpod_config_structured_candidates_for_processor_suppresses_non_gitpod() -> None:
    assert yaml_gitpod_config_structured_candidates_for_processor(
        {"name": "demo"},
        yaml_normalized_mapping=lambda value: value,
        yaml_mapping_looks_like_gitpod_config=yaml_mapping_looks_like_gitpod_config_for_processor,
        run_ordered_local_batch=lambda values, func, default_factory: [func(value) for value in values],
        artifact_container_image_url_candidate=lambda value, **kwargs: str(value),
        yaml_ref_collection=lambda value, *keys: [],
        yaml_ref_value=lambda value, key: None,
        gitpod_repository_url_candidates=lambda value: ["unused"],
    ) == []


class _GitpodYaml:
    @staticmethod
    def safe_load_all(text: str) -> list[Any]:
        if "raise" in text:
            raise ValueError("bad yaml")
        return [
            {"image": "ghcr.io/acme/dev:latest"},
            {"image": "ghcr.io/acme/dev:latest"},
            {"additionalRepositories": ["github.com/acme/app"]},
        ]


def test_gitpod_structured_payload_text_for_processor_extracts_and_dedupes_batches() -> None:
    assert gitpod_structured_payload_text_for_processor(
        "image: ghcr.io/acme/dev:latest",
        source_hint=".gitpod.yml",
        gitpod_config_artifact_label=lambda value: "gitpod" if "gitpod" in value else "",
        yaml_module=_GitpodYaml,
        run_ordered_local_batch=lambda values, func, default_factory: [func(value) for value in values],
        gitpod_document_structured_candidates=lambda document: (
            [document["image"]]
            if "image" in document
            else [str(value) for value in document.get("additionalRepositories", [])]
        ),
    ) == "\n".join(
        [
            "ghcr.io/acme/dev:latest",
            "github.com/acme/app",
        ]
    )


def test_gitpod_structured_payload_text_for_processor_suppresses_non_gitpod_or_bad_yaml() -> None:
    assert gitpod_structured_payload_text_for_processor(
        "image: ghcr.io/acme/dev:latest",
        source_hint="ci.yml",
        gitpod_config_artifact_label=lambda value: "",
        yaml_module=_GitpodYaml,
        run_ordered_local_batch=lambda values, func, default_factory: [func(value) for value in values],
        gitpod_document_structured_candidates=lambda document: ["ghcr.io/acme/dev:latest"],
    ) == ""
    assert gitpod_structured_payload_text_for_processor(
        "raise",
        source_hint=".gitpod.yml",
        gitpod_config_artifact_label=lambda value: "gitpod",
        yaml_module=_GitpodYaml,
        run_ordered_local_batch=lambda values, func, default_factory: [func(value) for value in values],
        gitpod_document_structured_candidates=lambda document: ["ghcr.io/acme/dev:latest"],
    ) == ""


def test_iter_bicep_text_blocks_for_processor_collects_nested_resource_blocks() -> None:
    pattern = re.compile(r"^\s*resource\s+\w+\s+'([^']+)'\s*=\s*\{")

    assert iter_bicep_text_blocks_for_processor(
        "\n".join(
            [
                "param location string",
                "resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {",
                "  name: 'acct'",
                "  properties: {",
                "    allowBlobPublicAccess: false",
                "  }",
                "}",
                "resource app 'Microsoft.Web/sites@2022-09-01' = {",
                "  name: 'app'",
                "}",
            ]
        ),
        bicep_resource_start_pattern=pattern,
    ) == [
        (
            "microsoft.storage/storageaccounts@2023-01-01",
            "\n".join(
                [
                    "resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {",
                    "  name: 'acct'",
                    "  properties: {",
                    "    allowBlobPublicAccess: false",
                    "  }",
                    "}",
                ]
            ),
        ),
        (
            "microsoft.web/sites@2022-09-01",
            "\n".join(
                [
                    "resource app 'Microsoft.Web/sites@2022-09-01' = {",
                    "  name: 'app'",
                    "}",
                ]
            ),
        ),
    ]


def test_iter_bicep_text_blocks_for_processor_keeps_unclosed_block() -> None:
    pattern = re.compile(r"^\s*resource\s+\w+\s+'([^']+)'\s*=\s*\{")

    assert iter_bicep_text_blocks_for_processor(
        "resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: 'acct'",
        bicep_resource_start_pattern=pattern,
    ) == [
        (
            "microsoft.storage/storageaccounts@2023-01-01",
            "resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: 'acct'",
        )
    ]


def test_bicep_block_assignments_for_processor_binds_ordered_line_batch() -> None:
    calls: list[tuple[Any, ...]] = []

    def _line_entry(line_entry: tuple[int, str]) -> tuple[str, str] | None:
        calls.append(("line", line_entry))
        _index, line = line_entry
        if ":" not in line:
            return None
        key, value = line.split(":", 1)
        return key.strip().lower(), value.strip().strip("'\"")

    def _run_ordered_batch(
        items: list[Any],
        worker: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        calls.append(("batch", list(items), default_factory()))
        return [worker(item) for item in items] + [None, ("bad",), ("name", "override")]

    assert bicep_block_assignments_for_processor(
        "name: 'acct'\nignored\nName: 'acct2'",
        bicep_assignment_line_entry=_line_entry,
        run_ordered_batch=_run_ordered_batch,
    ) == {"name": "override"}
    assert calls[0] == (
        "batch",
        [(0, "name: 'acct'"), (1, "ignored"), (2, "Name: 'acct2'")],
        None,
    )
    assert ("line", (0, "name: 'acct'")) in calls
    assert ("line", (2, "Name: 'acct2'")) in calls


def test_bicep_block_assignments_for_processor_handles_empty_text() -> None:
    assert bicep_block_assignments_for_processor(
        "",
        bicep_assignment_line_entry=lambda _line_entry: ("name", "acct"),
        run_ordered_batch=lambda items, worker, *, default_factory: [worker(item) for item in items],
    ) == {}


def test_bicep_assignment_line_entry_for_processor_parses_quoted_assignments() -> None:
    assert bicep_assignment_line_entry_for_processor((4, "  Name: 'acct'  ")) == ("name", "acct")
    assert bicep_assignment_line_entry_for_processor((5, 'endpoint_url: "https://example.test"')) == (
        "endpoint_url",
        "https://example.test",
    )


def test_bicep_assignment_line_entry_for_processor_suppresses_comments_and_non_matches() -> None:
    assert bicep_assignment_line_entry_for_processor((0, "")) is None
    assert bicep_assignment_line_entry_for_processor((1, "// name: 'acct'")) is None
    assert bicep_assignment_line_entry_for_processor((2, "/* name: 'acct' */")) is None
    assert bicep_assignment_line_entry_for_processor((3, "* name: 'acct'")) is None
    assert bicep_assignment_line_entry_for_processor((4, "name: acct")) is None
    assert bicep_assignment_line_entry_for_processor((5, "name: ''")) is None


def test_bicep_text_structured_payload_text_for_processor_orders_and_dedupes_candidates() -> None:
    calls: list[tuple[Any, ...]] = []

    def _iter_blocks(text: str) -> list[tuple[str, str]]:
        calls.append(("iter", text))
        return [("type-a", "block-a"), ("type-b", "block-b"), ("type-c", "block-c")]

    def _block_candidate(block_job: tuple[str, str]) -> str:
        calls.append(("candidate", block_job))
        return {
            "type-a": "https://Example.test",
            "type-b": "https://example.test",
            "type-c": "s3://bucket",
        }[block_job[0]]

    def _candidate_entry(entry: tuple[int, str]) -> tuple[str, str] | None:
        calls.append(("entry", entry))
        index, candidate = entry
        if not isinstance(candidate, str) or not candidate:
            return None
        if index == 1:
            return candidate, "https://example.test"
        return candidate, candidate.lower()

    def _run_ordered_batch(
        items: list[Any],
        worker: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        calls.append(("batch", list(items), default_factory()))
        return [worker(item) for item in items] + [None, ("bad",)]

    assert (
        bicep_text_structured_payload_text_for_processor(
            "bicep text",
            iter_bicep_text_blocks=_iter_blocks,
            bicep_text_block_candidate=_block_candidate,
            structured_candidate_entry=_candidate_entry,
            run_ordered_batch=_run_ordered_batch,
        )
        == "https://Example.test\ns3://bucket"
    )
    assert calls[0] == ("iter", "bicep text")
    assert (
        "batch",
        [("type-a", "block-a"), ("type-b", "block-b"), ("type-c", "block-c")],
        "",
    ) in calls
    assert (
        "batch",
        [(0, "https://Example.test"), (1, "https://example.test"), (2, "s3://bucket"), (3, None), (4, ("bad",))],
        None,
    ) in calls


def test_bicep_text_structured_payload_text_for_processor_handles_empty_blocks() -> None:
    assert (
        bicep_text_structured_payload_text_for_processor(
            "bicep text",
            iter_bicep_text_blocks=lambda _text: [],
            bicep_text_block_candidate=lambda _block_job: "s3://bucket",
            structured_candidate_entry=lambda _entry: ("s3://bucket", "s3://bucket"),
            run_ordered_batch=lambda items, worker, *, default_factory: [worker(item) for item in items],
        )
        == ""
    )


def test_bicep_text_block_candidate_for_processor_builds_mapping_and_returns_first_candidate() -> None:
    calls: list[tuple[Any, ...]] = []

    def _assignments(block_text: str) -> dict[str, str]:
        calls.append(("assignments", block_text))
        return {"name": "assets", "kind": "StorageV2"}

    def _normalize(mapping: dict[str, Any]) -> dict[str, Any]:
        calls.append(("normalize", mapping))
        return {"normalized": mapping["type"], "properties": mapping["properties"]}

    def _candidates(mapping: dict[str, Any], normalized: dict[str, Any]) -> list[str]:
        calls.append(("candidates", mapping, normalized))
        return ["s3://assets", "s3://ignored"]

    assert (
        bicep_text_block_candidate_for_processor(
            ("Microsoft.Storage/storageAccounts@2023-01-01", "block text"),
            bicep_block_assignments=_assignments,
            yaml_normalized_mapping=_normalize,
            iac_resource_structured_candidates=_candidates,
        )
        == "s3://assets"
    )
    expected_mapping = {
        "type": "Microsoft.Storage/storageAccounts@2023-01-01",
        "properties": {"name": "assets", "kind": "StorageV2"},
        "name": "assets",
        "kind": "StorageV2",
    }
    assert calls[0] == ("assignments", "block text")
    assert ("normalize", expected_mapping) in calls
    assert ("candidates", expected_mapping, {"normalized": expected_mapping["type"], "properties": expected_mapping["properties"]}) in calls


def test_bicep_text_block_candidate_for_processor_suppresses_empty_assignments_and_candidates() -> None:
    assert (
        bicep_text_block_candidate_for_processor(
            ("type", "block"),
            bicep_block_assignments=lambda _block_text: {},
            yaml_normalized_mapping=lambda mapping: mapping,
            iac_resource_structured_candidates=lambda _mapping, _normalized: ["s3://assets"],
        )
        == ""
    )
    assert (
        bicep_text_block_candidate_for_processor(
            ("type", "block"),
            bicep_block_assignments=lambda _block_text: {"name": "assets"},
            yaml_normalized_mapping=lambda mapping: mapping,
            iac_resource_structured_candidates=lambda _mapping, _normalized: [],
        )
        == ""
    )


def test_goreleaser_scalar_values_for_processor_flattens_bounded_values() -> None:
    assert goreleaser_scalar_values_for_processor(
        {
            "image": "ghcr.io/acme/app:{{ .Tag }}",
            "nested": [42, {"value": 1.5}, None],
        }
    ) == ["ghcr.io/acme/app:{{ .Tag }}", "42", "1.5"]


def test_goreleaser_image_template_values_for_processor_binds_candidate_callback() -> None:
    calls: list[tuple[Any, ...]] = []

    def _candidate(raw_value: str, *, require_explicit_registry: bool) -> str:
        calls.append((raw_value, require_explicit_registry))
        if raw_value.startswith("ghcr.io/"):
            return "ghcr.io/acme/app"
        return ""

    assert goreleaser_image_template_values_for_processor(
        ["ghcr.io/acme/app:{{ .Tag }}", "acme/app:{{ .Tag }}"],
        templated_container_image_url_candidate=_candidate,
    ) == ["ghcr.io/acme/app"]
    assert calls == [
        ("ghcr.io/acme/app:{{ .Tag }}", True),
        ("acme/app:{{ .Tag }}", True),
    ]


def test_goreleaser_blob_bucket_value_for_processor_normalizes_cloud_buckets() -> None:
    def _normalized(mapping: dict[str, Any]) -> dict[str, Any]:
        return {str(key).lower(): value for key, value in mapping.items()}

    def _fingerprint(value: str) -> str:
        return str(value or "").lower().replace("-", "")

    def _ref_value(mapping: dict[str, Any], *keys: str) -> str:
        return next(
            (str(mapping.get(str(key).lower(), "")) for key in keys if mapping.get(str(key).lower(), "")),
            "",
        )

    def _valid_bucket(value: str) -> str:
        return str(value or "").strip().lower()

    assert (
        goreleaser_blob_bucket_value_for_processor(
            {"provider": "aws", "bucketName": "acme-release-artifacts"},
            yaml_normalized_mapping=_normalized,
            yaml_key_fingerprint=_fingerprint,
            yaml_ref_value=_ref_value,
            yaml_valid_bucket_name=_valid_bucket,
        )
        == "s3://acme-release-artifacts"
    )
    assert (
        goreleaser_blob_bucket_value_for_processor(
            {"type": "google-cloud-storage", "name": "acme-release-gcs"},
            yaml_normalized_mapping=_normalized,
            yaml_key_fingerprint=_fingerprint,
            yaml_ref_value=_ref_value,
            yaml_valid_bucket_name=_valid_bucket,
        )
        == "gs://acme-release-gcs"
    )
    assert (
        goreleaser_blob_bucket_value_for_processor(
            {"provider": "s3", "bucket": "UPPER"},
            yaml_normalized_mapping=lambda mapping: mapping,
            yaml_key_fingerprint=lambda value: str(value or "").lower(),
            yaml_ref_value=lambda mapping, *keys: next(
                (str(mapping.get(key, "")) for key in keys if mapping.get(key, "")),
                "",
            ),
            yaml_valid_bucket_name=lambda value: str(value or "").strip(),
        )
        == ""
    )


def test_yaml_mapping_looks_like_goreleaser_config_for_processor_detects_markers() -> None:
    assert yaml_mapping_looks_like_goreleaser_config_for_processor(
        {"projectname": "acme", "dockers": []},
        "release.yaml",
    )
    assert yaml_mapping_looks_like_goreleaser_config_for_processor(
        {"blobs": []},
        ".goreleaser.yaml",
    )
    assert not yaml_mapping_looks_like_goreleaser_config_for_processor(
        {"dockers": []},
        "release.yaml",
    )
    assert not yaml_mapping_looks_like_goreleaser_config_for_processor(
        {"projectname": "acme"},
        "release.yaml",
    )


def test_yaml_goreleaser_config_structured_candidates_for_processor_gates_and_dedupes() -> None:
    calls: list[tuple[Any, ...]] = []

    def _looks_like(mapping: dict[str, Any], normalized: dict[str, Any], path_hint: str) -> bool:
        calls.append(("looks", mapping, normalized, path_hint))
        return path_hint == ".goreleaser.yaml"

    def _values(value: Any, path: tuple[str, ...], *, use_workers: bool) -> list[str]:
        calls.append(("values", value, path, use_workers))
        return [" ghcr.io/acme/app ", "GHCR.IO/acme/app", "", None, "s3://release-bucket"]

    mapping = {"dockers": []}
    normalized = {"dockers": []}

    assert yaml_goreleaser_config_structured_candidates_for_processor(
        mapping,
        normalized,
        ".goreleaser.yaml",
        yaml_mapping_looks_like_goreleaser_config=_looks_like,
        yaml_goreleaser_candidate_values_for_node=_values,
    ) == ["ghcr.io/acme/app", "s3://release-bucket"]
    assert calls == [
        ("looks", mapping, normalized, ".goreleaser.yaml"),
        ("values", mapping, (), True),
    ]

    calls.clear()
    assert yaml_goreleaser_config_structured_candidates_for_processor(
        mapping,
        normalized,
        "release.yaml",
        yaml_mapping_looks_like_goreleaser_config=_looks_like,
        yaml_goreleaser_candidate_values_for_node=_values,
    ) == []
    assert calls == [("looks", mapping, normalized, "release.yaml")]


def test_yaml_goreleaser_child_candidate_values_for_node_for_processor_routes_docker_images() -> None:
    calls: list[tuple[Any, ...]] = []

    def _fingerprint(value: str) -> str:
        calls.append(("fingerprint", value))
        return value.lower().replace("_", "")

    def _images(value: Any) -> list[str]:
        calls.append(("images", value))
        return ["ghcr.io/acme/app"]

    def _recurse(value: Any, path: tuple[str, ...], *, use_workers: bool) -> list[str]:
        calls.append(("recurse", value, path, use_workers))
        return ["s3://release-bucket"]

    assert yaml_goreleaser_child_candidate_values_for_node_for_processor(
        "image_template",
        "ghcr.io/acme/app:{{ .Tag }}",
        ("dockers",),
        yaml_key_fingerprint=_fingerprint,
        yaml_goreleaser_image_template_values=_images,
        yaml_goreleaser_candidate_values_for_node=_recurse,
    ) == ["ghcr.io/acme/app", "s3://release-bucket"]
    assert calls == [
        ("fingerprint", "image_template"),
        ("images", "ghcr.io/acme/app:{{ .Tag }}"),
        ("recurse", "ghcr.io/acme/app:{{ .Tag }}", ("dockers", "imagetemplate"), False),
    ]


def test_yaml_goreleaser_child_candidate_values_for_node_for_processor_skips_non_docker_images() -> None:
    calls: list[tuple[Any, ...]] = []

    assert yaml_goreleaser_child_candidate_values_for_node_for_processor(
        "image",
        "ghcr.io/acme/app:{{ .Tag }}",
        ("archives",),
        yaml_key_fingerprint=lambda value: value.lower(),
        yaml_goreleaser_image_template_values=lambda value: calls.append(("images", value)) or ["ignored"],
        yaml_goreleaser_candidate_values_for_node=lambda value, path, *, use_workers: (
            calls.append(("recurse", value, path, use_workers)) or ["archive-result"]
        ),
    ) == ["archive-result"]
    assert calls == [
        ("recurse", "ghcr.io/acme/app:{{ .Tag }}", ("archives", "image"), False),
    ]


def test_yaml_goreleaser_child_candidate_values_for_processor_unpacks_job() -> None:
    calls: list[tuple[Any, ...]] = []

    def _child_values(key: Any, child: Any, path: tuple[str, ...]) -> list[str]:
        calls.append((key, child, path))
        return ["candidate"]

    assert yaml_goreleaser_child_candidate_values_for_processor(
        (4, "image", "ghcr.io/acme/app:{{ .Tag }}", ("dockers",)),
        yaml_goreleaser_child_candidate_values_for_node=_child_values,
    ) == ["candidate"]
    assert calls == [("image", "ghcr.io/acme/app:{{ .Tag }}", ("dockers",))]


def test_yaml_gitops_repository_child_values_for_processor_recurses_without_workers() -> None:
    calls: list[tuple[Any, bool]] = []

    def _repository_values(child: Any, *, use_workers: bool) -> list[str]:
        calls.append((child, use_workers))
        return ["https://github.com/acme/app"]

    child = {"repoURL": "https://github.com/acme/app"}

    assert yaml_gitops_repository_child_values_for_processor(
        (7, child),
        yaml_gitops_repository_values_for_node=_repository_values,
    ) == ["https://github.com/acme/app"]
    assert calls == [(child, False)]


def test_yaml_gitops_repository_candidates_for_processor_normalizes_repository_urls() -> None:
    def _normalize(value: str) -> str:
        return value.rstrip("/")

    def _image_candidate(value: str) -> str:
        return value.removeprefix("oci://").removeprefix("docker://")

    assert yaml_gitops_repository_candidates_for_processor(
        " 'https://github.com/acme/app.git/' ",
        normalize_artifact_text_url=_normalize,
        artifact_container_image_url_candidate=_image_candidate,
        strip_git_repository_suffix=strip_git_repository_suffix_for_processor,
    ) == ["https://github.com/acme/app"]
    assert yaml_gitops_repository_candidates_for_processor(
        "git@GitHub.com:acme/app.git",
        normalize_artifact_text_url=_normalize,
        artifact_container_image_url_candidate=_image_candidate,
        strip_git_repository_suffix=strip_git_repository_suffix_for_processor,
    ) == ["https://github.com/acme/app"]
    assert yaml_gitops_repository_candidates_for_processor(
        "ssh://git@example.com/acme/app.git",
        normalize_artifact_text_url=_normalize,
        artifact_container_image_url_candidate=_image_candidate,
        strip_git_repository_suffix=strip_git_repository_suffix_for_processor,
    ) == ["https://example.com/acme/app"]
    assert yaml_gitops_repository_candidates_for_processor(
        "git://example.com/acme/app.git",
        normalize_artifact_text_url=_normalize,
        artifact_container_image_url_candidate=_image_candidate,
        strip_git_repository_suffix=strip_git_repository_suffix_for_processor,
    ) == ["https://example.com/acme/app"]


def test_yaml_gitops_repository_candidates_for_processor_handles_images_and_empty_values() -> None:
    def _normalize(_value: str) -> str:
        return ""

    def _image_candidate(value: str) -> str:
        return "ghcr.io/acme/app:1.0" if value.startswith(("oci://", "docker://")) else ""

    assert yaml_gitops_repository_candidates_for_processor(
        "oci://ghcr.io/acme/app:1.0",
        normalize_artifact_text_url=_normalize,
        artifact_container_image_url_candidate=_image_candidate,
        strip_git_repository_suffix=strip_git_repository_suffix_for_processor,
    ) == ["ghcr.io/acme/app:1.0"]
    assert yaml_gitops_repository_candidates_for_processor(
        "not a repository",
        normalize_artifact_text_url=_normalize,
        artifact_container_image_url_candidate=_image_candidate,
        strip_git_repository_suffix=strip_git_repository_suffix_for_processor,
    ) == []
    assert yaml_gitops_repository_candidates_for_processor(
        "",
        normalize_artifact_text_url=_normalize,
        artifact_container_image_url_candidate=_image_candidate,
        strip_git_repository_suffix=strip_git_repository_suffix_for_processor,
    ) == []


def test_yaml_gitops_repository_candidates_from_mapping_for_processor_batches_and_dedupes() -> None:
    calls: list[tuple[Any, ...]] = []
    mapping = {"repoURL": "https://github.com/acme/app"}

    def _values(value: dict[str, Any], *, use_workers: bool) -> list[str]:
        calls.append(("values", value, use_workers))
        return ["one", "two", "three"]

    def _candidates(value: str) -> list[str]:
        calls.append(("candidate", value))
        return {
            "one": ["https://github.com/acme/app", "https://github.com/acme/api"],
            "two": ["https://github.com/acme/App", "https://github.com/acme/worker"],
        }.get(value, [])

    def _run_batch(
        items: list[str],
        worker: Callable[[str], list[str]],
        *,
        default_factory: Callable[[], list[str]],
    ) -> list[list[str]]:
        calls.append(("batch", list(items), default_factory()))
        return [worker(item) for item in items]

    assert yaml_gitops_repository_candidates_from_mapping_for_processor(
        mapping,
        yaml_gitops_repository_values_for_node=_values,
        yaml_gitops_repository_candidates=_candidates,
        run_ordered_local_batch=_run_batch,
    ) == [
        "https://github.com/acme/app",
        "https://github.com/acme/api",
        "https://github.com/acme/worker",
    ]
    assert calls == [
        ("values", mapping, True),
        ("batch", ["one", "two", "three"], []),
        ("candidate", "one"),
        ("candidate", "two"),
        ("candidate", "three"),
    ]


def test_yaml_gitops_repository_values_for_node_for_processor_extracts_direct_and_hint_values() -> None:
    def _normalize(mapping: dict[str, Any]) -> dict[str, Any]:
        return mapping

    def _ref(mapping: dict[str, Any], key: str) -> str:
        value = mapping.get(key)
        return str(value).strip() if value else ""

    assert yaml_gitops_repository_values_for_node_for_processor(
        {
            "repoURL": "https://github.com/acme/app",
            "name": "sourceURL",
            "value": "git@github.com:acme/worker.git",
            "nested": {"url": "https://github.com/acme/api"},
        },
        use_workers=False,
        yaml_normalized_mapping=_normalize,
        yaml_ref_value=_ref,
        yaml_key_fingerprint=lambda value: value.lower(),
        yaml_gitops_repository_child_values=lambda _job: ["worker-only"],
        run_ordered_local_batch=lambda items, worker, *, default_factory: [worker(item) for item in items],
    ) == [
        "https://github.com/acme/app",
        "git@github.com:acme/worker.git",
        "https://github.com/acme/api",
    ]


def test_yaml_gitops_repository_values_for_node_for_processor_uses_workers_for_children() -> None:
    calls: list[tuple[Any, ...]] = []

    def _run_batch(
        items: list[tuple[int, Any]],
        worker: Callable[[tuple[int, Any]], list[str]],
        *,
        default_factory: Callable[[], list[str]],
    ) -> list[list[str]]:
        calls.append(("batch", list(items), default_factory()))
        return [worker(item) for item in items]

    def _child_values(job: tuple[int, Any]) -> list[str]:
        calls.append(("child", job))
        _index, child = job
        return [child["repoURL"]] if isinstance(child, dict) and "repoURL" in child else []

    value = [{"repoURL": "https://github.com/acme/app"}, {"name": "skip"}]

    assert yaml_gitops_repository_values_for_node_for_processor(
        value,
        use_workers=True,
        yaml_normalized_mapping=lambda mapping: mapping,
        yaml_ref_value=lambda mapping, key: str(mapping.get(key, "") or ""),
        yaml_key_fingerprint=lambda value: value.lower(),
        yaml_gitops_repository_child_values=_child_values,
        run_ordered_local_batch=_run_batch,
    ) == ["https://github.com/acme/app"]
    assert calls == [
        ("batch", [(0, {"repoURL": "https://github.com/acme/app"}), (1, {"name": "skip"})], []),
        ("child", (0, {"repoURL": "https://github.com/acme/app"})),
        ("child", (1, {"name": "skip"})),
    ]


def test_yaml_flux_source_ref_candidates_for_processor_maps_supported_kinds() -> None:
    def _normalize(mapping: dict[str, Any]) -> dict[str, Any]:
        return {str(key).lower(): value for key, value in mapping.items()}

    def _ref(mapping: dict[str, Any], key: str) -> str:
        return str(mapping.get(key.lower(), "") or "")

    def _segment(value: Any) -> str:
        return str(value or "").strip().replace(" ", "-")

    common = {
        "yaml_normalized_mapping": _normalize,
        "yaml_ref_value": _ref,
        "yaml_key_fingerprint": lambda value: value.lower(),
        "yaml_external_secret_ref_segment": _segment,
    }

    assert yaml_flux_source_ref_candidates_for_processor(
        {"kind": "GitRepository", "name": "app-repo", "namespace": "team-a"},
        **common,
    ) == ["flux-gitrepository://team-a/app-repo"]
    assert yaml_flux_source_ref_candidates_for_processor(
        {"kind": "HelmRepository", "name": "charts"},
        **common,
    ) == ["flux-helmrepository://charts"]
    assert yaml_flux_source_ref_candidates_for_processor(
        {"kind": "OCIRepository", "name": "images"},
        **common,
    ) == ["flux-ocirepository://images"]
    assert yaml_flux_source_ref_candidates_for_processor(
        {"kind": "Bucket", "name": "state"},
        **common,
    ) == ["flux-bucket://state"]


def test_yaml_flux_source_ref_candidates_for_processor_suppresses_missing_and_unknown_refs() -> None:
    common = {
        "yaml_normalized_mapping": lambda mapping: mapping,
        "yaml_ref_value": lambda mapping, key: str(mapping.get(key, "") or ""),
        "yaml_key_fingerprint": lambda value: value.lower(),
        "yaml_external_secret_ref_segment": lambda value: str(value or "").strip(),
    }

    assert yaml_flux_source_ref_candidates_for_processor({"kind": "GitRepository"}, **common) == []
    assert yaml_flux_source_ref_candidates_for_processor({"name": "app"}, **common) == []
    assert yaml_flux_source_ref_candidates_for_processor({"kind": "Kustomization", "name": "app"}, **common) == []


def test_yaml_flux_bucket_structured_candidates_for_processor_maps_provider_outputs() -> None:
    do_pattern = re.compile(r"^(?:(?P<bucket>[a-z0-9.\-]{3,63})\.)?(?P<region>[a-z0-9\-]{2,32})\.digitaloceanspaces\.com$")
    common = {
        "yaml_normalized_mapping": lambda mapping: mapping,
        "yaml_ref_value": lambda mapping, *keys: next((str(mapping.get(key, "") or "") for key in keys if mapping.get(key)), ""),
        "yaml_valid_bucket_name": lambda value: str(value or "").strip().lower(),
        "yaml_external_secret_ref_segment": lambda value: str(value or "").strip().lower(),
        "do_spaces_endpoint_host_re": do_pattern,
    }

    assert yaml_flux_bucket_structured_candidates_for_processor(
        {"bucketName": "Team-Logs", "provider": "google"},
        **common,
    ) == ["gs://team-logs"]
    assert yaml_flux_bucket_structured_candidates_for_processor(
        {"bucket": "snapshots", "provider": "azure", "accountName": "acct123"},
        **common,
    ) == ["https://acct123.blob.core.windows.net/snapshots"]
    assert yaml_flux_bucket_structured_candidates_for_processor(
        {"name": "assets", "endpoint": "sgp1.digitaloceanspaces.com"},
        **common,
    ) == ["https://assets.sgp1.digitaloceanspaces.com"]
    assert yaml_flux_bucket_structured_candidates_for_processor(
        {"bucket": "backups", "provider": "aws"},
        **common,
    ) == ["s3://backups"]


def test_yaml_flux_bucket_structured_candidates_for_processor_suppresses_empty_and_invalid_buckets() -> None:
    common = {
        "yaml_normalized_mapping": lambda mapping: mapping,
        "yaml_ref_value": lambda mapping, *keys: next((str(mapping.get(key, "") or "") for key in keys if mapping.get(key)), ""),
        "yaml_valid_bucket_name": lambda value: str(value or "").strip().lower() if str(value or "").strip() != "bad" else "",
        "yaml_external_secret_ref_segment": lambda value: str(value or "").strip().lower(),
        "do_spaces_endpoint_host_re": re.compile(r"(?P<region>[a-z0-9-]+)\.digitaloceanspaces\.com"),
    }

    assert yaml_flux_bucket_structured_candidates_for_processor({}, **common) == []
    assert yaml_flux_bucket_structured_candidates_for_processor({"bucket": "bad"}, **common) == []


def test_yaml_manifest_looks_like_crossplane_for_processor_detects_crossplane_groups() -> None:
    assert yaml_manifest_looks_like_crossplane_for_processor("s3.aws.crossplane.io/v1beta1")
    assert yaml_manifest_looks_like_crossplane_for_processor("ec2.aws.upbound.io/v1beta1")
    assert yaml_manifest_looks_like_crossplane_for_processor("pkg.crossplane.io/v1")


def test_yaml_manifest_looks_like_crossplane_for_processor_suppresses_unrelated_groups() -> None:
    assert not yaml_manifest_looks_like_crossplane_for_processor("apps/v1")
    assert not yaml_manifest_looks_like_crossplane_for_processor("crossplane.example.com/v1")
    assert not yaml_manifest_looks_like_crossplane_for_processor("")


def test_crossplane_provider_family_for_processor_detects_known_providers() -> None:
    assert crossplane_provider_family_for_processor("s3.aws.upbound.io/v1beta1") == "aws"
    assert crossplane_provider_family_for_processor("compute.gcp.crossplane.io/v1beta1") == "gcp"
    assert crossplane_provider_family_for_processor("network.azure.upbound.io/v1beta1") == "azure"
    assert crossplane_provider_family_for_processor("kubernetes.crossplane.io/v1alpha1") == "kubernetes"
    assert crossplane_provider_family_for_processor("spaces.digitalocean.crossplane.io/v1alpha1") == "digitalocean"
    assert crossplane_provider_family_for_processor("dns.cloudflare.crossplane.io/v1alpha1") == "cloudflare"


def test_crossplane_provider_family_for_processor_falls_back_to_normalized_group() -> None:
    assert crossplane_provider_family_for_processor("database.example.io/v1") == "database-example-io"
    assert crossplane_provider_family_for_processor("") == "crossplane"


def test_yaml_crossplane_external_name_for_processor_extracts_matching_annotation() -> None:
    def _child_mapping(mapping: dict[str, Any], *keys: str) -> dict[str, Any]:
        for key in keys:
            value = mapping.get(key)
            if isinstance(value, dict):
                return value
        return {}

    assert yaml_crossplane_external_name_for_processor(
        {
            "metadata": {
                "annotations": {
                    " Crossplane.io/External-Name ": " Prod Bucket ",
                    "other": "ignored",
                }
            }
        },
        yaml_child_mapping=_child_mapping,
        yaml_external_secret_ref_segment=lambda value: str(value or "").strip().lower().replace(" ", "-"),
    ) == "prod-bucket"


def test_yaml_crossplane_external_name_for_processor_suppresses_missing_annotation() -> None:
    common = {
        "yaml_child_mapping": lambda mapping, *keys: mapping.get(keys[0], {}) if isinstance(mapping.get(keys[0]), dict) else {},
        "yaml_external_secret_ref_segment": lambda value: str(value or "").strip(),
    }

    assert yaml_crossplane_external_name_for_processor({}, **common) == ""
    assert yaml_crossplane_external_name_for_processor({"metadata": {"annotations": {"other": "value"}}}, **common) == ""


def test_yaml_crossplane_cloud_candidates_for_processor_maps_bucket_providers() -> None:
    common = {
        "mapping": {},
        "yaml_child_mapping": lambda mapping, *keys: next((mapping[key] for key in keys if isinstance(mapping.get(key), dict)), {}),
        "yaml_normalized_mapping": lambda mapping: mapping,
        "yaml_ref_value": lambda mapping, *keys: next((str(mapping.get(key, "") or "") for key in keys if mapping.get(key)), ""),
        "yaml_valid_bucket_name": lambda value: str(value or "").strip().lower(),
    }

    assert yaml_crossplane_cloud_candidates_for_processor(
        kind="bucket",
        api_version="s3.aws.upbound.io/v1beta1",
        spec={"forProvider": {"bucketName": "Team-Logs"}},
        resource_name="fallback",
        **common,
    ) == ["s3://team-logs"]
    assert yaml_crossplane_cloud_candidates_for_processor(
        kind="bucket",
        api_version="storage.gcp.crossplane.io/v1beta1",
        spec={"forProvider": {"name": "Gcp-Logs"}},
        resource_name="fallback",
        **common,
    ) == ["gs://gcp-logs"]
    assert yaml_crossplane_cloud_candidates_for_processor(
        kind="bucket",
        api_version="s3.aws.upbound.io/v1beta1",
        spec={"forProvider": {}},
        resource_name="Fallback-Bucket",
        **common,
    ) == ["s3://fallback-bucket"]


def test_yaml_crossplane_cloud_candidates_for_processor_maps_azure_and_suppresses_invalid() -> None:
    common = {
        "mapping": {},
        "yaml_child_mapping": lambda mapping, *keys: next((mapping[key] for key in keys if isinstance(mapping.get(key), dict)), {}),
        "yaml_normalized_mapping": lambda mapping: mapping,
        "yaml_ref_value": lambda mapping, *keys: next((str(mapping.get(key, "") or "") for key in keys if mapping.get(key)), ""),
        "yaml_valid_bucket_name": lambda value: str(value or "").strip().lower(),
    }

    assert yaml_crossplane_cloud_candidates_for_processor(
        kind="container",
        api_version="storage.azure.upbound.io/v1beta1",
        spec={"forProvider": {"accountName": "acct123", "containerName": "Snapshots"}},
        resource_name="fallback",
        **common,
    ) == ["https://acct123.blob.core.windows.net/snapshots"]
    assert yaml_crossplane_cloud_candidates_for_processor(
        kind="container",
        api_version="storage.azure.upbound.io/v1beta1",
        spec={"forProvider": {"accountName": "Acct123", "containerName": "Snapshots"}},
        resource_name="fallback",
        **common,
    ) == []
    assert yaml_crossplane_cloud_candidates_for_processor(
        kind="database",
        api_version="database.example.io/v1",
        spec={"forProvider": {"name": "db"}},
        resource_name="fallback",
        **common,
    ) == []


def test_yaml_crossplane_structured_candidates_for_processor_handles_identity_resources() -> None:
    common = {
        "mapping": {"spec": {}},
        "api_version": "pkg.crossplane.io/v1",
        "crossplane_provider_family": lambda _api_version: "crossplane",
        "yaml_child_mapping": lambda mapping, *keys: next((mapping[key] for key in keys if isinstance(mapping.get(key), dict)), {}),
        "yaml_external_secret_ref_segment": lambda value: str(value or "").strip(),
        "yaml_ref_value": lambda mapping, *keys: next((str(mapping.get(key, "") or "") for key in keys if mapping.get(key)), ""),
        "yaml_normalized_mapping": lambda mapping: mapping,
        "yaml_crossplane_external_name": lambda _mapping: "",
        "yaml_crossplane_cloud_candidates": lambda **_kwargs: [],
    }

    assert yaml_crossplane_structured_candidates_for_processor(
        kind="providerconfig",
        object_identifier="default",
        **common,
    ) == ["crossplane-providerconfig://crossplane/default"]
    assert yaml_crossplane_structured_candidates_for_processor(
        kind="composition",
        object_identifier="apps.example.org",
        **common,
    ) == ["crossplane-composition://apps.example.org"]
    assert yaml_crossplane_structured_candidates_for_processor(
        kind="compositeresourcedefinition",
        object_identifier="xapps.example.org",
        **common,
    ) == ["crossplane-xrd://xapps.example.org"]


def test_yaml_crossplane_structured_candidates_for_processor_combines_refs_resource_and_cloud() -> None:
    calls: list[tuple[Any, ...]] = []
    mapping = {
        "spec": {
            "providerConfigRef": {"name": " team-prod "},
        },
        "metadata": {"name": "bucket"},
    }

    def _child_mapping(value: dict[str, Any], *keys: str) -> dict[str, Any]:
        calls.append(("child", tuple(keys)))
        return next((value[key] for key in keys if isinstance(value.get(key), dict)), {})

    def _cloud_candidates(**kwargs: Any) -> list[str]:
        calls.append(("cloud", kwargs["kind"], kwargs["resource_name"], kwargs["spec"]))
        return [f"s3://{kwargs['resource_name']}"]

    assert yaml_crossplane_structured_candidates_for_processor(
        mapping,
        kind="bucket",
        api_version="s3.aws.upbound.io/v1beta1",
        object_identifier="object-name",
        crossplane_provider_family=lambda _api_version: "aws",
        yaml_child_mapping=_child_mapping,
        yaml_external_secret_ref_segment=lambda value: str(value or "").strip(),
        yaml_ref_value=lambda value, *keys: next((str(value.get(key, "") or "") for key in keys if value.get(key)), ""),
        yaml_normalized_mapping=lambda value: value,
        yaml_crossplane_external_name=lambda _mapping: "external-bucket",
        yaml_crossplane_cloud_candidates=_cloud_candidates,
    ) == [
        "crossplane-providerconfig://aws/team-prod",
        "crossplane-resource://aws/bucket/external-bucket",
        "s3://external-bucket",
    ]
    assert calls == [
        ("child", ("spec",)),
        ("child", ("providerConfigRef", "provider_config_ref")),
        ("cloud", "bucket", "external-bucket", mapping["spec"]),
    ]


def test_yaml_kubernetes_object_identifier_for_processor_formats_namespaced_identifier() -> None:
    def _child_mapping(mapping: dict[str, Any], *keys: str) -> dict[str, Any]:
        return next((mapping[key] for key in keys if isinstance(mapping.get(key), dict)), {})

    common = {
        "yaml_child_mapping": _child_mapping,
        "yaml_normalized_mapping": lambda mapping: mapping,
        "yaml_ref_value": lambda mapping, *keys: next((str(mapping.get(key, "") or "") for key in keys if mapping.get(key)), ""),
        "yaml_external_secret_ref_segment": lambda value: str(value or "").strip().lower().replace(" ", "-"),
    }

    assert yaml_kubernetes_object_identifier_for_processor(
        {"metadata": {"namespace": " Team A ", "name": " Prod Secret "}},
        **common,
    ) == "team-a/prod-secret"
    assert yaml_kubernetes_object_identifier_for_processor(
        {"metadata": {"name": " Cluster Store "}},
        **common,
    ) == "cluster-store"


def test_yaml_kubernetes_object_identifier_for_processor_suppresses_missing_metadata_or_name() -> None:
    common = {
        "yaml_child_mapping": lambda mapping, *keys: next((mapping[key] for key in keys if isinstance(mapping.get(key), dict)), {}),
        "yaml_normalized_mapping": lambda mapping: mapping,
        "yaml_ref_value": lambda mapping, *keys: next((str(mapping.get(key, "") or "") for key in keys if mapping.get(key)), ""),
        "yaml_external_secret_ref_segment": lambda value: str(value or "").strip(),
    }

    assert yaml_kubernetes_object_identifier_for_processor({}, **common) == ""
    assert yaml_kubernetes_object_identifier_for_processor({"metadata": {"namespace": "team-a"}}, **common) == ""


def test_yaml_external_secret_store_refs_for_processor_formats_store_refs() -> None:
    common = {
        "yaml_child_mapping": lambda mapping, *keys: next((mapping[key] for key in keys if isinstance(mapping.get(key), dict)), {}),
        "yaml_normalized_mapping": lambda mapping: mapping,
        "yaml_ref_value": lambda mapping, *keys: next((str(mapping.get(key, "") or "") for key in keys if mapping.get(key)), ""),
        "yaml_external_secret_ref_segment": lambda value: str(value or "").strip().lower().replace(" ", "-"),
        "yaml_key_fingerprint": lambda value: value.lower().replace("-", "").replace("_", ""),
    }

    assert yaml_external_secret_store_refs_for_processor(
        {"secretStoreRef": {"name": " Team Store ", "kind": "SecretStore"}},
        "ignored/object",
        **common,
    ) == ["secret-store://team-store"]
    assert yaml_external_secret_store_refs_for_processor(
        {"secret_store_ref": {"name": " Cluster Store ", "kind": "ClusterSecretStore"}},
        "ignored/object",
        **common,
    ) == ["cluster-secret-store://cluster-store"]


def test_yaml_external_secret_store_refs_for_processor_suppresses_missing_store_refs() -> None:
    common = {
        "yaml_child_mapping": lambda mapping, *keys: next((mapping[key] for key in keys if isinstance(mapping.get(key), dict)), {}),
        "yaml_normalized_mapping": lambda mapping: mapping,
        "yaml_ref_value": lambda mapping, *keys: next((str(mapping.get(key, "") or "") for key in keys if mapping.get(key)), ""),
        "yaml_external_secret_ref_segment": lambda value: str(value or "").strip(),
        "yaml_key_fingerprint": lambda value: value.lower().replace("-", "").replace("_", ""),
    }

    assert yaml_external_secret_store_refs_for_processor({}, "ignored/object", **common) == []
    assert (
        yaml_external_secret_store_refs_for_processor(
            {"secretStoreRef": {"kind": "SecretStore"}},
            "ignored/object",
            **common,
        )
        == []
    )


def test_yaml_external_secret_remote_ref_entry_keys_for_processor_reads_data_ref() -> None:
    common = {
        "yaml_child_mapping": lambda mapping, *keys: next((mapping[key] for key in keys if isinstance(mapping.get(key), dict)), {}),
        "yaml_normalized_mapping": lambda mapping: {str(key).lower(): value for key, value in mapping.items()},
        "yaml_ref_value": lambda mapping, *keys: next((str(mapping.get(str(key).lower(), "") or "") for key in keys if mapping.get(str(key).lower())), ""),
    }

    assert yaml_external_secret_remote_ref_entry_keys_for_processor(
        ("data", {"remoteRef": {"remoteKey": "prod/api-token"}}),
        **common,
    ) == ["prod/api-token"]
    assert yaml_external_secret_remote_ref_entry_keys_for_processor(
        ("data", {"remote_ref": {"key": "prod/db-password"}}),
        **common,
    ) == ["prod/db-password"]


def test_yaml_external_secret_remote_ref_entry_keys_for_processor_reads_data_from_refs() -> None:
    common = {
        "yaml_child_mapping": lambda mapping, *keys: next((mapping[key] for key in keys if isinstance(mapping.get(key), dict)), {}),
        "yaml_normalized_mapping": lambda mapping: {str(key).lower(): value for key, value in mapping.items()},
        "yaml_ref_value": lambda mapping, *keys: next((str(mapping.get(str(key).lower(), "") or "") for key in keys if mapping.get(str(key).lower())), ""),
    }

    assert yaml_external_secret_remote_ref_entry_keys_for_processor(
        (
            "data_from",
            {
                "extract": {"path": "team-a/"},
                "find": {"name": "shared-"},
            },
        ),
        **common,
    ) == ["team-a/", "shared-"]
    assert yaml_external_secret_remote_ref_entry_keys_for_processor(("unknown", {}), **common) == []
    assert yaml_external_secret_remote_ref_entry_keys_for_processor(("data", {}), **common) == []


def test_yaml_external_secret_remote_ref_keys_for_processor_collects_ordered_jobs() -> None:
    calls: list[tuple[Any, ...]] = []

    def _run_batch(
        items: list[tuple[str, dict[str, Any]]],
        worker: Callable[[tuple[str, dict[str, Any]]], list[str]],
        *,
        default_factory: Callable[[], list[str]],
    ) -> list[list[str]]:
        calls.append((items, default_factory()))
        return [worker(item) for item in items]

    def _entry_keys(job: tuple[str, dict[str, Any]]) -> list[str]:
        family, entry = job
        return [f"{family}:{entry['id']}"]

    assert yaml_external_secret_remote_ref_keys_for_processor(
        {
            "data": [{"id": "one"}, "ignored", {"id": "two"}],
            "dataFrom": [{"id": "three"}],
        },
        run_ordered_local_batch=_run_batch,
        yaml_external_secret_remote_ref_entry_keys=_entry_keys,
    ) == ["data:one", "data:two", "data_from:three"]
    assert calls == [
        (
            [
                ("data", {"id": "one"}),
                ("data", {"id": "two"}),
                ("data_from", {"id": "three"}),
            ],
            [],
        )
    ]


def test_yaml_external_secret_remote_ref_keys_for_processor_trims_and_dedupes() -> None:
    def _run_batch(
        items: list[tuple[str, dict[str, Any]]],
        worker: Callable[[tuple[str, dict[str, Any]]], list[str]],
        *,
        default_factory: Callable[[], list[str]],
    ) -> list[list[str]]:
        del default_factory
        return [worker(item) for item in items]

    batches = {
        "one": [" 'Prod/Token' ", "prod/token", ""],
        "two": ['"Shared/Path"', "shared/path", "Other"],
    }

    assert yaml_external_secret_remote_ref_keys_for_processor(
        {"datafrom": [{"id": "one"}, {"id": "two"}]},
        run_ordered_local_batch=_run_batch,
        yaml_external_secret_remote_ref_entry_keys=lambda job: batches[job[1]["id"]],
    ) == ["Prod/Token", "Shared/Path", "Other"]


def test_yaml_external_secret_provider_candidates_for_processor_expands_cloud_refs() -> None:
    def _child_mapping(mapping: dict[str, Any], *keys: str) -> dict[str, Any]:
        return next((mapping[key] for key in keys if isinstance(mapping.get(key), dict)), {})

    common = {
        "yaml_child_mapping": _child_mapping,
        "yaml_normalized_mapping": lambda mapping: {str(key).lower(): value for key, value in mapping.items()},
        "yaml_ref_value": lambda mapping, *keys: next((str(mapping.get(str(key).lower(), "") or "") for key in keys if mapping.get(str(key).lower())), ""),
        "yaml_external_secret_ref_segment": lambda value: "" if " " in str(value or "") else str(value or "").strip().strip("\"'").strip("/"),
        "yaml_valid_project_ref": lambda value: str(value or "").strip() if str(value or "").strip().startswith("proj-") else "",
        "yaml_vault_address_candidate": lambda value: "",
        "normalize_artifact_text_url": lambda value: "",
    }

    assert yaml_external_secret_provider_candidates_for_processor(
        {
            "aws": {"region": "ap-southeast-1", "service": "ParameterStore"},
            "gcp": {"projectID": "proj-team-a"},
        },
        ["prod/db-password", "bad key"],
        **common,
    ) == [
        "aws-parameterstore://ap-southeast-1",
        "aws-parameterstore://ap-southeast-1/prod/db-password",
        "gcp-secretmanager://proj-team-a",
        "gcp-secretmanager://proj-team-a/prod/db-password",
    ]


def test_yaml_external_secret_provider_candidates_for_processor_adds_url_providers() -> None:
    def _child_mapping(mapping: dict[str, Any], *keys: str) -> dict[str, Any]:
        return next((mapping[key] for key in keys if isinstance(mapping.get(key), dict)), {})

    def _normalize_url(value: str) -> str:
        text = str(value or "").strip()
        return text if text.startswith("https://") else ""

    common = {
        "yaml_child_mapping": _child_mapping,
        "yaml_normalized_mapping": lambda mapping: {str(key).lower(): value for key, value in mapping.items()},
        "yaml_ref_value": lambda mapping, *keys: next((str(mapping.get(str(key).lower(), "") or "") for key in keys if mapping.get(str(key).lower())), ""),
        "yaml_external_secret_ref_segment": lambda value: str(value or "").strip().strip("/").replace(" ", "-"),
        "yaml_valid_project_ref": lambda value: "",
        "yaml_vault_address_candidate": _normalize_url,
        "normalize_artifact_text_url": _normalize_url,
    }

    assert yaml_external_secret_provider_candidates_for_processor(
        {
            "azureKv": {"vaultUrl": "https://vault.example.net"},
            "vault": {"server": "https://Vault.Example.com:8200", "path": "team a"},
            "webhook": {"endpoint": "https://hooks.example.com/secret"},
            "gitlab": {"url": "https://gitlab.example.com/api"},
        },
        [],
        **common,
    ) == [
        "https://vault.example.net",
        "https://Vault.Example.com:8200",
        "hashicorp-vault://vault.example.com/team-a",
        "https://hooks.example.com/secret",
        "https://gitlab.example.com/api",
    ]
    assert yaml_external_secret_provider_candidates_for_processor({}, [], **common) == []


def test_yaml_external_secret_ref_segment_for_processor_quotes_safe_segment() -> None:
    assert yaml_external_secret_ref_segment_for_processor(" '/team+a/key:@value' ") == "team+a/key:@value"
    assert yaml_external_secret_ref_segment_for_processor("team/value?secret=1") == "team/value%3Fsecret=1"


def test_yaml_external_secret_ref_segment_for_processor_rejects_unsafe_values() -> None:
    assert yaml_external_secret_ref_segment_for_processor("") == ""
    assert yaml_external_secret_ref_segment_for_processor("team key") == ""
    assert yaml_external_secret_ref_segment_for_processor("{{ .remote }}") == ""
    assert yaml_external_secret_ref_segment_for_processor("a" * 513) == ""


def test_yaml_sops_section_entries_for_processor_returns_dict_and_list_entries() -> None:
    def _fingerprint(value: str) -> str:
        return value.lower().replace("-", "").replace("_", "")

    assert yaml_sops_section_entries_for_processor(
        {"gcp-kms": {"resource_id": "projects/p/locations/global/keyRings/r/cryptoKeys/k"}},
        "gcp_kms",
        "gcpKms",
        "gcp-kms",
        yaml_key_fingerprint=_fingerprint,
    ) == [{"resource_id": "projects/p/locations/global/keyRings/r/cryptoKeys/k"}]
    assert yaml_sops_section_entries_for_processor(
        {"azureKv": [{"vault_url": "https://vault.example"}, "ignored", {"vaultUrl": "https://vault2.example"}]},
        "azure_kv",
        "azureKv",
        "azure-kv",
        yaml_key_fingerprint=_fingerprint,
    ) == [{"vault_url": "https://vault.example"}, {"vaultUrl": "https://vault2.example"}]


def test_yaml_sops_section_entries_for_processor_suppresses_missing_or_unsupported_values() -> None:
    def _fingerprint(value: str) -> str:
        return value.lower().replace("-", "").replace("_", "")

    assert yaml_sops_section_entries_for_processor(
        {"kms": "not-a-section"},
        "kms",
        yaml_key_fingerprint=_fingerprint,
    ) == []
    assert yaml_sops_section_entries_for_processor(
        {"age": [{"recipient": "x"}]},
        "kms",
        yaml_key_fingerprint=_fingerprint,
    ) == []


def test_yaml_sops_metadata_entry_candidate_for_processor_accepts_kms_and_vault_refs() -> None:
    common = {
        "yaml_ref_value": lambda mapping, *keys: next((str(mapping.get(key, "") or "") for key in keys if mapping.get(key)), ""),
        "aws_kms_arn_pattern": re.compile(r"arn:aws:kms:[a-z0-9-]+:\d{12}:key/[a-z0-9-]+"),
        "gcp_kms_resource_pattern": re.compile(r"projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+"),
        "normalize_artifact_text_url": lambda value: str(value or "").strip() if str(value or "").strip().startswith("https://") else "",
        "yaml_vault_address_candidate": lambda value: f"https://{str(value).strip().lower()}" if "." in str(value) else "",
    }

    assert yaml_sops_metadata_entry_candidate_for_processor(
        ("aws_kms", {"arn": "arn:aws:kms:us-east-1:123456789012:key/key-123"}),
        **common,
    ) == "arn:aws:kms:us-east-1:123456789012:key/key-123"
    assert yaml_sops_metadata_entry_candidate_for_processor(
        ("gcp_kms", {"resourceId": "projects/p/locations/global/keyRings/r/cryptoKeys/k"}),
        **common,
    ) == "projects/p/locations/global/keyRings/r/cryptoKeys/k"
    assert yaml_sops_metadata_entry_candidate_for_processor(
        ("azure_kv", {"vault-url": "https://vault.example.net"}),
        **common,
    ) == "https://vault.example.net"
    assert yaml_sops_metadata_entry_candidate_for_processor(
        ("hc_vault", {"vaultAddress": "Vault.Example.com"}),
        **common,
    ) == "https://vault.example.com"


def test_yaml_sops_metadata_entry_candidate_for_processor_suppresses_invalid_refs() -> None:
    common = {
        "yaml_ref_value": lambda mapping, *keys: next((str(mapping.get(key, "") or "") for key in keys if mapping.get(key)), ""),
        "aws_kms_arn_pattern": re.compile(r"arn:aws:kms:[a-z0-9-]+:\d{12}:key/[a-z0-9-]+"),
        "gcp_kms_resource_pattern": re.compile(r"projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+"),
        "normalize_artifact_text_url": lambda value: "",
        "yaml_vault_address_candidate": lambda value: "",
    }

    assert yaml_sops_metadata_entry_candidate_for_processor(("aws_kms", {"arn": "not-an-arn"}), **common) == ""
    assert yaml_sops_metadata_entry_candidate_for_processor(("gcp_kms", {"resource_id": "bad"}), **common) == ""
    assert yaml_sops_metadata_entry_candidate_for_processor(("azure_kv", {"vaultUrl": "http://vault.example"}), **common) == ""
    assert yaml_sops_metadata_entry_candidate_for_processor(("unknown", {"arn": "anything"}), **common) == ""


def test_yaml_sops_metadata_structured_candidates_for_processor_uses_direct_sops_mapping() -> None:
    calls: list[tuple[Any, ...]] = []

    def _section_entries(mapping: dict[str, Any], *keys: str) -> list[dict[str, Any]]:
        calls.append(("section", keys))
        section = keys[0]
        value = mapping.get(section)
        if isinstance(value, list):
            return [entry for entry in value if isinstance(entry, dict)]
        return [value] if isinstance(value, dict) else []

    def _run_batch(
        items: list[tuple[str, dict[str, Any]]],
        worker: Callable[[tuple[str, dict[str, Any]]], str],
        *,
        default_factory: Callable[[], str],
    ) -> list[str]:
        calls.append(("batch", items, default_factory()))
        return [worker(item) for item in items]

    assert yaml_sops_metadata_structured_candidates_for_processor(
        {
            "kms": [{"id": "aws-one"}, {"id": "AWS-ONE"}],
            "gcp_kms": {"id": "gcp-one"},
            "azure_kv": {"id": ""},
            "hc_vault": {"id": "vault-one"},
        },
        {},
        "config.sops.yaml",
        yaml_has_hint=lambda path_hint, *hints: "sops" in path_hint,
        yaml_sops_section_entries=_section_entries,
        run_ordered_local_batch=_run_batch,
        yaml_sops_metadata_entry_candidate=lambda job: f" '{job[1]['id']}' " if job[1].get("id") else "",
    ) == ["aws-one", "gcp-one", "vault-one"]
    assert calls[-1] == (
        "batch",
        [
            ("aws_kms", {"id": "aws-one"}),
            ("aws_kms", {"id": "AWS-ONE"}),
            ("gcp_kms", {"id": "gcp-one"}),
            ("azure_kv", {"id": ""}),
            ("hc_vault", {"id": "vault-one"}),
        ],
        "",
    )


def test_yaml_sops_metadata_structured_candidates_for_processor_uses_nested_sops_mapping() -> None:
    def _section_entries(mapping: dict[str, Any], *keys: str) -> list[dict[str, Any]]:
        for key in keys:
            value = mapping.get(key)
            if isinstance(value, dict):
                return [value]
        return []

    assert yaml_sops_metadata_structured_candidates_for_processor(
        {},
        {"sops": {"gcpKms": {"id": "nested-gcp"}}},
        "config.yaml",
        yaml_has_hint=lambda path_hint, *hints: False,
        yaml_sops_section_entries=_section_entries,
        run_ordered_local_batch=lambda items, worker, default_factory: [worker(item) for item in items],
        yaml_sops_metadata_entry_candidate=lambda job: job[1]["id"],
    ) == ["nested-gcp"]
    assert yaml_sops_metadata_structured_candidates_for_processor(
        {},
        {"not_sops": {}},
        "config.yaml",
        yaml_has_hint=lambda path_hint, *hints: False,
        yaml_sops_section_entries=_section_entries,
        run_ordered_local_batch=lambda items, worker, default_factory: [worker(item) for item in items],
        yaml_sops_metadata_entry_candidate=lambda job: job[1]["id"],
    ) == []


def test_yaml_vault_address_candidate_for_processor_accepts_urls_and_hostnames() -> None:
    def _normalize(value: str) -> str:
        text = str(value or "").strip()
        return text if text.startswith(("http://", "https://")) else ""

    assert yaml_vault_address_candidate_for_processor(
        ' "https://Vault.Example.com:8200" ',
        normalize_artifact_text_url=_normalize,
    ) == "https://Vault.Example.com:8200"
    assert yaml_vault_address_candidate_for_processor(
        "Vault.Example.com.",
        normalize_artifact_text_url=_normalize,
    ) == "https://vault.example.com"


def test_yaml_vault_address_candidate_for_processor_suppresses_invalid_values() -> None:
    assert yaml_vault_address_candidate_for_processor("", normalize_artifact_text_url=lambda value: "") == ""
    assert yaml_vault_address_candidate_for_processor(
        "not-host",
        normalize_artifact_text_url=lambda value: "",
    ) == ""
    assert yaml_vault_address_candidate_for_processor(
        "ftp://vault.example.com",
        normalize_artifact_text_url=lambda value: "ftp://vault.example.com",
    ) == ""


def test_cloudflare_valid_ref_for_processor_normalizes_valid_refs() -> None:
    assert cloudflare_valid_ref_for_processor(" 'Team.Ref_01' ") == "team.ref_01"
    assert cloudflare_valid_ref_for_processor("a-" + ("b" * 126)) == "a-" + ("b" * 126)


def test_cloudflare_valid_ref_for_processor_rejects_invalid_refs() -> None:
    assert cloudflare_valid_ref_for_processor("") == ""
    assert cloudflare_valid_ref_for_processor("-bad") == ""
    assert cloudflare_valid_ref_for_processor("a") == ""
    assert cloudflare_valid_ref_for_processor("a bad") == ""
    assert cloudflare_valid_ref_for_processor("a" * 129) == ""


def test_cloudflare_uri_candidate_for_processor_builds_uri_from_valid_ref() -> None:
    calls: list[str] = []

    def _valid_ref(value: str) -> str:
        calls.append(value)
        return cloudflare_valid_ref_for_processor(value)

    assert cloudflare_uri_candidate_for_processor(
        "r2",
        " 'Bucket.Ref_01' ",
        cloudflare_valid_ref=_valid_ref,
    ) == "cloudflare-r2://bucket.ref_01"
    assert calls == [" 'Bucket.Ref_01' "]


def test_cloudflare_uri_candidate_for_processor_suppresses_invalid_refs() -> None:
    assert cloudflare_uri_candidate_for_processor(
        "workers",
        "bad value",
        cloudflare_valid_ref=cloudflare_valid_ref_for_processor,
    ) == ""


def test_cloudflare_uri_candidate_entry_for_processor_delegates_tuple_values() -> None:
    calls: list[tuple[str, str]] = []

    def _candidate(family: str, value: str) -> str:
        calls.append((family, value))
        return f"{family}:{value}"

    assert cloudflare_uri_candidate_entry_for_processor(
        ("pages", "Project_01"),
        cloudflare_uri_candidate=_candidate,
    ) == "pages:Project_01"
    assert calls == [("pages", "Project_01")]


def test_cloudflare_uri_candidate_entry_for_processor_normalizes_blank_tuple_values() -> None:
    assert cloudflare_uri_candidate_entry_for_processor(
        ("", None),
        cloudflare_uri_candidate=lambda family, value: f"{family}:{value}",
    ) == ":"


def test_cloudflare_uri_candidate_entries_for_processor_batches_and_dedupes_entries() -> None:
    calls: list[tuple[Any, ...]] = []

    def _run_batch(
        items: list[tuple[str, Any]],
        worker: Callable[[tuple[str, Any]], str],
        *,
        default_factory: Callable[[], str],
    ) -> list[str]:
        calls.append(("batch", list(items), default_factory()))
        return [worker(item) for item in items]

    assert cloudflare_uri_candidate_entries_for_processor(
        [("r2", "bucket"), ("r2", "bucket"), ("pages", "project"), ("kv", "")],
        run_ordered_local_batch=_run_batch,
        cloudflare_uri_candidate_entry=lambda item: (
            "" if not item[1] else f"cloudflare-{item[0]}://{item[1]}"
        ),
    ) == ["cloudflare-r2://bucket", "cloudflare-pages://project"]
    assert calls == [
        (
            "batch",
            [("r2", "bucket"), ("r2", "bucket"), ("pages", "project"), ("kv", "")],
            "",
        )
    ]


def test_cloudflare_uri_candidate_entries_for_processor_preserves_first_seen_order() -> None:
    assert cloudflare_uri_candidate_entries_for_processor(
        [("pages", "project"), ("r2", "bucket"), ("pages", "project")],
        run_ordered_local_batch=lambda items, worker, default_factory: [worker(item) for item in items],
        cloudflare_uri_candidate_entry=lambda item: f"cloudflare-{item[0]}://{item[1]}",
    ) == ["cloudflare-pages://project", "cloudflare-r2://bucket"]


def test_yaml_cloudflare_structured_marker_flags_for_processor_detects_key_families() -> None:
    flags = yaml_cloudflare_structured_marker_flags_for_processor(
        {
            "r2bucketname": "bucket",
            "d1databasename": "db",
            "kvnamespaceid": "kv",
            "workername": "worker",
            "pagesprojectname": "pages",
            "compatibilitydate": "2024-01-01",
        },
        "service.yaml",
        yaml_has_hint=lambda path_hint, *hints: False,
    )

    assert flags == {
        "explicit_cloudflare_hint": False,
        "has_worker_markers": True,
        "has_r2_key": True,
        "has_d1_key": True,
        "has_kv_key": True,
        "has_worker_key": True,
        "has_pages_key": True,
    }


def test_yaml_cloudflare_structured_marker_flags_for_processor_uses_path_hint() -> None:
    calls: list[tuple[str, tuple[str, ...]]] = []

    def _has_hint(path_hint: str, *hints: str) -> bool:
        calls.append((path_hint, hints))
        return "wrangler" in path_hint

    flags = yaml_cloudflare_structured_marker_flags_for_processor(
        {},
        "apps/wrangler.toml",
        yaml_has_hint=_has_hint,
    )

    assert flags["explicit_cloudflare_hint"] is True
    assert flags["has_worker_markers"] is False
    assert calls == [
        (
            "apps/wrangler.toml",
            ("cloudflare", "wrangler", "r2", "d1", "kv", "workers", "worker", "pages"),
        )
    ]


def test_yaml_cloudflare_r2_candidate_ref_for_processor_uses_explicit_r2_keys() -> None:
    def _ref(mapping: dict[str, Any], *keys: str) -> str:
        return next((str(mapping[key]) for key in keys if mapping.get(key)), "")

    assert yaml_cloudflare_r2_candidate_ref_for_processor(
        {"r2BucketName": "media-assets"},
        explicit_cloudflare_hint=False,
        has_r2_key=True,
        yaml_ref_value=_ref,
    ) == ("r2", "media-assets")


def test_yaml_cloudflare_r2_candidate_ref_for_processor_uses_hinted_generic_bucket() -> None:
    assert yaml_cloudflare_r2_candidate_ref_for_processor(
        {"bucket": "hinted-assets"},
        explicit_cloudflare_hint=True,
        has_r2_key=False,
        yaml_ref_value=lambda mapping, *keys: next((str(mapping[key]) for key in keys if mapping.get(key)), ""),
    ) == ("r2", "hinted-assets")


def test_yaml_cloudflare_r2_candidate_ref_for_processor_suppresses_unhinted_generic_bucket() -> None:
    assert yaml_cloudflare_r2_candidate_ref_for_processor(
        {"bucket": "generic-assets"},
        explicit_cloudflare_hint=False,
        has_r2_key=False,
        yaml_ref_value=lambda mapping, *keys: next((str(mapping[key]) for key in keys if mapping.get(key)), ""),
    ) is None


def test_yaml_cloudflare_d1_candidate_ref_for_processor_uses_explicit_d1_keys() -> None:
    assert yaml_cloudflare_d1_candidate_ref_for_processor(
        {"d1DatabaseName": "prod-db"},
        explicit_cloudflare_hint=False,
        has_d1_key=True,
        yaml_ref_value=lambda mapping, *keys: next((str(mapping[key]) for key in keys if mapping.get(key)), ""),
    ) == ("d1", "prod-db")


def test_yaml_cloudflare_d1_candidate_ref_for_processor_uses_hinted_generic_database() -> None:
    assert yaml_cloudflare_d1_candidate_ref_for_processor(
        {"database_id": "hinted-db"},
        explicit_cloudflare_hint=True,
        has_d1_key=False,
        yaml_ref_value=lambda mapping, *keys: next((str(mapping[key]) for key in keys if mapping.get(key)), ""),
    ) == ("d1", "hinted-db")


def test_yaml_cloudflare_d1_candidate_ref_for_processor_suppresses_unhinted_generic_database() -> None:
    assert yaml_cloudflare_d1_candidate_ref_for_processor(
        {"database_name": "generic-db"},
        explicit_cloudflare_hint=False,
        has_d1_key=False,
        yaml_ref_value=lambda mapping, *keys: next((str(mapping[key]) for key in keys if mapping.get(key)), ""),
    ) is None


def test_yaml_cloudflare_kv_candidate_ref_for_processor_uses_explicit_kv_keys() -> None:
    assert yaml_cloudflare_kv_candidate_ref_for_processor(
        {"kvNamespaceId": "prod-kv"},
        explicit_cloudflare_hint=False,
        has_kv_key=True,
        yaml_ref_value=lambda mapping, *keys: next((str(mapping[key]) for key in keys if mapping.get(key)), ""),
    ) == ("kv", "prod-kv")


def test_yaml_cloudflare_kv_candidate_ref_for_processor_uses_hinted_generic_namespace() -> None:
    assert yaml_cloudflare_kv_candidate_ref_for_processor(
        {"namespace-id": "hinted-kv"},
        explicit_cloudflare_hint=True,
        has_kv_key=False,
        yaml_ref_value=lambda mapping, *keys: next((str(mapping[key]) for key in keys if mapping.get(key)), ""),
    ) == ("kv", "hinted-kv")


def test_yaml_cloudflare_kv_candidate_ref_for_processor_suppresses_unhinted_generic_namespace() -> None:
    assert yaml_cloudflare_kv_candidate_ref_for_processor(
        {"namespace_id": "generic-kv"},
        explicit_cloudflare_hint=False,
        has_kv_key=False,
        yaml_ref_value=lambda mapping, *keys: next((str(mapping[key]) for key in keys if mapping.get(key)), ""),
    ) is None


def test_yaml_cloudflare_worker_candidate_ref_for_processor_uses_explicit_worker_keys() -> None:
    assert yaml_cloudflare_worker_candidate_ref_for_processor(
        {"workerName": "edge-worker"},
        "config.yaml",
        explicit_cloudflare_hint=False,
        has_worker_markers=False,
        has_worker_key=True,
        yaml_ref_value=lambda mapping, *keys: next((str(mapping[key]) for key in keys if mapping.get(key)), ""),
        yaml_has_hint=lambda path_hint, *hints: False,
    ) == ("worker", "edge-worker")


def test_yaml_cloudflare_worker_candidate_ref_for_processor_uses_marker_name_fallback() -> None:
    assert yaml_cloudflare_worker_candidate_ref_for_processor(
        {"name": "marker-worker"},
        "config.yaml",
        explicit_cloudflare_hint=False,
        has_worker_markers=True,
        has_worker_key=False,
        yaml_ref_value=lambda mapping, *keys: next((str(mapping[key]) for key in keys if mapping.get(key)), ""),
        yaml_has_hint=lambda path_hint, *hints: False,
    ) == ("worker", "marker-worker")


def test_yaml_cloudflare_worker_candidate_ref_for_processor_uses_path_hint_gate() -> None:
    calls: list[tuple[str, tuple[str, ...]]] = []

    def _has_hint(path_hint: str, *hints: str) -> bool:
        calls.append((path_hint, hints))
        return "wrangler" in path_hint

    assert yaml_cloudflare_worker_candidate_ref_for_processor(
        {"worker_name": "hinted-worker"},
        "apps/wrangler.toml",
        explicit_cloudflare_hint=False,
        has_worker_markers=False,
        has_worker_key=False,
        yaml_ref_value=lambda mapping, *keys: next((str(mapping[key]) for key in keys if mapping.get(key)), ""),
        yaml_has_hint=_has_hint,
    ) == ("worker", "hinted-worker")
    assert calls == [("apps/wrangler.toml", ("worker", "workers", "wrangler"))]


def test_yaml_cloudflare_worker_candidate_ref_for_processor_suppresses_ungated_worker_name() -> None:
    assert yaml_cloudflare_worker_candidate_ref_for_processor(
        {"worker_name": "generic-worker"},
        "config.yaml",
        explicit_cloudflare_hint=False,
        has_worker_markers=False,
        has_worker_key=False,
        yaml_ref_value=lambda mapping, *keys: next((str(mapping[key]) for key in keys if mapping.get(key)), ""),
        yaml_has_hint=lambda path_hint, *hints: False,
    ) is None


def test_yaml_cloudflare_pages_candidate_ref_for_processor_uses_explicit_pages_keys() -> None:
    assert yaml_cloudflare_pages_candidate_ref_for_processor(
        {"pagesProjectName": "marketing-site"},
        "config.yaml",
        has_pages_key=True,
        yaml_ref_value=lambda mapping, *keys: next((str(mapping[key]) for key in keys if mapping.get(key)), ""),
        yaml_has_hint=lambda path_hint, *hints: False,
    ) == ("pages", "marketing-site")


def test_yaml_cloudflare_pages_candidate_ref_for_processor_uses_path_hint_name_fallback() -> None:
    calls: list[tuple[str, tuple[str, ...]]] = []

    def _has_hint(path_hint: str, *hints: str) -> bool:
        calls.append((path_hint, hints))
        return "pages" in path_hint

    assert yaml_cloudflare_pages_candidate_ref_for_processor(
        {"name": "hinted-pages"},
        "apps/pages/config.yaml",
        has_pages_key=False,
        yaml_ref_value=lambda mapping, *keys: next((str(mapping[key]) for key in keys if mapping.get(key)), ""),
        yaml_has_hint=_has_hint,
    ) == ("pages", "hinted-pages")
    assert calls == [("apps/pages/config.yaml", ("pages",))]


def test_yaml_cloudflare_pages_candidate_ref_for_processor_uses_build_output_name_fallback() -> None:
    assert yaml_cloudflare_pages_candidate_ref_for_processor(
        {"name": "build-output-pages", "pagesbuildoutputdir": "dist"},
        "config.yaml",
        has_pages_key=False,
        yaml_ref_value=lambda mapping, *keys: next((str(mapping[key]) for key in keys if mapping.get(key)), ""),
        yaml_has_hint=lambda path_hint, *hints: False,
    ) == ("pages", "build-output-pages")


def test_yaml_cloudflare_pages_candidate_ref_for_processor_suppresses_ungated_project_name() -> None:
    assert yaml_cloudflare_pages_candidate_ref_for_processor(
        {"project_name": "generic-project"},
        "config.yaml",
        has_pages_key=False,
        yaml_ref_value=lambda mapping, *keys: next((str(mapping[key]) for key in keys if mapping.get(key)), ""),
        yaml_has_hint=lambda path_hint, *hints: False,
    ) is None


def test_yaml_cloudflare_structured_candidates_for_processor_collects_all_families_in_order() -> None:
    def _ref(mapping: dict[str, Any], *keys: str) -> str:
        return next((str(mapping[key]) for key in keys if mapping.get(key)), "")

    assert yaml_cloudflare_structured_candidates_for_processor(
        {
            "r2_bucket_name": "assets",
            "d1_database_name": "app-db",
            "kv_namespace_id": "sessions",
            "worker_name": "edge-worker",
            "pages_project_name": "marketing",
        },
        "config.yaml",
        yaml_has_hint=lambda path_hint, *hints: False,
        yaml_ref_value=_ref,
        run_ordered_local_batch=lambda items, worker, default_factory: [worker(item) for item in items],
        cloudflare_uri_candidate_entry=lambda item: f"cloudflare-{item[0]}://{item[1]}",
    ) == [
        "cloudflare-r2://assets",
        "cloudflare-d1://app-db",
        "cloudflare-kv://sessions",
        "cloudflare-worker://edge-worker",
        "cloudflare-pages://marketing",
    ]


def test_yaml_cloudflare_structured_candidates_for_processor_suppresses_generic_config() -> None:
    assert yaml_cloudflare_structured_candidates_for_processor(
        {"bucket": "generic-bucket", "name": "generic-name"},
        "config.yaml",
        yaml_has_hint=lambda path_hint, *hints: False,
        yaml_ref_value=lambda mapping, *keys: next((str(mapping[key]) for key in keys if mapping.get(key)), ""),
        run_ordered_local_batch=lambda items, worker, default_factory: [worker(item) for item in items],
        cloudflare_uri_candidate_entry=lambda item: f"cloudflare-{item[0]}://{item[1]}",
    ) == []


def test_yaml_candidate_batch_entries_for_processor_preserves_batch_order() -> None:
    assert yaml_candidate_batch_entries_for_processor((4, ("first", "second"))) == [
        "first",
        "second",
    ]


def test_yaml_candidate_family_entries_for_processor_preserves_family_order() -> None:
    assert yaml_candidate_family_entries_for_processor((2, ["alpha", "beta"])) == [
        "alpha",
        "beta",
    ]


def test_yaml_candidate_merge_entry_for_processor_strips_and_suppresses_empty_values() -> None:
    assert yaml_candidate_merge_entry_for_processor((0, "  candidate  ")) == "candidate"
    assert yaml_candidate_merge_entry_for_processor((1, "   ")) is None


def test_yaml_goreleaser_candidate_values_for_node_for_processor_uses_workers_for_dicts() -> None:
    calls: list[tuple[Any, ...]] = []

    def _run_batch(
        items: list[Any],
        worker: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        calls.append(("batch", list(items), default_factory()))
        return [worker(item) for item in items]

    def _child(job: tuple[int, Any, Any, tuple[str, ...]]) -> list[str]:
        calls.append(("child", job))
        _index, key, value, path = job
        return [f"{key}:{value}:{'/'.join(path)}"]

    assert yaml_goreleaser_candidate_values_for_node_for_processor(
        {"first": "one", "second": "two"},
        (),
        use_workers=True,
        yaml_goreleaser_blob_bucket_value=lambda _mapping: "",
        yaml_goreleaser_child_candidate_values=_child,
        yaml_goreleaser_child_candidate_values_for_node=lambda key, value, path: [f"local:{key}:{value}:{path}"],
        run_ordered_local_batch=_run_batch,
    ) == ["first:one:", "second:two:"]
    assert calls == [
        ("batch", [(0, "first", "one", ()), (1, "second", "two", ())], []),
        ("child", (0, "first", "one", ())),
        ("child", (1, "second", "two", ())),
    ]


def test_yaml_goreleaser_candidate_values_for_node_for_processor_handles_blobs_and_lists() -> None:
    calls: list[tuple[Any, ...]] = []

    values = [{"bucket": "first"}, {"bucket": "second"}] + [{"bucket": "ignored"} for _ in range(300)]

    assert yaml_goreleaser_candidate_values_for_node_for_processor(
        values,
        ("blobs",),
        use_workers=True,
        yaml_goreleaser_blob_bucket_value=lambda mapping: f"s3://{mapping['bucket']}",
        yaml_goreleaser_child_candidate_values=lambda _job: ["worker"],
        yaml_goreleaser_child_candidate_values_for_node=lambda key, value, path: (
            calls.append(("local", key, value, path)) or []
        ),
        run_ordered_local_batch=lambda items, worker, *, default_factory: [worker(item) for item in items],
    )[:2] == ["s3://first", "s3://second"]
    assert len(calls) == 256
    assert yaml_goreleaser_candidate_values_for_node_for_processor(
        "scalar",
        (),
        use_workers=True,
        yaml_goreleaser_blob_bucket_value=lambda _mapping: "s3://unused",
        yaml_goreleaser_child_candidate_values=lambda _job: ["unused"],
        yaml_goreleaser_child_candidate_values_for_node=lambda _key, _value, _path: ["unused"],
        run_ordered_local_batch=lambda items, worker, *, default_factory: [worker(item) for item in items],
    ) == []


def test_strip_git_repository_suffix_for_processor_normalizes_suffixes() -> None:
    assert strip_git_repository_suffix_for_processor(" https://github.com/acme/app.git/ ") == "https://github.com/acme/app"
    assert strip_git_repository_suffix_for_processor("git@example.com:acme/app.GIT") == "git@example.com:acme/app"
    assert strip_git_repository_suffix_for_processor("https://github.com/acme/app") == "https://github.com/acme/app"
    assert strip_git_repository_suffix_for_processor("") == ""


def test_mobile_config_store_wrappers_bind_storage_callbacks(monkeypatch: Any) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _artifact_child_seed_depth(self, con: Any, source_seed_id: int | None) -> int:
            calls.append(("depth", con, source_seed_id))
            return 2

        def _run_ordered_local_batch(
            self,
            items: list[Any],
            worker: Callable[[Any], Any],
            *,
            default_factory: Callable[[], Any],
        ) -> list[Any]:
            calls.append(("batch", list(items), default_factory()))
            return [worker(item) for item in items]

        def _firebase_project_persistence_entry(self, project: Any, *, source_url: str) -> dict[str, Any]:
            calls.append(("firebase_entry", project, source_url))
            return {"project": project}

        def _supabase_config_persistence_entry(self, config: Any, *, source_url: str) -> dict[str, Any]:
            calls.append(("supabase_entry", config, source_url))
            return {"config": config}

        def _store_cloud_asset_reference(self, *args: Any, **kwargs: Any) -> None:
            calls.append(("cloud", args, kwargs))

        def _artifact_cloud_asset_metadata(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            calls.append(("metadata", args, kwargs))
            return {"metadata": True}

        def _insert_seed(self, *args: Any, **kwargs: Any) -> bool:
            calls.append(("insert", args, kwargs))
            return True

        def _link_artifact_source_seed(self, *args: Any, **kwargs: Any) -> None:
            calls.append(("link", args, kwargs))

        def _merge_artifact_relation_context(
            self,
            relation_metadata: dict[str, Any] | None,
            artifact_context: dict[str, Any] | None,
        ) -> dict[str, Any]:
            calls.append(("merge", relation_metadata, artifact_context))
            return {"merged": True}

        def _store_artifact_url_seed(self, *args: Any, **kwargs: Any) -> int:
            calls.append(("url", args, kwargs))
            return 1

        def _store_key_finding(self, *args: Any, **kwargs: Any) -> None:
            calls.append(("key", args, kwargs))

    def _store_firebase(
        con: Any,
        firebase_projects: list[Any],
        *,
        source_seed_id: int | None,
        source_url: str,
        artifact_context: dict[str, Any] | None,
        artifact_child_seed_depth: Callable[..., int],
        run_ordered_batch: Callable[..., list[Any]],
        firebase_project_persistence_entry: Callable[..., dict[str, Any] | None],
        store_cloud_asset_reference: Callable[..., None],
        artifact_cloud_asset_metadata: Callable[..., dict[str, Any]],
        insert_seed: Callable[..., bool],
        link_artifact_source_seed: Callable[..., None],
        merge_artifact_relation_context_fn: Callable[..., dict[str, Any]],
        store_artifact_url_seed: Callable[..., int],
        store_key_finding: Callable[..., None],
    ) -> tuple[int, int]:
        calls.append(("store_firebase", con, firebase_projects, source_seed_id, source_url, artifact_context))
        depth = artifact_child_seed_depth(con, source_seed_id)
        entries = run_ordered_batch(
            firebase_projects,
            lambda project: firebase_project_persistence_entry(project, source_url=source_url),
            default_factory=lambda: None,
        )
        store_cloud_asset_reference(con, asset_type="firebase")
        artifact_cloud_asset_metadata(con, source_seed_id=source_seed_id)
        insert_seed(con, "firebase", depth=depth)
        link_artifact_source_seed(con, source_seed_id, "firebase")
        merge_artifact_relation_context_fn({"rule": "firebase"}, artifact_context)
        store_artifact_url_seed(con, "https://firebase.example")
        store_key_finding(con, service="firebase")
        return len(entries), depth

    def _store_supabase(
        con: Any,
        supabase_configs: list[Any],
        *,
        source_seed_id: int | None,
        source_url: str,
        artifact_context: dict[str, Any] | None,
        artifact_child_seed_depth: Callable[..., int],
        run_ordered_batch: Callable[..., list[Any]],
        supabase_config_persistence_entry: Callable[..., dict[str, Any] | None],
        store_cloud_asset_reference: Callable[..., None],
        artifact_cloud_asset_metadata: Callable[..., dict[str, Any]],
        store_artifact_url_seed: Callable[..., int],
        merge_artifact_relation_context_fn: Callable[..., dict[str, Any]],
        insert_seed: Callable[..., bool],
        link_artifact_source_seed: Callable[..., None],
        store_key_finding: Callable[..., None],
    ) -> tuple[int, int]:
        calls.append(("store_supabase", con, supabase_configs, source_seed_id, source_url, artifact_context))
        depth = artifact_child_seed_depth(con, source_seed_id)
        entries = run_ordered_batch(
            supabase_configs,
            lambda config: supabase_config_persistence_entry(config, source_url=source_url),
            default_factory=lambda: None,
        )
        store_cloud_asset_reference(con, asset_type="supabase")
        artifact_cloud_asset_metadata(con, source_seed_id=source_seed_id)
        store_artifact_url_seed(con, "https://supabase.example")
        merge_artifact_relation_context_fn({"rule": "supabase"}, artifact_context)
        insert_seed(con, "supabase", depth=depth)
        link_artifact_source_seed(con, source_seed_id, "supabase")
        store_key_finding(con, service="supabase")
        return len(entries), depth + 1

    monkeypatch.setattr(runtime, "store_firebase_projects", _store_firebase)
    monkeypatch.setattr(runtime, "store_supabase_configs", _store_supabase)

    con = object()
    adapter = _Adapter()
    assert store_firebase_projects_for_processor(
        adapter,
        con,  # type: ignore[arg-type]
        ["firebase-project"],
        source_seed_id=10,
        source_url="file:///mobile.apk",
        artifact_context={"parser": "apk"},
    ) == (1, 2)
    assert store_supabase_configs_for_processor(
        adapter,
        con,  # type: ignore[arg-type]
        ["supabase-config"],
        source_seed_id=20,
        source_url="file:///mobile.apk",
        artifact_context={"parser": "ipa"},
    ) == (1, 3)
    assert calls == [
        ("store_firebase", con, ["firebase-project"], 10, "file:///mobile.apk", {"parser": "apk"}),
        ("depth", con, 10),
        ("batch", ["firebase-project"], None),
        ("firebase_entry", "firebase-project", "file:///mobile.apk"),
        ("cloud", (con,), {"asset_type": "firebase"}),
        ("metadata", (con,), {"source_seed_id": 10}),
        ("insert", (con, "firebase"), {"depth": 2}),
        ("link", (con, 10, "firebase"), {}),
        ("merge", {"rule": "firebase"}, {"parser": "apk"}),
        ("url", (con, "https://firebase.example"), {}),
        ("key", (con,), {"service": "firebase"}),
        ("store_supabase", con, ["supabase-config"], 20, "file:///mobile.apk", {"parser": "ipa"}),
        ("depth", con, 20),
        ("batch", ["supabase-config"], None),
        ("supabase_entry", "supabase-config", "file:///mobile.apk"),
        ("cloud", (con,), {"asset_type": "supabase"}),
        ("metadata", (con,), {"source_seed_id": 20}),
        ("url", (con, "https://supabase.example"), {}),
        ("merge", {"rule": "supabase"}, {"parser": "ipa"}),
        ("insert", (con, "supabase"), {"depth": 2}),
        ("link", (con, 20, "supabase"), {}),
        ("key", (con,), {"service": "supabase"}),
    ]


def test_mobile_config_persistence_entry_wrappers_delegate(monkeypatch: Any) -> None:
    calls: list[tuple[Any, ...]] = []

    monkeypatch.setattr(
        runtime,
        "firebase_project_persistence_entry",
        lambda project, *, source_url: {"project": project, "source_url": source_url},
    )
    monkeypatch.setattr(
        runtime,
        "supabase_config_persistence_entry",
        lambda config, *, source_url, redact_secret, encrypt_secret_material: {
            "config": config,
            "source_url": source_url,
            "redacted": redact_secret("secret"),
            "encrypted": encrypt_secret_material("secret"),
        },
    )

    assert firebase_project_persistence_entry_for_processor(
        "firebase-project",
        source_url="file:///mobile.apk",
    ) == {"project": "firebase-project", "source_url": "file:///mobile.apk"}
    assert supabase_config_persistence_entry_for_processor(
        "supabase-config",
        source_url="file:///mobile.apk",
        redact_secret=lambda value: calls.append(("redact", value)) or "redacted",
        encrypt_secret_material=lambda value: calls.append(("encrypt", value)) or "encrypted",
    ) == {
        "config": "supabase-config",
        "source_url": "file:///mobile.apk",
        "redacted": "redacted",
        "encrypted": "encrypted",
    }
    assert calls == [("redact", "secret"), ("encrypt", "secret")]


def test_generic_text_discovery_batch_wrappers_bind_callbacks(monkeypatch: Any) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _run_ordered_local_batch(
            self,
            items: list[Any],
            worker: Callable[[Any], Any],
            *,
            default_factory: Callable[[], Any],
        ) -> list[Any]:
            calls.append(("batch", list(items), default_factory()))
            return [worker(item) for item in items]

        def _generic_text_discovery_job(
            self,
            discovery_job: tuple[str, str, str],
        ) -> tuple[str, str, str] | None:
            calls.append(("job", discovery_job))
            return discovery_job

        def _collect_generic_text_discovery_job_result(
            self,
            discovery_job: tuple[str, str, str],
        ) -> ArtifactTextDiscoveryBatch:
            calls.append(("result", discovery_job))
            return ArtifactTextDiscoveryBatch(source_file=discovery_job[0], urls=[discovery_job[2]])

    monkeypatch.setattr(
        runtime,
        "collect_artifact_text_discovery_batches",
        lambda discovery_jobs, *, run_ordered_batch, artifact_text_discovery_job, collect_artifact_text_discovery_job_result: run_ordered_batch(
            run_ordered_batch(
                discovery_jobs,
                artifact_text_discovery_job,
                default_factory=lambda: None,
            ),
            collect_artifact_text_discovery_job_result,
            default_factory=lambda: ArtifactTextDiscoveryBatch(source_file=""),
        ),
    )

    batches = collect_generic_text_discovery_batches_for_processor(
        _Adapter(),
        [("source.txt", "source.txt/path", "https://example.test")],
    )
    assert [(batch.source_file, batch.urls) for batch in batches] == [
        ("source.txt", ["https://example.test"]),
    ]
    assert calls == [
        ("batch", [("source.txt", "source.txt/path", "https://example.test")], None),
        ("job", ("source.txt", "source.txt/path", "https://example.test")),
        ("batch", [("source.txt", "source.txt/path", "https://example.test")], ArtifactTextDiscoveryBatch(source_file="")),
        ("result", ("source.txt", "source.txt/path", "https://example.test")),
    ]


def test_generic_text_discovery_wrapper_helpers_delegate(monkeypatch: Any) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _collect_generic_text_discoveries(
            self,
            text: str,
            *,
            source_file: str,
            source_hint: str = "",
        ) -> ArtifactTextDiscoveryBatch:
            calls.append(("discoveries", text, source_file, source_hint))
            return ArtifactTextDiscoveryBatch(source_file=source_file, urls=[text])

    monkeypatch.setattr(runtime, "artifact_text_discovery_job", lambda job: job if job[2].strip() else None)
    monkeypatch.setattr(
        runtime,
        "collect_artifact_text_discovery_job_result",
        lambda discovery_job, *, collect_artifact_text_discoveries: collect_artifact_text_discoveries(
            discovery_job[2],
            source_file=discovery_job[0],
            source_hint=discovery_job[1],
        ),
    )
    monkeypatch.setattr(
        runtime,
        "artifact_text_discovery_batch_entry",
        lambda entry: ArtifactTextDiscoveryBatch(source_file=entry[1].source_file, urls=list(entry[1].urls)),
    )

    assert generic_text_discovery_job_for_processor(("source.txt", "", " text ")) == ("source.txt", "", " text ")
    batch = collect_generic_text_discovery_job_result_for_processor(
        _Adapter(),
        ("source.txt", "source.txt/path", "https://example.test"),
    )
    assert batch.source_file == "source.txt"
    assert batch.urls == ["https://example.test"]
    copied = artifact_text_discovery_family_entry_for_processor(
        (0, ArtifactTextDiscoveryBatch(source_file="source.txt", urls=["https://copy.test"])),
    )
    assert copied.source_file == "source.txt"
    assert copied.urls == ["https://copy.test"]
    assert calls == [("discoveries", "https://example.test", "source.txt", "source.txt/path")]


def test_collect_generic_text_discoveries_for_processor_binds_family_callbacks(
    monkeypatch: Any,
) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _run_ordered_local_batch(
            self,
            items: list[Any],
            worker: Callable[[Any], Any],
            *,
            default_factory: Callable[[], Any],
        ) -> list[Any]:
            calls.append(("batch", list(items), default_factory()))
            return [worker(item) for item in items]

        def _collect_generic_text_discovery_family(
            self,
            family: str,
            *,
            text: str,
            source_file: str,
            source_hint: str = "",
        ) -> ArtifactTextDiscoveryBatch:
            calls.append(("family", family, text, source_file, source_hint))
            return ArtifactTextDiscoveryBatch(source_file=source_file, urls=[f"{family}:{text}"])

        def _artifact_text_discovery_family_entry(
            self,
            family_batch_entry: tuple[int, ArtifactTextDiscoveryBatch],
        ) -> ArtifactTextDiscoveryBatch:
            calls.append(("entry", family_batch_entry[0], list(family_batch_entry[1].urls)))
            return family_batch_entry[1]

        def _artifact_text_discovery_merge_entry(
            self,
            family_batch_entry: tuple[int, ArtifactTextDiscoveryBatch],
        ) -> ArtifactTextDiscoveryBatch:
            calls.append(("merge_entry", family_batch_entry[0], list(family_batch_entry[1].urls)))
            return family_batch_entry[1]

        def _merge_artifact_text_discovery_batch(
            self,
            target: ArtifactTextDiscoveryBatch,
            source: ArtifactTextDiscoveryBatch,
        ) -> None:
            calls.append(("merge", list(source.urls)))
            target.urls.extend(source.urls)

    def _collect_text(
        text: str,
        *,
        source_file: str,
        source_hint: str,
        run_ordered_batch: Callable[..., list[Any]],
        collect_generic_text_discovery_family: Callable[..., ArtifactTextDiscoveryBatch],
        artifact_text_discovery_family_entry: Callable[..., ArtifactTextDiscoveryBatch],
        artifact_text_discovery_merge_entry: Callable[..., ArtifactTextDiscoveryBatch],
        merge_artifact_text_discovery_batch_fn: Callable[..., None],
    ) -> ArtifactTextDiscoveryBatch:
        families = ["urls", "keys"]
        family_batches = run_ordered_batch(
            families,
            lambda family: collect_generic_text_discovery_family(
                family,
                text=text,
                source_file=source_file,
                source_hint=source_hint,
            ),
            default_factory=lambda: ArtifactTextDiscoveryBatch(source_file=source_file),
        )
        prepared = run_ordered_batch(
            list(enumerate(family_batches)),
            artifact_text_discovery_family_entry,
            default_factory=lambda: ArtifactTextDiscoveryBatch(source_file=source_file),
        )
        merge_ready = run_ordered_batch(
            list(enumerate(prepared)),
            artifact_text_discovery_merge_entry,
            default_factory=lambda: ArtifactTextDiscoveryBatch(source_file=source_file),
        )
        target = ArtifactTextDiscoveryBatch(source_file=source_file)
        for source in merge_ready:
            merge_artifact_text_discovery_batch_fn(target, source)
        return target

    monkeypatch.setattr(runtime, "collect_artifact_text_discoveries", _collect_text)

    batch = collect_generic_text_discoveries_for_processor(
        _Adapter(),
        "payload",
        source_file="source.txt",
        source_hint="source.txt/path",
    )
    assert batch.source_file == "source.txt"
    assert batch.urls == ["urls:payload", "keys:payload"]
    assert calls == [
        ("batch", ["urls", "keys"], ArtifactTextDiscoveryBatch(source_file="source.txt")),
        ("family", "urls", "payload", "source.txt", "source.txt/path"),
        ("family", "keys", "payload", "source.txt", "source.txt/path"),
        (
            "batch",
            [
                (0, ArtifactTextDiscoveryBatch(source_file="source.txt", urls=["urls:payload"])),
                (1, ArtifactTextDiscoveryBatch(source_file="source.txt", urls=["keys:payload"])),
            ],
            ArtifactTextDiscoveryBatch(source_file="source.txt"),
        ),
        ("entry", 0, ["urls:payload"]),
        ("entry", 1, ["keys:payload"]),
        (
            "batch",
            [
                (0, ArtifactTextDiscoveryBatch(source_file="source.txt", urls=["urls:payload"])),
                (1, ArtifactTextDiscoveryBatch(source_file="source.txt", urls=["keys:payload"])),
            ],
            ArtifactTextDiscoveryBatch(source_file="source.txt"),
        ),
        ("merge_entry", 0, ["urls:payload"]),
        ("merge_entry", 1, ["keys:payload"]),
        ("merge", ["urls:payload"]),
        ("merge", ["keys:payload"]),
    ]


def test_collect_generic_text_discovery_family_for_processor_binds_family_helpers(
    monkeypatch: Any,
) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        _artifact_key_patterns = ["pattern"]

        def _run_ordered_local_batch(
            self,
            items: list[Any],
            worker: Callable[[Any], Any],
            *,
            default_factory: Callable[[], Any],
        ) -> list[Any]:
            calls.append(("batch", list(items), default_factory()))
            return [worker(item) for item in items]

        def _artifact_text_url_family_candidates(self, *args: Any, **kwargs: Any) -> list[str]:
            calls.append(("url_candidates", args, kwargs))
            return ["https://example.test"]

        def _artifact_text_contact_identity_candidates(self, *args: Any, **kwargs: Any) -> list[tuple[str, str, str, str]]:
            calls.append(("identity_candidates", args, kwargs))
            return [("owner", "email", "ops@example.test", "artifact")]

        def _artifact_text_key_pattern_findings(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            calls.append(("key_findings", args, kwargs))
            return []

        def _artifact_text_cloud_asset_family_candidates(self, *args: Any, **kwargs: Any) -> list[tuple[str, str, str]]:
            calls.append(("cloud_candidates", args, kwargs))
            return [("aws_s3", "bucket", "artifact")]

    def _batch(source_file: str, **values: list[Any]) -> ArtifactTextDiscoveryBatch:
        batch = ArtifactTextDiscoveryBatch(source_file=source_file)
        for name, entries in values.items():
            getattr(batch, name).extend(entries)
        return batch

    def _simple(family: str, **kwargs: Any) -> ArtifactTextDiscoveryBatch | None:
        calls.append(("simple", family, kwargs["source_file"]))
        if family == "emails":
            return _batch(kwargs["source_file"], emails=["ops@example.test"])
        return None

    def _network(family: str, **kwargs: Any) -> ArtifactTextDiscoveryBatch | None:
        calls.append(("network", family, kwargs["source_label"]))
        if family == "network_hosts":
            return _batch(kwargs["source_file"], host_seeds=[("host.example.test", "hostname")])
        return None

    def _url(family: str, **kwargs: Any) -> ArtifactTextDiscoveryBatch | None:
        calls.append(("url", family, kwargs["source_file"]))
        if family == "urls":
            return _batch(kwargs["source_file"], urls=["https://example.test"])
        return None

    def _identity(family: str, **kwargs: Any) -> ArtifactTextDiscoveryBatch | None:
        calls.append(("identity", family, kwargs["source_file"]))
        if family == "contact_identities":
            return _batch(
                kwargs["source_file"],
                identity_seeds=[("owner", "email", "ops@example.test", "artifact")],
            )
        return None

    def _keys(family: str, **kwargs: Any) -> ArtifactTextDiscoveryBatch | None:
        calls.append(
            (
                "keys",
                family,
                kwargs["artifact_key_patterns"],
                kwargs["redact_secret"]("secret"),
                kwargs["parse_azure_storage_connection_string"]("AccountName=x"),
                kwargs["redact_azure_storage_connection_string"]("AccountKey=y"),
                kwargs["encrypt_secret_material_for_finding"]("secret"),
            )
        )
        if family == "keys":
            return _batch(kwargs["source_file"], key_findings=[{"pattern": "api"}])
        return None

    def _cloud(family: str, **kwargs: Any) -> ArtifactTextDiscoveryBatch | None:
        calls.append(("cloud", family, kwargs["source_file"]))
        if family == "cloud_assets":
            return _batch(kwargs["source_file"], cloud_assets=[("aws_s3", "bucket", "artifact")])
        return None

    monkeypatch.setattr(runtime, "collect_artifact_simple_text_discovery_family", _simple)
    monkeypatch.setattr(runtime, "collect_artifact_network_host_text_discovery_family", _network)
    monkeypatch.setattr(runtime, "collect_artifact_url_text_discovery_family", _url)
    monkeypatch.setattr(runtime, "collect_artifact_identity_text_discovery_family", _identity)
    monkeypatch.setattr(runtime, "collect_artifact_key_text_discovery_family", _keys)
    monkeypatch.setattr(runtime, "collect_artifact_cloud_asset_text_discovery_family", _cloud)

    common_kwargs = {
        "text": "payload",
        "source_file": "source.txt",
        "source_hint": "hint.txt",
        "email_pattern": object(),
        "phone_pattern": object(),
        "strip_artifact_url_userinfo_in_text": str,
        "artifact_email_seed_entry": str,
        "artifact_phone_seed_entry": str,
        "extract_artifact_ip_seeds": lambda _text: [],
        "extract_artifact_network_endpoint_seeds": lambda *_args, **_kwargs: [],
        "looks_like_gitreview_text_config_name": lambda _value: False,
        "extract_artifact_gitreview_host_seeds": lambda _text: [],
        "artifact_format_label": lambda value: str(value),
        "mta_sts_mx_hosts": lambda _text: [],
        "matrix_server_delegated_hosts": lambda _text: [],
        "did_web_hosts": lambda _text: [],
        "did_web_hosts_from_lines": lambda _text: [],
        "nostr_relay_hosts": lambda _text: [],
        "terraform_dns_record_hosts": lambda _text: [],
        "artifact_network_host_seed_entries_for_host": lambda _host: [],
        "redact_secret": lambda _value: "redacted",
        "parse_azure_storage_connection_string": lambda _value: {"account": "x"},
        "redact_azure_storage_connection_string": lambda _value: "redacted-azure",
        "encrypt_secret_material_for_finding": lambda _value: ("cipher", "key"),
    }

    adapter = _Adapter()
    assert collect_generic_text_discovery_family_for_processor(adapter, "emails", **common_kwargs).emails == [
        "ops@example.test",
    ]
    assert collect_generic_text_discovery_family_for_processor(
        adapter,
        "network_hosts",
        **common_kwargs,
    ).host_seeds == [("host.example.test", "hostname")]
    assert collect_generic_text_discovery_family_for_processor(adapter, "urls", **common_kwargs).urls == [
        "https://example.test",
    ]
    assert collect_generic_text_discovery_family_for_processor(
        adapter,
        "contact_identities",
        **common_kwargs,
    ).identity_seeds == [("owner", "email", "ops@example.test", "artifact")]
    assert collect_generic_text_discovery_family_for_processor(adapter, "keys", **common_kwargs).key_findings == [
        {"pattern": "api"},
    ]
    assert collect_generic_text_discovery_family_for_processor(
        adapter,
        "cloud_assets",
        **common_kwargs,
    ).cloud_assets == [("aws_s3", "bucket", "artifact")]
    assert collect_generic_text_discovery_family_for_processor(adapter, "unknown", **common_kwargs) == (
        ArtifactTextDiscoveryBatch(source_file="source.txt")
    )
    assert ("keys", "keys", ["pattern"], "redacted", {"account": "x"}, "redacted-azure", ("cipher", "key")) in calls
    assert ("cloud", "cloud_assets", "source.txt") in calls


def test_artifact_text_key_pattern_findings_for_processor_builds_contextual_findings() -> None:
    calls: list[tuple[Any, ...]] = []
    primary_pattern = SimpleNamespace(
        name="api_key",
        regex=re.compile(r"API_KEY=([A-Z0-9]+)"),
        group=1,
    )
    context_pattern = SimpleNamespace(
        name="api_key_context",
        regex=re.compile(r"OWNER=([a-z]+)"),
        group=1,
    )

    def _contextual_findings(
        pattern: Any,
        patterns: list[Any],
        text: str,
        context: dict[str, object],
    ) -> list[dict[str, object]]:
        calls.append((pattern.name, [item.name for item in patterns], text, context))
        return [
            {
                "pattern": context_pattern,
                "key_value": "ops",
                **context,
                "contextual": True,
            }
        ]

    findings = artifact_text_key_pattern_findings_for_processor(
        primary_pattern,
        [primary_pattern, context_pattern],
        "OWNER=ops\nAPI_KEY=ABC123",
        source_file="artifact/config.env",
        contextual_findings_for_content=_contextual_findings,
    )

    assert findings == [
        {
            "pattern": primary_pattern,
            "key_value": "ABC123",
            "source_url": "artifact/config.env",
            "repo_name": "config.env",
            "file_path": "artifact/config.env",
            "backend": "artifact_text_extract",
        },
        {
            "pattern": context_pattern,
            "key_value": "ops",
            "source_url": "artifact/config.env",
            "repo_name": "config.env",
            "file_path": "artifact/config.env",
            "backend": "artifact_text_extract",
            "contextual": True,
        },
    ]
    assert calls == [
        (
            "api_key",
            ["api_key", "api_key_context"],
            "OWNER=ops\nAPI_KEY=ABC123",
            {
                "source_url": "artifact/config.env",
                "repo_name": "config.env",
                "file_path": "artifact/config.env",
                "backend": "artifact_text_extract",
            },
        )
    ]


def test_artifact_text_key_pattern_findings_for_processor_handles_empty_matches() -> None:
    no_match_pattern = SimpleNamespace(
        name="missing",
        regex=re.compile(r"TOKEN=([A-Z]+)"),
        group=1,
    )
    bad_group_pattern = SimpleNamespace(
        name="bad_group",
        regex=re.compile(r"TOKEN=([A-Z]+)"),
        group=2,
    )

    def _unexpected_contextual_findings(*_args: Any, **_kwargs: Any) -> list[dict[str, object]]:
        raise AssertionError("contextual findings should not run")

    assert (
        artifact_text_key_pattern_findings_for_processor(
            no_match_pattern,
            [no_match_pattern],
            "NO_TOKEN=true",
            source_file="artifact/config.env",
            contextual_findings_for_content=_unexpected_contextual_findings,
        )
        == []
    )
    assert (
        artifact_text_key_pattern_findings_for_processor(
            bad_group_pattern,
            [bad_group_pattern],
            "TOKEN=ABC",
            source_file="artifact/config.env",
            contextual_findings_for_content=_unexpected_contextual_findings,
        )
        == []
    )


def test_artifact_text_direct_url_candidate_for_processor_normalizes_blank_safe() -> None:
    calls: list[str] = []

    assert artifact_text_direct_url_candidate_for_processor(
        None,  # type: ignore[arg-type]
        normalize_artifact_text_url=lambda value: calls.append(value) or value.upper(),
    ) == ""
    assert calls == [""]


def test_artifact_text_url_family_candidates_for_processor_filters_direct_urls() -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _run_ordered_local_batch(
            self,
            items: list[Any],
            worker: Callable[[Any], Any],
            *,
            default_factory: Callable[[], Any],
        ) -> list[Any]:
            calls.append(("batch", list(items), default_factory()))
            return [worker(item) for item in items]

        def _artifact_text_direct_url_candidate(self, raw_url: str) -> str:
            calls.append(("direct", raw_url))
            return raw_url.rstrip(".,")

    deps = _url_family_candidate_dependencies(
        artifact_format_label=lambda _source_file: "manifest.json",
        source_looks_like_helm_index=lambda _source_file: True,
        url_looks_like_helm_chart_archive=lambda value: value.endswith(".tgz"),
    )

    urls = artifact_text_url_family_candidates_for_processor(
        _Adapter(),
        "direct",
        text=(
            "https://example.test/app#fragment "
            "https://example.test/app#fragment "
            "https://charts.example.test/pkg.tgz "
            "ftp://ignored.example.test"
        ),
        source_file="manifest.json",
        **deps,
    )

    assert urls == ["https://example.test/app"]
    assert calls == [
        (
            "batch",
            [
                "https://example.test/app#fragment",
                "https://example.test/app#fragment",
                "https://charts.example.test/pkg.tgz",
            ],
            "",
        ),
        ("direct", "https://example.test/app#fragment"),
        ("direct", "https://example.test/app#fragment"),
        ("direct", "https://charts.example.test/pkg.tgz"),
    ]


def test_artifact_text_url_family_candidates_for_processor_routes_label_gated_families() -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _run_ordered_local_batch(self, *_args: Any, **_kwargs: Any) -> list[Any]:
            raise AssertionError("direct URL batch should not run")

        def _artifact_text_direct_url_candidate(self, _raw_url: str) -> str:
            raise AssertionError("direct URL candidate should not run")

    def _callback(name: str) -> Callable[..., list[str]]:
        def _inner(*args: Any, **kwargs: Any) -> list[str]:
            calls.append((name, args, kwargs))
            return [name]

        return _inner

    deps = _url_family_candidate_dependencies(
        artifact_format_label=lambda source_file: source_file,
        host_meta_href_urls=_callback("host_meta"),
        well_known_link_urls=_callback("well_known"),
        api_catalog_urls=_callback("api_catalog"),
        passkey_endpoint_urls=_callback("passkey"),
        agent_card_urls=_callback("agent_card"),
        open_resource_discovery_urls=_callback("open_resource"),
        mercure_urls=_callback("mercure"),
        jmap_urls=_callback("jmap"),
        webweaver_urls=_callback("webweaver"),
        redocly_config_urls=_callback("redocly"),
    )
    adapter = _Adapter()

    assert artifact_text_url_family_candidates_for_processor(
        adapter,
        "host_meta_metadata",
        text="payload",
        source_file="host-meta",
        **deps,
    ) == ["host_meta"]
    assert artifact_text_url_family_candidates_for_processor(
        adapter,
        "host_meta_metadata",
        text="payload",
        source_file="other",
        **deps,
    ) == []
    assert artifact_text_url_family_candidates_for_processor(
        adapter,
        "well_known_link_metadata",
        text="payload",
        source_file="webfinger",
        **deps,
    ) == ["well_known"]
    assert artifact_text_url_family_candidates_for_processor(
        adapter,
        "api_catalog_metadata",
        text="payload",
        source_file="api-catalog",
        **deps,
    ) == ["api_catalog"]
    assert artifact_text_url_family_candidates_for_processor(
        adapter,
        "passkey_metadata",
        text="payload",
        source_file="passkey-endpoints",
        **deps,
    ) == ["passkey"]
    assert artifact_text_url_family_candidates_for_processor(
        adapter,
        "agent_card_metadata",
        text="payload",
        source_file="agent-card.json",
        **deps,
    ) == ["agent_card"]
    assert artifact_text_url_family_candidates_for_processor(
        adapter,
        "open_resource_discovery",
        text="payload",
        source_file="open-resource-discovery",
        **deps,
    ) == ["open_resource"]
    assert artifact_text_url_family_candidates_for_processor(
        adapter,
        "mercure_metadata",
        text="payload",
        source_file="mercure",
        **deps,
    ) == ["mercure"]
    assert artifact_text_url_family_candidates_for_processor(
        adapter,
        "jmap_metadata",
        text="payload",
        source_file="jmap",
        **deps,
    ) == ["jmap"]
    assert artifact_text_url_family_candidates_for_processor(
        adapter,
        "webweaver_metadata",
        text="payload",
        source_file="webweaver.json",
        **deps,
    ) == ["webweaver"]
    assert artifact_text_url_family_candidates_for_processor(
        adapter,
        "redocly_config",
        text="payload",
        source_file="redocly-config",
        **deps,
    ) == ["redocly"]
    assert calls == [
        ("host_meta", ("payload",), {"base_url": "host-meta"}),
        ("well_known", ("payload",), {"base_url": "webfinger"}),
        ("api_catalog", ("payload",), {"base_url": "api-catalog"}),
        ("passkey", ("payload",), {"base_url": "passkey-endpoints"}),
        ("agent_card", ("payload",), {"base_url": "agent-card.json"}),
        ("open_resource", ("payload",), {"base_url": "open-resource-discovery"}),
        ("mercure", ("payload",), {"base_url": "mercure"}),
        ("jmap", ("payload",), {"base_url": "jmap"}),
        ("webweaver", ("payload",), {"base_url": "webweaver.json"}),
        ("redocly", ("payload",), {"base_url": "redocly-config"}),
    ]


def test_artifact_text_url_family_candidates_for_processor_routes_open_families() -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _run_ordered_local_batch(self, *_args: Any, **_kwargs: Any) -> list[Any]:
            raise AssertionError("direct URL batch should not run")

        def _artifact_text_direct_url_candidate(self, _raw_url: str) -> str:
            raise AssertionError("direct URL candidate should not run")

    def _callback(name: str) -> Callable[..., list[str]]:
        def _inner(*args: Any, **kwargs: Any) -> list[str]:
            calls.append((name, args, kwargs))
            return [name]

        return _inner

    deps = _url_family_candidate_dependencies(
        artifact_format_label=lambda _source_file: "source-label",
        extract_artifact_relative_route_urls=_callback("relative"),
        public_metadata_document_urls=_callback("public_metadata"),
        oauth_metadata_urls=_callback("oauth"),
        jwks_urls=_callback("jwks"),
        feed_urls=_callback("feed"),
        json_feed_urls=_callback("json_feed"),
        opensearch_description_urls=_callback("opensearch"),
        saml_metadata_urls=_callback("saml"),
        web_manifest_urls=_callback("web_manifest"),
        helm_index_chart_package_urls=_callback("helm"),
        extract_artifact_package_registry_urls=lambda text: calls.append(("package", (text,), {})) or ["package"],
        extract_artifact_container_image_urls=lambda text, *, source_hint: calls.append(
            ("container", (text,), {"source_hint": source_hint})
        )
        or ["container"],
    )
    adapter = _Adapter()

    family_results = {
        family: artifact_text_url_family_candidates_for_processor(
            adapter,
            family,
            text="payload",
            source_file="source.txt",
            **deps,
        )
        for family in (
            "relative_routes",
            "public_metadata_links",
            "oauth_metadata",
            "jwks_metadata",
            "feed_metadata",
            "json_feed_metadata",
            "opensearch_description",
            "saml_metadata",
            "web_manifest_metadata",
            "helm_index",
            "package_registry",
            "container_images",
            "unknown",
        )
    }

    assert family_results == {
        "relative_routes": ["relative"],
        "public_metadata_links": ["public_metadata"],
        "oauth_metadata": ["oauth"],
        "jwks_metadata": ["jwks"],
        "feed_metadata": ["feed"],
        "json_feed_metadata": ["json_feed"],
        "opensearch_description": ["opensearch"],
        "saml_metadata": ["saml"],
        "web_manifest_metadata": ["web_manifest"],
        "helm_index": ["helm"],
        "package_registry": ["package"],
        "container_images": ["container"],
        "unknown": [],
    }
    assert ("public_metadata", ("payload",), {"source_label": "source-label", "base_url": "source.txt"}) in calls
    assert ("helm", ("payload",), {"source_hint": "source.txt", "base_url": "source.txt"}) in calls
    assert ("container", ("payload",), {"source_hint": "source.txt"}) in calls


def _url_family_candidate_dependencies(**overrides: Any) -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "artifact_url_pattern": re.compile(r"https?://[^\s\"'<>`]+", re.IGNORECASE),
        "artifact_format_label": lambda source_file: source_file,
        "source_looks_like_helm_index": lambda _source_file: False,
        "url_looks_like_helm_chart_archive": lambda _url: False,
        "extract_artifact_relative_route_urls": lambda text, *, base_url: [f"relative:{base_url}:{text}"],
        "public_metadata_document_urls": lambda text, **kwargs: [f"public:{kwargs['base_url']}:{text}"],
        "host_meta_href_urls": lambda text, *, base_url: [f"host-meta:{base_url}:{text}"],
        "well_known_link_urls": lambda text, *, base_url: [f"well-known:{base_url}:{text}"],
        "api_catalog_urls": lambda text, *, base_url: [f"api-catalog:{base_url}:{text}"],
        "passkey_endpoint_urls": lambda text, *, base_url: [f"passkey:{base_url}:{text}"],
        "agent_card_urls": lambda text, *, base_url: [f"agent-card:{base_url}:{text}"],
        "open_resource_discovery_urls": lambda text, *, base_url: [f"open-resource:{base_url}:{text}"],
        "mercure_urls": lambda text, *, base_url: [f"mercure:{base_url}:{text}"],
        "jmap_urls": lambda text, *, base_url: [f"jmap:{base_url}:{text}"],
        "webweaver_urls": lambda text, *, base_url: [f"webweaver:{base_url}:{text}"],
        "oauth_metadata_urls": lambda text, **kwargs: [f"oauth:{kwargs['base_url']}:{text}"],
        "jwks_urls": lambda text, **kwargs: [f"jwks:{kwargs['base_url']}:{text}"],
        "feed_urls": lambda text, **kwargs: [f"feed:{kwargs['base_url']}:{text}"],
        "json_feed_urls": lambda text, **kwargs: [f"json-feed:{kwargs['base_url']}:{text}"],
        "opensearch_description_urls": lambda text, **kwargs: [f"opensearch:{kwargs['base_url']}:{text}"],
        "saml_metadata_urls": lambda text, **kwargs: [f"saml:{kwargs['base_url']}:{text}"],
        "web_manifest_urls": lambda text, **kwargs: [f"web-manifest:{kwargs['base_url']}:{text}"],
        "helm_index_chart_package_urls": lambda text, **kwargs: [f"helm:{kwargs['base_url']}:{text}"],
        "redocly_config_urls": lambda text, *, base_url: [f"redocly:{base_url}:{text}"],
        "extract_artifact_package_registry_urls": lambda text: [f"package:{text}"],
        "extract_artifact_container_image_urls": lambda text, *, source_hint: [f"container:{source_hint}:{text}"],
    }
    defaults.update(overrides)
    return defaults


def test_artifact_text_contact_identity_candidates_for_processor_extracts_and_dedupes() -> None:
    text = "\n".join(
        [
            "BEGIN:VCARD",
            "TITLE:Security\\, Lead",
            "FN:Bryan Example",
            "FN:Bryan Example",
            "N:Example;Ana;Maria;Dr.;PhD",
            "ORG:Forge Labs;Security",
            "EMAIL:ops@example.test",
            "END:VCARD",
        ]
    )

    candidates = artifact_text_contact_identity_candidates_for_processor(
        text,
        source_file="artifact.txt",
        artifact_format_label=lambda _source_file: "text",
        calendar_contact_title_line_value=calendar_contact_title_line_value_for_processor_wrapper,
        calendar_contact_identity_line_entry=calendar_contact_identity_line_entry_for_processor_wrapper,
    )

    assert candidates == [
        ("Bryan Example", "name", "fn", "Security, Lead"),
        ("Dr. Ana Maria Example PhD", "name", "n", "Security, Lead"),
        ("Forge Labs", "company", "org", "Security, Lead"),
    ]


def test_artifact_text_contact_identity_candidates_for_processor_respects_marker_gate_and_limit() -> None:
    assert artifact_text_contact_identity_candidates_for_processor(
        "FN:No Marker",
        source_file="artifact.txt",
        artifact_format_label=lambda _source_file: "text",
        calendar_contact_title_line_value=calendar_contact_title_line_value_for_processor_wrapper,
        calendar_contact_identity_line_entry=calendar_contact_identity_line_entry_for_processor_wrapper,
    ) == []

    many_contacts = "\n".join(["BEGIN:VCARD", *[f"FN:Person {index}" for index in range(45)]])
    candidates = artifact_text_contact_identity_candidates_for_processor(
        many_contacts,
        source_file="contacts.vcf",
        artifact_format_label=lambda _source_file: "vcf",
        calendar_contact_title_line_value=calendar_contact_title_line_value_for_processor_wrapper,
        calendar_contact_identity_line_entry=calendar_contact_identity_line_entry_for_processor_wrapper,
    )
    assert len(candidates) == 40
    assert candidates[0] == ("Person 0", "name", "fn", "")
    assert candidates[-1] == ("Person 39", "name", "fn", "")


def test_calendar_contact_identity_line_entry_for_processor_parses_supported_keys() -> None:
    assert calendar_contact_identity_line_entry_for_processor(
        "FN:Bryan Example",
        calendar_contact_identity_value=calendar_contact_identity_value_for_processor_wrapper,
        looks_like_person_name=lambda _value: True,
    ) == ("Bryan Example", "name", "fn")
    assert calendar_contact_identity_line_entry_for_processor(
        "ORG=Forge Labs;Security",
        calendar_contact_identity_value=calendar_contact_identity_value_for_processor_wrapper,
        looks_like_person_name=lambda _value: True,
    ) == ("Forge Labs", "company", "org")
    assert calendar_contact_identity_line_entry_for_processor(
        "FN:https://example.test",
        calendar_contact_identity_value=calendar_contact_identity_value_for_processor_wrapper,
        looks_like_person_name=lambda _value: True,
    ) is None
    assert calendar_contact_identity_line_entry_for_processor(
        "FN:One",
        calendar_contact_identity_value=calendar_contact_identity_value_for_processor_wrapper,
        looks_like_person_name=lambda _value: False,
    ) is None


def test_calendar_contact_value_helpers_clean_and_reject_invalid_values() -> None:
    assert calendar_contact_title_line_value_for_processor(
        "TITLE=Security\\nLead",
        calendar_contact_identity_value=calendar_contact_identity_value_for_processor_wrapper,
    ) == "Security Lead"
    assert calendar_contact_identity_value_for_processor(
        "n",
        "Example;Ana;Maria;Dr.;PhD",
        clean_calendar_contact_identity_value=clean_calendar_contact_identity_value_for_processor,
    ) == "Dr. Ana Maria Example PhD"
    assert calendar_contact_identity_value_for_processor(
        "org",
        ";Forge\\; Labs;Security",
        clean_calendar_contact_identity_value=clean_calendar_contact_identity_value_for_processor,
    ) == "Forge\\"
    assert clean_calendar_contact_identity_value_for_processor("A") == ""
    assert clean_calendar_contact_identity_value_for_processor("ops@example.test") == ""
    assert clean_calendar_contact_identity_value_for_processor("https://example.test") == ""
    assert clean_calendar_contact_identity_value_for_processor("12345") == ""


def calendar_contact_identity_value_for_processor_wrapper(key: str, raw_value: str) -> str:
    return calendar_contact_identity_value_for_processor(
        key,
        raw_value,
        clean_calendar_contact_identity_value=clean_calendar_contact_identity_value_for_processor,
    )


def calendar_contact_title_line_value_for_processor_wrapper(raw_line: str) -> str:
    return calendar_contact_title_line_value_for_processor(
        raw_line,
        calendar_contact_identity_value=calendar_contact_identity_value_for_processor_wrapper,
    )


def calendar_contact_identity_line_entry_for_processor_wrapper(
    raw_line: str,
) -> tuple[str, str, str] | None:
    return calendar_contact_identity_line_entry_for_processor(
        raw_line,
        calendar_contact_identity_value=calendar_contact_identity_value_for_processor_wrapper,
        looks_like_person_name=lambda value: bool(value and " " in value),
    )


def test_artifact_text_aws_cloud_asset_family_candidates_for_processor_extracts_aws_assets() -> None:
    calls: list[str] = []
    s3_uri_pattern = re.compile(r"s3://([a-z0-9.\-]{3,63})(?:/|(?=\s|$))", re.IGNORECASE)
    s3_arn_pattern = re.compile(
        r"\barn:(?:aws|aws-cn|aws-us-gov):s3:::(?P<bucket>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])"
        r"(?=$|[/\s\"'`<>,;)\]}])",
        re.IGNORECASE,
    )
    kms_arn_pattern = re.compile(
        r"\barn:(?:aws|aws-cn|aws-us-gov):kms:[a-z0-9-]+:\d{12}:"
        r"(?:key/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        r"|alias/[A-Za-z0-9/_+=,.@-]{1,256})"
        r"(?=$|[/\s\"'`<>,;)\]}])",
        re.IGNORECASE,
    )

    def _generic_arns(text: str) -> list[tuple[str, str, str]]:
        calls.append(text)
        return [("aws_lambda_function", "arn:aws:lambda:us-east-1:123456789012:function:worker", "artifact_aws_lambda_arn")]

    common = {
        "aws_s3_uri_pattern": s3_uri_pattern,
        "aws_s3_arn_pattern": s3_arn_pattern,
        "aws_kms_arn_pattern": kms_arn_pattern,
        "aws_generic_arn_cloud_asset_candidates": _generic_arns,
    }

    assert artifact_text_aws_cloud_asset_family_candidates_for_processor(
        "aws_s3",
        text=(
            "s3://Ops-Bucket/path s3://ops-bucket/ "
            "arn:aws:s3:::Arn-Bucket arn:aws-us-gov:s3:::Gov-Bucket "
            "arn:aws-cn:s3:::Cn-Bucket"
        ),
        **common,
    ) == [
        ("aws_s3", "ops-bucket", "artifact_s3_uri"),
        ("aws_s3", "arn-bucket", "artifact_s3_arn"),
        ("aws_s3", "gov-bucket", "artifact_s3_arn"),
        ("aws_s3", "cn-bucket", "artifact_s3_arn"),
    ]
    assert artifact_text_aws_cloud_asset_family_candidates_for_processor(
        "aws_kms",
        text=(
            "arn:aws:kms:us-east-1:123456789012:key/ABCDEF12-1234-1234-1234-ABCDEF123456 "
            "arn:aws:kms:us-east-1:123456789012:alias/Team/Key"
        ),
        **common,
    ) == [
        (
            "aws_kms",
            "arn:aws:kms:us-east-1:123456789012:key/abcdef12-1234-1234-1234-abcdef123456",
            "artifact_aws_kms_arn",
        ),
        ("aws_kms", "arn:aws:kms:us-east-1:123456789012:alias/team/key", "artifact_aws_kms_arn"),
    ]
    assert artifact_text_aws_cloud_asset_family_candidates_for_processor(
        "aws_arns",
        text="arn payload",
        **common,
    ) == [
        ("aws_lambda_function", "arn:aws:lambda:us-east-1:123456789012:function:worker", "artifact_aws_lambda_arn")
    ]
    assert artifact_text_aws_cloud_asset_family_candidates_for_processor(
        "gcs",
        text="gs://bucket",
        **common,
    ) is None
    assert calls == ["arn payload"]


def test_artifact_text_gcp_cloud_asset_family_candidates_for_processor_extracts_gcp_assets() -> None:
    gcs_uri_pattern = re.compile(r"gs://([a-z0-9._\-]{3,222})(?:/|(?=\s|$))", re.IGNORECASE)
    gcs_resource_bucket_pattern = re.compile(
        r"\b(?://storage\.googleapis\.com/)?projects/_/buckets/"
        r"(?P<bucket>[a-z0-9][a-z0-9._\-]{1,220}[a-z0-9])"
        r"(?=$|[/\s\"'`<>,;)\]}])",
        re.IGNORECASE,
    )
    gcp_kms_resource_pattern = re.compile(
        r"\bprojects/(?P<project>[a-z][a-z0-9-]{4,28}[a-z0-9])"
        r"/locations/(?P<location>[A-Za-z0-9_-]{1,63})"
        r"/keyRings/(?P<keyring>[A-Za-z0-9_-]{1,63})"
        r"/cryptoKeys/(?P<key>[A-Za-z0-9_-]{1,63})"
        r"(?:/cryptoKeyVersions/(?P<version>[0-9]{1,32}))?"
        r"(?=$|[/\s\"'`<>,;)\]}])",
    )
    common = {
        "gcs_uri_pattern": gcs_uri_pattern,
        "gcs_resource_bucket_pattern": gcs_resource_bucket_pattern,
        "gcp_kms_resource_pattern": gcp_kms_resource_pattern,
    }

    assert artifact_text_gcp_cloud_asset_family_candidates_for_processor(
        "gcs",
        text=(
            "gs://Ops-Bucket/path gs://ops-bucket/ "
            "projects/_/buckets/Resource-Bucket "
            "https://storage.googleapis.com/projects/_/buckets/Url-Resource-Bucket"
        ),
        **common,
    ) == [
        ("gcs", "ops-bucket", "artifact_gcs_uri"),
        ("gcs", "resource-bucket", "artifact_gcs_resource"),
        ("gcs", "url-resource-bucket", "artifact_gcs_resource"),
    ]
    assert artifact_text_gcp_cloud_asset_family_candidates_for_processor(
        "gcp_kms",
        text=(
            "projects/acme-prod1/locations/global/keyRings/KeyRing/cryptoKeys/SigningKey "
            "projects/acme-prod1/locations/global/keyRings/KeyRing/cryptoKeys/SigningKey"
        ),
        **common,
    ) == [
        (
            "gcp_kms",
            "projects/acme-prod1/locations/global/keyRings/KeyRing/cryptoKeys/SigningKey",
            "artifact_gcp_kms_resource",
        )
    ]
    assert artifact_text_gcp_cloud_asset_family_candidates_for_processor(
        "azure_blob",
        text="blob",
        **common,
    ) is None


def test_artifact_text_azure_cloud_asset_family_candidates_for_processor_extracts_azure_assets() -> None:
    azure_blob_resource_id_pattern = re.compile(
        r"/providers/Microsoft\.Storage/storageAccounts/(?P<account>[a-z0-9]{3,24})"
        r"/blobServices/default/containers/(?P<container>[a-z0-9][a-z0-9\-]{1,61}[a-z0-9])"
        r"(?=$|[/\s\"'`<>,;)\]}])",
        re.IGNORECASE,
    )
    azure_key_vault_url_pattern = re.compile(
        r"https?://(?P<vault>[a-z0-9][a-z0-9-]{1,22}[a-z0-9])\.vault\.azure\.net"
        r"(?:/(?P<family>keys|secrets|certificates)/(?P<name>[^/?#\s\"'`<>,;)\]}]+))?",
        re.IGNORECASE,
    )
    microsoft_identity_association_app_id_pattern = re.compile(
        r"(?i)[\"']application[_-]?id[\"']\s*:\s*[\"']"
        r"(?P<app_id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
        r"[\"']"
    )
    common = {
        "azure_blob_resource_id_pattern": azure_blob_resource_id_pattern,
        "azure_key_vault_url_pattern": azure_key_vault_url_pattern,
        "microsoft_identity_association_app_id_pattern": microsoft_identity_association_app_id_pattern,
    }

    assert artifact_text_azure_cloud_asset_family_candidates_for_processor(
        "azure_blob",
        text=(
            "/providers/Microsoft.Storage/storageAccounts/AcctOne"
            "/blobServices/default/containers/Container-One "
            "/providers/Microsoft.Storage/storageAccounts/accttwo"
            "/blobServices/default/containers/container-two"
        ),
        **common,
    ) == [
        ("azure_blob", "acctone/container-one", "artifact_azure_resource"),
        ("azure_blob", "accttwo/container-two", "artifact_azure_resource"),
    ]
    assert artifact_text_azure_cloud_asset_family_candidates_for_processor(
        "azure_key_vault",
        text=(
            "https://VaultOne.vault.azure.net/secrets/API%2DKey "
            "https://vaultone.vault.azure.net/secrets/api%2Dkey "
            "https://VaultTwo.vault.azure.net"
        ),
        **common,
    ) == [
        ("azure_key_vault", "vaultone/secrets/api-key", "artifact_azure_key_vault_url"),
        ("azure_key_vault", "vaulttwo", "artifact_azure_key_vault_url"),
    ]
    assert artifact_text_azure_cloud_asset_family_candidates_for_processor(
        "azure_ad_app",
        text=(
            '"applicationId": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE" '
            '"application_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"'
        ),
        **common,
    ) == [
        (
            "azure_ad_app",
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "artifact_microsoft_identity_association",
        )
    ]
    assert artifact_text_azure_cloud_asset_family_candidates_for_processor(
        "cloudflare",
        text="cloudflare",
        **common,
    ) is None


def test_artifact_text_app_manifest_family_candidates_for_processor_extracts_app_manifests() -> None:
    def _artifact_format_label(source_file: str) -> str:
        return source_file

    def _ads_txt_assets(text: str, *, app_ads: bool = False) -> list[tuple[str, str, str]]:
        suffix = "app" if app_ads else "web"
        return [("ad_publisher_account", f"{text}:{suffix}", "artifact_ads_txt")]

    common = {
        "artifact_format_label": _artifact_format_label,
        "ads_txt_publisher_account_assets": _ads_txt_assets,
        "sellers_json_seller_account_assets": lambda text: [
            ("seller_account", text, "artifact_sellers_json")
        ],
        "ai_plugin_manifest_assets": lambda text: [
            ("ai_plugin_manifest", text, "artifact_ai_plugin_manifest")
        ],
        "assetlinks_android_packages": lambda text: [text],
        "android_manifest_package_names": lambda text: [f"{text}.pkg"],
        "aasa_ios_app_ids": lambda text: [text],
        "web_manifest_related_application_assets": lambda text: [
            ("mobile_related_app", text, "artifact_web_manifest")
        ],
    }

    assert artifact_text_app_manifest_family_candidates_for_processor(
        "ads_txt_publisher_accounts",
        text="pub-1",
        source_file="ads.txt",
        **common,
    ) == [("ad_publisher_account", "pub-1:web", "artifact_ads_txt")]
    assert artifact_text_app_manifest_family_candidates_for_processor(
        "app_ads_txt_publisher_accounts",
        text="pub-2",
        source_file="app-ads.txt",
        **common,
    ) == [("ad_publisher_account", "pub-2:app", "artifact_ads_txt")]
    assert artifact_text_app_manifest_family_candidates_for_processor(
        "sellers_json_seller_accounts",
        text="seller-1",
        source_file="sellers.json",
        **common,
    ) == [("seller_account", "seller-1", "artifact_sellers_json")]
    assert artifact_text_app_manifest_family_candidates_for_processor(
        "ai_plugin_manifests",
        text="plugin.example",
        source_file="ai-plugin.json",
        **common,
    ) == [("ai_plugin_manifest", "plugin.example", "artifact_ai_plugin_manifest")]
    assert artifact_text_app_manifest_family_candidates_for_processor(
        "android_assetlinks",
        text="com.example.assetlinks",
        source_file="assetlinks.json",
        **common,
    ) == [
        (
            "mobile_android_package",
            "com.example.assetlinks",
            "artifact_assetlinks_android_package",
        )
    ]
    assert artifact_text_app_manifest_family_candidates_for_processor(
        "android_manifest",
        text="com.example.manifest",
        source_file="android-manifest",
        **common,
    ) == [
        (
            "mobile_android_package",
            "com.example.manifest.pkg",
            "artifact_android_manifest_package",
        )
    ]
    assert artifact_text_app_manifest_family_candidates_for_processor(
        "android_manifest",
        text="<manifest package='com.example.inline' />",
        source_file="xml",
        **common,
    ) == [
        (
            "mobile_android_package",
            "<manifest package='com.example.inline' />.pkg",
            "artifact_android_manifest_package",
        )
    ]
    assert artifact_text_app_manifest_family_candidates_for_processor(
        "apple_app_site_association",
        text="TEAMID.bundle",
        source_file="apple-app-site-association",
        **common,
    ) == [("mobile_ios_app", "TEAMID.bundle", "artifact_apple_app_site_association")]
    assert artifact_text_app_manifest_family_candidates_for_processor(
        "web_manifest_related_applications",
        text="related-app",
        source_file="webmanifest",
        **common,
    ) == [("mobile_related_app", "related-app", "artifact_web_manifest")]
    assert artifact_text_app_manifest_family_candidates_for_processor(
        "web_manifest_related_applications",
        text="related-app",
        source_file="manifest.json",
        **common,
    ) == [("mobile_related_app", "related-app", "artifact_web_manifest")]

    assert artifact_text_app_manifest_family_candidates_for_processor(
        "ads_txt_publisher_accounts",
        text="pub-1",
        source_file="text",
        **common,
    ) == []
    assert artifact_text_app_manifest_family_candidates_for_processor(
        "android_manifest",
        text="plain text",
        source_file="xml",
        **common,
    ) == []
    assert artifact_text_app_manifest_family_candidates_for_processor(
        "kubernetes_secret_manifests",
        text="secret",
        source_file="yaml",
        **common,
    ) is None


def test_artifact_text_orchestration_manifest_family_candidates_for_processor_extracts_manifest_assets() -> None:
    kubernetes_secret_manifest_asset_uri_pattern = re.compile(
        r"\b(?P<family>"
        r"external-secret|secret-store|cluster-secret-store|sealed-secret|"
        r"secret-provider-class|aws-cognito-user-pool|aws-cognito-identity-pool|"
        r"aws-cognito-app-client|aws-appsync-api|aws-pinpoint-app|aws-ecs-task-definition|"
        r"aws-lambda-function|aws-lambda-layer|aws-iam-role|aws-kms-key|aws-efs-access-point|"
        r"aws-sqs-queue|aws-sns-topic|aws-secretsmanager|aws-parameterstore|"
        r"gcp-secretmanager|hashicorp-vault"
        r")://(?P<identifier>[^\s\"'`<>,;)\]}]+)",
        re.IGNORECASE,
    )
    gitops_manifest_asset_uri_pattern = re.compile(
        r"\b(?P<family>"
        r"argo-application|argo-applicationset|"
        r"flux-gitrepository|flux-helmrepository|flux-ocirepository|flux-kustomization|"
        r"flux-bucket|crossplane-providerconfig|crossplane-resource|"
        r"crossplane-composition|crossplane-xrd"
        r")://(?P<identifier>[^\s\"'`<>,;)\]}]+)",
        re.IGNORECASE,
    )
    workflow_manifest_asset_uri_pattern = re.compile(
        r"\b(?P<family>"
        r"appveyor-pipeline|azure-pipeline|bitbucket-pipeline|circleci-pipeline|"
        r"gitlab-pipeline|github-workflow|github-action|buildkite-pipeline|drone-pipeline|"
        r"woodpecker-pipeline|tekton-pipeline|tekton-task|tekton-pipelinerun|"
        r"tekton-taskrun|argo-workflow|argo-workflowtemplate|argo-cronworkflow|"
        r"argo-clusterworkflowtemplate"
        r")://(?P<identifier>[^\s\"'`<>,;)\]}]+)",
        re.IGNORECASE,
    )
    common = {
        "kubernetes_secret_manifest_asset_uri_pattern": kubernetes_secret_manifest_asset_uri_pattern,
        "gitops_manifest_asset_uri_pattern": gitops_manifest_asset_uri_pattern,
        "workflow_manifest_asset_uri_pattern": workflow_manifest_asset_uri_pattern,
    }

    assert artifact_text_orchestration_manifest_family_candidates_for_processor(
        "kubernetes_secret_manifests",
        text=(
            "external-secret://Team/Prod%2FSecret "
            "external-secret://team/prod%2fsecret "
            "aws-cognito-user-pool://us-east-1_ABCdef "
            "aws-cognito-user-pool://us-east-1_ABCdef/ "
            "gcp-secretmanager://Projects/Acme/Secrets/API"
        ),
        **common,
    ) == [
        ("external_secret", "team/prod/secret", "artifact_kubernetes_secret_manifest"),
        ("aws_cognito_user_pool", "us-east-1_ABCdef", "artifact_amplify_client_config"),
        ("gcp_secretmanager", "projects/acme/secrets/api", "artifact_kubernetes_secret_manifest"),
    ]
    assert artifact_text_orchestration_manifest_family_candidates_for_processor(
        "gitops_manifests",
        text=(
            "argo-application://Team/App%2DOne "
            "argo-application://team/app%2Done "
            "flux-gitrepository://Org/Repo"
        ),
        **common,
    ) == [
        ("argo_application", "team/app-one", "artifact_gitops_manifest"),
        ("flux_gitrepository", "org/repo", "artifact_gitops_manifest"),
    ]
    assert artifact_text_orchestration_manifest_family_candidates_for_processor(
        "workflow_manifests",
        text=(
            "github-workflow://Org/Repo/.github/workflows/Build%2EYml "
            "github-workflow://org/repo/.github/workflows/build%2eyml "
            "tekton-task://Namespace/Task"
        ),
        **common,
    ) == [
        ("github_workflow", "org/repo/.github/workflows/build.yml", "artifact_workflow_manifest"),
        ("tekton_task", "namespace/task", "artifact_workflow_manifest"),
    ]
    assert artifact_text_orchestration_manifest_family_candidates_for_processor(
        "cloudflare",
        text="cloudflare",
        **common,
    ) is None


def test_artifact_text_cloudflare_asset_family_candidates_for_processor_extracts_cloudflare_assets() -> None:
    cloudflare_structured_asset_uri_pattern = re.compile(
        r"cloudflare-(r2|d1|kv|worker|pages)://([a-z0-9][a-z0-9._\-]{1,127})(?:/|(?=\s|$))",
        re.IGNORECASE,
    )

    assert artifact_text_cloudflare_asset_family_candidates_for_processor(
        "cloudflare",
        text=(
            "cloudflare-r2://Bucket.One/ "
            "cloudflare-d1://DB_Main "
            "cloudflare-kv://Namespace-One "
            "cloudflare-worker://Worker.Name "
            "cloudflare-pages://Site.Pages"
        ),
        cloudflare_structured_asset_uri_pattern=cloudflare_structured_asset_uri_pattern,
    ) == [
        ("cloudflare_r2", "bucket.one", "artifact_cloudflare_config"),
        ("cloudflare_d1", "db_main", "artifact_cloudflare_config"),
        ("cloudflare_kv", "namespace-one", "artifact_cloudflare_config"),
        ("cloudflare_worker", "worker.name", "artifact_cloudflare_config"),
        ("cloudflare_pages", "site.pages", "artifact_cloudflare_config"),
    ]
    assert artifact_text_cloudflare_asset_family_candidates_for_processor(
        "workflow_manifests",
        text="cloudflare-r2://Bucket.One/",
        cloudflare_structured_asset_uri_pattern=cloudflare_structured_asset_uri_pattern,
    ) is None


def test_structured_discovery_wrapper_helpers_delegate(monkeypatch: Any, tmp_path: Path) -> None:
    parsed = ParsedArtifact(
        artifact_id=13,
        source_url="file:///artifact.txt",
        artifact_type="text",
        path=tmp_path / "artifact.txt",
        payloads=[("source.txt", "path", "payload")],
    )

    monkeypatch.setattr(
        runtime,
        "artifact_discovery_payloads",
        lambda *, source_url, payloads: [(source_url, payloads[0][1], payloads[0][2])],
    )
    monkeypatch.setattr(runtime, "artifact_structured_discovery_payload_job", lambda payload: payload if payload[2] else None)
    monkeypatch.setattr(
        runtime,
        "artifact_structured_discovery_result_entry",
        lambda result_entry: [("result", str(result_entry[0]), "text")] if result_entry[1] is not None else None,
    )
    monkeypatch.setattr(
        runtime,
        "artifact_structured_discovery_payload_entry",
        lambda payload_batch, *, source_file, source_hint: (
            source_file,
            source_hint,
            payload_batch[1].strip(),
        )
        if payload_batch[1].strip()
        else None,
    )

    assert artifact_discovery_payloads_for_processor(parsed) == [("file:///artifact.txt", "path", "payload")]
    assert structured_discovery_payload_job_for_processor(("source", "path", "payload")) == (
        "source",
        "path",
        "payload",
    )
    assert structured_discovery_result_entry_for_processor((2, [("source", "path", "payload")])) == [
        ("result", "2", "text")
    ]
    assert structured_discovery_payload_entry_for_processor(
        (0, " structured "),
        source_file="source.txt",
        source_hint="source.txt/path",
    ) == ("source.txt", "source.txt/path", "structured")


def test_expand_structured_discovery_jobs_for_processor_binds_callbacks(monkeypatch: Any) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _run_ordered_local_batch(
            self,
            items: list[Any],
            worker: Callable[[Any], Any],
            *,
            default_factory: Callable[[], Any],
        ) -> list[Any]:
            calls.append(("batch", list(items), default_factory()))
            return [worker(item) for item in items]

        def _structured_discovery_payload_job(
            self,
            payload: tuple[str, str, str],
        ) -> tuple[str, str, str] | None:
            calls.append(("payload_job", payload))
            return payload

        def _structured_discovery_jobs_for_payload(
            self,
            payload: tuple[str, str, str],
        ) -> list[tuple[str, str, str]]:
            calls.append(("jobs", payload))
            return [(payload[0], payload[1], f"{payload[2]}:structured")]

        def _structured_discovery_result_entry(
            self,
            result_entry: tuple[int, list[tuple[str, str, str]] | None],
        ) -> list[tuple[str, str, str]] | None:
            calls.append(("result", result_entry))
            return result_entry[1]

    assert expand_structured_discovery_jobs_for_processor(
        _Adapter(),
        [("source.txt", "path", "payload")],
    ) == [("source.txt", "path", "payload:structured")]
    assert calls == [
        ("batch", [("source.txt", "path", "payload")], None),
        ("payload_job", ("source.txt", "path", "payload")),
        ("batch", [("source.txt", "path", "payload")], []),
        ("jobs", ("source.txt", "path", "payload")),
        ("batch", [(0, [("source.txt", "path", "payload:structured")])], None),
        ("result", (0, [("source.txt", "path", "payload:structured")])),
    ]


def test_structured_discovery_jobs_for_payload_for_processor_binds_families(monkeypatch: Any) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        _STRUCTURED_DISCOVERY_FAMILIES = ("json", "yaml")

        def _run_ordered_local_batch(
            self,
            items: list[Any],
            worker: Callable[[Any], Any],
            *,
            default_factory: Callable[[], Any],
        ) -> list[Any]:
            calls.append(("batch", list(items), default_factory()))
            return [worker(item) for item in items]

        def _build_structured_discovery_payload_fragment(
            self,
            family: str,
            *,
            text: str,
            extract_path: str,
            source_file: str,
        ) -> str:
            calls.append(("fragment", family, text, extract_path, source_file))
            return f"{family}:{text}"

        def _structured_discovery_payload_entry(
            self,
            payload_batch: tuple[int, str],
            *,
            source_file: str,
            source_hint: str,
        ) -> tuple[str, str, str]:
            calls.append(("entry", payload_batch, source_file, source_hint))
            return source_file, source_hint, payload_batch[1]

    assert structured_discovery_jobs_for_payload_for_processor(
        _Adapter(),
        ("source.txt", "config/path", "value"),
    ) == [
        ("source.txt", "source.txt/config/path", "json:value"),
        ("source.txt", "source.txt/config/path", "yaml:value"),
    ]
    assert calls == [
        ("batch", ["json", "yaml"], ""),
        ("fragment", "json", "value", "config/path", "source.txt"),
        ("fragment", "yaml", "value", "config/path", "source.txt"),
        ("batch", [(0, "json:value"), (1, "yaml:value")], None),
        ("entry", (0, "json:value"), "source.txt", "source.txt/config/path"),
        ("entry", (1, "yaml:value"), "source.txt", "source.txt/config/path"),
    ]


def test_data_uri_wrapper_helpers_bind_callbacks(monkeypatch: Any) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _decode_text_artifact_bytes(self, data: bytes) -> str:
            calls.append(("decode_text", data))
            return data.decode()

        def _run_ordered_local_batch(
            self,
            items: list[Any],
            worker: Callable[[Any], Any],
            *,
            default_factory: Callable[[], Any],
        ) -> list[Any]:
            calls.append(("batch", list(items), default_factory()))
            return [worker(item) for item in items]

        def _data_uri_payload_entry(self, match_entry: tuple[str, str]) -> str:
            calls.append(("payload_entry", match_entry))
            return f"payload:{match_entry[1]}"

        def _data_uri_image_payload_entry(self, match_entry: tuple[int, str, str]) -> str:
            calls.append(("image_entry", match_entry))
            return f"image:{match_entry[0]}:{match_entry[2]}"

        def _ocr_image_bytes(self, data: bytes, suffix: str) -> str:
            calls.append(("ocr", data, suffix))
            return "ocr text"

        def _barcode_image_bytes_payload(self, data: bytes) -> str:
            calls.append(("barcode", data))
            return "barcode text"

        def _image_metadata_payload(self, data: bytes) -> str:
            calls.append(("metadata", data))
            return "metadata text"

    monkeypatch.setattr(runtime, "decode_artifact_data_uri_bytes", lambda meta, raw_data: f"{meta}:{raw_data}".encode())

    def _payload_entry(
        match_entry: tuple[str, str],
        *,
        max_artifact_member_bytes: int,
        decode_text_artifact_bytes: Callable[[bytes], str],
    ) -> str:
        calls.append(("payload", match_entry, max_artifact_member_bytes))
        return decode_text_artifact_bytes(b"abcdef"[:max_artifact_member_bytes])

    def _structured_text(
        text: str,
        *,
        data_uri_pattern: Any,
        run_ordered_batch: Callable[..., list[Any]],
        data_uri_payload_entry: Callable[[tuple[str, str]], str],
    ) -> str:
        calls.append(("structured", text, data_uri_pattern))
        return "|".join(
            run_ordered_batch(
                [("text/plain", "a"), ("text/plain", "b")],
                data_uri_payload_entry,
                default_factory=str,
            )
        )

    def _image_payload(
        match_entry: tuple[int, str, str],
        *,
        ocr_image_suffixes: set[str],
        max_ocr_image_bytes: int,
        suffix_from_content_type: Callable[[str], str],
        ocr_image_bytes: Callable[[bytes, str], str],
        barcode_image_bytes_payload: Callable[[bytes], str],
        image_metadata_payload: Callable[[bytes], str],
    ) -> str:
        suffix = suffix_from_content_type("image/png")
        calls.append(("image_payload", match_entry, ocr_image_suffixes, max_ocr_image_bytes, suffix))
        payload = b"image-bytes"[:max_ocr_image_bytes]
        return "\n".join(
            (
                ocr_image_bytes(payload, suffix),
                barcode_image_bytes_payload(payload),
                image_metadata_payload(payload),
            )
        )

    def _image_structured_text(
        text: str,
        *,
        data_uri_pattern: Any,
        run_ordered_batch: Callable[..., list[Any]],
        data_uri_image_payload_entry: Callable[[tuple[int, str, str]], str],
    ) -> str:
        calls.append(("image_structured", text, data_uri_pattern))
        return "|".join(
            run_ordered_batch(
                [(0, "image/png", "raw")],
                data_uri_image_payload_entry,
                default_factory=str,
            )
        )

    monkeypatch.setattr(runtime, "artifact_data_uri_payload_entry", _payload_entry)
    monkeypatch.setattr(runtime, "artifact_data_uri_structured_payload_text", _structured_text)
    monkeypatch.setattr(runtime, "artifact_data_uri_image_payload_entry", _image_payload)
    monkeypatch.setattr(runtime, "artifact_data_uri_image_structured_payload_text", _image_structured_text)

    adapter = _Adapter()
    assert decode_data_uri_bytes_for_processor("text/plain", "abc") == b"text/plain:abc"
    assert data_uri_payload_entry_for_processor(adapter, ("text/plain", "abc"), max_artifact_member_bytes=3) == "abc"
    assert data_uri_structured_payload_text_for_processor(adapter, "data", data_uri_pattern="pattern") == (
        "payload:a|payload:b"
    )
    assert data_uri_image_payload_entry_for_processor(
        adapter,
        (0, "image/png", "raw"),
        ocr_image_suffixes={".png"},
        max_ocr_image_bytes=5,
        suffix_from_content_type=lambda content_type: ".png" if content_type == "image/png" else "",
    ) == "ocr text\nbarcode text\nmetadata text"
    assert data_uri_image_structured_payload_text_for_processor(adapter, "image-data", data_uri_pattern="pattern") == (
        "image:0:raw"
    )
    assert calls == [
        ("payload", ("text/plain", "abc"), 3),
        ("decode_text", b"abc"),
        ("structured", "data", "pattern"),
        ("batch", [("text/plain", "a"), ("text/plain", "b")], ""),
        ("payload_entry", ("text/plain", "a")),
        ("payload_entry", ("text/plain", "b")),
        ("image_payload", (0, "image/png", "raw"), {".png"}, 5, ".png"),
        ("ocr", b"image", ".png"),
        ("barcode", b"image"),
        ("metadata", b"image"),
        ("image_structured", "image-data", "pattern"),
        ("batch", [(0, "image/png", "raw")], ""),
        ("image_entry", (0, "image/png", "raw")),
    ]


def test_iac_text_structured_payload_text_for_processor_dedupes_family_lines() -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _run_ordered_local_batch(
            self,
            items: tuple[str, ...],
            worker: Callable[[str], str],
            *,
            default_factory: Callable[[], str],
        ) -> list[str]:
            calls.append(("batch", items, default_factory()))
            return [worker(item) for item in items]

        def _iac_text_structured_payload_family(
            self,
            family: str,
            *,
            text: str,
            source_hint: str,
        ) -> str:
            calls.append(("family", family, text, source_hint))
            if family == "terraform":
                return "alpha\nBeta\n"
            if family == "bicep":
                return " beta \nGamma"
            return ""

    assert iac_text_structured_payload_text_for_processor(
        _Adapter(),
        "iac text",
        source_hint="source.tf",
        iac_structured_payload_families=("terraform", "bicep", "empty"),
    ) == "alpha\nBeta\nGamma"
    assert calls == [
        ("batch", ("terraform", "bicep", "empty"), ""),
        ("family", "terraform", "iac text", "source.tf"),
        ("family", "bicep", "iac text", "source.tf"),
        ("family", "empty", "iac text", "source.tf"),
    ]


def test_iac_text_structured_payload_family_for_processor_dispatches_candidates() -> None:
    calls: list[tuple[Any, ...]] = []

    class _Adapter:
        def _terraform_text_structured_payload_text(self, text: str, *, source_hint: str) -> str:
            calls.append(("terraform", text, source_hint))
            return "terraform-result"

        def _bicep_text_structured_payload_text(self, text: str) -> str:
            calls.append(("bicep", text))
            return "bicep-result"

    def _candidate(name: str) -> Callable[..., list[str]]:
        def _inner(text: str, *, source_hint: str) -> list[str]:
            calls.append((name, text, source_hint))
            return [f"{name}-one", f"{name}-two"]

        return _inner

    kwargs = {
        "cloudformation_template_candidates": _candidate("cloudformation"),
        "serverless_framework_candidates": _candidate("serverless"),
        "sam_config_candidates": _candidate("sam_config"),
        "pulumi_config_candidates": _candidate("pulumi_config"),
        "sst_config_candidates": _candidate("sst_config"),
        "aws_cdk_candidates": _candidate("aws_cdk"),
    }
    adapter = _Adapter()

    assert (
        iac_text_structured_payload_family_for_processor(
            adapter,
            "terraform",
            text="iac text",
            source_hint="source",
            **kwargs,
        )
        == "terraform-result"
    )
    assert (
        iac_text_structured_payload_family_for_processor(
            adapter,
            "bicep",
            text="iac text",
            source_hint="source",
            **kwargs,
        )
        == "bicep-result"
    )
    assert (
        iac_text_structured_payload_family_for_processor(
            adapter,
            "cloudformation",
            text="iac text",
            source_hint="source",
            **kwargs,
        )
        == "cloudformation-one\ncloudformation-two"
    )
    assert (
        iac_text_structured_payload_family_for_processor(
            adapter,
            "serverless",
            text="iac text",
            source_hint="source",
            **kwargs,
        )
        == "serverless-one\nserverless-two"
    )
    assert (
        iac_text_structured_payload_family_for_processor(
            adapter,
            "sam_config",
            text="iac text",
            source_hint="source",
            **kwargs,
        )
        == "sam_config-one\nsam_config-two"
    )
    assert (
        iac_text_structured_payload_family_for_processor(
            adapter,
            "pulumi_config",
            text="iac text",
            source_hint="source",
            **kwargs,
        )
        == "pulumi_config-one\npulumi_config-two"
    )
    assert (
        iac_text_structured_payload_family_for_processor(
            adapter,
            "sst_config",
            text="iac text",
            source_hint="source",
            **kwargs,
        )
        == "sst_config-one\nsst_config-two"
    )
    assert (
        iac_text_structured_payload_family_for_processor(
            adapter,
            "aws_cdk",
            text="iac text",
            source_hint="source",
            **kwargs,
        )
        == "aws_cdk-one\naws_cdk-two"
    )
    assert (
        iac_text_structured_payload_family_for_processor(
            adapter,
            "unknown",
            text="iac text",
            source_hint="source",
            **kwargs,
        )
        == ""
    )
    assert calls == [
        ("terraform", "iac text", "source"),
        ("bicep", "iac text"),
        ("cloudformation", "iac text", "source"),
        ("serverless", "iac text", "source"),
        ("sam_config", "iac text", "source"),
        ("pulumi_config", "iac text", "source"),
        ("sst_config", "iac text", "source"),
        ("aws_cdk", "iac text", "source"),
    ]


def test_emit_artifact_processor_stage_progress_emits_labeled_snapshot() -> None:
    events: list[tuple[str, dict[str, object]]] = []

    emit_artifact_processor_stage_progress(
        "parse",
        total=3,
        workers=2,
        completed=3,
        failed=1,
        started_at=1.0,
        progress_label="1.K artifact queue",
        progress_callback=lambda label, payload: events.append((label, dict(payload))),
    )

    assert events == [
        (
            "1.K artifact queue / parse",
            {
                "total": 3,
                "workers": 2,
                "running": 0,
                "pending": 0,
                "queue_depth": 0,
                "completed": 3,
                "failed": 1,
                "eta_seconds": 0.0,
            },
        )
    ]


def test_emit_artifact_processor_stage_progress_skips_missing_callback_or_label() -> None:
    events: list[tuple[str, dict[str, object]]] = []

    emit_artifact_processor_stage_progress(
        "parse",
        total=1,
        workers=1,
        completed=0,
        failed=0,
        started_at=1.0,
        progress_label="",
        progress_callback=lambda label, payload: events.append((label, dict(payload))),
    )
    emit_artifact_processor_stage_progress(
        "parse",
        total=1,
        workers=1,
        completed=0,
        failed=0,
        started_at=1.0,
        progress_label="1.K artifact queue",
        progress_callback=None,
    )

    assert events == []


def test_artifact_processor_progress_stage_label_preserves_artifact_label_rules() -> None:
    assert artifact_processor_progress_stage_label("1.K artifact queue", "parse") == "1.K artifact queue / parse"
    assert artifact_processor_progress_stage_label("1.K artifact queue", "") == "1.K artifact queue"
    assert artifact_processor_progress_stage_label("", "parse") == ""


def test_processor_entrypoint_wrappers_bind_adapter_context(monkeypatch: Any, tmp_path: Path) -> None:
    class _Adapter:
        _db_path = tmp_path / "engagement.db"
        _engagement_id = 1001
        status_calls: list[tuple[Any, ...]]
        local_path_calls: list[tuple[Any, ...]]

        def __init__(self) -> None:
            self.status_calls = []
            self.local_path_calls = []

        def _run_ordered_local_batch(self, *_args: Any, **_kwargs: Any) -> list[Any]:
            return []

        def _local_artifact_record(self, _path: Path) -> None:
            return None

        def _local_artifact_metadata_matches(self, _existing: Any, _current: dict[str, Any]) -> bool:
            return False

        def _artifact_queue_dispatch_entry(self, _item: tuple[int, Any]) -> None:
            return None

        def _download_remote_artifacts(self, _requests: list[Any]) -> list[Any]:
            return []

        def _remote_download_reconciliation_entry(self, _item: tuple[int, Any, Any]) -> None:
            return None

        def _update_artifact_status(self, *_args: Any, **_kwargs: Any) -> None:
            return None

        def _set_artifact_local_path(self, *_args: Any, **_kwargs: Any) -> None:
            return None

        def _parse_local_artifacts(self, _items: list[Any]) -> list[Any]:
            return []

        def _persist_parsed_artifact(self, _ctx: Any, _parsed: Any) -> tuple[int, int, int, dict[str, Any]]:
            return 0, 0, 0, {}

    adapter = _Adapter()
    calls: list[tuple[Any, ...]] = []
    summary = ArtifactProcessingSummary(processed=4)

    def _ingest(
        db_path: Path,
        engagement_id: int,
        *,
        services: ArtifactProcessorRuntimeServices,
        search_roots: list[Path] | None,
    ) -> int:
        calls.append(("ingest", db_path, engagement_id, services, search_roots))
        return 3

    def _process(
        db_path: Path,
        engagement_id: int,
        *,
        services: ArtifactProcessorRuntimeServices,
        progress_label: str | None,
        progress_callback: Callable[[str, dict[str, object]], None] | None,
    ) -> ArtifactProcessingSummary:
        calls.append(("process", db_path, engagement_id, services, progress_label, progress_callback))
        return summary

    monkeypatch.setattr(runtime, "ingest_local_artifacts_with_runtime_services", _ingest)
    monkeypatch.setattr(runtime, "process_artifact_queue_with_runtime_services", _process)

    progress_callback = lambda _label, _payload: None

    assert ingest_local_artifacts_for_processor(adapter, search_roots=[tmp_path]) == 3
    assert (
        process_artifact_queue_for_processor(
            adapter,
            progress_label="1.K artifact queue",
            progress_callback=progress_callback,
        )
        is summary
    )

    assert calls[0][:3] == ("ingest", tmp_path / "engagement.db", 1001)
    assert calls[0][4] == [tmp_path]
    assert isinstance(calls[0][3], ArtifactProcessorRuntimeServices)
    assert calls[1][:3] == ("process", tmp_path / "engagement.db", 1001)
    assert isinstance(calls[1][3], ArtifactProcessorRuntimeServices)
    assert calls[1][4:] == ("1.K artifact queue", progress_callback)


def test_artifact_processor_callbacks_for_processor_binds_adapter_services(tmp_path: Path) -> None:
    class _Connection:
        def __init__(self) -> None:
            self.commits = 0

        def commit(self) -> None:
            self.commits += 1

    class _Adapter:
        _db_path = tmp_path / "engagement.db"
        _engagement_id = 1001
        status_calls: list[tuple[Any, ...]]
        local_path_calls: list[tuple[Any, ...]]

        def __init__(self) -> None:
            self.status_calls = []
            self.local_path_calls = []

        def _run_ordered_local_batch(
            self,
            items: list[Any],
            worker: Callable[[Any], Any],
            *,
            default_factory: Callable[[], Any],
        ) -> list[Any]:
            del default_factory
            return [worker(item) for item in items]

        def _local_artifact_record(self, _path: Path) -> None:
            return None

        def _local_artifact_metadata_matches(self, _existing: Any, _current: dict[str, Any]) -> bool:
            return False

        def _artifact_queue_dispatch_entry(self, item: tuple[int, Any]) -> tuple[str, tuple[int, Any]]:
            return "dispatch", item

        def _download_remote_artifacts(
            self,
            requests: list[Any],
            *,
            progress_label: str | None = None,
            progress_callback: Callable[[str, dict[str, object]], None] | None = None,
        ) -> list[Any]:
            del progress_label, progress_callback
            return [("download", requests)]

        def _remote_download_reconciliation_entry(self, item: tuple[int, Any, Any]) -> tuple[str, int]:
            return "reconcile", item[0]

        def _update_artifact_status(self, *_args: Any, **_kwargs: Any) -> str:
            self.status_calls.append((*_args, _kwargs))
            return "status"

        def _set_artifact_local_path(self, *_args: Any, **_kwargs: Any) -> str:
            self.local_path_calls.append((*_args, _kwargs))
            return "local"

        def _parse_local_artifacts(
            self,
            items: list[Any],
            *,
            progress_label: str | None = None,
            progress_callback: Callable[[str, dict[str, object]], None] | None = None,
        ) -> list[Any]:
            del progress_label, progress_callback
            return [("parse", items)]

        def _persist_parsed_artifact(self, _ctx: Any, _parsed: Any) -> tuple[int, int, int, dict[str, Any]]:
            return 1, 0, 0, {}

    con = _Connection()
    adapter = _Adapter()
    callbacks = artifact_processor_callbacks_for_processor(
        adapter,
        con,  # type: ignore[arg-type]
        progress_label="1.K artifact queue",
        progress_callback=lambda _label, _payload: None,
    )

    assert callbacks.dispatch_one((7, "row")) == ("dispatch", (7, "row"))
    assert callbacks.download_remote_artifacts(["request"]) == [("download", ["request"])]
    assert callbacks.reconcile_one((3, "request", "result")) == ("reconcile", 3)
    callbacks.update_remote_failure_status(7, "failed", "boom")
    callbacks.set_artifact_local_path(7, tmp_path / "artifact.txt", "text", {"size": 4})
    callbacks.update_skipped_status(8, "skipped", "not local", {"reason": "scope"})
    callbacks.update_parsed_status(9, "processed", "ok", None)
    assert callbacks.parse_local_artifacts(["item"]) == [("parse", ["item"])]
    assert callbacks.persist_parsed_artifact(None) == (1, 0, 0, {})
    callbacks.commit_after_acquisition()
    callbacks.commit_after_processing()
    assert con.commits == 2
    assert adapter.status_calls == [
        (con, 7, "failed", "boom", {}),
        (con, 8, "skipped", "not local", {"metadata": {"reason": "scope"}}),
        (con, 9, "processed", "ok", {"metadata": None}),
    ]
    assert adapter.local_path_calls == [
        (
            con,
            7,
            tmp_path / "artifact.txt",
            {"artifact_type": "text", "metadata_extra": {"size": 4}},
        )
    ]


def test_process_artifact_queue_with_runtime_services_opens_schema_and_closes(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    con = _FakeConnection()
    summary = ArtifactProcessingSummary(processed=2, failed=1)
    events: list[tuple[str, dict[str, object]]] = []
    calls: list[tuple[Any, ...]] = []

    monkeypatch.setattr(runtime, "direct_connect", lambda db_path: calls.append(("connect", db_path)) or con)
    monkeypatch.setattr(runtime, "apply_schema", lambda conn: calls.append(("schema", conn)))
    monkeypatch.setattr(runtime, "run_migrations", lambda conn: calls.append(("migrations", conn)))

    def _process_queue(
        conn: Any,
        engagement_id: int,
        *,
        callbacks: Any,
        commit_after_attempt_mark: Callable[[], None],
    ) -> Any:
        calls.append(("process", conn, engagement_id, callbacks))
        assert callbacks.download_remote_artifacts([]) == []
        commit_after_attempt_mark()
        return SimpleNamespace(summary=summary)

    monkeypatch.setattr(runtime, "process_artifact_queue_for_engagement", _process_queue)

    result = process_artifact_queue_with_runtime_services(
        tmp_path / "engagement.db",
        1001,
        services=_services(calls),
        progress_label="1.K artifact queue",
        progress_callback=lambda label, payload: events.append((label, dict(payload))),
    )

    assert result is summary
    assert con.row_factory is sqlite3.Row
    assert con.commits == 1
    assert con.closed is True
    assert calls[:3] == [
        ("connect", tmp_path / "engagement.db"),
        ("schema", con),
        ("migrations", con),
    ]
    assert any(call[0] == "process" for call in calls)


def test_ingest_local_artifacts_with_runtime_services_binds_services_and_closes(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    con = _FakeConnection()
    calls: list[tuple[Any, ...]] = []

    monkeypatch.setattr(runtime, "direct_connect", lambda db_path: calls.append(("connect", db_path)) or con)
    monkeypatch.setattr(runtime, "apply_schema", lambda conn: calls.append(("schema", conn)))
    monkeypatch.setattr(runtime, "run_migrations", lambda conn: calls.append(("migrations", conn)))

    def _ingest(
        conn: Any,
        engagement_id: int,
        *,
        search_roots: list[Path] | None,
        run_ordered_batch: Callable[..., list[Any]],
        record_local_artifact: Callable[[Path], tuple[str, str, dict[str, Any]] | None],
        local_artifact_metadata_matches: Callable[[Any, dict[str, Any]], bool],
        commit_after_ingest: Callable[[], None],
    ) -> int:
        calls.append(("ingest", conn, engagement_id, search_roots))
        assert run_ordered_batch(["x"], lambda item: item, default_factory=lambda: "fallback") == ["x"]
        assert record_local_artifact(tmp_path / "artifact.txt") == (
            "artifact",
            "local",
            {"path": (tmp_path / "artifact.txt").as_posix()},
        )
        assert local_artifact_metadata_matches({"a": 1}, {"a": 1}) is True
        commit_after_ingest()
        return 3

    monkeypatch.setattr(runtime, "ingest_local_artifacts_for_engagement", _ingest)

    result = ingest_local_artifacts_with_runtime_services(
        tmp_path / "engagement.db",
        1001,
        services=_services(calls),
        search_roots=[tmp_path],
    )

    assert result == 3
    assert con.commits == 1
    assert con.closed is True
    assert calls[:3] == [
        ("connect", tmp_path / "engagement.db"),
        ("schema", con),
        ("migrations", con),
    ]
    assert any(call[0] == "ingest" for call in calls)
