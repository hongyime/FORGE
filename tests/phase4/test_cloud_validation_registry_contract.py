from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.phase4 import cloud_validate


_TERMINAL_SAFE_STATUSES = {
    "VALIDATED",
    "ACCESSIBLE_BUT_NO_DATA",
    "UNVERIFIED",
    "DEAD",
    "HONEYPOT_SUSPECTED",
    "UNSUPPORTED",
}


# Audited from engagement_orchestrator artifact cloud asset emission paths and
# URI families produced by the artifact helper modules they consume.
_ARTIFACT_EMITTED_CLOUD_ASSET_TYPES = (
    "amplify",
    "ad_publisher_account",
    "ad_seller_account",
    "ai_plugin_manifest",
    "appveyor_pipeline",
    "argo_application",
    "argo_applicationset",
    "argo_clusterworkflowtemplate",
    "argo_cronworkflow",
    "argo_workflow",
    "argo_workflowtemplate",
    "aws_appsync_api",
    "aws_cognito_app_client",
    "aws_cognito_identity_pool",
    "aws_cognito_user_pool",
    "aws_ecs_task_definition",
    "aws_efs_access_point",
    "aws_iam_role",
    "aws_kms",
    "aws_kms_key",
    "aws_lambda_function",
    "aws_lambda_layer",
    "aws_parameterstore",
    "aws_pinpoint_app",
    "aws_s3",
    "aws_secretsmanager",
    "aws_sns_topic",
    "aws_sqs_queue",
    "azure_blob",
    "azure_key_vault",
    "azure_pipeline",
    "azure_static_web_app",
    "bitbucket_pipeline",
    "buildkite_pipeline",
    "circleci_pipeline",
    "cloudflare_d1",
    "cloudflare_kv",
    "cloudflare_pages",
    "cloudflare_r2",
    "cloudflare_worker",
    "cluster_secret_store",
    "crossplane_composition",
    "crossplane_providerconfig",
    "crossplane_resource",
    "crossplane_xrd",
    "do_spaces",
    "drone_pipeline",
    "external_secret",
    "external_secret_store",
    "firebase",
    "fly",
    "flux_bucket",
    "flux_gitrepository",
    "flux_helmrepository",
    "flux_kustomization",
    "flux_ocirepository",
    "gcp_appspot",
    "gcp_cloud_run",
    "gcp_cloudfunctions",
    "gcp_kms",
    "gcp_secretmanager",
    "github_action",
    "github_pages",
    "github_workflow",
    "gitlab_pages",
    "gitlab_pipeline",
    "hashicorp_vault",
    "heroku",
    "mobile_android_package",
    "mobile_ios_app",
    "mobile_ios_app_store_id",
    "netlify",
    "railway",
    "render",
    "sealed_secret",
    "secret_provider_class",
    "supabase",
    "tekton_pipeline",
    "tekton_pipelinerun",
    "tekton_task",
    "tekton_taskrun",
    "vercel",
    "woodpecker_pipeline",
)


class _ProviderCallsForbidden:
    calls: list[str] = []

    def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
        del args, kwargs
        self.calls.append("__init__")

    def __enter__(self) -> "_ProviderCallsForbidden":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> None:  # noqa: ANN003
        del kwargs
        self.calls.append(f"GET {url}")
        raise AssertionError("registry contract test must not make provider calls")

    def head(self, url: str, **kwargs) -> None:  # noqa: ANN003
        del kwargs
        self.calls.append(f"HEAD {url}")
        raise AssertionError("registry contract test must not make provider calls")


def _bootstrap_db(db_path: Path) -> None:
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
            """
        )
        con.commit()
    finally:
        con.close()


def _asset_identifier(asset_type: str) -> str:
    return f"{asset_type}-contract"


def _stub_registered_validators(monkeypatch) -> set[str]:  # noqa: ANN001
    registry = cloud_validate.CloudValidatorRegistry()

    def _stub_validate(
        self: cloud_validate.BaseCloudValidator,
        identifier: str,
        secret: str | None = None,
    ) -> cloud_validate.CloudValidationResult:
        del secret
        return cloud_validate.CloudValidationResult(
            asset_type=str(self.asset_type),
            identifier=str(identifier or "").strip(),
            validation_status="ACCESSIBLE_BUT_NO_DATA",
            validation_method="registry_contract_stub",
            notes="Existing deterministic validator stubbed for offline contract coverage.",
        )

    for validator_class in {type(validator) for validator in registry._validators.values()}:  # noqa: SLF001
        monkeypatch.setattr(validator_class, "validate", _stub_validate)
    return set(registry._validators)  # noqa: SLF001


def _assert_terminal_contract(
    summary: dict[str, object],
    *,
    expected_unsupported_types: set[str],
) -> None:
    assert summary["status"] == "success"
    assert summary["attempted"] == len(_ARTIFACT_EMITTED_CLOUD_ASSET_TYPES)
    assert summary["succeeded"] == len(_ARTIFACT_EMITTED_CLOUD_ASSET_TYPES)
    assert summary["failed"] == 0

    results_by_asset_type = {
        str(item["asset_type"]): item
        for item in summary["results"]  # type: ignore[index]
    }
    assert set(results_by_asset_type) == set(_ARTIFACT_EMITTED_CLOUD_ASSET_TYPES)
    assert {
        asset_type
        for asset_type, item in results_by_asset_type.items()
        if str(item["validation_status"]) == "UNSUPPORTED"
    } == expected_unsupported_types
    assert all(
        str(item["validation_status"]) in _TERMINAL_SAFE_STATUSES
        for item in results_by_asset_type.values()
    )
    assert "UNVALIDATED" not in dict(summary["status_counts"])  # type: ignore[arg-type]


def test_every_artifact_cloud_asset_type_reaches_terminal_state(tmp_path: Path, monkeypatch) -> None:
    supported_types = _stub_registered_validators(monkeypatch)
    expected_unsupported_types = set(_ARTIFACT_EMITTED_CLOUD_ASSET_TYPES) - supported_types
    assert expected_unsupported_types

    _ProviderCallsForbidden.calls.clear()
    monkeypatch.setattr(cloud_validate.httpx, "Client", _ProviderCallsForbidden)

    batch_db_path = tmp_path / "batch.db"
    _bootstrap_db(batch_db_path)
    batch_summary = cloud_validate.run_cloud_asset_validate_batch(
        1001,
        [
            (asset_type, _asset_identifier(asset_type))
            for asset_type in _ARTIFACT_EMITTED_CLOUD_ASSET_TYPES
        ],
        batch_db_path,
        max_workers=4,
    )
    _assert_terminal_contract(
        batch_summary,
        expected_unsupported_types=expected_unsupported_types,
    )

    sweep_db_path = tmp_path / "sweep.db"
    _bootstrap_db(sweep_db_path)
    con = sqlite3.connect(sweep_db_path)
    try:
        con.executemany(
            """
            INSERT INTO cloud_assets (engagement_id, asset_type, identifier, source)
            VALUES (?, ?, ?, ?)
            """,
            [
                (1001, asset_type, _asset_identifier(asset_type), "artifact_contract")
                for asset_type in _ARTIFACT_EMITTED_CLOUD_ASSET_TYPES
            ],
        )
        con.commit()
    finally:
        con.close()

    sweep_summary = cloud_validate.sweep_pending_cloud_asset_validations(
        1001,
        sweep_db_path,
        limit=len(_ARTIFACT_EMITTED_CLOUD_ASSET_TYPES),
        max_workers=4,
    )
    _assert_terminal_contract(
        sweep_summary,
        expected_unsupported_types=expected_unsupported_types,
    )

    con = sqlite3.connect(sweep_db_path)
    try:
        persisted_statuses = dict(
            con.execute(
                """
                SELECT asset_type, validation_status
                FROM cloud_validation_results
                WHERE engagement_id=1001
                """
            ).fetchall()
        )
    finally:
        con.close()

    assert set(persisted_statuses) == set(_ARTIFACT_EMITTED_CLOUD_ASSET_TYPES)
    assert set(persisted_statuses.values()) <= _TERMINAL_SAFE_STATUSES
    assert {
        asset_type
        for asset_type, status in persisted_statuses.items()
        if status == "UNSUPPORTED"
    } == expected_unsupported_types
    assert _ProviderCallsForbidden.calls == []
