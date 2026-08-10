from __future__ import annotations

import json
import sqlite3
import subprocess
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import pytest

from forge.core.errors import ProviderUnavailableError
from forge.engagement_orchestrator import ArtifactDownloadResult, ArtifactQueueProcessor
from forge.phase4 import cloud_validate
from forge.phase4.mobile_config_parse import FirebaseExtractor
from forge.phase6.report_synthesizer import ReportSynthesizer


@pytest.mark.slow
def test_kill_chain_dashboard_detail_preserves_recursive_fallback_review_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_ENGAGEMENT_KEY", "FORGE-TEST-ENGAGEMENT-KEY")

    engagement_id = "1001"
    artifact_url = "https://acme.example/mobile/acme-keys.apk?download=1"
    portal_url = "https://artifact-mixed-portal.acme.example/mobile"
    owner_email = "artifact-mixed-owner@acme.example"
    fetched_urls: list[str] = []

    class _FakeResponse:
        def __init__(self, status_code: int, text: str) -> None:
            self.status_code = status_code
            self.text = text
            self.headers = {"content-type": "application/json"}

    class _CloudClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self) -> "_CloudClient":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def close(self) -> None:
            return None

        def get(self, url: str, **kwargs):  # noqa: ANN003
            del kwargs
            if url == "https://acme-smoke-firebase.firebaseio.com/.json":
                return _FakeResponse(200, '{"users":[{"email":"firebase-owner@acme.example"}]}')
            if url == "https://acmesmoke.supabase.co/auth/v1/settings":
                return _FakeResponse(200, '{"site_url":"https://portal.acme.io"}')
            if url == "https://acmesmoke.supabase.co/rest/v1/":
                return _FakeResponse(200, f'[{{"id":1,"email":"{owner_email}"}}]')
            return _FakeResponse(404, "missing")

    def _run_module(cmd, **kwargs):  # noqa: ANN001
        del kwargs
        argv = [str(item) for item in cmd]
        module_argv = [item for item in argv[argv.index("forge.cli") + 1 :] if item != "--no-tor"]

        def _flag(flag: str) -> str | None:
            if flag not in module_argv:
                return None
            index = module_argv.index(flag)
            return module_argv[index + 1] if index + 1 < len(module_argv) else None

        if module_argv[:2] == ["graph", "build"]:
            from forge.cli import graph_build  # noqa: PLC0415

            graph_build(
                engagement=str(_flag("--engagement") or ""),
                fmt=str(_flag("--format") or "all"),
                output_dir=_flag("--output-dir"),
                min_severity=str(_flag("--min-severity") or "LOW"),
                critical_path_only="--critical-path-only" in module_argv,
                snapshot="--snapshot" in module_argv,
                max_nodes=int(_flag("--max-nodes") or "150"),
            )
            return subprocess.CompletedProcess(argv, 0, stdout="graph built\n", stderr="")

        if module_argv[:2] == ["report", "generate"]:
            from forge.cli import report_generate  # noqa: PLC0415

            max_loops = _flag("--max-loops")
            report_generate(
                engagement=str(_flag("--engagement") or ""),
                output=_flag("--output"),
                yes=("--yes" in module_argv or "-y" in module_argv),
                provider=_flag("--provider") or "auto",
                max_loops=int(max_loops) if max_loops is not None else None,
            )
            return subprocess.CompletedProcess(argv, 0, stdout="report built\n", stderr="")

        return subprocess.CompletedProcess(argv, 0, stdout="ok\n", stderr="")

    def _html_batch(specs, *_args, progress_label=None, **_kwargs):  # noqa: ANN001
        fetched_urls.extend(spec.url for spec in specs)
        if progress_label == "1.D cloud+HTML fetch":
            return [
                '<a href="/careers">Careers</a>' if spec.url == "https://acme.example" else ""
                for spec in specs
            ]
        if progress_label == "1.D5 URL surface fetch":
            return [
                f'<a href="{artifact_url}">Download client</a>'
                if spec.url == "https://acme.example/careers"
                else ""
                for spec in specs
            ]
        return ["" for _ in specs]

    def _callable_batch(items, worker, *, max_workers, progress_label=None, progress_callback=None):  # noqa: ANN001
        del worker, max_workers
        if progress_callback and progress_label:
            progress_callback(
                progress_label, {"total": len(items), "completed": len(items), "failed": 0}
            )
        if progress_label and progress_label.endswith("DNS enrichment"):
            return [
                {"root_domain": str(item), "queried_hosts": [str(item)], "cname_targets": []}
                for item in items
            ]
        if progress_label and progress_label.endswith("whois/RDAP"):
            return [{"root_domain": str(item), "rdap": {}} for item in items]
        if progress_label and progress_label.endswith("Wayback CDX"):
            return [{"root_domain": str(item), "urls": []} for item in items]
        raise AssertionError(f"unexpected callable batch label: {progress_label}")

    def _download_artifact(_self, request):  # noqa: ANN001
        cache_dir = tmp_path / "remote-artifacts"
        cache_dir.mkdir(parents=True, exist_ok=True)
        apk_path = cache_dir / "acme-keys.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr(
                "google-services.json",
                """
                {
                  "project_info": {
                    "project_id": "acme-smoke-firebase",
                    "firebase_url": "https://acme-smoke-firebase.firebaseio.com"
                  }
                }
                """.strip(),
            )
            zf.writestr(
                "assets/runtime.env",
                f"""
                SUPABASE_URL=https://acmesmoke.supabase.co
                SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFjbWVzbW9rZSIsInJvbGUiOiJhbm9uIn0.signature
                CONTACT_EMAIL={owner_email}
                PORTAL_URL={portal_url}
                AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
                AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
                SLACK_BOT_TOKEN=xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx
                MAILCHIMP_API_KEY=1234567890abcdef1234567890abcdef-us1
                AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=smokeblobacct;AccountKey={"A" * 86}==
                """.strip(),
            )
        assert request.source_url == artifact_url
        return ArtifactDownloadResult(
            artifact_id=request.artifact_id,
            source_url=request.source_url,
            artifact_type=request.artifact_type,
            path=apk_path,
            metadata_extra={"content_type": "application/vnd.android.package-archive"},
        )

    from forge.opsec.crypto import decrypt_string  # noqa: PLC0415
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        AwsKeyValidator,
        AzureStorageConnectionStringValidator,
        MailchimpKeyValidator,
        SlackTokenValidator,
        ValidationResult,
        ValidationState,
    )

    def _decrypt(value: str | None) -> str | None:
        if not value:
            return None
        try:
            return decrypt_string(str(value))
        except Exception:  # noqa: BLE001
            return str(value).strip() or None

    monkeypatch.setattr(subprocess, "run", _run_module)
    monkeypatch.setattr("forge.cli._run_html_fetch_batch", _html_batch)
    monkeypatch.setattr("forge.cli._run_callable_batch", _callable_batch)
    monkeypatch.setattr(
        ArtifactQueueProcessor, "_download_remote_artifact_request", _download_artifact
    )
    monkeypatch.setattr(cloud_validate.httpx, "Client", _CloudClient)
    monkeypatch.setattr(FirebaseExtractor, "_encrypt", lambda _self, raw_key: raw_key)
    monkeypatch.setattr(cloud_validate, "_decrypt_secret", _decrypt)
    monkeypatch.setattr(
        AwsKeyValidator,
        "validate",
        lambda self, key, secret=None, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="AWS AccountId: 742931608514",
        ),
    )
    monkeypatch.setattr(
        SlackTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Slack auth ok: actor_id=U7A3C9K2 team_id=T9B2D6F4",
        ),
    )
    monkeypatch.setattr(
        MailchimpKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Mailchimp ping ok: dc=us1 health=Everything's Chimpy!",
        ),
    )
    monkeypatch.setattr(
        AzureStorageConnectionStringValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Azure blob list accessible: account=smokeblobacct containers=1",
        ),
    )
    monkeypatch.setattr(ReportSynthesizer, "_ensure_provider_loaded", lambda self: None)
    monkeypatch.setattr(
        ReportSynthesizer,
        "_infer",
        lambda self, _prompt: (_ for _ in ()).throw(ProviderUnavailableError("rate limit")),
    )

    from forge.cli import kill_chain  # noqa: PLC0415

    scope_manifest = json.dumps(
        {
            "roe_id": "ROE-SMOKE-2026-07",
            "domains": [
                "acme.example",
                "acme-smoke-firebase.firebaseio.com",
                "acmesmoke.supabase.co",
            ],
            "urls": [
                "https://acme-smoke-firebase.firebaseio.com",
                "https://acmesmoke.supabase.co",
            ],
            "exact_seeds": [owner_email],
        }
    )
    kill_chain(
        seed="acme.example",
        related_seed=[],
        engagement=engagement_id,
        max_iter=2,
        tor=False,
        dry_run=False,
        attack_mode=False,
        roe_id="ROE-SMOKE-2026-07",
        scope_manifest=scope_manifest,
        skip_cloud=False,
        skip_keyscan=True,
        parallel_fanout=2,
        report_provider="auto",
        report_max_loops=0,
    )

    reports_dir = tmp_path / "reports"
    overview_path = reports_dir / "dashboard" / "data" / "engagements.json"
    assert overview_path.is_file()
    overview = json.loads(overview_path.read_text(encoding="utf-8"))
    overview_item = next(item for item in overview["items"] if item["id"] == engagement_id)
    detail_path = reports_dir / "dashboard" / overview_item["detail_data"]
    assert detail_path.is_file()
    detail = json.loads(detail_path.read_text(encoding="utf-8"))

    assert "https://acme.example" in fetched_urls
    assert "https://acme.example/careers" in fetched_urls
    assert owner_email in detail["seeds"]
    assert artifact_url.split("?", 1)[0] in json.dumps(detail["seeds"])
    assert portal_url in detail["seeds"]

    report_summary = detail["report_summary"]
    assert report_summary["provider"] == "template"
    assert report_summary["requested_provider"] == "auto"
    assert report_summary["render_backend"] == "template"
    assert report_summary["fallback_reason"] == "rate limit"
    assert str(report_summary["findings_checksum"]).startswith("sha256:")

    run_summary = detail["run_summary"]
    assert run_summary["roe_id"] == "ROE-SMOKE-2026-07"
    policy = run_summary["metadata"]["live_execution_policy"]
    assert policy["scope_manifest_required"] is True
    assert policy["scope_manifest_present"] is True
    detail_json = json.dumps(detail, sort_keys=True)
    assert scope_manifest not in detail_json
    assert "exact_seeds" not in detail_json

    validation_rows = {
        (row["Type"], row["Method"]): row for row in detail["sections"]["cloud_validation_results"]
    }
    assert validation_rows[("firebase", "firebase_database_shallow_read")]["Status"] == "VALIDATED"
    assert validation_rows[("supabase", "supabase_rest_root")]["Status"] == "VALIDATED"
    assert validation_rows[("aws", "aws_sts_get_caller_identity")]["Status"] == "VALIDATED"
    assert validation_rows[("slack", "slack_auth_test")]["Status"] == "VALIDATED"
    assert (
        validation_rows[("azure", "azure_blob_list_containers_shared_key")]["Status"] == "VALIDATED"
    )
    assert validation_rows[("mailchimp", "mailchimp_ping_api")]["Status"] == "UNVERIFIED"
    assert "Chimpy" in validation_rows[("mailchimp", "mailchimp_ping_api")]["Notes"]

    key_rows = detail["sections"]["key_scanner_findings"]
    assert {
        (row["Service"], row["Validation Status"], row["Validation Method"]) for row in key_rows
    } >= {
        ("aws", "VALIDATED", "aws_sts_get_caller_identity"),
        ("slack", "VALIDATED", "slack_auth_test"),
    }
    key_json = json.dumps(key_rows)
    assert "AWS_SECRET_ACCESS_KEY" not in key_json
    assert "wJalrXUtn" not in key_json

    graph_nodes = detail["graph_payload"]["nodes"]
    assert any(
        node.get("source_table") == "vulnerability_findings"
        and (node.get("metadata") or {}).get("validation_status") == "VALIDATED"
        for node in graph_nodes
    )
    assert any(
        node.get("source_table") == "cloud_assets"
        and (node.get("metadata") or {}).get("validation_status") == "UNVERIFIED"
        and (node.get("metadata") or {}).get("validation_method") == "mailchimp_ping_api"
        for node in graph_nodes
    )

    db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
    with sqlite3.connect(db_path) as con:
        assert con.execute("SELECT COUNT(*) FROM engagement_seeds").fetchone()[0] >= 4
