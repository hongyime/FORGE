from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

from forge.core.errors import ProviderUnavailableError
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.deterministic_findings import DeterministicFindingEngine
from forge.engagement_orchestrator import ArtifactQueueProcessor, EngagementSynthesisEngine
from forge.phase4 import cloud_validate
from forge.phase6.report_synthesizer import ReportSynthesizer
from forge.utils.intel.social_scraper import _parse_epieos_response


def _bootstrap_db(db_path: Path) -> None:
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Example', '["acme.example","https://downloads.acme.example/app.apk"]',
                    'ACTIVE', 'delta-one')
            """
        )
        con.commit()
    finally:
        con.close()


def _ensure_social_profiles_table(con: sqlite3.Connection) -> None:
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS social_profiles (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'epieos',
            profile_data TEXT,
            queried_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(engagement_id, email, source)
        )
        """
    )


class _FakeResponse:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = {"content-type": "application/json"}


class _SupabaseRestAccessClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_SupabaseRestAccessClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "auth/v1/settings" in url:
            return _FakeResponse(
                200,
                (
                    '{"site_url":"https://portal.acme.io","external_email_enabled":true,'
                    '"mailer_autoconfirm":false}'
                ),
            )
        return _FakeResponse(
            200,
            '[{"id":1,"email":"ops@acme.io"}]',
        )


def test_end_to_end_engagement_pipeline_generates_template_report(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    _bootstrap_db(db_path)

    apk_path = artifact_root / "acme-app.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr(
            "google-services.json",
            """
            {
              "project_info": {
                "project_id": "acme-firebase-prod",
                "firebase_url": "https://acme-firebase-prod.firebaseio.com"
              },
              "client": [
                {
                  "api_key": [
                    { "current_key": "AIzaSyDUMMYKEY1234567890" }
                  ]
                }
              ]
            }
            """.strip(),
        )
        zf.writestr(
            "assets/supabase-config.js",
            """
            export const SUPABASE_URL = "https://acmeworkspace.supabase.co";
            export const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.signature";
            CONTACT_EMAIL=security@acme.example
            API_ENDPOINT=https://api.acme.example/v1/mobile
            """.strip(),
        )

    artifact_processor = ArtifactQueueProcessor(db_path, 1001)
    queued = artifact_processor.ingest_local_artifacts([artifact_root])
    artifact_summary = artifact_processor.process()
    synthesis_summary = EngagementSynthesisEngine(db_path, 1001, depth_limit=3).run()

    assert queued == 1
    assert artifact_summary.processed == 1
    assert artifact_summary.firebase_projects >= 1
    assert artifact_summary.supabase_configs >= 1
    assert artifact_summary.discovered_seeds >= 1
    assert "acme.example" in synthesis_summary.root_domains

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, evidence, notes)
            VALUES
                (1001, 'firebase', 'acme-firebase-prod', 'VALIDATED',
                 'firebase_database_shallow_read', 200, '{"users":1}', 'Live records observed')
            """
        )
        con.execute(
            """
            UPDATE key_scanner_findings
            SET validation_state='ACTIVE',
                validation_detail='VALIDATED:firebase_database_shallow_read'
            WHERE engagement_id=1001 AND service='firebase'
            """
        )
        con.commit()
    finally:
        con.close()

    finding_summary = DeterministicFindingEngine(db_path, 1001).run()
    assert finding_summary.active_findings >= 1
    assert finding_summary.severity_summary["HIGH"] >= 2

    synthesizer = ReportSynthesizer(
        db_path=db_path,
        output_dir=tmp_path,
        provider="template",
        assume_yes=True,
    )
    report_path = synthesizer.generate(engagement_id=1001)

    assert report_path.exists()
    assert report_path.with_suffix(".json").exists()
    assert report_path.with_suffix(".pdf").exists()

    report_text = report_path.read_text(encoding="utf-8")
    assert "Acme Example" in report_text
    assert "Executive Summary" in report_text
    assert "Risk Ratings" in report_text
    assert "Validated Firebase data exposure" in report_text
    assert "template mode, no LLM" in report_text
    assert "Data integrity checksum (structured input)" in report_text


def test_end_to_end_engagement_pipeline_falls_back_to_raw_export_when_report_family_write_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    _bootstrap_db(db_path)

    apk_path = artifact_root / "acme-app.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr(
            "google-services.json",
            """
            {
              "project_info": {
                "project_id": "acme-firebase-prod",
                "firebase_url": "https://acme-firebase-prod.firebaseio.com"
              }
            }
            """.strip(),
        )

    artifact_processor = ArtifactQueueProcessor(db_path, 1001)
    assert artifact_processor.ingest_local_artifacts([artifact_root]) == 1
    artifact_summary = artifact_processor.process()
    assert artifact_summary.processed == 1
    EngagementSynthesisEngine(db_path, 1001, depth_limit=3).run()

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, evidence, notes)
            VALUES
                (1001, 'firebase', 'acme-firebase-prod', 'VALIDATED',
                 'firebase_database_shallow_read', 200, '{"users":1}', 'Live records observed')
            """
        )
        con.execute(
            """
            UPDATE key_scanner_findings
            SET validation_state='ACTIVE',
                validation_detail='VALIDATED:firebase_database_shallow_read'
            WHERE engagement_id=1001 AND service='firebase'
            """
        )
        con.commit()
    finally:
        con.close()

    finding_summary = DeterministicFindingEngine(db_path, 1001).run()
    assert finding_summary.active_findings >= 1

    synthesizer = ReportSynthesizer(
        db_path=db_path,
        output_dir=tmp_path,
        provider="template",
        assume_yes=True,
    )
    monkeypatch.setattr(
        synthesizer,
        "_write_companion_exports",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )

    report_path = synthesizer.generate(engagement_id=1001)
    csv_path = report_path.with_suffix(".csv")

    assert report_path.suffix == ".json"
    assert report_path.exists()
    assert csv_path.exists()

    payload = json.loads(report_path.read_text(encoding="utf-8"))
    csv_text = csv_path.read_text(encoding="utf-8")

    assert payload["provider"] == "raw_export"
    assert payload["requested_provider"] == "template"
    assert payload["upstream_provider"] == "template"
    assert payload["format"] == "raw_export"
    assert "disk full" in str(payload["fallback_reason"] or "")
    assert "disk full" in payload["report_write_error"]
    assert payload["context"]["engagement_name"] == "Acme Example"
    assert payload["context"]["overall_risk"] == "HIGH"
    assert "Validated Firebase data exposure" in csv_text


def test_end_to_end_engagement_pipeline_auto_provider_failure_exports_actual_template_backend(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    _bootstrap_db(db_path)

    apk_path = artifact_root / "acme-app.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr(
            "google-services.json",
            """
            {
              "project_info": {
                "project_id": "acme-firebase-prod",
                "firebase_url": "https://acme-firebase-prod.firebaseio.com"
              }
            }
            """.strip(),
        )

    artifact_processor = ArtifactQueueProcessor(db_path, 1001)
    assert artifact_processor.ingest_local_artifacts([artifact_root]) == 1
    artifact_summary = artifact_processor.process()
    assert artifact_summary.processed == 1
    EngagementSynthesisEngine(db_path, 1001, depth_limit=3).run()

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, evidence, notes)
            VALUES
                (1001, 'firebase', 'acme-firebase-prod', 'VALIDATED',
                 'firebase_database_shallow_read', 200, '{"users":1}', 'Live records observed')
            """
        )
        con.execute(
            """
            UPDATE key_scanner_findings
            SET validation_state='ACTIVE',
                validation_detail='VALIDATED:firebase_database_shallow_read'
            WHERE engagement_id=1001 AND service='firebase'
            """
        )
        con.commit()
    finally:
        con.close()

    finding_summary = DeterministicFindingEngine(db_path, 1001).run()
    assert finding_summary.active_findings >= 1

    con = sqlite3.connect(db_path)
    try:
        findings = con.execute(
            """
            SELECT title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchall()
        assert ("Validated Firebase data exposure",) in findings
    finally:
        con.close()

    synthesizer = ReportSynthesizer(
        db_path=db_path,
        output_dir=tmp_path,
        provider="auto",
        assume_yes=True,
    )
    monkeypatch.setattr(synthesizer, "_ensure_provider_loaded", lambda: None)
    monkeypatch.setattr(
        synthesizer,
        "_infer",
        lambda _prompt: (_ for _ in ()).throw(ProviderUnavailableError("quota exceeded")),
    )

    report_path = synthesizer.generate(engagement_id=1001)
    json_payload = report_path.with_suffix(".json").read_text(encoding="utf-8")

    assert "LLM fallback engaged: quota exceeded" in report_path.read_text(encoding="utf-8")
    assert '"provider": "template"' in json_payload
    assert '"requested_provider": "auto"' in json_payload
    assert '"fallback_reason": "quota exceeded"' in json_payload


def test_end_to_end_engagement_pipeline_auto_without_cloud_uses_local_llama(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    _bootstrap_db(db_path)

    class _FakeLlama:
        def create_chat_completion(self, **kwargs):  # noqa: ANN003
            del kwargs
            return {
                "choices": [
                    {
                        "message": {
                            "content": (
                                "## 1. Executive Summary\n\n"
                                "The overall risk is HIGH. "
                                + " ".join(["Professional assessment finding."] * 15)
                                + "\n\n## 2. Engagement Scope & Methodology\n\n"
                                + " ".join(["Professional assessment finding."] * 15)
                                + "\n\n## 3. Reconnaissance Findings\n\n"
                                + " ".join(["Professional assessment finding."] * 15)
                                + "\n\n## 4. OSINT & Credential Intelligence\n\n"
                                + " ".join(["Professional assessment finding."] * 15)
                                + "\n\n## 5. Vulnerability & Exploit Correlation\n\n"
                                + " ".join(["Professional assessment finding."] * 15)
                                + "\n\n## 6. Post-Exploitation Activities\n\n"
                                + " ".join(["Professional assessment finding."] * 15)
                                + "\n\n## 7. Risk Ratings & Remediation Recommendations\n\n"
                                + " ".join(["Professional assessment finding."] * 15)
                            )
                        }
                    }
                ]
            }

    apk_path = artifact_root / "acme-app.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr(
            "google-services.json",
            """
            {
              "project_info": {
                "project_id": "acme-firebase-prod",
                "firebase_url": "https://acme-firebase-prod.firebaseio.com"
              }
            }
            """.strip(),
        )

    artifact_processor = ArtifactQueueProcessor(db_path, 1001)
    assert artifact_processor.ingest_local_artifacts([artifact_root]) == 1
    artifact_summary = artifact_processor.process()
    assert artifact_summary.processed == 1
    EngagementSynthesisEngine(db_path, 1001, depth_limit=3).run()

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, evidence, notes)
            VALUES
                (1001, 'firebase', 'acme-firebase-prod', 'VALIDATED',
                 'firebase_database_shallow_read', 200, '{"users":1}', 'Live records observed')
            """
        )
        con.execute(
            """
            UPDATE key_scanner_findings
            SET validation_state='ACTIVE',
                validation_detail='VALIDATED:firebase_database_shallow_read'
            WHERE engagement_id=1001 AND service='firebase'
            """
        )
        con.commit()
    finally:
        con.close()

    DeterministicFindingEngine(db_path, 1001).run()

    synthesizer = ReportSynthesizer(
        db_path=db_path,
        output_dir=tmp_path,
        provider="auto",
        assume_yes=True,
    )

    def _fake_ensure_provider_loaded() -> None:
        raise ValueError("no configured cloud providers detected")

    def _fake_ensure_model_loaded(*, allow_auto_local: bool = False) -> None:
        del allow_auto_local
        synthesizer._llm = _FakeLlama()

    monkeypatch.setattr(synthesizer, "_ensure_provider_loaded", _fake_ensure_provider_loaded)
    monkeypatch.setattr(synthesizer, "_ensure_model_loaded", _fake_ensure_model_loaded)

    report_path = synthesizer.generate(engagement_id=1001)
    report_text = report_path.read_text(encoding="utf-8")
    json_payload = report_path.with_suffix(".json").read_text(encoding="utf-8")

    assert "template mode, no LLM" not in report_text
    assert "## 1. Executive Summary" in report_text
    assert '"provider": "llama_cpp"' in json_payload
    assert '"requested_provider": "auto"' in json_payload
    assert '"fallback_reason": "no configured cloud providers detected"' in json_payload


def test_end_to_end_engagement_pipeline_validates_key_only_supabase_and_falls_back_to_template(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    _bootstrap_db(db_path)

    supabase_anon_jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFjbWUtd29ya3NwYWNlIiwicm9sZSI6ImFub24ifQ."
        "signature999"
    )
    (artifact_root / "mobile-config.js").write_text(
        f"""
        export const SUPABASE_ANON_KEY = "{supabase_anon_jwt}";
        export const OWNER_EMAIL = "supabase-owner@acme.example";
        export const MOBILE_PORTAL = "https://portal.acme.example/mobile";
        """.strip(),
        encoding="utf-8",
    )

    artifact_processor = ArtifactQueueProcessor(db_path, 1001)
    queued = artifact_processor.ingest_local_artifacts([artifact_root])
    artifact_summary = artifact_processor.process()
    synthesis_summary = EngagementSynthesisEngine(db_path, 1001, depth_limit=3).run()

    assert queued == 1
    assert artifact_summary.processed == 1
    assert artifact_summary.supabase_configs >= 1
    assert artifact_summary.discovered_seeds >= 3
    assert "acme.example" in synthesis_summary.root_domains

    con = sqlite3.connect(db_path)
    try:
        key_row = con.execute(
            """
            SELECT id, domain, key_enc
            FROM key_scanner_findings
            WHERE engagement_id=1001 AND service='supabase'
            """
        ).fetchone()
        assert key_row is not None
        assert key_row[1] == "acme-workspace"
        assert str(key_row[2] or "").strip()

        con.execute(
            """
            UPDATE key_scanner_findings
            SET domain='',
                source_url='',
                repo_name='mobile-config.js',
                key_enc='ciphertext-placeholder',
                validation_state='UNCONFIRMED',
                validation_detail=''
            WHERE id=?
            """,
            (int(key_row[0]),),
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(cloud_validate, "_decrypt_secret", lambda _value: supabase_anon_jwt)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _SupabaseRestAccessClient)

    validation_summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert validation_summary["attempted"] == 1
    assert validation_summary["succeeded"] == 1
    assert validation_summary["status_counts"]["VALIDATED"] == 1

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001 AND asset_type='supabase'
            """
        ).fetchone()
        assert validation_row == (
            "supabase",
            "acme-workspace",
            "VALIDATED",
            "supabase_rest_root",
        )

        key_state = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE engagement_id=1001 AND service='supabase'
            """
        ).fetchone()
        assert key_state is not None
        assert key_state[0] == "ACTIVE"
        assert str(key_state[1] or "").startswith("VALIDATED:supabase_rest_root:")
    finally:
        con.close()

    finding_summary = DeterministicFindingEngine(db_path, 1001).run()
    assert finding_summary.active_findings == 2
    assert finding_summary.severity_summary["HIGH"] == 2

    con = sqlite3.connect(db_path)
    try:
        findings = con.execute(
            """
            SELECT vuln_type, severity, title, cloud_provider, resource_id
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY vuln_type, title
            """
        ).fetchall()
        assert (
            "DETERMINISTIC_CLOUD_EXPOSURE",
            "HIGH",
            "Validated Supabase data exposure",
            "supabase",
            "acme-workspace",
        ) in findings
        assert any(
            row[0] == "DETERMINISTIC_KEY_EXPOSURE"
            and row[2] == "Validated exposed supabase credential reference"
            for row in findings
        )
    finally:
        con.close()

    synthesizer = ReportSynthesizer(
        db_path=db_path,
        output_dir=tmp_path,
        provider="auto",
        assume_yes=True,
    )
    monkeypatch.setattr(synthesizer, "_ensure_provider_loaded", lambda: None)
    monkeypatch.setattr(
        synthesizer,
        "_infer",
        lambda _prompt: (_ for _ in ()).throw(ProviderUnavailableError("provider outage")),
    )

    report_path = synthesizer.generate(engagement_id=1001)
    report_text = report_path.read_text(encoding="utf-8")
    json_payload = report_path.with_suffix(".json").read_text(encoding="utf-8")

    assert "Validated Supabase data exposure" in report_text
    assert "Validated exposed supabase credential reference" in report_text
    assert "LLM fallback engaged: provider outage" in report_text
    assert '"provider": "template"' in json_payload
    assert '"requested_provider": "auto"' in json_payload
    assert '"fallback_reason": "provider outage"' in json_payload


def test_end_to_end_engagement_pipeline_validates_artifact_discovered_azure_connection_string(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    _bootstrap_db(db_path)

    azure_connection_string = (
        "DefaultEndpointsProtocol=https;"
        "AccountName=acmeartifactblob;"
        f"AccountKey={'A' * 86}=="
    )
    (artifact_root / "ops.env").write_text(
        f"""
        AZURE_STORAGE_CONNECTION_STRING="{azure_connection_string}"
        CONTACT_EMAIL=azure-owner@acme.example
        PORTAL_URL=https://portal.acme.example/storage
        """.strip(),
        encoding="utf-8",
    )

    artifact_processor = ArtifactQueueProcessor(db_path, 1001)
    queued = artifact_processor.ingest_local_artifacts([artifact_root])
    artifact_summary = artifact_processor.process()
    synthesis_summary = EngagementSynthesisEngine(db_path, 1001, depth_limit=3).run()

    assert queued == 1
    assert artifact_summary.processed == 1
    assert artifact_summary.discovered_seeds >= 2
    assert "acme.example" in synthesis_summary.root_domains

    con = sqlite3.connect(db_path)
    try:
        key_row = con.execute(
            """
            SELECT domain, key_enc
            FROM key_scanner_findings
            WHERE engagement_id=1001 AND service='azure' AND pattern_name='azure_storage_key'
            """
        ).fetchone()
        assert key_row is not None
        assert key_row[0] == "acmeartifactblob"
        assert str(key_row[1] or "").strip()
    finally:
        con.close()

    monkeypatch.setattr(cloud_validate, "_decrypt_secret", lambda _value: azure_connection_string)
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        AzureStorageConnectionStringValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        AzureStorageConnectionStringValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Azure blob list accessible: account=acmeartifactblob containers=1",
        ),
    )

    validation_summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert validation_summary["attempted"] == 1
    assert validation_summary["succeeded"] == 1
    assert validation_summary["status_counts"]["VALIDATED"] == 1

    finding_summary = DeterministicFindingEngine(db_path, 1001).run()
    assert finding_summary.active_findings == 1
    assert finding_summary.severity_summary["HIGH"] == 1

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "azure",
            "acmeartifactblob",
            "VALIDATED",
            "azure_blob_list_containers_shared_key",
        )

        finding_row = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert finding_row == (
            "DETERMINISTIC_KEY_EXPOSURE",
            "HIGH",
            "Validated exposed azure credential reference",
        )
    finally:
        con.close()

    synthesizer = ReportSynthesizer(
        db_path=db_path,
        output_dir=tmp_path,
        provider="template",
        assume_yes=True,
    )
    report_path = synthesizer.generate(engagement_id=1001)
    report_text = report_path.read_text(encoding="utf-8")

    assert "Validated exposed azure credential reference" in report_text
    assert "Acme Example" in report_text


def test_end_to_end_engagement_pipeline_processes_certificate_profile_artifacts_into_report(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    _bootstrap_db(db_path)

    (artifact_root / "gateway.pem").write_text(
        """
        -----BEGIN CERTIFICATE-----
        MIICFAKECERT
        -----END CERTIFICATE-----
        URI:https://acme-certs.vercel.app/bootstrap
        EMAIL:certops@acme.example
        BACKUP=gs://acme-cert-gcs/archive/root.pem
        """.strip(),
        encoding="utf-8",
    )
    (artifact_root / "deploy.key").write_text(
        """
        -----BEGIN PRIVATE KEY-----
        MIIEFAKEKEY
        -----END PRIVATE KEY-----
        FIREBASE=https://acme-keyvault.firebaseio.com
        SUPABASE_URL=https://certvault.supabase.co
        CONTACT=keyowner@acme.example
        ADMIN_URL=https://keyportal.acme.example/login
        """.strip(),
        encoding="utf-8",
    )
    (artifact_root / "device.mobileconfig").write_text(
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0">
          <dict>
            <key>PayloadDisplayName</key><string>Acme Device Profile</string>
            <key>PayloadDescription</key><string>https://mdm.acme.example/enroll</string>
            <key>PayloadContent</key><string>https://acmeportal.appspot.com/profile mdm@acme.example</string>
          </dict>
        </plist>
        """.strip(),
        encoding="utf-8",
    )

    artifact_processor = ArtifactQueueProcessor(db_path, 1001)
    queued = artifact_processor.ingest_local_artifacts([artifact_root])
    artifact_summary = artifact_processor.process()
    synthesis_summary = EngagementSynthesisEngine(db_path, 1001, depth_limit=3).run()

    assert queued == 3
    assert artifact_summary.processed == 3
    assert artifact_summary.discovered_seeds >= 8
    assert "acme.example" in synthesis_summary.root_domains

    con = sqlite3.connect(db_path)
    try:
        cloud_assets = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT asset_type, identifier
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert ("firebase", "acme-keyvault") in cloud_assets
        assert ("vercel", "acme-certs") in cloud_assets
        assert ("gcp_appspot", "acmeportal") in cloud_assets
        assert ("supabase", "certvault") in cloud_assets
        assert ("gcs", "acme-cert-gcs") in cloud_assets

        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, evidence, notes)
            VALUES
                (1001, 'firebase', 'acme-keyvault', 'VALIDATED',
                 'firebase_database_shallow_read', 200, '{"records":2}', 'Live records observed'),
                (1001, 'supabase', 'certvault', 'ACCESSIBLE_BUT_NO_DATA',
                 'supabase_settings', 200, '{"site_url":"https://portal.acme.example"}', 'Settings endpoint exposed metadata')
            """
        )
        con.commit()
    finally:
        con.close()

    finding_summary = DeterministicFindingEngine(db_path, 1001).run()
    assert finding_summary.active_findings >= 1
    assert finding_summary.severity_summary["HIGH"] >= 1

    synthesizer = ReportSynthesizer(
        db_path=db_path,
        output_dir=tmp_path,
        provider="template",
        assume_yes=True,
    )
    report_path = synthesizer.generate(engagement_id=1001)

    assert report_path.exists()
    report_text = report_path.read_text(encoding="utf-8")
    assert "Acme Example" in report_text
    assert "Validated Firebase data exposure" in report_text
    assert "Public Supabase project metadata observed" not in report_text
    assert "template mode, no LLM" in report_text


def test_end_to_end_engagement_pipeline_mixes_rtf_social_profile_and_template_fallback(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    _bootstrap_db(db_path)

    rtf_path = artifact_root / "engagement-intel.rtf"
    rtf_path.write_bytes(
        (
            rb"{\rtf1\ansi\deff0"
            rb"{\fonttbl{\f0 Arial;}}"
            rb"\viewkind4\uc1\pard\f0\fs20 "
            rb"Owner: rtf\'2downer\'40acme\'2eexample\par "
            rb"Portal: https://portal\'2eacme\'2eexample/console\par "
            rb"Profile: https://dev\'2eto/rtfblue/latest-post\par "
            rb"Phone: \'2b1 555 333 1111\par "
            rb"Cloud: https://rtf\'2dfirebase\'2dprod\'2efirebaseio\'2ecom\par"
            rb"}"
        )
    )

    con = sqlite3.connect(db_path)
    try:
        _ensure_social_profiles_table(con)
        con.execute(
            """
            INSERT INTO emails (engagement_id, email, domain, source)
            VALUES (?, ?, ?, ?)
            """,
            (1001, "security@acme.example", "acme.example", "seed_fixture"),
        )
        con.execute(
            """
            INSERT INTO social_profiles (engagement_id, email, source, profile_data)
            VALUES (?, ?, ?, ?)
            """,
            (
                1001,
                "security@acme.example",
                "epieos",
                json.dumps(
                    {
                        "source": "epieos",
                        "platform": "threads",
                        "profile_url": "https://www.threads.net/@threadblue",
                        "display_name": "Alice Example",
                        "bio_links": [
                            {"value": "mailto:linked.ops@acme.example?subject=intro"},
                            {"value": "tel:+1 (555) 765-0001"},
                        ],
                        "urls": [
                            {"value": "https://wa.me/15557650002"},
                            {"value": "https://ops.acme.example/team"},
                        ],
                    }
                ),
            ),
        )
        con.execute(
            """
            INSERT INTO social_profiles (engagement_id, email, source, profile_data)
            VALUES (?, ?, ?, ?)
            """,
            (
                1001,
                "security@acme.example",
                "epieos:explicit_urls",
                json.dumps(
                    _parse_epieos_response(
                        {
                            "email": "security@acme.example",
                            "medium": {
                                "url": "https://bluewriter.medium.com/signal-boost",
                                "name": "Blue Writer",
                            },
                            "bluesky": {
                                "url": "https://bsky.app/profile/ops.blue",
                                "name": "Ops Blue",
                            },
                        }
                    )
                ),
            ),
        )
        con.commit()
    finally:
        con.close()

    artifact_processor = ArtifactQueueProcessor(db_path, 1001)
    queued = artifact_processor.ingest_local_artifacts([artifact_root])
    artifact_summary = artifact_processor.process()
    synthesis_summary = EngagementSynthesisEngine(db_path, 1001, depth_limit=3).run()

    assert queued == 1
    assert artifact_summary.processed == 1
    assert artifact_summary.discovered_seeds >= 4
    assert synthesis_summary.seeds_inserted >= 6
    assert "acme.example" in synthesis_summary.root_domains
    assert "rtf-firebase-prod" not in synthesis_summary.root_domains

    con = sqlite3.connect(db_path)
    try:
        seeds = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT seed_value, seed_type
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert ("rtf-owner@acme.example", "email") in seeds
        assert ("linked.ops@acme.example", "email") in seeds
        assert ("+15553331111", "phone") in seeds
        assert ("+15557650001", "phone") in seeds
        assert ("+15557650002", "phone") in seeds
        assert ("https://portal.acme.example/console", "url") in seeds
        assert ("https://ops.acme.example/team", "url") in seeds
        assert ("https://bluewriter.medium.com/signal-boost", "url") in seeds
        assert ("https://bsky.app/profile/ops.blue", "url") in seeds
        assert ("rtfblue", "username") in seeds
        assert ("threadblue", "username") in seeds
        assert ("bluewriter", "username") in seeds
        assert ("ops.blue", "username") in seeds
        assert ("Alice Example", "name") in seeds
        assert ("Blue Writer", "name") in seeds
        assert ("Ops Blue", "name") in seeds

        relation_rows = {
            (str(row[0]), str(row[1]), str(row[2]))
            for row in con.execute(
                """
                SELECT src.seed_value, dst.seed_value, sr.relation_type
                FROM seed_relations sr
                JOIN engagement_seeds src ON src.id=sr.source_seed_id
                JOIN engagement_seeds dst ON dst.id=sr.target_seed_id
                WHERE sr.engagement_id=1001
                """
            ).fetchall()
        }
        assert ("https://dev.to/rtfblue/latest-post", "rtfblue", "derived_from") in relation_rows
        assert ("security@acme.example", "threadblue", "same_entity") in relation_rows
        assert ("security@acme.example", "bluewriter", "same_entity") in relation_rows
        assert ("security@acme.example", "ops.blue", "same_entity") in relation_rows
        assert ("security@acme.example", "linked.ops@acme.example", "same_entity") in relation_rows
        assert ("security@acme.example", "+15557650001", "same_entity") in relation_rows
        assert ("security@acme.example", "+15557650002", "same_entity") in relation_rows

        cloud_assets = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT asset_type, identifier
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert ("firebase", "rtf-firebase-prod") in cloud_assets

        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, evidence, notes)
            VALUES
                (1001, 'firebase', 'rtf-firebase-prod', 'VALIDATED',
                 'firebase_database_shallow_read', 200, '{"records":2}', 'Live records observed')
            """
        )
        con.commit()
    finally:
        con.close()

    finding_summary = DeterministicFindingEngine(db_path, 1001).run()
    assert finding_summary.active_findings >= 1
    assert finding_summary.severity_summary["HIGH"] >= 1

    synthesizer = ReportSynthesizer(
        db_path=db_path,
        output_dir=tmp_path,
        provider="auto",
        assume_yes=True,
    )
    monkeypatch.setattr(synthesizer, "_ensure_provider_loaded", lambda: None)
    monkeypatch.setattr(
        synthesizer,
        "_infer",
        lambda _prompt: (_ for _ in ()).throw(ProviderUnavailableError("rate limit")),
    )

    report_path = synthesizer.generate(engagement_id=1001)
    report_text = report_path.read_text(encoding="utf-8")
    json_payload = report_path.with_suffix(".json").read_text(encoding="utf-8")

    assert "Acme Example" in report_text
    assert "Executive Summary" in report_text
    assert "Validated Firebase data exposure" in report_text
    assert "LLM fallback engaged: rate limit" in report_text
    assert "Data integrity checksum (structured input)" in report_text
    assert '"provider": "template"' in json_payload
    assert '"requested_provider": "auto"' in json_payload
    assert '"fallback_reason": "rate limit"' in json_payload


def test_end_to_end_engagement_pipeline_mixes_key_validators_cloud_asset_and_template_fallback(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("FORGE_ENGAGEMENT_KEY", "FORGE-TEST-ENGAGEMENT-KEY")
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    _bootstrap_db(db_path)

    azure_connection_string = (
        "DefaultEndpointsProtocol=https;"
        "AccountName=comboartifactblob;"
        f"AccountKey={'A' * 86}=="
    )
    google_api_key = "AIza" + "G" * 35
    gitlab_pat = "glpat-" + "L" * 20
    (artifact_root / "operator-keys.env").write_text(
        (
            "CONTACT_EMAIL=mixed-owner@acme.example\n"
            "PORTAL_URL=https://keys.acme.example/portal\n"
            "FIREBASE_URL=https://combo-firebase-prod.firebaseio.com\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "SLACK_BOT_TOKEN=xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx\n"
            "MAILCHIMP_API_KEY=1234567890abcdef1234567890abcdef-us1\n"
            "SENDGRID_API_KEY=SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg\n"
            f"GITLAB_PAT={gitlab_pat}\n"
            f"GOOGLE_API_KEY={google_api_key}\n"
            f"AZURE_STORAGE_CONNECTION_STRING={azure_connection_string}\n"
        ),
        encoding="utf-8",
    )

    artifact_processor = ArtifactQueueProcessor(db_path, 1001)
    queued = artifact_processor.ingest_local_artifacts([artifact_root])
    artifact_summary = artifact_processor.process()
    synthesis_summary = EngagementSynthesisEngine(db_path, 1001, depth_limit=3).run()

    assert queued == 1
    assert artifact_summary.processed == 1
    assert artifact_summary.discovered_seeds >= 3
    assert "acme.example" in synthesis_summary.root_domains

    con = sqlite3.connect(db_path)
    try:
        key_hits = {
            (str(row[0]), str(row[1]))
            for row in con.execute(
                """
                SELECT service, pattern_name
                FROM key_scanner_findings
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert ("aws", "aws_access_key_id") in key_hits
        assert ("aws", "aws_secret_access_key") in key_hits
        assert ("slack", "slack_bot_token") in key_hits
        assert ("mailchimp", "mailchimp_api_key") in key_hits
        assert ("sendgrid", "sendgrid_api_key") in key_hits
        assert ("gitlab", "gitlab_pat") in key_hits
        assert ("google", "google_api_key") in key_hits
        assert ("azure", "azure_storage_key") in key_hits

        cloud_assets = {
            (str(row[0]), str(row[1]))
            for row in con.execute(
                """
                SELECT asset_type, identifier
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert ("firebase", "combo-firebase-prod") in cloud_assets
    finally:
        con.close()

    class _FirebaseValidatedClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self) -> "_FirebaseValidatedClient":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
            del kwargs
            if url == "https://combo-firebase-prod.firebaseio.com/users.json":
                return _FakeResponse(200, '{"alice":{"email":"ops@acme.io"}}')
            if url == "https://combo-firebase-prod.firebaseio.com/.json":
                return _FakeResponse(200, '{"users":true}')
            return _FakeResponse(404, "not found")

    monkeypatch.setattr(cloud_validate.httpx, "Client", _FirebaseValidatedClient)
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        AwsKeyValidator,
        AzureStorageConnectionStringValidator,
        GitlabPatValidator,
        GoogleApiKeyValidator,
        MailchimpKeyValidator,
        SlackTokenValidator,
        ValidationResult,
        ValidationState,
    )

    def _fake_aws_validate(self, key, secret=None, proxy=None, **kwargs):  # noqa: ANN001, ARG001
        if key == "AKIAIOSFODNN7EXAMPLE" and secret == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY":
            return ValidationResult(
                state=ValidationState.ACTIVE,
                detail="AWS AccountId: 742931608514",
            )
        return ValidationResult(
            state=ValidationState.UNCONFIRMED,
            detail="AWS secret key not co-located",
        )

    monkeypatch.setattr(AwsKeyValidator, "validate", _fake_aws_validate)
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
        GitlabPatValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="GitLab user ok: user_id=42 username=delta-ops user_profile_present=true",
        ),
    )
    monkeypatch.setattr(
        GoogleApiKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=(
                "Google Generative Language models ok: models=2 "
                "sample=models/gemini-2.5-flash,models/text-embedding-004"
            ),
        ),
    )
    from forge.utils.intel.secret_finder import SendgridKeyValidator  # noqa: PLC0415

    monkeypatch.setattr(
        SendgridKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=(
                "SendGrid profile ok: proof=profile profile_hash=0123456789abcdef "
                "email_present=true"
            ),
        ),
    )
    monkeypatch.setattr(
        AzureStorageConnectionStringValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Azure blob list accessible: account=comboartifactblob containers=1",
        ),
    )

    cloud_result = cloud_validate.run_cloud_asset_validate(
        engagement_id=1001,
        asset_type="firebase",
        identifier="combo-firebase-prod",
        db_path=db_path,
    )
    assert cloud_result["status"] == "success"
    assert cloud_result["validation_status"] == "VALIDATED"
    assert cloud_result["validation_method"] == "firebase_database_node_read"

    validation_summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=4,
    )

    assert validation_summary["attempted"] == 8
    assert validation_summary["succeeded"] == 8
    assert validation_summary["status_counts"]["VALIDATED"] == 8

    con = sqlite3.connect(db_path)
    try:
        validation_rows = {
            (str(row[0]), str(row[1]), str(row[2]), str(row[3]))
            for row in con.execute(
                """
                SELECT asset_type, identifier, validation_status, validation_method
                FROM cloud_validation_results
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        validation_by_method = {
            (asset_type, method): (identifier, status)
            for asset_type, identifier, status, method in validation_rows
        }
        assert (
            "firebase",
            "combo-firebase-prod",
            "VALIDATED",
            "firebase_database_node_read",
        ) in validation_rows
        assert validation_by_method[("aws", "aws_sts_get_caller_identity")][1] == "VALIDATED"
        assert validation_by_method[("slack", "slack_auth_test")] == (
            "t9b2d6f4/u7a3c9k2",
            "VALIDATED",
        )
        assert validation_by_method[("mailchimp", "mailchimp_ping_api")] == ("us1", "VALIDATED")
        assert validation_by_method[("sendgrid", "sendgrid_profile_api")] == (
            "profile/0123456789abcdef",
            "VALIDATED",
        )
        assert validation_by_method[("gitlab", "gitlab_current_user_api")] == (
            "delta-ops",
            "VALIDATED",
        )
        assert validation_by_method[("google", "google_generative_language_models_list")] == (
            "generativelanguage/models",
            "VALIDATED",
        )
        assert validation_by_method[("azure", "azure_blob_list_containers_shared_key")] == (
            "comboartifactblob",
            "VALIDATED",
        )
    finally:
        con.close()

    finding_summary = DeterministicFindingEngine(db_path, 1001).run()
    assert finding_summary.active_findings >= 6
    assert finding_summary.severity_summary["HIGH"] >= 6

    con = sqlite3.connect(db_path)
    try:
        findings = {
            (str(row[0]), str(row[1]), str(row[2]))
            for row in con.execute(
                """
                SELECT vuln_type, severity, title
                FROM vulnerability_findings
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert (
            "DETERMINISTIC_CLOUD_EXPOSURE",
            "HIGH",
            "Validated Firebase data exposure",
        ) in findings
        assert (
            "DETERMINISTIC_KEY_EXPOSURE",
            "HIGH",
            "Validated exposed aws credential reference",
        ) in findings
        assert (
            "DETERMINISTIC_KEY_EXPOSURE",
            "HIGH",
            "Validated exposed slack credential reference",
        ) in findings
        assert (
            "DETERMINISTIC_KEY_EXPOSURE",
            "HIGH",
            "Validated exposed mailchimp credential reference",
        ) in findings
        assert (
            "DETERMINISTIC_KEY_EXPOSURE",
            "HIGH",
            "Validated exposed sendgrid credential reference",
        ) in findings
        assert (
            "DETERMINISTIC_KEY_EXPOSURE",
            "HIGH",
            "Validated exposed gitlab credential reference",
        ) in findings
        assert (
            "DETERMINISTIC_KEY_EXPOSURE",
            "HIGH",
            "Validated exposed google credential reference",
        ) in findings
        assert (
            "DETERMINISTIC_KEY_EXPOSURE",
            "HIGH",
            "Validated exposed azure credential reference",
        ) in findings
    finally:
        con.close()

    synthesizer = ReportSynthesizer(
        db_path=db_path,
        output_dir=tmp_path,
        provider="auto",
        assume_yes=True,
    )
    monkeypatch.setattr(synthesizer, "_ensure_provider_loaded", lambda: None)
    monkeypatch.setattr(
        synthesizer,
        "_infer",
        lambda _prompt: (_ for _ in ()).throw(ProviderUnavailableError("quota exceeded")),
    )

    report_path = synthesizer.generate(engagement_id=1001)
    report_text = report_path.read_text(encoding="utf-8")
    json_payload = report_path.with_suffix(".json").read_text(encoding="utf-8")

    assert report_path.exists()
    assert report_path.with_suffix(".json").exists()
    assert report_path.with_suffix(".pdf").exists()
    assert "Acme Example" in report_text
    assert "Validated Firebase data exposure" in report_text
    assert "Validated exposed aws credential reference" in report_text
    assert "Validated exposed slack credential reference" in report_text
    assert "Validated exposed mailchimp credential reference" in report_text
    assert "Validated exposed sendgrid credential reference" in report_text
    assert "Validated exposed gitlab credential reference" in report_text
    assert "Validated exposed google credential reference" in report_text
    assert "Validated exposed azure credential reference" in report_text
    assert "LLM fallback engaged: quota exceeded" in report_text
    assert "Data integrity checksum (structured input)" in report_text
    assert '"provider": "template"' in json_payload
    assert '"requested_provider": "auto"' in json_payload
    assert '"fallback_reason": "quota exceeded"' in json_payload
