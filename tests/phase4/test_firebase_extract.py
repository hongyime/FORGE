"""
tests/phase4/test_firebase_extract.py
Unit tests for mobile_config_parse.py (Module 4-F).

All tests are fully offline (zipfile fixture data, stdlib only).
No network calls at any point.
"""
from __future__ import annotations

import base64
import io
import json
import plistlib
import sqlite3
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from forge.cli import app
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.phase4.mobile_config_parse import FirebaseExtractor, FirebaseProject


# ══════════════════════════════════════════════════════════════════════════════
# APK fixture builder helpers
# ══════════════════════════════════════════════════════════════════════════════

def _make_apk(tmp_path: Path, google_services: dict | None = None,
              strings_xml: str | None = None) -> Path:
    apk = tmp_path / "test.apk"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        if google_services:
            zf.writestr("google-services.json", json.dumps(google_services))
        if strings_xml:
            zf.writestr("res/values/strings.xml", strings_xml)
    apk.write_bytes(buf.getvalue())
    return apk


def _make_ipa(tmp_path: Path, plist_data: dict | None = None,
              other_plist: str | None = None) -> Path:
    ipa = tmp_path / "test.ipa"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        if plist_data:
            plist_bytes = plistlib.dumps(plist_data)
            zf.writestr("Payload/MyApp.app/GoogleService-Info.plist", plist_bytes)
        if other_plist:
            zf.writestr("Payload/MyApp.app/Settings.plist", other_plist)
    ipa.write_bytes(buf.getvalue())
    return ipa


def _make_archive_style_android_bundle(
    tmp_path: Path,
    name: str,
    *,
    google_services: dict | None = None,
    supabase_text: str | None = None,
) -> Path:
    bundle = tmp_path / name
    base_apk = io.BytesIO()
    with zipfile.ZipFile(base_apk, "w") as zf:
        if google_services:
            zf.writestr("google-services.json", json.dumps(google_services))
        if supabase_text:
            zf.writestr("assets/supabase-config.js", supabase_text)
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("manifest.json", '{"name":"Bundle"}')
        zf.writestr("base.apk", base_apk.getvalue())
    bundle.write_bytes(outer.getvalue())
    return bundle


# ══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════════════════

_GOOGLE_SERVICES = {
    "project_info": {
        "project_id": "myapp-firebase-prod",
        "firebase_url": "https://myapp-firebase-prod-default-rtdb.firebaseio.com",
    },
    "client": [
        {
            "client_info": {"mobilesdk_app_id": "1:123456789:android:abc123"},
            "api_key": [{"current_key": "AIzaSyDEADBEEF_PLACEHOLDER_KEY_001"}],
        }
    ],
}

_GOOGLESERVICE_PLIST = {
    "PROJECT_ID":    "myapp-ios-project",
    "API_KEY":       "AIzaSyDEADBEEF_IOS_PLACEHOLDER_KEY",
    "DATABASE_URL":  "https://myapp-ios-project-default-rtdb.firebaseio.com",
    "BUNDLE_ID":     "com.example.myapp",
    "GCX_SENDER_ID": "987654321",
}

_STRINGS_XML_WITH_RTDB = """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="firebase_database_url">https://fallback-project-default-rtdb.firebaseio.com</string>
</resources>
"""


def _supabase_anon_key_for_ref(project_ref: str) -> str:
    payload = base64.urlsafe_b64encode(
        json.dumps({"iss": "supabase", "ref": project_ref, "role": "anon"}).encode("utf-8")
    ).decode("ascii").rstrip("=")
    return f"eyJhbGciOiJIUzI1NiJ9.{payload}.signature"


@pytest.fixture
def extractor() -> FirebaseExtractor:
    return FirebaseExtractor(age_pubkey=None)  # no encryption in tests


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    db = tmp_path / "eng.db"
    con = sqlite3.connect(db)
    FirebaseExtractor._ensure_schema(con)
    con.commit(); con.close()
    return db


# ══════════════════════════════════════════════════════════════════════════════
# APK extraction
# ══════════════════════════════════════════════════════════════════════════════

class TestAPKExtraction:

    def test_extracts_project_id(self, extractor: FirebaseExtractor, tmp_path: Path):
        apk = _make_apk(tmp_path, google_services=_GOOGLE_SERVICES)
        projects = extractor.extract_apk(apk)
        assert len(projects) == 1
        assert projects[0].project_id == "myapp-firebase-prod"

    def test_extracts_rtdb_url(self, extractor: FirebaseExtractor, tmp_path: Path):
        apk = _make_apk(tmp_path, google_services=_GOOGLE_SERVICES)
        projects = extractor.extract_apk(apk)
        assert "firebaseio.com" in (projects[0].rtdb_url or "")

    def test_api_key_not_stored_in_plaintext(self, extractor: FirebaseExtractor, tmp_path: Path):
        apk = _make_apk(tmp_path, google_services=_GOOGLE_SERVICES)
        projects = extractor.extract_apk(apk)
        p = projects[0]
        # api_key_enc should NOT be the raw key
        if p.api_key_enc is not None:
            assert "AIzaSy" not in p.api_key_enc or "__UNENCRYPTED" in p.api_key_enc

    def test_source_file_recorded(self, extractor: FirebaseExtractor, tmp_path: Path):
        apk = _make_apk(tmp_path, google_services=_GOOGLE_SERVICES)
        projects = extractor.extract_apk(apk)
        assert str(apk) in projects[0].source_file

    def test_missing_project_id_skipped(self, extractor: FirebaseExtractor, tmp_path: Path):
        apk = _make_apk(tmp_path, google_services={"project_info": {}, "client": []})
        projects = extractor.extract_apk(apk)
        assert projects == []

    def test_corrupt_apk_returns_empty(self, extractor: FirebaseExtractor, tmp_path: Path):
        bad_apk = tmp_path / "bad.apk"
        bad_apk.write_bytes(b"NOT A ZIP FILE")
        projects = extractor.extract_apk(bad_apk)
        assert projects == []

    def test_missing_file_returns_empty(self, extractor: FirebaseExtractor, tmp_path: Path):
        projects = extractor.extract_apk(tmp_path / "nonexistent.apk")
        assert projects == []

    def test_apk_without_google_services_falls_back_to_strings_xml(
        self, extractor: FirebaseExtractor, tmp_path: Path
    ):
        apk = _make_apk(tmp_path, strings_xml=_STRINGS_XML_WITH_RTDB)
        projects = extractor.extract_apk(apk)
        assert len(projects) == 1
        assert "fallback-project" in projects[0].project_id

    def test_rtdb_url_regex_matches(self, extractor: FirebaseExtractor, tmp_path: Path):
        xml = "<resources><string>https://myapp-default-rtdb.firebaseio.com</string></resources>"
        apk = _make_apk(tmp_path, strings_xml=xml)
        projects = extractor.extract_apk(apk)
        assert any("firebaseio.com" in (p.rtdb_url or "") for p in projects)

    def test_extracts_storage_bucket_from_google_services(
        self, extractor: FirebaseExtractor, tmp_path: Path
    ):
        apk = _make_apk(
            tmp_path,
            google_services={
                "project_info": {
                    "project_id": "myapp-firebase-prod",
                    "firebase_url": "https://myapp-firebase-prod-default-rtdb.firebaseio.com",
                    "storage_bucket": "myapp-firebase-prod.appspot.com",
                },
                "client": [],
            },
        )
        projects = extractor.extract_apk(apk)
        assert len(projects) == 1
        assert projects[0].storage_bucket == "myapp-firebase-prod.appspot.com"

    def test_extracts_project_id_from_archive_style_android_bundle(
        self, extractor: FirebaseExtractor, tmp_path: Path
    ):
        bundle = _make_archive_style_android_bundle(
            tmp_path,
            "test.xapk",
            google_services=_GOOGLE_SERVICES,
        )
        projects = extractor.extract_apk(bundle)
        assert len(projects) == 1
        assert projects[0].project_id == "myapp-firebase-prod"
        assert projects[0].source_file == str(bundle)
        assert projects[0].extract_path == "base.apk!google-services.json"

    def test_extract_apk_batches_google_services_member_parsing(
        self, extractor: FirebaseExtractor, tmp_path: Path, monkeypatch
    ):
        original_batch = FirebaseExtractor._phase4_ordered_batch
        parse_batches: list[int] = []

        def _tracking_batch(items, builder, *, default_factory):  # noqa: ANN001
            batch_items = list(items)
            if getattr(builder, "__name__", "") == "_google_services_json_parse_job":
                parse_batches.append(len(batch_items))
            return original_batch(
                batch_items,
                builder,
                default_factory=default_factory,
            )

        monkeypatch.setattr(
            FirebaseExtractor,
            "_phase4_ordered_batch",
            staticmethod(_tracking_batch),
        )

        apk = tmp_path / "multi-google-services.apk"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "google-services.json",
                json.dumps({"project_info": {"project_id": "first-firebase"}, "client": []}),
            )
            zf.writestr(
                "feature/google-services.json",
                json.dumps({"project_info": {"project_id": "second-firebase"}, "client": []}),
            )
        apk.write_bytes(buf.getvalue())

        projects = extractor.extract_apk(apk)

        assert parse_batches == [2]
        assert [project.project_id for project in projects] == ["first-firebase", "second-firebase"]

    def test_extract_apk_batches_strings_xml_fallback_parsing(
        self, extractor: FirebaseExtractor, tmp_path: Path, monkeypatch
    ):
        original_batch = FirebaseExtractor._phase4_ordered_batch
        fallback_batches: list[int] = []

        def _tracking_batch(items, builder, *, default_factory):  # noqa: ANN001
            batch_items = list(items)
            if getattr(builder, "__name__", "") == "_strings_xml_project_candidates_job":
                fallback_batches.append(len(batch_items))
            return original_batch(
                batch_items,
                builder,
                default_factory=default_factory,
            )

        monkeypatch.setattr(
            FirebaseExtractor,
            "_phase4_ordered_batch",
            staticmethod(_tracking_batch),
        )

        apk = tmp_path / "multi-strings.apk"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "res/values/strings.xml",
                '<resources><string>https://first-fallback-default-rtdb.firebaseio.com</string></resources>',
            )
            zf.writestr(
                "split/res/values/strings.xml",
                '<resources><string>https://second-fallback-default-rtdb.firebaseio.com</string></resources>',
            )
        apk.write_bytes(buf.getvalue())

        projects = extractor.extract_apk(apk)

        assert fallback_batches == [2]
        assert [project.project_id for project in projects] == ["first-fallback", "second-fallback"]

    def test_extract_archive_style_bundle_batches_firebase_nested_bundle_parsing(
        self, extractor: FirebaseExtractor, tmp_path: Path, monkeypatch
    ):
        original_batch = FirebaseExtractor._phase4_ordered_batch
        nested_batches: list[int] = []

        def _tracking_batch(items, builder, *, default_factory):  # noqa: ANN001
            batch_items = list(items)
            if getattr(builder, "__name__", "") == "_extract_firebase_nested_bundle_job":
                nested_batches.append(len(batch_items))
            return original_batch(
                batch_items,
                builder,
                default_factory=default_factory,
            )

        monkeypatch.setattr(
            FirebaseExtractor,
            "_phase4_ordered_batch",
            staticmethod(_tracking_batch),
        )

        first_apk = io.BytesIO()
        with zipfile.ZipFile(first_apk, "w") as zf:
            zf.writestr(
                "google-services.json",
                json.dumps({"project_info": {"project_id": "first-nested"}, "client": []}),
            )
        second_apk = io.BytesIO()
        with zipfile.ZipFile(second_apk, "w") as zf:
            zf.writestr(
                "google-services.json",
                json.dumps({"project_info": {"project_id": "second-nested"}, "client": []}),
            )

        bundle = tmp_path / "nested-firebase.xapk"
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as zf:
            zf.writestr("splits/first.apk", first_apk.getvalue())
            zf.writestr("splits/second.apk", second_apk.getvalue())
        bundle.write_bytes(outer.getvalue())

        projects = extractor.extract_apk(bundle)

        assert nested_batches == [2]
        assert [project.project_id for project in projects] == ["first-nested", "second-nested"]
        assert [project.extract_path for project in projects] == [
            "splits/first.apk!google-services.json",
            "splits/second.apk!google-services.json",
        ]


# ══════════════════════════════════════════════════════════════════════════════
# IPA extraction
# ══════════════════════════════════════════════════════════════════════════════

class TestIPAExtraction:

    def test_extracts_project_id(self, extractor: FirebaseExtractor, tmp_path: Path):
        ipa = _make_ipa(tmp_path, plist_data=_GOOGLESERVICE_PLIST)
        projects = extractor.extract_ipa(ipa)
        assert len(projects) == 1
        assert projects[0].project_id == "myapp-ios-project"

    def test_extracts_bundle_id(self, extractor: FirebaseExtractor, tmp_path: Path):
        ipa = _make_ipa(tmp_path, plist_data=_GOOGLESERVICE_PLIST)
        projects = extractor.extract_ipa(ipa)
        assert projects[0].bundle_id == "com.example.myapp"

    def test_extracts_rtdb_url(self, extractor: FirebaseExtractor, tmp_path: Path):
        ipa = _make_ipa(tmp_path, plist_data=_GOOGLESERVICE_PLIST)
        projects = extractor.extract_ipa(ipa)
        assert "firebaseio.com" in (projects[0].rtdb_url or "")

    def test_api_key_encrypted_not_plaintext(self, extractor: FirebaseExtractor, tmp_path: Path):
        ipa = _make_ipa(tmp_path, plist_data=_GOOGLESERVICE_PLIST)
        projects = extractor.extract_ipa(ipa)
        p = projects[0]
        if p.api_key_enc:
            assert "AIzaSy" not in p.api_key_enc or "__UNENCRYPTED" in p.api_key_enc

    def test_corrupt_ipa_returns_empty(self, extractor: FirebaseExtractor, tmp_path: Path):
        bad = tmp_path / "bad.ipa"
        bad.write_bytes(b"NOT A ZIP")
        projects = extractor.extract_ipa(bad)
        assert projects == []

    def test_fallback_plist_rtdb_regex(self, extractor: FirebaseExtractor, tmp_path: Path):
        plist_xml = (
            '<?xml version="1.0"?>'
            '<plist><dict><key>DB</key>'
            '<string>https://ios-fallback-default-rtdb.firebaseio.com</string>'
            '</dict></plist>'
        )
        ipa = _make_ipa(tmp_path, other_plist=plist_xml)
        projects = extractor.extract_ipa(ipa)
        assert any("ios-fallback" in (p.project_id or "") for p in projects)

    def test_extract_ipa_batches_googleservice_plist_member_parsing(
        self, extractor: FirebaseExtractor, tmp_path: Path, monkeypatch
    ):
        original_batch = FirebaseExtractor._phase4_ordered_batch
        parse_batches: list[int] = []

        def _tracking_batch(items, builder, *, default_factory):  # noqa: ANN001
            batch_items = list(items)
            if getattr(builder, "__name__", "") == "_googleservice_plist_parse_job":
                parse_batches.append(len(batch_items))
            return original_batch(
                batch_items,
                builder,
                default_factory=default_factory,
            )

        monkeypatch.setattr(
            FirebaseExtractor,
            "_phase4_ordered_batch",
            staticmethod(_tracking_batch),
        )

        ipa = tmp_path / "multi-googleservice.ipa"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "Payload/First.app/GoogleService-Info.plist",
                plistlib.dumps({"PROJECT_ID": "first-ios", "BUNDLE_ID": "com.example.first"}),
            )
            zf.writestr(
                "Payload/Second.app/GoogleService-Info.plist",
                plistlib.dumps({"PROJECT_ID": "second-ios", "BUNDLE_ID": "com.example.second"}),
            )
        ipa.write_bytes(buf.getvalue())

        projects = extractor.extract_ipa(ipa)

        assert parse_batches == [2]
        assert [project.project_id for project in projects] == ["first-ios", "second-ios"]

    def test_extract_ipa_batches_plist_fallback_member_parsing(
        self, extractor: FirebaseExtractor, tmp_path: Path, monkeypatch
    ):
        original_batch = FirebaseExtractor._phase4_ordered_batch
        fallback_batches: list[int] = []

        def _tracking_batch(items, builder, *, default_factory):  # noqa: ANN001
            batch_items = list(items)
            if getattr(builder, "__name__", "") == "_plist_fallback_project_candidates_job":
                fallback_batches.append(len(batch_items))
            return original_batch(
                batch_items,
                builder,
                default_factory=default_factory,
            )

        monkeypatch.setattr(
            FirebaseExtractor,
            "_phase4_ordered_batch",
            staticmethod(_tracking_batch),
        )

        ipa = tmp_path / "multi-fallback-plist.ipa"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "Payload/First.app/Settings.plist",
                '<plist><string>https://first-ios-default-rtdb.firebaseio.com</string></plist>',
            )
            zf.writestr(
                "Payload/Second.app/Settings.plist",
                '<plist><string>https://second-ios-default-rtdb.firebaseio.com</string></plist>',
            )
        ipa.write_bytes(buf.getvalue())

        projects = extractor.extract_ipa(ipa)

        assert fallback_batches == [2]
        assert [project.project_id for project in projects] == ["first-ios", "second-ios"]


# ══════════════════════════════════════════════════════════════════════════════
# Storage
# ══════════════════════════════════════════════════════════════════════════════

class TestStorage:

    def test_store_writes_cloud_asset(
        self, extractor: FirebaseExtractor, tmp_db: Path, tmp_path: Path
    ):
        projects = [
            FirebaseProject(
                project_id="test-proj", api_key_enc=None, rtdb_url=None,
                bundle_id=None, source_file="app.apk", extract_path="google-services.json",
            )
        ]
        count = extractor.store(projects, tmp_db, engagement_id=1)
        assert count == 1
        con = sqlite3.connect(tmp_db)
        row = con.execute(
            "SELECT * FROM cloud_assets WHERE identifier='test-proj'"
        ).fetchone()
        con.close()
        assert row is not None

    def test_store_deduplicates(
        self, extractor: FirebaseExtractor, tmp_db: Path
    ):
        p = FirebaseProject("dup-proj", None, None, None, "app.apk", "g.json")
        extractor.store([p], tmp_db, 1)
        extractor.store([p], tmp_db, 1)
        con = sqlite3.connect(tmp_db)
        count = con.execute(
            "SELECT COUNT(*) FROM cloud_assets WHERE identifier='dup-proj'"
        ).fetchone()[0]
        con.close()
        assert count == 1

    def test_store_writes_gcs_asset_for_storage_bucket(
        self, extractor: FirebaseExtractor, tmp_db: Path
    ):
        p = FirebaseProject(
            "bucket-proj",
            None,
            None,
            None,
            "app.apk",
            "g.json",
            "bucket-proj.appspot.com",
        )
        extractor.store([p], tmp_db, 1)
        con = sqlite3.connect(tmp_db)
        row = con.execute(
            "SELECT asset_type, identifier FROM cloud_assets WHERE identifier='bucket-proj.appspot.com'"
        ).fetchone()
        con.close()
        assert row == ("gcs", "bucket-proj.appspot.com")

    def test_store_batches_multiple_project_entries_through_ordered_helper(
        self, extractor: FirebaseExtractor, tmp_db: Path, monkeypatch
    ):
        original_batch = FirebaseExtractor._phase4_ordered_batch
        batch_sizes: list[int] = []

        def _tracking_batch(items, builder, *, default_factory):  # noqa: ANN001
            batch_items = list(items)
            batch_sizes.append(len(batch_items))
            return original_batch(
                batch_items,
                builder,
                default_factory=default_factory,
            )

        monkeypatch.setattr(
            FirebaseExtractor,
            "_phase4_ordered_batch",
            staticmethod(_tracking_batch),
        )

        projects = [
            FirebaseProject("batch-proj-a", None, None, None, "app.apk", "a.json"),
            FirebaseProject("batch-proj-b", None, None, None, "app.apk", "b.json"),
        ]

        count = extractor.store(projects, tmp_db, engagement_id=1)

        assert count == 2
        assert batch_sizes == [2]
        con = sqlite3.connect(tmp_db)
        try:
            rows = con.execute(
                "SELECT identifier FROM cloud_assets WHERE identifier LIKE 'batch-proj-%' ORDER BY identifier"
            ).fetchall()
        finally:
            con.close()
        assert rows == [("batch-proj-a",), ("batch-proj-b",)]

    def test_emit_json_hides_plaintext_key(
        self, extractor: FirebaseExtractor, tmp_path: Path
    ):
        projects = [
            FirebaseProject(
                project_id="my-proj", api_key_enc="ENCRYPTED_VALUE",
                rtdb_url=None, bundle_id=None,
                source_file="app.apk", extract_path="g.json",
            )
        ]
        out = tmp_path / "output.json"
        extractor.emit_json(projects, out)
        data = json.loads(out.read_text())
        assert data[0]["api_key"] == "<age-encrypted>"
        assert "ENCRYPTED_VALUE" not in out.read_text()

    def test_emit_json_null_key_when_none(
        self, extractor: FirebaseExtractor, tmp_path: Path
    ):
        projects = [
            FirebaseProject("p", None, None, None, "a.apk", "g.json")
        ]
        out = tmp_path / "out.json"
        extractor.emit_json(projects, out)
        data = json.loads(out.read_text())
        assert data[0]["api_key"] is None

    def test_store_supabase_configs_writes_cloud_asset_and_key_finding(
        self, extractor: FirebaseExtractor, tmp_db: Path
    ):
        from forge.phase4.mobile_config_parse import SupabaseConfig

        configs = [
            SupabaseConfig(
                project_ref="stored-proj",
                project_url="https://stored-proj.supabase.co",
                anon_key="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN0b3JlZC1wcm9qIiwicm9sZSI6ImFub24ifQ.signature123",
                source_file="bundle.xapk",
                extract_path="base.apk!assets/supabase-config.js",
            )
        ]
        count = extractor.store_supabase_configs(configs, tmp_db, engagement_id=1)
        assert count == 1
        con = sqlite3.connect(tmp_db)
        try:
            cloud_row = con.execute(
                "SELECT asset_type, identifier FROM cloud_assets WHERE identifier='stored-proj'"
            ).fetchone()
            assert cloud_row == ("supabase", "stored-proj")
            key_row = con.execute(
                "SELECT service, pattern_name, domain, key_redacted FROM key_scanner_findings WHERE domain='stored-proj'"
            ).fetchone()
            assert key_row is not None
            assert key_row[0] == "supabase"
            assert key_row[1] == "supabase_mobile_config"
            assert key_row[2] == "stored-proj"
            assert "..." in str(key_row[3])
        finally:
            con.close()

    def test_emit_mobile_config_json_includes_supabase_without_plaintext(
        self, extractor: FirebaseExtractor, tmp_path: Path
    ):
        from forge.phase4.mobile_config_parse import SupabaseConfig

        projects = [
            FirebaseProject(
                project_id="my-proj",
                api_key_enc="ENCRYPTED_VALUE",
                rtdb_url="https://my-proj.firebaseio.com",
                bundle_id=None,
                source_file="bundle.xapk",
                extract_path="base.apk!google-services.json",
            )
        ]
        configs = [
            SupabaseConfig(
                project_ref="archive-proj",
                project_url="https://archive-proj.supabase.co",
                anon_key="super-secret-anon-key",
                source_file="bundle.xapk",
                extract_path="base.apk!assets/supabase-config.js",
            )
        ]
        out = tmp_path / "mobile-config.json"
        extractor.emit_mobile_config_json(projects, configs, out)
        payload = json.loads(out.read_text())
        assert payload["firebase_projects"][0]["project_id"] == "my-proj"
        assert payload["supabase_configs"][0]["project_ref"] == "archive-proj"
        assert payload["supabase_configs"][0]["anon_key"] == "<age-encrypted>"
        assert "super-secret-anon-key" not in out.read_text()


class TestSupabaseExtraction:

    def test_extract_supabase_apk(self, extractor: FirebaseExtractor, tmp_path: Path):
        apk = tmp_path / "supabase.apk"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "assets/supabase-config.json",
                json.dumps(
                    {
                        "supabaseUrl": "https://demo-project.supabase.co",
                        "supabaseKey": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.sig",
                    }
                ),
            )
        apk.write_bytes(buf.getvalue())
        configs = extractor.extract_supabase_apk(apk)
        assert len(configs) == 1
        assert configs[0].project_ref == "demo-project"

    def test_extract_supabase_ipa(self, extractor: FirebaseExtractor, tmp_path: Path):
        ipa = tmp_path / "supabase.ipa"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "Payload/App.app/Config.plist",
                "https://ios-proj.supabase.co key eyJabc.eyJdef.sig",
            )
        ipa.write_bytes(buf.getvalue())
        configs = extractor.extract_supabase_ipa(ipa)
        assert len(configs) == 1
        assert configs[0].project_ref == "ios-proj"

    def test_extract_supabase_key_only_text_uses_jwt_ref(self, extractor: FirebaseExtractor):
        configs = extractor._extract_supabase_from_text(  # noqa: SLF001
            (
                'export const anon = '
                '"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
                'eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImtleW9ubHktcHJvaiIsInJvbGUiOiJhbm9uIn0.'
                'signature321";'
            ),
            "artifact.js",
            "assets/config.js",
        )
        assert len(configs) == 1
        assert configs[0].project_ref == "keyonly-proj"
        assert configs[0].project_url == "https://keyonly-proj.supabase.co"

    def test_extract_supabase_multiple_keys_uses_ordered_batch(
        self, extractor: FirebaseExtractor, monkeypatch
    ):
        original_batch = FirebaseExtractor._phase4_ordered_batch
        batch_sizes: list[int] = []

        def _tracking_batch(items, builder, *, default_factory):  # noqa: ANN001
            batch_items = list(items)
            batch_sizes.append(len(batch_items))
            return original_batch(
                batch_items,
                builder,
                default_factory=default_factory,
            )

        monkeypatch.setattr(
            FirebaseExtractor,
            "_phase4_ordered_batch",
            staticmethod(_tracking_batch),
        )

        configs = extractor._extract_supabase_from_text(  # noqa: SLF001
            (
                'const first = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
                'eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZpcnN0LXByb2oiLCJyb2xlIjoiYW5vbiJ9.'
                'signature111";\n'
                'const second = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
                'eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNlY29uZC1wcm9qIiwicm9sZSI6ImFub24ifQ.'
                'signature222";'
            ),
            "artifact.js",
            "assets/config.js",
        )

        assert batch_sizes == [2]
        assert [config.project_ref for config in configs] == ["first-proj", "second-proj"]

    def test_extract_supabase_apk_batches_text_member_parsing(
        self, extractor: FirebaseExtractor, tmp_path: Path, monkeypatch
    ):
        original_batch = FirebaseExtractor._phase4_ordered_batch
        member_parse_batches: list[int] = []

        def _tracking_batch(items, builder, *, default_factory):  # noqa: ANN001
            batch_items = list(items)
            if getattr(builder, "__name__", "") == "_extract_supabase_member_text_job":
                member_parse_batches.append(len(batch_items))
            return original_batch(
                batch_items,
                builder,
                default_factory=default_factory,
            )

        monkeypatch.setattr(
            FirebaseExtractor,
            "_phase4_ordered_batch",
            staticmethod(_tracking_batch),
        )

        apk = tmp_path / "multi-supabase.apk"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "assets/a.js",
                f'export const anon = "{_supabase_anon_key_for_ref("first-proj")}";',
            )
            zf.writestr(
                "assets/b.ts",
                f'export const anon = "{_supabase_anon_key_for_ref("second-proj")}";',
            )
        apk.write_bytes(buf.getvalue())

        configs = extractor.extract_supabase_apk(apk)

        assert member_parse_batches == [2]
        assert [config.project_ref for config in configs] == ["first-proj", "second-proj"]

    def test_extract_supabase_archive_style_bundle_batches_nested_bundle_parsing(
        self, extractor: FirebaseExtractor, tmp_path: Path, monkeypatch
    ):
        original_batch = FirebaseExtractor._phase4_ordered_batch
        nested_parse_batches: list[int] = []

        def _tracking_batch(items, builder, *, default_factory):  # noqa: ANN001
            batch_items = list(items)
            if getattr(builder, "__name__", "") == "_extract_supabase_nested_bundle_job":
                nested_parse_batches.append(len(batch_items))
            return original_batch(
                batch_items,
                builder,
                default_factory=default_factory,
            )

        monkeypatch.setattr(
            FirebaseExtractor,
            "_phase4_ordered_batch",
            staticmethod(_tracking_batch),
        )

        first_apk = io.BytesIO()
        with zipfile.ZipFile(first_apk, "w") as zf:
            zf.writestr(
                "assets/first.js",
                f'export const anon = "{_supabase_anon_key_for_ref("first-proj")}";',
            )
        second_apk = io.BytesIO()
        with zipfile.ZipFile(second_apk, "w") as zf:
            zf.writestr(
                "assets/second.js",
                f'export const anon = "{_supabase_anon_key_for_ref("second-proj")}";',
            )

        bundle = tmp_path / "nested-supabase.xapk"
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as zf:
            zf.writestr("splits/first.apk", first_apk.getvalue())
            zf.writestr("splits/second.apk", second_apk.getvalue())
        bundle.write_bytes(outer.getvalue())

        configs = extractor.extract_supabase_apk(bundle)

        assert nested_parse_batches == [2]
        assert [config.project_ref for config in configs] == ["first-proj", "second-proj"]
        assert [config.extract_path for config in configs] == [
            "splits/first.apk!assets/first.js",
            "splits/second.apk!assets/second.js",
        ]

    def test_extract_supabase_archive_style_android_bundle(self, extractor: FirebaseExtractor, tmp_path: Path):
        bundle = _make_archive_style_android_bundle(
            tmp_path,
            "test.apkm",
            supabase_text=(
                'export const url = "https://archive-proj.supabase.co";\n'
                'export const anon = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
                'eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFyY2hpdmUtcHJvaiIsInJvbGUiOiJhbm9uIn0.'
                'signature123";\n'
            ),
        )
        configs = extractor.extract_supabase_apk(bundle)
        assert len(configs) == 1
        assert configs[0].project_ref == "archive-proj"
        assert configs[0].project_url == "https://archive-proj.supabase.co"
        assert configs[0].source_file == str(bundle)
        assert configs[0].extract_path == "base.apk!assets/supabase-config.js"


class TestWebConfigExtraction:

    def test_extract_web_config(self, extractor: FirebaseExtractor):
        html = """
        <html><script>
        firebase.initializeApp({"projectId":"web-proj","apiKey":"AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz1234567","databaseURL":"https://web-proj.firebaseio.com"});
        </script></html>
        """
        with patch("forge.phase4.mobile_config_parse.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__.return_value = mock_client
            mock_client.__exit__.return_value = None
            page_resp = MagicMock(status_code=200, text=html)
            json_resp = MagicMock(status_code=404)
            mock_client.get.side_effect = [page_resp, json_resp, json_resp]
            mock_client_cls.return_value = mock_client
            projects = extractor.extract_web_config("https://app.example.com")
        assert len(projects) == 1
        assert projects[0].project_id == "web-proj"


def test_firebase_web_extract_denies_db_url_scope_path_drift_before_fetch() -> None:
    from forge.opsec.scope_gate import ScopeViolationError
    from forge.phase4.firebase_extract import extract_firebase_config

    con = sqlite3.connect(":memory:")
    try:
        with pytest.raises(ScopeViolationError):
            extract_firebase_config(
                1001,
                ["https://allowed.example/app/"],
                "https://allowed.example/admin",
                con,
                dry_run=True,
            )
    finally:
        con.close()


def test_firebase_web_extract_skips_out_of_prefix_js_before_fetch(monkeypatch) -> None:
    from forge.phase4 import firebase_extract

    target_url = "https://allowed.example/app/index.html"
    drifted_js = "https://allowed.example/admin/app.js"
    calls: list[str] = []

    def _fake_fetch(url: str, _cfg=None):  # noqa: ANN001
        calls.append(url)
        if url == target_url:
            return '<script src="/admin/app.js"></script>'
        if url == drifted_js:
            raise AssertionError("out-of-prefix JS must not be fetched")
        return ""

    monkeypatch.setattr(firebase_extract, "wait_for_internet", lambda: True)
    monkeypatch.setattr(
        firebase_extract,
        "with_internet_retry",
        lambda func, *args, **kwargs: func(*args, **kwargs),
    )
    monkeypatch.setattr(firebase_extract, "_fetch_text", _fake_fetch)

    con = sqlite3.connect(":memory:")
    try:
        projects = firebase_extract.extract_firebase_config(
            1001,
            ["https://allowed.example/app/"],
            target_url,
            con,
        )
    finally:
        con.close()

    assert projects == []
    assert calls == [target_url, target_url]


def test_cloud_firebase_extract_cli_persists_supabase_from_archive_style_bundle(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_ENGAGEMENT_KEY", "FORGE-TEST-ENGAGEMENT-KEY")

    engagement_db = tmp_path / ".forge_data" / "engagements" / "1001.db"
    engagement_db.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(engagement_db)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'CLI Mobile Extract', '[]', 'ACTIVE', 'delta-one')
            """
        )
        con.commit()
    finally:
        con.close()

    bundle = _make_archive_style_android_bundle(
        tmp_path,
        "cli-bundle.xapk",
        google_services=_GOOGLE_SERVICES,
        supabase_text=(
            'export const url = "https://cli-archive.supabase.co";\n'
            'export const anon = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
            'eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNsaS1hcmNoaXZlIiwicm9sZSI6ImFub24ifQ.'
            'signature123";\n'
        ),
    )
    output_json = tmp_path / "cli-mobile-config.json"
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "cloud",
            "firebase-extract",
            "--engagement",
            "1001",
            "--apk",
            str(bundle),
            "--output-json",
            str(output_json),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Firebase:" in result.output
    assert "Supabase:" in result.output
    payload = json.loads(output_json.read_text())
    assert payload["firebase_projects"][0]["project_id"] == "myapp-firebase-prod"
    assert payload["supabase_configs"][0]["project_ref"] == "cli-archive"

    con = sqlite3.connect(engagement_db)
    try:
        supabase_asset = con.execute(
            "SELECT asset_type, identifier FROM cloud_assets WHERE identifier='cli-archive'"
        ).fetchone()
        assert supabase_asset == ("supabase", "cli-archive")
        key_row = con.execute(
            "SELECT service, pattern_name, domain FROM key_scanner_findings WHERE domain='cli-archive'"
        ).fetchone()
        assert key_row == ("supabase", "supabase_mobile_config", "cli-archive")
    finally:
        con.close()
