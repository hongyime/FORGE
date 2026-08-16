from __future__ import annotations

import json
import plistlib
import sqlite3
import tarfile
import threading
import time
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from forge.engagement_orchestrator import ArtifactQueueProcessor
from forge.phase4.mobile_config_parse import FirebaseProject, SupabaseConfig
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_nested_mobile_configs_from_archive_bundles(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_nested_mobile"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    ipa_bytes = BytesIO()
    with zipfile.ZipFile(ipa_bytes, "w") as zf:
        binary_plist = plistlib.dumps(
            {
                "PROJECT_ID": "nested-ipa-firebase",
                "API_KEY": "AIzaSyNESTEDIPAKEY1234567890",
                "DATABASE_URL": "https://nested-ipa-firebase.firebaseio.com",
                "BUNDLE_ID": "com.acme.nested",
            },
            fmt=plistlib.FMT_BINARY,
        )
        zf.writestr("Payload/Acme.app/GoogleService-Info.plist", binary_plist)
        zf.writestr(
            "Payload/Acme.app/config.js",
            """
            export const url = "https://nestedbundle.supabase.co";
            export const anon = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5lc3RlZGJ1bmRsZSIsInJvbGUiOiJhbm9uIn0.signature123";
            export const owner = "nested-bundle-owner@acme.example";
            export const endpoint = "https://nestedbundle.acme.example/mobile";
            """.strip(),
        )

    bundle_path = artifact_root / "mobile-bundle.zip"
    with zipfile.ZipFile(bundle_path, "w") as zf:
        zf.writestr("packages/client.ipa", ipa_bytes.getvalue())

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.firebase_projects >= 1
    assert summary.supabase_configs >= 1

    con = sqlite3.connect(db_path)
    try:
        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("firebase", "nested-ipa-firebase") in cloud_assets
        assert ("supabase", "nestedbundle") in cloud_assets

        key_findings = con.execute(
            """
            SELECT service, pattern_name, domain
            FROM key_scanner_findings
            WHERE engagement_id=1001
            ORDER BY service, domain
            """
        ).fetchall()
        assert ("firebase", "firebase_mobile_config", "nested-ipa-firebase") in key_findings
        assert ("supabase", "supabase_mobile_config", "nestedbundle") in key_findings

        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "nested-bundle-owner@acme.example" in emails

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
        assert ("nested-bundle-owner@acme.example", "email") in seeds
        assert ("https://nestedbundle.acme.example/mobile", "url") in seeds

        artifact_meta = {
            row[0]: json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert artifact_meta[bundle_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[bundle_path.resolve().as_posix()]["nested_mobile_member_count"] >= 1
        assert artifact_meta[bundle_path.resolve().as_posix()]["metadata_payload_count"] >= 1
    finally:
        con.close()


def run_parallelizes_nested_zip_mobile_member_extraction_and_preserves_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    archive_path = tmp_path / "parallel-mobile-bundle.zip"
    member_bytes = {
        "packages/client-1.ipa": b"ipa-one",
        "packages/client-2.apk": b"apk-two",
        "packages/client-3.xapk": b"xapk-three",
    }
    with zipfile.ZipFile(archive_path, "w") as zf:
        for member_name, data in member_bytes.items():
            zf.writestr(member_name, data)

    delays = {
        "packages/client-1.ipa": 0.05,
        "packages/client-2.apk": 0.01,
        "packages/client-3.xapk": 0.03,
    }
    payload_texts = {
        "packages/client-1.ipa": "nested-zip-one@acme.example",
        "packages/client-2.apk": "nested-zip-two@acme.example",
        "packages/client-3.xapk": "nested-zip-three@acme.example",
    }
    project_ids = {
        "packages/client-1.ipa": "nested-zip-firebase-one",
        "packages/client-2.apk": "nested-zip-firebase-two",
        "packages/client-3.xapk": "nested-zip-firebase-three",
    }
    project_refs = {
        "packages/client-1.ipa": "nestedzipone",
        "packages/client-2.apk": "nestedziptwo",
        "packages/client-3.xapk": "nestedzipthree",
    }
    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_extract_mobile_configs_from_member_bytes(
        _self,
        data: bytes,
        source_path: Path,
        member_name: str,
    ) -> tuple[list[tuple[str, str, str]], list[FirebaseProject], list[SupabaseConfig]]:
        assert source_path == archive_path
        assert data == member_bytes[member_name]
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(delays[member_name])
            return (
                [(str(source_path), f"{member_name}!payload.txt", payload_texts[member_name])],
                [
                    FirebaseProject(
                        project_id=project_ids[member_name],
                        api_key_enc=None,
                        rtdb_url=None,
                        bundle_id=None,
                        source_file=str(source_path),
                        extract_path=f"{member_name}!google-services.json",
                    )
                ],
                [
                    SupabaseConfig(
                        project_ref=project_refs[member_name],
                        project_url=f"https://{project_refs[member_name]}.supabase.co",
                        anon_key="anon",
                        source_file=str(source_path),
                        extract_path=f"{member_name}!supabase.js",
                    )
                ],
            )
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_extract_mobile_configs_from_member_bytes",
        fake_extract_mobile_configs_from_member_bytes,
    )

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=2)
    with zipfile.ZipFile(archive_path) as zf:
        payloads, firebase_projects, supabase_configs, mobile_members = (
            processor._extract_nested_mobile_configs_from_zip(zf, archive_path)
        )

    assert peak == 2
    assert mobile_members == 3
    assert payloads == [
        (str(archive_path), "packages/client-1.ipa!payload.txt", "nested-zip-one@acme.example"),
        (str(archive_path), "packages/client-2.apk!payload.txt", "nested-zip-two@acme.example"),
        (str(archive_path), "packages/client-3.xapk!payload.txt", "nested-zip-three@acme.example"),
    ]
    assert [project.project_id for project in firebase_projects] == [
        "nested-zip-firebase-one",
        "nested-zip-firebase-two",
        "nested-zip-firebase-three",
    ]
    assert [config.project_ref for config in supabase_configs] == [
        "nestedzipone",
        "nestedziptwo",
        "nestedzipthree",
    ]


def run_nested_mobile_configs_from_7z_archive(tmp_path: Path) -> None:
    py7zr = pytest.importorskip("py7zr")

    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_nested_7z_mobile"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    base_apk_bytes = BytesIO()
    with zipfile.ZipFile(base_apk_bytes, "w") as zf:
        zf.writestr(
            "google-services.json",
            """
            {
              "project_info": {
                "project_id": "nested-7z-firebase",
                "firebase_url": "https://nested-7z-firebase.firebaseio.com",
                "storage_bucket": "nested-7z-firebase.appspot.com"
              }
            }
            """.strip(),
        )
        zf.writestr(
            "assets/supabase.js",
            """
            export const url = "https://nested7z.supabase.co";
            export const anon = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5lc3RlZDd6Iiwicm9sZSI6ImFub24ifQ.signature123";
            export const owner = "nested-7z-owner@acme.example";
            export const endpoint = "https://nested7z.acme.example/mobile";
            """.strip(),
        )

    xapk_bytes = BytesIO()
    with zipfile.ZipFile(xapk_bytes, "w") as zf:
        zf.writestr("manifest.json", '{"name":"Nested 7z Remote Bundle"}')
        zf.writestr("base.apk", base_apk_bytes.getvalue())

    seven_path = artifact_root / "mobile-delivery.7z"
    with py7zr.SevenZipFile(seven_path, "w") as archive:
        archive.writestr(xapk_bytes.getvalue(), "packages/client.xapk")
        archive.writestr(b"ignore", "packages/readme.txt")

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.firebase_projects >= 1
    assert summary.supabase_configs >= 1
    assert summary.discovered_seeds >= 5

    con = sqlite3.connect(db_path)
    try:
        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("firebase", "nested-7z-firebase") in cloud_assets
        assert ("gcs", "nested-7z-firebase.appspot.com") in cloud_assets
        assert ("supabase", "nested7z") in cloud_assets

        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "nested-7z-owner@acme.example" in emails

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
        assert ("nested-7z-firebase", "other") in seeds
        assert ("https://storage.googleapis.com/nested-7z-firebase.appspot.com", "url") in seeds
        assert ("https://nested7z.supabase.co", "url") in seeds
        assert ("nested7z", "other") in seeds
        assert ("nested-7z-owner@acme.example", "email") in seeds
        assert ("https://nested7z.acme.example/mobile", "url") in seeds

        artifact_meta = {
            row[0]: json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert artifact_meta[seven_path.resolve().as_posix()]["format"] == "7z"
        assert artifact_meta[seven_path.resolve().as_posix()]["nested_mobile_member_count"] >= 1
        assert artifact_meta[seven_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()


def run_parallelizes_nested_7z_mobile_member_extraction_and_preserves_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    py7zr = pytest.importorskip("py7zr")

    db_path = tmp_path / "engagement.db"
    archive_path = tmp_path / "parallel-mobile-bundle.7z"
    member_bytes = {
        "packages/client-1.ipa": b"ipa-one",
        "packages/client-2.apk": b"apk-two",
        "packages/client-3.xapk": b"xapk-three",
    }
    with py7zr.SevenZipFile(archive_path, "w") as archive:
        for member_name, data in member_bytes.items():
            archive.writestr(data, member_name)

    delays = {
        "packages/client-1.ipa": 0.05,
        "packages/client-2.apk": 0.01,
        "packages/client-3.xapk": 0.03,
    }
    payload_texts = {
        "packages/client-1.ipa": "nested-7z-one@acme.example",
        "packages/client-2.apk": "nested-7z-two@acme.example",
        "packages/client-3.xapk": "nested-7z-three@acme.example",
    }
    project_ids = {
        "packages/client-1.ipa": "nested-7z-firebase-one",
        "packages/client-2.apk": "nested-7z-firebase-two",
        "packages/client-3.xapk": "nested-7z-firebase-three",
    }
    project_refs = {
        "packages/client-1.ipa": "nested7zone",
        "packages/client-2.apk": "nested7ztwo",
        "packages/client-3.xapk": "nested7zthree",
    }
    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_extract_mobile_configs_from_member_bytes(
        _self,
        data: bytes,
        source_path: Path,
        member_name: str,
    ) -> tuple[list[tuple[str, str, str]], list[FirebaseProject], list[SupabaseConfig]]:
        assert source_path == archive_path
        assert data == member_bytes[member_name]
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(delays[member_name])
            return (
                [(str(source_path), f"{member_name}!payload.txt", payload_texts[member_name])],
                [
                    FirebaseProject(
                        project_id=project_ids[member_name],
                        api_key_enc=None,
                        rtdb_url=None,
                        bundle_id=None,
                        source_file=str(source_path),
                        extract_path=f"{member_name}!google-services.json",
                    )
                ],
                [
                    SupabaseConfig(
                        project_ref=project_refs[member_name],
                        project_url=f"https://{project_refs[member_name]}.supabase.co",
                        anon_key="anon",
                        source_file=str(source_path),
                        extract_path=f"{member_name}!supabase.js",
                    )
                ],
            )
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_extract_mobile_configs_from_member_bytes",
        fake_extract_mobile_configs_from_member_bytes,
    )

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=2)
    payloads, firebase_projects, supabase_configs, mobile_members = (
        processor._extract_nested_mobile_configs_from_7z(
            archive_path.read_bytes(),
            archive_path,
        )
    )

    assert peak == 2
    assert mobile_members == 3
    assert payloads == [
        (str(archive_path), "packages/client-1.ipa!payload.txt", "nested-7z-one@acme.example"),
        (str(archive_path), "packages/client-2.apk!payload.txt", "nested-7z-two@acme.example"),
        (str(archive_path), "packages/client-3.xapk!payload.txt", "nested-7z-three@acme.example"),
    ]
    assert [project.project_id for project in firebase_projects] == [
        "nested-7z-firebase-one",
        "nested-7z-firebase-two",
        "nested-7z-firebase-three",
    ]
    assert [config.project_ref for config in supabase_configs] == [
        "nested7zone",
        "nested7ztwo",
        "nested7zthree",
    ]


def run_parallelizes_nested_zip_mobile_member_planning_and_preserves_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    archive_path = tmp_path / "parallel-mobile-member-plan.zip"
    member_names = [
        "packages/client-1.ipa",
        "packages/client-2.apk",
        "packages/client-3.xapk",
        "packages/client-4.apkm",
        "packages/client-5.aab",
    ]
    with zipfile.ZipFile(archive_path, "w") as zf:
        for member_name in member_names:
            zf.writestr(member_name, member_name.encode("utf-8"))
        zf.writestr("packages/ignore.txt", b"ignore")

    delays = {
        "packages/client-1.ipa": 0.05,
        "packages/client-2.apk": 0.01,
        "packages/client-3.xapk": 0.03,
        "packages/client-4.apkm": 0.02,
        "packages/client-5.aab": 0.04,
        "packages/ignore.txt": 0.01,
    }
    active = 0
    peak = 0
    lock = threading.Lock()
    original_entry = ArtifactQueueProcessor._nested_mobile_zip_member_entry

    def tracking_entry(member):  # noqa: ANN001
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(delays[member.filename])
            return original_entry(member)
        finally:
            with lock:
                active -= 1

    def fake_extract_mobile_configs_from_member_bytes(
        _self,
        data: bytes,
        source_path: Path,
        member_name: str,
    ) -> tuple[list[tuple[str, str, str]], list[FirebaseProject], list[SupabaseConfig]]:
        del data
        project_id = Path(member_name).stem.lower().replace("client-", "member-")
        return (
            [(str(source_path), f"{member_name}!payload.txt", project_id)],
            [],
            [],
        )

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_nested_mobile_zip_member_entry",
        staticmethod(tracking_entry),
    )
    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_extract_mobile_configs_from_member_bytes",
        fake_extract_mobile_configs_from_member_bytes,
    )

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=8)
    with zipfile.ZipFile(archive_path) as zf:
        payloads, firebase_projects, supabase_configs, mobile_members = (
            processor._extract_nested_mobile_configs_from_zip(zf, archive_path)
        )

    assert peak == 4
    assert mobile_members == 5
    assert payloads == [
        (str(archive_path), "packages/client-1.ipa!payload.txt", "member-1"),
        (str(archive_path), "packages/client-2.apk!payload.txt", "member-2"),
        (str(archive_path), "packages/client-3.xapk!payload.txt", "member-3"),
        (str(archive_path), "packages/client-4.apkm!payload.txt", "member-4"),
        (str(archive_path), "packages/client-5.aab!payload.txt", "member-5"),
    ]
    assert firebase_projects == []
    assert supabase_configs == []


def run_parallelizes_nested_zip_mobile_member_job_planning_and_preserves_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    archive_path = tmp_path / "parallel-mobile-member-job-plan.zip"
    member_names = [
        "packages/client-1.ipa",
        "packages/client-2.apk",
        "packages/client-3.xapk",
        "packages/client-4.apkm",
        "packages/client-5.aab",
    ]
    with zipfile.ZipFile(archive_path, "w") as zf:
        for member_name in member_names:
            zf.writestr(member_name, member_name.encode("utf-8"))
        zf.writestr("packages/ignore.txt", b"ignore")

    delays = {
        "packages/client-1.ipa": 0.05,
        "packages/client-2.apk": 0.01,
        "packages/client-3.xapk": 0.03,
        "packages/client-4.apkm": 0.02,
        "packages/client-5.aab": 0.04,
    }
    active = 0
    peak = 0
    entered = 0
    lock = threading.Lock()
    gate = threading.Event()
    original_entry = ArtifactQueueProcessor._nested_mobile_member_job

    def tracking_entry(member_job):  # noqa: ANN001
        nonlocal active, peak, entered
        member_name, _member_bytes = member_job
        with lock:
            active += 1
            peak = max(peak, active)
            entered += 1
            current_entered = entered
            if entered >= 4:
                gate.set()
        try:
            if current_entered <= 4:
                assert gate.wait(timeout=1.0)
            time.sleep(delays[member_name])
            return original_entry(member_job)
        finally:
            with lock:
                active -= 1

    def fake_extract_mobile_configs_from_member_bytes(
        _self,
        data: bytes,
        source_path: Path,
        member_name: str,
    ) -> tuple[list[tuple[str, str, str]], list[FirebaseProject], list[SupabaseConfig]]:
        assert data == member_name.encode("utf-8")
        return (
            [(str(source_path), f"{member_name}!payload.txt", Path(member_name).stem)],
            [],
            [],
        )

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_nested_mobile_member_job",
        staticmethod(tracking_entry),
    )
    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_extract_mobile_configs_from_member_bytes",
        fake_extract_mobile_configs_from_member_bytes,
    )

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=8)
    with zipfile.ZipFile(archive_path) as zf:
        payloads, firebase_projects, supabase_configs, mobile_members = (
            processor._extract_nested_mobile_configs_from_zip(zf, archive_path)
        )

    assert peak >= 4
    assert mobile_members == 5
    assert payloads == [
        (str(archive_path), "packages/client-1.ipa!payload.txt", "client-1"),
        (str(archive_path), "packages/client-2.apk!payload.txt", "client-2"),
        (str(archive_path), "packages/client-3.xapk!payload.txt", "client-3"),
        (str(archive_path), "packages/client-4.apkm!payload.txt", "client-4"),
        (str(archive_path), "packages/client-5.aab!payload.txt", "client-5"),
    ]
    assert firebase_projects == []
    assert supabase_configs == []


def run_parallelizes_nested_tar_mobile_member_extraction_and_preserves_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    archive_path = tmp_path / "parallel-mobile-bundle.tar"
    member_bytes = {
        "packages/client-1.ipa": b"ipa-one",
        "packages/client-2.apk": b"apk-two",
        "packages/client-3.apkm": b"apkm-three",
    }
    with tarfile.open(archive_path, "w") as tf:
        for member_name, data in member_bytes.items():
            info = tarfile.TarInfo(member_name)
            info.size = len(data)
            tf.addfile(info, BytesIO(data))

    delays = {
        "packages/client-1.ipa": 0.05,
        "packages/client-2.apk": 0.01,
        "packages/client-3.apkm": 0.03,
    }
    payload_texts = {
        "packages/client-1.ipa": "nested-tar-one@acme.example",
        "packages/client-2.apk": "nested-tar-two@acme.example",
        "packages/client-3.apkm": "nested-tar-three@acme.example",
    }
    project_ids = {
        "packages/client-1.ipa": "nested-tar-firebase-one",
        "packages/client-2.apk": "nested-tar-firebase-two",
        "packages/client-3.apkm": "nested-tar-firebase-three",
    }
    project_refs = {
        "packages/client-1.ipa": "nestedtarone",
        "packages/client-2.apk": "nestedtartwo",
        "packages/client-3.apkm": "nestedtarthree",
    }
    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_extract_mobile_configs_from_member_bytes(
        _self,
        data: bytes,
        source_path: Path,
        member_name: str,
    ) -> tuple[list[tuple[str, str, str]], list[FirebaseProject], list[SupabaseConfig]]:
        assert source_path == archive_path
        assert data == member_bytes[member_name]
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(delays[member_name])
            return (
                [(str(source_path), f"{member_name}!payload.txt", payload_texts[member_name])],
                [
                    FirebaseProject(
                        project_id=project_ids[member_name],
                        api_key_enc=None,
                        rtdb_url=None,
                        bundle_id=None,
                        source_file=str(source_path),
                        extract_path=f"{member_name}!google-services.json",
                    )
                ],
                [
                    SupabaseConfig(
                        project_ref=project_refs[member_name],
                        project_url=f"https://{project_refs[member_name]}.supabase.co",
                        anon_key="anon",
                        source_file=str(source_path),
                        extract_path=f"{member_name}!supabase.js",
                    )
                ],
            )
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_extract_mobile_configs_from_member_bytes",
        fake_extract_mobile_configs_from_member_bytes,
    )

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=2)
    with tarfile.open(archive_path) as tf:
        payloads, firebase_projects, supabase_configs, mobile_members = (
            processor._extract_nested_mobile_configs_from_tar(tf, archive_path)
        )

    assert peak == 2
    assert mobile_members == 3
    assert payloads == [
        (str(archive_path), "packages/client-1.ipa!payload.txt", "nested-tar-one@acme.example"),
        (str(archive_path), "packages/client-2.apk!payload.txt", "nested-tar-two@acme.example"),
        (str(archive_path), "packages/client-3.apkm!payload.txt", "nested-tar-three@acme.example"),
    ]
    assert [project.project_id for project in firebase_projects] == [
        "nested-tar-firebase-one",
        "nested-tar-firebase-two",
        "nested-tar-firebase-three",
    ]
    assert [config.project_ref for config in supabase_configs] == [
        "nestedtarone",
        "nestedtartwo",
        "nestedtarthree",
    ]


def run_parallelizes_nested_tar_mobile_member_planning_and_preserves_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    archive_path = tmp_path / "parallel-mobile-member-plan.tar"
    member_names = [
        "packages/client-1.ipa",
        "packages/client-2.apk",
        "packages/client-3.apkm",
        "packages/client-4.xapk",
        "packages/client-5.aab",
    ]
    with tarfile.open(archive_path, "w") as tf:
        for member_name in member_names:
            payload = member_name.encode("utf-8")
            info = tarfile.TarInfo(member_name)
            info.size = len(payload)
            tf.addfile(info, BytesIO(payload))
        ignore_info = tarfile.TarInfo("packages/ignore.txt")
        ignore_payload = b"ignore"
        ignore_info.size = len(ignore_payload)
        tf.addfile(ignore_info, BytesIO(ignore_payload))

    delays = {
        "packages/client-1.ipa": 0.05,
        "packages/client-2.apk": 0.01,
        "packages/client-3.apkm": 0.03,
        "packages/client-4.xapk": 0.02,
        "packages/client-5.aab": 0.04,
        "packages/ignore.txt": 0.01,
    }
    active = 0
    entered = 0
    peak = 0
    lock = threading.Lock()
    gate = threading.Event()
    original_entry = ArtifactQueueProcessor._nested_mobile_tar_member_entry

    def tracking_entry(member):  # noqa: ANN001
        nonlocal active, entered, peak
        with lock:
            active += 1
            entered += 1
            peak = max(peak, active)
            if entered >= 4:
                gate.set()
        try:
            gate.wait(timeout=1.0)
            time.sleep(delays[member.name])
            return original_entry(member)
        finally:
            with lock:
                active -= 1

    def fake_extract_mobile_configs_from_member_bytes(
        _self,
        data: bytes,
        source_path: Path,
        member_name: str,
    ) -> tuple[list[tuple[str, str, str]], list[FirebaseProject], list[SupabaseConfig]]:
        del data
        project_id = Path(member_name).stem.lower().replace("client-", "member-")
        return (
            [(str(source_path), f"{member_name}!payload.txt", project_id)],
            [],
            [],
        )

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_nested_mobile_tar_member_entry",
        staticmethod(tracking_entry),
    )
    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_extract_mobile_configs_from_member_bytes",
        fake_extract_mobile_configs_from_member_bytes,
    )

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=8)
    with tarfile.open(archive_path) as tf:
        payloads, firebase_projects, supabase_configs, mobile_members = (
            processor._extract_nested_mobile_configs_from_tar(tf, archive_path)
        )

    assert peak == 4
    assert mobile_members == 5
    assert payloads == [
        (str(archive_path), "packages/client-1.ipa!payload.txt", "member-1"),
        (str(archive_path), "packages/client-2.apk!payload.txt", "member-2"),
        (str(archive_path), "packages/client-3.apkm!payload.txt", "member-3"),
        (str(archive_path), "packages/client-4.xapk!payload.txt", "member-4"),
        (str(archive_path), "packages/client-5.aab!payload.txt", "member-5"),
    ]
    assert firebase_projects == []
    assert supabase_configs == []


def run_parallelizes_nested_tar_mobile_member_job_planning_and_preserves_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    archive_path = tmp_path / "parallel-mobile-member-job-plan.tar"
    member_names = [
        "packages/client-1.ipa",
        "packages/client-2.apk",
        "packages/client-3.apkm",
        "packages/client-4.xapk",
        "packages/client-5.aab",
    ]
    with tarfile.open(archive_path, "w") as tf:
        for member_name in member_names:
            payload = member_name.encode("utf-8")
            info = tarfile.TarInfo(member_name)
            info.size = len(payload)
            tf.addfile(info, BytesIO(payload))
        ignore_info = tarfile.TarInfo("packages/ignore.txt")
        ignore_payload = b"ignore"
        ignore_info.size = len(ignore_payload)
        tf.addfile(ignore_info, BytesIO(ignore_payload))

    delays = {
        "packages/client-1.ipa": 0.05,
        "packages/client-2.apk": 0.01,
        "packages/client-3.apkm": 0.03,
        "packages/client-4.xapk": 0.02,
        "packages/client-5.aab": 0.04,
    }
    active = 0
    peak = 0
    entered = 0
    lock = threading.Lock()
    gate = threading.Event()
    original_entry = ArtifactQueueProcessor._nested_mobile_member_job

    def tracking_entry(member_job):  # noqa: ANN001
        nonlocal active, peak, entered
        member_name, _member_bytes = member_job
        with lock:
            active += 1
            peak = max(peak, active)
            entered += 1
            current_entered = entered
            if entered >= 4:
                gate.set()
        try:
            if current_entered <= 4:
                assert gate.wait(timeout=1.0)
            time.sleep(delays[member_name])
            return original_entry(member_job)
        finally:
            with lock:
                active -= 1

    def fake_extract_mobile_configs_from_member_bytes(
        _self,
        data: bytes,
        source_path: Path,
        member_name: str,
    ) -> tuple[list[tuple[str, str, str]], list[FirebaseProject], list[SupabaseConfig]]:
        assert data == member_name.encode("utf-8")
        return (
            [(str(source_path), f"{member_name}!payload.txt", Path(member_name).stem)],
            [],
            [],
        )

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_nested_mobile_member_job",
        staticmethod(tracking_entry),
    )
    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_extract_mobile_configs_from_member_bytes",
        fake_extract_mobile_configs_from_member_bytes,
    )

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=8)
    with tarfile.open(archive_path) as tf:
        payloads, firebase_projects, supabase_configs, mobile_members = (
            processor._extract_nested_mobile_configs_from_tar(tf, archive_path)
        )

    assert peak >= 4
    assert mobile_members == 5
    assert payloads == [
        (str(archive_path), "packages/client-1.ipa!payload.txt", "client-1"),
        (str(archive_path), "packages/client-2.apk!payload.txt", "client-2"),
        (str(archive_path), "packages/client-3.apkm!payload.txt", "client-3"),
        (str(archive_path), "packages/client-4.xapk!payload.txt", "client-4"),
        (str(archive_path), "packages/client-5.aab!payload.txt", "client-5"),
    ]
    assert firebase_projects == []
    assert supabase_configs == []


def run_nested_archive_style_mobile_bundle_from_outer_archive(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_nested_archive_mobile"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    base_apk_bytes = BytesIO()
    with zipfile.ZipFile(base_apk_bytes, "w") as zf:
        zf.writestr(
            "google-services.json",
            """
            {
              "project_info": {
                "project_id": "nested-xapk-firebase",
                "firebase_url": "https://nested-xapk-firebase.firebaseio.com",
                "storage_bucket": "nested-xapk-firebase.appspot.com"
              }
            }
            """.strip(),
        )
        zf.writestr(
            "assets/supabase.js",
            """
            export const url = "https://nestedxapk.supabase.co";
            export const anon = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5lc3RlZHhhcGsiLCJyb2xlIjoiYW5vbiJ9.signature123";
            export const owner = "nested-xapk-owner@acme.example";
            export const endpoint = "https://nestedxapk.acme.example/mobile";
            """.strip(),
        )

    xapk_bytes = BytesIO()
    with zipfile.ZipFile(xapk_bytes, "w") as zf:
        zf.writestr("manifest.json", '{"name":"Nested Remote Bundle"}')
        zf.writestr("base.apk", base_apk_bytes.getvalue())

    bundle_path = artifact_root / "mobile-delivery.zip"
    with zipfile.ZipFile(bundle_path, "w") as zf:
        zf.writestr("packages/client.xapk", xapk_bytes.getvalue())

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.firebase_projects >= 1
    assert summary.supabase_configs >= 1
    assert summary.discovered_seeds >= 5

    con = sqlite3.connect(db_path)
    try:
        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("firebase", "nested-xapk-firebase") in cloud_assets
        assert ("gcs", "nested-xapk-firebase.appspot.com") in cloud_assets
        assert ("supabase", "nestedxapk") in cloud_assets

        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "nested-xapk-owner@acme.example" in emails

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
        assert ("nested-xapk-firebase", "other") in seeds
        assert ("https://storage.googleapis.com/nested-xapk-firebase.appspot.com", "url") in seeds
        assert ("https://nestedxapk.supabase.co", "url") in seeds
        assert ("nestedxapk", "other") in seeds
        assert ("nested-xapk-owner@acme.example", "email") in seeds
        assert ("https://nestedxapk.acme.example/mobile", "url") in seeds

        artifact_meta = {
            row[0]: json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert artifact_meta[bundle_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[bundle_path.resolve().as_posix()]["nested_mobile_member_count"] >= 1
        assert artifact_meta[bundle_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()
