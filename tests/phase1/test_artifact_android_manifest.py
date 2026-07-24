from __future__ import annotations

import sqlite3
import zipfile
from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _artifact_format_label,
)
from forge.utils.artifact_android_manifest import (
    android_manifest_artifact_label,
    android_manifest_package_names,
    android_manifest_urls,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


_MANIFEST = dedent(
    """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.acme.portal">
      <application>
        <activity android:name=".MainActivity" android:exported="true">
          <intent-filter>
            <action android:name="android.intent.action.VIEW" />
            <category android:name="android.intent.category.DEFAULT" />
            <category android:name="android.intent.category.BROWSABLE" />
            <data
              android:scheme="https"
              android:host="portal.acme.example"
              android:pathPrefix="/mobile" />
          </intent-filter>
          <intent-filter>
            <action android:name="android.intent.action.VIEW" />
            <category android:name="android.intent.category.BROWSABLE" />
            <data android:scheme="acme" android:host="portal.acme.example" />
          </intent-filter>
          <intent-filter>
            <action android:name="android.intent.action.VIEW" />
            <category android:name="android.intent.category.BROWSABLE" />
            <data android:scheme="https" android:host="localhost" />
          </intent-filter>
          <intent-filter>
            <action android:name="android.intent.action.VIEW" />
            <category android:name="android.intent.category.BROWSABLE" />
            <data android:scheme="https" android:host="${TENANT}.example.com" />
          </intent-filter>
        </activity>
      </application>
    </manifest>
    """
).strip()


def test_android_manifest_helper_extracts_safe_package_and_deep_links() -> None:
    assert android_manifest_artifact_label("app/src/main/AndroidManifest.xml") == "android-manifest"
    assert _artifact_format_label("AndroidManifest.xml") == "android-manifest"
    assert android_manifest_package_names(_MANIFEST) == ["com.acme.portal"]
    assert android_manifest_urls(_MANIFEST) == ["https://portal.acme.example/mobile"]
    assert android_manifest_package_names('<manifest package="not a package" />') == []


def test_android_manifest_direct_file_persists_package_and_deep_link(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "android_direct" / "app" / "src" / "main"
    artifact_root.mkdir(parents=True)
    bootstrap_engagement(db_path, name="Android Manifest Direct Test")
    (artifact_root / "AndroidManifest.xml").write_text(_MANIFEST, encoding="utf-8")

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root.parents[2]])
    summary = processor.process()

    assert queued == 1
    assert summary.processed == 1
    _assert_android_manifest_pivots(db_path)
    _assert_metadata_format(db_path, "android-manifest")


def test_android_manifest_archive_member_preserves_attribute_only_pivots(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "android_archive"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Android Manifest Archive Test")
    archive_path = artifact_root / "library.aar"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", _MANIFEST)

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == 1
    assert summary.processed == 1
    _assert_android_manifest_pivots(db_path)


def _assert_android_manifest_pivots(db_path: Path) -> None:
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
    finally:
        con.close()

    assert ("https://portal.acme.example/mobile", "url") in seeds
    assert ("mobile_android_package", "com.acme.portal") in cloud_assets
    assert ("https://localhost", "url") not in seeds
    assert ("https://${TENANT}.example.com", "url") not in seeds


def _assert_metadata_format(db_path: Path, expected_format: str) -> None:
    con = sqlite3.connect(db_path)
    try:
        formats = {
            row[0]
            for row in con.execute(
                """
                SELECT json_extract(metadata_json, '$.format')
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()
    assert expected_format in formats
