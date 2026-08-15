from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from textwrap import dedent
from typing import Callable

from forge.engagement_orchestrator import ArtifactQueueProcessor


def run_queue_processor_extracts_native_build_config_text_artifacts(
    tmp_path: Path,
    bootstrap_engagement: Callable[[Path], None],
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_native_build_config"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    cmake_path = artifact_root / "Toolchain.cmake"
    cmake_path.write_text(
        dedent(
            """
            set(OWNER "cmake-owner@acme.example")
            set(API_BASE "https://cmake.acme.example/build")
            set(FIREBASE_DB "https://cmake-firebase.firebaseio.com")
            set(SUPABASE_URL "https://cmakevault.supabase.co/rest/v1")
            set(ARCHIVE "s3://acme-cmake-bucket/builds/toolchain.tar")
            """
        ).strip(),
        encoding="utf-8",
    )

    meson_path = artifact_root / "meson.build"
    meson_path.write_text(
        dedent(
            """
            project('acme', 'cpp')
            owner = 'meson-owner@acme.example'
            endpoint = 'https://meson.acme.example/native'
            gcs = 'gs://acme-meson-gcs/builds/latest.json'
            """
        ).strip(),
        encoding="utf-8",
    )

    sconstruct_path = artifact_root / "SConstruct"
    sconstruct_path.write_text(
        dedent(
            """
            owner = "scons-owner@acme.example"
            dashboard = "https://scons.acme.example/build"
            """
        ).strip(),
        encoding="utf-8",
    )

    nested_bundle = artifact_root / "native-build-config.zip"
    with zipfile.ZipFile(nested_bundle, "w") as zf:
        zf.writestr(
            "configure.ac",
            dedent(
                """
                AC_INIT([acme], [1.0], [autoconf-owner@acme.example])
                AC_DEFINE([STATUS_URL], [https://autoconf.acme.example/configure])
                AC_DEFINE([FIREBASE_DB], [https://autoconf-firebase.firebaseio.com])
                """
            ).strip(),
        )
        zf.writestr(
            "Makefile.am",
            dedent(
                """
                maintainer_email = automake-owner@acme.example
                release_url = https://automake.acme.example/release
                release_bucket = s3://acme-automake-bucket/releases/latest.tar.gz
                """
            ).strip(),
        )
        zf.writestr(
            "m4/acme.m4",
            dedent(
                """
                AC_DEFUN([ACME_OWNER], [m4-owner@acme.example])
                AC_DEFUN([ACME_URL], [https://m4.acme.example/macro])
                AC_DEFUN([ACME_GCS], [gs://acme-m4-gcs/macros/latest.txt])
                """
            ).strip(),
        )
        zf.writestr(
            "scripts/SConscript",
            dedent(
                """
                owner = "sconscript-owner@acme.example"
                callback = "https://sconscript.acme.example/callback"
                supabase = "https://sconscriptvault.supabase.co/rest/v1"
                """
            ).strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 4
    assert summary.processed >= 4
    assert summary.discovered_seeds >= 14

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        for expected_email in {
            "cmake-owner@acme.example",
            "meson-owner@acme.example",
            "scons-owner@acme.example",
            "autoconf-owner@acme.example",
            "automake-owner@acme.example",
            "m4-owner@acme.example",
            "sconscript-owner@acme.example",
        }:
            assert expected_email in emails

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
        for expected_url in {
            "https://cmake.acme.example/build",
            "https://meson.acme.example/native",
            "https://scons.acme.example/build",
            "https://autoconf.acme.example/configure",
            "https://automake.acme.example/release",
            "https://m4.acme.example/macro",
            "https://sconscript.acme.example/callback",
        }:
            assert (expected_url, "url") in seeds
        assert ("cmake-owner@acme.example", "email") in seeds
        assert ("autoconf-owner@acme.example", "email") in seeds
        assert ("sconscript-owner@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-automake-bucket") in cloud_assets
        assert ("aws_s3", "acme-cmake-bucket") in cloud_assets
        assert ("firebase", "autoconf-firebase") in cloud_assets
        assert ("firebase", "cmake-firebase") in cloud_assets
        assert ("gcs", "acme-m4-gcs") in cloud_assets
        assert ("gcs", "acme-meson-gcs") in cloud_assets
        assert ("supabase", "cmakevault") in cloud_assets
        assert ("supabase", "sconscriptvault") in cloud_assets

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
        assert artifact_meta[cmake_path.resolve().as_posix()]["format"] == "cmake"
        assert artifact_meta[meson_path.resolve().as_posix()]["format"] == "build"
        assert artifact_meta[sconstruct_path.resolve().as_posix()]["format"] == "sconstruct"
        assert artifact_meta[nested_bundle.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[nested_bundle.resolve().as_posix()]["payload_count"] >= 4
    finally:
        con.close()
