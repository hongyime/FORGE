"""Tests for the cloud_ref seed classifier + hostname detection.

Task 4 from post-audit forward task list. See docs/cloud_ref_seed_plan.md
for the full 14-file blast radius; this test set covers slice 1
(classifier + hostname detection) and the DB migration for widening the
CHECK constraint.
"""

from __future__ import annotations

import sqlite3

import pytest

from forge.engagement_orchestrator import (
    _classify_seed_value,
    _hostname_is_cloud_ref,
    _CLOUD_REF_HOSTNAME_SUFFIXES,
)


class TestHostnameIsCloudRef:
    """Every provider hostname the plan doc lists must round-trip to True."""

    @pytest.mark.parametrize(
        "host",
        [
            # Supabase
            "myapp.supabase.co",
            "myapp.supabase.in",
            # Firebase / Google
            "myapp.firebaseio.com",
            "myapp.firebaseapp.com",
            "myapp.web.app",
            "myapp.appspot.com",
            "bucket.storage.googleapis.com",
            "storage.cloud.google.com",
            # S3
            "mybucket.s3.amazonaws.com",
            "mybucket.s3-website.amazonaws.com",
            "mybucket.s3.us-east-1.amazonaws.com",
            "mybucket.s3.eu-west-2.amazonaws.com",
            "s3-us-west-2.amazonaws.com",
            # CloudFront + Amplify
            "d123abc.cloudfront.net",
            "main.d123abc.amplifyapp.com",
            # Azure
            "myacct.blob.core.windows.net",
            "myacct.dfs.core.windows.net",
            "myacct.file.core.windows.net",
            # DO
            "mybucket.nyc3.digitaloceanspaces.com",
            # Vercel / Netlify / CF Pages
            "myapp.vercel.app",
            "myapp.netlify.app",
            "myapp.pages.dev",
            "myapp.workers.dev",
            # Firebase RTDB regional
            "myapp.europe-west1.firebasedatabase.app",
        ],
    )
    def test_matches_provider_hostname(self, host: str) -> None:
        assert _hostname_is_cloud_ref(host), f"expected cloud_ref match for {host!r}"

    @pytest.mark.parametrize(
        "host",
        [
            "example.com",
            "portal.example.com",
            "acme.co",
            "www.google.com",
            "some-other-domain.io",
            "",
        ],
    )
    def test_rejects_non_provider_hostname(self, host: str) -> None:
        assert not _hostname_is_cloud_ref(host), (
            f"expected non-match for {host!r} (must not be cloud_ref)"
        )

    def test_strips_wildcards_and_leading_dots(self) -> None:
        assert _hostname_is_cloud_ref("*.myapp.supabase.co")
        assert _hostname_is_cloud_ref(".myapp.supabase.co")

    def test_case_insensitive(self) -> None:
        assert _hostname_is_cloud_ref("MyApp.SUPABASE.CO")


class TestClassifySeedValue:
    """cloud_ref must beat url and domain when the hostname matches."""

    def test_bare_supabase_hostname_is_cloud_ref(self) -> None:
        assert _classify_seed_value("xyz.supabase.co") == "cloud_ref"

    def test_https_supabase_url_is_cloud_ref(self) -> None:
        assert _classify_seed_value("https://xyz.supabase.co/rest/v1/foo") == "cloud_ref"

    def test_bare_firebase_hostname_is_cloud_ref(self) -> None:
        assert _classify_seed_value("myapp.firebaseio.com") == "cloud_ref"

    def test_regional_s3_url_is_cloud_ref(self) -> None:
        assert _classify_seed_value("https://bucket.s3.us-east-1.amazonaws.com/") == "cloud_ref"

    def test_azure_blob_hostname_is_cloud_ref(self) -> None:
        assert _classify_seed_value("acct.blob.core.windows.net") == "cloud_ref"

    def test_generic_domain_still_returns_domain(self) -> None:
        assert _classify_seed_value("example.com") == "domain"
        assert _classify_seed_value("portal.example.com") == "domain"

    def test_generic_http_url_still_returns_url(self) -> None:
        assert _classify_seed_value("https://portal.example.com/login") == "url"

    def test_apk_url_still_beats_cloud_ref_on_bundle_suffix(self) -> None:
        # A .apk hosted on cloudfront is more importantly a mobile bundle;
        # apk_url still wins.
        assert _classify_seed_value("https://d123abc.cloudfront.net/build.apk") == "apk_url"

    def test_email_still_returns_email(self) -> None:
        assert _classify_seed_value("user@example.com") == "email"

    def test_phone_still_returns_phone(self) -> None:
        assert _classify_seed_value("+15551234567") == "phone"

    def test_username_still_returns_username(self) -> None:
        assert _classify_seed_value("@operator") == "username"

    def test_ipv4_still_returns_ipv4(self) -> None:
        assert _classify_seed_value("10.0.0.5") == "ipv4"


class TestSchemaAcceptsCloudRef:
    """The engagement_seeds CHECK constraint must accept cloud_ref rows."""

    def test_check_constraint_permits_cloud_ref_after_migration(self, tmp_path) -> None:
        from forge.db.migrations import run_migrations

        db_path = tmp_path / "eng.db"
        conn = sqlite3.connect(db_path)
        try:
            # bootstrap minimal engagements row to satisfy FK
            run_migrations(conn)
            conn.execute(
                "INSERT INTO engagements (id, name, operator, created_at) "
                "VALUES (1, 'test', 'kiro', CURRENT_TIMESTAMP)"
            )
            # Insert every seed_type from the CHECK list to prove none regressed.
            for seed_type in (
                "domain",
                "email",
                "phone",
                "username",
                "ipv4",
                "ipv6",
                "name",
                "company",
                "url",
                "apk_url",
                "subdomain",
                "cloud_ref",
                "other",
            ):
                conn.execute(
                    """
                    INSERT INTO engagement_seeds
                        (engagement_id, seed_value, seed_type)
                    VALUES (?, ?, ?)
                    """,
                    (1, f"value-for-{seed_type}", seed_type),
                )
            # A garbage seed_type must still be rejected.
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    """
                    INSERT INTO engagement_seeds
                        (engagement_id, seed_value, seed_type)
                    VALUES (?, ?, ?)
                    """,
                    (1, "garbage", "not_a_real_type"),
                )
        finally:
            conn.close()

    def test_pre_migration_engagement_seeds_row_survives_upgrade(self, tmp_path) -> None:
        """Legacy DB with only 12 seed types must round-trip through the
        migration without dropping rows or losing constraints."""
        from forge.db.migrations import run_migrations

        db_path = tmp_path / "legacy.db"
        conn = sqlite3.connect(db_path)
        try:
            # Pre-flight: create the old schema (no cloud_ref in CHECK)
            conn.executescript("""
                CREATE TABLE engagements (
                    id INTEGER PRIMARY KEY,
                    name TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE engagement_seeds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
                    seed_value TEXT NOT NULL,
                    seed_type TEXT NOT NULL CHECK (seed_type IN (
                        'domain','email','phone','username','ipv4','ipv6',
                        'name','company','url','apk_url','subdomain','other'
                    )),
                    source TEXT NOT NULL DEFAULT 'operator',
                    status TEXT NOT NULL DEFAULT 'pending',
                    depth INTEGER NOT NULL DEFAULT 0,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    parent_seed_id INTEGER,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (engagement_id, seed_type, seed_value)
                );
                CREATE TABLE _schema_version (
                    version INTEGER NOT NULL,
                    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO _schema_version (version) VALUES (25);
                INSERT INTO engagements (id, name) VALUES (1, 'legacy');
                INSERT INTO engagement_seeds (engagement_id, seed_value, seed_type)
                    VALUES (1, 'example.com', 'domain');
                INSERT INTO engagement_seeds (engagement_id, seed_value, seed_type)
                    VALUES (1, 'https://xyz.supabase.co/', 'url');
            """)
            conn.commit()

            # Migrate
            run_migrations(conn)

            # Legacy rows must still exist
            row_count = conn.execute("SELECT COUNT(*) FROM engagement_seeds").fetchone()[0]
            assert row_count == 2, f"expected 2 legacy rows preserved, got {row_count}"

            # cloud_ref must now be insertable
            conn.execute(
                "INSERT INTO engagement_seeds (engagement_id, seed_value, seed_type) "
                "VALUES (1, 'xyz.supabase.co', 'cloud_ref')"
            )
        finally:
            conn.close()
