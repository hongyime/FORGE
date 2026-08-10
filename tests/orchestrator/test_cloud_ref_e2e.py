"""End-to-end cloud_ref persistence + classifier + consumer round-trip.

Task 4 slice 4/6. Proves that a ``cloud_ref`` seed inserted into a fresh
engagement DB flows through every pipeline stage without silently being
coerced back to ``url`` or ``other``:

* schema accepts the row (migration applied)
* classifier tags identical-value input as ``cloud_ref``
* provider_url_seed_type mirrors the classifier
* URL-family SQL filters retrieve the row
* graph/display consumers route it correctly
"""

from __future__ import annotations

import sqlite3

import pytest


CLOUD_REF_HOSTNAMES = (
    "myapp.supabase.co",
    "https://myapp.firebaseio.com/",
    "https://bucket.s3.amazonaws.com/",
    "acct.blob.core.windows.net",
    "https://myapp.vercel.app/",
)


@pytest.fixture
def cloud_ref_db(tmp_path):
    """Fresh engagement DB with a cloud_ref seed inserted."""
    from forge.db.migrations import run_migrations

    db_path = tmp_path / "engagement.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    run_migrations(conn)
    conn.execute("INSERT INTO engagements (id, name, operator) VALUES (1, 'cloud_ref_e2e', 'kiro')")
    for host in CLOUD_REF_HOSTNAMES:
        conn.execute(
            "INSERT INTO engagement_seeds "
            "(engagement_id, seed_value, seed_type, source, status) "
            "VALUES (?, ?, 'cloud_ref', 'operator', 'completed')",
            (1, host),
        )
    conn.commit()
    yield conn
    conn.close()


class TestCloudRefRoundTrip:
    def test_cloud_ref_rows_persist_at_expected_count(
        self, cloud_ref_db: sqlite3.Connection
    ) -> None:
        count = cloud_ref_db.execute(
            "SELECT COUNT(*) FROM engagement_seeds "
            "WHERE engagement_id = 1 AND seed_type = 'cloud_ref'"
        ).fetchone()[0]
        assert count == len(CLOUD_REF_HOSTNAMES)

    def test_classifier_and_provider_url_agree_on_all_hosts(self) -> None:
        from forge.engagement_orchestrator import _classify_seed_value
        from forge.utils.intel.provider_urls import provider_url_seed_type

        for host in CLOUD_REF_HOSTNAMES:
            classifier_verdict = _classify_seed_value(host)
            assert classifier_verdict == "cloud_ref", (
                f"classifier for {host!r} returned {classifier_verdict!r}"
            )
            if host.startswith("http"):
                provider_verdict = provider_url_seed_type(host)
                assert provider_verdict == "cloud_ref", (
                    f"provider_url_seed_type for {host!r} returned {provider_verdict!r}"
                )

    def test_url_family_filter_finds_cloud_ref(self, cloud_ref_db: sqlite3.Connection) -> None:
        rows = cloud_ref_db.execute(
            """
            SELECT seed_value FROM engagement_seeds
            WHERE engagement_id = ?
              AND seed_type IN ('url', 'apk_url', 'cloud_ref')
            """,
            (1,),
        ).fetchall()
        assert len(rows) == len(CLOUD_REF_HOSTNAMES)
        seed_values = {row["seed_value"] for row in rows}
        for host in CLOUD_REF_HOSTNAMES:
            assert host in seed_values

    def test_domain_family_filter_also_finds_cloud_ref(
        self, cloud_ref_db: sqlite3.Connection
    ) -> None:
        rows = cloud_ref_db.execute(
            """
            SELECT seed_value FROM engagement_seeds
            WHERE engagement_id = ?
              AND seed_type IN ('domain', 'subdomain', 'cloud_ref')
              AND COALESCE(status, 'pending') != 'failed'
            """,
            (1,),
        ).fetchall()
        assert len(rows) == len(CLOUD_REF_HOSTNAMES)

    def test_graph_node_type_is_host(self, cloud_ref_db: sqlite3.Connection) -> None:
        from forge.reporting.dashboard import _seed_graph_node_type

        rows = cloud_ref_db.execute(
            "SELECT seed_type FROM engagement_seeds WHERE engagement_id = 1"
        ).fetchall()
        for row in rows:
            assert _seed_graph_node_type(row["seed_type"]) == "HOST"

    def test_safe_display_renders_all_hosts(self) -> None:
        from forge.phase6.report_synthesizer import ContextBuilder

        for host in CLOUD_REF_HOSTNAMES:
            display = ContextBuilder._safe_seed_display_value(host, "cloud_ref")
            assert display, f"empty display for {host!r}"
            assert len(display) <= 160

    def test_unique_constraint_prevents_dup(self, cloud_ref_db: sqlite3.Connection) -> None:
        """Reinserting the same (engagement, type, value) tuple must fail."""
        with pytest.raises(sqlite3.IntegrityError):
            cloud_ref_db.execute(
                "INSERT INTO engagement_seeds "
                "(engagement_id, seed_value, seed_type) VALUES (?, ?, 'cloud_ref')",
                (1, CLOUD_REF_HOSTNAMES[0]),
            )
