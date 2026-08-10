from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema


def _bootstrap_engagement(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (?, ?, ?, 'ACTIVE', 'test-operator')
            """,
            (1001, "Convergence Fixture", json.dumps(["*.acme.example"])),
        )
        con.commit()
    finally:
        con.close()


def _seed_email_backlog(db_path: Path, count: int) -> None:
    con = sqlite3.connect(db_path)
    try:
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        emails = [
            (f"{alphabet[index // len(alphabet)]}{alphabet[index % len(alphabet)]}@acme.example",)
            for index in range(count)
        ]
        con.executemany(
            """
            INSERT INTO emails (engagement_id, email, domain, source)
            VALUES (1001, ?, 'acme.example', 'fixture')
            """,
            emails,
        )
        con.executemany(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth)
            VALUES (1001, ?, 'email', 'discovered', 'pending', 1)
            """,
            emails,
        )
        con.commit()
    finally:
        con.close()


def _run_dry_kill_chain(max_iter: int) -> None:
    from forge.cli import kill_chain

    kill_chain(
        seed="acme.example",
        related_seed=[],
        engagement="1001",
        max_iter=max_iter,
        tor=False,
        dry_run=True,
        attack_mode=False,
        skip_cloud=True,
        skip_keyscan=True,
        parallel_fanout=2,
        report_provider="template",
    )


def _email_chain_state(db_path: Path) -> tuple[int, dict[str, object]]:
    con = sqlite3.connect(db_path)
    try:
        processed_count = con.execute(
            """
            SELECT COUNT(DISTINCT es.seed_value)
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND sr.loop_name='fanout_e_chain'
              AND sr.status='skipped'
              AND es.seed_value IN (
                    SELECT email
                    FROM emails
                    WHERE engagement_id=1001
                      AND source='fixture'
              )
            """
        ).fetchone()[0]
        metadata = json.loads(
            con.execute(
                """
                SELECT metadata_json
                FROM engagement_runs
                WHERE engagement_id=1001
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()[0]
        )
        return int(processed_count), metadata
    finally:
        con.close()


def test_kill_chain_drains_capped_email_backlog_when_snapshot_is_stable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.delenv("FORGE_ROE_ID", raising=False)

    db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
    _bootstrap_engagement(db_path)
    _seed_email_backlog(db_path, 21)

    _run_dry_kill_chain(max_iter=2)

    processed_count, metadata = _email_chain_state(db_path)
    assert processed_count == 21
    assert metadata["processed_emails"] >= 21
    assert metadata["pending_work_total"] == 0
    assert metadata["last_iteration_stable"] is True


def test_kill_chain_preserves_pending_backlog_when_max_iterations_exhaust(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.delenv("FORGE_ROE_ID", raising=False)

    db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
    _bootstrap_engagement(db_path)
    _seed_email_backlog(db_path, 41)

    _run_dry_kill_chain(max_iter=2)

    processed_count, metadata = _email_chain_state(db_path)
    assert processed_count == 40
    assert metadata["processed_emails"] == 40
    assert metadata["pending_work_counts"]["emails"] == 1
    assert metadata["pending_work_total"] == 1
    assert metadata["last_iteration_stable"] is False


def test_keyscan_discovered_org_uses_schema_allowed_seed_source(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.delenv("FORGE_ROE_ID", raising=False)

    db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
    _bootstrap_engagement(db_path)
    manifest_path = tmp_path / "roe-scope.json"
    manifest_path.write_text(
        json.dumps(
            {
                "roe_id": "ROE-TEST-2026-07",
                "domains": ["acme.example", "*.acme.example"],
                "authorized_seeds": ["acme.example"],
            }
        ),
        encoding="utf-8",
    )

    import forge.cli as cli

    def html_batch(specs, *_args, **_kwargs):  # noqa: ANN001
        return [
            '<a href="https://github.com/acmeidentity">identity</a>'
            if (urlparse(spec.url).hostname or "").lower() == "acme.example"
            else ""
            for spec in specs
        ]

    def callable_batch(items, worker, **kwargs):  # noqa: ANN001, ANN003
        label = str(kwargs.get("progress_label") or "")
        if "DNS enrichment" in label:
            return [
                {"root_domain": item, "queried_hosts": [], "cname_targets": []} for item in items
            ]
        if "whois/RDAP" in label:
            return [{"root_domain": item, "rdap": {}} for item in items]
        if "Wayback CDX" in label:
            return [{"root_domain": item, "urls": [], "url_metadata": {}} for item in items]
        return [worker(item) for item in items]

    monkeypatch.setattr(cli, "_run_html_fetch_batch", html_batch)
    monkeypatch.setattr(cli, "_run_callable_batch", callable_batch)
    monkeypatch.setattr(
        cli,
        "_run_forge_module_subprocess",
        lambda argv, **_kwargs: subprocess.CompletedProcess(argv, 0, "", ""),
    )

    cli.kill_chain(
        seed="acme.example",
        related_seed=[],
        engagement="1001",
        max_iter=1,
        tor=False,
        dry_run=False,
        attack_mode=False,
        roe_id="ROE-TEST-2026-07",
        scope_manifest=str(manifest_path),
        skip_cloud=True,
        skip_keyscan=False,
        parallel_fanout=1,
        report_provider="template",
        report_max_loops=0,
    )

    keyscan_seed = "acme.example::github_org::acmeidentity"
    con = sqlite3.connect(db_path)
    try:
        seed = con.execute(
            """
            SELECT source, metadata_json
            FROM engagement_seeds
            WHERE engagement_id=1001
              AND seed_value=?
            """,
            (keyscan_seed,),
        ).fetchone()
        assert seed is not None
        assert seed[0] == "cross_reference"

        keyscan_run = con.execute(
            """
            SELECT sr.metadata_json
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND sr.loop_name='fanout_f_keyscan'
              AND es.seed_value=?
              AND sr.status='completed'
            LIMIT 1
            """,
            (keyscan_seed,),
        ).fetchone()
        assert keyscan_run is not None
        keyscan_metadata = json.loads(keyscan_run[0])
        assert keyscan_metadata["origin"] == "keyscan_org"
        assert keyscan_metadata["query_domain"] == "acme.example"
        assert keyscan_metadata["github_org"] == "acmeidentity"
    finally:
        con.close()
