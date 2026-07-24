import json
import sqlite3
import subprocess
from pathlib import Path

from tests.phase1.test_engagement_orchestrator import _bootstrap_engagement


def _direct_batch(items, worker, *, max_workers, progress_label=None, progress_callback=None):  # noqa: ANN001
    del max_workers, progress_label, progress_callback
    return [worker(item) for item in items]


def _write_report_if_requested(module_argv: tuple[str, ...], tmp_path: Path) -> None:
    if module_argv[:2] != ("report", "generate") or "--output" not in module_argv:
        return
    report_path = tmp_path / module_argv[module_argv.index("--output") + 1]
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("# Final report\n", encoding="utf-8")


def test_kill_chain_retries_failed_recursive_seed_fanouts_only(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    manifest_path = tmp_path / "roe-scope.json"
    manifest_path.write_text(
        json.dumps(
            {
                "roe_id": "ROE-TEST-2026-07",
                "authorized_seeds": [
                    "@retryuser",
                    "@okuser",
                    "+15550000001",
                    "+15550000002",
                ],
            }
        ),
        encoding="utf-8",
    )

    module_attempts: list[tuple[str, ...]] = []

    def _fake_module_subprocess(cmd_argv, **kwargs):  # noqa: ANN001
        del kwargs
        module_argv = tuple(str(item) for item in cmd_argv)
        if module_argv[:2] in {("osint", "usernames"), ("osint", "phone")}:
            module_attempts.append(module_argv)
        _write_report_if_requested(module_argv, tmp_path)
        if "retryuser" in module_argv or "+15550000001" in module_argv:
            return subprocess.CompletedProcess(
                ["forge", *module_argv],
                1,
                stdout="",
                stderr="simulated recursive fan-out failure",
            )
        return subprocess.CompletedProcess(["forge", *module_argv], 0, stdout="ok\n", stderr="")

    monkeypatch.setattr("forge.cli._run_forge_module_subprocess", _fake_module_subprocess)
    monkeypatch.setattr("forge.cli._run_inprocess_batch", _direct_batch)

    from forge.cli import kill_chain

    kill_chain(
        seed="@retryuser",
        related_seed=["@okuser", "+15550000001", "+15550000002"],
        engagement="1001",
        max_iter=2,
        tor=False,
        dry_run=False,
        attack_mode=False,
        roe_id="ROE-TEST-2026-07",
        scope_manifest=str(manifest_path),
        skip_cloud=True,
        skip_keyscan=True,
        parallel_fanout=1,
        report_provider="template",
    )

    username_attempts = [
        argv[argv.index("--usernames") + 1]
        for argv in module_attempts
        if argv[:2] == ("osint", "usernames")
    ]
    phone_attempts = [
        argv[argv.index("--number") + 1]
        for argv in module_attempts
        if argv[:2] == ("osint", "phone")
    ]
    assert username_attempts.count("okuser") == 1
    assert username_attempts.count("retryuser") == 2
    assert phone_attempts.count("+15550000002") == 1
    assert phone_attempts.count("+15550000001") == 2

    db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
    con = sqlite3.connect(db_path)
    try:
        failed_runs = con.execute(
            """
            SELECT es.seed_value, sr.loop_name, sr.status, sr.error, sr.metadata_json
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND sr.status='failed'
              AND sr.loop_name IN ('fanout_k_seed_username', 'fanout_l_seed_phone')
            ORDER BY sr.id
            """
        ).fetchall()
    finally:
        con.close()

    failed_by_seed = {
        str(seed_value): [
            (str(loop_name), str(error or ""), json.loads(str(metadata_json or "{}")))
            for row_seed, loop_name, _status, error, metadata_json in failed_runs
            if str(row_seed) == str(seed_value)
        ]
        for seed_value in {"@retryuser", "+15550000001"}
    }
    assert len(failed_by_seed["@retryuser"]) == 2
    assert len(failed_by_seed["+15550000001"]) == 2
    assert all(
        item[2]["returncode"] == 1 and "simulated recursive fan-out failure" in item[1]
        for runs in failed_by_seed.values()
        for item in runs
    )


def test_kill_chain_retries_failed_ip_name_company_fanouts_only(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    manifest_path = tmp_path / "roe-scope.json"
    manifest_path.write_text(
        json.dumps(
            {
                "roe_id": "ROE-TEST-2026-07",
                "ip_ranges": ["203.0.113.0/24"],
                "authorized_seeds": [
                    "Alice Example",
                    "Bob Example",
                    "Acme Corp",
                    "Orbit LLC",
                ],
            }
        ),
        encoding="utf-8",
    )

    attempts: list[tuple[str, str]] = []
    failing_values = {"203.0.113.50", "Alice Example", "Acme Corp"}

    def _fake_module_subprocess(cmd_argv, **kwargs):  # noqa: ANN001
        del kwargs
        module_argv = tuple(str(item) for item in cmd_argv)
        value = ""
        kind = ""
        if module_argv[:2] == ("osint", "shodan") and "--target" in module_argv:
            kind = "ip"
            value = module_argv[module_argv.index("--target") + 1]
        elif module_argv[:2] == ("osint", "name") and "--name" in module_argv:
            value = module_argv[module_argv.index("--name") + 1]
            kind = "company" if value.endswith(("Corp", "LLC")) else "name"
        if kind:
            attempts.append((kind, value))
        _write_report_if_requested(module_argv, tmp_path)
        if value in failing_values:
            return subprocess.CompletedProcess(
                ["forge", *module_argv],
                1,
                stdout="",
                stderr="simulated recursive fan-out failure",
            )
        return subprocess.CompletedProcess(["forge", *module_argv], 0, stdout="ok\n", stderr="")

    monkeypatch.setattr("forge.cli._run_forge_module_subprocess", _fake_module_subprocess)
    monkeypatch.setattr("forge.cli._run_inprocess_batch", _direct_batch)

    from forge.cli import kill_chain

    kill_chain(
        seed="203.0.113.50",
        related_seed=[
            "203.0.113.51",
            "Alice Example",
            "Bob Example",
            "Acme Corp",
            "Orbit LLC",
        ],
        engagement="1001",
        max_iter=2,
        tor=False,
        dry_run=False,
        attack_mode=False,
        roe_id="ROE-TEST-2026-07",
        scope_manifest=str(manifest_path),
        skip_cloud=True,
        skip_keyscan=True,
        parallel_fanout=1,
        report_provider="template",
    )

    assert attempts.count(("ip", "203.0.113.50")) == 2
    assert attempts.count(("ip", "203.0.113.51")) == 1
    assert attempts.count(("name", "Alice Example")) == 2
    assert attempts.count(("name", "Bob Example")) == 1
    assert attempts.count(("company", "Acme Corp")) == 2
    assert attempts.count(("company", "Orbit LLC")) == 1


def test_kill_chain_retries_failed_social_handle_chain_only(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    manifest_path = tmp_path / "roe-scope.json"
    manifest_path.write_text(
        json.dumps(
            {
                "roe_id": "ROE-TEST-2026-07",
                "authorized_seeds": ["@operator"],
            }
        ),
        encoding="utf-8",
    )

    db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    _bootstrap_engagement(db_path)
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS social_profiles (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'instagram',
                profile_data TEXT,
                queried_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, email, source)
            )
            """
        )
        con.executemany(
            """
            INSERT INTO social_profiles (engagement_id, email, source, profile_data)
            VALUES (?, ?, ?, ?)
            """,
            [
                (1001, "fail@acme.example", "fixture_fail", json.dumps({"handle": "failhandle"})),
                (1001, "ok@acme.example", "fixture_ok", json.dumps({"handle": "okhandle"})),
            ],
        )
        con.commit()
    finally:
        con.close()

    attempts: list[tuple[str, str]] = []

    def _fake_module_subprocess(cmd_argv, **kwargs):  # noqa: ANN001
        del kwargs
        module_argv = tuple(str(item) for item in cmd_argv)
        handle = ""
        kind = ""
        if module_argv[:2] == ("osint", "usernames") and "--usernames" in module_argv:
            handle = module_argv[module_argv.index("--usernames") + 1]
            kind = "sherlock"
        elif module_argv[:2] == ("osint", "instagram") and "--username" in module_argv:
            handle = module_argv[module_argv.index("--username") + 1]
            kind = "instagram"
        if handle in {"failhandle", "okhandle"}:
            attempts.append((kind, handle))
        _write_report_if_requested(module_argv, tmp_path)
        if handle == "failhandle":
            return subprocess.CompletedProcess(
                ["forge", *module_argv],
                1,
                stdout="",
                stderr="simulated social handle failure",
            )
        return subprocess.CompletedProcess(["forge", *module_argv], 0, stdout="ok\n", stderr="")

    monkeypatch.setattr("forge.cli._run_forge_module_subprocess", _fake_module_subprocess)
    monkeypatch.setattr("forge.cli._run_inprocess_batch", _direct_batch)

    from forge.cli import kill_chain

    kill_chain(
        seed="@operator",
        related_seed=[],
        engagement="1001",
        max_iter=2,
        tor=False,
        dry_run=False,
        attack_mode=False,
        roe_id="ROE-TEST-2026-07",
        scope_manifest=str(manifest_path),
        skip_cloud=True,
        skip_keyscan=True,
        parallel_fanout=1,
        report_provider="template",
    )

    assert attempts.count(("sherlock", "failhandle")) >= 2
    assert attempts.count(("instagram", "failhandle")) == 2
    assert attempts.count(("sherlock", "okhandle")) == 1
    assert attempts.count(("instagram", "okhandle")) == 1


def test_kill_chain_retries_failed_executable_cloud_scan_refs_only(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    manifest_path = tmp_path / "roe-scope.json"
    manifest_path.write_text(
        json.dumps(
            {
                "roe_id": "ROE-TEST-2026-07",
                "domains": [
                    "acme.example",
                    "alpha.supabase.co",
                    "bravo.firebaseio.com",
                    "echo.netlify.app",
                ],
                "urls": [
                    "https://alpha.supabase.co",
                    "https://bravo.firebaseio.com",
                    "https://echo.netlify.app",
                ],
                "authorized_seeds": ["acme.example"],
            }
        ),
        encoding="utf-8",
    )

    cloud_attempts: list[tuple[str, str]] = []

    def _fake_module_subprocess(cmd_argv, **kwargs):  # noqa: ANN001
        del kwargs
        module_argv = tuple(str(item) for item in cmd_argv)
        if module_argv[:2] in {("cloud", "supabase"), ("cloud", "firebase")}:
            project_ref = module_argv[module_argv.index("--project-ref") + 1]
            cloud_attempts.append((module_argv[1], project_ref))
            if module_argv[:2] == ("cloud", "supabase"):
                return subprocess.CompletedProcess(
                    ["forge", *module_argv],
                    1,
                    stdout="",
                    stderr="simulated cloud scan failure",
                )
        _write_report_if_requested(module_argv, tmp_path)
        return subprocess.CompletedProcess(["forge", *module_argv], 0, stdout="ok\n", stderr="")

    def _fake_html_batch(specs, *_args, progress_label=None, **_kwargs):  # noqa: ANN001
        if str(progress_label or "").endswith(".D cloud+HTML fetch"):
            return [
                (
                    "<html>"
                    "https://alpha.supabase.co "
                    "https://bravo.firebaseio.com "
                    "https://echo.netlify.app"
                    "</html>"
                )
                for _ in specs
            ]
        if str(progress_label or "").endswith((".D2 passive text fetch", ".D5 URL surface fetch")):
            return ["" for _ in specs]
        raise AssertionError(f"unexpected html batch label: {progress_label}")

    def _fake_callable_batch(items, worker, *, max_workers, progress_label=None, progress_callback=None):  # noqa: ANN001
        del worker, max_workers
        if progress_callback is not None and progress_label:
            progress_callback(
                progress_label,
                {
                    "total": len(items),
                    "workers": min(1, len(items)) if items else 0,
                    "running": 0,
                    "pending": 0,
                    "queue_depth": 0,
                    "completed": len(items),
                    "failed": 0,
                    "eta_seconds": 0.0,
                },
            )
        progress_name = str(progress_label or "")
        if progress_name.endswith(".G DNS enrichment"):
            return [
                {
                    "root_domain": str(item),
                    "queried_hosts": [str(item)],
                    "cname_targets": [],
                    "signals": [],
                }
                for item in items
            ]
        if progress_name.endswith(".H whois/RDAP"):
            return [{"root_domain": str(item), "rdap": {}} for item in items]
        if progress_name.endswith(".I Wayback CDX"):
            return [{"root_domain": str(item), "urls": []} for item in items]
        raise AssertionError(f"unexpected callable batch label: {progress_label}")

    def _fake_cloud_validation_batch(  # noqa: ANN001
        engagement_id,
        items,
        db_path,
        *,
        max_workers,
        progress_label=None,
        progress_callback=None,
        **_kwargs,
    ):
        del engagement_id, db_path, max_workers
        if progress_callback is not None and progress_label:
            progress_callback(
                progress_label,
                {
                    "total": len(items),
                    "workers": min(1, len(items)) if items else 0,
                    "running": 0,
                    "pending": 0,
                    "queue_depth": 0,
                    "completed": len(items),
                    "failed": 0,
                    "eta_seconds": 0.0,
                },
            )
        return {
            "results": [
                {
                    "status": "success",
                    "validation_status": "UNVERIFIED",
                    "validation_method": "stub",
                }
                for _ in items
            ]
        }

    monkeypatch.setattr("forge.cli._run_forge_module_subprocess", _fake_module_subprocess)
    monkeypatch.setattr("forge.cli._run_html_fetch_batch", _fake_html_batch)
    monkeypatch.setattr("forge.cli._run_callable_batch", _fake_callable_batch)
    monkeypatch.setattr(
        "forge.phase4.cloud_validate.run_cloud_asset_validate_batch",
        _fake_cloud_validation_batch,
    )

    from forge.cli import kill_chain

    kill_chain(
        seed="acme.example",
        engagement="1001",
        max_iter=2,
        tor=False,
        dry_run=False,
        attack_mode=False,
        roe_id="ROE-TEST-2026-07",
        scope_manifest=str(manifest_path),
        skip_cloud=False,
        skip_keyscan=True,
        parallel_fanout=1,
        report_provider="template",
    )

    assert cloud_attempts.count(("supabase", "alpha")) == 2
    assert cloud_attempts.count(("firebase", "bravo")) == 1
    assert all(project_ref != "echo" for _command, project_ref in cloud_attempts)

    db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
    con = sqlite3.connect(db_path)
    try:
        failed_rows = con.execute(
            """
            SELECT es.seed_value, sr.status, sr.error, sr.metadata_json
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND sr.loop_name='fanout_j_cloud_scan'
              AND es.seed_value='supabase:alpha'
            ORDER BY sr.id
            """
        ).fetchall()
        skipped_rows = con.execute(
            """
            SELECT es.seed_value, sr.status
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND sr.loop_name='fanout_j_cloud_scan'
              AND es.seed_value='netlify:echo'
            ORDER BY sr.id
            """
        ).fetchall()
    finally:
        con.close()

    assert len(failed_rows) == 2
    assert all(row[1] == "failed" for row in failed_rows)
    assert all("simulated cloud scan failure" in str(row[2] or "") for row in failed_rows)
    assert all(json.loads(str(row[3] or "{}"))["returncode"] == 1 for row in failed_rows)
    assert skipped_rows == []
