import json
import sqlite3
import subprocess
from pathlib import Path

from forge.engagement_orchestrator import ArtifactDownloadResult, ArtifactQueueProcessor
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


def _host_from_url(url: str) -> str:
    return url.split("://", 1)[1].split("/", 1)[0].lower()


def _emit_done_progress(
    items: object,
    *,
    progress_label: str | None,
    progress_callback,
) -> None:  # noqa: ANN001
    if progress_callback is None or not progress_label:
        return
    total = len(items) if hasattr(items, "__len__") else 0
    progress_callback(
        progress_label,
        {
            "total": total,
            "workers": min(1, total) if total else 0,
            "running": 0,
            "pending": 0,
            "queue_depth": 0,
            "completed": total,
            "failed": 0,
            "eta_seconds": 0.0,
        },
    )


def _install_host_surface_test_mocks(
    monkeypatch,
    tmp_path: Path,
    *,
    fetched_hosts_by_label: dict[str, list[str]] | None = None,
    fetched_hosts: list[str] | None = None,
) -> None:  # noqa: ANN001
    def _fake_module_subprocess(cmd_argv, **kwargs):  # noqa: ANN001
        del kwargs
        module_argv = tuple(str(item) for item in cmd_argv)
        _write_report_if_requested(module_argv, tmp_path)
        return subprocess.CompletedProcess(["forge", *module_argv], 0, stdout="ok\n", stderr="")

    def _fake_html_batch(specs, *_args, progress_label=None, **_kwargs):  # noqa: ANN001
        label = str(progress_label or "")
        if label.endswith(".D cloud+HTML fetch"):
            hosts = [_host_from_url(str(spec.url)) for spec in specs]
            if fetched_hosts_by_label is not None:
                fetched_hosts_by_label.setdefault(label, []).extend(hosts)
            if fetched_hosts is not None:
                fetched_hosts.extend(hosts)
            return ["<html><title>ok</title></html>" for _ in specs]
        if label.endswith((".D2 passive text fetch", ".D5 URL surface fetch")):
            return ["" for _ in specs]
        raise AssertionError(f"unexpected html batch label: {progress_label}")

    def _fake_callable_batch(items, worker, *, max_workers, progress_label=None, progress_callback=None):  # noqa: ANN001
        del worker, max_workers
        _emit_done_progress(
            items,
            progress_label=progress_label,
            progress_callback=progress_callback,
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

    def _fake_ptr_lookup_batch(ips, lookup_func, *, max_workers, progress_label=None, progress_callback=None):  # noqa: ANN001
        del lookup_func, max_workers
        _emit_done_progress(
            ips,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )
        return [(str(ip), "") for ip in ips]

    monkeypatch.setattr("forge.cli._run_forge_module_subprocess", _fake_module_subprocess)
    monkeypatch.setattr("forge.cli._run_html_fetch_batch", _fake_html_batch)
    monkeypatch.setattr("forge.cli._run_callable_batch", _fake_callable_batch)
    monkeypatch.setattr("forge.cli._run_inprocess_batch", _direct_batch)
    monkeypatch.setattr("forge.cli._run_ptr_lookup_batch", _fake_ptr_lookup_batch)


def _latest_run_metadata(db_path: Path) -> dict[str, object]:
    con = sqlite3.connect(db_path)
    try:
        row = con.execute(
            """
            SELECT metadata_json
            FROM engagement_runs
            WHERE engagement_id=1001
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
    finally:
        con.close()
    return json.loads(str((row or ["{}"])[0] or "{}"))


def test_artifact_queue_retries_failed_rows_until_attempts_exhausted(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path)
    source_url = "https://downloads.acme.example/transient.apk"
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, artifact_type, discovered_from, status, max_attempts)
            VALUES
                (1001, ?, 'apk', 'engagement_seed', 'queued', 2)
            """,
            (source_url,),
        )
        con.commit()
    finally:
        con.close()

    attempts: list[str] = []

    def _fake_downloads(self, requests, **_kwargs):  # noqa: ANN001
        del self
        attempts.extend(str(request.source_url) for request in requests)
        return [
            ArtifactDownloadResult(
                artifact_id=request.artifact_id,
                source_url=request.source_url,
                artifact_type=request.artifact_type,
                error="simulated transient download failure",
            )
            for request in requests
        ]

    monkeypatch.setattr(ArtifactQueueProcessor, "_download_remote_artifacts", _fake_downloads)

    processor = ArtifactQueueProcessor(db_path, 1001)
    first = processor.process()
    second = processor.process()
    exhausted = processor.process()

    assert first.failed == 1
    assert second.failed == 1
    assert exhausted.failed == 0
    assert attempts == [source_url, source_url]

    con = sqlite3.connect(db_path)
    try:
        row = con.execute(
            """
            SELECT status, attempt_count, max_attempts, notes
            FROM artifact_queue
            WHERE engagement_id=1001 AND source_url=?
            """,
            (source_url,),
        ).fetchone()
    finally:
        con.close()

    assert row == ("failed", 2, 2, "simulated transient download failure")


def test_kill_chain_known_host_surface_backlog_advances_beyond_first_batch(
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
                "domains": ["acme.example"],
                "authorized_seeds": ["acme.example"],
            }
        ),
        encoding="utf-8",
    )

    db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    _bootstrap_engagement(db_path)
    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context)
            VALUES (?, ?, ?, 'unknown', '{}')
            """,
            [
                (
                    1001,
                    f"198.51.100.{index + 1}",
                    f"host{index:02d}.acme.example",
                )
                for index in range(45)
            ],
        )
        con.commit()
    finally:
        con.close()

    fetched_hosts_by_label: dict[str, list[str]] = {}
    _install_host_surface_test_mocks(
        monkeypatch,
        tmp_path,
        fetched_hosts_by_label=fetched_hosts_by_label,
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
        skip_cloud=True,
        skip_keyscan=True,
        parallel_fanout=1,
        report_provider="template",
    )

    first_hosts = set(fetched_hosts_by_label["1.D cloud+HTML fetch"])
    second_hosts = set(fetched_hosts_by_label["2.D cloud+HTML fetch"])
    assert "acme.example" in first_hosts
    assert "downloads.acme.example" in first_hosts
    assert "host00.acme.example" in first_hosts
    assert "host17.acme.example" in first_hosts
    assert "host18.acme.example" not in first_hosts
    assert "host18.acme.example" in second_hosts
    assert "host37.acme.example" in second_hosts
    assert "host00.acme.example" not in second_hosts

    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            """
            SELECT es.seed_value, sr.status, sr.metadata_json
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND sr.loop_name='fanout_d_host_surface'
            ORDER BY sr.id
            """
        ).fetchall()
    finally:
        con.close()

    completed_hosts = {str(seed_value) for seed_value, status, _meta in rows if status == "completed"}
    assert len(completed_hosts) == 40
    assert "host37.acme.example" in completed_hosts
    assert "host38.acme.example" not in completed_hosts
    assert all(
        json.loads(str(metadata_json or "{}"))["fetch_status"] == "payload"
        for _seed_value, _status, metadata_json in rows
    )


def test_kill_chain_resume_prioritizes_retryable_host_surface_rows(
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
                "domains": ["acme.example"],
                "authorized_seeds": ["acme.example"],
            }
        ),
        encoding="utf-8",
    )

    db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    _bootstrap_engagement(db_path)
    stale_host = "zz-retry.acme.example"
    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context)
            VALUES (?, ?, ?, 'unknown', '{}')
            """,
            [
                (1001, f"198.51.100.{index + 1}", f"host{index:02d}.acme.example")
                for index in range(25)
            ]
            + [(1001, "198.51.100.250", stale_host)],
        )
        cur = con.execute(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
            VALUES (?, ?, 'subdomain', 'discovered', 'running', 1, 0.8, '{}')
            """,
            (1001, stale_host),
        )
        stale_seed_id = int(cur.lastrowid)
        con.execute(
            """
            INSERT INTO seed_runs
                (engagement_id, seed_id, loop_name, status, input_count, output_count,
                 metadata_json, started_at)
            VALUES (?, ?, 'fanout_d_host_surface', 'running', 1, 0, '{"iteration":0}',
                    '2026-07-09 08:00:00')
            """,
            (1001, stale_seed_id),
        )
        con.commit()
    finally:
        con.close()

    fetched_hosts: list[str] = []
    _install_host_surface_test_mocks(
        monkeypatch,
        tmp_path,
        fetched_hosts=fetched_hosts,
    )

    from forge.cli import kill_chain

    kill_chain(
        seed="acme.example",
        engagement="1001",
        max_iter=1,
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

    first_batch_hosts = set(fetched_hosts)
    assert stale_host in first_batch_hosts
    assert "host16.acme.example" in first_batch_hosts
    assert "host17.acme.example" not in first_batch_hosts

    metadata = _latest_run_metadata(db_path)
    pending_counts = metadata.get("pending_work_counts", {})
    assert pending_counts["host_surfaces"] >= 1
    assert metadata["last_iteration_stable"] is False

    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            """
            SELECT sr.status, sr.error, sr.metadata_json
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND sr.loop_name='fanout_d_host_surface'
              AND es.seed_value=?
            ORDER BY sr.id
            """,
            (stale_host,),
        ).fetchall()
    finally:
        con.close()

    assert [row[0] for row in rows] == ["failed", "completed"]
    assert "abandoned before explicit completion" in str(rows[0][1] or "")
    completed_meta = json.loads(str(rows[1][2] or "{}"))
    assert completed_meta["fetch_status"] == "payload"
    assert completed_meta["hostname"] == stale_host


def test_kill_chain_skips_over_depth_persisted_recursive_seeds(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_KILL_CHAIN_SYNTHESIS_DEPTH", "1")
    manifest_path = tmp_path / "roe-scope.json"
    over_depth_values = {
        "deep@acme.example",
        "@deepuser",
        "+15550000009",
        "203.0.113.55",
        "2001:db8::55",
        "Alice Example",
        "Acme Deep Corp",
        "https://portal.acme.example/deep",
    }
    manifest_path.write_text(
        json.dumps(
            {
                "roe_id": "ROE-TEST-2026-07",
                "domains": ["acme.example"],
                "urls": ["https://portal.acme.example/deep"],
                "ip_ranges": ["203.0.113.0/24", "2001:db8::/32"],
                "authorized_seeds": ["acme.example", *sorted(over_depth_values)],
            }
        ),
        encoding="utf-8",
    )

    db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    _bootstrap_engagement(db_path)
    over_depth_rows = [
        ("deep@acme.example", "email"),
        ("@deepuser", "username"),
        ("+15550000009", "phone"),
        ("203.0.113.55", "ipv4"),
        ("2001:db8::55", "ipv6"),
        ("Alice Example", "name"),
        ("Acme Deep Corp", "company"),
        ("https://portal.acme.example/deep", "url"),
    ]
    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO engagement_seeds (
                engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json
            )
            VALUES (1001, ?, ?, 'cross_reference', 'pending', 2, 0.9, '{}')
            """,
            over_depth_rows,
        )
        con.commit()
    finally:
        con.close()

    module_attempts: list[tuple[str, ...]] = []
    d5_fetches: list[str] = []

    def _fake_module_subprocess(cmd_argv, **kwargs):  # noqa: ANN001
        del kwargs
        module_argv = tuple(str(item) for item in cmd_argv)
        module_attempts.append(module_argv)
        _write_report_if_requested(module_argv, tmp_path)
        return subprocess.CompletedProcess(["forge", *module_argv], 0, stdout="ok\n", stderr="")

    def _fake_html_batch(specs, *_args, progress_label=None, **_kwargs):  # noqa: ANN001
        if str(progress_label or "").endswith(".D5 URL surface fetch"):
            d5_fetches.extend(str(spec.url) for spec in specs)
        return ["" for _ in specs]

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

    def _fake_ptr_lookup_batch(ips, lookup_func, *, max_workers, progress_label=None, progress_callback=None):  # noqa: ANN001
        del lookup_func, max_workers
        if progress_callback is not None and progress_label:
            progress_callback(
                progress_label,
                {
                    "total": len(ips),
                    "workers": min(1, len(ips)) if ips else 0,
                    "running": 0,
                    "pending": 0,
                    "queue_depth": 0,
                    "completed": len(ips),
                    "failed": 0,
                    "eta_seconds": 0.0,
                },
            )
        return [(str(ip), "") for ip in ips]

    monkeypatch.setattr("forge.cli._run_forge_module_subprocess", _fake_module_subprocess)
    monkeypatch.setattr("forge.cli._run_html_fetch_batch", _fake_html_batch)
    monkeypatch.setattr("forge.cli._run_callable_batch", _fake_callable_batch)
    monkeypatch.setattr("forge.cli._run_inprocess_batch", _direct_batch)
    monkeypatch.setattr("forge.cli._run_ptr_lookup_batch", _fake_ptr_lookup_batch)

    from forge.cli import kill_chain

    kill_chain(
        seed="acme.example",
        engagement="1001",
        max_iter=1,
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

    attempted_text = "\n".join(" ".join(attempt) for attempt in module_attempts)
    assert "deep@acme.example" not in attempted_text
    assert "deepuser" not in attempted_text
    assert "+15550000009" not in attempted_text
    assert "203.0.113.55" not in attempted_text
    assert "2001:db8::55" not in attempted_text
    assert "Alice Example" not in attempted_text
    assert "Acme Deep Corp" not in attempted_text
    assert "https://portal.acme.example/deep" not in d5_fetches

    con = sqlite3.connect(db_path)
    try:
        seed_rows = con.execute(
            """
            SELECT seed_value, seed_type, depth
            FROM engagement_seeds
            WHERE engagement_id=1001
              AND depth=2
            """
        ).fetchall()
        receipt_rows = con.execute(
            """
            SELECT es.seed_value, es.seed_type, sr.loop_name, sr.status, sr.error, sr.metadata_json
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND sr.error='synthesis_depth_limit_exceeded'
            ORDER BY es.seed_type, es.seed_value
            """
        ).fetchall()
    finally:
        con.close()

    assert {(value, seed_type) for value, seed_type, _depth in seed_rows} == set(over_depth_rows)
    expected_receipts = {
        ("deep@acme.example", "email", "fanout_e_chain"),
        ("@deepuser", "username", "fanout_k_seed_username"),
        ("+15550000009", "phone", "fanout_l_seed_phone"),
        ("203.0.113.55", "ipv4", "fanout_o_seed_ip"),
        ("2001:db8::55", "ipv6", "fanout_o_seed_ip"),
        ("Alice Example", "name", "fanout_m_seed_name"),
        ("Acme Deep Corp", "company", "fanout_n_seed_company"),
        ("https://portal.acme.example/deep", "url", "fanout_d5_url_seed_html"),
    }
    assert {
        (seed_value, seed_type, loop_name)
        for seed_value, seed_type, loop_name, status, _error, _metadata_json in receipt_rows
        if status == "skipped"
    } == expected_receipts
    for _seed_value, _seed_type, _loop_name, _status, _error, metadata_json in receipt_rows:
        metadata = json.loads(str(metadata_json or "{}"))
        assert metadata["skip_reason"] == "synthesis_depth_limit_exceeded"
        assert metadata["skipped_before_dispatch"] is True
        assert metadata["seed_depth"] == 2
        assert metadata["synthesis_depth_limit"] == 1

    pending_counts = _latest_run_metadata(db_path).get("pending_work_counts", {})
    for key in (
        "emails",
        "url_seeds",
        "username_seeds",
        "phone_seeds",
        "ip_seeds",
        "name_seeds",
        "company_seeds",
    ):
        assert key not in pending_counts


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
    metadata = _latest_run_metadata(db_path)
    assert metadata["pending_work_counts"]["username_seeds"] == 1
    assert metadata["pending_work_counts"]["phone_seeds"] == 1
    assert metadata["pending_work_total"] >= 2
    assert metadata["last_iteration_stable"] is False


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
    db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
    metadata = _latest_run_metadata(db_path)
    assert metadata["pending_work_counts"]["ip_seeds"] == 1
    assert metadata["pending_work_counts"]["name_seeds"] == 1
    assert metadata["pending_work_counts"]["company_seeds"] == 1
    assert metadata["pending_work_total"] >= 3
    assert metadata["last_iteration_stable"] is False

    con = sqlite3.connect(db_path)
    try:
        failed_runs = con.execute(
            """
            SELECT es.seed_value, sr.loop_name, sr.status, sr.error, sr.metadata_json
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND sr.status='failed'
              AND sr.loop_name IN (
                  'fanout_o_seed_ip',
                  'fanout_m_seed_name',
                  'fanout_n_seed_company'
              )
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
        for seed_value in failing_values
    }
    assert len(failed_by_seed["203.0.113.50"]) == 2
    assert len(failed_by_seed["Alice Example"]) == 2
    assert len(failed_by_seed["Acme Corp"]) == 2
    assert all(
        item[2]["returncode"] == 1 and "simulated recursive fan-out failure" in item[1]
        for runs in failed_by_seed.values()
        for item in runs
    )


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
    metadata = _latest_run_metadata(db_path)
    assert metadata["pending_work_counts"]["social_handles"] == 1
    assert metadata["pending_work_total"] >= 1
    assert metadata["last_iteration_stable"] is False

    con = sqlite3.connect(db_path)
    try:
        failed_rows = con.execute(
            """
            SELECT sr.status, sr.error, sr.metadata_json
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND sr.loop_name='fanout_e5_chain'
              AND es.seed_value='failhandle'
            ORDER BY sr.id
            """
        ).fetchall()
        completed_rows = con.execute(
            """
            SELECT sr.status
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND sr.loop_name='fanout_e5_chain'
              AND es.seed_value='okhandle'
            ORDER BY sr.id
            """
        ).fetchall()
    finally:
        con.close()

    assert len(failed_rows) == 2
    assert all(row[0] == "failed" for row in failed_rows)
    assert all("social-handle fan-out modules failed" in str(row[1] or "") for row in failed_rows)
    assert all(1 in json.loads(str(row[2] or "{}"))["returncodes"] for row in failed_rows)
    assert completed_rows == [("completed",)]


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
    metadata = _latest_run_metadata(db_path)
    assert metadata["pending_work_counts"]["cloud_refs"] == 1
    assert metadata["pending_work_total"] >= 1
    assert metadata["last_iteration_stable"] is False
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
            SELECT es.seed_value, sr.status, sr.error, sr.metadata_json
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
    assert len(skipped_rows) == 1
    assert skipped_rows[0][0] == "netlify:echo"
    assert skipped_rows[0][1] == "skipped"
    assert skipped_rows[0][2] == "unsupported_cloud_service"
    skipped_metadata = json.loads(str(skipped_rows[0][3] or "{}"))
    assert skipped_metadata["unsupported_before_scan"] is True
    assert skipped_metadata["service"] == "netlify"
    assert skipped_metadata["ref"] == "echo"


def test_kill_chain_retries_failed_artifact_queue_rows_and_keeps_pending_work(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    manifest_path = tmp_path / "roe-scope.json"
    artifact_url = "https://downloads.acme.example/mobile.apk"
    manifest_path.write_text(
        json.dumps(
            {
                "roe_id": "ROE-TEST-2026-07",
                "domains": ["acme.example", "downloads.acme.example"],
                "urls": [artifact_url],
                "authorized_seeds": ["acme.example"],
            }
        ),
        encoding="utf-8",
    )

    download_attempts: list[str] = []

    def _fake_module_subprocess(cmd_argv, **kwargs):  # noqa: ANN001
        del kwargs
        module_argv = tuple(str(item) for item in cmd_argv)
        _write_report_if_requested(module_argv, tmp_path)
        return subprocess.CompletedProcess(["forge", *module_argv], 0, stdout="ok\n", stderr="")

    def _fake_html_batch(specs, *_args, progress_label=None, **_kwargs):  # noqa: ANN001
        if str(progress_label or "").endswith(".D cloud+HTML fetch"):
            return [f'<html><a href="{artifact_url}">mobile</a></html>' for _ in specs]
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

    def _fake_downloads(self, requests, **_kwargs):  # noqa: ANN001
        del self
        download_attempts.extend(str(request.source_url) for request in requests)
        return [
            ArtifactDownloadResult(
                artifact_id=request.artifact_id,
                source_url=request.source_url,
                artifact_type=request.artifact_type,
                error="simulated artifact download failure",
            )
            for request in requests
        ]

    monkeypatch.setattr("forge.cli._run_forge_module_subprocess", _fake_module_subprocess)
    monkeypatch.setattr("forge.cli._run_html_fetch_batch", _fake_html_batch)
    monkeypatch.setattr("forge.cli._run_callable_batch", _fake_callable_batch)
    monkeypatch.setattr("forge.cli._run_inprocess_batch", _direct_batch)
    monkeypatch.setattr(ArtifactQueueProcessor, "_download_remote_artifacts", _fake_downloads)

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
        skip_cloud=True,
        skip_keyscan=True,
        parallel_fanout=1,
        report_provider="template",
    )

    assert download_attempts == [artifact_url, artifact_url]
    db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
    metadata = _latest_run_metadata(db_path)
    assert metadata["pending_work_counts"]["artifact_queue"] == 1
    assert metadata["pending_work_total"] >= 1
    assert metadata["last_iteration_stable"] is False

    con = sqlite3.connect(db_path)
    try:
        row = con.execute(
            """
            SELECT status, attempt_count, max_attempts, notes
            FROM artifact_queue
            WHERE engagement_id=1001 AND source_url=?
            """,
            (artifact_url,),
        ).fetchone()
    finally:
        con.close()

    assert row == ("failed", 2, 3, "simulated artifact download failure")


def test_kill_chain_mixed_case_unsupported_cloud_ref_is_resume_stable(
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
                "domains": ["acme.example", "Echo.netlify.app"],
                "urls": ["https://Echo.netlify.app"],
                "authorized_seeds": ["acme.example"],
            }
        ),
        encoding="utf-8",
    )

    def _fake_module_subprocess(cmd_argv, **kwargs):  # noqa: ANN001
        del kwargs
        module_argv = tuple(str(item) for item in cmd_argv)
        _write_report_if_requested(module_argv, tmp_path)
        return subprocess.CompletedProcess(["forge", *module_argv], 0, stdout="ok\n", stderr="")

    def _fake_html_batch(specs, *_args, progress_label=None, **_kwargs):  # noqa: ANN001
        if str(progress_label or "").endswith(".D cloud+HTML fetch"):
            return ["<html>https://Echo.netlify.app</html>" for _ in specs]
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

    monkeypatch.setattr("forge.cli._run_forge_module_subprocess", _fake_module_subprocess)
    monkeypatch.setattr("forge.cli._run_html_fetch_batch", _fake_html_batch)
    monkeypatch.setattr("forge.cli._run_callable_batch", _fake_callable_batch)
    monkeypatch.setattr("forge.cli._run_inprocess_batch", _direct_batch)

    from forge.cli import kill_chain

    for _ in range(2):
        kill_chain(
            seed="acme.example",
            engagement="1001",
            max_iter=1,
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

    db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            """
            SELECT es.seed_value, sr.status, sr.error, sr.metadata_json
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND sr.loop_name='fanout_j_cloud_scan'
              AND es.seed_value='netlify:echo'
            ORDER BY sr.id
            """
        ).fetchall()
        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier, provider_identifier, source
            FROM cloud_assets
            WHERE engagement_id=1001 AND asset_type='netlify'
            ORDER BY id
            """
        ).fetchall()
    finally:
        con.close()

    assert len(rows) == 1
    assert rows[0][0] == "netlify:echo"
    assert rows[0][1] == "skipped"
    assert rows[0][2] == "unsupported_cloud_service"
    skipped_metadata = json.loads(str(rows[0][3] or "{}"))
    assert skipped_metadata["service"] == "netlify"
    assert skipped_metadata["ref"] == "Echo"
    assert cloud_assets == [
        ("netlify", "echo", "Echo", "kill_chain_cloud_ref"),
    ]


def test_kill_chain_cloud_asset_pending_count_is_alias_aware(
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
                "domains": ["acme.example"],
                "authorized_seeds": ["acme.example"],
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
            INSERT INTO cloud_assets
                (engagement_id, asset_type, identifier, provider_identifier, source)
            VALUES (1001, 's3', 'AliasBucket', 'AliasBucket', 'fixture')
            """
        )
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, provider_identifier,
                 validation_status, validation_method, evidence, notes)
            VALUES (1001, 'aws_s3', 'aliasbucket', 'AliasBucket',
                    'UNVERIFIED', 'fixture', 'alias receipt', 'canonical alias')
            """
        )
        con.commit()
    finally:
        con.close()

    def _fake_module_subprocess(cmd_argv, **kwargs):  # noqa: ANN001
        del kwargs
        module_argv = tuple(str(item) for item in cmd_argv)
        _write_report_if_requested(module_argv, tmp_path)
        return subprocess.CompletedProcess(["forge", *module_argv], 0, stdout="ok\n", stderr="")

    def _fake_html_batch(specs, *_args, progress_label=None, **_kwargs):  # noqa: ANN001
        del progress_label
        return ["" for _ in specs]

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
        label = str(progress_label or "")
        if label.endswith(".G DNS enrichment"):
            return [{"root_domain": str(item), "queried_hosts": [], "cname_targets": [], "signals": []} for item in items]
        if label.endswith(".H whois/RDAP"):
            return [{"root_domain": str(item), "rdap": {}} for item in items]
        if label.endswith(".I Wayback CDX"):
            return [{"root_domain": str(item), "urls": []} for item in items]
        return []

    monkeypatch.setattr("forge.cli._run_forge_module_subprocess", _fake_module_subprocess)
    monkeypatch.setattr("forge.cli._run_html_fetch_batch", _fake_html_batch)
    monkeypatch.setattr("forge.cli._run_callable_batch", _fake_callable_batch)

    from forge.cli import kill_chain

    kill_chain(
        seed="acme.example",
        engagement="1001",
        max_iter=1,
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

    metadata = _latest_run_metadata(db_path)
    assert "cloud_asset_validations" not in metadata.get("pending_work_counts", {})


def test_kill_chain_retries_failed_email_seed_rows(
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
                "authorized_seeds": ["@operator", "retry@acme.example"],
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
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (1001, "retry@acme.example", "email", "discovered", "failed", 1, 0.9, "{}"),
        )
        con.commit()
    finally:
        con.close()

    email_attempts: list[tuple[str, str]] = []

    def _fake_module_subprocess(cmd_argv, **kwargs):  # noqa: ANN001
        del kwargs
        module_argv = tuple(str(item) for item in cmd_argv)
        if module_argv[:2] in {
            ("osint", "xposed"),
            ("osint", "accounts"),
            ("osint", "social"),
            ("osint", "gravatar"),
            ("osint", "google"),
            ("osint", "emailrep"),
        } and "--emails" in module_argv:
            email = module_argv[module_argv.index("--emails") + 1]
            email_attempts.append((module_argv[1], email))
            if email == "retry@acme.example":
                return subprocess.CompletedProcess(
                    ["forge", *module_argv],
                    1,
                    stdout="",
                    stderr="simulated email fan-out failure",
                )
        _write_report_if_requested(module_argv, tmp_path)
        return subprocess.CompletedProcess(["forge", *module_argv], 0, stdout="ok\n", stderr="")

    monkeypatch.setattr("forge.cli._run_forge_module_subprocess", _fake_module_subprocess)
    monkeypatch.setattr("forge.cli._run_inprocess_batch", _direct_batch)

    from forge.cli import kill_chain

    kill_chain(
        seed="@operator",
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

    assert email_attempts.count(("xposed", "retry@acme.example")) == 2
    assert email_attempts.count(("emailrep", "retry@acme.example")) == 2

    con = sqlite3.connect(db_path)
    try:
        failed_runs = con.execute(
            """
            SELECT sr.status, sr.error, sr.metadata_json
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND sr.loop_name='fanout_e_chain'
              AND es.seed_value='retry@acme.example'
            ORDER BY sr.id
            """
        ).fetchall()
    finally:
        con.close()

    assert len(failed_runs) == 2
    assert all(row[0] == "failed" for row in failed_runs)
    assert all("email fan-out modules failed" in str(row[1] or "") for row in failed_runs)
    assert all(1 in json.loads(str(row[2] or "{}"))["returncodes"] for row in failed_runs)


def test_kill_chain_retries_failed_keyscan_targets_and_orgs_only(
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
                "domains": ["acme.example"],
                "authorized_seeds": ["acme.example"],
            }
        ),
        encoding="utf-8",
    )

    keyscan_attempts: list[tuple[str, str]] = []

    def _fake_module_subprocess(cmd_argv, **kwargs):  # noqa: ANN001
        del kwargs
        module_argv = tuple(str(item) for item in cmd_argv)
        if module_argv[:2] == ("osint", "keyscan") and "--domain" in module_argv:
            domain = module_argv[module_argv.index("--domain") + 1]
            org = module_argv[module_argv.index("--org") + 1] if "--org" in module_argv else ""
            keyscan_attempts.append((domain, org))
            if org == "failorg":
                return subprocess.CompletedProcess(
                    ["forge", *module_argv],
                    1,
                    stdout="",
                    stderr="simulated keyscan failure",
                )
        _write_report_if_requested(module_argv, tmp_path)
        return subprocess.CompletedProcess(["forge", *module_argv], 0, stdout="ok\n", stderr="")

    def _fake_html_batch(specs, *_args, progress_label=None, **_kwargs):  # noqa: ANN001
        if str(progress_label or "").endswith(".D cloud+HTML fetch"):
            return [
                (
                    "<html>"
                    '<a href="https://github.com/failorg/repo">fail</a>'
                    '<a href="https://github.com/okorg/repo">ok</a>'
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

    monkeypatch.setattr("forge.cli._run_forge_module_subprocess", _fake_module_subprocess)
    monkeypatch.setattr("forge.cli._run_html_fetch_batch", _fake_html_batch)
    monkeypatch.setattr("forge.cli._run_callable_batch", _fake_callable_batch)

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
        skip_cloud=True,
        skip_keyscan=False,
        parallel_fanout=1,
        report_provider="template",
    )

    assert keyscan_attempts.count(("acme.example", "")) == 1
    assert keyscan_attempts.count(("acme.example", "okorg")) == 1
    assert keyscan_attempts.count(("acme.example", "failorg")) == 2
    assert ("okorg", "") not in keyscan_attempts
    assert ("failorg", "") not in keyscan_attempts

    db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
    fail_key = "acme.example::github_org::failorg"
    ok_key = "acme.example::github_org::okorg"
    con = sqlite3.connect(db_path)
    try:
        failed_rows = con.execute(
            """
            SELECT es.seed_value, sr.status, sr.error, sr.metadata_json
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND sr.loop_name='fanout_f_keyscan'
              AND es.seed_value=?
            ORDER BY sr.id
            """,
            (fail_key,),
        ).fetchall()
        completed_rows = con.execute(
            """
            SELECT es.seed_value, sr.status
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND sr.loop_name='fanout_f_keyscan'
              AND es.seed_value=?
            ORDER BY sr.id
            """,
            (ok_key,),
        ).fetchall()
    finally:
        con.close()

    assert len(failed_rows) == 2
    assert all(row[1] == "failed" for row in failed_rows)
    assert all("simulated keyscan failure" in str(row[2] or "") for row in failed_rows)
    assert all(json.loads(str(row[3] or "{}"))["returncode"] == 1 for row in failed_rows)
    assert all(json.loads(str(row[3] or "{}"))["origin"] == "keyscan_org" for row in failed_rows)
    assert all(json.loads(str(row[3] or "{}"))["query_domain"] == "acme.example" for row in failed_rows)
    assert all(json.loads(str(row[3] or "{}"))["github_org"] == "failorg" for row in failed_rows)
    assert completed_rows == [(ok_key, "completed")]


def test_kill_chain_counts_failed_root_keyscan_as_pending_work(
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
                "domains": ["acme.example"],
                "authorized_seeds": ["acme.example"],
            }
        ),
        encoding="utf-8",
    )

    _install_host_surface_test_mocks(monkeypatch, tmp_path)
    root_keyscan_attempts: list[str] = []

    def _fake_module_subprocess(cmd_argv, **kwargs):  # noqa: ANN001
        del kwargs
        module_argv = tuple(str(item) for item in cmd_argv)
        if (
            module_argv[:2] == ("osint", "keyscan")
            and "--domain" in module_argv
            and "--org" not in module_argv
        ):
            root_keyscan_attempts.append(module_argv[module_argv.index("--domain") + 1])
            return subprocess.CompletedProcess(
                ["forge", *module_argv],
                1,
                stdout="",
                stderr="simulated root keyscan failure",
            )
        _write_report_if_requested(module_argv, tmp_path)
        return subprocess.CompletedProcess(["forge", *module_argv], 0, stdout="ok\n", stderr="")

    monkeypatch.setattr("forge.cli._run_forge_module_subprocess", _fake_module_subprocess)

    from forge.cli import kill_chain

    kill_chain(
        seed="acme.example",
        engagement="1001",
        max_iter=3,
        tor=False,
        dry_run=False,
        attack_mode=False,
        roe_id="ROE-TEST-2026-07",
        scope_manifest=str(manifest_path),
        skip_cloud=True,
        skip_keyscan=False,
        parallel_fanout=1,
        report_provider="template",
    )

    assert root_keyscan_attempts == ["acme.example", "acme.example", "acme.example"]

    db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
    con = sqlite3.connect(db_path)
    try:
        failed_rows = con.execute(
            """
            SELECT sr.status, sr.error, sr.metadata_json
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND sr.loop_name='fanout_f_keyscan'
              AND es.seed_value='acme.example'
            ORDER BY sr.id
            """
        ).fetchall()
    finally:
        con.close()

    assert len(failed_rows) == 3
    assert all(row[0] == "failed" for row in failed_rows)
    assert all("simulated root keyscan failure" in str(row[1] or "") for row in failed_rows)
    assert all(json.loads(str(row[2] or "{}"))["origin"] == "keyscan_target" for row in failed_rows)

    metadata = _latest_run_metadata(db_path)
    pending_counts = metadata.get("pending_work_counts", {})
    assert pending_counts["root_keyscan_domains"] == 1
    assert metadata["pending_work_total"] >= 1
    assert metadata["last_iteration_stable"] is False


def test_kill_chain_keyscan_org_targets_are_per_root_domain(
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
                "domains": ["acme.example", "beta.example"],
                "authorized_seeds": ["acme.example", "beta.example"],
            }
        ),
        encoding="utf-8",
    )

    keyscan_attempts: list[tuple[str, str]] = []

    def _fake_module_subprocess(cmd_argv, **kwargs):  # noqa: ANN001
        del kwargs
        module_argv = tuple(str(item) for item in cmd_argv)
        if module_argv[:2] == ("osint", "keyscan") and "--domain" in module_argv:
            domain = module_argv[module_argv.index("--domain") + 1]
            org = module_argv[module_argv.index("--org") + 1] if "--org" in module_argv else ""
            keyscan_attempts.append((domain, org))
        _write_report_if_requested(module_argv, tmp_path)
        return subprocess.CompletedProcess(["forge", *module_argv], 0, stdout="ok\n", stderr="")

    def _fake_html_batch(specs, *_args, progress_label=None, **_kwargs):  # noqa: ANN001
        if str(progress_label or "").endswith(".D cloud+HTML fetch"):
            return ['<a href="https://github.com/sharedorg/repo">shared</a>' for _ in specs]
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

    monkeypatch.setattr("forge.cli._run_forge_module_subprocess", _fake_module_subprocess)
    monkeypatch.setattr("forge.cli._run_html_fetch_batch", _fake_html_batch)
    monkeypatch.setattr("forge.cli._run_callable_batch", _fake_callable_batch)
    monkeypatch.setattr("forge.cli._run_inprocess_batch", _direct_batch)

    from forge.cli import kill_chain

    kill_chain(
        seed="acme.example",
        related_seed=["beta.example"],
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
    )

    assert keyscan_attempts.count(("acme.example", "")) == 1
    assert keyscan_attempts.count(("beta.example", "")) == 1
    assert keyscan_attempts.count(("acme.example", "sharedorg")) == 1
    assert keyscan_attempts.count(("beta.example", "sharedorg")) == 1
    assert ("sharedorg", "") not in keyscan_attempts

    db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
    con = sqlite3.connect(db_path)
    try:
        completed = {
            str(row[0])
            for row in con.execute(
                """
                SELECT es.seed_value
                FROM seed_runs sr
                JOIN engagement_seeds es ON es.id=sr.seed_id
                WHERE sr.engagement_id=1001
                  AND sr.loop_name='fanout_f_keyscan'
                  AND sr.status='completed'
                """
            ).fetchall()
        }
    finally:
        con.close()

    assert "acme.example::github_org::sharedorg" in completed
    assert "beta.example::github_org::sharedorg" in completed


def test_kill_chain_retries_empty_d5_url_fetches_only(
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
                "urls": [
                    "https://portal.acme.example/fail",
                    "https://portal.acme.example/ok",
                ],
                "authorized_seeds": [
                    "https://portal.acme.example/fail",
                    "https://portal.acme.example/ok",
                ],
            }
        ),
        encoding="utf-8",
    )

    d5_attempts: list[str] = []

    def _fake_module_subprocess(cmd_argv, **kwargs):  # noqa: ANN001
        del kwargs
        module_argv = tuple(str(item) for item in cmd_argv)
        _write_report_if_requested(module_argv, tmp_path)
        return subprocess.CompletedProcess(["forge", *module_argv], 0, stdout="ok\n", stderr="")

    def _fake_html_batch(specs, *_args, progress_label=None, **_kwargs):  # noqa: ANN001
        label = str(progress_label or "")
        if label.endswith(".D5 URL surface fetch"):
            payloads: list[str] = []
            for spec in specs:
                url = str(spec.url)
                d5_attempts.append(url)
                payloads.append("" if url.endswith("/fail") else "<html><title>ok</title></html>")
            return payloads
        if label.endswith((".D cloud+HTML fetch", ".D2 passive text fetch")):
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

    monkeypatch.setattr("forge.cli._run_forge_module_subprocess", _fake_module_subprocess)
    monkeypatch.setattr("forge.cli._run_html_fetch_batch", _fake_html_batch)
    monkeypatch.setattr("forge.cli._run_callable_batch", _fake_callable_batch)
    monkeypatch.setattr("forge.cli._run_inprocess_batch", _direct_batch)

    from forge.cli import kill_chain

    kill_chain(
        seed="https://portal.acme.example/fail",
        related_seed=["https://portal.acme.example/ok"],
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

    assert d5_attempts.count("https://portal.acme.example/fail") == 2
    assert d5_attempts.count("https://portal.acme.example/ok") == 1

    db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
    con = sqlite3.connect(db_path)
    try:
        fail_rows = con.execute(
            """
            SELECT sr.status, sr.error, sr.metadata_json
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND sr.loop_name='fanout_d5_url_seed_html'
              AND es.seed_value='https://portal.acme.example/fail'
            ORDER BY sr.id
            """
        ).fetchall()
        ok_rows = con.execute(
            """
            SELECT sr.status, sr.error, sr.metadata_json
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND sr.loop_name='fanout_d5_url_seed_html'
              AND es.seed_value='https://portal.acme.example/ok'
            ORDER BY sr.id
            """
        ).fetchall()
    finally:
        con.close()

    assert len(fail_rows) == 2
    assert all(row[0] == "failed" and row[1] == "empty_url_fetch" for row in fail_rows)
    assert all(json.loads(str(row[2] or "{}"))["fetch_status"] == "empty" for row in fail_rows)
    assert len(ok_rows) == 1
    assert ok_rows[0][0] == "completed"
    assert json.loads(str(ok_rows[0][2] or "{}"))["fetch_status"] == "payload"
