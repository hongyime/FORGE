import json
import sqlite3
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tests.phase1.test_kill_chain_retry_state import _direct_batch, _write_report_if_requested

ROOT_DOMAIN = "acme.example"
PROVIDER_LOOPS = {
    "G": "fanout_g_dns",
    "H": "fanout_h_rdap",
    "I": "fanout_i_wayback",
}


def _install_status_case_fakes(
    tmp_path: Path,
    monkeypatch,
    factories: dict[str, Callable[[str], dict[str, Any]]],
    attempts: list[tuple[str, str]],
    *,
    module_fail_stages: set[str] | None = None,
) -> None:
    def _fake_module_subprocess(cmd_argv, **kwargs):  # noqa: ANN001
        del kwargs
        module_argv = tuple(str(item) for item in cmd_argv)
        stage = ""
        target = ""
        if module_argv[:2] == ("recon", "subdomains") and "--domain" in module_argv:
            stage = "A"
            target = module_argv[module_argv.index("--domain") + 1]
        elif module_argv[:2] == ("osint", "harvest") and "--domain" in module_argv:
            stage = "B"
            target = module_argv[module_argv.index("--domain") + 1]
        elif module_argv[:2] == ("osint", "linkedin") and "--domain" in module_argv:
            stage = "B2"
            target = module_argv[module_argv.index("--domain") + 1]
        elif module_argv[:2] == ("osint", "shodan") and "--target" in module_argv:
            stage = "D3"
            target = module_argv[module_argv.index("--target") + 1]
        elif module_argv[:2] == ("osint", "urlscan") and "--hostname" in module_argv:
            stage = "D4"
            target = module_argv[module_argv.index("--hostname") + 1]
        if stage:
            attempts.append((stage, target))
        _write_report_if_requested(module_argv, tmp_path)
        if stage and stage in (module_fail_stages or set()):
            return subprocess.CompletedProcess(
                ["forge", *module_argv],
                1,
                stdout="",
                stderr=f"simulated {stage} failure",
            )
        return subprocess.CompletedProcess(["forge", *module_argv], 0, stdout="ok\n", stderr="")

    def _fake_html_batch(specs, *_args, progress_label=None, **_kwargs):  # noqa: ANN001
        if str(progress_label or "").endswith(
            (".D cloud+HTML fetch", ".D2 passive text fetch", ".D5 URL surface fetch")
        ):
            return ["" for _ in specs]
        raise AssertionError(f"unexpected html batch label: {progress_label}")

    def _fake_callable_batch(  # noqa: ANN001
        items,
        worker,
        *,
        max_workers,
        progress_label=None,
        progress_callback=None,
    ):
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
        for stage, suffix in {
            "G": ".G DNS enrichment",
            "H": ".H whois/RDAP",
            "I": ".I Wayback CDX",
        }.items():
            if progress_name.endswith(suffix):
                attempts.extend((stage, str(item)) for item in items)
                return [factories[stage](str(item)) for item in items]
        raise AssertionError(f"unexpected callable batch label: {progress_label}")

    monkeypatch.setattr("forge.cli._run_forge_module_subprocess", _fake_module_subprocess)
    monkeypatch.setattr("forge.cli._run_html_fetch_batch", _fake_html_batch)
    monkeypatch.setattr("forge.cli._run_callable_batch", _fake_callable_batch)
    monkeypatch.setattr("forge.cli._run_inprocess_batch", _direct_batch)


def _run_status_case(
    tmp_path: Path,
    monkeypatch,
    factories: dict[str, Callable[[str], dict[str, Any]]],
    *,
    max_iter: int,
    runs: int = 1,
    module_fail_stages: set[str] | None = None,
    manifest_domains: list[str] | None = None,
    dry_run: bool = False,
    use_scope_manifest: bool = True,
) -> tuple[Path, list[tuple[str, str]]]:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    manifest_path = tmp_path / "roe-scope.json"
    if use_scope_manifest:
        manifest_path.write_text(
            json.dumps(
                {
                    "roe_id": "ROE-TEST-2026-07",
                    "domains": manifest_domains or [ROOT_DOMAIN],
                    "authorized_seeds": [ROOT_DOMAIN],
                }
            ),
            encoding="utf-8",
        )
    attempts: list[tuple[str, str]] = []
    _install_status_case_fakes(
        tmp_path,
        monkeypatch,
        factories,
        attempts,
        module_fail_stages=module_fail_stages,
    )

    from forge.cli import kill_chain

    for _ in range(max(1, int(runs))):
        kill_chain(
            seed=ROOT_DOMAIN,
            engagement="1001",
            max_iter=max_iter,
            tor=False,
            dry_run=dry_run,
            attack_mode=False,
            roe_id="ROE-TEST-2026-07" if use_scope_manifest else None,
            scope_manifest=str(manifest_path) if use_scope_manifest else None,
            skip_cloud=True,
            skip_keyscan=True,
            parallel_fanout=1,
            report_provider="template",
        )
    return tmp_path / ".forge_data" / "engagements" / "1001.db", attempts


def _audit_actions(db_path: Path, action: str) -> list[tuple[str, str]]:
    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            """
            SELECT target, result
            FROM audit_log
            WHERE engagement_id=1001 AND action=?
            ORDER BY id
            """,
            (action,),
        ).fetchall()
    finally:
        con.close()
    return [(str(target or ""), str(result or "")) for target, result in rows]


def _provider_seed_runs(db_path: Path) -> list[tuple[str, str, str, dict[str, Any]]]:
    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            """
            SELECT sr.loop_name, sr.status, sr.error, sr.metadata_json
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND es.seed_value=?
              AND sr.loop_name IN ('fanout_g_dns', 'fanout_h_rdap', 'fanout_i_wayback')
            ORDER BY sr.id
            """,
            (ROOT_DOMAIN,),
        ).fetchall()
    finally:
        con.close()
    return [
        (str(loop), str(status), str(error or ""), json.loads(str(metadata or "{}")))
        for loop, status, error, metadata in rows
    ]


def _latest_run_metadata(db_path: Path) -> dict[str, Any]:
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


def _dns_result(domain: str, status: str, error: str = "") -> dict[str, Any]:
    return {
        "root_domain": domain,
        "status": status,
        "error": error,
        "provider_errors": [error] if error else [],
        "queried_hosts": [domain],
        "cname_targets": [],
        "signals": [],
    }


def _rdap_result(domain: str, status: str, error: str = "") -> dict[str, Any]:
    return {
        "root_domain": domain,
        "rdap": {
            "_forge_status": status,
            "_forge_error": error,
            "_forge_http_status": 503 if status == "failed" else 404,
        },
    }


def _archive_result(
    domain: str,
    status: str,
    *,
    urls: list[str] | None = None,
    error: str = "",
) -> dict[str, Any]:
    return {
        "root_domain": domain,
        "status": status,
        "error": error,
        "archive_errors": [error] if error else [],
        "provider_statuses": {
            "wayback": "completed" if status == "completed" else status,
            "commoncrawl": "failed" if error else "completed",
        },
        "urls": urls or [],
        "url_metadata": {},
    }


def test_provider_failures_finalize_failed_and_retry(tmp_path: Path, monkeypatch) -> None:
    db_path, attempts = _run_status_case(
        tmp_path,
        monkeypatch,
        {
            "G": lambda domain: _dns_result(domain, "failed", "simulated_dns_timeout"),
            "H": lambda domain: _rdap_result(domain, "failed", "simulated_rdap_503"),
            "I": lambda domain: _archive_result(
                domain,
                "failed",
                error="wayback:timeout; commoncrawl:timeout",
            ),
        },
        max_iter=2,
    )

    assert attempts.count(("G", ROOT_DOMAIN)) == 2
    assert attempts.count(("H", ROOT_DOMAIN)) == 2
    assert attempts.count(("I", ROOT_DOMAIN)) == 2
    failed_by_loop = {
        loop: sum(1 for row_loop, status, _error, _metadata in _provider_seed_runs(db_path)
                  if row_loop == loop and status == "failed")
        for loop in PROVIDER_LOOPS.values()
    }
    assert failed_by_loop == {loop: 2 for loop in PROVIDER_LOOPS.values()}


@pytest.mark.parametrize(
    ("failed_stage", "failed_loop", "pending_key"),
    [
        ("A", "fanout_a_subdomains", "root_subdomain_domains"),
        ("B", "fanout_b_harvest", "root_harvest_domains"),
        ("B2", "fanout_b2_linkedin", "root_linkedin_domains"),
        ("D3", "fanout_d3_shodan", "root_shodan_domains"),
        ("D4", "fanout_d4_urlscan", "root_urlscan_domains"),
    ],
)
def test_root_tool_failure_keeps_same_run_retry_budget_alive(
    tmp_path: Path,
    monkeypatch,
    failed_stage: str,
    failed_loop: str,
    pending_key: str,
) -> None:
    db_path, attempts = _run_status_case(
        tmp_path,
        monkeypatch,
        {
            "G": lambda domain: _dns_result(domain, "completed"),
            "H": lambda domain: _rdap_result(domain, "skipped", "http_status_404"),
            "I": lambda domain: _archive_result(domain, "completed"),
        },
        max_iter=2,
        module_fail_stages={failed_stage},
    )

    assert attempts.count((failed_stage, ROOT_DOMAIN)) == 2
    for completed_stage in {"A", "B", "B2", "D3", "D4"} - {failed_stage}:
        assert attempts.count((completed_stage, ROOT_DOMAIN)) == 1
    assert attempts.count(("G", ROOT_DOMAIN)) == 1
    assert attempts.count(("H", ROOT_DOMAIN)) == 1
    assert attempts.count(("I", ROOT_DOMAIN)) == 1

    con = sqlite3.connect(db_path)
    try:
        failed_a_runs = con.execute(
            """
            SELECT sr.status, sr.error
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND es.seed_value=?
              AND sr.loop_name=?
              AND sr.status='failed'
            ORDER BY sr.id
            """,
            (ROOT_DOMAIN, failed_loop),
        ).fetchall()
    finally:
        con.close()
    assert len(failed_a_runs) == 2
    assert all(
        f"simulated {failed_stage} failure" in str(error or "")
        for _status, error in failed_a_runs
    )
    run_metadata = _latest_run_metadata(db_path)
    assert run_metadata["pending_work_counts"][pending_key] == 1
    assert run_metadata["pending_work_total"] >= 1
    assert run_metadata["last_iteration_stable"] is False


def test_synthesized_out_of_scope_root_is_not_dispatched(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from forge.engagement_orchestrator import SynthesisSummary

    def _fake_synthesis_run(_self) -> SynthesisSummary:  # noqa: ANN001
        return SynthesisSummary(root_domains=[ROOT_DOMAIN, "evil.example"])

    monkeypatch.setattr(
        "forge.engagement_orchestrator.EngagementSynthesisEngine.run",
        _fake_synthesis_run,
    )

    db_path, attempts = _run_status_case(
        tmp_path,
        monkeypatch,
        {
            "G": lambda domain: _dns_result(domain, "completed"),
            "H": lambda domain: _rdap_result(domain, "skipped", "http_status_404"),
            "I": lambda domain: _archive_result(domain, "completed"),
        },
        max_iter=1,
    )

    assert any(target == ROOT_DOMAIN for _stage, target in attempts)
    assert all(target != "evil.example" for _stage, target in attempts)
    metadata = _latest_run_metadata(db_path)
    assert ROOT_DOMAIN in list(metadata.get("root_domains") or [])
    assert "evil.example" not in list(metadata.get("root_domains") or [])
    denied_rows = _audit_actions(db_path, "root_domain_scope_denied")
    assert denied_rows
    evil_denials = [
        result
        for target, result in denied_rows
        if target == "evil.example"
    ]
    assert len(evil_denials) == 1
    assert "reason=scope_manifest_denied" in evil_denials[0]
    assert f"scope_manifest={(tmp_path / 'roe-scope.json').resolve().as_posix()}" in evil_denials[0]


def test_authorized_synthesized_root_enters_root_fanouts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from forge.engagement_orchestrator import SynthesisSummary

    def _fake_synthesis_run(_self) -> SynthesisSummary:  # noqa: ANN001
        return SynthesisSummary(root_domains=[ROOT_DOMAIN, "beta.example"])

    monkeypatch.setattr(
        "forge.engagement_orchestrator.EngagementSynthesisEngine.run",
        _fake_synthesis_run,
    )

    db_path, attempts = _run_status_case(
        tmp_path,
        monkeypatch,
        {
            "G": lambda domain: _dns_result(domain, "completed"),
            "H": lambda domain: _rdap_result(domain, "skipped", "http_status_404"),
            "I": lambda domain: _archive_result(domain, "completed"),
        },
        max_iter=1,
        manifest_domains=[ROOT_DOMAIN, "beta.example"],
    )

    for stage in {"A", "B", "B2", "D3", "D4", "G", "H", "I"}:
        assert attempts.count((stage, "beta.example")) == 1
    metadata = _latest_run_metadata(db_path)
    assert "beta.example" in list(metadata.get("root_domains") or [])
    assert _audit_actions(db_path, "root_domain_scope_denied") == []


def test_dry_run_without_manifest_allows_synthesized_preview_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from forge.engagement_orchestrator import SynthesisSummary

    def _fake_synthesis_run(_self) -> SynthesisSummary:  # noqa: ANN001
        return SynthesisSummary(root_domains=[ROOT_DOMAIN, "preview.example"])

    monkeypatch.setattr(
        "forge.engagement_orchestrator.EngagementSynthesisEngine.run",
        _fake_synthesis_run,
    )

    db_path, _attempts = _run_status_case(
        tmp_path,
        monkeypatch,
        {
            "G": lambda domain: _dns_result(domain, "completed"),
            "H": lambda domain: _rdap_result(domain, "skipped", "http_status_404"),
            "I": lambda domain: _archive_result(domain, "completed"),
        },
        max_iter=1,
        dry_run=True,
        use_scope_manifest=False,
    )

    metadata = _latest_run_metadata(db_path)
    assert "preview.example" in list(metadata.get("root_domains") or [])
    assert metadata["live_execution_policy"]["scope_manifest_present"] is False
    assert _audit_actions(db_path, "root_domain_scope_denied") == []


def test_provider_true_no_data_is_terminal(tmp_path: Path, monkeypatch) -> None:
    db_path, attempts = _run_status_case(
        tmp_path,
        monkeypatch,
        {
            "G": lambda domain: _dns_result(domain, "completed"),
            "H": lambda domain: _rdap_result(domain, "skipped", "http_status_404"),
            "I": lambda domain: _archive_result(domain, "completed"),
        },
        max_iter=2,
    )

    assert attempts.count(("G", ROOT_DOMAIN)) == 1
    assert attempts.count(("H", ROOT_DOMAIN)) == 1
    assert attempts.count(("I", ROOT_DOMAIN)) == 1
    statuses = [(loop, status) for loop, status, _error, _metadata in _provider_seed_runs(db_path)]
    assert statuses == [
        ("fanout_g_dns", "completed"),
        ("fanout_h_rdap", "skipped"),
        ("fanout_i_wayback", "completed"),
    ]


def test_archive_partial_provider_failure_keeps_urls_and_metadata(
    tmp_path: Path,
    monkeypatch,
) -> None:
    archived_url = f"https://portal.{ROOT_DOMAIN}/login"
    db_path, _attempts = _run_status_case(
        tmp_path,
        monkeypatch,
        {
            "G": lambda domain: _dns_result(domain, "completed"),
            "H": lambda domain: _rdap_result(domain, "skipped", "http_status_404"),
            "I": lambda domain: _archive_result(
                domain,
                "completed",
                urls=[archived_url],
                error="commoncrawl:http_status_503",
            ),
        },
        max_iter=1,
    )

    rows = _provider_seed_runs(db_path)
    wayback_rows = [row for row in rows if row[0] == "fanout_i_wayback"]
    assert [(row[1], row[2]) for row in wayback_rows] == [("completed", "")]
    metadata = wayback_rows[0][3]
    assert metadata["archive_errors"] == ["commoncrawl:http_status_503"]
    assert metadata["provider_statuses"]["commoncrawl"] == "failed"

    con = sqlite3.connect(db_path)
    try:
        crawl_urls = {
            str(row[0])
            for row in con.execute(
                """
                SELECT COALESCE(final_url, url)
                FROM crawl_results
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()
    assert archived_url in crawl_urls
