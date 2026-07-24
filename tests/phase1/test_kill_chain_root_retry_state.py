import json
import subprocess
from pathlib import Path

from tests.phase1.test_kill_chain_retry_state import _direct_batch, _write_report_if_requested


def test_kill_chain_root_domain_fanouts_do_not_rerun_after_success(
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

    module_attempts: list[tuple[str, str]] = []
    callable_attempts: list[tuple[str, str]] = []

    def _fake_module_subprocess(cmd_argv, **kwargs):  # noqa: ANN001
        del kwargs
        module_argv = tuple(str(item) for item in cmd_argv)
        target = ""
        kind = ""
        if module_argv[:2] == ("recon", "subdomains") and "--domain" in module_argv:
            kind = "A"
            target = module_argv[module_argv.index("--domain") + 1]
        elif module_argv[:2] == ("osint", "harvest") and "--domain" in module_argv:
            kind = "B"
            target = module_argv[module_argv.index("--domain") + 1]
        elif module_argv[:2] == ("osint", "shodan") and "--target" in module_argv:
            kind = "D3"
            target = module_argv[module_argv.index("--target") + 1]
        elif module_argv[:2] == ("osint", "urlscan") and "--hostname" in module_argv:
            kind = "D4"
            target = module_argv[module_argv.index("--hostname") + 1]
        if kind:
            module_attempts.append((kind, target))
        _write_report_if_requested(module_argv, tmp_path)
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
        if progress_name.endswith(".G DNS enrichment"):
            callable_attempts.extend(("G", str(item)) for item in items)
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
            callable_attempts.extend(("H", str(item)) for item in items)
            return [{"root_domain": str(item), "rdap": {}} for item in items]
        if progress_name.endswith(".I Wayback CDX"):
            callable_attempts.extend(("I", str(item)) for item in items)
            return [{"root_domain": str(item), "urls": []} for item in items]
        raise AssertionError(f"unexpected callable batch label: {progress_label}")

    monkeypatch.setattr("forge.cli._run_forge_module_subprocess", _fake_module_subprocess)
    monkeypatch.setattr("forge.cli._run_html_fetch_batch", _fake_html_batch)
    monkeypatch.setattr("forge.cli._run_callable_batch", _fake_callable_batch)
    monkeypatch.setattr("forge.cli._run_inprocess_batch", _direct_batch)

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

    assert module_attempts.count(("A", "acme.example")) == 1
    assert module_attempts.count(("B", "acme.example")) == 1
    assert module_attempts.count(("D3", "acme.example")) == 1
    assert module_attempts.count(("D4", "acme.example")) == 1
    assert callable_attempts.count(("G", "acme.example")) == 1
    assert callable_attempts.count(("H", "acme.example")) == 1
    assert callable_attempts.count(("I", "acme.example")) == 1
