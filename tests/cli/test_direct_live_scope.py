from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest
import typer

import forge.cli as cli
from forge.db.session import get_engagement_db
from forge.phase1 import crawler
from forge.phase4 import auth_bypass as auth_bypass_mod


class _FakeConfig:
    def __init__(self, db_path: Path, data_dir: Path) -> None:
        self._db_path = db_path
        self.data_dir = data_dir
        self.browser_timeout = 1.0
        self.screenshot_enabled = False
        self.shodan_key = None
        self.cdn_detection = False
        self.waf_detection = False
        self.operator = "tester"
        self.auth_max_attempts = 1
        self.auth_rate_limit = 0.0
        self.firebase_web_discovery = False
        self.firebase_repo_scavenge = False
        self.cloud_aws_profile = None
        self.cloud_aws_regions = []
        self.cloud_aws_services = []
        self.cloud_azure_subscription_id = None
        self.cloud_azure_tenant_id = None
        self.cloud_azure_client_id = None
        self.cloud_azure_services = []
        self.supabase_auto_discovery = False
        self.mobile_assets_scan = False
        self.repo_key_scavenge = False

    def engagement_db_path(self, _engagement: str) -> Path:
        return self._db_path


def test_run_forge_module_subprocess_returns_timeout_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []

    def _timeout_run(args: list[str], **kwargs: object) -> object:
        calls.append({"args": args, **kwargs})
        raise subprocess.TimeoutExpired(
            cmd=args,
            timeout=float(kwargs["timeout"]),
            output="partial stdout",
            stderr=b"late stderr",
        )

    monkeypatch.setattr(cli.subprocess, "run", _timeout_run)

    result = cli._run_forge_module_subprocess(
        ["cloud", "aws", "--engagement", "1001"],
        tor_prefix=["--tor"],
        timeout_seconds=2.5,
    )

    assert result.returncode == 124
    assert calls[0]["timeout"] == 2.5
    assert calls[0]["args"][:5] == [
        cli.sys.executable,
        "-m",
        "forge.cli",
        "--tor",
        "cloud",
    ]
    assert "timeout after 2.5s" in result.stderr
    assert "late stderr" in result.stderr


def test_detected_prereq_child_argv_adds_live_authorization_once() -> None:
    manifest = '{"roe_id":"ROE-ACME-2026-07","domains":["acme.example"]}'

    aws = cli._detected_prereq_child_argv(
        ["cloud", "aws", "--engagement", "1001"],
        roe_id="ROE-ACME-2026-07",
        scope_manifest=manifest,
    )
    firebase_extract = cli._detected_prereq_child_argv(
        ["cloud", "firebase-extract", "--engagement", "1001", "--apk", "client.apk"],
        roe_id="ROE-ACME-2026-07",
        scope_manifest=manifest,
    )
    already_hardened = cli._detected_prereq_child_argv(
        [
            "cloud",
            "firebase",
            "--engagement",
            "1001",
            "--roe-id",
            "ROE-ACME-2026-07",
            "--scope-manifest",
            manifest,
        ],
        roe_id="ROE-ACME-2026-07",
        scope_manifest=manifest,
    )

    assert aws[-3:] == ["--roe-id", "ROE-ACME-2026-07", "--yes"]
    assert "--scope-manifest" not in aws
    assert firebase_extract[-2:] == ["--scope-manifest", manifest]
    assert already_hardened.count("--roe-id") == 1
    assert already_hardened.count("--scope-manifest") == 1


def test_direct_keyscan_org_restriction_uses_scoped_domain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    manifest_path = tmp_path / "scope.json"
    manifest_path.write_text(
        json.dumps({"roe_id": "ROE-ACME-2026-07", "domains": ["acme.example"]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))
    observed: dict[str, object] = {}

    def _fake_run_key_scanner(**kwargs: object) -> int:
        observed.update(kwargs)
        return 0

    monkeypatch.setattr(
        "forge.utils.intel.secret_finder.run_key_scanner",
        _fake_run_key_scanner,
    )

    cli.osint_keyscan(
        engagement="1001",
        domain="acme.example",
        org="okorg",
        github_token=None,
        gitlab_token=None,
        validation_proxy=None,
        scope_manifest=str(manifest_path),
        no_validate=True,
        dry_run=True,
    )

    assert observed["domain"] == "acme.example"
    assert observed["org"] == "okorg"

    observed.clear()
    with pytest.raises(typer.BadParameter, match="outside scope manifest"):
        cli.osint_keyscan(
            engagement="1001",
            domain="okorg",
            org=None,
            github_token=None,
            gitlab_token=None,
            validation_proxy=None,
            scope_manifest=str(manifest_path),
            no_validate=True,
            dry_run=True,
        )
    assert observed == {}


def _bootstrap_engagement(db_path: Path, *, scope: object) -> None:
    con = get_engagement_db(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'direct-cli-scope', ?, 'ACTIVE', 'tester')
            ON CONFLICT(id) DO UPDATE SET scope_json=excluded.scope_json
            """,
            (json.dumps(scope),),
        )
        con.commit()
    finally:
        con.close()


def test_direct_recon_crawl_denies_out_of_scope_before_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    calls: list[str] = []

    def _fail_crawl(*_args: object, **_kwargs: object) -> list[object]:
        calls.append("called")
        raise AssertionError("out-of-scope direct crawl must not reach crawler")

    monkeypatch.setattr(crawler, "crawl_target_sync", _fail_crawl)

    with pytest.raises(typer.BadParameter, match="outside scope"):
        cli.recon_crawl(
            engagement="1001",
            target="https://evil.example",
            depth=1,
            screenshot=False,
            scope_manifest=None,
        )
    assert calls == []


def test_direct_recon_subdomains_denies_out_of_scope_before_enum(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import forge.phase1.subdomain_enum as subdomain_enum

    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    calls: list[str] = []

    def _fail_enum(*_args: object, **_kwargs: object) -> list[str]:
        calls.append("called")
        raise AssertionError("out-of-scope direct subdomain enum must not run")

    monkeypatch.setattr(subdomain_enum, "enumerate_subdomains", _fail_enum)

    with pytest.raises(typer.BadParameter, match="outside scope"):
        cli.recon_subdomains(
            engagement="1001",
            domain="evil.example",
            resume=True,
            scope_manifest=None,
        )
    assert calls == []


def test_direct_recon_crawl_scope_manifest_url_prefix_denies_same_host_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    calls: list[str] = []
    monkeypatch.setattr(crawler, "crawl_target_sync", lambda *args, **kwargs: calls.append("called") or [])

    with pytest.raises(typer.BadParameter, match="outside scope manifest"):
        cli.recon_crawl(
            engagement="1001",
            target="https://allowed.example/admin",
            depth=1,
            screenshot=False,
            scope_manifest=json.dumps(
                {
                    "roe_id": "ROE-ACME-2026-07",
                    "domains": ["allowed.example"],
                    "urls": ["https://allowed.example/app/"],
                }
            ),
        )
    assert calls == []


def test_direct_recon_crawl_passes_scope_to_crawler(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    calls: list[dict[str, object]] = []

    def _fake_crawl(*_args: object, **kwargs: object) -> list[object]:
        calls.append(dict(kwargs))
        return []

    monkeypatch.setattr(crawler, "crawl_target_sync", _fake_crawl)

    cli.recon_crawl(
        engagement="1001",
        target="https://allowed.example/app",
        depth=1,
        screenshot=False,
        scope_manifest=None,
    )

    assert calls[0]["target_url"] == "https://allowed.example/app"
    assert calls[0]["scope_values"] == ["allowed.example"]
    assert calls[0]["require_scope"] is True


def test_direct_auth_bypass_requires_roe_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    calls: list[str] = []
    monkeypatch.setattr(auth_bypass_mod, "run_bypass_assessment", lambda *args, **kwargs: calls.append("called"))

    with pytest.raises(typer.BadParameter, match="requires --roe-id"):
        cli.auth_bypass(
            engagement="1001",
            target="https://allowed.example/login",
            technique="sql-injection",
            roe_id=None,
            scope_manifest=None,
        )
    assert calls == []


def test_direct_auth_bypass_scope_manifest_denies_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    calls: list[str] = []
    monkeypatch.setattr(auth_bypass_mod, "run_bypass_assessment", lambda *args, **kwargs: calls.append("called"))

    with pytest.raises(typer.BadParameter, match="outside scope manifest"):
        cli.auth_bypass(
            engagement="1001",
            target="https://allowed.example/admin/login",
            technique="sql-injection",
            roe_id="ROE-ACME-2026-07",
            scope_manifest=json.dumps(
                {
                    "roe_id": "ROE-ACME-2026-07",
                    "domains": ["allowed.example"],
                    "urls": ["https://allowed.example/app/"],
                }
            ),
        )
    assert calls == []


def test_direct_auth_bypass_module_scope_gate_denies_before_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])

    calls: list[str] = []

    def _fail_post(*_args: object, **_kwargs: object) -> object:
        calls.append("called")
        raise AssertionError("out-of-scope auth bypass must not reach httpx.post")

    monkeypatch.setattr(auth_bypass_mod.httpx, "post", _fail_post)

    with pytest.raises(Exception, match="not within engagement scope"):
        auth_bypass_mod.run_bypass_assessment(
            engagement_id=1001,
            db_path=db_path,
            target_url="https://evil.example/login",
            require_scope=True,
        )
    assert calls == []


def test_direct_recon_ports_passes_scope_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["10.10.0.0/16"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    calls: list[dict[str, object]] = []

    def _fake_scan(**kwargs: object) -> list[object]:
        calls.append(kwargs)
        return []

    monkeypatch.setattr("forge.phase1.port_scanner.scan_engagement_enhanced", _fake_scan)

    cli.recon_ports(
        engagement="1001",
        timeout=0.1,
        enhanced=True,
        scope_manifest=None,
    )

    assert calls[0]["scope_override"] == ["10.10.0.0/16"]


def test_crawler_filters_out_of_prefix_links_before_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    fetched: list[str] = []

    class _Response:
        def __init__(self, url: str, text: str) -> None:
            self.url = url
            self.text = text
            self.headers = {}

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __aenter__(self) -> "_Client":
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, url: str) -> _Response:
            fetched.append(url)
            return _Response(
                url,
                '<html><title>ok</title><a href="/app/next">next</a><a href="/admin">admin</a></html>',
            )

    monkeypatch.setattr(crawler.httpx, "AsyncClient", _Client)

    rows = crawler.crawl_target_sync(
        engagement_id=1001,
        target_url="https://allowed.example/app/",
        db_path=db_path,
        depth=1,
        scope_values=["allowed.example"],
        url_prefixes=["https://allowed.example/app/"],
        require_scope=True,
    )

    assert [row.final_url for row in rows] == [
        "https://allowed.example/app/",
        "https://allowed.example/app/next",
    ]
    assert "https://allowed.example/admin" not in fetched
    con = sqlite3.connect(db_path)
    try:
        saved = [
            row[0]
            for row in con.execute(
                "SELECT final_url FROM crawl_results WHERE engagement_id=1001 ORDER BY id"
            ).fetchall()
        ]
    finally:
        con.close()
    assert saved == [
        "https://allowed.example/app/",
        "https://allowed.example/app/next",
    ]


def test_direct_osint_urlscan_denies_out_of_scope_before_lookup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import forge.utils.intel.urlscan_lookup as urlscan_lookup

    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    calls: list[str] = []
    monkeypatch.setattr(
        urlscan_lookup,
        "search_urlscan",
        lambda *args, **kwargs: calls.append("called") or {},
    )

    with pytest.raises(typer.BadParameter, match="outside scope"):
        cli.osint_urlscan(
            engagement="1001",
            hostname="evil.example",
            max_results=5,
            scope_manifest=None,
        )
    assert calls == []


def test_direct_osint_shodan_denies_out_of_scope_before_lookup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import forge.utils.intel.shodan_lookup as shodan_lookup

    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))
    monkeypatch.setattr(shodan_lookup, "_shodan_key", lambda: "test-key")

    calls: list[str] = []
    monkeypatch.setattr(
        shodan_lookup,
        "lookup_shodan_domain",
        lambda *args, **kwargs: calls.append("called") or {},
    )

    with pytest.raises(typer.BadParameter, match="outside scope"):
        cli.osint_shodan(
            engagement="1001",
            target="evil.example",
            scope_manifest=None,
        )
    assert calls == []


def test_direct_auth_brute_requires_roe_before_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import httpx

    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    calls: list[str] = []
    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: calls.append("called"))

    with pytest.raises(typer.BadParameter, match="requires --roe-id"):
        cli.auth_brute(
            engagement="1001",
            target="https://allowed.example/login",
            username="admin",
            dictionary_type="dynamic",
            max_attempts=1,
            roe_id=None,
            scope_manifest=None,
        )
    assert calls == []


def test_direct_auth_brute_scope_denies_before_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import httpx

    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    calls: list[str] = []
    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: calls.append("called"))

    with pytest.raises(typer.BadParameter, match="outside scope"):
        cli.auth_brute(
            engagement="1001",
            target="https://evil.example/login",
            username="admin",
            dictionary_type="dynamic",
            max_attempts=1,
            roe_id="ROE-ACME-2026-07",
            scope_manifest=None,
        )
    assert calls == []


def test_direct_cloud_firebase_requires_roe_before_auditor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["project.firebaseapp.com"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    with pytest.raises(typer.BadParameter, match="requires --roe-id"):
        cli.cloud_firebase(
            engagement="1001",
            project_id="project",
            api_key=None,
            auto_discover_web=False,
            scavenge_repos=False,
            tests="auth",
            timeout=1,
            dry_run=False,
            roe_id=None,
            scope_manifest=None,
        )


def test_direct_cloud_supabase_scope_denies_before_scanner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.supabase.co"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    with pytest.raises(typer.BadParameter, match="outside scope"):
        cli.cloud_supabase(
            engagement="1001",
            project_ref="evil",
            url=None,
            anon_key=None,
            auth_token=None,
            auto_discover=False,
            mobile_extract=False,
            repo_scavenge=False,
            dry_run=False,
            roe_id="ROE-ACME-2026-07",
            scope_manifest=None,
        )


def test_direct_cloud_firebase_extract_target_url_denies_before_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import forge.phase4.firebase_extract as firebase_extract

    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    calls: list[str] = []
    monkeypatch.setattr(
        firebase_extract,
        "extract_firebase_config",
        lambda *args, **kwargs: calls.append("called") or [],
    )

    with pytest.raises(typer.BadParameter, match="outside scope"):
        cli.cloud_firebase_extract(
            engagement="1001",
            apk=None,
            ipa=None,
            target_url="https://evil.example",
            output_json=None,
            dry_run=False,
            scope_manifest=None,
        )
    assert calls == []


def test_direct_cloud_aws_requires_roe_before_questionary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    with pytest.raises(typer.BadParameter, match="requires --roe-id"):
        cli.cloud_aws(
            engagement="1001",
            profile=None,
            regions=None,
            services="all",
            dry_run=False,
            output_format="json",
            output_path=None,
            timeout=1,
            roe_id=None,
        )


def test_direct_cloud_aws_yes_skips_questionary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import forge.phase4.aws_audit as aws_audit

    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        aws_audit,
        "run_aws_audit",
        lambda **kwargs: calls.append(kwargs) or [],
    )

    cli.cloud_aws(
        engagement="1001",
        profile=None,
        regions=None,
        services="all",
        dry_run=False,
        output_format="json",
        output_path=str(tmp_path / "aws.json"),
        timeout=1,
        roe_id="ROE-ACME-2026-07",
        yes=True,
    )

    assert calls[0]["engagement_id"] == 1001
    assert calls[0]["dry_run"] is False


def test_direct_cloud_azure_requires_roe_before_questionary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    with pytest.raises(typer.BadParameter, match="requires --roe-id"):
        cli.cloud_azure(
            engagement="1001",
            subscription_id=None,
            tenant_id=None,
            client_id=None,
            client_secret=None,
            services="all",
            dry_run=False,
            output_format="json",
            output_path=None,
            timeout=1,
            roe_id=None,
        )


def test_direct_cloud_azure_yes_skips_questionary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import forge.phase4.azure_audit as azure_audit

    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        azure_audit,
        "run_azure_audit",
        lambda **kwargs: calls.append(kwargs) or [],
    )

    cli.cloud_azure(
        engagement="1001",
        subscription_id=None,
        tenant_id=None,
        client_id=None,
        client_secret=None,
        services="all",
        dry_run=False,
        output_format="json",
        output_path=str(tmp_path / "azure.json"),
        timeout=1,
        roe_id="ROE-ACME-2026-07",
        yes=True,
    )

    assert calls[0]["engagement_id"] == 1001
    assert calls[0]["dry_run"] is False


def test_direct_vuln_idor_requires_roe_before_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    with pytest.raises(typer.BadParameter, match="requires --roe-id"):
        cli.vuln_idor(
            engagement="1001",
            target="https://allowed.example/app?id=1",
            depth=1,
            delay=0.0,
            cookie=None,
            header=None,
            dry_run=False,
            roe_id=None,
            scope_manifest=None,
        )


def test_direct_vuln_idor_scope_denies_before_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import forge.phase4.param_probe as param_probe

    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    calls: list[str] = []

    class _Scanner:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            calls.append("init")

        def scan(self, *_args: object, **_kwargs: object) -> list[object]:
            calls.append("scan")
            return []

    monkeypatch.setattr(param_probe, "IDORScanner", _Scanner)

    with pytest.raises(typer.BadParameter, match="outside scope"):
        cli.vuln_idor(
            engagement="1001",
            target="https://evil.example/app?id=1",
            depth=1,
            delay=0.0,
            cookie=None,
            header=None,
            dry_run=False,
            roe_id="ROE-ACME-2026-07",
            scope_manifest=None,
        )
    assert calls == []


def test_idor_scanner_module_scope_gate_denies_before_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forge.phase4.param_probe import IDORScanner

    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    scanner = IDORScanner(db_path=db_path, engagement_id=1001)

    calls: list[str] = []
    monkeypatch.setattr(scanner, "_make_session", lambda *args, **kwargs: calls.append("called"))

    with pytest.raises(Exception, match="not within engagement scope"):
        scanner.scan(
            target_url="https://evil.example/app?id=1",
            depth=1,
            delay=0.0,
            dry_run=False,
            require_scope=True,
        )
    assert calls == []


def test_direct_vuln_passive_target_scope_denies_before_collection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import forge.phase2.xray_runner as xray_runner

    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))

    calls: list[str] = []
    monkeypatch.setattr(
        xray_runner,
        "run_passive_http_collection",
        lambda *args, **kwargs: calls.append("called") or 0,
    )

    with pytest.raises(typer.BadParameter, match="outside scope"):
        cli.vuln_passive(
            engagement="1001",
            target="https://evil.example/",
            input_file=None,
            proxy=None,
            scope_manifest=None,
        )
    assert calls == []


def test_supabase_scanner_module_scope_gate_denies_before_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forge.phase4.api_policy_check import SupabaseScanner

    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.supabase.co"])
    scanner = SupabaseScanner(db_path=db_path, engagement_id=1001)

    calls: list[str] = []
    monkeypatch.setattr(scanner, "_make_session", lambda *args, **kwargs: calls.append("called"))

    with pytest.raises(Exception, match="not within engagement scope"):
        scanner.scan(
            project_ref="evil",
            dry_run=False,
            auto_discover=False,
            mobile_extract=False,
            repo_scavenge=False,
            require_scope=True,
        )
    assert calls == []


def test_firebase_auditor_module_scope_gate_denies_before_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forge.phase4.cloud_audit import FirebaseAuditor

    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.firebaseapp.com"])
    auditor = FirebaseAuditor(db_path=db_path, engagement_id=1001)

    calls: list[str] = []
    monkeypatch.setattr(auditor, "_register_cleanup", lambda *args, **kwargs: calls.append("called"))

    with pytest.raises(Exception, match="not within engagement scope"):
        auditor.run(
            project_id="evil",
            tests=["auth"],
            dry_run=False,
            auto_discover_web=False,
            repo_scavenge=False,
            require_scope=True,
        )
    assert calls == []


def test_direct_post_shell_requires_roe_before_payload_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))
    monkeypatch.setattr(cli, "_assert_offensive_cli", lambda *_args, **_kwargs: None)

    with pytest.raises(typer.BadParameter, match="requires --roe-id"):
        cli.post_shell(
            engagement="1001",
            lhost="127.0.0.1",
            lport=443,
            gen_cert=False,
            roe_id=None,
        )


def test_direct_post_beacon_requires_roe_before_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))
    monkeypatch.setattr(cli, "_assert_offensive_cli", lambda *_args, **_kwargs: None)

    with pytest.raises(typer.BadParameter, match="requires --roe-id"):
        cli.post_beacon(
            engagement="1001",
            agent_type="python",
            channel="https",
            c2_urls="https://c2.example",
            interval=60,
            jitter_pct=10,
            output=str(tmp_path / "beacon.py"),
            smb_pipe_name=None,
            smb_target=None,
            smb_username=None,
            smb_domain=None,
            smb_fallback_timeout=None,
            icmp_target_ip=None,
            icmp_packet_interval=None,
            enable_fallback=True,
            roe_id=None,
        )


def test_direct_post_lateral_scope_denies_before_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import forge.utils.post.remote_exec as remote_exec

    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    monkeypatch.setattr(cli.ForgeConfig, "load", staticmethod(lambda: _FakeConfig(db_path, tmp_path)))
    monkeypatch.setattr(cli, "_assert_offensive_cli", lambda *_args, **_kwargs: None)

    calls: list[str] = []
    monkeypatch.setattr(remote_exec, "run_lateral", lambda *args, **kwargs: calls.append("called"))

    with pytest.raises(typer.BadParameter, match="outside scope"):
        cli.post_lateral(
            engagement="1001",
            target_host="evil.example",
            technique="smb_exec",
            cleanup_on_exit=True,
            roe_id="ROE-ACME-2026-07",
            scope_manifest=None,
        )
    assert calls == []


def test_phase5_boundary_check_reads_scope_json(
    tmp_path: Path,
) -> None:
    from forge.utils.post.boundary_check import assert_in_scope

    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])

    assert_in_scope("allowed.example", 1001, db_path)


def test_phase5_boundary_check_reads_manifest_scope_json(
    tmp_path: Path,
) -> None:
    from forge.utils.post.boundary_check import assert_in_scope

    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(
        db_path,
        scope={
            "domains": ["allowed.example"],
            "urls": ["https://portal.allowed.example/app"],
            "authorized_seeds": ["security@allowed.example"],
        },
    )

    assert_in_scope("allowed.example", 1001, db_path)
    assert_in_scope("https://portal.allowed.example/admin", 1001, db_path)
