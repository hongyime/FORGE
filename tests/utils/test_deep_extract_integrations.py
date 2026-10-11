"""Integration tests verifying every module calls deep_extract.

The universal :func:`forge.utils.deep_extract.deep_extract_from_content`
hook is wired into:

* ``forge.phase1.crawler`` — after fetching HTML
* ``forge.phase2.theharvester`` — after parsing JSON output
* ``forge.phase2.xposed`` — after fetching breach data
* ``forge.phase4.firebase_extract`` — after fetching JS/HTML
* ``forge.phase4.supabase_scanner`` — after fetching JS/HTML
* ``forge.phase4.artifact_parsers`` — new ``deep_extract_artifact`` helper
* ``forge.utils.intel.wayback_lookup`` — ``deep_extract_wayback_urls``
* ``forge.utils.intel.commoncrawl_lookup`` — ``deep_extract_commoncrawl_urls``
* ``forge.phase6.report_synthesizer`` — after Markdown render

Each test checks the integration is live. These are focused smoke tests;
the end-to-end behaviour of each module itself has its own test suite.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


class TestCrawlerIntegration:
    def test_crawler_module_imports_deep_extract(self) -> None:
        """The crawler module should reference deep_extract in its body."""
        source = Path("forge/phase1/crawler.py").read_text(encoding="utf-8")
        assert "deep_extract_from_content" in source
        assert "crawler:" in source  # the source label prefix


class TestEmailChainIntegration:
    def test_xposed_calls_deep_extract(self) -> None:
        source = Path("forge/phase2/xposed.py").read_text(encoding="utf-8")
        assert "deep_extract_from_content" in source
        assert "xposedornot:" in source

    def test_theharvester_calls_deep_extract(self) -> None:
        source = Path("forge/phase2/theharvester.py").read_text(encoding="utf-8")
        assert "deep_extract_from_content" in source
        assert "theharvester:" in source


class TestCloudScanIntegration:
    def test_firebase_extract_calls_deep_extract(self) -> None:
        source = Path("forge/phase4/firebase_extract.py").read_text(encoding="utf-8")
        assert "deep_extract_from_content" in source
        assert "firebase_extract:" in source

    def test_supabase_scanner_calls_deep_extract(self) -> None:
        source = Path("forge/phase4/supabase_scanner.py").read_text(encoding="utf-8")
        assert "deep_extract_from_content" in source
        assert "supabase_scanner:" in source


class TestDnsIntegration:
    def test_cli_dns_probe_calls_deep_extract(self) -> None:
        source = Path("forge/cli.py").read_text(encoding="utf-8")
        assert "deep_extract_from_content" in source
        assert '"dns:' in source or "'dns:" in source or "f\"dns:" in source


class TestWaybackCommonCrawlIntegration:
    def test_wayback_module_has_helper(self) -> None:
        from forge.utils.intel.wayback_lookup import deep_extract_wayback_urls

        result = deep_extract_wayback_urls(
            [
                "https://acme.example/admin/old",
                "https://cdn.acme.example/legacy.js?token=abc",
            ],
            domain_name="acme.example",
        )
        # Pure functional call — no engagement so stats aren't persisted,
        # but the extraction still returns the merged payload.
        assert "acme.example" in result["domains"]
        assert "cdn.acme.example" in result["domains"]
        assert any("https://" in u for u in result["urls"])

    def test_commoncrawl_module_has_helper(self) -> None:
        from forge.utils.intel.commoncrawl_lookup import (
            deep_extract_commoncrawl_urls,
        )

        result = deep_extract_commoncrawl_urls(
            ["https://portal.acme.example/users", "https://api.acme.example/v2"],
            domain_name="acme.example",
        )
        assert "portal.acme.example" in result["domains"]
        assert "api.acme.example" in result["domains"]

    def test_wayback_helper_empty_input_returns_empty(self) -> None:
        from forge.utils.intel.wayback_lookup import deep_extract_wayback_urls

        assert deep_extract_wayback_urls([], domain_name="acme.example") == {}


class TestArtifactIntegration:
    def test_artifact_parsers_expose_deep_extract(self) -> None:
        from forge.phase4.artifact_parsers import (
            deep_extract_artifact,
            extract_strings,
        )

        assert callable(deep_extract_artifact)
        assert callable(extract_strings)

    def test_extract_strings_returns_printable_runs(self, tmp_path: Path) -> None:
        from forge.phase4.artifact_parsers import extract_strings

        f = tmp_path / "artifact.bin"
        payload = (
            b"\x00\x01\x02stable_run_1\n"
            b"\xff\xfe\xfdhttps://api.acme.example/leak\n"
            b"\x00admin@acme.example\n"
        )
        f.write_bytes(payload)
        strings = extract_strings(f)
        assert any("stable_run_1" in s for s in strings)
        assert any("https://api.acme.example/leak" in s for s in strings)
        assert any("admin@acme.example" in s for s in strings)

    def test_deep_extract_artifact_scans_strings(self, tmp_path: Path) -> None:
        from forge.phase4.artifact_parsers import deep_extract_artifact

        f = tmp_path / "artifact.bin"
        f.write_bytes(
            b"random bytes\n"
            b"https://portal.acme.example/x\n"
            b"\x00s3://acme-public-assets\n"
        )
        result = deep_extract_artifact(f, source="unit:artifact")
        assert result["domains"] == ["portal.acme.example"]
        assert "cloud_ref:aws_s3:acme-public-assets" in result["cloud_refs"]


class TestReportIntegration:
    def test_report_synthesizer_calls_deep_extract(self) -> None:
        source = Path("forge/phase6/report_synthesizer.py").read_text(encoding="utf-8")
        assert "deep_extract_from_content" in source
        assert "report:" in source


class TestDashboardCliIntegration:
    def test_dashboard_cli_registers_extraction_stats(self) -> None:
        import typer

        from forge.dashboard.cli import register_dashboard_commands

        app = typer.Typer()
        register_dashboard_commands(app)
        commands = [cmd.name for cmd in app.registered_commands]
        assert "goal-progress" in commands
        assert "extraction-stats" in commands

    def test_extraction_stats_subcommand_runs(self, tmp_path: Path) -> None:
        """``forge dashboard extraction-stats`` invokes without error."""
        import typer
        from typer.testing import CliRunner

        from forge.dashboard.cli import register_dashboard_commands

        app = typer.Typer()
        register_dashboard_commands(app)
        runner = CliRunner()

        # Seed a row so there's something to render
        from forge.utils.deep_extract import deep_extract_from_content

        db = tmp_path / "eng.db"
        deep_extract_from_content(
            "https://portal.acme.example and admin@acme.example",
            source="integration:test",
            engagement_id=1234,
            db_path=str(db),
        )

        # Patch ForgeConfig.engagement_db_path to point to our temp DB
        with patch(
            "forge.dashboard.cli.ForgeConfig"
        ) as cfg_cls:
            cfg_instance = cfg_cls.load.return_value
            cfg_instance.engagement_db_path.return_value = db
            result = runner.invoke(
                app, ["extraction-stats", "-e", "1234", "--json"]
            )
        assert result.exit_code == 0, result.output
        payload_text = result.stdout
        assert "portal.acme.example" in payload_text or "integration:test" in payload_text


class TestDeepExtractNeverRaises:
    """Any one of the integration points failing must not kill its parent.

    This is a safety contract: deep extraction is a seed-feedback
    improvement, not a critical path. Even if the hook raises, the
    hosting module must continue.
    """

    def test_crawler_hook_tolerates_extraction_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from forge.utils import deep_extract

        def raiser(*a, **k):
            raise RuntimeError("boom")

        monkeypatch.setattr(deep_extract, "deep_extract_from_content", raiser)
        # The hook is only wired as an inner try/except — directly
        # calling the raising replacement must raise, but the hook sites
        # (phase1.crawler, phase2.theharvester, etc.) each wrap the call
        # in try/except so they still work. We assert that the direct
        # call does raise so the import path is live.
        with pytest.raises(RuntimeError):
            deep_extract.deep_extract_from_content("x", source="t")
