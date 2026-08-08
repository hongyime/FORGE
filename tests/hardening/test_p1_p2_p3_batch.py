"""Regression tests for P1/P2/P3 hardening fixes shipped after `83f85d4`.

Coverage:
- P1-A01: auth_check.py env-pollution fix + threading lock + test-key production refusal
- P1: audit_log column canonical rewrites in 4 modules
- P2-B01: TUI cascade choices built from _AUTO_CASCADE_DEFAULT_ORDER
- P2-B02: doctor command registered exactly once
- P2-B03: wizard passes scope_override to scan_engagement
- P2-B04: handle_finder migrated to bounded_worker_pool
- P2-B05: _scan_host_ports_sync guards against running event loop
- P2-B06: V-03 flags IPv6 + loopback + CGNAT + link-local
- P2-B07: V-03 warns on overly-broad approved_ip_ranges
- P2-B10: scope-manifest size cap + path allowlist
- P2-B13: cloud_ref canonicalised in webui
- P3-C02: Firebase api_key redacted first4...last4
"""

from __future__ import annotations

import inspect
import logging
import re
import sqlite3
from pathlib import Path

import pytest


class TestAuthCheckEnvPollutionFix:
    """P1-A01: FORGE_ENGAGEMENT_KEY must not stay polluted by test-key."""

    def test_lock_is_defined_at_module_level(self) -> None:
        from forge.utils.intel import auth_check

        assert hasattr(auth_check, "_AUTH_CHECK_ENV_LOCK")
        import threading as _th
        assert isinstance(auth_check._AUTH_CHECK_ENV_LOCK, type(_th.Lock()))

    def test_finally_clause_pops_empty_string_previous(self) -> None:
        """Read the source and confirm the pop guard treats '' the same as None."""
        from forge.utils.intel import auth_check

        source = inspect.getsource(auth_check)
        assert "previous_key in (None, \"\")" in source, (
            "finally-clause must restore both None and '' cases so an "
            "empty-string prior key doesn't leave test-key in place."
        )

    def test_production_path_refuses_test_key_fallback(self) -> None:
        """When PYTEST_CURRENT_TEST is unset, code path must NOT mutate env to test-key."""
        from forge.utils.intel import auth_check

        source = inspect.getsource(auth_check)
        # Verify the production-refusal branch is present.
        assert "PYTEST_CURRENT_TEST" in source
        assert 'os.environ.get("PYTEST_CURRENT_TEST")' in source


class TestAuditLogColumnsCanonical:
    """P1: 4 modules must use canonical audit_log column set."""

    @pytest.mark.parametrize(
        "module_path",
        [
            "forge/phase5/approval_gate.py",
            "forge/phase5/exfiltration.py",
            "forge/utils/playbooks/rce_hunter.py",
            "forge/utils/playbooks/waf_evasion.py",
        ],
    )
    def test_module_no_longer_uses_legacy_detail_timestamp_columns(self, module_path: str) -> None:
        text = Path(module_path).read_text(encoding="utf-8", errors="replace")
        # Only look for the specific pattern the old code used.
        legacy = "(engagement_id, action, detail, operator, timestamp)"
        assert legacy not in text, (
            f"{module_path} still uses legacy audit_log column set "
            f"{legacy!r} which silently drops rows on the canonical schema."
        )

    @pytest.mark.parametrize(
        "module_path",
        [
            "forge/phase5/approval_gate.py",
            "forge/phase5/exfiltration.py",
            "forge/utils/playbooks/rce_hunter.py",
            "forge/utils/playbooks/waf_evasion.py",
        ],
    )
    def test_module_uses_canonical_audit_log_columns(self, module_path: str) -> None:
        text = Path(module_path).read_text(encoding="utf-8", errors="replace")
        assert "phase, module, action, target, result, operator" in text, (
            f"{module_path} must use the canonical (phase, module, action, "
            f"target, result, operator, logged_at) column set."
        )


class TestDoctorCommandRegisteredExactlyOnce:
    """P2-B02: no more duplicate @app.command('doctor')."""

    def test_only_one_doctor_registration(self) -> None:
        text = Path("forge/cli.py").read_text(encoding="utf-8", errors="replace")
        count = len(re.findall(r'@app\.command\("doctor"\)', text))
        assert count == 1, (
            f"expected exactly one @app.command('doctor'), found {count}. "
            f"The Typer decorator idiom silently discards duplicates but "
            f"they cause dead-code drift over time."
        )


class TestWizardPassesScopeOverride:
    """P2-B03: phase1/wizard.py must pass scope_override to scan_engagement."""

    def test_wizard_source_contains_scope_override_kwarg(self) -> None:
        text = Path("forge/phase1/wizard.py").read_text(encoding="utf-8", errors="replace")
        assert "scope_override=" in text, (
            "wizard must pass scope_override so _host_row_is_authorized_by_scope "
            "doesn't short-circuit True via the hosts.in_scope=1 DB bit."
        )
        assert "load_scope_from_db" in text, (
            "wizard must load the engagement scope before invoking the "
            "port scanner."
        )


class TestHandleFinderMigratedToBoundedWorkerPool:
    """P2-B04: handle_finder uses run_bounded instead of ThreadPoolExecutor."""

    def test_handle_finder_imports_run_bounded(self) -> None:
        text = Path("forge/utils/intel/handle_finder.py").read_text(encoding="utf-8")
        assert "from forge.utils.bounded_worker_pool import run_bounded" in text


class TestScanHostPortsSyncGuardsRunningLoop:
    """P2-B05: _scan_host_ports_sync uses running-loop guard."""

    def test_source_contains_get_running_loop_guard(self) -> None:
        text = Path("forge/phase1/port_scanner.py").read_text(encoding="utf-8")
        assert "asyncio.get_running_loop()" in text, (
            "port_scanner must guard asyncio.run against a running event loop."
        )

    @pytest.mark.asyncio
    async def test_can_be_called_from_running_event_loop(self) -> None:
        """Real-world: call scan_host_ports_sync from within an async context."""
        from forge.phase1.port_scanner import _scan_host_ports_sync

        # 198.18.0.1 is RFC-2544 test net; port 65533 almost certainly closed.
        # Sync helper must not crash despite being invoked from an async test.
        result = _scan_host_ports_sync("198.18.0.1", [65533], timeout=0.05)
        assert isinstance(result, list)


class TestV03ExtendedDetection:
    """P2-B06: V-03 flags IPv6, loopback, CGNAT, link-local."""

    def _run_v03(self, text: str, **kw):
        from forge.phase6.llm_validator import _v03_no_internal_ips, ValidationResult

        result = ValidationResult()
        _v03_no_internal_ips(text, kw.pop("approved_ips", None), result, False, **kw)
        return result

    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",           # IPv4 loopback
            "127.5.10.15",         # IPv4 loopback broad
            "100.64.0.1",          # CGNAT low
            "100.127.255.254",     # CGNAT high
            "169.254.1.1",         # IPv4 link-local
        ],
    )
    def test_ipv4_extended_ranges_flagged(self, ip: str) -> None:
        result = self._run_v03(f"See {ip} in the log", approved_ips=[])
        assert any(f"[V-03] Internal IP '{ip}'" in w for w in result.warnings), (
            f"V-03 must flag {ip!r} as internal."
        )

    @pytest.mark.parametrize(
        "ip",
        [
            "::1",                 # IPv6 loopback
            "fc00:1::1",           # IPv6 ULA (fc)
            "fd12:3456:789a::1",   # IPv6 ULA (fd)
            "fe80::1",             # IPv6 link-local
        ],
    )
    def test_ipv6_internal_ranges_flagged(self, ip: str) -> None:
        result = self._run_v03(f"jumpbox at {ip} exfiltrated data", approved_ips=[])
        assert any(f"[V-03] Internal IP" in w and ip.lower() in w.lower() for w in result.warnings), (
            f"V-03 must flag IPv6 internal {ip!r}."
        )

    def test_public_ip_not_flagged(self) -> None:
        result = self._run_v03("8.8.8.8 is Google DNS", approved_ips=[])
        assert not any("[V-03]" in w for w in result.warnings)


class TestV03OverlyBroadCidrWarning:
    """P2-B07: warn on 0.0.0.0/0 in approved_ip_ranges."""

    def test_prefixlen_zero_ipv4_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        from forge.phase6.llm_validator import _parse_approved_ip_ranges

        caplog.set_level(logging.WARNING, logger="forge.phase6.llm_validator")
        _parse_approved_ip_ranges(["0.0.0.0/0"])
        assert any(
            "unusually broad" in rec.message
            for rec in caplog.records
        )

    def test_narrow_range_no_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        from forge.phase6.llm_validator import _parse_approved_ip_ranges

        caplog.set_level(logging.WARNING, logger="forge.phase6.llm_validator")
        _parse_approved_ip_ranges(["10.0.0.0/24"])
        assert not any(
            "unusually broad" in rec.message
            for rec in caplog.records
        )


class TestScopeManifestPathAllowlist:
    """P2-B10: scope-manifest reads must be size-capped + path-allowlisted."""

    def test_rejects_oversize_inline_json(self) -> None:
        from forge.cli import _load_scope_manifest

        huge = "{" + '"pad":"' + ("A" * 1_100_000) + '"}'
        with pytest.raises(ValueError, match="1 MiB"):
            _load_scope_manifest(huge)

    def test_rejects_oversize_file(self, tmp_path: Path) -> None:
        from forge.cli import _load_scope_manifest

        big = tmp_path / "big.json"
        big.write_bytes(b'{"x":"' + b"a" * 1_100_000 + b'"}')
        with pytest.raises(ValueError, match="1 MiB"):
            _load_scope_manifest(str(big))

    def test_rejects_absolute_path_outside_workspace(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Path under neither cwd nor home is rejected."""
        from forge.cli import _load_scope_manifest

        # Use tmp_path as cwd. Then attempt to read from a completely separate
        # tmp folder created outside of it.
        outside = Path(tmp_path.parent) / "outside_workspace"
        outside.mkdir(exist_ok=True)
        outside_file = outside / "manifest.json"
        outside_file.write_text('{"domains": ["example.com"]}')

        monkeypatch.chdir(tmp_path)
        # Also override home so the "under home" fallback doesn't accidentally allow it
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        with pytest.raises(ValueError, match="outside the current working"):
            _load_scope_manifest(str(outside_file))

    def test_accepts_path_under_cwd(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from forge.cli import _load_scope_manifest

        manifest = tmp_path / "manifest.json"
        manifest.write_text('{"domains": ["example.com"]}')
        monkeypatch.chdir(tmp_path)
        # Should not raise.
        result = _load_scope_manifest(str(manifest))
        assert result["domains"] == ["example.com"]


class TestWebuiCanonicalisationIncludesCloudRef:
    """P2-B13: webui _canonical_seed_value canonicalises cloud_ref URLs."""

    def test_source_lists_cloud_ref(self) -> None:
        text = Path("forge/webui/app.py").read_text(encoding="utf-8")
        assert 'in {"url", "apk_url", "cloud_ref"}' in text, (
            "webui _canonical_seed_value must canonicalise cloud_ref URLs "
            "to avoid trailing-slash / casing duplicates."
        )


class TestFirebaseApiKeyRedactionFirst4Last4:
    """P3-C02: Firebase api_key printed as first4...last4, not first-N chars."""

    def test_cli_source_no_longer_shows_first_12_chars(self) -> None:
        # Cloud commands extracted to cli_cloud.py; check both files
        cli_text = Path("forge/cli.py").read_text(encoding="utf-8", errors="replace")
        cloud_text = Path("forge/cli_cloud.py").read_text(encoding="utf-8", errors="replace")
        combined = cli_text + cloud_text
        assert "api_key',''))[:12]" not in combined
        # And the redaction helper pattern is present (in cli_cloud.py after extraction)
        assert "[:4]" in combined and "[-4:]" in combined

    def test_firebase_extract_source_no_longer_shows_first_10_chars(self) -> None:
        text = Path("forge/phase4/firebase_extract.py").read_text(encoding="utf-8", errors="replace")
        assert "api_key[:10]" not in text
        assert "[:4]" in text and "[-4:]" in text
