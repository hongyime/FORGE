"""
tests/phase2/test_key_scanner.py
Canonical path maps to: forge/utils/intel/secret_finder.py  (Module 2-J)

Coverage target: 85%  (PRD §15.1)
OPSEC invariants tested:
  - no_validate → zero HTTP calls to provider APIs
  - proxy enforcement: exits 1 when validate enabled and proxy absent
  - questionary confirmation required before validation
  - key redaction in all output paths
VCR cassette directory: tests/cassettes/keyscan/
"""

from __future__ import annotations

import sqlite3
import sys
import re
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from forge.utils.intel.secret_finder import (
    AnthropicKeyValidator,
    AwsKeyValidator,
    AzureStorageConnectionStringValidator,
    CloudflareApiTokenValidator,
    DatadogApiKeyValidator,
    DiscordBotTokenValidator,
    GithubPatValidator,
    HuggingFaceTokenValidator,
    KeyPattern,
    NetlifyTokenValidator,
    NotionTokenValidator,
    OpenAIKeyValidator,
    PostHogPersonalApiKeyValidator,
    SentryAuthTokenValidator,
    SendgridKeyValidator,
    SlackTokenValidator,
    StripeKeyValidator,
    TelegramBotTokenValidator,
    VercelTokenValidator,
    ValidationResult,
    ValidationState,
    _gitlab_keyscan,
    _redact,
    _store_key_finding,
    load_key_patterns,
    run_key_scanner,
    run_keyscan,  # alias — must equal run_key_scanner
)

# ─── fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture()
def engagement_db(tmp_path: Path) -> Path:
    """
    Minimal engagement DB fixture aligned with the canonical secret_finder.py DDL.

    key_scanner_findings schema matches _KEYSCAN_DDL in secret_finder.py:
      - Full column set: domain, service, pattern_name, source_backend, source_url,
        repo_name, key_redacted, key_enc, validation_state, validation_detail,
        found_at, validated_at.
      - UNIQUE constraint on (engagement_id, source_url, pattern_name).
      - validation_state CHECK uses REVOKED/UNCONFIRMED (not INVALID/UNVALIDATED).

    audit_log uses logged_at (not timestamp) to match the canonical schema.py column name.
    """
    db = tmp_path / "eng.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE engagements (
            id INTEGER PRIMARY KEY,
            name TEXT,
            scope_json TEXT,
            status TEXT,
            operator TEXT,
            created_at TEXT,
            updated_at TEXT
        );
        CREATE TABLE key_scanner_findings (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id    INTEGER NOT NULL,
            domain           TEXT    NOT NULL,
            service          TEXT    NOT NULL,
            pattern_name     TEXT    NOT NULL,
            source_backend   TEXT    NOT NULL DEFAULT 'github',
            source_url       TEXT    NOT NULL,
            repo_name        TEXT,
            key_redacted     TEXT    NOT NULL,
            key_enc          TEXT,
            validation_state TEXT    NOT NULL DEFAULT 'UNCONFIRMED'
                             CHECK (validation_state IN ('ACTIVE','REVOKED','UNCONFIRMED','ERROR')),
            validation_detail TEXT,
            found_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            validated_at     TIMESTAMP,
            UNIQUE (engagement_id, source_url, pattern_name)
        );
        CREATE TABLE scavenger_findings (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id     INTEGER NOT NULL,
            url               TEXT    NOT NULL,
            pattern_name      TEXT    NOT NULL,
            matched_value_enc TEXT    NOT NULL,
            context           TEXT,
            backend           TEXT    NOT NULL DEFAULT 'github',
            discovered_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (engagement_id, url, pattern_name)
        );
        CREATE TABLE audit_log (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            phase         TEXT,
            module        TEXT,
            action        TEXT,
            target        TEXT,
            result        TEXT,
            operator      TEXT,
            logged_at     TEXT
        );
        INSERT INTO engagements
            (id, name, scope_json, status, operator, created_at, updated_at)
        VALUES
            (1, 'test-eng', '["example.com"]', 'ACTIVE', 'tester', datetime('now'), datetime('now'));
    """)
    con.commit()
    con.close()
    return db


def _mock_http(payload: dict, status: int = 200) -> MagicMock:
    m = MagicMock()
    m.status_code = status
    m.json.return_value = payload
    m.headers = {}
    return m


def _github_search_page(items: list[dict], total: int) -> MagicMock:
    m = MagicMock()
    m.status_code = 200
    m.json.return_value = {"items": items, "total_count": total}
    m.headers = {"X-RateLimit-Remaining": "29", "X-RateLimit-Reset": "9999999999"}
    return m


def _result_item(n: int = 1) -> dict:
    return {
        "html_url": f"https://github.com/example/repo/blob/main/creds{n}.py",
        "repository": {"full_name": "example/repo"},
        "path": f"creds{n}.py",
    }


# ═══════════════════════════════════════════════════════════════════════════
# Pattern file
# ═══════════════════════════════════════════════════════════════════════════


class TestPatternFile:
    def test_minimum_pattern_count(self):
        patterns = load_key_patterns()
        assert len(patterns) >= 7

    def test_all_patterns_have_required_fields(self):
        for p in load_key_patterns():
            assert "name" in p, f"Missing 'name' in: {p}"
            assert "pattern" in p, f"Missing 'pattern' in: {p}"
            assert "service" in p, f"Missing 'service' in: {p}"
            assert "validation_method" in p, f"Missing 'validation_method' in: {p}"

    def test_patterns_compile_as_regex(self):
        import re

        for p in load_key_patterns():
            re.compile(p["pattern"])  # must not raise

    def test_aws_pattern_present(self):
        services = [p["service"].lower() for p in load_key_patterns()]
        assert any("aws" in s for s in services)

    def test_stripe_pattern_present(self):
        services = [p["service"].lower() for p in load_key_patterns()]
        assert any("stripe" in s for s in services)

    def test_github_pat_pattern_present(self):
        services = [p["service"].lower() for p in load_key_patterns()]
        assert any("github" in s for s in services)

    def test_gitlab_pat_pattern_present(self):
        gitlab_patterns = [
            p for p in load_key_patterns() if p["service"].lower() == "gitlab"
        ]
        assert any(p["name"] == "gitlab_pat" for p in gitlab_patterns)

    def test_legacy_phase2_gitlab_pattern_uses_shared_validator(self):
        from forge.phase2 import key_scanner as legacy_key_scanner  # noqa: PLC0415

        patterns = legacy_key_scanner._load_patterns()
        gitlab_pattern = next(pattern for pattern in patterns if pattern["name"] == "gitlab_pat")

        assert gitlab_pattern["service"] == "gitlab"
        assert gitlab_pattern["validation_method"] == "GitlabPatValidator"
        assert "GitlabPatValidator" in legacy_key_scanner._VALIDATOR_MAP

    def test_legacy_phase2_run_keyscan_extracts_real_source_content(self, tmp_path: Path):
        from forge.phase2 import key_scanner as legacy_key_scanner  # noqa: PLC0415

        db_path = tmp_path / "legacy-keyscan.db"
        con = sqlite3.connect(db_path)
        secret = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        pattern = {
            "name": "github_pat_classic",
            "service": "github",
            "regex": r"ghp_[A-Za-z0-9]{36}",
            "confidence": "high",
            "validation_method": "GithubPatValidator",
        }
        hit = {
            "source_url": "https://github.com/acme/repo/blob/main/settings.py",
            "raw_url": "https://raw.githubusercontent.com/acme/repo/main/settings.py",
            "repo_name": "acme/repo",
            "backend": "github",
        }
        try:
            with (
                patch.object(legacy_key_scanner, "_load_patterns", return_value=[pattern]),
                patch.object(legacy_key_scanner, "wait_for_internet", return_value=True),
                patch.object(legacy_key_scanner, "with_internet_retry", return_value=[hit]),
                patch.object(
                    legacy_key_scanner,
                    "_fetch_file_content",
                    return_value=f"GITHUB_TOKEN={secret}",
                ),
            ):
                count = legacy_key_scanner.run_keyscan(
                    engagement_id=1,
                    engagement_scope=["example.com"],
                    domain="example.com",
                    eng_db_conn=con,
                    github_token="ghp_operator",
                    no_validate=True,
                )

            row = con.execute(
                """
                SELECT key_redacted, key_enc, source_backend, repo_name
                FROM key_scanner_findings
                WHERE source_url=?
                """,
                (hit["source_url"],),
            ).fetchone()
        finally:
            con.close()

        assert count == 1
        assert row is not None
        assert row[0] == "ghp_...GHIJ"
        assert row[0] != legacy_key_scanner._redact("[extracted-from-file]")
        assert row[1] is None
        assert row[2] == "github"
        assert row[3] == "acme/repo"

    def test_legacy_phase2_run_keyscan_uses_gitlab_token(self, tmp_path: Path):
        from forge.phase2 import key_scanner as legacy_key_scanner  # noqa: PLC0415

        db_path = tmp_path / "legacy-gitlab-keyscan.db"
        con = sqlite3.connect(db_path)
        secret = "glpat-abcdefghijklmnopqrst"
        pattern = {
            "name": "gitlab_pat",
            "service": "gitlab",
            "regex": r"glpat-[A-Za-z0-9_-]{20}",
            "confidence": "high",
            "validation_method": "GitlabPatValidator",
        }
        hit = {
            "source_url": "https://gitlab.com/acme/repo/-/blob/main/prod.env",
            "raw_url": "https://gitlab.com/api/v4/projects/123/repository/files/prod.env/raw",
            "repo_name": "acme/repo",
            "backend": "gitlab",
            "ref": "main",
        }

        def _run_provider(fn, *args):
            return fn(*args)

        try:
            with (
                patch.object(legacy_key_scanner, "_load_patterns", return_value=[pattern]),
                patch.object(legacy_key_scanner, "wait_for_internet", return_value=True),
                patch.object(legacy_key_scanner, "with_internet_retry", side_effect=_run_provider),
                patch.object(legacy_key_scanner, "_github_keyscan", return_value=[]),
                patch.object(legacy_key_scanner, "_gitlab_keyscan", return_value=[hit]) as mock_gitlab,
                patch.object(
                    legacy_key_scanner,
                    "_fetch_file_content",
                    return_value=f"GITLAB_TOKEN={secret}",
                ) as mock_fetch,
            ):
                count = legacy_key_scanner.run_keyscan(
                    engagement_id=1,
                    engagement_scope=["example.com"],
                    domain="example.com",
                    eng_db_conn=con,
                    github_token=None,
                    gitlab_token="glpat_operator",
                    no_validate=True,
                )

            row = con.execute(
                """
                SELECT key_redacted, source_backend, repo_name
                FROM key_scanner_findings
                WHERE source_url=?
                """,
                (hit["source_url"],),
            ).fetchone()
        finally:
            con.close()

        assert count == 1
        mock_gitlab.assert_called_once_with(pattern, "example.com", "glpat_operator")
        mock_fetch.assert_called_once_with(
            hit["raw_url"],
            "glpat_operator",
            backend="gitlab",
            ref="main",
        )
        assert row == ("glpa...qrst", "gitlab", "acme/repo")

    def test_legacy_phase2_validation_detail_records_method_prefix(self, tmp_path: Path):
        from forge.phase2 import key_scanner as legacy_key_scanner  # noqa: PLC0415

        db_path = tmp_path / "legacy-validation-method.db"
        con = sqlite3.connect(db_path)
        secret = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        pattern = {
            "name": "github_pat_classic",
            "service": "github",
            "regex": r"ghp_[A-Za-z0-9]{36}",
            "confidence": "high",
            "validation_method": "GithubPatValidator",
        }
        hit = {
            "source_url": "https://github.com/acme/repo/blob/main/settings.py",
            "raw_url": "https://raw.githubusercontent.com/acme/repo/main/settings.py",
            "repo_name": "acme/repo",
            "backend": "github",
        }

        class _FakeGithubValidator:
            result_validation_method = "github_user_api"

            def validate(self, key, proxy=None):  # noqa: ANN001
                del key, proxy
                return legacy_key_scanner.ValidationResult(
                    state=legacy_key_scanner.ValidationState.ACTIVE,
                    detail="GitHub user ok: user_id=123456 login=alice user_profile_present=true",
                )

        try:
            with (
                patch.object(legacy_key_scanner, "_load_patterns", return_value=[pattern]),
                patch.object(legacy_key_scanner, "wait_for_internet", return_value=True),
                patch.object(legacy_key_scanner, "with_internet_retry", return_value=[hit]),
                patch.object(
                    legacy_key_scanner,
                    "_fetch_file_content",
                    return_value=f"GITHUB_TOKEN={secret}",
                ),
                patch.dict(
                    legacy_key_scanner._VALIDATOR_MAP,
                    {"GithubPatValidator": _FakeGithubValidator()},
                ),
                patch("questionary.confirm") as mock_confirm,
            ):
                mock_confirm.return_value.ask.return_value = True
                count = legacy_key_scanner.run_keyscan(
                    engagement_id=1,
                    engagement_scope=["example.com"],
                    domain="example.com",
                    eng_db_conn=con,
                    github_token="ghp_operator",
                    no_validate=False,
                    validation_proxy="socks5://127.0.0.1:9050",
                )

            row = con.execute(
                "SELECT validation_state, validation_detail FROM key_scanner_findings"
            ).fetchone()
        finally:
            con.close()

        assert count == 1
        assert row is not None
        assert row[0] == "ACTIVE"
        assert row[1] == (
            "VALIDATED:github_user_api:"
            "GitHub user ok: user_id=123456 login=alice user_profile_present=true"
        )

    def test_legacy_phase2_slack_patterns_use_shared_validator(self):
        from forge.phase2 import key_scanner as legacy_key_scanner  # noqa: PLC0415

        patterns = legacy_key_scanner._load_patterns()
        slack_patterns = {
            pattern["name"]: pattern
            for pattern in patterns
            if pattern["service"] == "slack"
        }

        assert slack_patterns["slack_bot_token"]["validation_method"] == "SlackTokenValidator"
        assert slack_patterns["slack_user_token"]["validation_method"] == "SlackTokenValidator"
        assert "SlackTokenValidator" in legacy_key_scanner._VALIDATOR_MAP

    def test_legacy_phase2_supported_provider_patterns_use_shared_validators(self):
        from forge.phase2 import key_scanner as legacy_key_scanner  # noqa: PLC0415

        patterns = {
            pattern["name"]: pattern
            for pattern in legacy_key_scanner._load_patterns()
        }

        assert patterns["stripe_live_secret_key"]["validation_method"] == "StripeKeyValidator"
        assert patterns["mailchimp_api_key"]["validation_method"] == "MailchimpKeyValidator"
        assert patterns["azure_storage_key"]["validation_method"] == (
            "AzureStorageConnectionStringValidator"
        )
        assert isinstance(
            legacy_key_scanner._VALIDATOR_MAP["StripeKeyValidator"],
            StripeKeyValidator,
        )
        assert isinstance(
            legacy_key_scanner._VALIDATOR_MAP["SendgridKeyValidator"],
            SendgridKeyValidator,
        )
        assert "MailchimpKeyValidator" in legacy_key_scanner._VALIDATOR_MAP
        assert "AzureStorageConnectionStringValidator" in legacy_key_scanner._VALIDATOR_MAP

    def test_legacy_phase2_stripe_sendgrid_map_uses_proof_aware_shared_validators(self):
        from forge.phase2 import key_scanner as legacy_key_scanner  # noqa: PLC0415

        stripe_validator = legacy_key_scanner._VALIDATOR_MAP["StripeKeyValidator"]
        with patch("httpx.Client.get", return_value=_mock_http({"ok": True}, status=200)):
            stripe_result = stripe_validator.validate("sk_live_" + "x" * 24)
        assert stripe_result.state == ValidationState.UNCONFIRMED
        assert "missing balance object" in (stripe_result.detail or "")

        sendgrid_validator = legacy_key_scanner._VALIDATOR_MAP["SendgridKeyValidator"]
        with patch(
            "forge.utils.intel.secret_finder.key_validation_get",
            return_value=_mock_http({"id": "placeholder"}, status=200),
        ):
            sendgrid_result = sendgrid_validator.validate(
                "SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg"
            )
        assert sendgrid_result.state == ValidationState.UNCONFIRMED
        assert "missing profile proof" in (sendgrid_result.detail or "")

    def test_legacy_phase2_stripe_fallback_validator_requires_balance_proof(self):
        from forge.phase2 import key_scanner as legacy_key_scanner  # noqa: PLC0415

        stripe_validator = legacy_key_scanner.StripeKeyValidator()

        with patch("httpx.Client.get", return_value=_mock_http({"ok": True}, status=200)):
            low_signal = stripe_validator.validate("sk_live_" + "x" * 24)
        assert low_signal.state == legacy_key_scanner.ValidationState.UNCONFIRMED
        assert low_signal.detail == "Stripe balance response missing balance object"

        with patch(
            "httpx.Client.get",
            return_value=_mock_http(
                {
                    "object": "balance",
                    "livemode": True,
                    "available": [{"currency": "usd"}],
                    "pending": [{"currency": "sgd"}],
                },
                status=200,
            ),
        ):
            proven = stripe_validator.validate("sk_live_" + "x" * 24)
        assert proven.state == legacy_key_scanner.ValidationState.ACTIVE
        assert proven.detail == "Stripe balance accessible: mode=live currencies=sgd,usd"

    def test_legacy_phase2_sendgrid_fallback_validator_requires_profile_proof(self):
        from forge.phase2 import key_scanner as legacy_key_scanner  # noqa: PLC0415

        sendgrid_validator = legacy_key_scanner.SendgridKeyValidator()

        with patch("httpx.Client.get", return_value=_mock_http({"id": "placeholder"}, status=200)):
            low_signal = sendgrid_validator.validate(
                "SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg"
            )
        assert low_signal.state == legacy_key_scanner.ValidationState.UNCONFIRMED
        assert low_signal.detail == "SendGrid profile response missing profile proof"

        with patch(
            "httpx.Client.get",
            return_value=_mock_http(
                {"email": "ops@example.com", "username": "mailops"},
                status=200,
            ),
        ):
            proven = sendgrid_validator.validate(
                "SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg"
            )
        assert proven.state == legacy_key_scanner.ValidationState.ACTIVE
        assert proven.detail == (
            "SendGrid profile ok: proof=profile profile_hash=af3c82544f648b38 "
            "email_present=true username_present=true"
        )

    def test_legacy_phase2_ai_provider_patterns_use_shared_validators(self):
        from forge.phase2 import key_scanner as legacy_key_scanner  # noqa: PLC0415

        patterns = {
            pattern["name"]: pattern
            for pattern in legacy_key_scanner._load_patterns()
        }

        assert patterns["openai_project_api_key"]["validation_method"] == "OpenAIKeyValidator"
        assert patterns["openai_legacy_api_key"]["validation_method"] == "OpenAIKeyValidator"
        assert patterns["anthropic_api_key"]["validation_method"] == "AnthropicKeyValidator"
        assert isinstance(legacy_key_scanner._VALIDATOR_MAP["OpenAIKeyValidator"], OpenAIKeyValidator)
        assert isinstance(
            legacy_key_scanner._VALIDATOR_MAP["AnthropicKeyValidator"],
            AnthropicKeyValidator,
        )

    def test_legacy_phase2_social_messaging_patterns_use_shared_validators(self):
        from forge.phase2 import key_scanner as legacy_key_scanner  # noqa: PLC0415

        patterns = {
            pattern["name"]: pattern
            for pattern in legacy_key_scanner._load_patterns()
        }

        assert patterns["huggingface_token"]["validation_method"] == (
            "HuggingFaceTokenValidator"
        )
        assert patterns["discord_bot_token"]["validation_method"] == "DiscordBotTokenValidator"
        assert patterns["telegram_bot_token"]["validation_method"] == (
            "TelegramBotTokenValidator"
        )
        assert isinstance(
            legacy_key_scanner._VALIDATOR_MAP["HuggingFaceTokenValidator"],
            HuggingFaceTokenValidator,
        )
        assert isinstance(
            legacy_key_scanner._VALIDATOR_MAP["DiscordBotTokenValidator"],
            DiscordBotTokenValidator,
        )
        assert isinstance(
            legacy_key_scanner._VALIDATOR_MAP["TelegramBotTokenValidator"],
            TelegramBotTokenValidator,
        )

    def test_legacy_phase2_collaboration_observability_patterns_use_shared_validators(self):
        from forge.phase2 import key_scanner as legacy_key_scanner  # noqa: PLC0415

        patterns = {
            pattern["name"]: pattern
            for pattern in legacy_key_scanner._load_patterns()
        }

        assert patterns["notion_integration_token"]["validation_method"] == (
            "NotionTokenValidator"
        )
        assert patterns["notion_legacy_secret_token"]["validation_method"] == (
            "NotionTokenValidator"
        )
        assert patterns["notion_legacy_secret_token"]["group"] == 1
        assert patterns["datadog_api_key"]["validation_method"] == "DatadogApiKeyValidator"
        assert patterns["datadog_api_key"]["group"] == 1
        assert patterns["cloudflare_api_token"]["validation_method"] == (
            "CloudflareApiTokenValidator"
        )
        assert patterns["cloudflare_api_token"]["group"] == 1
        assert patterns["vercel_access_token"]["validation_method"] == "VercelTokenValidator"
        assert patterns["vercel_access_token"]["group"] == 1
        assert patterns["netlify_personal_access_token"]["validation_method"] == (
            "NetlifyTokenValidator"
        )
        assert patterns["netlify_personal_access_token"]["group"] == 1
        assert patterns["posthog_personal_api_key"]["validation_method"] == (
            "PostHogPersonalApiKeyValidator"
        )
        assert patterns["sentry_auth_token"]["validation_method"] == "SentryAuthTokenValidator"
        assert patterns["sentry_auth_token"]["group"] == 1
        assert isinstance(
            legacy_key_scanner._VALIDATOR_MAP["NotionTokenValidator"],
            NotionTokenValidator,
        )
        assert isinstance(
            legacy_key_scanner._VALIDATOR_MAP["DatadogApiKeyValidator"],
            DatadogApiKeyValidator,
        )
        assert isinstance(
            legacy_key_scanner._VALIDATOR_MAP["CloudflareApiTokenValidator"],
            CloudflareApiTokenValidator,
        )
        assert isinstance(
            legacy_key_scanner._VALIDATOR_MAP["VercelTokenValidator"],
            VercelTokenValidator,
        )
        assert isinstance(
            legacy_key_scanner._VALIDATOR_MAP["NetlifyTokenValidator"],
            NetlifyTokenValidator,
        )
        assert isinstance(
            legacy_key_scanner._VALIDATOR_MAP["PostHogPersonalApiKeyValidator"],
            PostHogPersonalApiKeyValidator,
        )
        assert isinstance(
            legacy_key_scanner._VALIDATOR_MAP["SentryAuthTokenValidator"],
            SentryAuthTokenValidator,
        )


# ═══════════════════════════════════════════════════════════════════════════
# _redact
# ═══════════════════════════════════════════════════════════════════════════


class TestRedact:
    def test_standard_key_redacted(self):
        assert _redact("AKIAIOSFODNN7EXAMPLE") == "AKIA...IPLE"

    def test_short_key_returns_stars(self):
        assert _redact("short") == "****"

    def test_exactly_8_chars_returns_stars(self):
        assert _redact("12345678") == "****"

    def test_full_key_never_in_output(self):
        key = "sk_live_abcdefghijklmnopqrstu"
        assert key not in _redact(key)


# ═══════════════════════════════════════════════════════════════════════════
# GithubPatValidator
# ═══════════════════════════════════════════════════════════════════════════


class TestGithubPatValidator:
    def test_active_token_returns_active(self):
        v = GithubPatValidator()
        with patch(
            "httpx.Client.get",
            return_value=_mock_http(
                {
                    "id": 7382914,
                    "login": "acme-secops",
                    "html_url": "https://github.com/acme-secops",
                },
                status=200,
            ),
        ):
            r = v.validate("ghp_" + "a" * 36)
        assert r.state == ValidationState.ACTIVE
        assert r.detail == (
            "GitHub user ok: user_id=7382914 login=acme-secops user_profile_present=true"
        )

    def test_200_without_login_stays_unconfirmed(self):
        v = GithubPatValidator()
        with patch("httpx.Client.get", return_value=_mock_http({"id": 123456}, status=200)):
            r = v.validate("ghp_" + "c" * 36)
        assert r.state == ValidationState.UNCONFIRMED
        assert r.detail == "GitHub user response missing login"

    def test_200_with_placeholder_login_stays_unconfirmed(self):
        v = GithubPatValidator()
        with patch("httpx.Client.get", return_value=_mock_http({"login": "unknown"}, status=200)):
            r = v.validate("ghp_" + "d" * 36)
        assert r.state == ValidationState.UNCONFIRMED
        assert r.detail == "GitHub user response missing login"

    def test_200_without_user_id_stays_unconfirmed(self):
        v = GithubPatValidator()
        with patch(
            "httpx.Client.get",
            return_value=_mock_http(
                {
                    "login": "acme-secops",
                    "html_url": "https://github.com/acme-secops",
                },
                status=200,
            ),
        ):
            r = v.validate("ghp_" + "g" * 36)
        assert r.state == ValidationState.UNCONFIRMED
        assert r.detail == "GitHub user response missing user id"

    def test_200_without_profile_proof_stays_unconfirmed(self):
        v = GithubPatValidator()
        with patch(
            "httpx.Client.get",
            return_value=_mock_http({"id": 7382914, "login": "acme-secops"}, status=200),
        ):
            r = v.validate("ghp_" + "h" * 36)
        assert r.state == ValidationState.UNCONFIRMED
        assert r.detail == "GitHub user response missing user proof"

    def test_revoked_token_returns_revoked(self):
        v = GithubPatValidator()
        with patch("httpx.Client.get", return_value=_mock_http({}, status=401)):
            r = v.validate("ghp_" + "b" * 36)
        assert r.state == ValidationState.REVOKED

    def test_network_error_returns_error_state(self):
        import httpx

        v = GithubPatValidator()
        with patch("httpx.Client.get", side_effect=httpx.ConnectError("refused")):
            r = v.validate("ghp_" + "e" * 36)
        assert r.state == ValidationState.ERROR

    def test_placeholder_token_never_short_circuits_to_active(self):
        import httpx

        v = GithubPatValidator()
        with patch("httpx.Client.get", side_effect=httpx.ConnectError("refused")):
            r = v.validate("ghp_" + "f" * 36)
        assert r.state == ValidationState.ERROR

    def test_unexpected_status_returns_error(self):
        v = GithubPatValidator()
        with patch("httpx.Client.get", return_value=_mock_http({}, status=500)):
            r = v.validate("ghp_" + "a" * 36)
        assert r.state in (ValidationState.ERROR, ValidationState.UNCONFIRMED)


# ═══════════════════════════════════════════════════════════════════════════
# StripeKeyValidator
# ═══════════════════════════════════════════════════════════════════════════


class TestStripeKeyValidator:
    def test_active_key_returns_active(self):
        v = StripeKeyValidator()
        with patch(
            "httpx.Client.get",
            return_value=_mock_http(
                {
                    "object": "balance",
                    "livemode": True,
                    "available": [{"amount": 1200, "currency": "usd"}],
                    "pending": [],
                },
                status=200,
            ),
        ):
            r = v.validate("sk_live_" + "x" * 24)
        assert r.state == ValidationState.ACTIVE

    def test_401_returns_revoked(self):
        v = StripeKeyValidator()
        with patch("httpx.Client.get", return_value=_mock_http({}, status=401)):
            r = v.validate("sk_live_fakekey0000000000000000000000")
        assert r.state == ValidationState.REVOKED

    def test_placeholder_key_never_short_circuits_to_active(self):
        import httpx

        v = StripeKeyValidator()
        with patch("httpx.Client.get", side_effect=httpx.ConnectError("refused")):
            r = v.validate("sk_live_fakekey0000000000000000000000")
        assert r.state == ValidationState.ERROR


class TestSlackTokenValidator:
    def test_active_token_returns_active(self):
        token = "xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx"
        v = SlackTokenValidator()
        with patch(
            "httpx.Client.post",
            return_value=_mock_http(
                {"ok": True, "user_id": "U8K4P2Q9R", "team": "Acme", "team_id": "T5M7N2Q8P"},
                status=200,
            ),
        ):
            r = v.validate(token)
        assert r.state == ValidationState.ACTIVE
        assert r.detail == "Slack auth ok: actor_id=U8K4P2Q9R team_id=T5M7N2Q8P"

    def test_ok_without_actor_or_team_stays_unconfirmed(self):
        token = "xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx"
        v = SlackTokenValidator()
        with patch(
            "httpx.Client.post",
            return_value=_mock_http({"ok": True}, status=200),
        ):
            r = v.validate(token)
        assert r.state == ValidationState.UNCONFIRMED
        assert "actor/team identifiers" in (r.detail or "")

    def test_placeholder_actor_and_team_ids_stay_unconfirmed(self):
        token = "xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx"
        v = SlackTokenValidator()
        with patch(
            "httpx.Client.post",
            return_value=_mock_http(
                {"ok": True, "user_id": "unknown", "bot_id": "B000", "team_id": "T000"},
                status=200,
            ),
        ):
            r = v.validate(token)
        assert r.state == ValidationState.UNCONFIRMED
        assert "actor/team identifiers" in (r.detail or "")

    def test_invalid_auth_returns_revoked(self):
        token = "xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx"
        v = SlackTokenValidator()
        with patch(
            "httpx.Client.post",
            return_value=_mock_http({"ok": False, "error": "invalid_auth"}, status=200),
        ):
            r = v.validate(token)
        assert r.state == ValidationState.REVOKED


class TestAzureStorageConnectionStringValidator:
    def test_active_connection_string_returns_active(self):
        validator = AzureStorageConnectionStringValidator()
        connection_string = (
            "DefaultEndpointsProtocol=https;"
            "AccountName=acmestorage;"
            f"AccountKey={'A' * 86}=="
        )
        response = MagicMock()
        response.status_code = 200
        response.text = (
            "<?xml version='1.0' encoding='utf-8'?>"
            "<EnumerationResults>"
            "<Containers>"
            "<Container><Name>reports</Name></Container>"
            "</Containers>"
            "</EnumerationResults>"
        )
        with patch("httpx.Client.get", return_value=response):
            result = validator.validate(connection_string)
        assert result.state == ValidationState.ACTIVE
        assert result.detail == "Azure blob list accessible: account=acmestorage containers=1"

    def test_empty_container_listing_is_still_active(self):
        validator = AzureStorageConnectionStringValidator()
        connection_string = (
            "DefaultEndpointsProtocol=https;"
            "AccountName=acmestorage;"
            f"AccountKey={'A' * 86}=="
        )
        response = MagicMock()
        response.status_code = 200
        response.text = (
            "<?xml version='1.0' encoding='utf-8'?>"
            "<EnumerationResults>"
            "<Containers />"
            "</EnumerationResults>"
        )
        with patch("httpx.Client.get", return_value=response):
            result = validator.validate(connection_string)
        assert result.state == ValidationState.ACTIVE
        assert result.detail == "Azure blob list accessible: account=acmestorage containers=0"

    def test_malformed_success_response_stays_unconfirmed(self):
        validator = AzureStorageConnectionStringValidator()
        connection_string = (
            "DefaultEndpointsProtocol=https;"
            "AccountName=acmestorage;"
            f"AccountKey={'A' * 86}=="
        )
        response = MagicMock()
        response.status_code = 200
        response.text = "<html>ok</html>"
        with patch("httpx.Client.get", return_value=response):
            result = validator.validate(connection_string)
        assert result.state == ValidationState.UNCONFIRMED
        assert "EnumerationResults" in (result.detail or "")

    def test_key_based_auth_disabled_returns_unconfirmed(self):
        validator = AzureStorageConnectionStringValidator()
        connection_string = (
            "DefaultEndpointsProtocol=https;"
            "AccountName=acmestorage;"
            f"AccountKey={'A' * 86}=="
        )
        response = MagicMock()
        response.status_code = 403
        response.text = (
            "<?xml version='1.0' encoding='utf-8'?>"
            "<Error><Code>KeyBasedAuthenticationNotPermitted</Code></Error>"
        )
        with patch("httpx.Client.get", return_value=response):
            result = validator.validate(connection_string)
        assert result.state == ValidationState.UNCONFIRMED


# ═══════════════════════════════════════════════════════════════════════════
# OPSEC invariant: --no-validate makes zero provider calls
# ═══════════════════════════════════════════════════════════════════════════


class TestNoValidateZeroCalls:
    def test_no_validate_makes_zero_http_calls(self, engagement_db):
        """
        OPSEC critical: in --no-validate mode, zero outbound calls must
        be made to any provider validation endpoint.
        """
        with (
            patch("forge.utils.intel.secret_finder.GithubPatValidator.validate") as mock_val,
            patch("forge.utils.intel.secret_finder.StripeKeyValidator.validate") as mock_st,
            patch("forge.utils.intel.secret_finder.AwsKeyValidator.validate") as mock_aws,
            patch("forge.utils.intel.secret_finder._github_keyscan", return_value=iter([])),
        ):
            run_keyscan(
                engagement_id=1,
                db_path=engagement_db,
                domain="example.com",
                github_token="ghp_fake",
                gitlab_token=None,
                validation_proxy=None,
                no_validate=True,
                delay=0.0,
                age_pubkey="age1testpubkey",
                dry_run=False,
            )
        mock_val.assert_not_called()
        mock_st.assert_not_called()
        mock_aws.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════
# OPSEC invariant: proxy enforcement
# ═══════════════════════════════════════════════════════════════════════════


class TestProxyEnforcement:
    def test_exits_1_without_proxy_when_validate_enabled(self, engagement_db):
        with (
            pytest.raises(SystemExit) as exc_info,
            patch("forge.utils.intel.secret_finder._github_keyscan", return_value=iter([])),
        ):
            run_keyscan(
                engagement_id=1,
                db_path=engagement_db,
                domain="example.com",
                github_token="ghp_fake",
                gitlab_token=None,
                validation_proxy=None,  # absent
                no_validate=False,  # validate enabled
                delay=0.0,
                age_pubkey="age1testpubkey",
                dry_run=False,
            )
        assert exc_info.value.code == 1

    def test_no_exit_when_proxy_provided(self, engagement_db):
        """Must not exit when proxy is provided and validation is enabled."""
        with (
            patch("forge.utils.intel.secret_finder._github_keyscan", return_value=iter([])),
            patch("questionary.confirm") as mock_q,
        ):
            mock_q.return_value.ask.return_value = False  # cancel at confirmation
            try:
                run_keyscan(
                    engagement_id=1,
                    db_path=engagement_db,
                    domain="example.com",
                    github_token="ghp_fake",
                    gitlab_token=None,
                    validation_proxy="socks5://127.0.0.1:9050",
                    no_validate=False,
                    delay=0.0,
                    age_pubkey="age1testpubkey",
                    dry_run=False,
                )
            except SystemExit as e:
                assert e.code != 1, "Must not exit 1 when proxy is supplied"


# ═══════════════════════════════════════════════════════════════════════════
# OPSEC invariant: questionary confirmation before first validation call
# ═══════════════════════════════════════════════════════════════════════════


class TestValidationConfirmation:
    def _fake_finding(self):
        return MagicMock(
            html_url="https://github.com/example/repo/blob/main/cfg.py",
            content="AKIAIOSFODNN7EXAMPLE",
            pattern_name="aws_access_key_id",
        )

    def test_questionary_called_before_first_validation(self, engagement_db):
        with (
            patch(
                "forge.utils.intel.secret_finder._github_keyscan",
                return_value=iter([self._fake_finding()]),
            ),
            patch(
                "forge.utils.intel.secret_finder._fetch_file_content",
                return_value="AKIAIOSFODNN7EXAMPLE",
            ),
            patch(
                "forge.utils.intel.secret_finder.AwsKeyValidator.validate",
                return_value=ValidationResult(state=ValidationState.ACTIVE),
            ),
            patch("forge.utils.intel.secret_finder.encrypt_string", return_value="ENC:x"),
            patch("questionary.confirm") as mock_q,
        ):
            mock_q.return_value.ask.return_value = True

            run_keyscan(
                engagement_id=1,
                db_path=engagement_db,
                domain="example.com",
                github_token="ghp_fake",
                validation_proxy="socks5://127.0.0.1:9050",
                no_validate=False,
                delay=0.0,
                age_pubkey="age1testpubkey",
                dry_run=False,
            )

        mock_q.assert_called_once()  # exactly once per session, not per key

    def test_validation_aborted_if_confirmation_declined(self, engagement_db):
        with (
            patch(
                "forge.utils.intel.secret_finder._github_keyscan",
                return_value=iter([self._fake_finding()]),
            ),
            patch("forge.utils.intel.secret_finder.AwsKeyValidator.validate") as mock_val,
            patch("questionary.confirm") as mock_q,
        ):
            mock_q.return_value.ask.return_value = False  # operator declines

            run_keyscan(
                engagement_id=1,
                db_path=engagement_db,
                domain="example.com",
                github_token="ghp_fake",
                validation_proxy="socks5://127.0.0.1:9050",
                no_validate=False,
                delay=0.0,
                age_pubkey="age1testpubkey",
                dry_run=False,
            )

        mock_val.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════
# GitLab source search
# ═══════════════════════════════════════════════════════════════════════════


class TestGitLabKeyScan:
    def test_gitlab_keyscan_fetches_raw_file_and_extracts_real_key(self):
        pattern = KeyPattern(
            name="gitlab_pat",
            service="gitlab",
            regex=re.compile(r"glpat-[A-Za-z0-9_-]{20}"),
            confidence="high",
            group=0,
            validation_method="GitlabPatValidator",
        )
        secret = "glpat-abcdefghijklmnopqrst"
        calls: list[tuple[str, dict | None]] = []

        class GitLabClient:
            def get(self, url, params=None, headers=None, timeout=None):  # noqa: ANN001
                del headers, timeout
                calls.append((url, params))
                response = MagicMock()
                response.status_code = 200
                response.headers = {}
                if url.endswith("/api/v4/search"):
                    response.json.return_value = [
                        {
                            "project_id": 123,
                            "path": "config/prod.env",
                            "ref": "main",
                            "data": "redacted search snippet",
                        }
                    ]
                    response.text = ""
                    return response
                if url.endswith("/api/v4/projects/123"):
                    response.json.return_value = {
                        "path_with_namespace": "acme/repo",
                        "web_url": "https://gitlab.com/acme/repo",
                        "default_branch": "main",
                    }
                    response.text = ""
                    return response
                if "/repository/files/config%2Fprod.env/raw" in url:
                    response.json.return_value = {}
                    response.text = f"GITLAB_TOKEN={secret}"
                    return response
                response.status_code = 404
                response.json.return_value = {}
                response.text = ""
                return response

        findings = _gitlab_keyscan(
            "example.com",
            "acme",
            [pattern],
            ["glpat-operator-token"],
            GitLabClient(),
            0.0,
        )

        assert len(findings) == 1
        assert findings[0]["backend"] == "gitlab"
        assert findings[0]["key_value"] == secret
        assert findings[0]["repo_name"] == "acme/repo"
        assert findings[0]["source_url"] == "https://gitlab.com/acme/repo/-/blob/main/config/prod.env"
        assert any(
            params == {"scope": "blobs", "search": f"{pattern.regex.pattern[:40]} example.com"}
            for _, params in calls
        )
        assert any(params == {"ref": "main"} for _, params in calls)

    def test_gitlab_keyscan_skips_without_token(self):
        client = MagicMock()
        pattern = KeyPattern(
            name="gitlab_pat",
            service="gitlab",
            regex=re.compile(r"glpat-[A-Za-z0-9_-]{20}"),
            confidence="high",
            group=0,
            validation_method="GitlabPatValidator",
        )

        findings = _gitlab_keyscan("example.com", None, [pattern], [], client, 0.0)

        assert findings == []
        client.get.assert_not_called()

    def test_run_keyscan_persists_gitlab_backend_findings(self, engagement_db):
        pattern = KeyPattern(
            name="gitlab_pat",
            service="gitlab",
            regex=re.compile(r"glpat-[A-Za-z0-9_-]{20}"),
            confidence="high",
            group=0,
            validation_method="GitlabPatValidator",
        )
        secret = "glpat-abcdefghijklmnopqrst"
        finding = {
            "pattern": pattern,
            "key_value": secret,
            "source_url": "https://gitlab.com/acme/repo/-/blob/main/config/prod.env",
            "repo_name": "acme/repo",
            "file_path": "config/prod.env",
            "backend": "gitlab",
        }

        with (
            patch("forge.utils.intel.secret_finder._github_keyscan", return_value=[]),
            patch("forge.utils.intel.secret_finder._gitlab_keyscan", return_value=[finding]),
            patch("forge.utils.intel.secret_finder.encrypt_string", return_value="ENC:gitlab"),
        ):
            count = run_keyscan(
                engagement_id=1,
                db_path=engagement_db,
                domain="example.com",
                github_token=None,
                gitlab_token="glpat-operator-token",
                validation_proxy=None,
                no_validate=True,
                delay=0.0,
                age_pubkey="age1testpubkey",
                dry_run=False,
            )

        con = sqlite3.connect(engagement_db)
        row = con.execute(
            """
            SELECT source_backend, repo_name, key_redacted, validation_state
            FROM key_scanner_findings
            WHERE source_url=?
            """,
            ("https://gitlab.com/acme/repo/-/blob/main/config/prod.env",),
        ).fetchone()
        con.close()

        assert count == 1
        assert row == ("gitlab", "acme/repo", "glpa...qrst", "UNCONFIRMED")


# ═══════════════════════════════════════════════════════════════════════════
# Storage, dedup, encryption
# ═══════════════════════════════════════════════════════════════════════════


class TestKeyStorage:
    def _run_with_one_finding(self, engagement_db, finding_content: str, pattern: str):
        finding = MagicMock()
        finding.html_url = "https://github.com/example/repo/blob/main/cfg.py"
        finding.pattern_name = pattern

        with (
            patch("forge.utils.intel.secret_finder._github_keyscan", return_value=iter([finding])),
            patch(
                "forge.utils.intel.secret_finder._fetch_file_content", return_value=finding_content
            ),
            patch("forge.utils.intel.secret_finder.encrypt_string", return_value="ENC:encrypted"),
            patch(
                "forge.utils.intel.secret_finder.GithubPatValidator.validate",
                return_value=ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=(
                        "GitHub user ok: "
                        "user_id=123456 login=testuser user_profile_present=true"
                    ),
                ),
            ),
            patch("questionary.confirm") as mock_q,
        ):
            mock_q.return_value.ask.return_value = True
            run_keyscan(
                engagement_id=1,
                db_path=engagement_db,
                domain="example.com",
                github_token="ghp_fake",
                validation_proxy="socks5://127.0.0.1:9050",
                no_validate=False,
                delay=0.0,
                age_pubkey="age1testpubkey",
                dry_run=False,
            )

    def test_finding_written_to_db(self, engagement_db):
        self._run_with_one_finding(
            engagement_db,
            "token = ghp_faketoken1234567890123456789012345",
            "github_pat_classic",
        )
        con = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM key_scanner_findings").fetchone()[0]
        con.close()
        assert count >= 1

    def test_key_encrypted_before_write(self, engagement_db):
        con = sqlite3.connect(engagement_db)
        finding = {
            "pattern": KeyPattern(
                name="github_pat_classic",
                service="github",
                regex=re.compile(r"ghp_[A-Za-z0-9]{10,}"),
                confidence="high",
                group=0,
                validation_method="GithubPatValidator",
            ),
            "backend": "github",
            "source_url": "https://github.com/example/repo/blob/main/cfg.py",
            "repo_name": "example/repo",
            "key_value": "ghp_faketoken1234567890123456789012345",
        }
        with patch("forge.utils.intel.secret_finder._encrypt", return_value="ENC:sealed") as mock_encrypt:
            inserted = _store_key_finding(
                con=con,
                engagement_id=1,
                domain="example.com",
                finding=finding,
                vresult=ValidationResult(state=ValidationState.UNCONFIRMED),
            )
        row = con.execute(
            "SELECT key_enc, key_redacted FROM key_scanner_findings WHERE source_url=?",
            (finding["source_url"],),
        ).fetchone()
        con.close()

        assert inserted is True
        mock_encrypt.assert_called_once_with(finding["key_value"])
        assert row is not None
        assert row[0] == "ENC:sealed"
        assert finding["key_value"] not in row[0]

    def test_dedup_no_double_write(self, engagement_db):
        self._run_with_one_finding(
            engagement_db,
            "token = ghp_faketoken1234567890123456789012345",
            "github_pat_classic",
        )
        self._run_with_one_finding(
            engagement_db,
            "token = ghp_faketoken1234567890123456789012345",
            "github_pat_classic",
        )
        con = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM key_scanner_findings").fetchone()[0]
        con.close()
        assert count == 1

    def test_validation_state_recorded(self, engagement_db):
        self._run_with_one_finding(
            engagement_db,
            "token = ghp_faketoken1234567890123456789012345",
            "github_pat_classic",
        )
        con = sqlite3.connect(engagement_db)
        row = con.execute("SELECT validation_state FROM key_scanner_findings LIMIT 1").fetchone()
        con.close()
        assert row is not None
        assert row[0] in ("ACTIVE", "REVOKED", "UNCONFIRMED", "ERROR")

    def test_direct_validation_detail_records_method_prefix(self, engagement_db):
        self._run_with_one_finding(
            engagement_db,
            "token = ghp_faketoken1234567890123456789012345",
            "github_pat_classic",
        )
        con = sqlite3.connect(engagement_db)
        row = con.execute(
            "SELECT validation_detail FROM key_scanner_findings LIMIT 1"
        ).fetchone()
        con.close()

        assert row is not None
        assert str(row[0] or "").startswith("VALIDATED:github_user_api:")
        assert "login=testuser" in str(row[0] or "")

    def test_primary_aws_access_key_hit_persists_adjacent_context_secret(self, engagement_db):
        finding = MagicMock()
        finding.html_url = "https://github.com/example/repo/blob/main/cfg.py"
        finding.pattern_name = "aws_access_key_id"

        content = (
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        )

        with (
            patch("forge.utils.intel.secret_finder._github_keyscan", return_value=iter([finding])),
            patch("forge.utils.intel.secret_finder._fetch_file_content", return_value=content),
        ):
            run_keyscan(
                engagement_id=1,
                db_path=engagement_db,
                domain="example.com",
                github_token="ghp_fake",
                validation_proxy=None,
                no_validate=True,
                delay=0.0,
                age_pubkey="age1testpubkey",
                dry_run=False,
            )

        con = sqlite3.connect(engagement_db)
        rows = con.execute(
            """
            SELECT service, pattern_name, validation_state
            FROM key_scanner_findings
            ORDER BY pattern_name
            """
        ).fetchall()
        con.close()

        assert rows == [
            ("aws", "aws_access_key_id", "UNCONFIRMED"),
            ("aws", "aws_secret_access_key", "UNCONFIRMED"),
        ]

    def test_slack_bot_token_hit_validates_and_persists(self, engagement_db):
        finding = MagicMock()
        finding.html_url = "https://github.com/example/repo/blob/main/chatops.env"
        finding.pattern_name = "slack_bot_token"
        content = 'SLACK_BOT_TOKEN="xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx"'

        with (
            patch("forge.utils.intel.secret_finder._github_keyscan", return_value=iter([finding])),
            patch("forge.utils.intel.secret_finder._fetch_file_content", return_value=content),
            patch("forge.utils.intel.secret_finder.encrypt_string", return_value="ENC:slack"),
            patch(
                "forge.utils.intel.secret_finder.SlackTokenValidator.validate",
                return_value=ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail="Slack auth ok: actor_id=U7A3C9K2 team_id=T9B2D6F4",
                ),
            ),
            patch("questionary.confirm") as mock_q,
        ):
            mock_q.return_value.ask.return_value = True
            run_keyscan(
                engagement_id=1,
                db_path=engagement_db,
                domain="example.com",
                github_token="ghp_fake",
                validation_proxy="socks5://127.0.0.1:9050",
                no_validate=False,
                delay=0.0,
                age_pubkey="age1testpubkey",
                dry_run=False,
            )

        con = sqlite3.connect(engagement_db)
        row = con.execute(
            """
            SELECT service, pattern_name, validation_state, validation_detail
            FROM key_scanner_findings
            WHERE source_url=?
            """,
            ("https://github.com/example/repo/blob/main/chatops.env",),
        ).fetchone()
        con.close()

        assert row is not None
        assert row[0] == "slack"
        assert row[1] == "slack_bot_token"
        assert row[2] == "ACTIVE"
        assert "Slack auth ok: actor_id=U7A3C9K2 team_id=T9B2D6F4" in str(row[3] or "")

    def test_mailchimp_api_key_hit_validates_and_persists(self, engagement_db):
        finding = MagicMock()
        finding.html_url = "https://github.com/example/repo/blob/main/newsletter.env"
        finding.pattern_name = "mailchimp_api_key"
        content = 'MAILCHIMP_API_KEY="1234567890abcdef1234567890abcdef-us1"'

        with (
            patch("forge.utils.intel.secret_finder._github_keyscan", return_value=iter([finding])),
            patch("forge.utils.intel.secret_finder._fetch_file_content", return_value=content),
            patch("forge.utils.intel.secret_finder.encrypt_string", return_value="ENC:mailchimp"),
            patch(
                "forge.utils.intel.secret_finder.MailchimpKeyValidator.validate",
                return_value=ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail="Mailchimp ping ok: dc=us1 health=Everything's Chimpy!",
                ),
            ),
            patch("questionary.confirm") as mock_q,
        ):
            mock_q.return_value.ask.return_value = True
            run_keyscan(
                engagement_id=1,
                db_path=engagement_db,
                domain="example.com",
                github_token="ghp_fake",
                validation_proxy="socks5://127.0.0.1:9050",
                no_validate=False,
                delay=0.0,
                age_pubkey="age1testpubkey",
                dry_run=False,
            )

        con = sqlite3.connect(engagement_db)
        row = con.execute(
            """
            SELECT service, pattern_name, validation_state, validation_detail
            FROM key_scanner_findings
            WHERE source_url=?
            """,
            ("https://github.com/example/repo/blob/main/newsletter.env",),
        ).fetchone()
        con.close()

        assert row is not None
        assert row[0] == "mailchimp"
        assert row[1] == "mailchimp_api_key"
        assert row[2] == "ACTIVE"
        assert "Mailchimp ping ok" in str(row[3] or "")

    def test_sendgrid_api_key_hit_validates_and_persists(self, engagement_db):
        finding = MagicMock()
        finding.html_url = "https://github.com/example/repo/blob/main/mailer.env"
        finding.pattern_name = "sendgrid_api_key"
        content = (
            'SENDGRID_API_KEY="SG.ABCDEFGHIJKLMNOPQRSTUV.'
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg"'
        )

        with (
            patch("forge.utils.intel.secret_finder._github_keyscan", return_value=iter([finding])),
            patch("forge.utils.intel.secret_finder._fetch_file_content", return_value=content),
            patch("forge.utils.intel.secret_finder.encrypt_string", return_value="ENC:sendgrid"),
            patch(
                "forge.utils.intel.secret_finder.SendgridKeyValidator.validate",
                return_value=ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail=(
                        "SendGrid profile ok: proof=profile profile_hash=0123456789abcdef "
                        "email_present=true"
                    ),
                ),
            ),
            patch("questionary.confirm") as mock_q,
        ):
            mock_q.return_value.ask.return_value = True
            run_keyscan(
                engagement_id=1,
                db_path=engagement_db,
                domain="example.com",
                github_token="ghp_fake",
                validation_proxy="socks5://127.0.0.1:9050",
                no_validate=False,
                delay=0.0,
                age_pubkey="age1testpubkey",
                dry_run=False,
            )

        con = sqlite3.connect(engagement_db)
        row = con.execute(
            """
            SELECT service, pattern_name, validation_state, validation_detail
            FROM key_scanner_findings
            WHERE source_url=?
            """,
            ("https://github.com/example/repo/blob/main/mailer.env",),
        ).fetchone()
        con.close()

        assert row is not None
        assert row[0] == "sendgrid"
        assert row[1] == "sendgrid_api_key"
        assert row[2] == "ACTIVE"
        assert "SendGrid profile ok" in str(row[3] or "")

    def test_azure_storage_connection_string_hit_validates_and_persists(self, engagement_db):
        finding = MagicMock()
        finding.html_url = "https://github.com/example/repo/blob/main/storage.env"
        finding.pattern_name = "azure_storage_key"
        content = (
            "AZURE_STORAGE_CONNECTION_STRING="
            "\"DefaultEndpointsProtocol=https;"
            "AccountName=acmestorage;"
            f"AccountKey={'A' * 86}==\""
        )

        with (
            patch("forge.utils.intel.secret_finder._github_keyscan", return_value=iter([finding])),
            patch("forge.utils.intel.secret_finder._fetch_file_content", return_value=content),
            patch("forge.utils.intel.secret_finder.encrypt_string", return_value="ENC:azure"),
            patch(
                "forge.utils.intel.secret_finder.AzureStorageConnectionStringValidator.validate",
                return_value=ValidationResult(
                    state=ValidationState.ACTIVE,
                    detail="Azure blob list accessible: account=acmestorage containers=1",
                ),
            ),
            patch("questionary.confirm") as mock_q,
        ):
            mock_q.return_value.ask.return_value = True
            run_keyscan(
                engagement_id=1,
                db_path=engagement_db,
                domain="example.com",
                github_token="ghp_fake",
                validation_proxy="socks5://127.0.0.1:9050",
                no_validate=False,
                delay=0.0,
                age_pubkey="age1testpubkey",
                dry_run=False,
            )

        con = sqlite3.connect(engagement_db)
        row = con.execute(
            """
            SELECT service, pattern_name, validation_state, validation_detail
            FROM key_scanner_findings
            WHERE source_url=?
            """,
            ("https://github.com/example/repo/blob/main/storage.env",),
        ).fetchone()
        con.close()

        assert row is not None
        assert row[0] == "azure"
        assert row[1] == "azure_storage_key"
        assert row[2] == "ACTIVE"
        assert "Azure blob list accessible" in str(row[3] or "")

    def test_audit_log_redacts_key(self, engagement_db):
        self._run_with_one_finding(
            engagement_db,
            "token = ghp_faketoken1234567890123456789012345",
            "github_pat_classic",
        )
        con = sqlite3.connect(engagement_db)
        rows = con.execute("SELECT result FROM audit_log").fetchall()
        con.close()
        full_key = "ghp_faketoken1234567890123456789012345"
        for (result,) in rows:
            assert full_key not in (result or "")

    def test_dry_run_no_db_write(self, engagement_db):
        with patch("forge.utils.intel.secret_finder._github_keyscan", return_value=iter([])):
            run_keyscan(
                engagement_id=1,
                db_path=engagement_db,
                domain="example.com",
                github_token="ghp_fake",
                validation_proxy=None,
                no_validate=True,
                delay=0.0,
                age_pubkey="age1testpubkey",
                dry_run=True,
            )
        con = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM key_scanner_findings").fetchone()[0]
        con.close()
        assert count == 0

    def test_dedup_with_scavenger_findings(self, engagement_db):
        """Keys already in scavenger_findings must be skipped before validation."""
        con = sqlite3.connect(engagement_db)
        con.execute(
            "INSERT INTO scavenger_findings VALUES "
            "(1,1,'https://github.com/example/repo/blob/main/cfg.py',"
            "'github_pat_classic','ENC:x','ctx','github',datetime('now'))"
        )
        con.commit()
        con.close()

        with (
            patch("forge.utils.intel.secret_finder.GithubPatValidator.validate") as mock_val,
            patch("forge.utils.intel.secret_finder._github_keyscan", return_value=iter([])),
        ):
            run_keyscan(
                engagement_id=1,
                db_path=engagement_db,
                domain="example.com",
                github_token="ghp_fake",
                validation_proxy="socks5://127.0.0.1:9050",
                no_validate=False,
                delay=0.0,
                age_pubkey="age1testpubkey",
                dry_run=False,
            )
        mock_val.assert_not_called()
