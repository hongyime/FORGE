"""
tests/phase2/test_secret_finder.py
Unit tests for Module 2-J: secret_finder.py
"""
from __future__ import annotations

import json
import sqlite3
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from forge.utils.intel.secret_finder import (
    AnthropicKeyValidator,
    AwsKeyValidator,
    AzureStorageConnectionStringValidator,
    CloudflareApiTokenValidator,
    DatadogApiKeyValidator,
    DiscordBotTokenValidator,
    GoogleApiKeyValidator,
    GithubPatValidator,
    GitlabPatValidator,
    HuggingFaceTokenValidator,
    MailchimpKeyValidator,
    NetlifyTokenValidator,
    NotionTokenValidator,
    OpenAIKeyValidator,
    PostHogPersonalApiKeyValidator,
    SentryAuthTokenValidator,
    SendgridKeyValidator,
    SlackTokenValidator,
    StripeKeyValidator,
    TelegramBotTokenValidator,
    TwilioKeyValidator,
    VercelTokenValidator,
    ValidationState,
    ValidationResult,
    _redact,
    _store_key_finding,
    load_key_patterns,
    load_validatable_primary_patterns,
    run_key_scanner,
    KeyPattern,
)
import re


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def pattern_file(tmp_path: Path) -> Path:
    f = tmp_path / "api_key_patterns.json"
    f.write_text(json.dumps({
        "version": "1.0",
        "patterns": [
            {"name": "aws_access_key_id", "service": "aws",
             "regex": "AKIA[0-9A-Z]{16}", "confidence": "high",
             "validation_method": "AwsKeyValidator"},
            {"name": "github_pat_classic", "service": "github",
             "regex": "ghp_[A-Za-z0-9]{36}", "confidence": "high",
             "validation_method": "GithubPatValidator"},
            {"name": "mailchimp_api_key", "service": "mailchimp",
             "regex": "[0-9a-fA-F]{32}-us[0-9]{1,2}", "confidence": "high",
             "validation_method": "MailchimpKeyValidator"},
            {"name": "stripe_live_key", "service": "stripe",
             "regex": "sk_live_[0-9a-zA-Z]{24,}", "confidence": "high",
             "validation_method": "StripeKeyValidator"},
        ]
    }))
    return f


@pytest.fixture
def engagement_db(tmp_path: Path) -> Path:
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
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            phase TEXT, module TEXT, action TEXT, target TEXT,
            result TEXT, operator TEXT, logged_at TEXT
        );
        INSERT INTO engagements (id, name, scope_json, status, operator, created_at, updated_at)
        VALUES (1, 'test', '["example.com"]', 'ACTIVE', 'tester', datetime('now'), datetime('now'));
    """)
    con.commit()
    con.close()
    return db


# ---------------------------------------------------------------------------
# load_key_patterns
# ---------------------------------------------------------------------------

def test_load_key_patterns(pattern_file):
    patterns = load_key_patterns(pattern_file)
    assert len(patterns) == 4
    services = {p.service for p in patterns}
    assert "aws" in services
    assert "github" in services
    assert "mailchimp" in services


def test_load_key_patterns_missing_file(tmp_path):
    patterns = load_key_patterns(tmp_path / "nofile.json")
    assert patterns == []


def test_load_validatable_primary_patterns_skips_context_required(tmp_path: Path):
    pattern_file = tmp_path / "api_key_patterns.json"
    pattern_file.write_text(json.dumps({
        "version": "1.0",
        "patterns": [
            {"name": "twilio_account_sid", "service": "twilio",
             "regex": "AC[a-z0-9]{32}", "confidence": "medium",
             "validation_method": "TwilioKeyValidator"},
            {"name": "twilio_auth_token", "service": "twilio",
             "regex": "[a-z0-9]{32}", "confidence": "low",
             "validation_method": "TwilioKeyValidator",
             "context_required": "twilio_account_sid"},
            {"name": "mailchimp_api_key", "service": "mailchimp",
             "regex": "[0-9a-fA-F]{32}-us[0-9]{1,2}", "confidence": "high",
             "validation_method": "MailchimpKeyValidator"},
        ],
    }))

    patterns = load_validatable_primary_patterns(pattern_file)
    names = {pattern.name for pattern in patterns}
    assert "twilio_account_sid" in names
    assert "mailchimp_api_key" in names
    assert "twilio_auth_token" not in names


def test_default_google_api_key_pattern_is_validatable() -> None:
    patterns = load_validatable_primary_patterns()
    google_pattern = next(
        pattern for pattern in patterns if pattern.name == "google_api_key"
    )
    assert google_pattern.service == "google"
    assert google_pattern.validation_method == "GoogleApiKeyValidator"


def test_default_gitlab_pat_pattern_is_validatable() -> None:
    patterns = load_validatable_primary_patterns()
    gitlab_pattern = next(
        pattern for pattern in patterns if pattern.name == "gitlab_pat"
    )
    assert gitlab_pattern.service == "gitlab"
    assert gitlab_pattern.validation_method == "GitlabPatValidator"


def test_default_ai_provider_patterns_are_validatable() -> None:
    patterns = {pattern.name: pattern for pattern in load_validatable_primary_patterns()}

    assert patterns["openai_project_api_key"].service == "openai"
    assert patterns["openai_project_api_key"].validation_method == "OpenAIKeyValidator"
    assert patterns["openai_legacy_api_key"].service == "openai"
    assert patterns["openai_legacy_api_key"].validation_method == "OpenAIKeyValidator"
    assert patterns["anthropic_api_key"].service == "anthropic"
    assert patterns["anthropic_api_key"].validation_method == "AnthropicKeyValidator"


def test_default_social_messaging_provider_patterns_are_validatable() -> None:
    patterns = {pattern.name: pattern for pattern in load_validatable_primary_patterns()}

    assert patterns["huggingface_token"].service == "huggingface"
    assert patterns["huggingface_token"].validation_method == "HuggingFaceTokenValidator"
    assert patterns["discord_bot_token"].service == "discord"
    assert patterns["discord_bot_token"].validation_method == "DiscordBotTokenValidator"
    assert patterns["telegram_bot_token"].service == "telegram"
    assert patterns["telegram_bot_token"].validation_method == "TelegramBotTokenValidator"


def test_default_collaboration_observability_provider_patterns_are_validatable() -> None:
    patterns = {pattern.name: pattern for pattern in load_validatable_primary_patterns()}

    assert patterns["notion_integration_token"].service == "notion"
    assert patterns["notion_integration_token"].validation_method == "NotionTokenValidator"
    assert patterns["notion_legacy_secret_token"].service == "notion"
    assert patterns["notion_legacy_secret_token"].group == 1
    assert patterns["notion_legacy_secret_token"].validation_method == "NotionTokenValidator"
    assert patterns["datadog_api_key"].service == "datadog"
    assert patterns["datadog_api_key"].group == 1
    assert patterns["datadog_api_key"].validation_method == "DatadogApiKeyValidator"
    assert patterns["cloudflare_api_token"].service == "cloudflare"
    assert patterns["cloudflare_api_token"].group == 1
    assert patterns["cloudflare_api_token"].validation_method == "CloudflareApiTokenValidator"
    assert patterns["vercel_access_token"].service == "vercel"
    assert patterns["vercel_access_token"].group == 1
    assert patterns["vercel_access_token"].validation_method == "VercelTokenValidator"
    assert patterns["netlify_personal_access_token"].service == "netlify"
    assert patterns["netlify_personal_access_token"].group == 1
    assert patterns["netlify_personal_access_token"].validation_method == "NetlifyTokenValidator"
    assert patterns["posthog_personal_api_key"].service == "posthog"
    assert patterns["posthog_personal_api_key"].validation_method == (
        "PostHogPersonalApiKeyValidator"
    )
    assert patterns["sentry_auth_token"].service == "sentry"
    assert patterns["sentry_auth_token"].group == 1
    assert patterns["sentry_auth_token"].validation_method == "SentryAuthTokenValidator"


# ---------------------------------------------------------------------------
# _redact
# ---------------------------------------------------------------------------

def test_redact_long():
    assert _redact("AKIAIOSFODNN7EXAMPLE") == "AKIA...IPLE"

def test_redact_short():
    assert _redact("abc") == "****"


# ---------------------------------------------------------------------------
# Validators — mock HTTP responses
# ---------------------------------------------------------------------------

def test_github_pat_validator_active(monkeypatch):
    class _GithubClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://api.github.com/user"
            assert str(headers.get("Authorization") or "").startswith("Bearer ")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "id": 738251,
                "login": "testuser",
                "html_url": "https://github.com/testuser",
                "email": "private@acme.io",
            }
            return response

    monkeypatch.setattr("httpx.Client", _GithubClient)
    result = GithubPatValidator().validate("ghp_" + "a" * 36)
    assert result.state == ValidationState.ACTIVE
    assert result.detail == (
        "GitHub user ok: user_id=738251 login=testuser user_profile_present=true "
        "profile_url_matches_login=true"
    )
    assert "private@acme.io" not in (result.detail or "")


def test_github_pat_validator_sequential_user_id_stays_unconfirmed(monkeypatch):
    class _GithubClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "id": 123456,
                "login": "testuser",
                "html_url": "https://github.com/testuser",
            }
            return response

    monkeypatch.setattr("httpx.Client", _GithubClient)
    result = GithubPatValidator().validate("ghp_" + "a" * 36)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "GitHub user response missing user id"


def test_github_pat_validator_200_without_login_stays_unconfirmed(monkeypatch):
    class _GithubClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://api.github.com/user"
            assert str(headers.get("Authorization") or "").startswith("Bearer ")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"id": 738251}
            return response

    monkeypatch.setattr("httpx.Client", _GithubClient)
    result = GithubPatValidator().validate("ghp_" + "c" * 36)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "GitHub user response missing login"


def test_github_pat_validator_200_without_user_id_stays_unconfirmed(monkeypatch):
    class _GithubClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "login": "testuser",
                "html_url": "https://github.com/testuser",
                "email": "private@acme.io",
            }
            return response

    monkeypatch.setattr("httpx.Client", _GithubClient)
    result = GithubPatValidator().validate("ghp_" + "g" * 36)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "GitHub user response missing user id"
    assert "private@acme.io" not in (result.detail or "")


def test_github_pat_validator_200_without_profile_proof_stays_unconfirmed(monkeypatch):
    class _GithubClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "id": 738251,
                "login": "testuser",
            }
            return response

    monkeypatch.setattr("httpx.Client", _GithubClient)
    result = GithubPatValidator().validate("ghp_" + "h" * 36)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "GitHub user response missing user proof"


def test_github_pat_validator_200_with_reserved_profile_url_stays_unconfirmed(monkeypatch):
    class _GithubClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "id": 738251,
                "login": "testuser",
                "avatar_url": "https://example.com/avatar.png",
            }
            return response

    monkeypatch.setattr("httpx.Client", _GithubClient)
    result = GithubPatValidator().validate("ghp_" + "h" * 36)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "GitHub user response missing user proof"


def test_github_pat_validator_200_with_reserved_profile_subdomain_stays_unconfirmed(monkeypatch):
    class _GithubClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "id": 738251,
                "login": "testuser",
                "html_url": "https://profile.example.org/testuser",
            }
            return response

    monkeypatch.setattr("httpx.Client", _GithubClient)
    result = GithubPatValidator().validate("ghp_" + "h" * 36)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "GitHub user response missing user proof"


def test_github_pat_validator_200_with_placeholder_login_stays_unconfirmed(monkeypatch):
    class _GithubClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"login": "unknown"}
            return response

    monkeypatch.setattr("httpx.Client", _GithubClient)
    result = GithubPatValidator().validate("ghp_" + "d" * 36)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "GitHub user response missing login"


def test_github_pat_validator_200_with_repeated_login_stays_unconfirmed(monkeypatch):
    class _GithubClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"login": "aaaaaaaa"}
            return response

    monkeypatch.setattr("httpx.Client", _GithubClient)
    result = GithubPatValidator().validate("ghp_" + "e" * 36)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "GitHub user response missing login"


def test_github_pat_validator_generic_profile_proof_stays_unconfirmed(monkeypatch):
    class _GithubClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "id": 738251,
                "login": "validlogin",
                "name": "user",
            }
            return response

    monkeypatch.setattr("httpx.Client", _GithubClient)
    result = GithubPatValidator().validate("ghp_" + "q" * 36)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "GitHub user response missing user proof"


def test_github_pat_validator_malformed_token_stays_unconfirmed_before_request(monkeypatch):
    called = False

    class _GithubClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            nonlocal called
            del args, kwargs
            called = True

    monkeypatch.setattr("httpx.Client", _GithubClient)
    result = GithubPatValidator().validate("not-a-github-pat")

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "GitHub PAT shape is invalid for deterministic validation"
    assert called is False


def test_github_pat_validator_rate_limited_stays_unconfirmed(monkeypatch):
    from forge.utils.intel import http_pacing  # noqa: PLC0415

    http_pacing._clear_rate_limit_cooldowns_for_tests()
    monkeypatch.setattr(http_pacing.time, "sleep", lambda _seconds: None)
    monkeypatch.setenv("FORGE_KEY_VALIDATION_RATE_LIMIT_RETRIES", "0")

    class _GithubClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://api.github.com/user"
            assert str(headers.get("Authorization") or "").startswith("Bearer ghp_")
            response = MagicMock()
            response.status_code = 429
            return response

    monkeypatch.setattr("httpx.Client", _GithubClient)
    result = GithubPatValidator().validate("ghp_" + "f" * 36)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "HTTP 429"
    http_pacing._clear_rate_limit_cooldowns_for_tests()


def test_github_pat_validator_forbidden_stays_unconfirmed(monkeypatch):
    class _GithubClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://api.github.com/user"
            assert str(headers.get("Authorization") or "").startswith("Bearer github_pat_")
            response = MagicMock()
            response.status_code = 403
            return response

    monkeypatch.setattr("httpx.Client", _GithubClient)
    result = GithubPatValidator().validate("github_pat_" + "A" * 82)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "HTTP 403"


def test_github_pat_validator_revoked(monkeypatch):
    with patch("forge.utils.intel.secret_finder.GithubPatValidator.validate",
               return_value=ValidationResult(state=ValidationState.REVOKED, detail="401 Unauthorized")):
        result = GithubPatValidator().validate("ghp_" + "b" * 36)
    assert result.state == ValidationState.REVOKED


def test_gitlab_pat_validator_active_reads_current_user(monkeypatch):
    class _GitlabClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://gitlab.com/api/v4/user"
            assert str(headers.get("PRIVATE-TOKEN") or "").startswith("glpat-")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "id": 42,
                "username": "delta-ops",
                "web_url": "https://gitlab.com/delta-ops",
                "email": "private@acme.io",
            }
            return response

    monkeypatch.setattr("httpx.Client", _GitlabClient)
    result = GitlabPatValidator().validate("glpat-" + "A" * 20)

    assert result.state == ValidationState.ACTIVE
    assert result.detail == (
        "GitLab user ok: user_id=42 username=delta-ops user_profile_present=true "
        "profile_url_matches_login=true"
    )
    assert "private@acme.io" not in (result.detail or "")


def test_gitlab_pat_validator_200_without_username_stays_unconfirmed(monkeypatch):
    class _GitlabClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://gitlab.com/api/v4/user"
            assert str(headers.get("PRIVATE-TOKEN") or "").startswith("glpat-")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"id": 42, "email": "private@example.com"}
            return response

    monkeypatch.setattr("httpx.Client", _GitlabClient)
    result = GitlabPatValidator().validate("glpat-" + "C" * 20)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "GitLab user response missing username"
    assert "private@example.com" not in (result.detail or "")


def test_gitlab_pat_validator_200_without_user_id_stays_unconfirmed(monkeypatch):
    class _GitlabClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "username": "delta-ops",
                "email": "private@example.com",
            }
            return response

    monkeypatch.setattr("httpx.Client", _GitlabClient)
    result = GitlabPatValidator().validate("glpat-" + "G" * 20)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "GitLab user response missing user id"
    assert "private@example.com" not in (result.detail or "")


def test_gitlab_pat_validator_200_without_profile_proof_stays_unconfirmed(monkeypatch):
    class _GitlabClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "id": 42,
                "username": "delta-ops",
            }
            return response

    monkeypatch.setattr("httpx.Client", _GitlabClient)
    result = GitlabPatValidator().validate("glpat-" + "H" * 20)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "GitLab user response missing user proof"


def test_gitlab_pat_validator_reserved_email_proof_stays_unconfirmed(monkeypatch):
    class _GitlabClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "id": 42,
                "username": "delta-ops",
                "email": "private@example.com",
            }
            return response

    monkeypatch.setattr("httpx.Client", _GitlabClient)
    result = GitlabPatValidator().validate("glpat-" + "H" * 20)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "GitLab user response missing user proof"


def test_gitlab_pat_validator_200_with_placeholder_username_stays_unconfirmed(monkeypatch):
    class _GitlabClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"username": "undefined", "login": "unknown"}
            return response

    monkeypatch.setattr("httpx.Client", _GitlabClient)
    result = GitlabPatValidator().validate("glpat-" + "D" * 20)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "GitLab user response missing username"


def test_gitlab_pat_validator_200_with_repeated_username_stays_unconfirmed(monkeypatch):
    class _GitlabClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"username": "aaaaaaaa", "login": "000000"}
            return response

    monkeypatch.setattr("httpx.Client", _GitlabClient)
    result = GitlabPatValidator().validate("glpat-" + "E" * 20)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "GitLab user response missing username"


def test_gitlab_pat_validator_unauthorized_stays_unconfirmed(monkeypatch):
    class _GitlabClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 401
            return response

    monkeypatch.setattr("httpx.Client", _GitlabClient)
    result = GitlabPatValidator().validate("glpat-" + "B" * 20)

    assert result.state == ValidationState.UNCONFIRMED
    assert "gitlab.com" in (result.detail or "")


def test_gitlab_pat_validator_rate_limited_stays_unconfirmed(monkeypatch):
    from forge.utils.intel import http_pacing  # noqa: PLC0415

    http_pacing._clear_rate_limit_cooldowns_for_tests()
    monkeypatch.setattr(http_pacing.time, "sleep", lambda _seconds: None)
    monkeypatch.setenv("FORGE_KEY_VALIDATION_RATE_LIMIT_RETRIES", "0")

    class _GitlabClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://gitlab.com/api/v4/user"
            assert str(headers.get("PRIVATE-TOKEN") or "").startswith("glpat-")
            response = MagicMock()
            response.status_code = 429
            return response

    monkeypatch.setattr("httpx.Client", _GitlabClient)
    result = GitlabPatValidator().validate("glpat-" + "F" * 20)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "HTTP 429"
    http_pacing._clear_rate_limit_cooldowns_for_tests()


def test_aws_validator_unconfirmed_no_secret():
    result = AwsKeyValidator().validate("AKIAIOSFODNN7EXAMPLE", secret=None)
    assert result.state == ValidationState.UNCONFIRMED
    assert "secret key not co-located" in (result.detail or "").lower()


def test_aws_validator_200_without_account_id_stays_unconfirmed(monkeypatch):
    class _AwsClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

    class _SessionFactory:
        def __call__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            del args, kwargs
            return _AwsClient()

    response = MagicMock()
    response.status_code = 200
    response.text = (
        "<GetCallerIdentityResponse>"
        "<GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/test</Arn></GetCallerIdentityResult>"
        "</GetCallerIdentityResponse>"
    )
    fake_requests = types.SimpleNamespace(Session=_SessionFactory())
    monkeypatch.setitem(sys.modules, "curl_cffi", types.SimpleNamespace(requests=fake_requests))
    monkeypatch.setitem(sys.modules, "curl_cffi.requests", fake_requests)
    monkeypatch.setattr(
        "forge.utils.intel.secret_finder.key_validation_post",
        lambda *args, **kwargs: response,  # noqa: ARG005
    )

    result = AwsKeyValidator().validate(
        "AKIAIOSFODNN7EXAMPLE",
        secret="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert "missing AccountId" in (result.detail or "")


def test_aws_validator_200_with_placeholder_account_id_stays_unconfirmed(monkeypatch):
    class _AwsClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

    class _SessionFactory:
        def __call__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            del args, kwargs
            return _AwsClient()

    response = MagicMock()
    response.status_code = 200
    response.text = (
        "<GetCallerIdentityResponse>"
        "<GetCallerIdentityResult><Account>000000000000</Account></GetCallerIdentityResult>"
        "</GetCallerIdentityResponse>"
    )
    fake_requests = types.SimpleNamespace(Session=_SessionFactory())
    monkeypatch.setitem(sys.modules, "curl_cffi", types.SimpleNamespace(requests=fake_requests))
    monkeypatch.setitem(sys.modules, "curl_cffi.requests", fake_requests)
    monkeypatch.setattr(
        "forge.utils.intel.secret_finder.key_validation_post",
        lambda *args, **kwargs: response,  # noqa: ARG005
    )

    result = AwsKeyValidator().validate(
        "AKIAIOSFODNN7EXAMPLE",
        secret="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert "missing AccountId" in (result.detail or "")


def test_aws_validator_rate_limited_stays_unconfirmed(monkeypatch):
    class _AwsClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

    class _SessionFactory:
        def __call__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            del args, kwargs
            return _AwsClient()

    response = MagicMock()
    response.status_code = 429
    response.text = ""
    fake_requests = types.SimpleNamespace(Session=_SessionFactory())
    monkeypatch.setitem(sys.modules, "curl_cffi", types.SimpleNamespace(requests=fake_requests))
    monkeypatch.setitem(sys.modules, "curl_cffi.requests", fake_requests)
    monkeypatch.setattr(
        "forge.utils.intel.secret_finder.key_validation_post",
        lambda *args, **kwargs: response,  # noqa: ARG005
    )

    result = AwsKeyValidator().validate(
        "AKIAIOSFODNN7EXAMPLE",
        secret="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "HTTP 429"


def test_stripe_validator_active_includes_balance_evidence(monkeypatch):
    class _StripeClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://api.stripe.com/v1/balance"
            assert str(headers.get("Authorization") or "").startswith("Basic ")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "object": "balance",
                "livemode": True,
                "available": [{"amount": 1200, "currency": "usd"}],
                "pending": [{"amount": 500, "currency": "sgd"}],
            }
            return response

    monkeypatch.setattr("httpx.Client", _StripeClient)
    result = StripeKeyValidator().validate("sk_live_" + "x" * 24)
    assert result.state == ValidationState.ACTIVE
    assert result.detail == (
        "Stripe balance accessible: mode=live currencies=sgd,usd "
        "balances=available:1,pending:1"
    )


def test_stripe_validator_200_without_balance_object_stays_unconfirmed(monkeypatch):
    class _StripeClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"ok": True}
            return response

    monkeypatch.setattr("httpx.Client", _StripeClient)
    result = StripeKeyValidator().validate("sk_live_" + "x" * 24)

    assert result.state == ValidationState.UNCONFIRMED
    assert "missing balance object" in (result.detail or "")


def test_stripe_validator_200_balance_object_without_livemode_stays_unconfirmed(monkeypatch):
    class _StripeClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "object": "balance",
                "available": [],
                "pending": [],
            }
            return response

    monkeypatch.setattr("httpx.Client", _StripeClient)
    result = StripeKeyValidator().validate("sk_live_" + "x" * 24)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Stripe balance response missing balance proof"


def test_stripe_validator_200_live_key_with_test_mode_balance_stays_unconfirmed(monkeypatch):
    class _StripeClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "object": "balance",
                "livemode": False,
                "available": [{"amount": 100, "currency": "usd"}],
                "pending": [],
            }
            return response

    monkeypatch.setattr("httpx.Client", _StripeClient)
    result = StripeKeyValidator().validate("sk_live_" + "x" * 24)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Stripe balance response missing balance proof"


def test_stripe_validator_200_balance_object_without_balance_lists_stays_unconfirmed(monkeypatch):
    class _StripeClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "object": "balance",
                "livemode": True,
            }
            return response

    monkeypatch.setattr("httpx.Client", _StripeClient)
    result = StripeKeyValidator().validate("sk_live_" + "x" * 24)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Stripe balance response missing balance proof"


def test_stripe_validator_malformed_key_stays_unconfirmed_before_request(monkeypatch):
    called = False

    class _StripeClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            nonlocal called
            del args, kwargs
            called = True

    monkeypatch.setattr("httpx.Client", _StripeClient)
    result = StripeKeyValidator().validate("not-a-stripe-key")

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Stripe key shape is invalid for deterministic validation"
    assert called is False


def test_stripe_validator_restricted_key_forbidden_stays_unconfirmed(monkeypatch):
    class _StripeClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://api.stripe.com/v1/balance"
            assert str(headers.get("Authorization") or "").startswith("Basic ")
            response = MagicMock()
            response.status_code = 403
            return response

    monkeypatch.setattr("httpx.Client", _StripeClient)
    result = StripeKeyValidator().validate("rk_live_" + "R" * 24)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "HTTP 403"


def test_stripe_validator_rate_limited_stays_unconfirmed(monkeypatch):
    from forge.utils.intel import http_pacing  # noqa: PLC0415

    http_pacing._clear_rate_limit_cooldowns_for_tests()
    monkeypatch.setattr(http_pacing.time, "sleep", lambda _seconds: None)
    monkeypatch.setenv("FORGE_KEY_VALIDATION_RATE_LIMIT_RETRIES", "0")

    class _StripeClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://api.stripe.com/v1/balance"
            assert str(headers.get("Authorization") or "").startswith("Basic ")
            response = MagicMock()
            response.status_code = 429
            return response

    monkeypatch.setattr("httpx.Client", _StripeClient)
    result = StripeKeyValidator().validate("sk_live_" + "S" * 24)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "HTTP 429"
    http_pacing._clear_rate_limit_cooldowns_for_tests()


def test_twilio_validator_account_detail_omits_friendly_name() -> None:
    detail = TwilioKeyValidator._account_detail(
        "AC1234567890abcdef1234567890abcdef",
        {
            "sid": "AC1234567890abcdef1234567890abcdef",
            "status": "active",
            "type": "Full",
            "friendly_name": "Sensitive Customer Name",
        },
    )

    assert detail == (
        "Twilio account accessible: sid=AC1234567890abcdef1234567890abcdef "
        "status=active type=Full"
    )
    assert "Sensitive" not in detail


def test_twilio_validator_200_without_matching_sid_stays_unconfirmed(monkeypatch):
    class _TwilioClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

    class _SessionFactory:
        def __call__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            del args, kwargs
            return _TwilioClient()

    response = MagicMock()
    response.status_code = 200
    response.text = '{"status":"active","type":"Full"}'
    fake_requests = types.SimpleNamespace(Session=_SessionFactory())
    monkeypatch.setitem(sys.modules, "curl_cffi", types.SimpleNamespace(requests=fake_requests))
    monkeypatch.setitem(sys.modules, "curl_cffi.requests", fake_requests)
    monkeypatch.setattr(
        "forge.utils.intel.secret_finder.key_validation_get",
        lambda *args, **kwargs: response,  # noqa: ARG005
    )

    result = TwilioKeyValidator().validate(
        "AC1234567890abcdef1234567890abcdef",
        auth_token="auth-token",
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert "matching SID" in (result.detail or "")


def test_twilio_validator_matching_sid_and_status_is_active(monkeypatch):
    class _TwilioClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

    class _SessionFactory:
        def __call__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            del args, kwargs
            return _TwilioClient()

    response = MagicMock()
    response.status_code = 200
    response.text = (
        '{"sid":"AC1234567890abcdef1234567890abcdef",'
        '"status":"active","type":"Full"}'
    )
    fake_requests = types.SimpleNamespace(Session=_SessionFactory())
    monkeypatch.setitem(sys.modules, "curl_cffi", types.SimpleNamespace(requests=fake_requests))
    monkeypatch.setitem(sys.modules, "curl_cffi.requests", fake_requests)
    monkeypatch.setattr(
        "forge.utils.intel.secret_finder.key_validation_get",
        lambda *args, **kwargs: response,  # noqa: ARG005
    )

    result = TwilioKeyValidator().validate(
        "AC1234567890abcdef1234567890abcdef",
        auth_token="auth-token",
    )

    assert result.state == ValidationState.ACTIVE
    assert result.detail == (
        "Twilio account accessible: sid=AC1234567890abcdef1234567890abcdef "
        "status=active type=Full"
    )


def test_twilio_validator_200_matching_sid_without_status_stays_unconfirmed(monkeypatch):
    class _TwilioClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

    class _SessionFactory:
        def __call__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            del args, kwargs
            return _TwilioClient()

    response = MagicMock()
    response.status_code = 200
    response.text = '{"sid":"AC1234567890abcdef1234567890abcdef","type":"Full"}'
    fake_requests = types.SimpleNamespace(Session=_SessionFactory())
    monkeypatch.setitem(sys.modules, "curl_cffi", types.SimpleNamespace(requests=fake_requests))
    monkeypatch.setitem(sys.modules, "curl_cffi.requests", fake_requests)
    monkeypatch.setattr(
        "forge.utils.intel.secret_finder.key_validation_get",
        lambda *args, **kwargs: response,  # noqa: ARG005
    )

    result = TwilioKeyValidator().validate(
        "AC1234567890abcdef1234567890abcdef",
        auth_token="auth-token",
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert "SID/status proof" in (result.detail or "")


def test_twilio_validator_placeholder_sid_stays_unconfirmed_before_request(monkeypatch):
    called = False

    def _unexpected_call(*args, **kwargs):  # noqa: ANN002, ANN003
        nonlocal called
        called = True
        raise AssertionError("Twilio validation should not call provider for placeholder SID")

    monkeypatch.setattr("forge.utils.intel.secret_finder.key_validation_get", _unexpected_call)

    result = TwilioKeyValidator().validate(
        "AC" + "0" * 32,
        auth_token="auth-token",
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Twilio account SID shape is invalid for deterministic validation"
    assert called is False


def test_twilio_validator_rate_limited_stays_unconfirmed(monkeypatch):
    class _TwilioClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

    class _SessionFactory:
        def __call__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            del args, kwargs
            return _TwilioClient()

    response = MagicMock()
    response.status_code = 429
    fake_requests = types.SimpleNamespace(Session=_SessionFactory())
    monkeypatch.setitem(sys.modules, "curl_cffi", types.SimpleNamespace(requests=fake_requests))
    monkeypatch.setitem(sys.modules, "curl_cffi.requests", fake_requests)
    monkeypatch.setattr(
        "forge.utils.intel.secret_finder.key_validation_get",
        lambda *args, **kwargs: response,  # noqa: ARG005
    )

    result = TwilioKeyValidator().validate(
        "AC1234567890abcdef1234567890abcdef",
        auth_token="auth-token",
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "HTTP 429"


def test_azure_storage_connection_string_validator_rate_limited_stays_unconfirmed(monkeypatch):
    response = MagicMock()
    response.status_code = 429
    response.text = ""
    monkeypatch.setattr(
        "forge.utils.intel.secret_finder.key_validation_get",
        lambda *args, **kwargs: response,  # noqa: ARG005
    )

    result = AzureStorageConnectionStringValidator().validate(
        "DefaultEndpointsProtocol=https;"
        "AccountName=acmestorage;"
        "AccountKey=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=;"
        "EndpointSuffix=core.windows.net"
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "HTTP 429"


@pytest.mark.parametrize("account_name", ["aaaaaaaaaaaa", "placeholder", "test"])
def test_azure_storage_connection_string_validator_low_signal_account_stays_unconfirmed_before_request(
    monkeypatch,
    account_name: str,
) -> None:
    called = False

    def _unexpected_call(*args, **kwargs):  # noqa: ANN002, ANN003
        nonlocal called
        called = True
        raise AssertionError("Azure validation should not call provider for low-signal account names")

    monkeypatch.setattr("forge.utils.intel.secret_finder.key_validation_get", _unexpected_call)

    result = AzureStorageConnectionStringValidator().validate(
        "DefaultEndpointsProtocol=https;"
        f"AccountName={account_name};"
        "AccountKey=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=;"
        "EndpointSuffix=core.windows.net"
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Azure storage account name shape is invalid for deterministic validation"
    assert called is False


def test_mailchimp_validator_active(monkeypatch):
    class _MailchimpClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, auth=None):  # noqa: ANN001
            assert url == "https://us1.api.mailchimp.com/3.0/ping"
            assert auth == ("forge", "1234567890abcdef1234567890abcdef-us1")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"health_status": "Everything's Chimpy!"}
            return response

    monkeypatch.setattr("httpx.Client", _MailchimpClient)
    result = MailchimpKeyValidator().validate("1234567890abcdef1234567890abcdef-us1")
    assert result.state == ValidationState.ACTIVE
    assert result.detail == "Mailchimp ping ok: dc=us1 health=Everything's Chimpy!"


def test_mailchimp_validator_200_without_health_stays_unconfirmed(monkeypatch):
    class _MailchimpClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, auth=None):  # noqa: ANN001
            del url, auth
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"ok": True}
            return response

    monkeypatch.setattr("httpx.Client", _MailchimpClient)
    result = MailchimpKeyValidator().validate("1234567890abcdef1234567890abcdef-us1")

    assert result.state == ValidationState.UNCONFIRMED
    assert "missing health_status" in (result.detail or "")


def test_mailchimp_validator_placeholder_health_stays_unconfirmed(monkeypatch):
    class _MailchimpClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, auth=None):  # noqa: ANN001
            del url, auth
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"health_status": "placeholder"}
            return response

    monkeypatch.setattr("httpx.Client", _MailchimpClient)
    result = MailchimpKeyValidator().validate("1234567890abcdef1234567890abcdef-us1")

    assert result.state == ValidationState.UNCONFIRMED
    assert "missing health_status" in (result.detail or "")


def test_mailchimp_validator_chimpy_substring_health_stays_unconfirmed(monkeypatch):
    class _MailchimpClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, auth=None):  # noqa: ANN001
            del url, auth
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"health_status": "not chimpy"}
            return response

    monkeypatch.setattr("httpx.Client", _MailchimpClient)
    result = MailchimpKeyValidator().validate("1234567890abcdef1234567890abcdef-us1")

    assert result.state == ValidationState.UNCONFIRMED
    assert "missing health_status" in (result.detail or "")


def test_mailchimp_validator_non_us_datacenter_stays_unconfirmed_before_request(monkeypatch):
    called = False

    class _MailchimpClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            nonlocal called
            del args, kwargs
            called = True
            raise AssertionError("Mailchimp validation should not call non-US datacenter hosts")

    monkeypatch.setattr("httpx.Client", _MailchimpClient)
    result = MailchimpKeyValidator().validate("1234567890abcdef1234567890abcdef-eu1")

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Mailchimp API key missing datacenter suffix"
    assert called is False


def test_mailchimp_validator_malformed_key_stays_unconfirmed_before_request(monkeypatch):
    called = False

    class _MailchimpClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            nonlocal called
            del args, kwargs
            called = True
            raise AssertionError("Mailchimp validation should not call provider for malformed keys")

    monkeypatch.setattr("httpx.Client", _MailchimpClient)
    result = MailchimpKeyValidator().validate("not-a-mailchimp-key-us1")

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Mailchimp API key shape is invalid for deterministic validation"
    assert called is False


def test_mailchimp_validator_revoked(monkeypatch):
    class _MailchimpClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, auth=None):  # noqa: ANN001
            assert url == "https://us6.api.mailchimp.com/3.0/ping"
            assert auth == ("forge", "abcdefabcdefabcdefabcdefabcdefab-us6")
            response = MagicMock()
            response.status_code = 401
            return response

    monkeypatch.setattr("httpx.Client", _MailchimpClient)
    result = MailchimpKeyValidator().validate("abcdefabcdefabcdefabcdefabcdefab-us6")
    assert result.state == ValidationState.REVOKED


def test_mailchimp_validator_rate_limited_stays_unconfirmed(monkeypatch):
    from forge.utils.intel import http_pacing  # noqa: PLC0415

    http_pacing._clear_rate_limit_cooldowns_for_tests()
    monkeypatch.setattr(http_pacing.time, "sleep", lambda _seconds: None)
    monkeypatch.setenv("FORGE_KEY_VALIDATION_RATE_LIMIT_RETRIES", "0")

    class _MailchimpClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, auth=None):  # noqa: ANN001
            assert url == "https://us1.api.mailchimp.com/3.0/ping"
            assert auth == ("forge", "1234567890abcdef1234567890abcdef-us1")
            response = MagicMock()
            response.status_code = 429
            return response

    monkeypatch.setattr("httpx.Client", _MailchimpClient)
    result = MailchimpKeyValidator().validate("1234567890abcdef1234567890abcdef-us1")

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "HTTP 429"
    http_pacing._clear_rate_limit_cooldowns_for_tests()


def test_sendgrid_validator_malformed_key_stays_unconfirmed_before_request(monkeypatch):
    called = False

    class _SessionFactory:
        def __call__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            nonlocal called
            del args, kwargs
            called = True
            raise AssertionError("SendGrid validation should not call provider for malformed keys")

    fake_requests = types.SimpleNamespace(Session=_SessionFactory())
    monkeypatch.setitem(sys.modules, "curl_cffi", types.SimpleNamespace(requests=fake_requests))
    monkeypatch.setitem(sys.modules, "curl_cffi.requests", fake_requests)
    result = SendgridKeyValidator().validate("not-a-sendgrid-key")

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "SendGrid API key shape is invalid for deterministic validation"
    assert called is False


def test_sendgrid_validator_200_without_profile_proof_stays_unconfirmed(monkeypatch):
    class _SendgridClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None, **kwargs):  # noqa: ANN001
            del url, headers, kwargs
            response = MagicMock()
            response.status_code = 200
            response.text = '{"name":"Profile Without Stable Identifier"}'
            return response

    class _SessionFactory:
        def __call__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            del args, kwargs
            return _SendgridClient()

    fake_requests = types.SimpleNamespace(Session=_SessionFactory())
    monkeypatch.setitem(sys.modules, "curl_cffi", types.SimpleNamespace(requests=fake_requests))
    monkeypatch.setitem(sys.modules, "curl_cffi.requests", fake_requests)
    result = SendgridKeyValidator().validate(
        "SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg"
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert "profile proof" in (result.detail or "")


def test_sendgrid_validator_reserved_email_profile_stays_unconfirmed(monkeypatch):
    class _SendgridClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None, **kwargs):  # noqa: ANN001
            del headers, kwargs
            assert url == "https://api.sendgrid.com/v3/user/profile"
            response = MagicMock()
            response.status_code = 200
            response.text = '{"email":"sender@example.com"}'
            return response

    class _SessionFactory:
        def __call__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            del args, kwargs
            return _SendgridClient()

    fake_requests = types.SimpleNamespace(Session=_SessionFactory())
    monkeypatch.setitem(sys.modules, "curl_cffi", types.SimpleNamespace(requests=fake_requests))
    monkeypatch.setitem(sys.modules, "curl_cffi.requests", fake_requests)
    result = SendgridKeyValidator().validate(
        "SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg"
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "SendGrid profile response missing profile proof"


def test_sendgrid_validator_placeholder_username_profile_stays_unconfirmed(monkeypatch):
    class _SendgridClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None, **kwargs):  # noqa: ANN001
            del headers, kwargs
            assert url == "https://api.sendgrid.com/v3/user/profile"
            response = MagicMock()
            response.status_code = 200
            response.text = '{"username":"test"}'
            return response

    class _SessionFactory:
        def __call__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            del args, kwargs
            return _SendgridClient()

    fake_requests = types.SimpleNamespace(Session=_SessionFactory())
    monkeypatch.setitem(sys.modules, "curl_cffi", types.SimpleNamespace(requests=fake_requests))
    monkeypatch.setitem(sys.modules, "curl_cffi.requests", fake_requests)
    result = SendgridKeyValidator().validate(
        "SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg"
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "SendGrid profile response missing profile proof"


def test_sendgrid_validator_empty_scope_list_stays_unconfirmed(monkeypatch):
    class _SendgridClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None, **kwargs):  # noqa: ANN001
            del headers, kwargs
            response = MagicMock()
            if url == "https://api.sendgrid.com/v3/user/profile":
                response.status_code = 403
                response.text = "{}"
                return response
            assert url == "https://api.sendgrid.com/v3/scopes"
            response.status_code = 200
            response.text = '{"scopes":[]}'
            return response

    class _SessionFactory:
        def __call__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            del args, kwargs
            return _SendgridClient()

    fake_requests = types.SimpleNamespace(Session=_SessionFactory())
    monkeypatch.setitem(sys.modules, "curl_cffi", types.SimpleNamespace(requests=fake_requests))
    monkeypatch.setitem(sys.modules, "curl_cffi.requests", fake_requests)
    result = SendgridKeyValidator().validate(
        "SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg"
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "SendGrid scopes response missing scopes list"


def test_sendgrid_validator_placeholder_scope_list_stays_unconfirmed(monkeypatch):
    class _SendgridClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None, **kwargs):  # noqa: ANN001
            del headers, kwargs
            response = MagicMock()
            if url == "https://api.sendgrid.com/v3/user/profile":
                response.status_code = 403
                response.text = "{}"
                return response
            assert url == "https://api.sendgrid.com/v3/scopes"
            response.status_code = 200
            response.text = '{"scopes":["placeholder","test","aaaa"]}'
            return response

    class _SessionFactory:
        def __call__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            del args, kwargs
            return _SendgridClient()

    fake_requests = types.SimpleNamespace(Session=_SessionFactory())
    monkeypatch.setitem(sys.modules, "curl_cffi", types.SimpleNamespace(requests=fake_requests))
    monkeypatch.setitem(sys.modules, "curl_cffi.requests", fake_requests)
    result = SendgridKeyValidator().validate(
        "SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg"
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "SendGrid scopes response missing scopes list"


def test_sendgrid_validator_non_empty_scope_list_is_active_without_scope_names(monkeypatch):
    class _SendgridClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None, **kwargs):  # noqa: ANN001
            del headers, kwargs
            response = MagicMock()
            if url == "https://api.sendgrid.com/v3/user/profile":
                response.status_code = 403
                response.text = "{}"
                return response
            assert url == "https://api.sendgrid.com/v3/scopes"
            response.status_code = 200
            response.text = '{"scopes":["mail.send","alerts.read"]}'
            return response

    class _SessionFactory:
        def __call__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            del args, kwargs
            return _SendgridClient()

    fake_requests = types.SimpleNamespace(Session=_SessionFactory())
    monkeypatch.setitem(sys.modules, "curl_cffi", types.SimpleNamespace(requests=fake_requests))
    monkeypatch.setitem(sys.modules, "curl_cffi.requests", fake_requests)
    result = SendgridKeyValidator().validate(
        "SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg"
    )

    assert result.state == ValidationState.ACTIVE
    assert str(result.detail or "").startswith(
        "SendGrid scopes accessible: count=2 scope_hash="
    )
    assert "mail.send" not in (result.detail or "")
    assert "alerts.read" not in (result.detail or "")


def test_sendgrid_validator_profile_detail_omits_email_and_username(monkeypatch):
    class _SendgridClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None, **kwargs):  # noqa: ANN001
            del headers, kwargs
            assert url == "https://api.sendgrid.com/v3/user/profile"
            response = MagicMock()
            response.status_code = 200
            response.text = '{"email":"sender@acme.io","username":"SenderOps"}'
            return response

    class _SessionFactory:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __call__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            del args, kwargs
            return _SendgridClient()

    fake_requests = types.SimpleNamespace(Session=_SessionFactory())
    monkeypatch.setitem(sys.modules, "curl_cffi", types.SimpleNamespace(requests=fake_requests))
    monkeypatch.setitem(sys.modules, "curl_cffi.requests", fake_requests)
    result = SendgridKeyValidator().validate(
        "SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg"
    )

    assert result.state == ValidationState.ACTIVE
    assert result.detail == (
        "SendGrid profile ok: proof=profile profile_hash=f69bb455ec6910ec "
        "email_present=true username_present=true"
    )
    assert "sender@acme.io" not in (result.detail or "")
    assert "SenderOps" not in (result.detail or "")


def test_sendgrid_validator_profile_detail_hashes_stable_username_when_email_reserved(monkeypatch):
    class _SendgridClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None, **kwargs):  # noqa: ANN001
            del headers, kwargs
            assert url == "https://api.sendgrid.com/v3/user/profile"
            response = MagicMock()
            response.status_code = 200
            response.text = '{"email":"sender@example.com","username":"SenderOps"}'
            return response

    class _SessionFactory:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __call__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            del args, kwargs
            return _SendgridClient()

    fake_requests = types.SimpleNamespace(Session=_SessionFactory())
    monkeypatch.setitem(sys.modules, "curl_cffi", types.SimpleNamespace(requests=fake_requests))
    monkeypatch.setitem(sys.modules, "curl_cffi.requests", fake_requests)
    result = SendgridKeyValidator().validate(
        "SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg"
    )

    assert result.state == ValidationState.ACTIVE
    assert result.detail == (
        "SendGrid profile ok: proof=profile profile_hash=8ecbc8a5b9747e47 "
        "username_present=true"
    )
    assert "email_present=true" not in (result.detail or "")
    assert "sender@example.com" not in (result.detail or "")
    assert "SenderOps" not in (result.detail or "")


def test_sendgrid_validator_rate_limited_profile_stays_unconfirmed(monkeypatch):
    from forge.utils.intel import http_pacing  # noqa: PLC0415

    http_pacing._clear_rate_limit_cooldowns_for_tests()
    monkeypatch.setattr(http_pacing.time, "sleep", lambda _seconds: None)
    monkeypatch.setenv("FORGE_KEY_VALIDATION_RATE_LIMIT_RETRIES", "0")

    class _SendgridClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None, **kwargs):  # noqa: ANN001
            del headers, kwargs
            assert url == "https://api.sendgrid.com/v3/user/profile"
            response = MagicMock()
            response.status_code = 429
            response.text = "{}"
            return response

    class _SessionFactory:
        def __call__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            del args, kwargs
            return _SendgridClient()

    fake_requests = types.SimpleNamespace(Session=_SessionFactory())
    monkeypatch.setitem(sys.modules, "curl_cffi", types.SimpleNamespace(requests=fake_requests))
    monkeypatch.setitem(sys.modules, "curl_cffi.requests", fake_requests)
    result = SendgridKeyValidator().validate(
        "SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg"
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "HTTP 429"
    http_pacing._clear_rate_limit_cooldowns_for_tests()


def test_sendgrid_validator_rate_limited_scopes_stays_unconfirmed(monkeypatch):
    from forge.utils.intel import http_pacing  # noqa: PLC0415

    http_pacing._clear_rate_limit_cooldowns_for_tests()
    monkeypatch.setattr(http_pacing.time, "sleep", lambda _seconds: None)
    monkeypatch.setenv("FORGE_KEY_VALIDATION_RATE_LIMIT_RETRIES", "0")

    class _SendgridClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None, **kwargs):  # noqa: ANN001
            del headers, kwargs
            response = MagicMock()
            if url == "https://api.sendgrid.com/v3/user/profile":
                response.status_code = 403
                response.text = "{}"
                return response
            assert url == "https://api.sendgrid.com/v3/scopes"
            response.status_code = 429
            response.text = "{}"
            return response

    class _SessionFactory:
        def __call__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            del args, kwargs
            return _SendgridClient()

    fake_requests = types.SimpleNamespace(Session=_SessionFactory())
    monkeypatch.setitem(sys.modules, "curl_cffi", types.SimpleNamespace(requests=fake_requests))
    monkeypatch.setitem(sys.modules, "curl_cffi.requests", fake_requests)
    result = SendgridKeyValidator().validate(
        "SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg"
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "HTTP 429"
    http_pacing._clear_rate_limit_cooldowns_for_tests()


def test_google_api_key_validator_active_lists_gemini_models(monkeypatch):
    class _GoogleClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, params=None):  # noqa: ANN001
            assert url == "https://generativelanguage.googleapis.com/v1beta/models"
            assert str(params.get("key") or "").startswith("AIza")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "models": [
                    {"name": "models/gemini-2.5-flash"},
                    {"name": "models/text-embedding-004"},
                ]
            }
            return response

    monkeypatch.setattr("httpx.Client", _GoogleClient)
    result = GoogleApiKeyValidator().validate("AIza" + "A" * 35)

    assert result.state == ValidationState.ACTIVE
    assert result.detail == (
        "Google Generative Language models ok: models=2 "
        "sample=models/gemini-2.5-flash,models/text-embedding-004"
    )


def test_google_api_key_validator_200_without_models_stays_unconfirmed(monkeypatch):
    class _GoogleClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, params=None):  # noqa: ANN001
            assert url == "https://generativelanguage.googleapis.com/v1beta/models"
            assert str(params.get("key") or "").startswith("AIza")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"models": []}
            return response

    monkeypatch.setattr("httpx.Client", _GoogleClient)
    result = GoogleApiKeyValidator().validate("AIza" + "D" * 35)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Google Generative Language response missing models"


def test_google_api_key_validator_200_without_model_identifiers_stays_unconfirmed(monkeypatch):
    class _GoogleClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, params=None):  # noqa: ANN001
            del url, params
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "models": [
                    {"name": "unknown"},
                    {"name": "models/test"},
                    {"name": "models/0000"},
                ]
            }
            return response

    monkeypatch.setattr("httpx.Client", _GoogleClient)
    result = GoogleApiKeyValidator().validate("AIza" + "E" * 35)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Google Generative Language response missing model identifiers"


def test_google_api_key_validator_200_with_arbitrary_model_family_stays_unconfirmed(
    monkeypatch,
):
    class _GoogleClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, params=None):  # noqa: ANN001
            del url, params
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "models": [
                    {"name": "models/vendor-model-alpha"},
                    {"name": "models/service-placeholder-2026"},
                ]
            }
            return response

    monkeypatch.setattr("httpx.Client", _GoogleClient)
    result = GoogleApiKeyValidator().validate("AIza" + "G" * 35)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Google Generative Language response missing model identifiers"


def test_google_api_key_validator_invalid_key_is_revoked(monkeypatch):
    class _GoogleClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, params=None):  # noqa: ANN001
            del url, params
            response = MagicMock()
            response.status_code = 400
            response.json.return_value = {
                "error": {
                    "status": "API_KEY_INVALID",
                    "message": "API key not valid. Please pass a valid API key.",
                }
            }
            return response

    monkeypatch.setattr("httpx.Client", _GoogleClient)
    result = GoogleApiKeyValidator().validate("AIza" + "B" * 35)

    assert result.state == ValidationState.REVOKED
    assert "API_KEY_INVALID" in (result.detail or "")


def test_google_api_key_validator_restricted_key_stays_unconfirmed(monkeypatch):
    class _GoogleClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, params=None):  # noqa: ANN001
            del url, params
            response = MagicMock()
            response.status_code = 403
            response.json.return_value = {
                "error": {
                    "status": "PERMISSION_DENIED",
                    "message": "API key not authorized for this API.",
                }
            }
            return response

    monkeypatch.setattr("httpx.Client", _GoogleClient)
    result = GoogleApiKeyValidator().validate("AIza" + "C" * 35)

    assert result.state == ValidationState.UNCONFIRMED
    assert "PERMISSION_DENIED" in (result.detail or "")


def test_google_api_key_validator_rate_limited_stays_unconfirmed(monkeypatch):
    from forge.utils.intel import http_pacing  # noqa: PLC0415

    http_pacing._clear_rate_limit_cooldowns_for_tests()
    monkeypatch.setattr(http_pacing.time, "sleep", lambda _seconds: None)

    class _GoogleClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, params=None):  # noqa: ANN001
            assert url == "https://generativelanguage.googleapis.com/v1beta/models"
            assert str(params.get("key") or "").startswith("AIza")
            response = MagicMock()
            response.status_code = 429
            response.json.return_value = {
                "error": {
                    "status": "RESOURCE_EXHAUSTED",
                    "message": "Quota exceeded.",
                }
            }
            return response

    monkeypatch.setattr("httpx.Client", _GoogleClient)
    result = GoogleApiKeyValidator().validate("AIza" + "F" * 35)

    assert result.state == ValidationState.UNCONFIRMED
    assert "RESOURCE_EXHAUSTED" in (result.detail or "")
    http_pacing._clear_rate_limit_cooldowns_for_tests()


def test_openai_key_validator_active_lists_models(monkeypatch):
    class _OpenAIClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://api.openai.com/v1/models"
            assert str(headers.get("Authorization") or "").startswith("Bearer sk-proj-")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "object": "list",
                "data": [
                    {"id": "gpt-4o-mini", "object": "model"},
                    {"id": "text-embedding-3-small", "object": "model"},
                ],
            }
            return response

    monkeypatch.setattr("httpx.Client", _OpenAIClient)
    result = OpenAIKeyValidator().validate("sk-proj-" + "A" * 48)

    assert result.state == ValidationState.ACTIVE
    assert result.detail == (
        "OpenAI models ok: models=2 sample=gpt-4o-mini,text-embedding-3-small"
    )


def test_openai_key_validator_200_without_models_stays_unconfirmed(monkeypatch):
    class _OpenAIClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"object": "list", "data": []}
            return response

    monkeypatch.setattr("httpx.Client", _OpenAIClient)
    result = OpenAIKeyValidator().validate("sk-" + "B" * 48)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "OpenAI models response missing data"


def test_openai_key_validator_200_without_model_identifiers_stays_unconfirmed(monkeypatch):
    class _OpenAIClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "object": "list",
                "data": [
                    {"id": "placeholder"},
                    {"id": "0000"},
                    {"id": "aaaaaaaa"},
                ],
            }
            return response

    monkeypatch.setattr("httpx.Client", _OpenAIClient)
    result = OpenAIKeyValidator().validate("sk-proj-" + "F" * 48)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "OpenAI models response missing model identifiers"


def test_openai_key_validator_200_with_arbitrary_model_family_stays_unconfirmed(monkeypatch):
    class _OpenAIClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "object": "list",
                "data": [
                    {"id": "vendor-model-alpha"},
                    {"id": "llm-preview-stable"},
                ],
            }
            return response

    monkeypatch.setattr("httpx.Client", _OpenAIClient)
    result = OpenAIKeyValidator().validate("sk-proj-" + "G" * 48)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "OpenAI models response missing model identifiers"


def test_openai_key_validator_invalid_key_is_revoked(monkeypatch):
    class _OpenAIClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 401
            response.json.return_value = {
                "error": {
                    "code": "invalid_api_key",
                    "message": "Incorrect API key provided.",
                }
            }
            return response

    monkeypatch.setattr("httpx.Client", _OpenAIClient)
    result = OpenAIKeyValidator().validate("sk-proj-" + "C" * 48)

    assert result.state == ValidationState.REVOKED
    assert "invalid_api_key" in (result.detail or "")


def test_anthropic_key_validator_active_lists_models(monkeypatch):
    class _AnthropicClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://api.anthropic.com/v1/models"
            assert str(headers.get("x-api-key") or "").startswith("sk-ant-api03-")
            assert headers.get("anthropic-version") == "2023-06-01"
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "data": [
                    {"id": "claude-sonnet-4-5"},
                    {"id": "claude-haiku-4-5"},
                ],
                "has_more": False,
            }
            return response

    monkeypatch.setattr("httpx.Client", _AnthropicClient)
    result = AnthropicKeyValidator().validate("sk-ant-api03-" + "D" * 48)

    assert result.state == ValidationState.ACTIVE
    assert result.detail == (
        "Anthropic models ok: models=2 sample=claude-sonnet-4-5,claude-haiku-4-5"
    )


def test_anthropic_key_validator_200_without_model_identifiers_stays_unconfirmed(monkeypatch):
    class _AnthropicClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "data": [
                    {"id": "test"},
                    {"id": "model"},
                    {"id": "bbbbbbbb"},
                ],
                "has_more": False,
            }
            return response

    monkeypatch.setattr("httpx.Client", _AnthropicClient)
    result = AnthropicKeyValidator().validate("sk-ant-api03-" + "F" * 48)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Anthropic models response missing model identifiers"


def test_anthropic_key_validator_200_with_arbitrary_model_family_stays_unconfirmed(monkeypatch):
    class _AnthropicClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "data": [
                    {"id": "vendor-model-alpha"},
                    {"id": "sonnet-placeholder-2026"},
                ],
                "has_more": False,
            }
            return response

    monkeypatch.setattr("httpx.Client", _AnthropicClient)
    result = AnthropicKeyValidator().validate("sk-ant-api03-" + "G" * 48)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Anthropic models response missing model identifiers"


def test_anthropic_key_validator_rate_limited_stays_unconfirmed(monkeypatch):
    from forge.utils.intel import http_pacing  # noqa: PLC0415

    http_pacing._clear_rate_limit_cooldowns_for_tests()
    monkeypatch.setattr(http_pacing.time, "sleep", lambda _seconds: None)

    class _AnthropicClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 429
            response.json.return_value = {
                "error": {
                    "type": "rate_limit_error",
                    "message": "Too many requests.",
                }
            }
            return response

    monkeypatch.setattr("httpx.Client", _AnthropicClient)
    result = AnthropicKeyValidator().validate("sk-ant-api03-" + "E" * 48)

    assert result.state == ValidationState.UNCONFIRMED
    assert "rate_limit_error" in (result.detail or "")
    http_pacing._clear_rate_limit_cooldowns_for_tests()


def test_huggingface_token_validator_active_uses_whoami_without_private_detail(monkeypatch):
    class _HuggingFaceClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://huggingface.co/api/whoami-v2"
            assert str(headers.get("Authorization") or "").startswith("Bearer hf_")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "name": "acme-mlops",
                "email": "private@acme.io",
                "orgs": [{"name": "sensitive-org"}],
            }
            return response

    monkeypatch.setattr("httpx.Client", _HuggingFaceClient)
    result = HuggingFaceTokenValidator().validate("hf_" + "H" * 36)

    assert result.state == ValidationState.ACTIVE
    assert result.detail == "Hugging Face auth ok: user=acme-mlops user_profile_present=true"
    assert "private@acme.io" not in (result.detail or "")
    assert "sensitive-org" not in (result.detail or "")


def test_huggingface_token_validator_200_without_user_stays_unconfirmed(monkeypatch):
    class _HuggingFaceClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"email": "private@acme.example"}
            return response

    monkeypatch.setattr("httpx.Client", _HuggingFaceClient)
    result = HuggingFaceTokenValidator().validate("hf_" + "I" * 36)

    assert result.state == ValidationState.UNCONFIRMED
    assert "missing user identifier" in (result.detail or "")


def test_huggingface_token_validator_200_without_user_proof_stays_unconfirmed(monkeypatch):
    class _HuggingFaceClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"name": "acme-mlops"}
            return response

    monkeypatch.setattr("httpx.Client", _HuggingFaceClient)
    result = HuggingFaceTokenValidator().validate("hf_" + "L" * 36)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Hugging Face whoami response missing user proof"


def test_huggingface_token_validator_200_with_placeholder_user_stays_unconfirmed(monkeypatch):
    class _HuggingFaceClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "name": "unknown",
                "username": "----",
                "user": "null",
            }
            return response

    monkeypatch.setattr("httpx.Client", _HuggingFaceClient)
    result = HuggingFaceTokenValidator().validate("hf_" + "J" * 36)

    assert result.state == ValidationState.UNCONFIRMED
    assert "missing user identifier" in (result.detail or "")


@pytest.mark.parametrize("name", ["demo-user", "model-owner"])
def test_huggingface_token_validator_200_with_tokenized_placeholder_user_stays_unconfirmed(
    name: str,
    monkeypatch,
):
    class _HuggingFaceClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "name": name,
                "email": "owner@acme.io",
            }
            return response

    monkeypatch.setattr("httpx.Client", _HuggingFaceClient)
    result = HuggingFaceTokenValidator().validate("hf_" + "M" * 36)

    assert result.state == ValidationState.UNCONFIRMED
    assert "missing user identifier" in (result.detail or "")


def test_huggingface_token_validator_200_with_repeated_user_stays_unconfirmed(monkeypatch):
    class _HuggingFaceClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "name": "aaaaaaaa",
                "username": "000000",
                "user": "bbbbbb",
            }
            return response

    monkeypatch.setattr("httpx.Client", _HuggingFaceClient)
    result = HuggingFaceTokenValidator().validate("hf_" + "K" * 36)

    assert result.state == ValidationState.UNCONFIRMED
    assert "missing user identifier" in (result.detail or "")


def test_discord_bot_token_validator_active_uses_current_user(monkeypatch):
    class _DiscordClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://discord.com/api/v10/users/@me"
            assert str(headers.get("Authorization") or "").startswith("Bot ")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "id": "739251864203918576",
                "username": "sensitive-bot-name",
                "bot": True,
            }
            return response

    monkeypatch.setattr("httpx.Client", _DiscordClient)
    result = DiscordBotTokenValidator().validate(
        "M" * 24 + "." + "A" * 6 + "." + "B" * 27
    )

    assert result.state == ValidationState.ACTIVE
    assert result.detail == "Discord bot auth ok: bot_id=739251864203918576 bot_profile_present=true"
    assert "sensitive-bot-name" not in (result.detail or "")


def test_discord_bot_token_validator_id_only_response_stays_unconfirmed(monkeypatch):
    class _DiscordClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://discord.com/api/v10/users/@me"
            assert str(headers.get("Authorization") or "").startswith("Bot ")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"id": "739251864203918576"}
            return response

    monkeypatch.setattr("httpx.Client", _DiscordClient)
    result = DiscordBotTokenValidator().validate(
        "M" * 24 + "." + "A" * 6 + "." + "B" * 27
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Discord current user response missing bot proof"


def test_discord_bot_token_validator_non_bot_user_stays_unconfirmed(monkeypatch):
    class _DiscordClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://discord.com/api/v10/users/@me"
            assert str(headers.get("Authorization") or "").startswith("Bot ")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "id": "739251864203918576",
                "username": "not-a-bot-user",
                "bot": False,
            }
            return response

    monkeypatch.setattr("httpx.Client", _DiscordClient)
    result = DiscordBotTokenValidator().validate(
        "M" * 24 + "." + "A" * 6 + "." + "B" * 27
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Discord current user response missing bot proof"


def test_discord_bot_token_validator_placeholder_bot_id_stays_unconfirmed(monkeypatch):
    class _DiscordClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "id": "000000000000000000",
                "username": "placeholder-bot",
                "bot": True,
            }
            return response

    monkeypatch.setattr("httpx.Client", _DiscordClient)
    result = DiscordBotTokenValidator().validate(
        "M" * 24 + "." + "A" * 6 + "." + "B" * 27
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Discord current user response missing bot id"


def test_discord_bot_token_validator_sequential_bot_id_stays_unconfirmed(monkeypatch):
    class _DiscordClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "id": "123456789012345678",
                "username": "sensitive-bot-name",
                "bot": True,
            }
            return response

    monkeypatch.setattr("httpx.Client", _DiscordClient)
    result = DiscordBotTokenValidator().validate(
        "M" * 24 + "." + "A" * 6 + "." + "B" * 27
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Discord current user response missing bot id"


def test_discord_bot_token_validator_generic_bot_name_stays_unconfirmed(monkeypatch):
    class _DiscordClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "id": "739251864203918576",
                "username": "bot",
                "bot": True,
            }
            return response

    monkeypatch.setattr("httpx.Client", _DiscordClient)
    result = DiscordBotTokenValidator().validate(
        "M" * 24 + "." + "A" * 6 + "." + "B" * 27
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Discord current user response missing bot proof"


def test_discord_bot_token_validator_unauthorized_is_revoked(monkeypatch):
    class _DiscordClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 401
            response.json.return_value = {"message": "401: Unauthorized"}
            return response

    monkeypatch.setattr("httpx.Client", _DiscordClient)
    result = DiscordBotTokenValidator().validate(
        "N" * 24 + "." + "C" * 6 + "." + "D" * 27
    )

    assert result.state == ValidationState.REVOKED
    assert result.detail == "HTTP 401"


def test_telegram_bot_token_validator_active_uses_get_me(monkeypatch):
    class _TelegramClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str):  # noqa: ANN001
            assert url == "https://api.telegram.org/bot725419863:" + "T" * 35 + "/getMe"
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "ok": True,
                "result": {
                    "id": 725419863,
                    "is_bot": True,
                    "username": "private_bot_name",
                },
            }
            return response

    monkeypatch.setattr("httpx.Client", _TelegramClient)
    result = TelegramBotTokenValidator().validate("725419863:" + "T" * 35)

    assert result.state == ValidationState.ACTIVE
    assert result.detail == "Telegram bot auth ok: bot_id=725419863 bot_profile_present=true"
    assert "private_bot_name" not in (result.detail or "")


def test_telegram_bot_token_validator_mismatched_bot_id_stays_unconfirmed(monkeypatch):
    class _TelegramClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str):  # noqa: ANN001
            assert url == "https://api.telegram.org/bot725419863:" + "T" * 35 + "/getMe"
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "ok": True,
                "result": {
                    "id": 925419863,
                    "is_bot": True,
                    "username": "private_bot_name",
                },
            }
            return response

    monkeypatch.setattr("httpx.Client", _TelegramClient)
    result = TelegramBotTokenValidator().validate("725419863:" + "T" * 35)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Telegram getMe bot id did not match token prefix"


def test_telegram_bot_token_validator_id_only_response_stays_unconfirmed(monkeypatch):
    class _TelegramClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str):  # noqa: ANN001
            assert url == "https://api.telegram.org/bot725419863:" + "T" * 35 + "/getMe"
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "ok": True,
                "result": {"id": 725419863},
            }
            return response

    monkeypatch.setattr("httpx.Client", _TelegramClient)
    result = TelegramBotTokenValidator().validate("725419863:" + "T" * 35)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Telegram getMe response missing bot proof"


def test_telegram_bot_token_validator_non_bot_user_stays_unconfirmed(monkeypatch):
    class _TelegramClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str):  # noqa: ANN001
            assert url == "https://api.telegram.org/bot725419863:" + "T" * 35 + "/getMe"
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "ok": True,
                "result": {
                    "id": 725419863,
                    "is_bot": False,
                    "username": "not_a_bot_user",
                },
            }
            return response

    monkeypatch.setattr("httpx.Client", _TelegramClient)
    result = TelegramBotTokenValidator().validate("725419863:" + "T" * 35)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Telegram getMe response missing bot proof"


def test_telegram_bot_token_validator_placeholder_bot_id_stays_unconfirmed(monkeypatch):
    class _TelegramClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str):  # noqa: ANN001
            del url
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "ok": True,
                "result": {
                    "id": 777777777,
                    "is_bot": True,
                    "username": "placeholder_bot",
                },
            }
            return response

    monkeypatch.setattr("httpx.Client", _TelegramClient)
    result = TelegramBotTokenValidator().validate("1234567890:" + "T" * 35)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Telegram getMe response missing bot id"


def test_telegram_bot_token_validator_sequential_bot_id_stays_unconfirmed(monkeypatch):
    class _TelegramClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str):  # noqa: ANN001
            del url
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "ok": True,
                "result": {
                    "id": 765432109,
                    "is_bot": True,
                    "username": "private_bot_name",
                },
            }
            return response

    monkeypatch.setattr("httpx.Client", _TelegramClient)
    result = TelegramBotTokenValidator().validate("1234567890:" + "T" * 35)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Telegram getMe response missing bot id"


def test_telegram_bot_token_validator_generic_bot_name_stays_unconfirmed(monkeypatch):
    class _TelegramClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str):  # noqa: ANN001
            del url
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "ok": True,
                "result": {
                    "id": 725419863,
                    "is_bot": True,
                    "username": "bot",
                },
            }
            return response

    monkeypatch.setattr("httpx.Client", _TelegramClient)
    result = TelegramBotTokenValidator().validate("725419863:" + "T" * 35)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Telegram getMe response missing bot proof"


def test_telegram_bot_token_validator_unauthorized_is_revoked(monkeypatch):
    class _TelegramClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str):  # noqa: ANN001
            del url
            response = MagicMock()
            response.status_code = 401
            response.json.return_value = {
                "ok": False,
                "error_code": 401,
                "description": "Unauthorized",
            }
            return response

    monkeypatch.setattr("httpx.Client", _TelegramClient)
    result = TelegramBotTokenValidator().validate("1234567890:" + "U" * 35)

    assert result.state == ValidationState.REVOKED
    assert result.detail == "401: Unauthorized"


def test_notion_token_validator_active_uses_users_me_without_private_detail(monkeypatch):
    class _NotionClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://api.notion.com/v1/users/me"
            assert str(headers.get("Authorization") or "").startswith("Bearer ntn_")
            assert headers.get("Notion-Version") == "2026-03-11"
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "object": "user",
                "id": "3c90c3cc-0d44-4b50-8888-8dd25736052a",
                "name": "Sensitive Workspace Bot",
                "person": {"email": "private@acme.io"},
            }
            return response

    monkeypatch.setattr("httpx.Client", _NotionClient)
    result = NotionTokenValidator().validate("ntn_" + "N" * 40)

    assert result.state == ValidationState.ACTIVE
    assert result.detail == (
        "Notion users me ok: user_id=3c90c3cc-0d44-4b50-8888-8dd25736052a "
        "user_profile_present=true"
    )
    assert "Sensitive" not in (result.detail or "")
    assert "private@acme.io" not in (result.detail or "")


def test_notion_token_validator_200_without_user_id_stays_unconfirmed(monkeypatch):
    class _NotionClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"object": "user", "name": "No ID"}
            return response

    monkeypatch.setattr("httpx.Client", _NotionClient)
    result = NotionTokenValidator().validate("secret_" + "A" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Notion users/me response missing user id"


def test_notion_token_validator_200_without_user_proof_stays_unconfirmed(monkeypatch):
    class _NotionClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "object": "user",
                "id": "3c90c3cc-0d44-4b50-8888-8dd25736052a",
            }
            return response

    monkeypatch.setattr("httpx.Client", _NotionClient)
    result = NotionTokenValidator().validate("secret_" + "E" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Notion users/me response missing user proof"


def test_notion_token_validator_200_with_reserved_avatar_url_stays_unconfirmed(monkeypatch):
    class _NotionClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "object": "user",
                "id": "3c90c3cc-0d44-4b50-8888-8dd25736052a",
                "avatar_url": "https://example.com/avatar.png",
            }
            return response

    monkeypatch.setattr("httpx.Client", _NotionClient)
    result = NotionTokenValidator().validate("secret_" + "E" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Notion users/me response missing user proof"


def test_notion_token_validator_200_with_default_avatar_url_stays_unconfirmed(monkeypatch):
    class _NotionClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "object": "user",
                "id": "3c90c3cc-0d44-4b50-8888-8dd25736052a",
                "avatar_url": "https://cdn.acme.test/default-avatar.png",
            }
            return response

    monkeypatch.setattr("httpx.Client", _NotionClient)
    result = NotionTokenValidator().validate("secret_" + "E" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Notion users/me response missing user proof"


def test_notion_token_validator_200_with_malformed_user_id_stays_unconfirmed(monkeypatch):
    class _NotionClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"object": "user", "id": "-" * 36}
            return response

    monkeypatch.setattr("httpx.Client", _NotionClient)
    result = NotionTokenValidator().validate("secret_" + "C" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Notion users/me response missing user id"


def test_notion_token_validator_200_with_placeholder_uuid_stays_unconfirmed(monkeypatch):
    class _NotionClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"object": "user", "id": "00000000-0000-0000-0000-000000000000"}
            return response

    monkeypatch.setattr("httpx.Client", _NotionClient)
    result = NotionTokenValidator().validate("secret_" + "D" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Notion users/me response missing user id"


def test_notion_token_validator_200_with_sequential_uuid_stays_unconfirmed(monkeypatch):
    class _NotionClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "object": "user",
                "id": "12345678-9012-3456-7890-123456789012",
                "name": "Valid Looking User",
            }
            return response

    monkeypatch.setattr("httpx.Client", _NotionClient)
    result = NotionTokenValidator().validate("secret_" + "D" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Notion users/me response missing user id"


def test_notion_token_validator_unauthorized_is_revoked(monkeypatch):
    class _NotionClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 401
            response.json.return_value = {
                "code": "unauthorized",
                "message": "API token is invalid.",
            }
            return response

    monkeypatch.setattr("httpx.Client", _NotionClient)
    result = NotionTokenValidator().validate("ntn_" + "B" * 40)

    assert result.state == ValidationState.REVOKED
    assert "unauthorized" in (result.detail or "")


def test_datadog_api_key_validator_active_checks_documented_sites(monkeypatch):
    seen_urls: list[str] = []

    class _DatadogClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            seen_urls.append(url)
            assert headers.get("DD-API-KEY") == "0123456789abcdef0123456789abcdef"
            response = MagicMock()
            if "datadoghq.eu" in url:
                response.status_code = 200
                response.json.return_value = {"valid": True}
            else:
                response.status_code = 403
                response.json.return_value = {"errors": ["Forbidden"]}
            return response

    monkeypatch.setattr("httpx.Client", _DatadogClient)
    result = DatadogApiKeyValidator().validate("0123456789abcdef0123456789abcdef")

    assert result.state == ValidationState.ACTIVE
    assert result.detail == "Datadog API key valid: site=datadoghq.eu proof=valid_true"
    assert seen_urls == [
        "https://api.datadoghq.com/api/v1/validate",
        "https://api.datadoghq.eu/api/v1/validate",
    ]


def test_datadog_api_key_validator_placeholder_key_stays_unconfirmed_before_request(monkeypatch):
    called = False

    class _DatadogClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            nonlocal called
            del args, kwargs
            called = True
            raise AssertionError("Datadog validation should not call provider for placeholder keys")

    monkeypatch.setattr("httpx.Client", _DatadogClient)
    result = DatadogApiKeyValidator().validate("0" * 32)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Datadog API key shape is invalid for deterministic validation"
    assert called is False


def test_datadog_api_key_validator_200_without_valid_boolean_stays_unconfirmed(monkeypatch):
    class _DatadogClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert headers.get("DD-API-KEY") == "0123456789abcdef0123456789abcdef"
            response = MagicMock()
            if "datadoghq.eu" in url:
                response.status_code = 200
                response.json.return_value = {"status": "ok"}
            else:
                response.status_code = 403
                response.json.return_value = {"errors": ["Forbidden"]}
            return response

    monkeypatch.setattr("httpx.Client", _DatadogClient)
    result = DatadogApiKeyValidator().validate("0123456789abcdef0123456789abcdef")

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "datadoghq.eu: Datadog validate response missing valid boolean"


def test_datadog_api_key_validator_all_auth_failures_are_revoked(monkeypatch):
    class _DatadogClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 403
            response.json.return_value = {"errors": ["Forbidden"]}
            return response

    monkeypatch.setattr("httpx.Client", _DatadogClient)
    result = DatadogApiKeyValidator().validate("fedcba9876543210fedcba9876543210")

    assert result.state == ValidationState.REVOKED
    assert result.detail == "Datadog API key invalid across tested sites"


def test_cloudflare_api_token_validator_active_uses_verify_without_private_detail(monkeypatch):
    class _CloudflareClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://api.cloudflare.com/client/v4/user/tokens/verify"
            assert str(headers.get("Authorization") or "").startswith("Bearer ")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "success": True,
                "result": {
                    "id": "abcdef1234567890abcdef1234567890",
                    "status": "active",
                    "name": "Sensitive deployment token",
                },
            }
            return response

    monkeypatch.setattr("httpx.Client", _CloudflareClient)
    result = CloudflareApiTokenValidator().validate("C" * 40)

    assert result.state == ValidationState.ACTIVE
    assert result.detail == (
        "Cloudflare token valid: token_id=abcdef1234567890abcdef1234567890 status=active"
    )
    assert "Sensitive" not in (result.detail or "")


def test_cloudflare_api_token_validator_placeholder_token_id_stays_unconfirmed(monkeypatch):
    class _CloudflareClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "success": True,
                "result": {"id": "placeholder", "status": "active"},
            }
            return response

    monkeypatch.setattr("httpx.Client", _CloudflareClient)
    result = CloudflareApiTokenValidator().validate("C" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Cloudflare token verify response missing token id"


def test_cloudflare_api_token_validator_inactive_token_is_revoked(monkeypatch):
    class _CloudflareClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "success": True,
                "result": {"id": "abcdef1234567890abcdef1234567890", "status": "expired"},
            }
            return response

    monkeypatch.setattr("httpx.Client", _CloudflareClient)
    result = CloudflareApiTokenValidator().validate("C" * 40)

    assert result.state == ValidationState.REVOKED
    assert result.detail == "Cloudflare token status: expired"


def test_vercel_token_validator_active_uses_current_user_without_private_detail(monkeypatch):
    class _VercelClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://api.vercel.com/v2/user"
            assert str(headers.get("Authorization") or "").startswith("Bearer ")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "user": {
                    "id": "usr_abcdefghijklmnop",
                    "email": "private@acme.io",
                    "name": "Sensitive User",
                }
            }
            return response

    monkeypatch.setattr("httpx.Client", _VercelClient)
    result = VercelTokenValidator().validate("V" * 40)

    assert result.state == ValidationState.ACTIVE
    assert result.detail == "Vercel user ok: user_id=usr_abcdefghijklmnop user_profile_present=true"
    assert "private@acme.io" not in (result.detail or "")
    assert "Sensitive" not in (result.detail or "")


def test_vercel_token_validator_generic_name_proof_stays_unconfirmed(monkeypatch):
    class _VercelClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "user": {
                    "id": "usr_abcdefghijklmnop",
                    "name": "Test User",
                }
            }
            return response

    monkeypatch.setattr("httpx.Client", _VercelClient)
    result = VercelTokenValidator().validate("V" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Vercel user response missing user proof"


def test_vercel_token_validator_id_only_response_stays_unconfirmed(monkeypatch):
    class _VercelClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"user": {"id": "usr_abcdefghijklmnop"}}
            return response

    monkeypatch.setattr("httpx.Client", _VercelClient)
    result = VercelTokenValidator().validate("V" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Vercel user response missing user proof"


def test_vercel_token_validator_placeholder_user_id_stays_unconfirmed(monkeypatch):
    class _VercelClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"user": {"id": "placeholder"}}
            return response

    monkeypatch.setattr("httpx.Client", _VercelClient)
    result = VercelTokenValidator().validate("V" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Vercel user response missing user id"


def test_vercel_token_validator_repeated_user_id_stays_unconfirmed(monkeypatch):
    class _VercelClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"user": {"id": "aaaaaaaaaaaaaaaa"}}
            return response

    monkeypatch.setattr("httpx.Client", _VercelClient)
    result = VercelTokenValidator().validate("V" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Vercel user response missing user id"


def test_vercel_token_validator_prefixed_repeated_user_id_stays_unconfirmed(monkeypatch):
    class _VercelClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"user": {"id": "usr_000000000000"}}
            return response

    monkeypatch.setattr("httpx.Client", _VercelClient)
    result = VercelTokenValidator().validate("V" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Vercel user response missing user id"


def test_vercel_token_validator_tokenized_placeholder_user_id_stays_unconfirmed(monkeypatch):
    class _VercelClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "user": {
                    "id": "usr_placeholder",
                    "email": "private@acme.io",
                }
            }
            return response

    monkeypatch.setattr("httpx.Client", _VercelClient)
    result = VercelTokenValidator().validate("V" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Vercel user response missing user id"


def test_netlify_token_validator_active_uses_current_user_without_private_detail(monkeypatch):
    class _NetlifyClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://api.netlify.com/api/v1/user"
            assert str(headers.get("Authorization") or "").startswith("Bearer ")
            assert headers.get("User-Agent") == "ForgeSecurityAssessment/1.0"
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "id": "netlify-user-123",
                "email": "private@acme.io",
                "full_name": "Sensitive User",
            }
            return response

    monkeypatch.setattr("httpx.Client", _NetlifyClient)
    result = NetlifyTokenValidator().validate("N" * 40)

    assert result.state == ValidationState.ACTIVE
    assert result.detail == "Netlify user ok: user_id=netlify-user-123 user_profile_present=true"
    assert "private@acme.io" not in (result.detail or "")
    assert "Sensitive" not in (result.detail or "")


def test_netlify_token_validator_id_only_response_stays_unconfirmed(monkeypatch):
    class _NetlifyClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"id": "netlify-user-123"}
            return response

    monkeypatch.setattr("httpx.Client", _NetlifyClient)
    result = NetlifyTokenValidator().validate("N" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Netlify user response missing user proof"


def test_netlify_token_validator_placeholder_user_id_stays_unconfirmed(monkeypatch):
    class _NetlifyClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"id": "sample"}
            return response

    monkeypatch.setattr("httpx.Client", _NetlifyClient)
    result = NetlifyTokenValidator().validate("N" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Netlify user response missing user id"


def test_netlify_token_validator_repeated_user_id_stays_unconfirmed(monkeypatch):
    class _NetlifyClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"id": "000000000000"}
            return response

    monkeypatch.setattr("httpx.Client", _NetlifyClient)
    result = NetlifyTokenValidator().validate("N" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Netlify user response missing user id"


def test_netlify_token_validator_prefixed_repeated_user_id_stays_unconfirmed(monkeypatch):
    class _NetlifyClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"id": "user-aaaaaaaaaaaa"}
            return response

    monkeypatch.setattr("httpx.Client", _NetlifyClient)
    result = NetlifyTokenValidator().validate("N" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Netlify user response missing user id"


def test_posthog_personal_api_key_validator_active_checks_documented_hosts(monkeypatch):
    seen_urls: list[str] = []

    class _PostHogClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            seen_urls.append(url)
            assert str(headers.get("Authorization") or "").startswith("Bearer phx_")
            response = MagicMock()
            if "eu.posthog.com" in url:
                response.status_code = 200
                response.json.return_value = {
                    "uuid": "018f9b7d-1234-4567-9abc-def012345678",
                    "email": "private@acme.io",
                }
            else:
                response.status_code = 401
                response.json.return_value = {
                    "type": "authentication_error",
                    "code": "invalid_personal_api_key",
                    "detail": "Invalid Personal API key.",
                }
            return response

    monkeypatch.setattr("httpx.Client", _PostHogClient)
    result = PostHogPersonalApiKeyValidator().validate("phx_" + "P" * 40)

    assert result.state == ValidationState.ACTIVE
    assert result.detail == (
        "PostHog users me ok: host=eu.posthog.com "
        "user_id=018f9b7d-1234-4567-9abc-def012345678 user_profile_present=true"
    )
    assert "private@acme.io" not in (result.detail or "")
    assert seen_urls == [
        "https://us.posthog.com/api/users/@me/",
        "https://eu.posthog.com/api/users/@me/",
    ]


def test_posthog_personal_api_key_validator_continues_after_low_signal_success(monkeypatch):
    seen_urls: list[str] = []

    class _PostHogClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            seen_urls.append(url)
            assert str(headers.get("Authorization") or "").startswith("Bearer phx_")
            response = MagicMock()
            response.status_code = 200
            if "us.posthog.com" in url:
                response.json.return_value = {"uuid": "test"}
            else:
                response.json.return_value = {
                    "uuid": "018f9b7d-1234-4567-9abc-def012345678",
                    "email": "private@acme.io",
                }
            return response

    monkeypatch.setattr("httpx.Client", _PostHogClient)
    result = PostHogPersonalApiKeyValidator().validate("phx_" + "P" * 40)

    assert result.state == ValidationState.ACTIVE
    assert result.detail == (
        "PostHog users me ok: host=eu.posthog.com "
        "user_id=018f9b7d-1234-4567-9abc-def012345678 user_profile_present=true"
    )
    assert "private@acme.io" not in (result.detail or "")
    assert seen_urls == [
        "https://us.posthog.com/api/users/@me/",
        "https://eu.posthog.com/api/users/@me/",
    ]


def test_posthog_personal_api_key_validator_id_only_response_stays_unconfirmed(monkeypatch):
    class _PostHogClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del headers
            response = MagicMock()
            if "eu.posthog.com" in url:
                response.status_code = 200
                response.json.return_value = {
                    "uuid": "018f9b7d-1234-4567-9abc-def012345678",
                }
            else:
                response.status_code = 401
                response.json.return_value = {"detail": "Invalid Personal API key."}
            return response

    monkeypatch.setattr("httpx.Client", _PostHogClient)
    result = PostHogPersonalApiKeyValidator().validate("phx_" + "P" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "eu.posthog.com: PostHog users/@me response missing user proof"


def test_posthog_personal_api_key_validator_placeholder_user_id_stays_unconfirmed(monkeypatch):
    class _PostHogClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del headers
            response = MagicMock()
            if "eu.posthog.com" in url:
                response.status_code = 200
                response.json.return_value = {"uuid": "test"}
            else:
                response.status_code = 401
                response.json.return_value = {"detail": "Invalid Personal API key."}
            return response

    monkeypatch.setattr("httpx.Client", _PostHogClient)
    result = PostHogPersonalApiKeyValidator().validate("phx_" + "P" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "eu.posthog.com: PostHog users/@me response missing user id"


def test_posthog_personal_api_key_validator_repeated_user_id_stays_unconfirmed(monkeypatch):
    class _PostHogClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del headers
            response = MagicMock()
            response.status_code = 200 if "eu.posthog.com" in url else 401
            response.json.return_value = {"uuid": "zzzzzzzzzzzz"}
            return response

    monkeypatch.setattr("httpx.Client", _PostHogClient)
    result = PostHogPersonalApiKeyValidator().validate("phx_" + "P" * 32)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "eu.posthog.com: PostHog users/@me response missing user id"


def test_posthog_personal_api_key_validator_prefixed_repeated_id_stays_unconfirmed(monkeypatch):
    class _PostHogClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del headers
            response = MagicMock()
            response.status_code = 200 if "eu.posthog.com" in url else 401
            response.json.return_value = {"distinct_id": "user-000000000000"}
            return response

    monkeypatch.setattr("httpx.Client", _PostHogClient)
    result = PostHogPersonalApiKeyValidator().validate("phx_" + "P" * 32)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "eu.posthog.com: PostHog users/@me response missing user id"


def test_posthog_personal_api_key_validator_sequential_uuid_stays_unconfirmed(monkeypatch):
    class _PostHogClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del headers
            response = MagicMock()
            response.status_code = 200 if "eu.posthog.com" in url else 401
            response.json.return_value = {
                "uuid": "12345678-9012-3456-7890-123456789012",
                "email": "private@acme.io",
            }
            return response

    monkeypatch.setattr("httpx.Client", _PostHogClient)
    result = PostHogPersonalApiKeyValidator().validate("phx_" + "P" * 32)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "eu.posthog.com: PostHog users/@me response missing user id"


def test_posthog_personal_api_key_validator_all_auth_failures_are_revoked(monkeypatch):
    class _PostHogClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 401
            response.json.return_value = {
                "type": "authentication_error",
                "code": "invalid_personal_api_key",
                "detail": "Invalid Personal API key.",
            }
            return response

    monkeypatch.setattr("httpx.Client", _PostHogClient)
    result = PostHogPersonalApiKeyValidator().validate("phx_" + "Q" * 40)

    assert result.state == ValidationState.REVOKED
    assert result.detail == "PostHog personal API key invalid across tested hosts"


def test_sentry_auth_token_validator_active_uses_orgs_without_private_detail(monkeypatch):
    class _SentryClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://sentry.io/api/0/organizations/"
            assert str(headers.get("Authorization") or "").startswith("Bearer ")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = [
                {
                    "id": "4505524236910592",
                    "slug": "sensitive-org",
                    "name": "Sensitive Org",
                }
            ]
            return response

    monkeypatch.setattr("httpx.Client", _SentryClient)
    result = SentryAuthTokenValidator().validate("S" * 40)

    assert result.state == ValidationState.ACTIVE
    assert result.detail == (
        "Sentry organizations ok: org_id=4505524236910592 "
        "org_slug_present=true org_slug_stable=true org_slug_hash=02330437d1a44352"
    )
    assert "sensitive-org" not in (result.detail or "")
    assert "Sensitive Org" not in (result.detail or "")


def test_sentry_auth_token_validator_generic_org_slug_stays_unconfirmed(monkeypatch):
    class _SentryClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = [{"id": "4505524236910592", "slug": "test-org"}]
            return response

    monkeypatch.setattr("httpx.Client", _SentryClient)
    result = SentryAuthTokenValidator().validate("S" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Sentry organizations response missing organization proof"


def test_sentry_auth_token_validator_id_only_response_stays_unconfirmed(monkeypatch):
    class _SentryClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = [{"id": "4505524236910592"}]
            return response

    monkeypatch.setattr("httpx.Client", _SentryClient)
    result = SentryAuthTokenValidator().validate("S" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Sentry organizations response missing organization proof"


def test_sentry_auth_token_validator_placeholder_org_id_stays_unconfirmed(monkeypatch):
    class _SentryClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = [{"id": "0000000000000000", "slug": "placeholder"}]
            return response

    monkeypatch.setattr("httpx.Client", _SentryClient)
    result = SentryAuthTokenValidator().validate("S" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Sentry organizations response missing organization proof"


def test_sentry_auth_token_validator_forbidden_stays_unconfirmed(monkeypatch):
    class _SentryClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 403
            response.json.return_value = {"detail": "You do not have permission."}
            return response

    monkeypatch.setattr("httpx.Client", _SentryClient)
    result = SentryAuthTokenValidator().validate("S" * 40)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "You do not have permission."


def test_sentry_auth_token_validator_unauthorized_is_revoked(monkeypatch):
    class _SentryClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def get(self, url: str, headers=None):  # noqa: ANN001
            del url, headers
            response = MagicMock()
            response.status_code = 401
            response.json.return_value = {"detail": "Authentication credentials were not provided."}
            return response

    monkeypatch.setattr("httpx.Client", _SentryClient)
    result = SentryAuthTokenValidator().validate("S" * 40)

    assert result.state == ValidationState.REVOKED
    assert result.detail == "Authentication credentials were not provided."


def test_slack_token_validator_active_requires_actor_and_team(monkeypatch):
    class _SlackClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def post(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://slack.com/api/auth.test"
            assert str(headers.get("Authorization") or "").startswith("Bearer ")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "ok": True,
                "user_id": "U7A3C9K2",
                "team_id": "T9B2D6F4",
                "user": "private-user",
                "team": "Sensitive Workspace",
            }
            return response

    monkeypatch.setattr("httpx.Client", _SlackClient)
    result = SlackTokenValidator().validate(
        "xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx"
    )

    assert result.state == ValidationState.ACTIVE
    assert result.detail == "Slack auth ok: actor_id=U7A3C9K2 team_id=T9B2D6F4"
    assert "private-user" not in (result.detail or "")
    assert "Sensitive" not in (result.detail or "")


def test_slack_token_validator_malformed_token_stays_unconfirmed_before_request(monkeypatch):
    called = False

    class _SlackClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            nonlocal called
            del args, kwargs
            called = True

    monkeypatch.setattr("httpx.Client", _SlackClient)
    result = SlackTokenValidator().validate("not-a-slack-token")

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Slack token shape is invalid for deterministic validation"
    assert called is False


def test_slack_token_validator_rate_limited_stays_unconfirmed(monkeypatch):
    from forge.utils.intel import http_pacing  # noqa: PLC0415

    http_pacing._clear_rate_limit_cooldowns_for_tests()
    monkeypatch.setattr(http_pacing.time, "sleep", lambda _seconds: None)
    monkeypatch.setenv("FORGE_KEY_VALIDATION_RATE_LIMIT_RETRIES", "0")

    class _SlackClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def post(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://slack.com/api/auth.test"
            assert str(headers.get("Authorization") or "").startswith("Bearer ")
            response = MagicMock()
            response.status_code = 429
            return response

    monkeypatch.setattr("httpx.Client", _SlackClient)
    result = SlackTokenValidator().validate(
        "xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx"
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "HTTP 429"
    http_pacing._clear_rate_limit_cooldowns_for_tests()


def test_slack_token_validator_actor_only_response_stays_unconfirmed(monkeypatch):
    class _SlackClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def post(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://slack.com/api/auth.test"
            assert str(headers.get("Authorization") or "").startswith("Bearer ")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"ok": True, "user_id": "U7A3C9K2"}
            return response

    monkeypatch.setattr("httpx.Client", _SlackClient)
    result = SlackTokenValidator().validate(
        "xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx"
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Slack auth response missing actor/team identifiers"


def test_slack_token_validator_team_only_response_stays_unconfirmed(monkeypatch):
    class _SlackClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def post(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://slack.com/api/auth.test"
            assert str(headers.get("Authorization") or "").startswith("Bearer ")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"ok": True, "team_id": "T9B2D6F4"}
            return response

    monkeypatch.setattr("httpx.Client", _SlackClient)
    result = SlackTokenValidator().validate(
        "xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx"
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Slack auth response missing actor/team identifiers"


def test_slack_token_validator_placeholder_ids_stay_unconfirmed(monkeypatch):
    class _SlackClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def post(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://slack.com/api/auth.test"
            assert str(headers.get("Authorization") or "").startswith("Bearer ")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "ok": True,
                "user_id": "unknown",
                "bot_id": "B000",
                "team_id": "T000",
            }
            return response

    monkeypatch.setattr("httpx.Client", _SlackClient)
    result = SlackTokenValidator().validate(
        "xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx"
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Slack auth response missing actor/team identifiers"


def test_slack_token_validator_repeated_letter_ids_stay_unconfirmed(monkeypatch):
    class _SlackClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def post(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://slack.com/api/auth.test"
            assert str(headers.get("Authorization") or "").startswith("Bearer ")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "ok": True,
                "user_id": "UAAAA",
                "bot_id": "BAAAA",
                "team_id": "TAAAA",
            }
            return response

    monkeypatch.setattr("httpx.Client", _SlackClient)
    result = SlackTokenValidator().validate(
        "xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx"
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Slack auth response missing actor/team identifiers"


def test_slack_token_validator_short_synthetic_ids_stay_unconfirmed(monkeypatch):
    class _SlackClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def post(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://slack.com/api/auth.test"
            assert str(headers.get("Authorization") or "").startswith("Bearer ")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "ok": True,
                "user_id": "U123",
                "team_id": "T123",
            }
            return response

    monkeypatch.setattr("httpx.Client", _SlackClient)
    result = SlackTokenValidator().validate(
        "xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx"
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Slack auth response missing actor/team identifiers"


def test_slack_token_validator_sequential_numeric_ids_stay_unconfirmed(monkeypatch):
    class _SlackClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def post(self, url: str, headers=None):  # noqa: ANN001
            assert url == "https://slack.com/api/auth.test"
            assert str(headers.get("Authorization") or "").startswith("Bearer ")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "ok": True,
                "user_id": "U1234567",
                "team_id": "T7654321",
            }
            return response

    monkeypatch.setattr("httpx.Client", _SlackClient)
    result = SlackTokenValidator().validate(
        "xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx"
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "Slack auth response missing actor/team identifiers"


# ---------------------------------------------------------------------------
# _store_key_finding
# ---------------------------------------------------------------------------

def _make_finding(pattern_name="aws_access_key_id", service="aws", key="AKIAIOSFODNN7EXAMPLE"):
    pat = KeyPattern(
        name=pattern_name,
        service=service,
        regex=re.compile("AKIA[0-9A-Z]{16}"),
        confidence="high",
        group=0,
        validation_method="AwsKeyValidator",
    )
    return {
        "pattern":    pat,
        "key_value":  key,
        "source_url": "https://github.com/org/repo/blob/main/config.py",
        "repo_name":  "org/repo",
        "file_path":  "config.py",
        "backend":    "github",
    }


def test_store_key_finding_inserts(engagement_db):
    con = sqlite3.connect(engagement_db)
    con.executescript("""
        CREATE TABLE key_scanner_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT, engagement_id INTEGER, domain TEXT,
            service TEXT, pattern_name TEXT, source_backend TEXT,
            source_url TEXT, repo_name TEXT, key_redacted TEXT, key_enc TEXT,
            validation_state TEXT DEFAULT 'UNCONFIRMED', validation_detail TEXT,
            found_at TEXT, validated_at TEXT,
            UNIQUE(engagement_id, source_url, pattern_name)
        );
    """)
    con.commit()

    finding = _make_finding()
    vresult = ValidationResult(state=ValidationState.ACTIVE, detail="AccountId: 742931608514")
    saved   = _store_key_finding(con, 1, "example.com", finding, vresult)
    assert saved is True

    row = con.execute(
        "SELECT validation_state, key_redacted FROM key_scanner_findings"
    ).fetchone()
    assert row[0] == "ACTIVE"
    assert "AKIA" in row[1]   # redacted contains prefix
    assert row[1] != "AKIAIOSFODNN7EXAMPLE"   # not full key
    con.close()


def test_store_key_finding_dedup(engagement_db):
    con = sqlite3.connect(engagement_db)
    con.executescript("""
        CREATE TABLE key_scanner_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT, engagement_id INTEGER, domain TEXT,
            service TEXT, pattern_name TEXT, source_backend TEXT,
            source_url TEXT, repo_name TEXT, key_redacted TEXT, key_enc TEXT,
            validation_state TEXT DEFAULT 'UNCONFIRMED', validation_detail TEXT,
            found_at TEXT, validated_at TEXT,
            UNIQUE(engagement_id, source_url, pattern_name)
        );
    """)
    con.commit()

    finding = _make_finding()
    vresult = ValidationResult(state=ValidationState.UNCONFIRMED)
    _store_key_finding(con, 1, "example.com", finding, vresult)
    saved2 = _store_key_finding(con, 1, "example.com", finding, vresult)
    assert saved2 is False

    count = con.execute("SELECT COUNT(*) FROM key_scanner_findings").fetchone()[0]
    assert count == 1
    con.close()


def test_store_key_finding_encrypted_key(engagement_db):
    """key_enc must not equal the raw key value."""
    con = sqlite3.connect(engagement_db)
    con.executescript("""
        CREATE TABLE key_scanner_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT, engagement_id INTEGER, domain TEXT,
            service TEXT, pattern_name TEXT, source_backend TEXT,
            source_url TEXT, repo_name TEXT, key_redacted TEXT, key_enc TEXT,
            validation_state TEXT DEFAULT 'UNCONFIRMED', validation_detail TEXT,
            found_at TEXT, validated_at TEXT,
            UNIQUE(engagement_id, source_url, pattern_name)
        );
    """)
    con.commit()

    finding = _make_finding()
    vresult = ValidationResult(state=ValidationState.ACTIVE)
    _store_key_finding(con, 1, "example.com", finding, vresult)

    row = con.execute("SELECT key_enc FROM key_scanner_findings").fetchone()
    assert row[0] != "AKIAIOSFODNN7EXAMPLE"   # must be encrypted
    con.close()


# ---------------------------------------------------------------------------
# run_key_scanner — scope + proxy enforcement
# ---------------------------------------------------------------------------

def test_run_key_scanner_requires_validation_proxy(engagement_db):
    with pytest.raises(RuntimeError, match="validation-proxy"):
        run_key_scanner(engagement_db, 1, "example.com", no_validate=False, validation_proxy=None)


def test_run_key_scanner_no_validate_skips_proxy_check(engagement_db):
    """--no-validate should not raise even without proxy."""
    with patch("forge.utils.intel.secret_finder.load_key_patterns", return_value=[]):
        with patch("forge.utils.intel.secret_finder.Session"):
            result = run_key_scanner(
                engagement_db, 1, "example.com",
                no_validate=True, validation_proxy=None, dry_run=False,
            )
    assert result == 0


def test_run_key_scanner_scope_violation(engagement_db):
    with pytest.raises((ValueError, RuntimeError)):
        run_key_scanner(
            engagement_db, 1, "outsidescope.com",
            no_validate=True, dry_run=False,
        )


def test_run_key_scanner_dry_run_zero(engagement_db, pattern_file, monkeypatch):
    monkeypatch.setattr(
        "forge.utils.intel.secret_finder.load_key_patterns",
        lambda *a, **kw: load_key_patterns(pattern_file),
    )
    result = run_key_scanner(
        engagement_db, 1, "example.com",
        no_validate=True, dry_run=True,
    )
    assert result == 0
