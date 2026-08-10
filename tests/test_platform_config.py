"""
tests/test_platform_config.py — Unit tests for PlatformSettings (autonomous platform config).

Validates:
  - Environment-variable-only configuration (Requirement 8.6)
  - Default values match design table (Requirement 13.5)
  - Validation of required fields and type coercion
  - No .env auto-loading
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from forge.config import ForgeConfig
from forge.config import PlatformSettings


class TestPlatformSettingsDefaults:
    """Verify all default values match the design configuration table."""

    def test_redis_url_defaults_to_none(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            # Remove any FORGE_REDIS_URL that might be set
            os.environ.pop("FORGE_REDIS_URL", None)
            settings = PlatformSettings()
            assert settings.redis_url is None

    def test_state_db_url_default(self) -> None:
        settings = PlatformSettings()
        assert (
            settings.state_db_url
            == "postgresql+asyncpg://forge:forge_dev_only@localhost:5433/forge"
        )

    def test_plugin_dir_default(self) -> None:
        settings = PlatformSettings()
        assert settings.plugin_dir == "./plugins"

    def test_llm_provider_default(self) -> None:
        # Isolate from operator .env — the test verifies the CODE default
        # regardless of what an operator has configured. `.env` has shipped
        # with FORGE_LLM_PROVIDER=auto since 2026-07-06.
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FORGE_LLM_PROVIDER", None)
            settings = PlatformSettings(_env_file=None)
        assert settings.llm_provider == "llama_cpp"

    def test_llm_model_path_defaults_to_none(self) -> None:
        settings = PlatformSettings()
        assert settings.llm_model_path is None

    def test_provider_timeout_default(self) -> None:
        settings = PlatformSettings()
        assert settings.provider_timeout == 5

    def test_heartbeat_interval_default(self) -> None:
        settings = PlatformSettings()
        assert settings.heartbeat_interval == 30

    def test_safe_mode_default(self) -> None:
        settings = PlatformSettings()
        assert settings.safe_mode == 0

    def test_scope_json_defaults_to_none(self) -> None:
        settings = PlatformSettings()
        assert settings.scope_json is None

    def test_governance_rules_defaults_to_none(self) -> None:
        settings = PlatformSettings()
        assert settings.governance_rules is None

    def test_audit_db_url_default(self) -> None:
        settings = PlatformSettings()
        assert (
            settings.audit_db_url
            == "postgresql+asyncpg://forge:forge_dev_only@localhost:5433/forge"
        )

    def test_telemetry_threshold_ms_default(self) -> None:
        settings = PlatformSettings()
        assert settings.telemetry_threshold_ms == 5000

    def test_message_retry_max_default(self) -> None:
        settings = PlatformSettings()
        assert settings.message_retry_max == 3

    def test_message_ack_timeout_default(self) -> None:
        settings = PlatformSettings()
        assert settings.message_ack_timeout == 60


class TestPlatformSettingsEnvOverrides:
    """Verify settings are correctly read from environment variables."""

    def test_redis_url_from_env(self) -> None:
        with patch.dict(os.environ, {"FORGE_REDIS_URL": "redis://localhost:6379/0"}):
            settings = PlatformSettings()
            assert settings.redis_url == "redis://localhost:6379/0"

    def test_state_db_url_from_env(self) -> None:
        with patch.dict(os.environ, {"FORGE_STATE_DB_URL": "postgresql://host/db"}):
            settings = PlatformSettings()
            assert settings.state_db_url == "postgresql://host/db"

    def test_plugin_dir_from_env(self) -> None:
        with patch.dict(os.environ, {"FORGE_PLUGIN_DIR": "/opt/forge/plugins"}):
            settings = PlatformSettings()
            assert settings.plugin_dir == "/opt/forge/plugins"

    def test_llm_provider_from_env(self) -> None:
        with patch.dict(os.environ, {"FORGE_LLM_PROVIDER": "ollama"}):
            settings = PlatformSettings()
            assert settings.llm_provider == "ollama"

    def test_llm_model_path_from_env(self) -> None:
        with patch.dict(os.environ, {"FORGE_LLM_MODEL_PATH": "/models/llama.gguf"}):
            settings = PlatformSettings()
            assert settings.llm_model_path == "/models/llama.gguf"

    def test_provider_timeout_from_env(self) -> None:
        with patch.dict(os.environ, {"FORGE_PROVIDER_TIMEOUT": "10"}):
            settings = PlatformSettings()
            assert settings.provider_timeout == 10

    def test_heartbeat_interval_from_env(self) -> None:
        with patch.dict(os.environ, {"FORGE_HEARTBEAT_INTERVAL": "15"}):
            settings = PlatformSettings()
            assert settings.heartbeat_interval == 15

    def test_safe_mode_from_env_numeric(self) -> None:
        with patch.dict(os.environ, {"FORGE_SAFE_MODE": "1"}):
            settings = PlatformSettings()
            assert settings.safe_mode == 1

    def test_safe_mode_from_env_string_true(self) -> None:
        with patch.dict(os.environ, {"FORGE_SAFE_MODE": "true"}):
            settings = PlatformSettings()
            assert settings.safe_mode == 1

    def test_safe_mode_from_env_string_yes(self) -> None:
        with patch.dict(os.environ, {"FORGE_SAFE_MODE": "yes"}):
            settings = PlatformSettings()
            assert settings.safe_mode == 1

    def test_safe_mode_from_env_string_on(self) -> None:
        with patch.dict(os.environ, {"FORGE_SAFE_MODE": "on"}):
            settings = PlatformSettings()
            assert settings.safe_mode == 1

    def test_scope_json_from_env(self) -> None:
        scope = '{"domains": ["example.com"], "ip_ranges": ["10.0.0.0/8"]}'
        with patch.dict(os.environ, {"FORGE_SCOPE_JSON": scope}):
            settings = PlatformSettings()
            assert settings.scope_json == scope

    def test_governance_rules_from_env(self) -> None:
        with patch.dict(os.environ, {"FORGE_GOVERNANCE_RULES": "/etc/forge/rules.yaml"}):
            settings = PlatformSettings()
            assert settings.governance_rules == "/etc/forge/rules.yaml"

    def test_audit_db_url_from_env(self) -> None:
        with patch.dict(os.environ, {"FORGE_AUDIT_DB_URL": "postgresql://host/audit"}):
            settings = PlatformSettings()
            assert settings.audit_db_url == "postgresql://host/audit"

    def test_telemetry_threshold_ms_from_env(self) -> None:
        with patch.dict(os.environ, {"FORGE_TELEMETRY_THRESHOLD_MS": "3000"}):
            settings = PlatformSettings()
            assert settings.telemetry_threshold_ms == 3000

    def test_message_retry_max_from_env(self) -> None:
        with patch.dict(os.environ, {"FORGE_MESSAGE_RETRY_MAX": "5"}):
            settings = PlatformSettings()
            assert settings.message_retry_max == 5

    def test_message_ack_timeout_from_env(self) -> None:
        with patch.dict(os.environ, {"FORGE_MESSAGE_ACK_TIMEOUT": "120"}):
            settings = PlatformSettings()
            assert settings.message_ack_timeout == 120


class TestPlatformSettingsValidation:
    """Verify validation logic for configuration values."""

    def test_provider_timeout_rejects_zero(self) -> None:
        with patch.dict(os.environ, {"FORGE_PROVIDER_TIMEOUT": "0"}):
            with pytest.raises(ValidationError):
                PlatformSettings()

    def test_provider_timeout_rejects_negative(self) -> None:
        with patch.dict(os.environ, {"FORGE_PROVIDER_TIMEOUT": "-1"}):
            with pytest.raises(ValidationError):
                PlatformSettings()

    def test_heartbeat_interval_rejects_zero(self) -> None:
        with patch.dict(os.environ, {"FORGE_HEARTBEAT_INTERVAL": "0"}):
            with pytest.raises(ValidationError):
                PlatformSettings()

    def test_message_retry_max_rejects_zero(self) -> None:
        with patch.dict(os.environ, {"FORGE_MESSAGE_RETRY_MAX": "0"}):
            with pytest.raises(ValidationError):
                PlatformSettings()

    def test_message_ack_timeout_rejects_negative(self) -> None:
        with patch.dict(os.environ, {"FORGE_MESSAGE_ACK_TIMEOUT": "-5"}):
            with pytest.raises(ValidationError):
                PlatformSettings()


class TestPlatformSettingsNoEnvFileLoading:
    """Verify that .env files are NOT auto-loaded (Requirement 8.6)."""

    def test_env_file_setting_is_none(self) -> None:
        """The model_config must explicitly disable .env loading."""
        assert PlatformSettings.model_config.get("env_file") is None

    def test_dotenv_not_loaded(self, tmp_path: pytest.TempPathFactory) -> None:
        """Even if a .env file exists in CWD, it must not be read."""
        env_file = tmp_path / ".env"  # type: ignore[operator]
        env_file.write_text("FORGE_LLM_PROVIDER=should_not_load\n")

        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)  # type: ignore[arg-type]
            # Isolate from the operator's inherited FORGE_LLM_PROVIDER (the
            # shipped .env has =auto; we're testing the CODE default here,
            # not what the operator has configured).
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("FORGE_LLM_PROVIDER", None)
                settings = PlatformSettings()
            # If .env was loaded, this would be "should_not_load"
            assert settings.llm_provider == "llama_cpp"
        finally:
            os.chdir(original_cwd)


class TestForgeConfigEnvCompatibility:
    """Verify runtime ForgeConfig compatibility aliases."""

    def test_shodan_api_key_env_is_preferred_over_legacy_name(self, tmp_path: Path) -> None:
        env = {
            "FORGE_DATA_DIR": str(tmp_path),
            "FORGE_SHODAN_API_KEY": "documented-key",
            "FORGE_SHODAN_KEY": "legacy-key",
        }
        with patch.dict(os.environ, env, clear=False):
            cfg = ForgeConfig.load()

        assert cfg.shodan_key == "documented-key"
