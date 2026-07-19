from __future__ import annotations

from forge.phase4 import cloud_validate


def test_telegram_secret_bound_identifier_uses_token_prefix() -> None:
    assert (
        cloud_validate._secret_bound_validation_identifier("telegram", "725419863:" + "T" * 35)
        == "725419863"
    )
    assert cloud_validate._secret_bound_validation_identifier("telegram", "bad-token") is None


def test_telegram_active_proof_must_match_token_prefix(monkeypatch) -> None:
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        TelegramBotTokenValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        TelegramBotTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Telegram bot auth ok: bot_id=925419863 bot_profile_present=true",
        ),
    )

    result = cloud_validate._validate_existing_key_service(
        "telegram",
        {
            "pattern_name": "telegram_bot_token",
            "source_url": "",
            "repo_name": "bot.env",
            "domain": "",
        },
        secret="725419863:" + "T" * 35,
    )

    assert result is not None
    assert result.validation_status == "UNVERIFIED"
    assert result.identifier == "725419863"
    assert "did not match" in result.notes
