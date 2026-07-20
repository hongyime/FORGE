from __future__ import annotations

import base64

from forge.phase4 import cloud_validate


def _discord_token_for_bot_id(bot_id: str) -> str:
    token_prefix = base64.urlsafe_b64encode(bot_id.encode("ascii")).decode("ascii").rstrip("=")
    return f"{token_prefix}.AAAAAA.{'B' * 27}"


def test_discord_secret_bound_identifier_uses_token_prefix() -> None:
    assert (
        cloud_validate._secret_bound_validation_identifier(
            "discord",
            _discord_token_for_bot_id("739251864203918576"),
        )
        == "739251864203918576"
    )
    assert cloud_validate._secret_bound_validation_identifier("discord", "bad-token") is None


def test_discord_active_proof_must_match_token_prefix(monkeypatch) -> None:
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        DiscordBotTokenValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        DiscordBotTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Discord bot auth ok: bot_id=135792468013579246 bot_profile_present=true",
        ),
    )

    result = cloud_validate._validate_existing_key_service(
        "discord",
        {
            "pattern_name": "discord_bot_token",
            "source_url": "",
            "repo_name": "chat.env",
            "domain": "",
        },
        secret=_discord_token_for_bot_id("739251864203918576"),
    )

    assert result is not None
    assert result.validation_status == "UNVERIFIED"
    assert result.identifier == "739251864203918576"
    assert "did not match" in result.notes


def test_discord_active_proof_requires_token_prefix_binding(monkeypatch) -> None:
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        DiscordBotTokenValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        DiscordBotTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Discord bot auth ok: bot_id=135792468013579246 bot_profile_present=true",
        ),
    )

    result = cloud_validate._validate_existing_key_service(
        "discord",
        {
            "pattern_name": "discord_bot_token",
            "source_url": "",
            "repo_name": "chat.env",
            "domain": "",
        },
        secret="M" * 24 + "." + "A" * 6 + "." + "B" * 27,
    )

    assert result is not None
    assert result.validation_status == "UNVERIFIED"
    assert result.identifier == "chat.env"
    assert "not bound" in result.notes
