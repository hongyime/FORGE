from __future__ import annotations

from collections.abc import Iterable, Mapping
import re
from typing import Any

from forge.utils.cloud_exposure_gate import normalize_cloud_exposure_asset_type
from forge.utils.validation_proof import parse_validated_detail

BOT_TOKEN_PROVIDERS = frozenset({"discord", "slack", "telegram"})
BOT_TOKEN_METHOD_PROVIDERS = {
    "discord_current_user": "discord",
    "slack_auth_test": "slack",
    "telegram_get_me": "telegram",
}


def _normalized_service(value: str) -> str:
    return normalize_cloud_exposure_asset_type(str(value or "").strip().lower())


def _proof_text(validation_detail: object) -> str:
    proof = parse_validated_detail(validation_detail, include_raw_proof=True)
    return str(
        proof.get("validation_proof")
        or proof.get("validation_raw_proof")
        or validation_detail
        or ""
    )


def key_validation_bot_provider(service: str, validation_detail: object = "") -> str:
    normalized_service = _normalized_service(service)
    if normalized_service in BOT_TOKEN_PROVIDERS:
        return normalized_service
    proof = parse_validated_detail(validation_detail, include_raw_proof=True)
    method = str(proof.get("validation_method") or "").strip().lower()
    return BOT_TOKEN_METHOD_PROVIDERS.get(method, "")


def key_validation_requires_linked_result(service: str, validation_detail: object = "") -> bool:
    return bool(key_validation_bot_provider(service, validation_detail))


def key_validation_detail_is_reportable(service: str, validation_detail: object) -> bool:
    if key_validation_requires_linked_result(service, validation_detail):
        return False
    proof = parse_validated_detail(validation_detail)
    return str(proof["validation_status"] or "").strip().upper() == "VALIDATED"


def _bot_proof_identifier(provider: str, validation_detail: object) -> str:
    proof = _proof_text(validation_detail)
    if provider == "slack":
        actor_match = re.search(
            r"\b(?:actor_id|user_id|bot_id)=([A-Z0-9]+)\b", proof, re.IGNORECASE
        )
        team_match = re.search(r"\bteam_id=([A-Z0-9]+)\b", proof, re.IGNORECASE)
        actor = str(actor_match.group(1) if actor_match else "").strip().upper()
        team = str(team_match.group(1) if team_match else "").strip().upper()
        if re.fullmatch(r"[UWB][A-Z0-9]{4,32}", actor) and re.fullmatch(
            r"[TE][A-Z0-9]{4,32}",
            team,
        ):
            return f"{team}/{actor}".lower()
        return ""
    limits = {"discord": (15, 22), "telegram": (6, 20)}.get(provider)
    if not limits:
        return ""
    min_len, max_len = limits
    match = re.search(r"\bbot_id=([0-9]+)\b", proof, re.IGNORECASE)
    if not match:
        return ""
    value = match.group(1)
    return value if min_len <= len(value) <= max_len else ""


def _candidate_values(*values: object) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        normalized = str(value or "").strip().lower()
        if normalized and normalized not in seen:
            seen.add(normalized)
            ordered.append(normalized)
    return tuple(ordered)


def key_validation_candidate_identifiers(
    identifier: object,
    validation_detail: object = "",
    *,
    service: str = "",
) -> tuple[str, ...]:
    provider = key_validation_bot_provider(service, validation_detail)
    return _candidate_values(identifier, _bot_proof_identifier(provider, validation_detail))


def key_validation_candidate_asset_types(
    service: str,
    validation_detail: object = "",
    *,
    aliases: Iterable[str] = (),
) -> tuple[str, ...]:
    provider = key_validation_bot_provider(service, validation_detail)
    return _candidate_values(
        _normalized_service(service),
        *(_normalized_service(alias) for alias in aliases),
        provider,
    )


def linked_key_validation_reportability(
    validation_index: Mapping[tuple[str, str], Any],
    service: str,
    identifier: object,
    validation_detail: object = "",
    *,
    asset_aliases: Iterable[str] = (),
) -> bool | None:
    matches: list[bool] = []
    for asset_type in key_validation_candidate_asset_types(
        service,
        validation_detail,
        aliases=asset_aliases,
    ):
        for candidate in key_validation_candidate_identifiers(
            identifier,
            validation_detail,
            service=asset_type,
        ):
            if (asset_type, candidate) not in validation_index:
                continue
            value = validation_index[(asset_type, candidate)]
            matches.append(value is True or str(value or "").strip().upper() == "VALIDATED")
    if not matches:
        return None
    return any(matches)
