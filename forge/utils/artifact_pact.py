from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlparse


PACT_PARENT_SEGMENTS = {"pact", "pacts", "pact-contracts", "consumer-pacts", "provider-pacts"}
GENERIC_EXTENSIONLESS_NAMES = {"dockerfile", "license", "makefile", "readme"}
PACT_CONTRACT_NAMES = {
    "pact.json",
    "pact.yaml",
    "pact.yml",
    "pacts.json",
    "pacts.yaml",
    "pacts.yml",
    "pact-contract.json",
    "pact-contract.yaml",
    "pact-contract.yml",
}
PACT_SUFFIXES = (".pact.json", ".pact.yaml", ".pact.yml")


def pact_contract_artifact_label(value: str) -> str:
    normalized = str(value or "").strip().replace("\\", "/").strip("/").lower()
    if not normalized:
        return ""
    parts = tuple(part for part in normalized.split("/") if part)
    name = Path(normalized).name
    if not name:
        return ""
    if name in PACT_CONTRACT_NAMES or name.endswith(PACT_SUFFIXES):
        return "pact-contract"
    if len(parts) >= 2 and set(parts[:-1]) & PACT_PARENT_SEGMENTS:
        stem = _stem_without_config_suffix(name)
        if name.endswith((".json", ".yaml", ".yml")) and _looks_like_pact_contract_stem(stem):
            return "pact-contract"
        if "." not in name and _looks_like_pact_contract_stem(name):
            return "pact-contract"
    stem = _stem_without_config_suffix(name)
    if (
        _has_token(stem, "pact")
        and _has_token(stem, "contract")
        and name.endswith((".json", ".yaml", ".yml"))
    ):
        return "pact-contract"
    if _has_token(stem, "pact") and _has_token(stem, "contract"):
        return "pact-contract"
    return ""


def pact_contract_remote_filename(source_path: str, content_suffix: str = "") -> str:
    candidate = Path(str(source_path or "").replace("\\", "/")).name.strip() or "pact-contract"
    suffix = Path(candidate).suffix.lower()
    if suffix in {".json", ".yaml", ".yml"} and pact_contract_artifact_label(candidate):
        return candidate
    if suffix in {".json", ".yaml", ".yml"}:
        return f"{Path(candidate).stem}.pact{suffix}"
    if content_suffix in {".pact.json", ".json", ".yaml", ".yml"}:
        return f"{candidate}.pact{'.json' if content_suffix in {'.pact.json', '.json'} else content_suffix}"
    return f"{candidate}.pact.json"


def pact_contract_candidate_values(
    document: Any,
    text: str,
    *,
    normalize_url: Callable[[str], str],
    document_values: Callable[[Any], list[str]],
    fallback_values: Callable[[str], list[str]],
    is_urlish_key: Callable[[str], bool],
) -> list[str]:
    values = _pact_document_values(
        document, normalize_url=normalize_url, is_urlish_key=is_urlish_key
    )
    for value in [*document_values(document), *fallback_values(text)]:
        if value not in values:
            values.append(value)
    return values[:512]


def _pact_document_values(
    document: Any,
    *,
    normalize_url: Callable[[str], str],
    is_urlish_key: Callable[[str], bool],
) -> list[str]:
    base_values = _pact_base_values(document)
    normalized_bases = [normalized for normalized in map(normalize_url, base_values) if normalized]
    base_url = normalized_bases[0] if normalized_bases else ""
    values = list(base_values)
    for interaction in _pact_interaction_sources(document):
        for value in _pact_interaction_values(
            interaction, base_url=base_url, is_urlish_key=is_urlish_key
        ):
            if value not in values:
                values.append(value)
    return values[:512]


def _pact_interaction_sources(document: Any) -> list[Any]:
    if isinstance(document, dict):
        sources: list[Any] = []
        for key in ("interactions", "messages"):
            value = document.get(key)
            if isinstance(value, list):
                sources.extend(value[:512])
        return sources
    return list(document[:512]) if isinstance(document, list) else []


def _pact_base_values(document: Any) -> list[str]:
    values: list[str] = []

    def append(value: Any) -> None:
        if isinstance(value, (str, int, float)):
            candidate = str(value).strip().strip("\"'")
            if candidate and candidate not in values:
                values.append(candidate)

    def get(mapping: dict[str, Any], *keys: str) -> str:
        normalized = {_key(key): value for key, value in mapping.items()}
        for key in keys:
            value = normalized.get(_key(key))
            if isinstance(value, (str, int, float)) and str(value).strip():
                return str(value).strip()
        return ""

    def append_mapping(mapping: dict[str, Any]) -> None:
        append(
            get(
                mapping,
                "providerBaseUrl",
                "providerUrl",
                "baseUrl",
                "baseURL",
                "base_url",
                "endpoint",
                "url",
                "uri",
                "host",
                "hostname",
            )
        )

    if isinstance(document, dict):
        append_mapping(document)
        if isinstance(document.get("provider"), dict):
            append_mapping(document["provider"])
        if isinstance(document.get("metadata"), dict):
            append(get(document["metadata"], "pactBrokerUrl", "pact_broker_url"))
    elif isinstance(document, list):
        for item in document[:128]:
            if isinstance(item, dict):
                for value in _pact_base_values(item):
                    append(value)
    return values[:128]


def _pact_interaction_values(
    value: Any, *, base_url: str, is_urlish_key: Callable[[str], bool]
) -> list[str]:
    values: list[str] = []

    def append(candidate: str) -> None:
        raw_candidate = str(candidate or "").strip().strip("\"'")
        if raw_candidate and raw_candidate not in values:
            values.append(raw_candidate)

    def request_target(candidate: Any) -> str:
        if not isinstance(candidate, (str, int, float)):
            return ""
        raw_candidate = str(candidate).strip().strip("\"'")
        if not raw_candidate or re.search(r"\s", raw_candidate):
            return ""
        if any(marker in raw_candidate for marker in ("{", "}", "${", "$(", "{{", "}}", "<", ">")):
            return raw_candidate
        lowered = raw_candidate.lower()
        if lowered.startswith(("http://", "https://", "ws://", "wss://")):
            return raw_candidate
        if raw_candidate.startswith("//"):
            parsed = urlparse(f"https:{raw_candidate}")
            return f"https:{raw_candidate}" if "." in str(parsed.hostname or "") else ""
        if raw_candidate.startswith(("/", "./", "../")) and base_url:
            return urljoin(base_url.rstrip("/") + "/", raw_candidate)
        return raw_candidate if _looks_hostish(raw_candidate) else ""

    def walk(child: Any, depth: int = 0) -> None:
        if len(values) >= 512:
            return
        if depth > 24:
            return
        if isinstance(child, dict):
            normalized = {_key(key): value for key, value in child.items()}
            request = normalized.get("request")
            if isinstance(request, dict):
                request_normalized = {_key(key): value for key, value in request.items()}
                for key in ("url", "uri", "path", "target"):
                    target = request_target(request_normalized.get(_key(key)))
                    if target:
                        append(target)
            for key, item in child.items():
                key_name = str(key or "")
                if _key(key_name) in {"url", "uri", "baseurl", "baseuri", "endpoint", "target"} or (
                    is_urlish_key(key_name) and isinstance(item, (str, int, float))
                ):
                    target = request_target(item)
                    if target:
                        append(target)
                walk(item, depth + 1)
        elif isinstance(child, list):
            for item in child[:512]:
                walk(item, depth + 1)

    walk(value)
    return values[:512]


def _key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())


def _tokens(value: str) -> set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", str(value or "").strip().lower()) if token}


def _has_token(value: str, token: str) -> bool:
    return str(token or "").strip().lower() in _tokens(value)


def _stem_without_config_suffix(name: str) -> str:
    stem = str(name or "").strip().lower()
    for suffix in (".json", ".toml", ".yaml", ".yml"):
        if stem.endswith(suffix):
            return stem[: -len(suffix)]
    return stem


def _looks_like_pact_contract_stem(value: str) -> bool:
    stem = str(value or "").strip().lower()
    if not stem or stem in GENERIC_EXTENSIONLESS_NAMES:
        return False
    tokens = _tokens(stem)
    if _has_token(stem, "pact") and len(tokens) >= 2:
        return True
    return len(tokens) >= 2 and bool(re.search(r"[-_]", stem))


def _looks_hostish(value: str) -> bool:
    text = str(value or "").strip()
    return (
        bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{1,253}(?::\d{1,5})?(?:/[^\s?#]*)?", text))
        and "." in text
    )
