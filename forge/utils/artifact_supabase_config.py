from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any


_REF_KEYS = {"project_id", "project_ref", "projectid", "projectref", "ref"}
_REF_RE = re.compile(r"^[a-z0-9][a-z0-9-]{3,63}$")
_KV_RE = re.compile(
    r"""(?im)^\s*(?P<key>project[_-]?(?:id|ref)|ref)\s*=\s*["']?(?P<value>[a-zA-Z0-9-]{4,64})["']?"""
)


def supabase_cli_config_artifact_label(value: str | Path) -> str:
    parts = [
        part.lower()
        for part in str(value or "").strip().replace("\\", "/").strip("/").split("/")
        if part
    ]
    for index in range(len(parts) - 1):
        if parts[index : index + 2] == ["supabase", "config.toml"]:
            return "supabase-config"
    return ""


def supabase_cli_config_urls(text: str, *, source_hint: str = "") -> list[str]:
    if not supabase_cli_config_artifact_label(source_hint):
        return []
    refs = _project_refs(text)
    return [f"https://{ref}.supabase.co" for ref in refs]


def _project_refs(text: str) -> list[str]:
    refs: list[str] = []
    seen: set[str] = set()

    parsed = _parse_toml(text)
    if isinstance(parsed, dict):
        for value in _document_ref_values(parsed):
            _append_ref(refs, seen, value)

    for match in _KV_RE.finditer(str(text or "")[:128 * 1024]):
        _append_ref(refs, seen, match.group("value"))
    return refs


def _parse_toml(text: str) -> Any:
    try:
        return tomllib.loads(str(text or ""))
    except Exception:  # noqa: BLE001
        return None


def _document_ref_values(value: Any) -> list[str]:
    if isinstance(value, dict):
        values: list[str] = []
        for key, child in list(value.items())[:512]:
            normalized_key = _key_fingerprint(str(key or ""))
            if normalized_key in _REF_KEYS and isinstance(child, (str, int, float)):
                values.append(str(child))
            values.extend(_document_ref_values(child))
        return values
    if isinstance(value, list):
        values: list[str] = []
        for child in value[:256]:
            values.extend(_document_ref_values(child))
        return values
    return []


def _append_ref(refs: list[str], seen: set[str], value: object) -> None:
    ref = str(value or "").strip().strip("\"'").lower()
    if not _REF_RE.fullmatch(ref):
        return
    if ref in {"example-project", "local-project", "project-id", "project-ref"}:
        return
    if ref in seen:
        return
    seen.add(ref)
    refs.append(ref)


def _key_fingerprint(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())
