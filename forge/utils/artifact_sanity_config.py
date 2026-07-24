from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


_CONFIG_NAMES = {
    "sanity.cli.js",
    "sanity.cli.mjs",
    "sanity.cli.ts",
    "sanity.cli.cjs",
    "sanity.config.js",
    "sanity.config.mjs",
    "sanity.config.ts",
    "sanity.config.cjs",
    "sanity.config.json",
    "sanity.config.yaml",
    "sanity.config.yml",
    "sanity.json",
}
_PROJECT_ID_RE = re.compile(
    r"""(?ix)
    ["']?
    (?:project[_-]?id|projectId)
    ["']?
    \s*[:=]\s*
    ["'](?P<value>[a-z0-9][a-z0-9-]{2,63})["']
    """
)
_DATASET_RE = re.compile(
    r"""(?ix)
    ["']?
    dataset
    ["']?
    \s*[:=]\s*
    ["'](?P<value>[A-Za-z0-9_][A-Za-z0-9_-]{0,63})["']
    """
)
_PROJECT_ID_KEYS = {"projectid", "project_id", "project-id"}


def sanity_config_artifact_label(value: str | Path) -> str:
    name = Path(str(value or "").strip().replace("\\", "/")).name.lower()
    return "sanity-config" if name in _CONFIG_NAMES else ""


def sanity_config_urls(text: str, *, source_hint: str = "") -> list[str]:
    if not sanity_config_artifact_label(source_hint):
        return []
    project_ids = _project_ids(text)
    return [f"https://{project_id}.api.sanity.io" for project_id in project_ids]


def _project_ids(text: str) -> list[str]:
    raw_text = str(text or "")[:128 * 1024]
    ids: list[str] = []
    seen: set[str] = set()
    for value in _document_project_ids(raw_text):
        _append_project_id(ids, seen, value)
    for match in _PROJECT_ID_RE.finditer(raw_text):
        _append_project_id(ids, seen, match.group("value"))
    if not _datasets(raw_text):
        return []
    return ids


def _datasets(text: str) -> list[str]:
    datasets: list[str] = []
    for match in _DATASET_RE.finditer(str(text or "")[:128 * 1024]):
        value = str(match.group("value") or "").strip()
        if value and value not in datasets:
            datasets.append(value)
    return datasets


def _document_project_ids(text: str) -> list[str]:
    raw_text = str(text or "").strip()
    if not raw_text:
        return []
    parsed = _safe_json_loads(raw_text)
    if isinstance(parsed, (dict, list)):
        return _node_project_ids(parsed)
    if yaml is None:
        return []
    try:
        documents = list(yaml.safe_load_all(raw_text))
    except Exception:  # noqa: BLE001
        return []
    values: list[str] = []
    for document in documents:
        if isinstance(document, (dict, list)):
            values.extend(_node_project_ids(document))
    return values


def _node_project_ids(value: Any) -> list[str]:
    if isinstance(value, dict):
        values: list[str] = []
        for key, child in list(value.items())[:512]:
            if _key_fingerprint(str(key or "")) in _PROJECT_ID_KEYS and isinstance(child, (str, int, float)):
                values.append(str(child))
            values.extend(_node_project_ids(child))
        return values
    if isinstance(value, list):
        values: list[str] = []
        for child in value[:256]:
            values.extend(_node_project_ids(child))
        return values
    return []


def _append_project_id(ids: list[str], seen: set[str], value: object) -> None:
    project_id = str(value or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,63}", project_id):
        return
    if project_id in {"example", "exampleid", "projectid", "yourprojectid"}:
        return
    if project_id in seen:
        return
    seen.add(project_id)
    ids.append(project_id)


def _safe_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:  # noqa: BLE001
        return None


def _key_fingerprint(value: str) -> str:
    return re.sub(r"[^a-z0-9_-]+", "", str(value or "").strip().lower())
