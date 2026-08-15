from __future__ import annotations

import json
import re
import sqlite3
import uuid
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from forge.utils.artifact_url_sanitizer import strip_sensitive_url_query

_STIX_DEFAULT_TIMESTAMP = "1970-01-01T00:00:00.000Z"

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
_ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_CPE_RE = re.compile(r"cpe:2\.3:[A-Za-z0-9_.*~!@$%^&()+={}\[\]|:;,.<>/?`#-]+", re.IGNORECASE)
_CVSS_VECTOR_RE = re.compile(r"^CVSS:(?P<version>\d+(?:\.\d+)?)/", re.IGNORECASE)
_SENSITIVE_FRAGMENT_RE = re.compile(
    r"(?i)(access[_-]?token|api[_-]?key|secret|password|signature|credential|session|authorization)"
)
_CVSS_VERSION_RANK = {"4.0": 0, "3.1": 1, "3.0": 2, "3.x": 3, "2.0": 4}
_CVSS_VARIANT_KEYS = (
    ("4.0", ("cvss_v4", "cvss4", "cvss40", "cvss_v40")),
    ("3.1", ("cvss_v31", "cvss31")),
    ("3.0", ("cvss_v30", "cvss30")),
    ("3.x", ("cvss_v3", "cvss3")),
    ("2.0", ("cvss_v2", "cvss2")),
)
_CVSS_V4_METRIC_ORDER = (
    "AV",
    "AC",
    "AT",
    "PR",
    "UI",
    "VC",
    "VI",
    "VA",
    "SC",
    "SI",
    "SA",
    "E",
    "CR",
    "IR",
    "AR",
    "MAV",
    "MAC",
    "MAT",
    "MPR",
    "MUI",
    "MVC",
    "MVI",
    "MVA",
    "MSC",
    "MSI",
    "MSA",
    "S",
    "AU",
    "R",
    "V",
    "RE",
    "U",
)
_CVSS_V4_REQUIRED_BASE_METRICS = set(_CVSS_V4_METRIC_ORDER[:11])


def _row_value(row: sqlite3.Row | Mapping[str, Any], key: str, default: Any = None) -> Any:
    if isinstance(row, sqlite3.Row):
        return row[key] if key in row.keys() else default
    return row.get(key, default)


def _json_loads(value: object) -> Any:
    if isinstance(value, (dict, list)):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _safe_exchange_url(value: object, *, limit: int = 500) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    sanitized = strip_sensitive_url_query(text)
    parsed = urlparse(sanitized)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        host = str(parsed.hostname or "").strip()
        if host:
            safe_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
            try:
                port = parsed.port
            except ValueError:
                port = None
            safe_netloc = f"{safe_host}:{port}" if port is not None else safe_host
            fragment = parsed.fragment
            if fragment and _SENSITIVE_FRAGMENT_RE.search(fragment):
                fragment = ""
            sanitized = parsed._replace(netloc=safe_netloc, fragment=fragment).geturl()
    return sanitized[:limit]


def _list_from_value(value: object) -> list[str]:
    parsed = _json_loads(value)
    if isinstance(parsed, list):
        raw_items = parsed
    elif isinstance(parsed, dict):
        raw_items = parsed.values()
    else:
        raw_items = re.split(r"[,;\s]+", _as_text(value))
    out: list[str] = []
    seen: set[str] = set()
    for item in raw_items:
        text = str(item or "").strip()
        if not text:
            continue
        if text not in seen:
            out.append(text)
            seen.add(text)
    return out


def _extract_ordered(pattern: re.Pattern[str], *values: object, transform=str.upper) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        for match in pattern.findall(_as_text(value)):
            text = transform(str(match).strip())
            if text and text not in seen:
                out.append(text)
                seen.add(text)
    return out


def _float_or_none(value: object) -> float | None:
    if value in (None, ""):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number


def _boolish(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "kev"}


def _row_mapping(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(row, sqlite3.Row):
        return {key: row[key] for key in row.keys()}
    return dict(row)


def _mapping_lookup(mapping: Mapping[str, Any], *keys: str) -> Any:
    lowered = {str(key).lower(): value for key, value in mapping.items()}
    for key in keys:
        lowered_key = key.lower()
        if lowered_key in lowered:
            return lowered[lowered_key]
    return None


def _normalize_cvss_version(value: object, vector: object = "") -> str:
    vector_text = str(vector or "").strip()
    match = _CVSS_VECTOR_RE.match(vector_text)
    if match:
        return match.group("version")
    text = str(value or "").strip()
    if not text:
        return ""
    text = text.removeprefix("CVSS:").lstrip("vV")
    lowered = text.lower()
    if lowered in {"4", "4.0", "40", "v4", "v4.0"}:
        return "4.0"
    if lowered in {"3.1", "31", "v3.1"}:
        return "3.1"
    if lowered in {"3.0", "30", "v3.0"}:
        return "3.0"
    if lowered in {"3", "3.x", "v3", "v3.x"}:
        return "3.x"
    if lowered in {"2", "2.0", "20", "v2", "v2.0"}:
        return "2.0"
    return text


def _cvss_version_rank(value: object) -> int:
    return _CVSS_VERSION_RANK.get(_normalize_cvss_version(value), 99)


def _cvss_v4_vector_status(vector: object) -> dict[str, Any]:
    text = str(vector or "").strip()
    if not text:
        return {"valid": False, "reason": "missing_vector"}
    if not text.upper().startswith("CVSS:4.0/"):
        return {"valid": False, "reason": "not_cvss_4_0_vector"}

    order = {metric: index for index, metric in enumerate(_CVSS_V4_METRIC_ORDER)}
    metrics: list[str] = []
    invalid_tokens: list[str] = []
    for token in text.split("/")[1:]:
        if ":" not in token:
            invalid_tokens.append(token)
            continue
        metric = token.split(":", 1)[0]
        metrics.append(metric)

    duplicates = sorted({metric for metric in metrics if metrics.count(metric) > 1})
    unknown = [metric for metric in metrics if metric not in order]
    positions = [order[metric] for metric in metrics if metric in order]
    ordered = positions == sorted(positions)
    missing = [
        metric
        for metric in _CVSS_V4_METRIC_ORDER[:11]
        if metric not in set(metrics)
    ]
    valid = not (missing or duplicates or unknown or invalid_tokens) and ordered
    metric_groups = ["base"]
    if any(metric == "E" for metric in metrics):
        metric_groups.append("threat")
    if any(metric in set(_CVSS_V4_METRIC_ORDER[12:26]) for metric in metrics):
        metric_groups.append("environmental")
    if any(metric in set(_CVSS_V4_METRIC_ORDER[26:]) for metric in metrics):
        metric_groups.append("supplemental")
    status: dict[str, Any] = {
        "valid": valid,
        "ordered": ordered,
        "metric_groups": metric_groups,
    }
    if missing:
        status["missing_base_metrics"] = missing
    if duplicates:
        status["duplicate_metrics"] = duplicates
    if unknown:
        status["unknown_metrics"] = unknown
    if invalid_tokens:
        status["invalid_tokens"] = invalid_tokens
    return status


def _cvss_candidate(
    *,
    score: object,
    version: object = "",
    vector: object = "",
    source: str,
) -> dict[str, Any] | None:
    score_value = _float_or_none(score)
    if score_value is not None and not 0.0 <= score_value <= 10.0:
        score_value = None
    vector_text = str(vector or "").strip()
    normalized_version = _normalize_cvss_version(version, vector_text)
    if score_value is None and not vector_text:
        return None
    candidate: dict[str, Any] = {
        "version": normalized_version,
        "source": source,
    }
    if score_value is not None:
        candidate["score"] = score_value
    if vector_text:
        candidate["vector"] = vector_text
    if normalized_version == "4.0":
        vector_status = _cvss_v4_vector_status(vector_text)
        candidate["vector_status"] = vector_status
        metric_groups = set(vector_status.get("metric_groups") or [])
        if {"threat", "environmental"} <= metric_groups:
            candidate["nomenclature"] = "CVSS-BTE"
        elif "environmental" in metric_groups:
            candidate["nomenclature"] = "CVSS-BE"
        elif "threat" in metric_groups:
            candidate["nomenclature"] = "CVSS-BT"
        else:
            candidate["nomenclature"] = "CVSS-B"
    return candidate


def _cvss_candidates_from_mapping(
    mapping: Mapping[str, Any],
    *,
    source: str,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    nested = _mapping_lookup(mapping, "cvss")
    if isinstance(nested, Mapping):
        candidate = _cvss_candidate(
            score=_mapping_lookup(nested, "score", "base_score"),
            version=_mapping_lookup(nested, "version"),
            vector=_mapping_lookup(nested, "vector", "vector_string"),
            source=source,
        )
        if candidate:
            candidates.append(candidate)

    candidate = _cvss_candidate(
        score=_mapping_lookup(mapping, "cvss_score", "base_score"),
        version=_mapping_lookup(mapping, "cvss_version"),
        vector=_mapping_lookup(mapping, "cvss_vector", "vector", "vector_string"),
        source=source,
    )
    if candidate:
        candidates.append(candidate)

    for version, prefixes in _CVSS_VARIANT_KEYS:
        for prefix in prefixes:
            payload = _mapping_lookup(mapping, prefix)
            candidate = None
            if isinstance(payload, Mapping):
                candidate = _cvss_candidate(
                    score=_mapping_lookup(payload, "score", "base_score"),
                    version=_mapping_lookup(payload, "version") or version,
                    vector=_mapping_lookup(payload, "vector", "vector_string"),
                    source=source,
                )
            elif payload is not None:
                text = str(payload or "").strip()
                candidate = _cvss_candidate(
                    score=None if text.upper().startswith("CVSS:") else payload,
                    version=version,
                    vector=text if text.upper().startswith("CVSS:") else "",
                    source=source,
                )
            if candidate:
                candidates.append(candidate)

            candidate = _cvss_candidate(
                score=_mapping_lookup(
                    mapping,
                    f"{prefix}_score",
                    f"{prefix}_base_score",
                    f"{prefix}_base",
                ),
                version=version,
                vector=_mapping_lookup(
                    mapping,
                    f"{prefix}_vector",
                    f"{prefix}_vector_string",
                ),
                source=source,
            )
            if candidate:
                candidates.append(candidate)
    return candidates


def _dedupe_cvss_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for candidate in candidates:
        key = (
            str(candidate.get("version") or ""),
            str(candidate.get("score") or ""),
            str(candidate.get("vector") or ""),
        )
        if key in seen:
            continue
        out.append(candidate)
        seen.add(key)
    return out


def _cvss_metadata(
    row: sqlite3.Row | Mapping[str, Any],
    seed: Mapping[str, Any],
    cve_meta: Mapping[str, Any],
    stix_meta: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    candidates: list[dict[str, Any]] = []
    for source_name, source_mapping in (
        ("finding", _row_mapping(row)),
        ("standards_json", seed),
        ("local_kb", cve_meta),
        ("local_stix", stix_meta or {}),
    ):
        candidates.extend(
            _cvss_candidates_from_mapping(source_mapping, source=source_name)
        )
    candidates = _dedupe_cvss_candidates(candidates)
    candidates.sort(
        key=lambda item: (
            _cvss_version_rank(item.get("version")),
            0 if item.get("source") == "finding" else 1 if item.get("source") == "standards_json" else 2,
        )
    )
    if not candidates:
        return None, []
    return candidates[0], candidates[1:]


def _metadata_seed(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    parsed = _json_loads(_row_value(row, "standards_json"))
    return dict(parsed) if isinstance(parsed, dict) else {}


def _ordered_unique(items: list[str], *, transform=str.upper, limit: int = 50) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        text = transform(str(item or "").strip())
        if not text or text in seen:
            continue
        out.append(text)
        seen.add(text)
        if len(out) >= limit:
            break
    return out


def _external_refs(
    *,
    cve_ids: list[str],
    cwe_ids: list[str],
    cpe_matches: list[str],
    attack_techniques: list[str],
    existing: object,
) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    parsed = _json_loads(existing)
    if isinstance(parsed, list):
        for item in parsed:
            if not isinstance(item, Mapping):
                continue
            source = str(item.get("source_name") or item.get("source") or "").strip()
            external_id = str(item.get("external_id") or item.get("id") or "").strip()
            url = _safe_exchange_url(item.get("url"))
            if source and external_id:
                ref = {"source_name": source, "external_id": external_id}
                if url:
                    ref["url"] = url
                refs.append(ref)
    refs.extend({"source_name": "cve", "external_id": cve_id} for cve_id in cve_ids)
    refs.extend({"source_name": "cwe", "external_id": cwe_id} for cwe_id in cwe_ids)
    refs.extend({"source_name": "cpe", "external_id": cpe} for cpe in cpe_matches[:10])
    refs.extend(
        {"source_name": "mitre-attack", "external_id": technique}
        for technique in attack_techniques
    )
    deduped: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for ref in refs:
        key = (ref["source_name"].lower(), ref["external_id"].upper())
        if key in seen:
            continue
        deduped.append(ref)
        seen.add(key)
    return deduped


def _merge_ref_inputs(*values: object) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    for value in values:
        parsed = _json_loads(value)
        if not isinstance(parsed, list):
            continue
        for item in parsed:
            if not isinstance(item, Mapping):
                continue
            source_name = str(item.get("source_name") or item.get("source") or "").strip()
            external_id = str(item.get("external_id") or item.get("id") or "").strip()
            if not source_name or not external_id:
                continue
            ref = {"source_name": source_name, "external_id": external_id}
            url = _safe_exchange_url(item.get("url"))
            if url:
                ref["url"] = url
            refs.append(ref)
    return refs


def _stix_external_references(standards: Mapping[str, Any]) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    for item in standards.get("stix_external_refs", []):
        if not isinstance(item, Mapping):
            continue
        source_name = str(item.get("source_name") or "").strip().lower()
        external_id = str(item.get("external_id") or "").strip()
        if not source_name or not external_id:
            continue
        ref = {"source_name": source_name, "external_id": external_id}
        url = _safe_exchange_url(item.get("url")) or _standard_ref_url(source_name, external_id)
        if url:
            ref["url"] = url
        refs.append(ref)
    return refs


def _standard_ref_url(source_name: str, external_id: str) -> str:
    source = source_name.lower()
    external = external_id.upper()
    if source == "cve" and _CVE_RE.fullmatch(external):
        return f"https://nvd.nist.gov/vuln/detail/{external}"
    if source == "cwe" and _CWE_RE.fullmatch(external):
        return f"https://cwe.mitre.org/data/definitions/{external.removeprefix('CWE-')}.html"
    if source == "mitre-attack" and _ATTACK_RE.fullmatch(external):
        return f"https://attack.mitre.org/techniques/{external.replace('.', '/')}/"
    return ""


def _stix_id(object_type: str, seed: str) -> str:
    return f"{object_type}--{uuid.uuid5(uuid.NAMESPACE_URL, seed)}"


def _stix_timestamp(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return _STIX_DEFAULT_TIMESTAMP
    normalized = text.replace(" ", "T", 1)
    if normalized.endswith("Z"):
        return normalized
    if "+" in normalized[10:] or normalized.endswith(("-00:00", "+00:00")):
        return normalized
    return f"{normalized.rstrip('Z')}Z"


def _clip_stix_text(value: str, *, limit: int = 4096) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3]}..."


def _merge_unique_text(
    existing: list[str],
    additions: object,
    *,
    transform=str.upper,
    limit: int = 50,
) -> list[str]:
    merged = list(existing)
    seen = {str(item) for item in merged}
    for item in _list_from_value(additions):
        text = transform(str(item or "").strip())
        if not text or text in seen:
            continue
        merged.append(text)
        seen.add(text)
        if len(merged) >= limit:
            break
    return merged


def _merge_stix_metadata(existing: dict[str, Any], incoming: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    merged["cve_ids"] = _merge_unique_text(
        list(merged.get("cve_ids") or []),
        incoming.get("cve_ids"),
    )
    merged["cwe_ids"] = _merge_unique_text(
        list(merged.get("cwe_ids") or []),
        incoming.get("cwe_ids"),
        limit=25,
    )
    merged["cpe_matches"] = _merge_unique_text(
        list(merged.get("cpe_matches") or []),
        incoming.get("cpe_matches"),
        transform=str,
    )
    merged["attack_techniques"] = _merge_unique_text(
        list(merged.get("attack_techniques") or []),
        incoming.get("attack_techniques"),
        limit=25,
    )
    merged["stix_external_refs"] = _external_refs(
        cve_ids=list(merged.get("cve_ids") or []),
        cwe_ids=list(merged.get("cwe_ids") or []),
        cpe_matches=list(merged.get("cpe_matches") or []),
        attack_techniques=list(merged.get("attack_techniques") or []),
        existing=_merge_ref_inputs(
            merged.get("stix_external_refs"),
            incoming.get("stix_external_refs"),
        ),
    )
    for key in (
        "cvss",
        "epss",
        "cisa_kev_due_date",
        "stix_object_id",
        "stix_object_name",
    ):
        if key not in merged and incoming.get(key) not in (None, "", [], {}):
            merged[key] = incoming[key]
    if incoming.get("cisa_kev"):
        merged["cisa_kev"] = True
    elif "cisa_kev" not in merged and incoming.get("cisa_kev") is not None:
        merged["cisa_kev"] = bool(incoming.get("cisa_kev"))
    merged["source"] = "local_stix"
    return merged


def vulnerability_stix_metadata_index(stix_bundle: Mapping[str, Any] | list[Any]) -> dict[str, dict[str, Any]]:
    """Return CVE-keyed standards metadata parsed from a local STIX 2.1 bundle."""
    if isinstance(stix_bundle, Mapping):
        objects = stix_bundle.get("objects") if isinstance(stix_bundle.get("objects"), list) else []
    elif isinstance(stix_bundle, list):
        objects = stix_bundle
    else:
        objects = []

    index: dict[str, dict[str, Any]] = {}
    for item in objects:
        if not isinstance(item, Mapping):
            continue
        if str(item.get("type") or "").strip().lower() != "vulnerability":
            continue
        name = str(item.get("name") or "").strip()
        description = str(item.get("description") or "").strip()
        stix_object_id = str(item.get("id") or "").strip()
        standards = item.get("x_forge_standards")
        standards = standards if isinstance(standards, Mapping) else {}
        external_refs = _merge_ref_inputs(
            item.get("external_references"),
            standards.get("stix_external_refs"),
        )
        ref_cves = [
            ref["external_id"]
            for ref in external_refs
            if str(ref.get("source_name") or "").strip().lower() == "cve"
        ]
        ref_cwes = [
            ref["external_id"]
            for ref in external_refs
            if str(ref.get("source_name") or "").strip().lower() == "cwe"
        ]
        ref_attack = [
            ref["external_id"]
            for ref in external_refs
            if str(ref.get("source_name") or "").strip().lower() == "mitre-attack"
        ]
        ref_cpes = [
            ref["external_id"]
            for ref in external_refs
            if str(ref.get("source_name") or "").strip().lower() == "cpe"
        ]
        cve_ids = _ordered_unique(
            _list_from_value(standards.get("cve_ids"))
            + ref_cves
            + _extract_ordered(_CVE_RE, name, description),
        )
        if not cve_ids:
            continue
        payload: dict[str, Any] = {
            "cve_ids": cve_ids,
            "cwe_ids": _ordered_unique(
                _list_from_value(standards.get("cwe_ids"))
                + ref_cwes
                + _extract_ordered(_CWE_RE, description),
                limit=25,
            ),
            "cpe_matches": _ordered_unique(
                _list_from_value(standards.get("cpe_matches"))
                + ref_cpes
                + _extract_ordered(_CPE_RE, description, transform=str),
                transform=str,
            ),
            "attack_techniques": _ordered_unique(
                _list_from_value(standards.get("attack_techniques"))
                + ref_attack
                + _extract_ordered(_ATTACK_RE, description),
                limit=25,
            ),
            "cisa_kev": _boolish(standards.get("cisa_kev")),
            "stix_external_refs": external_refs,
            "stix_object_id": stix_object_id,
            "stix_object_name": name,
        }
        for key in ("cvss", "epss", "cisa_kev_due_date"):
            if standards.get(key) not in (None, "", [], {}):
                payload[key] = standards[key]
        for cve_id in cve_ids:
            index[cve_id] = _merge_stix_metadata(index.get(cve_id, {}), payload)
    return index


def _standards_cve_ids(standards: Mapping[str, Any]) -> list[str]:
    return _ordered_unique(
        _list_from_value(standards.get("primary_cve"))
        + _list_from_value(standards.get("cve_ids"))
    )


def _matched_stix_metadata(
    stix_index: Mapping[str, dict[str, Any]],
    standards: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    merged: dict[str, Any] = {}
    matched: list[str] = []
    for cve_id in _standards_cve_ids(standards):
        stix_meta = stix_index.get(cve_id.upper())
        if not stix_meta:
            continue
        merged = _merge_stix_metadata(merged, stix_meta)
        matched.append(cve_id.upper())
    return merged, matched


def vulnerability_stix_enrichment_preview(
    con: sqlite3.Connection,
    engagement_id: int,
    stix_bundle: Mapping[str, Any] | list[Any],
) -> dict[str, Any]:
    """Summarize local STIX CVE matches without changing stored findings."""
    con.row_factory = sqlite3.Row
    columns = {
        str(row[1])
        for row in con.execute("PRAGMA table_info(vulnerability_findings)").fetchall()
    }
    if "standards_json" not in columns:
        return {
            "engagement_id": int(engagement_id),
            "finding_count": 0,
            "stix_cve_count": 0,
            "matched_finding_count": 0,
            "matched_cve_ids": [],
            "unmatched_stix_cve_ids": [],
            "finding_matches": [],
            "created_finding_count": 0,
            "network_calls": False,
        }
    rows = con.execute(
        "SELECT * FROM vulnerability_findings WHERE engagement_id=?",
        (int(engagement_id),),
    ).fetchall()
    stix_index = vulnerability_stix_metadata_index(stix_bundle)
    matches: list[dict[str, Any]] = []
    matched_cves: set[str] = set()
    for row in rows:
        preliminary = vulnerability_standards_metadata(row)
        _stix_meta, cve_ids = _matched_stix_metadata(stix_index, preliminary)
        if not cve_ids:
            continue
        matched_cves.update(cve_ids)
        matches.append(
            {
                "finding_id": int(row["id"]),
                "cve_ids": cve_ids,
            }
        )
    stix_cves = sorted(stix_index)
    return {
        "engagement_id": int(engagement_id),
        "finding_count": len(rows),
        "stix_cve_count": len(stix_cves),
        "matched_finding_count": len(matches),
        "matched_cve_ids": sorted(matched_cves),
        "unmatched_stix_cve_ids": [
            cve_id for cve_id in stix_cves if cve_id not in matched_cves
        ],
        "finding_matches": matches,
        "created_finding_count": 0,
        "network_calls": False,
    }


def lookup_local_cve_metadata(
    con: sqlite3.Connection,
    cve_id: str,
) -> dict[str, Any]:
    """Return optional local KB metadata for a CVE from supported cache schemas."""
    if con.row_factory is None:
        con.row_factory = sqlite3.Row
    cve = str(cve_id or "").strip().upper()
    if not cve:
        return {}
    tables = {
        str(row[0])
        for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    if "nvd_cves" in tables:
        row = con.execute(
            """
            SELECT *
            FROM nvd_cves
            WHERE cve_id=?
            """,
            (cve,),
        ).fetchone()
        if row:
            return _row_mapping(row)
    if {"cve", "cvss_scores"} <= tables:
        score_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(cvss_scores)").fetchall()
        }
        cvss_v4_expr = "s.cvss_v4" if "cvss_v4" in score_columns else "NULL"
        cvss_v4_vector_expr = (
            "s.cvss_v4_vector" if "cvss_v4_vector" in score_columns else "NULL"
        )
        cvss_v3_expr = "s.cvss_v3" if "cvss_v3" in score_columns else "NULL"
        cvss_v3_vector_expr = (
            "s.cvss_v3_vector" if "cvss_v3_vector" in score_columns else "NULL"
        )
        cvss_v2_expr = "s.cvss_v2" if "cvss_v2" in score_columns else "NULL"
        cvss_v2_vector_expr = (
            "s.cvss_v2_vector" if "cvss_v2_vector" in score_columns else "NULL"
        )
        row = con.execute(
            f"""
            SELECT c.cve_id, c.severity, c.cpe_matches, c.published_at, c.modified_at,
                   {cvss_v4_expr} AS cvss_v4_score,
                   {cvss_v4_vector_expr} AS cvss_v4_vector,
                   {cvss_v3_expr} AS cvss_v3_score,
                   {cvss_v3_vector_expr} AS cvss_v3_vector,
                   {cvss_v2_expr} AS cvss_v2_score,
                   {cvss_v2_vector_expr} AS cvss_v2_vector
            FROM cve c
            LEFT JOIN cvss_scores s ON s.cve_id=c.cve_id
            WHERE c.cve_id=?
            """,
            (cve,),
        ).fetchone()
        if row:
            payload = _row_mapping(row)
            return payload
    return {}


def vulnerability_standards_metadata(
    row: sqlite3.Row | Mapping[str, Any],
    *,
    cve_metadata: Mapping[str, Any] | None = None,
    stix_metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    seed = _metadata_seed(row)
    cve_meta = dict(cve_metadata or {})
    stix_meta = dict(stix_metadata or {})
    text_fields = (
        _row_value(row, "cve_id"),
        seed.get("cve_id"),
        seed.get("cve_ids"),
        _row_value(row, "title"),
        _row_value(row, "description"),
        _row_value(row, "evidence"),
    )
    cve_ids = _ordered_unique(
        _list_from_value(_row_value(row, "cve_id"))
        + _list_from_value(seed.get("cve_ids"))
        + _list_from_value(stix_meta.get("cve_ids"))
        + _extract_ordered(_CVE_RE, *text_fields)
    )
    primary_cve = cve_ids[0] if cve_ids else ""
    cwe_ids = _ordered_unique(
        _list_from_value(_row_value(row, "cwe_ids"))
        + _list_from_value(seed.get("cwe_ids"))
        + _list_from_value(stix_meta.get("cwe_ids"))
        + _extract_ordered(_CWE_RE, _row_value(row, "description"), _row_value(row, "evidence")),
        limit=25,
    )
    cpe_matches = _ordered_unique(
        _list_from_value(_row_value(row, "cpe_matches"))
        + _list_from_value(seed.get("cpe_matches"))
        + _list_from_value(cve_meta.get("cpe_matches"))
        + _list_from_value(stix_meta.get("cpe_matches"))
        + _extract_ordered(_CPE_RE, _row_value(row, "description"), _row_value(row, "evidence"), transform=str),
        transform=str,
    )
    attack_techniques = _ordered_unique(
        _list_from_value(_row_value(row, "attack_techniques"))
        + _list_from_value(seed.get("attack_techniques"))
        + _list_from_value(stix_meta.get("attack_techniques"))
        + _extract_ordered(_ATTACK_RE, _row_value(row, "description"), _row_value(row, "evidence")),
        limit=25,
    )
    cvss, cvss_alternatives = _cvss_metadata(row, seed, cve_meta, stix_meta)
    epss_score = _float_or_none(_row_value(row, "epss_score"))
    if epss_score is None:
        epss_score = _float_or_none(seed.get("epss_score"))
    if epss_score is None:
        epss = stix_meta.get("epss") if isinstance(stix_meta.get("epss"), Mapping) else {}
        epss_score = _float_or_none(epss.get("score"))
    epss_percentile = _float_or_none(_row_value(row, "epss_percentile"))
    if epss_percentile is None:
        epss_percentile = _float_or_none(seed.get("epss_percentile"))
    if epss_percentile is None:
        epss = stix_meta.get("epss") if isinstance(stix_meta.get("epss"), Mapping) else {}
        epss_percentile = _float_or_none(epss.get("percentile"))
    cisa_kev = _boolish(
        _row_value(row, "cisa_kev")
        or seed.get("cisa_kev")
        or stix_meta.get("cisa_kev")
    )
    cisa_kev_due_date = str(
        _row_value(row, "cisa_kev_due_date")
        or seed.get("cisa_kev_due_date")
        or stix_meta.get("cisa_kev_due_date")
        or ""
    ).strip()
    external_refs = _external_refs(
        cve_ids=cve_ids,
        cwe_ids=cwe_ids,
        cpe_matches=cpe_matches,
        attack_techniques=attack_techniques,
        existing=_merge_ref_inputs(
            _row_value(row, "stix_external_refs_json"),
            seed.get("stix_external_refs"),
            stix_meta.get("stix_external_refs"),
        ),
    )
    standards: dict[str, Any] = {
        "cve_ids": cve_ids,
        "primary_cve": primary_cve,
        "cwe_ids": cwe_ids,
        "cpe_matches": cpe_matches,
        "attack_techniques": attack_techniques,
        "cisa_kev": cisa_kev,
        "stix_external_refs": external_refs,
    }
    if cvss is not None:
        standards["cvss"] = cvss
    if cvss_alternatives:
        standards["cvss_alternatives"] = cvss_alternatives[:10]
    if epss_score is not None or epss_percentile is not None:
        standards["epss"] = {
            "score": epss_score,
            "percentile": epss_percentile,
        }
    if cisa_kev_due_date:
        standards["cisa_kev_due_date"] = cisa_kev_due_date
    standards.update({k: v for k, v in seed.items() if k not in standards})
    for key in ("stix_object_id", "stix_object_name"):
        if stix_meta.get(key):
            standards[key] = stix_meta[key]
    return standards


def vulnerability_stix_bundle(
    rows: list[sqlite3.Row | Mapping[str, Any]],
    *,
    title: str = "Forge Vulnerability Standards Export",
) -> dict[str, Any]:
    """Return a deterministic STIX 2.1 bundle for normalized findings."""
    objects: list[dict[str, Any]] = []
    for row in rows:
        obj = vulnerability_stix_object(row)
        if obj is not None:
            objects.append(obj)
    bundle_id = _stix_id("bundle", f"{title}:{','.join(obj['id'] for obj in objects)}")
    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
        "x_forge_export": {
            "title": title,
            "object_count": len(objects),
            "media_type": "application/stix+json;version=2.1",
        },
    }


def vulnerability_stix_object(
    row: sqlite3.Row | Mapping[str, Any],
) -> dict[str, Any] | None:
    """Return one STIX 2.1 vulnerability object, or None when no standard IDs exist."""
    standards = vulnerability_standards_metadata(row)
    primary_cve = str(standards.get("primary_cve") or "").strip().upper()
    cwe_ids = [str(item) for item in standards.get("cwe_ids", [])]
    attack_techniques = [str(item) for item in standards.get("attack_techniques", [])]
    if not primary_cve and not cwe_ids and not attack_techniques:
        return None
    source_table = str(_row_value(row, "source_table") or "vulnerability_findings")
    source_id = str(_row_value(row, "id") or _row_value(row, "source_id") or primary_cve or "")
    name = primary_cve or str(_row_value(row, "title") or cwe_ids[0] or attack_techniques[0])
    description = _as_text(_row_value(row, "description") or _row_value(row, "evidence"))
    timestamp = _stix_timestamp(
        _row_value(row, "found_at")
        or _row_value(row, "created_at")
        or _row_value(row, "updated_at")
    )
    stix_object: dict[str, Any] = {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": _stix_id("vulnerability", f"{source_table}:{source_id}:{name}"),
        "created": timestamp,
        "modified": timestamp,
        "name": name,
        "external_references": _stix_external_references(standards),
        "x_forge_source_table": source_table,
        "x_forge_source_id": source_id,
        "x_forge_severity": str(_row_value(row, "severity") or "").upper(),
        "x_forge_standards": standards,
    }
    if description:
        stix_object["description"] = _clip_stix_text(description)
    target_url = str(_row_value(row, "target_url") or "").strip()
    if target_url:
        stix_object["x_forge_target_url"] = _safe_exchange_url(target_url)
    validation_method = str(_row_value(row, "validation_method") or "").strip()
    if validation_method:
        stix_object["x_forge_validation_method"] = validation_method
    validation_status = str(_row_value(row, "validation_status") or "").strip()
    if validation_status:
        stix_object["x_forge_validation_status"] = validation_status
    reportable = _row_value(row, "reportable")
    if reportable is not None:
        stix_object["x_forge_reportable"] = _boolish(reportable)
    return stix_object


def vulnerability_taxii_manifest(
    stix_bundle: Mapping[str, Any],
    *,
    collection_id: str = "forge-vulnerability-standards",
    title: str = "Forge vulnerability standards",
) -> dict[str, Any]:
    """Return a TAXII 2.1-style manifest for a local STIX bundle."""
    objects = stix_bundle.get("objects") if isinstance(stix_bundle.get("objects"), list) else []
    return {
        "collection": {
            "id": collection_id,
            "title": title,
            "media_type": "application/stix+json;version=2.1",
        },
        "objects": [
            {
                "id": str(obj.get("id") or ""),
                "date_added": str(obj.get("created") or _STIX_DEFAULT_TIMESTAMP),
                "version": str(obj.get("modified") or _STIX_DEFAULT_TIMESTAMP),
                "media_type": "application/stix+json;version=2.1",
            }
            for obj in objects
            if isinstance(obj, Mapping) and obj.get("id")
        ],
    }


def enrich_vulnerability_findings(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    knowledge_con: sqlite3.Connection | None = None,
    stix_bundle: Mapping[str, Any] | list[Any] | None = None,
    only_stix_matches: bool = False,
) -> int:
    """Persist normalized standards metadata for findings using only local data."""
    con.row_factory = sqlite3.Row
    columns = {
        str(row[1])
        for row in con.execute("PRAGMA table_info(vulnerability_findings)").fetchall()
    }
    if "standards_json" not in columns:
        return 0
    rows = con.execute(
        "SELECT * FROM vulnerability_findings WHERE engagement_id=?",
        (int(engagement_id),),
    ).fetchall()
    stix_index = vulnerability_stix_metadata_index(stix_bundle or {})
    updated = 0
    for row in rows:
        preliminary = vulnerability_standards_metadata(row)
        stix_meta, _matched_cves = _matched_stix_metadata(stix_index, preliminary)
        if only_stix_matches and not stix_meta:
            continue
        cve_meta: dict[str, Any] = {}
        if knowledge_con is not None and preliminary.get("primary_cve"):
            knowledge_con.row_factory = sqlite3.Row
            cve_meta = lookup_local_cve_metadata(knowledge_con, str(preliminary["primary_cve"]))
        standards = vulnerability_standards_metadata(
            row,
            cve_metadata=cve_meta,
            stix_metadata=stix_meta,
        )
        assignments: dict[str, Any] = {"standards_json": json.dumps(standards, sort_keys=True)}
        if "cve_id" in columns and standards.get("primary_cve"):
            assignments["cve_id"] = standards["primary_cve"]
        cvss = standards.get("cvss") if isinstance(standards.get("cvss"), dict) else {}
        if "cvss_score" in columns and "score" in cvss:
            assignments["cvss_score"] = cvss["score"]
        if "cvss_version" in columns and cvss:
            assignments["cvss_version"] = cvss.get("version") or ""
        if "cvss_vector" in columns and cvss:
            assignments["cvss_vector"] = cvss.get("vector") or ""
        if "cwe_ids" in columns:
            assignments["cwe_ids"] = json.dumps(standards.get("cwe_ids", []), sort_keys=True)
        if "cpe_matches" in columns:
            assignments["cpe_matches"] = json.dumps(standards.get("cpe_matches", []), sort_keys=True)
        if "attack_techniques" in columns:
            assignments["attack_techniques"] = json.dumps(
                standards.get("attack_techniques", []),
                sort_keys=True,
            )
        if "stix_external_refs_json" in columns:
            assignments["stix_external_refs_json"] = json.dumps(
                standards.get("stix_external_refs", []),
                sort_keys=True,
            )
        if "epss_score" in columns and standards.get("epss"):
            assignments["epss_score"] = standards["epss"]["score"]
        if "epss_percentile" in columns and standards.get("epss"):
            assignments["epss_percentile"] = standards["epss"]["percentile"]
        if "cisa_kev" in columns:
            assignments["cisa_kev"] = 1 if standards.get("cisa_kev") else 0
        if "cisa_kev_due_date" in columns:
            assignments["cisa_kev_due_date"] = standards.get("cisa_kev_due_date") or ""
        set_clause = ", ".join(f"{column}=?" for column in assignments)
        con.execute(
            f"UPDATE vulnerability_findings SET {set_clause} WHERE id=?",
            (*assignments.values(), int(row["id"])),
        )
        updated += 1
    con.commit()
    return updated
