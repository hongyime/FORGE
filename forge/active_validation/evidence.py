"""Display helpers for active-validation evidence."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from forge.utils.artifact_url_sanitizer import strip_sensitive_url_query

_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(\"(?:api[_-]?key|access[_-]?token|token|secret|password|authorization|private[_-]?key)\"\s*:\s*\")[^\"]+(\")",
            re.IGNORECASE,
        ),
        r"\1[redacted]\2",
    ),
    (
        re.compile(
            r"(\b(?:api[_-]?key|access[_-]?token|token|secret|password|authorization|bearer)\b\s*[:=]\s*[\"']?)[^\"',;\s]{8,}",
            re.IGNORECASE,
        ),
        r"\1[redacted]",
    ),
    (
        re.compile(
            r"([?&](?:api[_-]?key|access[_-]?token|token|secret|signature|password)=)[^&\s\"']+",
            re.IGNORECASE,
        ),
        r"\1[redacted]",
    ),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[redacted]"),
    (
        re.compile(r"\b(?:ghp|github_pat|glpat|xox[baprs]|sk)-?[A-Za-z0-9_./+=-]{16,}\b"),
        "[redacted]",
    ),
)


def _as_mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _safe_label(value: object, *, limit: int = 180) -> str:
    text = " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())
    if not text:
        return ""
    text = _URL_RE.sub(lambda match: strip_sensitive_url_query(match.group(0)), text)
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text[:limit]


def _bool_label(value: object) -> str:
    return "yes" if bool(value) else "no"


def _http_proof_label(payload: Mapping[str, Any]) -> str:
    request = _as_mapping(payload.get("request"))
    response = _as_mapping(payload.get("response"))
    network_error = _as_mapping(payload.get("network_error"))
    reason = _safe_label(payload.get("reason"), limit=80)
    method = _safe_label(request.get("method"), limit=20)
    if not method:
        allowed = request.get("allowed_methods")
        if isinstance(allowed, list) and allowed:
            method = _safe_label(allowed[0], limit=20)
    status_code = response.get("status_code")
    parts: list[str] = []
    if status_code not in (None, ""):
        status_text = _safe_label(status_code, limit=20)
        parts.append(f"{method or 'HTTP'} {status_text}")
    elif network_error:
        error_type = _safe_label(network_error.get("type") or "error", limit=80)
        parts.append(f"{method or 'HTTP'} network_error={error_type}")
    elif reason:
        parts.append(f"blocked reason={reason}")
    elif payload:
        parts.append("live evidence recorded")
    redirect = _safe_label(response.get("redirect_location"), limit=120)
    if redirect:
        parts.append(f"redirect={redirect}")
    if "body_captured" in payload:
        parts.append(f"body={_bool_label(payload.get('body_captured'))}")
    return " ".join(parts)


def _list_label(value: object, *, limit: int = 120) -> str:
    if not isinstance(value, list):
        return ""
    labels = [_safe_label(item, limit=60) for item in value[:6]]
    return ", ".join(item for item in labels if item)[:limit]


def _http_security_headers_label(payload: Mapping[str, Any]) -> str:
    if payload.get("network_error"):
        return _http_proof_label(payload)
    request = _as_mapping(payload.get("request"))
    response = _as_mapping(payload.get("response"))
    headers = _as_mapping(payload.get("security_headers"))
    observed = _as_mapping(headers.get("observed"))
    method = _safe_label(request.get("method"), limit=20) or "HTTP"
    status_code = _safe_label(response.get("status_code"), limit=20)
    parts = [f"{method} {status_code}".strip()]
    parts.append(f"headers observed={len(observed)}")
    missing = _list_label(headers.get("missing"))
    weak = _list_label(headers.get("weak"))
    if missing:
        parts.append(f"missing={missing}")
    if weak:
        parts.append(f"weak={weak}")
    if "body_captured" in payload:
        parts.append(f"body={_bool_label(payload.get('body_captured'))}")
    return " ".join(part for part in parts if part)


def _fix_match_label(live_validation: Mapping[str, Any]) -> str:
    fix = _as_mapping(live_validation.get("fix_verification"))
    if not fix:
        return ""
    expected = _safe_label(fix.get("expected_result"), limit=80) or "-"
    observed = _safe_label(fix.get("observed_result"), limit=80) or "-"
    matched = _bool_label(fix.get("matched"))
    return f"expected={expected} observed={observed} matched={matched}"


def _control_validation_label(payload: Mapping[str, Any]) -> str:
    expected = _safe_label(payload.get("expected_result"), limit=80) or "-"
    observed = _safe_label(payload.get("observed_result"), limit=80) or "-"
    matched = _bool_label(payload.get("matched"))
    parts = [f"control expected={expected} observed={observed} matched={matched}"]
    control_name = _safe_label(payload.get("control_name"), limit=80)
    attack_step = _safe_label(payload.get("attack_step"), limit=80)
    detection_source = _safe_label(payload.get("detection_source"), limit=80)
    detection_signal = _safe_label(payload.get("detection_signal"), limit=100)
    if control_name:
        parts.append(f"control={control_name}")
    if attack_step:
        parts.append(f"attack={attack_step}")
    if detection_source:
        parts.append(f"source={detection_source}")
    if detection_signal:
        parts.append(f"signal={detection_signal}")
    if "body_captured" in payload:
        parts.append(f"body={_bool_label(payload.get('body_captured'))}")
    return " ".join(parts)


def active_validation_proof_summary(evidence: object) -> dict[str, str]:
    """Return compact, redacted proof labels for operator review surfaces."""

    payload = _as_mapping(evidence)
    live_validation = _as_mapping(payload.get("live_validation"))
    control_validation = _as_mapping(payload.get("control_validation"))
    live_proof = ""
    fix_match = ""
    if live_validation:
        fix_match = _fix_match_label(live_validation)
        if "security_headers" in live_validation:
            live_proof = _http_security_headers_label(live_validation)
        else:
            http_payload = _as_mapping(live_validation.get("http_reachability")) or live_validation
            live_proof = _http_proof_label(http_payload)

    evidence_label = ""
    if fix_match and live_proof:
        evidence_label = f"{fix_match}; {live_proof}"
    elif fix_match:
        evidence_label = fix_match
    elif live_proof:
        evidence_label = live_proof
    elif control_validation:
        evidence_label = _control_validation_label(control_validation)
    elif isinstance(payload.get("planned_steps"), list) and payload["planned_steps"]:
        step = _as_mapping(payload["planned_steps"][0])
        method = _safe_label(step.get("method"), limit=80) or "planned"
        effect = _safe_label(step.get("effect"), limit=80)
        evidence_label = f"{method} effect={effect}" if effect else method
    else:
        fixture = _as_mapping(payload.get("fixture"))
        if fixture:
            method = _safe_label(fixture.get("method"), limit=80) or "fixture"
            result = _safe_label(fixture.get("result"), limit=80)
            evidence_label = f"{method} result={result}" if result else method

    return {
        "evidence": evidence_label or "-",
        "live_proof": live_proof or "-",
        "fix_match": fix_match or "-",
    }
