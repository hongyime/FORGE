from __future__ import annotations

import json
import re
import sqlite3
import urllib.request
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from forge.opsec.scope_gate import ScopeViolationError, assert_in_scope, scope_entries_from_payload

SUPPORTED_IDENTITY_EXPOSURE_CONNECTORS = ("hibp_pwned_passwords",)
HIBP_PWNED_PASSWORDS_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
_USER_AGENT = "FORGE-OSINT/7.2 (authorized-engagement-tooling)"
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

RangeFetcher = Callable[[str, str, float, bool], str]


@dataclass(frozen=True)
class IdentityExposureRunConfig:
    connector_id: str
    engagement_id: int
    domain: str = ""
    offline_corpus_path: Path | None = None
    timeout_seconds: float = 30.0
    dry_run: bool = False
    operator: str = "connector-runner"
    use_padding: bool = True


@dataclass(frozen=True)
class _CredentialHash:
    credential_id: int
    email: str
    email_domain: str
    hash_type: str
    password_hash: str
    pwned_prefix: str


def run_identity_exposure_connector(
    con: sqlite3.Connection,
    config: IdentityExposureRunConfig,
    *,
    range_fetcher: RangeFetcher | None = None,
) -> dict[str, Any]:
    if con.row_factory is None:
        con.row_factory = sqlite3.Row
    connector_id = str(config.connector_id or "").strip().lower()
    if connector_id not in SUPPORTED_IDENTITY_EXPOSURE_CONNECTORS:
        raise ValueError(
            "identity exposure connector must be one of "
            f"{', '.join(SUPPORTED_IDENTITY_EXPOSURE_CONNECTORS)}"
        )
    engagement_id = int(config.engagement_id)
    scope = _scope_for_engagement(con, engagement_id)
    domain = _normalize_domain(config.domain)
    if domain:
        assert_in_scope(domain, scope)
    credentials, skipped = _credential_hashes_for_scope(
        con,
        engagement_id=engagement_id,
        scope=scope,
        domain=domain,
    )
    source = "offline_corpus" if config.offline_corpus_path is not None else "hibp_range_api"
    if config.dry_run:
        result = _identity_result(
            config,
            connector_id=connector_id,
            domain=domain,
            source="planned",
            status="planned",
            checked_count=len(credentials),
            exposed_count=0,
            persisted_count=0,
            remediation_count=0,
            skipped=skipped,
            credentials=credentials,
            matches=[],
        )
        _audit_identity_run(con, config, result=result)
        con.commit()
        return result

    try:
        counts = (
            _offline_pwned_counts(Path(config.offline_corpus_path), credentials)
            if config.offline_corpus_path is not None
            else _api_pwned_counts(
                credentials,
                timeout_seconds=max(1.0, min(float(config.timeout_seconds or 30.0), 120.0)),
                use_padding=bool(config.use_padding),
                range_fetcher=range_fetcher or _default_range_fetcher,
            )
        )
    except Exception as exc:  # noqa: BLE001 - provider/import failures are connector evidence.
        result = _identity_result(
            config,
            connector_id=connector_id,
            domain=domain,
            source=source,
            status="failed",
            checked_count=len(credentials),
            exposed_count=0,
            persisted_count=0,
            remediation_count=0,
            skipped=skipped,
            credentials=credentials,
            matches=[],
            reason="identity_exposure_lookup_failed",
            error_class=type(exc).__name__,
        )
        _audit_identity_run(con, config, result=result)
        con.commit()
        return result

    now = _utc_timestamp()
    persisted_count = 0
    exposed_count = 0
    remediation_count = 0
    matches: list[dict[str, Any]] = []
    for credential in credentials:
        pwned_count = int(counts.get(credential.password_hash) or 0)
        _update_credential_enrichment(
            con,
            credential,
            pwned_count=pwned_count,
            source=source,
            checked_at=now,
        )
        persisted_count += 1
        if pwned_count <= 0:
            continue
        exposed_count += 1
        remediation_count += _upsert_identity_remediation(
            con,
            engagement_id=engagement_id,
            credential=credential,
            pwned_count=pwned_count,
            source=source,
            checked_at=now,
        )
        matches.append(_match_payload(credential, pwned_count=pwned_count))

    result = _identity_result(
        config,
        connector_id=connector_id,
        domain=domain,
        source=source,
        status="completed",
        checked_count=len(credentials),
        exposed_count=exposed_count,
        persisted_count=persisted_count,
        remediation_count=remediation_count,
        skipped=skipped,
        credentials=credentials,
        matches=matches,
    )
    _audit_identity_run(con, config, result=result)
    con.commit()
    return result


def parse_hibp_range_response(prefix: str, hash_type: str, text: str) -> dict[str, int]:
    normalized_prefix = _normalize_prefix(prefix)
    suffix_len = _suffix_length(hash_type)
    counts: dict[str, int] = {}
    for raw_line in str(text or "").splitlines():
        parsed = _parse_hash_count_line(raw_line)
        if parsed is None:
            continue
        suffix, count = parsed
        if count <= 0 or len(suffix) != suffix_len:
            continue
        counts[f"{normalized_prefix}{suffix}"] = count
    return counts


def _credential_hashes_for_scope(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    scope: list[str],
    domain: str,
) -> tuple[list[_CredentialHash], list[dict[str, Any]]]:
    if not _table_exists(con, "credentials"):
        return [], [{"reason": "credentials_table_missing"}]
    rows = con.execute(
        """
        SELECT id, email, password_hash, hash_type
        FROM credentials
        WHERE engagement_id=?
          AND password_hash IS NOT NULL
          AND TRIM(COALESCE(password_hash, '')) != ''
        ORDER BY id
        """,
        (engagement_id,),
    ).fetchall()
    credentials: list[_CredentialHash] = []
    skipped: list[dict[str, Any]] = []
    for row in rows:
        credential_id = int(row["id"])
        email = str(row["email"] or "").strip().lower()
        email_domain = _email_domain(email)
        if domain and not _domain_matches(email_domain, domain):
            skipped.append(_skip_payload(credential_id, email, "domain_filter_mismatch"))
            continue
        try:
            assert_in_scope(email_domain, scope)
        except ScopeViolationError:
            skipped.append(_skip_payload(credential_id, email, "identity_domain_out_of_scope"))
            continue
        normalized = _normalize_hash(row["password_hash"], row["hash_type"])
        if normalized is None:
            skipped.append(_skip_payload(credential_id, email, "unsupported_or_invalid_hash"))
            continue
        hash_type, password_hash = normalized
        credentials.append(
            _CredentialHash(
                credential_id=credential_id,
                email=email,
                email_domain=email_domain,
                hash_type=hash_type,
                password_hash=password_hash,
                pwned_prefix=password_hash[:5],
            )
        )
    return credentials, skipped


def _api_pwned_counts(
    credentials: Iterable[_CredentialHash],
    *,
    timeout_seconds: float,
    use_padding: bool,
    range_fetcher: RangeFetcher,
) -> dict[str, int]:
    by_range: dict[tuple[str, str], list[_CredentialHash]] = defaultdict(list)
    for credential in credentials:
        by_range[(credential.hash_type, credential.pwned_prefix)].append(credential)
    counts: dict[str, int] = {}
    for (hash_type, prefix), group in sorted(by_range.items()):
        response_text = range_fetcher(prefix, hash_type, timeout_seconds, use_padding)
        range_counts = parse_hibp_range_response(prefix, hash_type, response_text)
        for credential in group:
            count = int(range_counts.get(credential.password_hash) or 0)
            if count > 0:
                counts[credential.password_hash] = count
    return counts


def _offline_pwned_counts(path: Path, credentials: Iterable[_CredentialHash]) -> dict[str, int]:
    requested = {credential.password_hash for credential in credentials}
    prefixes_by_type: dict[str, set[str]] = defaultdict(set)
    for credential in credentials:
        prefixes_by_type[credential.hash_type].add(credential.pwned_prefix)
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"offline corpus not found: {path}")
    counts: dict[str, int] = {}
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            parsed = _parse_hash_count_line(raw_line)
            if parsed is None:
                continue
            hash_fragment, count = parsed
            if count <= 0:
                continue
            if hash_fragment in requested:
                counts[hash_fragment] = count
                continue
            for hash_type in ("sha1", "ntlm"):
                if len(hash_fragment) != _suffix_length(hash_type):
                    continue
                for prefix in prefixes_by_type.get(hash_type, set()):
                    full_hash = f"{prefix}{hash_fragment}"
                    if full_hash in requested:
                        counts[full_hash] = count
    return counts


def _default_range_fetcher(
    prefix: str,
    hash_type: str,
    timeout_seconds: float,
    use_padding: bool,
) -> str:
    normalized_prefix = _normalize_prefix(prefix)
    url = HIBP_PWNED_PASSWORDS_RANGE_URL.format(prefix=normalized_prefix)
    if hash_type == "ntlm":
        url = f"{url}?mode=ntlm"
    headers = {"User-Agent": _USER_AGENT}
    if use_padding:
        headers["Add-Padding"] = "true"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        return response.read().decode("utf-8", errors="replace")


def _identity_result(
    config: IdentityExposureRunConfig,
    *,
    connector_id: str,
    domain: str,
    source: str,
    status: str,
    checked_count: int,
    exposed_count: int,
    persisted_count: int,
    remediation_count: int,
    skipped: list[dict[str, Any]],
    credentials: list[_CredentialHash],
    matches: list[dict[str, Any]],
    reason: str = "",
    error_class: str = "",
) -> dict[str, Any]:
    ranges = {
        (credential.hash_type, credential.pwned_prefix)
        for credential in credentials
    }
    payload: dict[str, Any] = {
        "connector_id": connector_id,
        "engagement_id": int(config.engagement_id),
        "domain": domain,
        "source": source,
        "status": status,
        "dry_run": bool(config.dry_run),
        "checked_count": int(checked_count),
        "exposed_count": int(exposed_count),
        "persisted_count": int(persisted_count),
        "remediation_count": int(remediation_count),
        "skipped_count": len(skipped),
        "queried_prefix_count": len(ranges),
        "hash_types": sorted({credential.hash_type for credential in credentials}),
        "matches": matches[:25],
        "skipped": skipped[:25],
        "privacy": (
            "Only stored SHA-1/NTLM password hashes are checked. Plaintext passwords "
            "and full hashes are not returned or audited; HIBP API mode sends only "
            "the first 5 hash characters."
        ),
    }
    if reason:
        payload["reason"] = reason
    if error_class:
        payload["error_class"] = error_class
    return payload


def _match_payload(credential: _CredentialHash, *, pwned_count: int) -> dict[str, Any]:
    return {
        "credential_id": credential.credential_id,
        "email": credential.email,
        "domain": credential.email_domain,
        "hash_type": credential.hash_type,
        "pwned_count": int(pwned_count),
    }


def _update_credential_enrichment(
    con: sqlite3.Connection,
    credential: _CredentialHash,
    *,
    pwned_count: int,
    source: str,
    checked_at: str,
) -> None:
    row = con.execute(
        """
        SELECT enrichment_data
        FROM credentials
        WHERE id=?
        """,
        (credential.credential_id,),
    ).fetchone()
    enrichment = _safe_json_loads(str(row["enrichment_data"] or "{}")) if row is not None else {}
    if not isinstance(enrichment, dict):
        enrichment = {}
    enrichment["hibp_pwned_passwords"] = {
        "connector_id": "hibp_pwned_passwords",
        "source": source,
        "status": "pwned" if pwned_count > 0 else "not_found",
        "pwned_count": int(pwned_count),
        "hash_type": credential.hash_type,
        "checked_at": checked_at,
        "privacy": "full hash and plaintext password omitted",
    }
    con.execute(
        """
        UPDATE credentials
        SET enrichment_data=?
        WHERE id=?
        """,
        (json.dumps(enrichment, sort_keys=True), credential.credential_id),
    )


def _upsert_identity_remediation(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    credential: _CredentialHash,
    pwned_count: int,
    source: str,
    checked_at: str,
) -> int:
    if not _table_exists(con, "remediation_items"):
        return 0
    finding_ref = f"identity_exposure:hibp_pwned_passwords:{credential.credential_id}"
    metadata = {
        "source": "identity_exposure",
        "connector_id": "hibp_pwned_passwords",
        "credential_id": credential.credential_id,
        "email": credential.email,
        "domain": credential.email_domain,
        "hash_type": credential.hash_type,
        "pwned_count": int(pwned_count),
        "checked_at": checked_at,
        "lookup_source": source,
        "privacy": "full hash and plaintext password omitted",
    }
    result = con.execute(
        """
        INSERT INTO remediation_items
            (engagement_id, finding_table, finding_ref, title, severity,
             status, retest_status, metadata_json)
        VALUES (?, 'manual', ?, ?, 'HIGH', 'open', 'not_requested', ?)
        ON CONFLICT(engagement_id, finding_table, finding_ref) DO UPDATE SET
            title=excluded.title,
            severity=excluded.severity,
            status=CASE
                WHEN remediation_items.status IN ('risk_accepted','resolved','false_positive')
                THEN remediation_items.status
                ELSE 'open'
            END,
            metadata_json=excluded.metadata_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            engagement_id,
            finding_ref,
            f"Pwned password hash observed for {credential.email}",
            json.dumps(metadata, sort_keys=True),
        ),
    )
    return int(result.rowcount or 0)


def _audit_identity_run(
    con: sqlite3.Connection,
    config: IdentityExposureRunConfig,
    *,
    result: Mapping[str, Any],
) -> None:
    if not _table_exists(con, "audit_log"):
        return
    parts = [
        str(result.get("status") or ""),
        f"source={result.get('source')}",
        f"checked={int(result.get('checked_count') or 0)}",
        f"exposed={int(result.get('exposed_count') or 0)}",
        f"persisted={int(result.get('persisted_count') or 0)}",
        f"skipped={int(result.get('skipped_count') or 0)}",
    ]
    reason = _bounded_text(result.get("reason"), 80)
    if reason:
        parts.append(f"reason={reason}")
    con.execute(
        """
        INSERT INTO audit_log
            (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'connectors', ?, 'identity_exposure_check', ?, ?, ?)
        """,
        (
            int(config.engagement_id),
            str(result.get("connector_id") or "hibp_pwned_passwords"),
            str(result.get("domain") or "*"),
            " ".join(parts),
            str(config.operator or "connector-runner"),
        ),
    )


def _scope_for_engagement(con: sqlite3.Connection, engagement_id: int) -> list[str]:
    row = con.execute(
        "SELECT scope_json FROM engagements WHERE id=?",
        (int(engagement_id),),
    ).fetchone()
    if row is None:
        raise LookupError(f"engagement not found: {engagement_id}")
    return scope_entries_from_payload(_safe_json_loads(str(row["scope_json"] or "[]")))


def _table_exists(con: sqlite3.Connection, table_name: str) -> bool:
    row = con.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type='table' AND name=?
        LIMIT 1
        """,
        (table_name,),
    ).fetchone()
    return row is not None


def _safe_json_loads(value: str | None) -> Any:
    if not value:
        return {}
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return {}


def _normalize_hash(value: object, hash_type: object) -> tuple[str, str] | None:
    normalized_type = str(hash_type or "").strip().lower().replace("-", "")
    if normalized_type not in {"sha1", "ntlm"}:
        return None
    text = str(value or "").strip().upper()
    if ":" in text:
        text = text.rsplit(":", 1)[-1].strip().upper()
    text = re.sub(r"[^0-9A-F]", "", text)
    expected_length = 40 if normalized_type == "sha1" else 32
    if len(text) != expected_length or not _HEX_RE.match(text):
        return None
    return normalized_type, text


def _parse_hash_count_line(raw_line: str) -> tuple[str, int] | None:
    line = str(raw_line or "").strip()
    if not line or ":" not in line:
        return None
    hash_fragment, raw_count = line.split(":", 1)
    hash_fragment = hash_fragment.strip().upper()
    if not hash_fragment or not _HEX_RE.match(hash_fragment):
        return None
    try:
        count = int(str(raw_count).strip())
    except ValueError:
        return None
    return hash_fragment, count


def _suffix_length(hash_type: str) -> int:
    return 27 if str(hash_type or "").strip().lower() == "ntlm" else 35


def _normalize_prefix(prefix: str) -> str:
    text = str(prefix or "").strip().upper()
    if len(text) != 5 or not _HEX_RE.match(text):
        raise ValueError("HIBP Pwned Passwords prefix must be 5 hex characters")
    return text


def _normalize_domain(value: object) -> str:
    return str(value or "").strip().lower().strip(".")


def _email_domain(email: str) -> str:
    return email.rsplit("@", 1)[-1].strip().lower().strip(".") if "@" in email else ""


def _domain_matches(candidate: str, domain: str) -> bool:
    normalized_candidate = _normalize_domain(candidate)
    normalized_domain = _normalize_domain(domain)
    return normalized_candidate == normalized_domain or normalized_candidate.endswith(
        f".{normalized_domain}"
    )


def _skip_payload(credential_id: int, email: str, reason: str) -> dict[str, Any]:
    return {
        "credential_id": int(credential_id),
        "email": str(email or ""),
        "reason": reason,
    }


def _utc_timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _bounded_text(value: object, limit: int = 240) -> str:
    return " ".join(str(value or "").strip().split())[:limit]
