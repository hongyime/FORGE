from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlparse, urlunparse

import httpx

from forge.db.session import get_engagement_db


@dataclass(frozen=True)
class PassiveFinding:
    engagement_id: int
    vuln_id: str
    plugin: str
    url: str
    payload: str | None
    param: str | None
    severity: str
    request_b64: str | None
    response_b64: str | None


def _int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = int(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _passive_http_max_workers_default() -> int:
    """Default scoped passive HTTP collection to slow, sequential probing."""
    return _int_env(
        "FORGE_PASSIVE_HTTP_MAX_WORKERS",
        1,
        minimum=1,
        maximum=4,
    )


def ingest_xray_jsonl(engagement_id: int, db_path: Path, jsonl_path: Path) -> int:
    if not jsonl_path.exists():
        return 0
    inserted = 0
    con = get_engagement_db(db_path)
    try:
        for line in jsonl_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            plugin = str(item.get("plugin", "unknown"))
            target = str(item.get("target", ""))
            vuln_id = str(item.get("id") or f"{plugin}:{target}")
            payload = item.get("payload")
            param = item.get("param")
            severity = str(item.get("severity", "LOW")).upper()
            if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
                severity = "LOW"
            request_b64 = item.get("request")
            response_b64 = item.get("response")
            cursor = con.execute(
                """
                INSERT OR IGNORE INTO passive_vulns (
                    engagement_id, vuln_id, plugin, url, payload, param, severity,
                    request_b64, response_b64
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement_id,
                    vuln_id,
                    plugin,
                    target,
                    payload if isinstance(payload, str) else None,
                    param if isinstance(param, str) else None,
                    severity,
                    request_b64 if isinstance(request_b64, str) else None,
                    response_b64 if isinstance(response_b64, str) else None,
                ),
            )
            if cursor.rowcount > 0:
                inserted += 1
        con.commit()
    finally:
        con.close()
    return inserted


def ingest_passive_file(engagement_id: int, db_path: Path, input_path: Path) -> int:
    if not input_path.exists():
        return 0
    suffix = input_path.suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        return ingest_xray_jsonl(engagement_id, db_path, input_path)
    text = input_path.read_text(encoding="utf-8", errors="ignore")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return 0
    if isinstance(data, list):
        return _ingest_json_array(engagement_id, db_path, data)
    if isinstance(data, dict):
        if "log" in data and isinstance(data.get("log"), dict):
            return _ingest_har(engagement_id, db_path, data)
        if "results" in data and isinstance(data.get("results"), list):
            return _ingest_json_array(engagement_id, db_path, list(data["results"]))
    return 0


def _ingest_json_array(engagement_id: int, db_path: Path, items: list[object]) -> int:
    normalized: list[dict[str, object]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        target = str(item.get("target") or item.get("url") or "")
        if not target:
            continue
        normalized.append(
            {
                "id": item.get("id") or f"array:{target}",
                "plugin": item.get("plugin") or item.get("type") or "unknown",
                "target": target,
                "payload": item.get("payload"),
                "param": item.get("param"),
                "severity": item.get("severity") or "LOW",
                "request": item.get("request"),
                "response": item.get("response"),
            }
        )
    temp = db_path.parent / f".tmp_passive_{engagement_id}.jsonl"
    temp_lines = "\n".join(json.dumps(row, ensure_ascii=False) for row in normalized)
    temp.write_text(temp_lines, encoding="utf-8")
    try:
        return ingest_xray_jsonl(engagement_id, db_path, temp)
    finally:
        temp.unlink(missing_ok=True)


def _ingest_har(engagement_id: int, db_path: Path, har: dict[str, object]) -> int:
    log = har.get("log")
    if not isinstance(log, dict):
        return 0
    entries = log.get("entries")
    if not isinstance(entries, list):
        return 0
    findings: list[PassiveFinding] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request")
        response = entry.get("response")
        if not isinstance(request, dict) or not isinstance(response, dict):
            continue
        url = str(request.get("url") or "")
        status = int(response.get("status") or 0)
        content = response.get("content")
        text = ""
        if isinstance(content, dict):
            text = str(content.get("text") or "")
        body = text.lower()
        parsed = urlparse(url)
        params = [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        if status >= 500 and "exception" in body:
            findings.append(
                PassiveFinding(
                    engagement_id=engagement_id,
                    vuln_id=f"har-exception:{url}",
                    plugin="har-exception",
                    url=url,
                    payload=None,
                    param=params[0] if params else None,
                    severity="LOW",
                    request_b64=None,
                    response_b64=None,
                )
            )
        if ("sql syntax" in body or "mysql" in body) and params:
            findings.append(
                PassiveFinding(
                    engagement_id=engagement_id,
                    vuln_id=f"har-sqli-leak:{url}",
                    plugin="har-sqli-leak",
                    url=url,
                    payload=None,
                    param=params[0],
                    severity="MEDIUM",
                    request_b64=None,
                    response_b64=None,
                )
            )
    con = get_engagement_db(db_path)
    inserted = 0
    try:
        for finding in findings:
            cursor = con.execute(
                """
                INSERT OR IGNORE INTO passive_vulns (
                    engagement_id, vuln_id, plugin, url, payload, param, severity,
                    request_b64, response_b64
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.engagement_id,
                    finding.vuln_id,
                    finding.plugin,
                    finding.url,
                    finding.payload,
                    finding.param,
                    finding.severity,
                    finding.request_b64,
                    finding.response_b64,
                ),
            )
            if cursor.rowcount > 0:
                inserted += 1
        con.commit()
    finally:
        con.close()
    return inserted


def _assert_passive_target_in_scope(target_url: str, scope: list[str]) -> None:
    from forge.opsec.scope_gate import assert_url_in_scope

    assert_url_in_scope(target_url, scope)


def run_passive_http_collection(
    engagement_id: int,
    db_path: Path,
    target_url: str,
    proxy: str | None = None,
    timeout: float = 12.0,
) -> int:
    from forge.opsec.scope_gate import load_scope_from_db
    scope = load_scope_from_db(str(db_path), engagement_id)
    _assert_passive_target_in_scope(target_url, scope)

    try:
        resp = httpx.get(target_url, timeout=timeout, proxy=proxy)
    except Exception:
        return 0
    body = resp.text.lower()
    findings: list[PassiveFinding] = []
    if "sql syntax" in body or "mysql" in body:
        findings.append(
            PassiveFinding(
                engagement_id=engagement_id,
                vuln_id=f"passive-sqli:{target_url}",
                plugin="passive-sqli",
                url=target_url,
                payload=None,
                param=None,
                severity="MEDIUM",
                request_b64=None,
                response_b64=None,
            )
        )
    if "stack trace" in body or "exception" in body:
        findings.append(
            PassiveFinding(
                engagement_id=engagement_id,
                vuln_id=f"passive-error-leak:{target_url}",
                plugin="passive-error-leak",
                url=target_url,
                payload=None,
                param=None,
                severity="LOW",
                request_b64=None,
                response_b64=None,
            )
        )
    con = get_engagement_db(db_path)
    inserted = 0
    try:
        for finding in findings:
            cursor = con.execute(
                """
                INSERT OR IGNORE INTO passive_vulns (
                    engagement_id, vuln_id, plugin, url, payload, param, severity,
                    request_b64, response_b64
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.engagement_id,
                    finding.vuln_id,
                    finding.plugin,
                    finding.url,
                    finding.payload,
                    finding.param,
                    finding.severity,
                    finding.request_b64,
                    finding.response_b64,
                ),
            )
            if cursor.rowcount > 0:
                inserted += 1
        con.commit()
    finally:
        con.close()
    return inserted


def _normalize_passive_target(raw_target: str) -> str | None:
    raw = str(raw_target or "").strip()
    if not raw:
        return None
    parsed = urlparse(raw)
    if not parsed.scheme:
        parsed = urlparse(f"https://{raw}")
    scheme = str(parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return None
    netloc = str(parsed.netloc or "").strip()
    path = parsed.path or ""
    if not netloc and "://" not in raw:
        netloc = str(parsed.path or "").strip()
        path = ""
    if not netloc:
        return None
    return urlunparse((scheme, netloc, path, "", parsed.query or "", ""))


def _engagement_passive_targets(
    engagement_id: int,
    db_path: Path,
    *,
    limit: int = 12,
) -> list[str]:
    con = get_engagement_db(db_path)
    targets: list[str] = []
    seen: set[str] = set()

    def _add_candidate(raw_value: object) -> None:
        normalized = _normalize_passive_target(str(raw_value or ""))
        if not normalized or normalized in seen or len(targets) >= max(1, int(limit)):
            return
        seen.add(normalized)
        targets.append(normalized)

    try:
        for row in con.execute(
            """
            SELECT COALESCE(final_url, url) AS target_url
            FROM crawl_results
            WHERE engagement_id=?
            ORDER BY discovered_at DESC, id DESC
            """,
            (engagement_id,),
        ).fetchall():
            _add_candidate(row["target_url"])
        if not targets:
            for row in con.execute(
                """
                SELECT seed_value
                FROM engagement_seeds
                WHERE engagement_id=?
                  AND seed_type IN ('url', 'domain', 'subdomain')
                ORDER BY depth ASC, id DESC
                """,
                (engagement_id,),
            ).fetchall():
                _add_candidate(row["seed_value"])
                if len(targets) >= max(1, int(limit)):
                    break
        if not targets:
            for row in con.execute(
                """
                SELECT hostname
                FROM hosts
                WHERE engagement_id=?
                  AND hostname IS NOT NULL
                  AND hostname != ''
                  AND hostname != ip
                ORDER BY discovered_at DESC, id DESC
                """,
                (engagement_id,),
            ).fetchall():
                _add_candidate(row["hostname"])
                if len(targets) >= max(1, int(limit)):
                    break
        if not targets:
            row = con.execute(
                """
                SELECT scope_json
                FROM engagements
                WHERE id=?
                """,
                (engagement_id,),
            ).fetchone()
            if row is not None:
                try:
                    from forge.opsec.scope_gate import scope_entries_from_payload  # noqa: PLC0415

                    scope_entries = scope_entries_from_payload(json.loads(str(row["scope_json"] or "[]")))
                except json.JSONDecodeError:
                    scope_entries = []
                for entry in scope_entries:
                    _add_candidate(entry)
                    if len(targets) >= max(1, int(limit)):
                        break
    finally:
        con.close()
    return targets


def run_passive_http_collection_for_engagement(
    engagement_id: int,
    db_path: Path,
    *,
    proxy: str | None = None,
    timeout: float = 12.0,
    limit: int = 12,
    max_workers: int | None = None,
) -> int:
    from forge.opsec.scope_gate import ScopeViolationError, load_scope_from_db

    scope = load_scope_from_db(str(db_path), engagement_id)
    targets = _engagement_passive_targets(
        engagement_id,
        db_path,
        limit=limit,
    )
    scoped_targets: list[str] = []
    for target_url in targets:
        try:
            _assert_passive_target_in_scope(target_url, scope)
        except ScopeViolationError:
            continue
        scoped_targets.append(target_url)

    if not scoped_targets:
        return 0

    requested_workers = (
        _passive_http_max_workers_default()
        if max_workers is None
        else max(1, min(int(max_workers or 1), 4))
    )
    bounded_workers = max(1, min(requested_workers, len(scoped_targets), 4))
    inserted = 0
    # Keep tiny target sets deterministic; the thread fan-out only pays for
    # itself once we have a few URLs to inspect.
    if len(scoped_targets) <= 2 or bounded_workers <= 1:
        for target_url in scoped_targets:
            inserted += run_passive_http_collection(
                engagement_id,
                db_path=db_path,
                target_url=target_url,
                proxy=proxy,
                timeout=timeout,
            )
        return inserted

    with ThreadPoolExecutor(max_workers=bounded_workers) as executor:
        future_map = {
            executor.submit(
                run_passive_http_collection,
                engagement_id,
                db_path=db_path,
                target_url=target_url,
                proxy=proxy,
                timeout=timeout,
            ): target_url
            for target_url in scoped_targets
        }
        for future in as_completed(future_map):
            inserted += int(future.result() or 0)
    return inserted


def mark_vuln_verified(db_path: Path, vuln_id: str) -> bool:
    con = get_engagement_db(db_path)
    try:
        con.execute(
            "UPDATE passive_vulns SET verified=1, false_positive=0, reported=0 WHERE vuln_id=?",
            (vuln_id,),
        )
        changed = con.total_changes > 0
        con.commit()
        return changed
    finally:
        con.close()


def mark_vuln_false_positive(db_path: Path, vuln_id: str) -> bool:
    con = get_engagement_db(db_path)
    try:
        con.execute(
            "UPDATE passive_vulns SET false_positive=1, verified=0 WHERE vuln_id=?",
            (vuln_id,),
        )
        changed = con.total_changes > 0
        con.commit()
        return changed
    finally:
        con.close()


def summarize_passive_vulns(engagement_id: int, db_path: Path) -> dict[str, int]:
    con = get_engagement_db(db_path)
    try:
        rows = con.execute(
            """
            SELECT severity, COUNT(*)
            FROM passive_vulns
            WHERE engagement_id=?
            GROUP BY severity
            """,
            (engagement_id,),
        ).fetchall()
    finally:
        con.close()
    summary: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for severity, count in rows:
        key = str(severity).upper()
        if key in summary:
            summary[key] = int(count)
    return summary
