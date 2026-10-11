"""forge/utils/deep_extract_stats.py — extraction stats ledger.

Persists per-engagement deep-extraction stats so operators (and the
dashboard) can see what the universal
:func:`forge.utils.deep_extract.deep_extract_from_content` hook actually
pulled out of every piece of text FORGE processed. Secret values are
**never** persisted — only labels and counts.

Storage model: one row per extraction call in a per-engagement SQLite
table ``deep_extraction_log``. The table is auto-created on first write
to keep this module independent of the main schema migration pipeline;
rows survive engagement DB `forge clean` under the normal retention
model. Query helpers aggregate by source for the dashboard view.

The table schema is intentionally minimal:

    engagement_id INTEGER NOT NULL
    source        TEXT NOT NULL
    url_count     INTEGER
    domain_count  INTEGER
    ip_count      INTEGER
    email_count   INTEGER
    phone_count   INTEGER
    cloud_ref_count INTEGER
    secrets_detected INTEGER
    secret_labels_json TEXT    -- JSON array of labels; no values
    total_count   INTEGER
    logged_at     TEXT NOT NULL  -- ISO UTC
    sample_json   TEXT             -- small JSON sample (bounded)

``sample_json`` keeps the first 20 of each category so the dashboard
can show which URLs/domains/ips were seen without replaying the regex
over the original source text (which may already be gone).
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional


logger = logging.getLogger(__name__)


DEEP_EXTRACT_STATS_SCHEMA_VERSION = "forge.utils.deep_extract_stats.v1"


_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS deep_extraction_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    url_count INTEGER NOT NULL DEFAULT 0,
    domain_count INTEGER NOT NULL DEFAULT 0,
    ip_count INTEGER NOT NULL DEFAULT 0,
    email_count INTEGER NOT NULL DEFAULT 0,
    phone_count INTEGER NOT NULL DEFAULT 0,
    cloud_ref_count INTEGER NOT NULL DEFAULT 0,
    secrets_detected INTEGER NOT NULL DEFAULT 0,
    secret_labels_json TEXT NOT NULL DEFAULT '[]',
    total_count INTEGER NOT NULL DEFAULT 0,
    logged_at TEXT NOT NULL,
    sample_json TEXT NOT NULL DEFAULT '{}'
)
"""

_CREATE_INDEX_SQL = (
    "CREATE INDEX IF NOT EXISTS idx_deep_extraction_log_engagement "
    "ON deep_extraction_log(engagement_id)",
    "CREATE INDEX IF NOT EXISTS idx_deep_extraction_log_source "
    "ON deep_extraction_log(engagement_id, source)",
    "CREATE INDEX IF NOT EXISTS idx_deep_extraction_log_logged_at "
    "ON deep_extraction_log(engagement_id, logged_at)",
)


# Keep sample lists bounded so the dashboard payload is predictable.
_SAMPLE_LIMIT = 20


def _resolve_db_path(engagement_id: int, db_path: Optional[str] = None) -> Optional[Path]:
    if db_path:
        return Path(str(db_path))
    try:
        from forge.config import ForgeConfig  # noqa: PLC0415

        cfg = ForgeConfig.load()
        return cfg.engagement_db_path(str(engagement_id))
    except Exception as exc:  # noqa: BLE001
        logger.debug("deep_extract_stats: cannot resolve db path: %s", exc)
        return None


def _ensure_table(con: sqlite3.Connection) -> None:
    con.execute(_CREATE_TABLE_SQL)
    for stmt in _CREATE_INDEX_SQL:
        con.execute(stmt)


def _sample(data: Any, limit: int = _SAMPLE_LIMIT) -> list[Any]:
    if not data:
        return []
    try:
        items = list(data)
    except TypeError:
        return []
    return items[:limit]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _open_connection(engagement_id: int, db_path: Optional[str]) -> Optional[sqlite3.Connection]:
    resolved = _resolve_db_path(engagement_id, db_path)
    if resolved is None:
        return None
    try:
        resolved.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    try:
        con = sqlite3.connect(str(resolved), timeout=5.0)
    except sqlite3.Error as exc:
        logger.debug("deep_extract_stats: sqlite open failed: %s", exc)
        return None
    try:
        con.execute("PRAGMA busy_timeout = 5000")
    except sqlite3.Error:
        pass
    return con


def log_extraction(
    engagement_id: int,
    source: str,
    results: Mapping[str, Any],
    *,
    db_path: Optional[str] = None,
) -> bool:
    """Log a single extraction result.

    Returns ``True`` on persisted write, ``False`` on any failure (the
    extraction call itself always succeeds; stats logging is advisory).
    """
    try:
        engagement_id = int(engagement_id)
    except (TypeError, ValueError):
        return False
    source_label = str(source or "").strip() or "unknown"

    con = _open_connection(engagement_id, db_path)
    if con is None:
        return False
    try:
        _ensure_table(con)

        urls = results.get("urls") or []
        domains = results.get("domains") or []
        ips = results.get("ips") or []
        emails = results.get("emails") or []
        phones = results.get("phones") or []
        cloud_refs = results.get("cloud_refs") or []
        secret_labels = results.get("secret_labels") or []
        secrets_detected = int(results.get("secrets_detected") or 0)
        total = int(
            results.get("total_count")
            or (
                len(urls)
                + len(domains)
                + len(ips)
                + len(emails)
                + len(phones)
                + len(cloud_refs)
            )
        )

        sample = {
            "urls": _sample(urls),
            "domains": _sample(domains),
            "ips": _sample(ips),
            "emails": _sample(emails),
            "phones": _sample(phones),
            "cloud_refs": _sample(cloud_refs),
        }

        con.execute(
            """
            INSERT INTO deep_extraction_log (
                engagement_id, source,
                url_count, domain_count, ip_count,
                email_count, phone_count, cloud_ref_count,
                secrets_detected, secret_labels_json,
                total_count, logged_at, sample_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                source_label,
                len(urls),
                len(domains),
                len(ips),
                len(emails),
                len(phones),
                len(cloud_refs),
                secrets_detected,
                json.dumps(list(secret_labels), ensure_ascii=False, sort_keys=True),
                total,
                _now_iso(),
                json.dumps(sample, ensure_ascii=False, sort_keys=True),
            ),
        )
        con.commit()
        return True
    except sqlite3.Error as exc:
        logger.debug("deep_extract_stats: write failed: %s", exc)
        return False
    finally:
        try:
            con.close()
        except Exception:  # noqa: BLE001
            pass


def get_extraction_summary(
    engagement_id: int,
    *,
    db_path: Optional[str] = None,
    limit_per_source: int = 10,
) -> dict[str, Any]:
    """Return aggregated per-source stats for the dashboard.

    Returns::

        {
            "schema_version": "forge.utils.deep_extract_stats.v1",
            "engagement_id": N,
            "totals": {
                "urls": int, "domains": int, "ips": int,
                "emails": int, "phones": int, "cloud_refs": int,
                "secrets_detected": int, "total": int,
                "log_rows": int,
                "unique_sources": int,
            },
            "sources": [
                {
                    "source": "crawler:https://x",
                    "entries": int,
                    "urls": int, "domains": int, "ips": int,
                    "emails": int, "phones": int, "cloud_refs": int,
                    "secrets_detected": int,
                    "total": int,
                    "last_logged_at": "...",
                    "secret_labels": [...]
                },
                ...
            ],
            "recent": [
                {
                    "source": "...", "logged_at": "...",
                    "urls": int, ..., "secrets_detected": int,
                },
                ...
            ],
        }
    """
    try:
        engagement_id = int(engagement_id)
    except (TypeError, ValueError):
        return {
            "schema_version": DEEP_EXTRACT_STATS_SCHEMA_VERSION,
            "engagement_id": None,
            "totals": _empty_totals(),
            "sources": [],
            "recent": [],
        }

    con = _open_connection(engagement_id, db_path)
    if con is None:
        return {
            "schema_version": DEEP_EXTRACT_STATS_SCHEMA_VERSION,
            "engagement_id": engagement_id,
            "totals": _empty_totals(),
            "sources": [],
            "recent": [],
        }
    try:
        _ensure_table(con)

        totals_row = con.execute(
            """
            SELECT
                COALESCE(SUM(url_count), 0),
                COALESCE(SUM(domain_count), 0),
                COALESCE(SUM(ip_count), 0),
                COALESCE(SUM(email_count), 0),
                COALESCE(SUM(phone_count), 0),
                COALESCE(SUM(cloud_ref_count), 0),
                COALESCE(SUM(secrets_detected), 0),
                COALESCE(SUM(total_count), 0),
                COUNT(*),
                COUNT(DISTINCT source)
            FROM deep_extraction_log
            WHERE engagement_id = ?
            """,
            (engagement_id,),
        ).fetchone() or (0,) * 10

        totals = {
            "urls": int(totals_row[0] or 0),
            "domains": int(totals_row[1] or 0),
            "ips": int(totals_row[2] or 0),
            "emails": int(totals_row[3] or 0),
            "phones": int(totals_row[4] or 0),
            "cloud_refs": int(totals_row[5] or 0),
            "secrets_detected": int(totals_row[6] or 0),
            "total": int(totals_row[7] or 0),
            "log_rows": int(totals_row[8] or 0),
            "unique_sources": int(totals_row[9] or 0),
        }

        source_rows = con.execute(
            """
            SELECT
                source,
                COUNT(*),
                COALESCE(SUM(url_count), 0),
                COALESCE(SUM(domain_count), 0),
                COALESCE(SUM(ip_count), 0),
                COALESCE(SUM(email_count), 0),
                COALESCE(SUM(phone_count), 0),
                COALESCE(SUM(cloud_ref_count), 0),
                COALESCE(SUM(secrets_detected), 0),
                COALESCE(SUM(total_count), 0),
                MAX(logged_at)
            FROM deep_extraction_log
            WHERE engagement_id = ?
            GROUP BY source
            ORDER BY SUM(total_count) DESC, source ASC
            """,
            (engagement_id,),
        ).fetchall()

        sources: list[dict[str, Any]] = []
        for row in source_rows:
            source = row[0]
            label_rows = con.execute(
                """
                SELECT DISTINCT secret_labels_json
                FROM deep_extraction_log
                WHERE engagement_id = ? AND source = ?
                """,
                (engagement_id, source),
            ).fetchall()
            labels: set[str] = set()
            for (payload,) in label_rows:
                if not payload:
                    continue
                try:
                    parsed = json.loads(payload)
                except (TypeError, ValueError):
                    continue
                if isinstance(parsed, list):
                    for item in parsed:
                        if isinstance(item, str) and item:
                            labels.add(item)
            sources.append(
                {
                    "source": source,
                    "entries": int(row[1] or 0),
                    "urls": int(row[2] or 0),
                    "domains": int(row[3] or 0),
                    "ips": int(row[4] or 0),
                    "emails": int(row[5] or 0),
                    "phones": int(row[6] or 0),
                    "cloud_refs": int(row[7] or 0),
                    "secrets_detected": int(row[8] or 0),
                    "total": int(row[9] or 0),
                    "last_logged_at": row[10] or "",
                    "secret_labels": sorted(labels),
                }
            )

        recent_rows = con.execute(
            """
            SELECT
                source, logged_at,
                url_count, domain_count, ip_count,
                email_count, phone_count, cloud_ref_count,
                secrets_detected, total_count
            FROM deep_extraction_log
            WHERE engagement_id = ?
            ORDER BY logged_at DESC, id DESC
            LIMIT ?
            """,
            (engagement_id, max(1, min(int(limit_per_source or 10), 500))),
        ).fetchall()

        recent: list[dict[str, Any]] = []
        for row in recent_rows:
            recent.append(
                {
                    "source": row[0],
                    "logged_at": row[1],
                    "urls": int(row[2] or 0),
                    "domains": int(row[3] or 0),
                    "ips": int(row[4] or 0),
                    "emails": int(row[5] or 0),
                    "phones": int(row[6] or 0),
                    "cloud_refs": int(row[7] or 0),
                    "secrets_detected": int(row[8] or 0),
                    "total": int(row[9] or 0),
                }
            )

        return {
            "schema_version": DEEP_EXTRACT_STATS_SCHEMA_VERSION,
            "engagement_id": engagement_id,
            "totals": totals,
            "sources": sources,
            "recent": recent,
        }
    except sqlite3.Error as exc:
        logger.debug("deep_extract_stats: read failed: %s", exc)
        return {
            "schema_version": DEEP_EXTRACT_STATS_SCHEMA_VERSION,
            "engagement_id": engagement_id,
            "totals": _empty_totals(),
            "sources": [],
            "recent": [],
        }
    finally:
        try:
            con.close()
        except Exception:  # noqa: BLE001
            pass


def iter_extraction_samples(
    engagement_id: int,
    source: str,
    *,
    db_path: Optional[str] = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Return bounded per-row extraction samples for a given source.

    Each row contains the ``sample_json`` payload (bounded to 20 items
    per category) and the counts captured when it was logged. Secret
    values are never retrievable via this helper.
    """
    try:
        engagement_id = int(engagement_id)
    except (TypeError, ValueError):
        return []
    label = str(source or "").strip()
    if not label:
        return []
    con = _open_connection(engagement_id, db_path)
    if con is None:
        return []
    try:
        _ensure_table(con)
        rows = con.execute(
            """
            SELECT
                logged_at,
                url_count, domain_count, ip_count,
                email_count, phone_count, cloud_ref_count,
                secrets_detected, total_count, sample_json, secret_labels_json
            FROM deep_extraction_log
            WHERE engagement_id = ? AND source = ?
            ORDER BY logged_at DESC, id DESC
            LIMIT ?
            """,
            (engagement_id, label, max(1, min(int(limit or 50), 500))),
        ).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            try:
                sample = json.loads(row[9] or "{}") if row[9] else {}
            except (TypeError, ValueError):
                sample = {}
            try:
                labels_raw = json.loads(row[10] or "[]") if row[10] else []
            except (TypeError, ValueError):
                labels_raw = []
            labels: list[str] = [str(item) for item in labels_raw if isinstance(item, str)]
            output.append(
                {
                    "logged_at": row[0],
                    "urls": int(row[1] or 0),
                    "domains": int(row[2] or 0),
                    "ips": int(row[3] or 0),
                    "emails": int(row[4] or 0),
                    "phones": int(row[5] or 0),
                    "cloud_refs": int(row[6] or 0),
                    "secrets_detected": int(row[7] or 0),
                    "total": int(row[8] or 0),
                    "sample": sample if isinstance(sample, dict) else {},
                    "secret_labels": labels,
                }
            )
        return output
    except sqlite3.Error as exc:
        logger.debug("deep_extract_stats: sample read failed: %s", exc)
        return []
    finally:
        try:
            con.close()
        except Exception:  # noqa: BLE001
            pass


def collect_new_seeds_since(
    engagement_id: int,
    *,
    since_iso: str,
    db_path: Optional[str] = None,
    limit: int = 200,
) -> dict[str, Any]:
    """Return new deep-extraction seeds logged after ``since_iso``.

    This is the kill-chain iteration-feedback entry point. Callers pass
    the ISO UTC timestamp of the current iteration start, and the
    helper returns the deduped union of every URL, domain, IP, email,
    phone, and cloud_ref logged since then.

    Downstream callers can scope-filter the returned sets (via
    :func:`forge.utils.deep_extract.filter_in_scope_hosts`) and feed
    them into the next iteration's work queue.

    Returns::

        {
            "schema_version": "forge.utils.deep_extract_stats.v1",
            "engagement_id": N,
            "since": "<iso>",
            "urls": [...], "domains": [...], ...,
            "row_count": int,
            "truncated": bool,
        }
    """
    try:
        engagement_id = int(engagement_id)
    except (TypeError, ValueError):
        return _empty_new_seeds(engagement_id, since_iso)
    con = _open_connection(engagement_id, db_path)
    if con is None:
        return _empty_new_seeds(engagement_id, since_iso)
    try:
        _ensure_table(con)
        cap = max(1, min(int(limit or 200), 1000))
        rows = con.execute(
            """
            SELECT sample_json
            FROM deep_extraction_log
            WHERE engagement_id = ? AND logged_at > ?
            ORDER BY logged_at ASC, id ASC
            LIMIT ?
            """,
            (engagement_id, str(since_iso or ""), cap),
        ).fetchall()
        urls: list[str] = []
        domains: list[str] = []
        ips: list[str] = []
        emails: list[str] = []
        phones: list[str] = []
        cloud_refs: list[str] = []
        u_seen: set[str] = set()
        d_seen: set[str] = set()
        i_seen: set[str] = set()
        e_seen: set[str] = set()
        p_seen: set[str] = set()
        c_seen: set[str] = set()

        def _append(dst: list[str], seen: set[str], items: Any) -> None:
            if not isinstance(items, list):
                return
            for item in items:
                if not isinstance(item, str) or not item or item in seen:
                    continue
                seen.add(item)
                dst.append(item)

        for (payload,) in rows:
            if not payload:
                continue
            try:
                sample = json.loads(payload)
            except (TypeError, ValueError):
                continue
            if not isinstance(sample, dict):
                continue
            _append(urls, u_seen, sample.get("urls"))
            _append(domains, d_seen, sample.get("domains"))
            _append(ips, i_seen, sample.get("ips"))
            _append(emails, e_seen, sample.get("emails"))
            _append(phones, p_seen, sample.get("phones"))
            _append(cloud_refs, c_seen, sample.get("cloud_refs"))

        total_row = con.execute(
            """
            SELECT COUNT(*) FROM deep_extraction_log
            WHERE engagement_id = ? AND logged_at > ?
            """,
            (engagement_id, str(since_iso or "")),
        ).fetchone() or (0,)
        total_count = int(total_row[0] or 0)

        return {
            "schema_version": DEEP_EXTRACT_STATS_SCHEMA_VERSION,
            "engagement_id": engagement_id,
            "since": since_iso or "",
            "urls": urls,
            "domains": domains,
            "ips": ips,
            "emails": emails,
            "phones": phones,
            "cloud_refs": cloud_refs,
            "row_count": total_count,
            "truncated": total_count > cap,
        }
    except sqlite3.Error as exc:
        logger.debug("deep_extract_stats: collect_new_seeds_since failed: %s", exc)
        return _empty_new_seeds(engagement_id, since_iso)
    finally:
        try:
            con.close()
        except Exception:  # noqa: BLE001
            pass


def _empty_new_seeds(engagement_id: Optional[int], since_iso: str) -> dict[str, Any]:
    return {
        "schema_version": DEEP_EXTRACT_STATS_SCHEMA_VERSION,
        "engagement_id": engagement_id,
        "since": since_iso or "",
        "urls": [],
        "domains": [],
        "ips": [],
        "emails": [],
        "phones": [],
        "cloud_refs": [],
        "row_count": 0,
        "truncated": False,
    }


def _empty_totals() -> dict[str, Any]:
    return {
        "urls": 0,
        "domains": 0,
        "ips": 0,
        "emails": 0,
        "phones": 0,
        "cloud_refs": 0,
        "secrets_detected": 0,
        "total": 0,
        "log_rows": 0,
        "unique_sources": 0,
    }


__all__ = [
    "DEEP_EXTRACT_STATS_SCHEMA_VERSION",
    "collect_new_seeds_since",
    "get_extraction_summary",
    "iter_extraction_samples",
    "log_extraction",
]
