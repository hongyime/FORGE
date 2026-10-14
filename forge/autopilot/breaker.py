"""Provider and Global Circuit Breakers for Autopilot Admission.

Maintains sliding-window rate-limit events and admission pause states across
providers, protecting external intelligence endpoints, target hosts, and
upstream services from rate-limit storms, IP bans, and quota exhaustion.

State is stored alongside scheduler leases in <data_dir>/scheduler.db.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from forge.autopilot.jitter import retry_after_delay
from forge.db.direct_connect import direct_connect

if TYPE_CHECKING:
    from forge.config import ForgeConfig

GLOBAL_PROVIDER_KEY = "__global__"
DEFAULT_WINDOW_SECONDS = 600
DEFAULT_PROVIDER_THRESHOLD = 3
DEFAULT_PAUSE_SECONDS = 900
DEFAULT_GLOBAL_PROVIDER_THRESHOLD = 3
DEFAULT_GLOBAL_EVENT_THRESHOLD = 10
DEFAULT_PROVIDER_MAX_INFLIGHT = 2


def _ensure_utc(dt: datetime | None = None) -> datetime:
    if dt is None:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_iso(iso_str: str) -> datetime:
    dt = datetime.fromisoformat(iso_str)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def canonical_provider(scope_or_url: str | None, url: str | None = None) -> str:
    """Normalize a scope, service name, URL, or domain to a canonical provider key."""
    raw = str(scope_or_url or "").strip().lower()
    candidate_url = str(url or "").strip().lower()

    # 1. Recognized external intelligence / scan service names
    KNOWN_SERVICES = {
        "shodan",
        "urlscan",
        "crtsh",
        "github",
        "virustotal",
        "commoncrawl",
        "wayback",
        "censys",
        "dehashed",
        "replit",
        "supabase",
        "identity",
        "web_fetch",
    }
    if raw in KNOWN_SERVICES:
        return raw

    # 2. Extract host from URL if provided or if raw is a URL
    target = candidate_url or raw
    if "://" in target:
        try:
            parsed = urlsplit(target)
            host = (parsed.netloc or parsed.path or "").split(":")[0].strip().lower()
            if host:
                return host
        except Exception:
            pass

    # 3. Handle email seeds
    if "@" in raw and "://" not in raw:
        return raw.split("@", 1)[1].strip().lower()

    # 4. Strip paths, ports, leading wildcards
    clean = raw.split("/")[0].split(":")[0].strip().lower()
    if clean.startswith("*."):
        clean = clean[2:]
    return clean or "unknown"


def ensure_breaker_schema(con: sqlite3.Connection) -> None:
    """Idempotently create provider events and breaker tables."""
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS provider_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            provider        TEXT NOT NULL,
            event_type      TEXT NOT NULL,
            recorded_at     TEXT NOT NULL,
            details         TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_provider_events_provider_time 
            ON provider_events(provider, recorded_at);
        CREATE INDEX IF NOT EXISTS idx_provider_events_time 
            ON provider_events(recorded_at);

        CREATE TABLE IF NOT EXISTS provider_breakers (
            provider        TEXT PRIMARY KEY,
            paused_until    TEXT,
            trip_reason     TEXT,
            last_tripped_at TEXT,
            updated_at      TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_provider_breakers_paused 
            ON provider_breakers(paused_until);
        """
    )


def record_rate_limit(
    provider: str,
    *,
    data_dir: Path | str | None = None,
    now: datetime | None = None,
    config: ForgeConfig | None = None,
    details: dict[str, Any] | None = None,
) -> bool:
    """Record a rate-limit event for provider in SQLite; trips breaker if threshold exceeded.

    Returns True if the breaker was tripped by this call, False otherwise.
    """
    prov = canonical_provider(provider)
    ref_time = _ensure_utc(now)
    now_iso = ref_time.isoformat()

    window_s = DEFAULT_WINDOW_SECONDS
    threshold = DEFAULT_PROVIDER_THRESHOLD
    pause_s = DEFAULT_PAUSE_SECONDS

    if config is not None:
        window_s = getattr(config, "breaker_rate_limit_window_s", DEFAULT_WINDOW_SECONDS)
        threshold = getattr(config, "breaker_rate_limit_threshold", DEFAULT_PROVIDER_THRESHOLD)
        pause_s = getattr(config, "breaker_pause_s", DEFAULT_PAUSE_SECONDS)
    else:
        try:
            from forge.config import ForgeConfig

            cfg = ForgeConfig.load()
            window_s = getattr(cfg, "breaker_rate_limit_window_s", DEFAULT_WINDOW_SECONDS)
            threshold = getattr(cfg, "breaker_rate_limit_threshold", DEFAULT_PROVIDER_THRESHOLD)
            pause_s = getattr(cfg, "breaker_pause_s", DEFAULT_PAUSE_SECONDS)
        except Exception:
            pass

    from forge.autopilot.scheduler import scheduler_db_path

    db_path = scheduler_db_path(data_dir)
    con = direct_connect(db_path)
    tripped = False
    try:
        ensure_breaker_schema(con)
        with con:
            cur = con.execute(
                "SELECT paused_until FROM provider_breakers WHERE provider = ?",
                (prov,),
            )
            row = cur.fetchone()
            was_paused = False
            if row and row[0]:
                try:
                    was_paused = _parse_iso(row[0]) > ref_time
                except Exception:
                    was_paused = False

            con.execute(
                """
                INSERT INTO provider_events (provider, event_type, recorded_at, details)
                VALUES (?, 'rate_limit', ?, ?)
                """,
                (prov, now_iso, json.dumps(details) if details else None),
            )

            # Prune events older than 24 hours
            stale_cutoff = (ref_time - timedelta(hours=24)).isoformat()
            con.execute(
                "DELETE FROM provider_events WHERE recorded_at < ?",
                (stale_cutoff,),
            )

            window_cutoff = (ref_time - timedelta(seconds=window_s)).isoformat()
            cur = con.execute(
                """
                SELECT COUNT(*) FROM provider_events
                WHERE provider = ? AND event_type = 'rate_limit' AND recorded_at >= ?
                """,
                (prov, window_cutoff),
            )
            count = cur.fetchone()[0]

            if count >= threshold:
                new_pause_until = (ref_time + timedelta(seconds=pause_s)).isoformat()
                con.execute(
                    """
                    INSERT INTO provider_breakers (provider, paused_until, trip_reason, last_tripped_at, updated_at)
                    VALUES (?, ?, 'threshold_exceeded', ?, ?)
                    ON CONFLICT(provider) DO UPDATE SET
                        paused_until = CASE
                            WHEN provider_breakers.paused_until IS NULL OR provider_breakers.paused_until < excluded.paused_until
                            THEN excluded.paused_until
                            ELSE provider_breakers.paused_until
                        END,
                        trip_reason = CASE
                            WHEN provider_breakers.paused_until IS NULL OR provider_breakers.paused_until < excluded.paused_until
                            THEN excluded.trip_reason
                            ELSE provider_breakers.trip_reason
                        END,
                        last_tripped_at = excluded.last_tripped_at,
                        updated_at = excluded.updated_at
                    """,
                    (prov, new_pause_until, now_iso, now_iso),
                )
                if not was_paused:
                    tripped = True
    finally:
        con.close()

    # Trigger global breaker evaluation
    check_and_update_global_breaker(data_dir=data_dir, now=ref_time, config=config)
    return tripped


def is_provider_paused(
    provider: str,
    *,
    data_dir: Path | str | None = None,
    now: datetime | None = None,
) -> bool:
    """Return True if the provider is currently paused due to breaker trip or Retry-After."""
    ref_time = _ensure_utc(now)
    prov = canonical_provider(provider)
    from forge.autopilot.scheduler import scheduler_db_path

    db_path = scheduler_db_path(data_dir)
    con = direct_connect(db_path)
    try:
        ensure_breaker_schema(con)
        cur = con.execute(
            "SELECT paused_until FROM provider_breakers WHERE provider = ?",
            (prov,),
        )
        row = cur.fetchone()
        if not row or not row[0]:
            return False
        return _parse_iso(row[0]) > ref_time
    finally:
        con.close()


def remaining_pause(
    provider: str,
    *,
    data_dir: Path | str | None = None,
    now: datetime | None = None,
) -> float:
    """Return remaining pause duration in seconds (0.0 if not paused)."""
    ref_time = _ensure_utc(now)
    prov = canonical_provider(provider)
    from forge.autopilot.scheduler import scheduler_db_path

    db_path = scheduler_db_path(data_dir)
    con = direct_connect(db_path)
    try:
        ensure_breaker_schema(con)
        cur = con.execute(
            "SELECT paused_until FROM provider_breakers WHERE provider = ?",
            (prov,),
        )
        row = cur.fetchone()
        if not row or not row[0]:
            return 0.0
        rem = (_parse_iso(row[0]) - ref_time).total_seconds()
        return max(0.0, rem)
    finally:
        con.close()


def set_retry_after(
    provider: str,
    retry_after_value: str | int | float | None,
    *,
    data_dir: Path | str | None = None,
    now: datetime | None = None,
    max_delay: float = 3600.0,
) -> float | None:
    """Parse Retry-After and pause provider admission for parsed seconds if positive.

    Returns the parsed delay in seconds, or None if invalid/absent.
    Composes with existing pause: sets paused_until = max(existing_paused_until, now + delay).
    """
    ref_time = _ensure_utc(now)
    delay = retry_after_delay(retry_after_value, max_delay=max_delay, now=ref_time)
    if delay is None or delay <= 0.0:
        return None

    prov = canonical_provider(provider)
    new_pause_until = (ref_time + timedelta(seconds=delay)).isoformat()
    now_iso = ref_time.isoformat()

    from forge.autopilot.scheduler import scheduler_db_path

    db_path = scheduler_db_path(data_dir)
    con = direct_connect(db_path)
    try:
        ensure_breaker_schema(con)
        with con:
            con.execute(
                """
                INSERT INTO provider_breakers (provider, paused_until, trip_reason, last_tripped_at, updated_at)
                VALUES (?, ?, 'retry_after', ?, ?)
                ON CONFLICT(provider) DO UPDATE SET
                    paused_until = CASE
                        WHEN provider_breakers.paused_until IS NULL OR provider_breakers.paused_until < excluded.paused_until
                        THEN excluded.paused_until
                        ELSE provider_breakers.paused_until
                    END,
                    trip_reason = CASE
                        WHEN provider_breakers.paused_until IS NULL OR provider_breakers.paused_until < excluded.paused_until
                        THEN 'retry_after'
                        ELSE provider_breakers.trip_reason
                    END,
                    last_tripped_at = CASE
                        WHEN provider_breakers.paused_until IS NULL OR provider_breakers.paused_until < excluded.paused_until
                        THEN excluded.last_tripped_at
                        ELSE provider_breakers.last_tripped_at
                    END,
                    updated_at = excluded.updated_at
                """,
                (prov, new_pause_until, now_iso, now_iso),
            )
        return delay
    finally:
        con.close()


def check_and_update_global_breaker(
    *,
    data_dir: Path | str | None = None,
    now: datetime | None = None,
    config: ForgeConfig | None = None,
) -> bool:
    """Evaluate sliding window for multi-provider rate limits; trip global breaker if threshold met.

    Returns True if global breaker is currently tripped or became tripped, False otherwise.
    """
    ref_time = _ensure_utc(now)
    now_iso = ref_time.isoformat()

    window_s = DEFAULT_WINDOW_SECONDS
    pause_s = DEFAULT_PAUSE_SECONDS
    global_prov_threshold = DEFAULT_GLOBAL_PROVIDER_THRESHOLD
    global_event_threshold = DEFAULT_GLOBAL_EVENT_THRESHOLD

    if config is not None:
        window_s = getattr(config, "breaker_rate_limit_window_s", DEFAULT_WINDOW_SECONDS)
        pause_s = getattr(config, "breaker_pause_s", DEFAULT_PAUSE_SECONDS)
        global_prov_threshold = getattr(
            config, "breaker_global_provider_threshold", DEFAULT_GLOBAL_PROVIDER_THRESHOLD
        )
        global_event_threshold = getattr(
            config, "breaker_global_event_threshold", DEFAULT_GLOBAL_EVENT_THRESHOLD
        )
    else:
        try:
            from forge.config import ForgeConfig

            cfg = ForgeConfig.load()
            window_s = getattr(cfg, "breaker_rate_limit_window_s", DEFAULT_WINDOW_SECONDS)
            pause_s = getattr(cfg, "breaker_pause_s", DEFAULT_PAUSE_SECONDS)
            global_prov_threshold = getattr(
                cfg, "breaker_global_provider_threshold", DEFAULT_GLOBAL_PROVIDER_THRESHOLD
            )
            global_event_threshold = getattr(
                cfg, "breaker_global_event_threshold", DEFAULT_GLOBAL_EVENT_THRESHOLD
            )
        except Exception:
            pass

    window_cutoff = (ref_time - timedelta(seconds=window_s)).isoformat()
    from forge.autopilot.scheduler import scheduler_db_path

    db_path = scheduler_db_path(data_dir)
    con = direct_connect(db_path)
    try:
        ensure_breaker_schema(con)
        with con:
            cur = con.execute(
                """
                SELECT COUNT(DISTINCT provider) FROM provider_events
                WHERE event_type = 'rate_limit'
                  AND provider != ?
                  AND recorded_at >= ?
                """,
                (GLOBAL_PROVIDER_KEY, window_cutoff),
            )
            distinct_providers = cur.fetchone()[0]

            cur = con.execute(
                """
                SELECT COUNT(*) FROM provider_events
                WHERE event_type = 'rate_limit'
                  AND recorded_at >= ?
                """,
                (window_cutoff,),
            )
            total_events = cur.fetchone()[0]

            should_trip = False
            trip_reason = ""
            if distinct_providers >= global_prov_threshold:
                should_trip = True
                trip_reason = "multi_provider_threshold"
            elif total_events >= global_event_threshold:
                should_trip = True
                trip_reason = "global_event_threshold"

            if should_trip:
                new_pause_until = (ref_time + timedelta(seconds=pause_s)).isoformat()
                con.execute(
                    """
                    INSERT INTO provider_breakers (provider, paused_until, trip_reason, last_tripped_at, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(provider) DO UPDATE SET
                        paused_until = CASE
                            WHEN provider_breakers.paused_until IS NULL OR provider_breakers.paused_until < excluded.paused_until
                            THEN excluded.paused_until
                            ELSE provider_breakers.paused_until
                        END,
                        trip_reason = CASE
                            WHEN provider_breakers.paused_until IS NULL OR provider_breakers.paused_until < excluded.paused_until
                            THEN excluded.trip_reason
                            ELSE provider_breakers.trip_reason
                        END,
                        last_tripped_at = excluded.last_tripped_at,
                        updated_at = excluded.updated_at
                    """,
                    (GLOBAL_PROVIDER_KEY, new_pause_until, trip_reason, now_iso, now_iso),
                )
                return True

            cur = con.execute(
                "SELECT paused_until FROM provider_breakers WHERE provider = ?",
                (GLOBAL_PROVIDER_KEY,),
            )
            row = cur.fetchone()
            if row and row[0]:
                return _parse_iso(row[0]) > ref_time
            return False
    finally:
        con.close()


def record_global_rate_limit(
    *,
    reason: str = "manual",
    pause_seconds: int = DEFAULT_PAUSE_SECONDS,
    data_dir: Path | str | None = None,
    now: datetime | None = None,
) -> None:
    """Explicitly trip the global circuit breaker for pause_seconds."""
    ref_time = _ensure_utc(now)
    now_iso = ref_time.isoformat()
    pause_until_iso = (ref_time + timedelta(seconds=pause_seconds)).isoformat()
    from forge.autopilot.scheduler import scheduler_db_path

    db_path = scheduler_db_path(data_dir)
    con = direct_connect(db_path)
    try:
        ensure_breaker_schema(con)
        with con:
            con.execute(
                """
                INSERT INTO provider_breakers (provider, paused_until, trip_reason, last_tripped_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(provider) DO UPDATE SET
                    paused_until = CASE
                        WHEN provider_breakers.paused_until IS NULL OR provider_breakers.paused_until < excluded.paused_until
                        THEN excluded.paused_until
                        ELSE provider_breakers.paused_until
                    END,
                    trip_reason = excluded.trip_reason,
                    last_tripped_at = excluded.last_tripped_at,
                    updated_at = excluded.updated_at
                """,
                (GLOBAL_PROVIDER_KEY, pause_until_iso, reason, now_iso, now_iso),
            )
    finally:
        con.close()


def is_global_paused(
    *,
    data_dir: Path | str | None = None,
    now: datetime | None = None,
) -> bool:
    """Return True if the global circuit breaker is active (all starts paused)."""
    return is_provider_paused(GLOBAL_PROVIDER_KEY, data_dir=data_dir, now=now)


def remaining_global_pause(
    *,
    data_dir: Path | str | None = None,
    now: datetime | None = None,
) -> float:
    """Return remaining global pause duration in seconds (0.0 if not paused)."""
    return remaining_pause(GLOBAL_PROVIDER_KEY, data_dir=data_dir, now=now)


def can_start_provider(
    provider: str,
    *,
    data_dir: Path | str | None = None,
    max_inflight: int = DEFAULT_PROVIDER_MAX_INFLIGHT,
) -> bool:
    """Return True if active leases for provider are below max_inflight."""
    prov = canonical_provider(provider)
    if not prov or prov == "unknown":
        return True
    from forge.autopilot.scheduler import ensure_scheduler_schema, scheduler_db_path

    db_path = scheduler_db_path(data_dir)
    con = direct_connect(db_path)
    try:
        ensure_scheduler_schema(con)
        cur = con.execute(
            "SELECT COUNT(*) FROM leases WHERE provider = ? AND status = 'active'",
            (prov,),
        )
        row = cur.fetchone()
        active_count = int(row[0]) if row else 0
        return active_count < max_inflight
    finally:
        con.close()
