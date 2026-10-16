"""Shared Autopilot Scheduler and Global Worker Budget Manager.

Provides cross-target slot and concurrency governance across both fresh starts
(import) and resumes. Implements SQLite-backed lease management, PID and TTL
staleness reaping, budget calculation, and file-based kill switch sentinel.
"""

from __future__ import annotations

import logging
import math
import os
import secrets
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from forge.config import ForgeConfig
from forge.db.direct_connect import direct_connect
from forge.autopilot.breaker import can_start_provider

_LOG = logging.getLogger(__name__)

DEFAULT_KILL_SWITCH_FILENAME = "autopilot.stop"
DEFAULT_GLOBAL_SLOTS = 4
DEFAULT_MAX_ACTIVE_TARGETS = 2
DEFAULT_LEASE_TTL_SECONDS = 600
DEFAULT_MEMORY_RESERVE_MB = 4096
_MAX_CHILD_MEMORY_SAMPLES = 10000


@dataclass(frozen=True)
class Lease:
    lease_id: str
    target_key: str
    target_value: str
    target_type: str
    engagement_id: int
    slot_count: int
    owner_pid: int
    owner_token: str
    kind: str  # "start" | "resume"
    acquired_at: str  # ISO-8601 UTC
    heartbeat_at: str  # ISO-8601 UTC
    expires_at: str  # ISO-8601 UTC
    status: str  # "active" | "released" | "reaped"
    released_at: Optional[str] = None
    release_reason: Optional[str] = None
    provider: str = ""


@dataclass(frozen=True)
class LeaseAcquireResult:
    acquired: bool
    lease: Optional[Lease]
    reason: str  # "ok" | "slots_exhausted" | "max_active_targets_reached" | "target_already_active" | "kill_switch_active"
    allocated_slots: int = 0


@dataclass(frozen=True)
class BudgetSnapshot:
    total_slots: int
    leased_slots: int
    available_slots: int
    max_active_targets: int
    active_targets_count: int
    active_leases_count: int


def scheduler_db_path(data_dir: Path | str | None = None) -> Path:
    """Return path to <data_dir>/scheduler.db, ensuring parent directory exists."""
    if data_dir is not None:
        base = Path(data_dir)
    else:
        try:
            base = ForgeConfig.load().data_dir
        except Exception:
            base = Path.home() / ".forge" / "data"
    path = base / "scheduler.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def kill_switch_path(data_dir: Path | str | None = None) -> Path:
    """Return path to kill switch sentinel file."""
    env_path = os.environ.get("FORGE_AUTOPILOT_KILL_SWITCH_FILE", "").strip()
    if env_path:
        return Path(env_path)
    if data_dir is not None:
        base = Path(data_dir)
    else:
        try:
            base = ForgeConfig.load().data_dir
        except Exception:
            base = Path.home() / ".forge" / "data"
    return base / DEFAULT_KILL_SWITCH_FILENAME


def is_kill_switch_active(
    data_dir: Path | str | None = None,
    kill_switch_file: Path | None = None,
) -> bool:
    """Return True if kill switch sentinel file exists, halting starts and resumes."""
    if kill_switch_file is not None:
        return Path(kill_switch_file).is_file()
    path = kill_switch_path(data_dir)
    return path.is_file()


def ensure_scheduler_schema(con: sqlite3.Connection) -> None:
    """Idempotently create the leases table and its indices."""
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS leases (
            lease_id        TEXT PRIMARY KEY,
            target_key      TEXT NOT NULL,
            target_value    TEXT NOT NULL,
            target_type     TEXT NOT NULL,
            engagement_id   INTEGER NOT NULL,
            slot_count      INTEGER NOT NULL DEFAULT 1,
            owner_pid       INTEGER NOT NULL,
            owner_token     TEXT NOT NULL,
            kind            TEXT NOT NULL DEFAULT 'start',
            acquired_at     TEXT NOT NULL,
            heartbeat_at    TEXT NOT NULL,
            expires_at      TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'active',
            released_at     TEXT,
            release_reason  TEXT,
            provider        TEXT NOT NULL DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_leases_status ON leases(status);
        CREATE INDEX IF NOT EXISTS idx_leases_target_key_status ON leases(target_key, status);
        CREATE INDEX IF NOT EXISTS idx_leases_engagement_status ON leases(engagement_id, status);
        CREATE INDEX IF NOT EXISTS idx_leases_expires ON leases(expires_at) WHERE status = 'active';
        CREATE INDEX IF NOT EXISTS idx_leases_provider_status ON leases(provider, status);

        CREATE TABLE IF NOT EXISTS tuning_overrides (
            key TEXT PRIMARY KEY CHECK (key IN ('global_slots', 'max_active_targets')),
            value INTEGER NOT NULL,
            updated_at TEXT NOT NULL,
            applied_decision_id TEXT
        );
        CREATE TABLE IF NOT EXISTS tuning_approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            slot_delta INTEGER NOT NULL,
            target_delta INTEGER NOT NULL,
            approver TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT,
            consumed_by_decision_id TEXT
        );
        """
    )
    cur = con.execute("PRAGMA table_info(leases)")
    cols = {row[1] for row in cur.fetchall()}
    if "provider" not in cols:
        try:
            con.execute("ALTER TABLE leases ADD COLUMN provider TEXT NOT NULL DEFAULT ''")
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_leases_provider_status ON leases(provider, status)"
            )
        except sqlite3.OperationalError:
            pass
    try:
        from forge.autopilot.breaker import ensure_breaker_schema

        ensure_breaker_schema(con)
    except Exception:
        pass


def _read_tuning_overrides(
    data_dir: Path | str | None, slots: int, targets: int
) -> tuple[int, int]:
    """Resolve configured limits from durable scheduler overrides when present."""
    con = direct_connect(scheduler_db_path(data_dir))
    try:
        ensure_scheduler_schema(con)
        rows = dict(con.execute("SELECT key, value FROM tuning_overrides"))
        return int(rows.get("global_slots", slots)), int(rows.get("max_active_targets", targets))
    finally:
        con.close()


def ensure_child_memory_schema(con: sqlite3.Connection) -> None:
    """Idempotently create aggregate child memory sample and p95 tables."""
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS child_memory_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            peak_rss_kb INTEGER NOT NULL,
            recorded_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS worker_memory_stats (
            key TEXT PRIMARY KEY,
            value_mb REAL NOT NULL,
            samples INTEGER NOT NULL,
            measured_at TEXT,
            updated_at TEXT NOT NULL
        );
        """
    )


def record_child_memory_sample(peak_rss_kb: Any, *, data_dir: Path | str | None = None) -> bool:
    """Persist an aggregate child RSS sample; telemetry failures never raise."""
    con = None
    try:
        if not isinstance(peak_rss_kb, int) or isinstance(peak_rss_kb, bool) or peak_rss_kb <= 0:
            return False
        con = direct_connect(scheduler_db_path(data_dir))
        ensure_child_memory_schema(con)
        con.execute(
            "INSERT INTO child_memory_samples (peak_rss_kb, recorded_at) VALUES (?, ?)",
            (peak_rss_kb, datetime.now(timezone.utc).isoformat()),
        )
        con.execute(
            "DELETE FROM child_memory_samples WHERE id NOT IN "
            "(SELECT id FROM child_memory_samples ORDER BY id DESC LIMIT ?)",
            (_MAX_CHILD_MEMORY_SAMPLES,),
        )
        con.commit()
        return True
    except Exception:
        return False
    finally:
        if con is not None:
            try:
                con.close()
            except Exception:
                pass


def compute_child_memory_p95(*, data_dir: Path | str | None = None) -> dict[str, Any] | None:
    """Compute measured p95 RSS for the operator.

    After a live run, read it with :func:`read_recorded_worker_memory_p95` or
    from cycle_end details ``worker_memory_p95``. Until T2.1c lands, apply the
    recorded ``p95_worker_memory_mb`` manually via
    ``FORGE_AUTOPILOT_P95_WORKER_MEMORY_MB``.
    """
    con = None
    try:
        con = direct_connect(scheduler_db_path(data_dir))
        ensure_child_memory_schema(con)
        rows = con.execute(
            "SELECT peak_rss_kb, recorded_at FROM child_memory_samples ORDER BY recorded_at, id"
        ).fetchall()
        if not rows:
            return None
        values = sorted(int(row[0]) for row in rows)
        p95_kb = values[max(0, math.ceil(0.95 * len(values)) - 1)]
        return {
            "p95_worker_memory_mb": p95_kb / 1024.0,
            "p95_worker_memory_kb": int(p95_kb),
            "samples": len(values),
            "measured_at": max(str(row[1]) for row in rows),
        }
    except Exception:
        return None
    finally:
        if con is not None:
            try:
                con.close()
            except Exception:
                pass


def record_worker_memory_p95(*, data_dir: Path | str | None = None) -> dict[str, Any] | None:
    """Store aggregate p95 and return the operator-readable value.

    After a live run, read it with :func:`read_recorded_worker_memory_p95` or
    from cycle_end details ``worker_memory_p95``. Until T2.1c lands, apply the
    recorded ``p95_worker_memory_mb`` manually via
    ``FORGE_AUTOPILOT_P95_WORKER_MEMORY_MB``.
    """
    computed = compute_child_memory_p95(data_dir=data_dir)
    if computed is None:
        return read_recorded_worker_memory_p95(data_dir=data_dir)
    con = None
    try:
        con = direct_connect(scheduler_db_path(data_dir))
        ensure_child_memory_schema(con)
        now = datetime.now(timezone.utc).isoformat()
        con.execute(
            "INSERT INTO worker_memory_stats (key, value_mb, samples, measured_at, updated_at) "
            "VALUES ('p95_worker_memory_mb', ?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value_mb=excluded.value_mb, "
            "samples=excluded.samples, measured_at=excluded.measured_at, updated_at=excluded.updated_at",
            (computed["p95_worker_memory_mb"], computed["samples"], computed["measured_at"], now),
        )
        con.commit()
        return {**computed, "updated_at": now}
    except Exception:
        return None
    finally:
        if con is not None:
            try:
                con.close()
            except Exception:
                pass


def read_recorded_worker_memory_p95(*, data_dir: Path | str | None = None) -> dict[str, Any] | None:
    """Read the stored p95 for the operator.

    After a live run, this value is also available in cycle_end details
    ``worker_memory_p95``. Until T2.1c lands, apply its
    ``p95_worker_memory_mb`` manually via
    ``FORGE_AUTOPILOT_P95_WORKER_MEMORY_MB``.
    """
    con = None
    try:
        con = direct_connect(scheduler_db_path(data_dir))
        ensure_child_memory_schema(con)
        row = con.execute(
            "SELECT value_mb, samples, measured_at, updated_at FROM worker_memory_stats "
            "WHERE key='p95_worker_memory_mb'"
        ).fetchone()
        if row is None:
            return None
        return {
            "p95_worker_memory_mb": float(row[0]),
            "samples": int(row[1]),
            "measured_at": row[2],
            "updated_at": row[3],
        }
    except Exception:
        return None
    finally:
        if con is not None:
            try:
                con.close()
            except Exception:
                pass


def resolve_p95_worker_memory_mb(
    config: ForgeConfig | None, *, data_dir: Path | str | None = None
) -> int:
    """Resolve p95 memory: config/env, then recorded measurement, then 0.

    The recorded value is the measured p95 from T2.1b. A value of 0 means
    unmeasured, so the worker budget falls back to configured slots.
    """
    try:
        cfg = getattr(config, "autopilot_p95_worker_memory_mb", 0) if config is not None else 0
        if isinstance(cfg, (int, float)) and not isinstance(cfg, bool) and cfg > 0:
            return int(cfg)
        recorded = read_recorded_worker_memory_p95(data_dir=data_dir)
        if recorded is not None:
            val = recorded.get("p95_worker_memory_mb")
            if isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0:
                return int(val)
    except Exception:
        return 0
    return 0


def compute_worker_budget(
    configured_slots: int = DEFAULT_GLOBAL_SLOTS,
    *,
    p95_worker_memory_mb: int = 0,
    memory_reserve_mb: int = DEFAULT_MEMORY_RESERVE_MB,
    mem_available_mb: int | None = None,
    effective_cpu_count: int | None = None,
) -> int:
    """Calculate effective worker budget W based on slots, RAM, and CPU.

    W = min(
        configured_global_slots,
        floor((MemAvailable - reserve_mb) / measured_p95_mb_per_worker),
        floor(effective_cpu_count * 0.75)
    )

    Callers resolve p95 via :func:`resolve_p95_worker_memory_mb`: explicit
    config/env first, recorded measurement second, and 0 when unmeasured, which
    makes W default strictly to configured_slots.
    """
    configured = max(0, int(configured_slots))
    if p95_worker_memory_mb <= 0:
        return configured

    if mem_available_mb is None:
        mem_available_mb = read_mem_available_mb()
    if mem_available_mb is None:
        mem_available_mb = memory_reserve_mb + (configured * p95_worker_memory_mb)

    if effective_cpu_count is None:
        effective_cpu_count = os.cpu_count() or 1

    cpu_slots = max(1, int(effective_cpu_count * 0.75))
    available_mem = mem_available_mb - memory_reserve_mb
    if available_mem <= 0:
        mem_slots = 0
    else:
        mem_slots = available_mem // p95_worker_memory_mb

    return max(0, min(configured, mem_slots, cpu_slots))


def read_mem_available_mb() -> int | None:
    """Read Linux MemAvailable in MiB, returning None when unavailable."""
    try:
        meminfo_path = Path("/proc/meminfo")
        if meminfo_path.is_file():
            for line in meminfo_path.read_text(encoding="utf-8").splitlines():
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except Exception:
        pass
    return None


def get_budget_snapshot(
    *,
    data_dir: Path | str | None = None,
    total_slots: int | None = None,
    max_active_targets: int | None = None,
    config: ForgeConfig | None = None,
) -> BudgetSnapshot:
    """Calculate and return current slot and target utilization against limits."""
    if config is None:
        try:
            config = ForgeConfig.load()
        except Exception:
            config = None

    configured_slots = getattr(config, "autopilot_global_slots", DEFAULT_GLOBAL_SLOTS) if config else DEFAULT_GLOBAL_SLOTS
    configured_targets = getattr(config, "autopilot_max_active_targets", DEFAULT_MAX_ACTIVE_TARGETS) if config else DEFAULT_MAX_ACTIVE_TARGETS
    configured_slots, configured_targets = _read_tuning_overrides(data_dir, configured_slots, configured_targets)

    if total_slots is None:
        cfg_slots = configured_slots
        p95_mem = resolve_p95_worker_memory_mb(config, data_dir=data_dir)
        reserve_mb = (
            getattr(config, "autopilot_memory_reserve_mb", DEFAULT_MEMORY_RESERVE_MB)
            if config
            else DEFAULT_MEMORY_RESERVE_MB
        )
        resolved_total_slots = compute_worker_budget(
            configured_slots=cfg_slots,
            p95_worker_memory_mb=p95_mem,
            memory_reserve_mb=reserve_mb,
        )
    else:
        resolved_total_slots = max(0, int(total_slots))

    if max_active_targets is None:
        resolved_max_targets = configured_targets
    else:
        resolved_max_targets = max(0, int(max_active_targets))

    db_path = scheduler_db_path(data_dir)
    con = direct_connect(db_path)
    try:
        ensure_scheduler_schema(con)
        cur = con.execute(
            """
            SELECT
                COUNT(*) as active_leases_count,
                COUNT(DISTINCT target_key) as active_targets_count,
                COALESCE(SUM(slot_count), 0) as leased_slots
            FROM leases
            WHERE status = 'active'
            """
        )
        row = cur.fetchone()
        active_leases_count = int(row[0]) if row else 0
        active_targets_count = int(row[1]) if row else 0
        leased_slots = int(row[2]) if row else 0
        available_slots = max(0, resolved_total_slots - leased_slots)
        return BudgetSnapshot(
            total_slots=resolved_total_slots,
            leased_slots=leased_slots,
            available_slots=available_slots,
            max_active_targets=resolved_max_targets,
            active_targets_count=active_targets_count,
            active_leases_count=active_leases_count,
        )
    finally:
        con.close()


def sample_process_resources() -> dict[str, float | int]:
    """Sample this process at call time; ru_maxrss units are platform-dependent (KB on Linux)."""
    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF)
        return {
            "memory_peak_kb": int(usage.ru_maxrss),
            "cpu_user_seconds": float(usage.ru_utime),
            "cpu_sys_seconds": float(usage.ru_stime),
        }
    except Exception:
        return {}


def provider_inflight_count(provider: str, *, data_dir: Path | str | None = None) -> int:
    """Return the active lease count for a provider, or zero if unavailable."""
    try:
        con = direct_connect(scheduler_db_path(data_dir))
        try:
            ensure_scheduler_schema(con)
            row = con.execute(
                "SELECT COUNT(*) FROM leases WHERE provider = ? AND status = 'active'",
                (provider,),
            ).fetchone()
            return int(row[0]) if row else 0
        finally:
            con.close()
    except Exception:
        return 0


def reap_stale_leases(
    *,
    data_dir: Path | str | None = None,
    now: datetime | None = None,
) -> list[str]:
    """Reap leases that have expired or whose owner PID has died.

    Finds all rows WHERE status = 'active':
      - If expires_at <= current_time: mark reaped (reason='expired_no_heartbeat').
      - If owner_pid is on localhost and os.kill(owner_pid, 0) raises ProcessLookupError:
        mark reaped (reason='owner_pid_dead').
    Returns list of reaped lease_ids.
    """
    db_path = scheduler_db_path(data_dir)
    con = direct_connect(db_path)
    try:
        ensure_scheduler_schema(con)
        ref_time = now or datetime.now(timezone.utc)
        reaped_ids: list[str] = []
        with con:
            cur = con.execute(
                "SELECT lease_id, owner_pid, expires_at FROM leases WHERE status = 'active'"
            )
            rows = cur.fetchall()
            for lease_id, owner_pid, expires_at_str in rows:
                is_expired = False
                try:
                    exp_dt = datetime.fromisoformat(expires_at_str)
                    if exp_dt.tzinfo is None:
                        exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                    if exp_dt <= ref_time:
                        is_expired = True
                except Exception:
                    is_expired = True

                if is_expired:
                    con.execute(
                        """
                        UPDATE leases
                        SET status = 'reaped', released_at = ?, release_reason = 'expired_no_heartbeat'
                        WHERE lease_id = ? AND status = 'active'
                        """,
                        (ref_time.isoformat(), lease_id),
                    )
                    reaped_ids.append(lease_id)
                    continue

                pid_dead = False
                try:
                    os.kill(int(owner_pid), 0)
                except ProcessLookupError:
                    pid_dead = True
                except PermissionError:
                    pid_dead = False
                except OSError:
                    pass

                if pid_dead:
                    con.execute(
                        """
                        UPDATE leases
                        SET status = 'reaped', released_at = ?, release_reason = 'owner_pid_dead'
                        WHERE lease_id = ? AND status = 'active'
                        """,
                        (ref_time.isoformat(), lease_id),
                    )
                    reaped_ids.append(lease_id)
        return reaped_ids
    finally:
        con.close()


def acquire_lease(
    *,
    target_key: str,
    target_value: str,
    target_type: str,
    engagement_id: int,
    requested_slots: int = 1,
    kind: str = "start",  # "start" | "resume"
    ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS,
    owner_token: str | None = None,
    data_dir: Path | str | None = None,
    config: ForgeConfig | None = None,
    provider: str | None = None,
) -> LeaseAcquireResult:
    """Atomically acquire a lease inside a SQLite transaction."""
    if is_kill_switch_active(data_dir=data_dir):
        return LeaseAcquireResult(
            acquired=False,
            lease=None,
            reason="kill_switch_active",
            allocated_slots=0,
        )

    from forge.autopilot.breaker import (
        canonical_provider,
        check_resource_pressure,
        is_global_paused,
        is_provider_paused,
    )

    pressured, pressure_reason = check_resource_pressure()
    if pressured:
        return LeaseAcquireResult(
            acquired=False,
            lease=None,
            reason=pressure_reason,
            allocated_slots=0,
        )
    if is_global_paused(data_dir=data_dir):
        return LeaseAcquireResult(
            acquired=False,
            lease=None,
            reason="global_circuit_breaker_active",
            allocated_slots=0,
        )

    resolved_provider = canonical_provider(provider or target_value or target_key)
    if is_provider_paused(resolved_provider, data_dir=data_dir):
        return LeaseAcquireResult(
            acquired=False,
            lease=None,
            reason="provider_circuit_breaker_active",
            allocated_slots=0,
        )

    reap_stale_leases(data_dir=data_dir)

    if config is None:
        try:
            config = ForgeConfig.load()
        except Exception:
            config = None

    cfg_slots = (
        getattr(config, "autopilot_global_slots", DEFAULT_GLOBAL_SLOTS)
        if config
        else DEFAULT_GLOBAL_SLOTS
    )
    cfg_slots, max_active_targets = _read_tuning_overrides(
        data_dir, cfg_slots,
        getattr(config, "autopilot_max_active_targets", DEFAULT_MAX_ACTIVE_TARGETS) if config else DEFAULT_MAX_ACTIVE_TARGETS,
    )
    p95_mem = resolve_p95_worker_memory_mb(config, data_dir=data_dir)
    reserve_mb = (
        getattr(config, "autopilot_memory_reserve_mb", DEFAULT_MEMORY_RESERVE_MB)
        if config
        else DEFAULT_MEMORY_RESERVE_MB
    )
    total_slots = compute_worker_budget(
        configured_slots=cfg_slots,
        p95_worker_memory_mb=p95_mem,
        memory_reserve_mb=reserve_mb,
    )
    provider_max_inflight = (
        getattr(config, "provider_max_inflight", 2)
        if config
        else int(os.environ.get("FORGE_PROVIDER_MAX_INFLIGHT", 2))
    )

    db_path = scheduler_db_path(data_dir)
    con = direct_connect(db_path)
    try:
        ensure_scheduler_schema(con)
        with con:
            cur = con.cursor()
            # 1. Inflight leases per provider
            if resolved_provider and resolved_provider != "unknown":
                cur.execute(
                    "SELECT COUNT(*) FROM leases WHERE provider = ? AND status = 'active'",
                    (resolved_provider,),
                )
                row = cur.fetchone()
                provider_active = int(row[0]) if row else 0
                if provider_active >= provider_max_inflight:
                    return LeaseAcquireResult(
                        acquired=False,
                        lease=None,
                        reason="provider_inflight_limit",
                        allocated_slots=0,
                    )

            # 2. Target already active
            cur.execute(
                "SELECT 1 FROM leases WHERE target_key = ? AND status = 'active' LIMIT 1",
                (target_key,),
            )
            if cur.fetchone() is not None:
                return LeaseAcquireResult(
                    acquired=False,
                    lease=None,
                    reason="target_already_active",
                    allocated_slots=0,
                )

            # 3. Max active targets reached
            cur.execute("SELECT COUNT(DISTINCT target_key) FROM leases WHERE status = 'active'")
            row = cur.fetchone()
            active_targets_count = int(row[0]) if row else 0
            if active_targets_count >= max_active_targets:
                return LeaseAcquireResult(
                    acquired=False,
                    lease=None,
                    reason="max_active_targets_reached",
                    allocated_slots=0,
                )

            # 4. Slots exhausted
            cur.execute("SELECT COALESCE(SUM(slot_count), 0) FROM leases WHERE status = 'active'")
            row = cur.fetchone()
            leased_slots = int(row[0]) if row else 0
            available_slots = total_slots - leased_slots
            if available_slots < 1:
                return LeaseAcquireResult(
                    acquired=False,
                    lease=None,
                    reason="slots_exhausted",
                    allocated_slots=0,
                )

            # 5. Slot allocation (partial allocation if available < requested)
            req = requested_slots if requested_slots > 0 else 1
            granted = min(req, available_slots)

            lease_id = str(uuid.uuid4())
            owner_pid = os.getpid()
            token = owner_token or secrets.token_hex(16)
            now = datetime.now(timezone.utc)
            acquired_at = now.isoformat()
            heartbeat_at = acquired_at
            expires_at = (now + timedelta(seconds=max(1, ttl_seconds))).isoformat()

            cur.execute(
                """
                INSERT INTO leases (
                    lease_id, target_key, target_value, target_type, engagement_id,
                    slot_count, owner_pid, owner_token, kind,
                    acquired_at, heartbeat_at, expires_at, status, provider
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)
                """,
                (
                    lease_id,
                    target_key,
                    target_value,
                    target_type,
                    engagement_id,
                    granted,
                    owner_pid,
                    token,
                    kind,
                    acquired_at,
                    heartbeat_at,
                    expires_at,
                    resolved_provider,
                ),
            )
            lease = Lease(
                lease_id=lease_id,
                target_key=target_key,
                target_value=target_value,
                target_type=target_type,
                engagement_id=engagement_id,
                slot_count=granted,
                owner_pid=owner_pid,
                owner_token=token,
                kind=kind,
                acquired_at=acquired_at,
                heartbeat_at=heartbeat_at,
                expires_at=expires_at,
                status="active",
                provider=resolved_provider,
            )
            return LeaseAcquireResult(
                acquired=True,
                lease=lease,
                reason="ok",
                allocated_slots=granted,
            )
    finally:
        con.close()


def release_lease(
    lease_id: str,
    *,
    reason: str = "completed",
    data_dir: Path | str | None = None,
) -> bool:
    """Mark an active lease as released."""
    db_path = scheduler_db_path(data_dir)
    con = direct_connect(db_path)
    try:
        ensure_scheduler_schema(con)
        now = datetime.now(timezone.utc).isoformat()
        with con:
            cur = con.execute(
                """
                UPDATE leases
                SET status = 'released', released_at = ?, release_reason = ?
                WHERE lease_id = ? AND status = 'active'
                """,
                (now, reason, lease_id),
            )
            return cur.rowcount > 0
    finally:
        con.close()


def heartbeat(
    lease_id: str,
    *,
    ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS,
    data_dir: Path | str | None = None,
) -> bool:
    """Refresh the heartbeat and expiry timestamp for an active lease."""
    db_path = scheduler_db_path(data_dir)
    con = direct_connect(db_path)
    try:
        ensure_scheduler_schema(con)
        now = datetime.now(timezone.utc)
        hb_at = now.isoformat()
        exp_at = (now + timedelta(seconds=max(1, ttl_seconds))).isoformat()
        with con:
            cur = con.execute(
                """
                UPDATE leases
                SET heartbeat_at = ?, expires_at = ?
                WHERE lease_id = ? AND status = 'active'
                """,
                (hb_at, exp_at, lease_id),
            )
            return cur.rowcount > 0
    finally:
        con.close()


def list_active_leases(
    *,
    data_dir: Path | str | None = None,
    reap_stale: bool = True,
) -> list[Lease]:
    """Return all currently active leases, optionally reaping stale ones first."""
    if reap_stale:
        reap_stale_leases(data_dir=data_dir)
    db_path = scheduler_db_path(data_dir)
    con = direct_connect(db_path)
    try:
        ensure_scheduler_schema(con)
        con.row_factory = sqlite3.Row
        cur = con.execute("SELECT * FROM leases WHERE status = 'active' ORDER BY acquired_at ASC")
        rows = cur.fetchall()
        leases: list[Lease] = []
        for r in rows:
            prov = str(r["provider"]) if "provider" in r.keys() and r["provider"] else ""
            leases.append(
                Lease(
                    lease_id=str(r["lease_id"]),
                    target_key=str(r["target_key"]),
                    target_value=str(r["target_value"]),
                    target_type=str(r["target_type"]),
                    engagement_id=int(r["engagement_id"]),
                    slot_count=int(r["slot_count"]),
                    owner_pid=int(r["owner_pid"]),
                    owner_token=str(r["owner_token"]),
                    kind=str(r["kind"]),
                    acquired_at=str(r["acquired_at"]),
                    heartbeat_at=str(r["heartbeat_at"]),
                    expires_at=str(r["expires_at"]),
                    status=str(r["status"]),
                    released_at=str(r["released_at"]) if r["released_at"] else None,
                    release_reason=str(r["release_reason"]) if r["release_reason"] else None,
                    provider=prov,
                )
            )
        return leases
    finally:
        con.close()
