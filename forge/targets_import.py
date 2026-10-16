from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import logging
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

import httpx

from forge.autopilot.jitter import (
    burst_size,
    burst_pause_seconds,
    effective_start_delay,
)
from forge.autopilot.scheduler import (
    acquire_lease,
    get_budget_snapshot,
    is_kill_switch_active,
    provider_inflight_count,
    record_child_memory_sample,
    release_lease,
    sample_process_resources,
)
from forge.config import (
    ForgeConfig,
    normalize_roe_strictness,
    resolve_roe_strictness,
)
from forge.db.control import index_engagement_db_file
from forge.db.session import get_engagement_db
from forge.domain_validation import canonicalize_domain
from forge.engagement_ids import allocate_engagement_id, numeric_engagement_db_files
from forge.governance.scope_gate import is_roe_wildcard
from forge.onboard.patterns import is_denied_target
from forge.onboard.mega_domain import mega_domain_decision, mega_domain_signals
from forge.subprocess_tree import run_contained_subprocess
from forge.utils.kill_chain_options import (
    DEFAULT_KILL_CHAIN_MAX_RUNTIME_MINUTES,
    DEFAULT_KILL_CHAIN_PARALLEL_FANOUT,
)
from forge.utils.kill_chain_fanout import cap_fanout
from forge.utils.target_keys import external_target_key

_DEFAULT_SLEEP = time.sleep

TARGET_FEED_SCHEMA_VERSION = "target-feed.v1"
TARGET_IMPORT_MONITORING_POLICY_NAME = "Target import seed exposure"
TARGET_IMPORT_MONITORING_INTERVAL_MINUTES = 60
# Keep target import aligned with the shared kill-chain runtime default.
DEFAULT_TARGET_IMPORT_MAX_RUNTIME_MINUTES = DEFAULT_KILL_CHAIN_MAX_RUNTIME_MINUTES
TARGET_IMPORT_CHILD_TIMEOUT_GRACE_SECONDS = 120
TARGET_IMPORT_PROGRESS_EVENT_CANDIDATES = 250
TARGET_IMPORT_PROGRESS_EVENT_SECONDS = 60.0
TARGET_FAILURE_STDERR_MAX_BYTES = 2048
# Consecutive failed start attempts are bounded independently of the success limit.
# A successful start resets this counter; skipped candidates do not affect it.
MAX_CONSECUTIVE_START_FAILURES = 3
_LOG = logging.getLogger(__name__)
MAX_TARGET_FEED_FILE_BYTES = 64 * 1024 * 1024
MAX_TARGET_FEED_IMPORT_ITEMS = 100_000
SUPPORTED_TARGET_TYPES = {
    "apk_url",
    "api_spec",
    "artifact_url",
    "auto",
    "cloud_ref",
    "company",
    "domain",
    "email",
    "email_address",
    "fqdn",
    "handle",
    "host",
    "hostname",
    "ip",
    "ip_address",
    "ipv4",
    "ipv6",
    "name",
    "organization",
    "person",
    "phone",
    "subdomain",
    "tel",
    "telephone",
    "url",
    "username",
    "web_url",
    "website",
}
CANONICAL_TARGET_TYPES = {
    "apk_url",
    "api_spec",
    "cloud_ref",
    "company",
    "domain",
    "email",
    "ipv4",
    "ipv6",
    "name",
    "phone",
    "subdomain",
    "url",
    "username",
}
TARGET_TYPE_ALIASES = {
    "artifact_url": "artifact_url",
    "email_address": "email",
    "fqdn": "auto",
    "handle": "username",
    "host": "auto",
    "hostname": "auto",
    "ip": "auto",
    "ip_address": "auto",
    "organization": "company",
    "person": "name",
    "tel": "phone",
    "telephone": "phone",
    "web_url": "url",
    "website": "url",
}
@dataclass(frozen=True)
class TargetFeedItem:
    target_type: str
    target_value: str
    canonical_value: str
    target_key: str
    source_kind: str
    source_group: str
    source_groups: tuple[str, ...]
    source_count: int
    priority: int
    scan_eligible: bool
    scan_eligibility_reason: str
    confidence: float
    first_seen_at: str
    provenance: str


@dataclass(frozen=True)
class TargetImportResult:
    engagement_id: int | None
    target_type: str
    target_value: str
    target_key: str
    scope_manifest: Path | None
    created: bool
    started: bool
    dry_run: bool
    source_count: int = 1
    priority: int = 60
    scan_eligible: bool = True
    scan_eligibility_reason: str = "eligible"
    start_skipped_reason: str = ""
    start_failed: bool = False
    start_error_type: str = ""
    start_stop_reason: str = ""
    unprocessed_count: int = 0


@dataclass
class _TargetImportCounters:
    starts_remaining: int | None
    consecutive_start_failures: int = 0
    successful_starts: int = 0
    lock: threading.RLock = dataclass_field(default_factory=threading.RLock, repr=False)
    stop_admission: bool = False


def load_target_feed(
    *,
    feed_url: str | None,
    feed_file: Path | None,
    auth_header_env: str | None,
    limit: int | None,
    mega_domain_signal_provider: Callable[[str], tuple[float | None, int | None]] | None = None,
) -> list[TargetFeedItem]:
    if bool(feed_url) == bool(feed_file):
        raise ValueError("specify exactly one of --feed-url or --feed-file")
    payload = _fetch_feed(feed_url, auth_header_env) if feed_url else _read_feed_file(feed_file)
    if not isinstance(payload, dict):
        raise ValueError("target feed must decode to a JSON object")
    schema_version = str(payload.get("schema_version") or "").strip()
    if schema_version != TARGET_FEED_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported target feed schema_version={schema_version!r}; "
            f"expected {TARGET_FEED_SCHEMA_VERSION!r}"
        )
    raw_items = payload.get("items")
    if not isinstance(raw_items, list):
        raise ValueError("target feed items must be a list")

    max_items = _normalize_limit(limit)
    ranked_items: list[tuple[int, TargetFeedItem]] = []
    seen: set[str] = set()
    for index, raw_item in enumerate(raw_items):
        item = _coerce_feed_item(raw_item, signal_provider=mega_domain_signal_provider)
        if item is None or item.target_key in seen:
            continue
        seen.add(item.target_key)
        ranked_items.append((index, item))
    ranked_items.sort(key=lambda ranked: (-ranked[1].priority, -ranked[1].source_count, ranked[0]))
    return [item for _, item in ranked_items[:max_items]]


def import_targets(
    *,
    feed_url: str | None,
    feed_file: Path | None,
    auth_header_env: str | None,
    roe_id: str | None,
    start: bool,
    dry_run: bool,
    limit: int | None,
    max_iter: int,
    max_runtime_minutes: int = DEFAULT_TARGET_IMPORT_MAX_RUNTIME_MINUTES,
    parallel_fanout: int = DEFAULT_KILL_CHAIN_PARALLEL_FANOUT,
    start_limit: int | None = None,
    min_start_source_count: int = 1,
    config: ForgeConfig | None = None,
    progress_callback: Callable[[str, dict[str, Any]], None] | None = None,
    roe_scope: str | None = None,
    roe_strictness: str | None = None,
    retry_after_seconds: float | None = None,
    roe_minimum_delay_seconds: float | None = None,
    sleep_fn: Callable[[float], None] | None = None,
    mega_domain_signal_provider: Callable[[str], tuple[float | None, int | None]] | None = None,
    max_active_targets: int = 2,
    _monotonic: Callable[[], float] = time.monotonic,
) -> list[TargetImportResult]:
    """Import feed targets and optionally start scoped kill chains.

    Starting stops after three consecutive failed start attempts. Only actual
    failed starts count; a successful start resets the streak, and skipped
    feed items neither count nor reset it. The terminal result records the
    stop reason and number of feed candidates left unprocessed.
    """
    if start and not dry_run and not str(roe_id or "").strip():
        raise ValueError("--start requires --roe-id so live execution is authorized")
    max_active_targets = max(1, int(max_active_targets))
    cfg = config or ForgeConfig.load()
    resolved_roe_scope = str(
        os.environ.get("FORGE_ROE_SCOPE", "") if roe_scope is None else roe_scope
    ).strip()
    resolved_roe_strictness = resolve_roe_strictness(roe_strictness, config=cfg)
    roe_wildcard = is_roe_wildcard({"roe_scope": resolved_roe_scope})
    sleep = sleep_fn if sleep_fn is not None else _DEFAULT_SLEEP
    items = load_target_feed(
        feed_url=feed_url,
        feed_file=feed_file,
        auth_header_env=auth_header_env,
        limit=limit,
        mega_domain_signal_provider=mega_domain_signal_provider or mega_domain_signals,
    )
    indexed_results: list[tuple[int, TargetImportResult]] = []
    counters = _TargetImportCounters(
        starts_remaining=_normalize_start_limit(start_limit)
    )
    min_start_sources = _normalize_min_start_source_count(min_start_source_count)
    existing_targets = _external_target_engagement_index(cfg)
    existing_targets_lock = threading.RLock()
    candidates = iter(enumerate(items))
    stopped = False
    evaluated = 0
    progress_reason_counts: dict[str, int] = {}
    last_progress_event_at = _monotonic()

    def emit_candidate_progress(result: TargetImportResult) -> None:
        """Emit bounded summaries: every 250 completions or 60 seconds.

        Batched events keep thousands of skipped feed items visible without
        creating a per-candidate event flood; the time threshold bounds silent
        stretches even when candidate processing is slow.
        """
        nonlocal evaluated, last_progress_event_at
        evaluated += 1
        reason = str(result.scan_eligibility_reason or "eligible")
        progress_reason_counts[reason] = progress_reason_counts.get(reason, 0) + 1
        now = _monotonic()
        if (
            progress_callback is not None
            and (evaluated % TARGET_IMPORT_PROGRESS_EVENT_CANDIDATES == 0
                 or now - last_progress_event_at >= TARGET_IMPORT_PROGRESS_EVENT_SECONDS)
        ):
            progress_callback("candidate_evaluation_progress", {
                "evaluated": evaluated,
                "skip_reason_counts": dict(progress_reason_counts),
                "top_skip_reasons": sorted(
                    progress_reason_counts.items(), key=lambda pair: (-pair[1], pair[0])
                )[:5],
            })
            last_progress_event_at = now
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_active_targets)
    pending: dict[concurrent.futures.Future[TargetImportResult], tuple[int, TargetFeedItem]] = {}
    burst_starts_by_strictness: dict[str, int] = {}

    def submit_next() -> bool:
        nonlocal stopped
        with counters.lock:
            if counters.stop_admission:
                stopped = True
        if stopped or (start and not dry_run and is_kill_switch_active(data_dir=cfg.data_dir)):
            stopped = True
            return False
        if start and not dry_run:
            with counters.lock:
                remaining = counters.starts_remaining
            if remaining is not None and remaining > 0 and sum(
                1 for _, candidate in pending.values() if candidate.scan_eligible
            ) >= remaining:
                return False
            with counters.lock:
                failed = counters.consecutive_start_failures
            if failed + sum(
                1 for _, candidate in pending.values() if candidate.scan_eligible
            ) >= MAX_CONSECUTIVE_START_FAILURES:
                return False
        try:
            item_index, item = next(candidates)
        except StopIteration:
            return False
        future = executor.submit(
            _run_one_import_target,
            item=item,
            item_index=item_index,
            items=items,
            config=cfg,
            existing_targets=existing_targets,
            existing_targets_lock=existing_targets_lock,
            counters=counters,
            min_start_sources=min_start_sources,
            start=start,
            dry_run=dry_run,
            roe_id=roe_id,
            roe_wildcard=roe_wildcard,
            roe_scope=resolved_roe_scope,
            roe_strictness=resolved_roe_strictness,
            max_iter=max_iter,
            max_runtime_minutes=max_runtime_minutes,
            parallel_fanout=parallel_fanout,
            progress_callback=progress_callback,
            sleep=sleep,
            retry_after_seconds=retry_after_seconds,
            roe_minimum_delay_seconds=roe_minimum_delay_seconds,
        )
        pending[future] = (item_index, item)
        return True

    try:
        initial_admission_limit = max_active_targets
        if start and not dry_run:
            initial_admission_limit = min(
                max_active_targets, burst_size(resolved_roe_strictness)
            )
        for _ in range(initial_admission_limit):
            if not submit_next():
                break
        while pending:
            future = next(concurrent.futures.as_completed(tuple(pending)))
            item_index, item = pending.pop(future)
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001 - isolate failures to one candidate
                result = TargetImportResult(
                    engagement_id=None,
                    target_type=item.target_type,
                    target_value=item.canonical_value,
                    target_key=item.target_key,
                    scope_manifest=None,
                    created=False,
                    started=False,
                    dry_run=dry_run,
                    source_count=item.source_count,
                    priority=item.priority,
                    scan_eligible=item.scan_eligible,
                    scan_eligibility_reason=item.scan_eligibility_reason,
                    start_failed=bool(start and not dry_run),
                    start_error_type=type(exc).__name__,
                )
            indexed_results.append((item_index, result))
            emit_candidate_progress(result)
            admit_replacement = True
            if result.started:
                with counters.lock:
                    burst_starts_by_strictness[resolved_roe_strictness] = (
                        burst_starts_by_strictness.get(resolved_roe_strictness, 0) + 1
                    )
                    burst_count = burst_starts_by_strictness[resolved_roe_strictness]
                burst_limit = burst_size(resolved_roe_strictness)
                if (
                    burst_count % burst_limit == 0
                    and item_index < len(items) - 1
                ):
                    sleep(burst_pause_seconds(resolved_roe_strictness))
                elif pending:
                    # Let the already-admitted candidates finish this burst
                    # before admitting candidates from the next one.
                    admit_replacement = False
            if result.start_stop_reason in (
                "consecutive_failure_budget_exhausted",
                "slots_exhausted",
                "max_active_targets_reached",
                "kill_switch_active",
                "global_circuit_breaker_active",
            ):
                stopped = True
                with counters.lock:
                    counters.stop_admission = True
            if not stopped and admit_replacement:
                submit_next()
    finally:
        executor.shutdown(wait=True)
    indexed_results.sort(key=lambda indexed: indexed[0])
    return [result for _, result in indexed_results]


def _run_one_import_target(
    *,
    item: TargetFeedItem,
    item_index: int,
    items: list[TargetFeedItem],
    config: ForgeConfig,
    existing_targets: dict[str, int],
    existing_targets_lock: threading.RLock,
    counters: _TargetImportCounters,
    min_start_sources: int,
    start: bool,
    dry_run: bool,
    roe_id: str | None,
    roe_wildcard: bool,
    roe_scope: str,
    roe_strictness: str,
    max_iter: int,
    max_runtime_minutes: int,
    parallel_fanout: int,
    progress_callback: Callable[[str, dict[str, Any]], None] | None,
    sleep: Callable[[float], None],
    retry_after_seconds: float | None,
    roe_minimum_delay_seconds: float | None,
) -> TargetImportResult:
    """Process one feed candidate, preserving import_targets' sequential behavior."""
    cfg = config
    with counters.lock:
        starts_remaining = counters.starts_remaining
    queue_start = time.monotonic()  # target enters the start queue here
    if dry_run:
        return TargetImportResult(
            engagement_id=None,
            target_type=item.target_type,
            target_value=item.canonical_value,
            target_key=item.target_key,
            scope_manifest=None,
            created=False,
            started=False,
            dry_run=True,
            source_count=item.source_count,
            priority=item.priority,
            scan_eligible=item.scan_eligible,
            scan_eligibility_reason=item.scan_eligibility_reason,
            start_skipped_reason="dry_run",
        )

    with existing_targets_lock:
        engagement_id, created = _create_or_reuse_engagement(cfg, item, existing_targets)
    if roe_wildcard:
        _write_engagement_scope_json(
            cfg, engagement_id=engagement_id,
            scope=_scope_json_for_item(item, roe_scope=roe_scope),
        )
    try:
        _ensure_target_import_monitoring(cfg, engagement_id=engagement_id, item=item)
    except Exception as exc:  # noqa: BLE001
        print(
            "warning: target import monitoring seed skipped "
            f"engagement={engagement_id} error={_bounded_text(exc, 180)}",
            file=sys.stderr,
        )
    manifest_path = _write_scope_manifest(cfg, engagement_id, item, roe_id, roe_scope)
    started = False
    start_failed = False
    start_error_type = ""
    start_skipped_reason = ""
    start_stop_reason = ""
    unprocessed_count = 0
    # The remainder of the original per-item path is kept in its original order.
    if (
        start
        and starts_remaining != 0
        and item.scan_eligible
        and item.source_count >= min_start_sources
        and not _has_kill_chain_run(cfg, engagement_id, item.canonical_value)
    ):
        if is_kill_switch_active(data_dir=cfg.data_dir):
            start_skipped_reason = "kill_switch_active"
            start_stop_reason = "kill_switch_active"
            unprocessed_count = len(items) - item_index - 1
        else:
            fanout_decision = cap_fanout(
                parallel_fanout, seed=item.canonical_value,
                target_type=item.target_type, roe_strictness=roe_strictness,
                requested_by="targets-import",
            )
            requested_slots = fanout_decision.effective
            lease_result = acquire_lease(
                target_key=item.target_key, target_value=item.canonical_value,
                target_type=item.target_type, engagement_id=engagement_id,
                requested_slots=requested_slots, kind="start", data_dir=cfg.data_dir,
                config=cfg,
            )
            provider_admission_blocked = False
            if lease_result.acquired and lease_result.lease is not None:
                from forge.autopilot.breaker import provider_admission_status

                try:
                    provider_admission_blocked = (
                        provider_admission_status(
                            item.canonical_value, data_dir=cfg.data_dir, phase="engagement"
                        ) == "BLOCKED"
                    )
                except Exception:
                    release_lease(
                        lease_result.lease.lease_id,
                        reason="provider_admission_check_failed",
                        data_dir=cfg.data_dir,
                    )
                    raise
                if provider_admission_blocked:
                    release_lease(
                        lease_result.lease.lease_id,
                        reason="provider_circuit_breaker_active",
                        data_dir=cfg.data_dir,
                    )
            queue_seconds = time.monotonic() - queue_start
            if provider_admission_blocked or not lease_result.acquired:
                start_skipped_reason = (
                    "provider_circuit_breaker_active"
                    if provider_admission_blocked else lease_result.reason
                )
                if not provider_admission_blocked and lease_result.reason in (
                    "slots_exhausted", "max_active_targets_reached",
                    "kill_switch_active", "global_circuit_breaker_active",
                ):
                    start_stop_reason = lease_result.reason
                    unprocessed_count = len(items) - item_index - 1
            else:
                lease = lease_result.lease
                effective_fanout = lease.slot_count if lease else requested_slots
                try:
                    snapshot = get_budget_snapshot(data_dir=cfg.data_dir, config=cfg)
                except Exception:
                    snapshot = None
                progress_details = {
                    "engagement_id": engagement_id,
                    "target_type": item.target_type,
                    "target_key": external_target_key(item.target_type, item.canonical_value),
                    "queue_seconds": round(queue_seconds, 6),
                    "requested_slots": requested_slots,
                    "effective_slots": effective_fanout,
                }
                if snapshot is not None:
                    progress_details.update({
                        "active_targets": snapshot.active_targets_count,
                        "leased_slots": snapshot.leased_slots,
                        "total_slots": snapshot.total_slots,
                    })
                progress_details.update(sample_process_resources())
                try:
                    parsed = datetime.fromisoformat(str(item.first_seen_at).replace("Z", "+00:00"))
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    delay = max(0.0, (datetime.now(timezone.utc) - parsed).total_seconds())
                    progress_details["scheduling_delay_seconds"] = round(delay, 3)
                except Exception:
                    pass
                try:
                    from forge.autopilot.breaker import (
                        canonical_provider, is_global_paused, is_provider_paused,
                    )
                    provider = canonical_provider(item.canonical_value)
                    progress_details["provider"] = provider
                    progress_details["provider_paused"] = bool(is_provider_paused(provider, data_dir=cfg.data_dir))
                    progress_details["global_paused"] = bool(is_global_paused(data_dir=cfg.data_dir))
                    progress_details["provider_inflight"] = provider_inflight_count(provider, data_dir=cfg.data_dir)
                except Exception:
                    for key in ("provider", "provider_paused", "global_paused", "provider_inflight"):
                        progress_details.pop(key, None)
                _notify_progress(progress_callback, "target_engaged", progress_details)
                try:
                    _start_kill_chain(
                        engagement_id=engagement_id, seed=item.canonical_value,
                        target_type=item.target_type, roe_id=str(roe_id or "").strip(),
                        scope_manifest=manifest_path, max_iter=max_iter,
                        max_runtime_minutes=max_runtime_minutes,
                        parallel_fanout=effective_fanout,
                        engagement_db_path=cfg.engagement_db_path(str(engagement_id)),
                        roe_strictness=roe_strictness, config=cfg, sleep_fn=sleep,
                        retry_after_seconds=retry_after_seconds,
                        roe_minimum_delay_seconds=roe_minimum_delay_seconds,
                    )
                except Exception as exc:
                    try:
                        from forge.autopilot.breaker import record_child_failure

                        record_child_failure(
                            provider=item.canonical_value,
                            reason=("timeout" if isinstance(exc, subprocess.CalledProcessError) and exc.returncode == 124 else type(exc).__name__),
                            data_dir=cfg.data_dir,
                        )
                    except Exception:
                        pass
                    failure_details: dict[str, Any] = {
                        **progress_details, "error_type": type(exc).__name__,
                        "exit_status": "failed",
                    }
                    if isinstance(exc, subprocess.CalledProcessError):
                        failure_details.update({
                            "return_code": exc.returncode,
                            "argv": _sanitize_failure_argv(exc.cmd),
                            "stderr_tail": _bounded_failure_stderr(exc.stderr),
                        })
                        if exc.returncode == 124:
                            from forge.orchestration.run_tracking import mark_timed_out_kill_chain_run_failed
                            mark_timed_out_kill_chain_run_failed(
                                cfg.engagement_db_path(str(engagement_id)),
                                engagement_id=engagement_id, seed_value=item.canonical_value,
                            )
                    _notify_progress(progress_callback, "target_failed", failure_details)
                    start_failed = True
                    start_error_type = type(exc).__name__
                    with counters.lock:
                        counters.consecutive_start_failures += 1
                        exhausted = counters.consecutive_start_failures >= MAX_CONSECUTIVE_START_FAILURES
                        if exhausted:
                            counters.stop_admission = True
                    if exhausted:
                        start_stop_reason = "consecutive_failure_budget_exhausted"
                        unprocessed_count = len(items) - item_index - 1
                else:
                    try:
                        from forge.autopilot.breaker import record_probe_success

                        record_probe_success(
                            item.canonical_value, data_dir=cfg.data_dir, phase="engagement"
                        )
                    except Exception:
                        pass
                    _notify_progress(progress_callback, "target_completed", {**progress_details, "exit_status": "completed"})
                    started = True
                    with counters.lock:
                        counters.consecutive_start_failures = 0
                        counters.successful_starts += 1
                        successful_starts = counters.successful_starts
                        if counters.starts_remaining is not None:
                            counters.starts_remaining -= 1
                        starts_remaining_after = counters.starts_remaining
                    if starts_remaining_after == 0:
                        start_stop_reason = "start_limit_reached"
                finally:
                    if lease is not None:
                        release_lease(
                            lease.lease_id,
                            reason="failed" if start_failed else "completed",
                            data_dir=cfg.data_dir,
                        )
    elif start and not item.scan_eligible:
        start_skipped_reason = item.scan_eligibility_reason
    elif start and item.source_count < min_start_sources:
        start_skipped_reason = f"source_count_below_min_start_threshold:{item.source_count}<{min_start_sources}"
    elif start and starts_remaining == 0:
        start_skipped_reason = "start_limit_reached"
    if start and not dry_run and not start_stop_reason and counters.starts_remaining != 0 and item_index == len(items) - 1:
        start_stop_reason = "no_more_candidates"
    return TargetImportResult(
        engagement_id=engagement_id, target_type=item.target_type,
        target_value=item.canonical_value, target_key=item.target_key,
        scope_manifest=manifest_path, created=created, started=started, dry_run=False,
        source_count=item.source_count, priority=item.priority,
        scan_eligible=item.scan_eligible,
        scan_eligibility_reason=item.scan_eligibility_reason,
        start_skipped_reason=start_skipped_reason, start_failed=start_failed,
        start_error_type=start_error_type, start_stop_reason=start_stop_reason,
        unprocessed_count=unprocessed_count,
    )


def _notify_progress(
    callback: Callable[[str, dict[str, Any]], None] | None,
    event_type: str,
    details: dict[str, Any],
) -> None:
    if callback is None:
        return
    try:
        callback(event_type, details)
    except Exception as exc:  # noqa: BLE001 - progress observers cannot affect engagement work
        _LOG.warning("target progress callback failed: %s", type(exc).__name__)


_SENSITIVE_ARGUMENT_RE = re.compile(
    r"(?i)(?:token|secret|password|passwd|credential|api[-_]?key|"
    r"(?:^|[-_])key(?:$|[-_])|authorization|bearer)"
)
_ENV_ASSIGNMENT_RE = re.compile(
    r"(\b[A-Z_][A-Z0-9_]*\s*=\s*)([^\s&,;]+)"
)
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:[A-Z_][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY)|"
    r"token|secret|password|passwd|credential|api[-_]?key|authorization|bearer)"
    r"\s*[=:]\s*)([^\s&,;]+)"
)
_BEARER_VALUE_RE = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/-]+=*")
_POSIX_ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9:/])/(?!/)[^\s\"'<>|,;]+")
_WINDOWS_ABSOLUTE_PATH_RE = re.compile(r"(?i)\b[A-Z]:\\[^\s\"'<>|,;]+")


def _sanitize_failure_text(value: object) -> str:
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value or "")
    text = _ENV_ASSIGNMENT_RE.sub(r"\1[REDACTED]", text)
    text = _SENSITIVE_ASSIGNMENT_RE.sub(r"\1[REDACTED]", text)
    text = _BEARER_VALUE_RE.sub(r"\1[REDACTED]", text)
    text = _POSIX_ABSOLUTE_PATH_RE.sub("[REDACTED_PATH]", text)
    return _WINDOWS_ABSOLUTE_PATH_RE.sub("[REDACTED_PATH]", text)


def _sanitize_failure_argv(command: object) -> list[str]:
    if isinstance(command, (list, tuple)):
        tokens = [str(token) for token in command]
    elif isinstance(command, bytes):
        tokens = [command.decode("utf-8", errors="replace")]
    elif isinstance(command, str):
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = command.split()
    else:
        tokens = [str(command)]

    sanitized: list[str] = []
    redact_next = False
    for token in tokens:
        if redact_next:
            sanitized.append("[REDACTED]")
            redact_next = False
            continue

        option, separator, _value = token.partition("=")
        if option.startswith("-") and _SENSITIVE_ARGUMENT_RE.search(option):
            if separator:
                sanitized.append(f"{_sanitize_failure_text(option)}=[REDACTED]")
            else:
                sanitized.append(_sanitize_failure_text(option))
                redact_next = True
            continue
        sanitized.append(_sanitize_failure_text(token))
    return sanitized


def _bounded_failure_stderr(value: object) -> str:
    text = _sanitize_failure_text(value)
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= TARGET_FAILURE_STDERR_MAX_BYTES:
        return text
    tail = encoded[-TARGET_FAILURE_STDERR_MAX_BYTES :].decode("utf-8", errors="replace")
    return f"[stderr truncated; showing last {TARGET_FAILURE_STDERR_MAX_BYTES} bytes]\n{tail}"


def _fetch_feed(feed_url: str | None, auth_header_env: str | None) -> Any:
    assert feed_url is not None
    headers: dict[str, str] = {}
    if auth_header_env:
        env_name = str(auth_header_env).strip()
        if not env_name:
            raise ValueError("--auth-header-env cannot be blank")
        header_value = os.environ.get(env_name)
        if not header_value:
            raise ValueError(f"auth header environment variable is not set: {env_name}")
        if ":" in header_value:
            name, value = header_value.split(":", 1)
            if name.strip() and value.strip():
                headers[name.strip()] = value.strip()
            else:
                raise ValueError(f"invalid auth header value in environment variable: {env_name}")
        else:
            headers["X-Monitor-Key"] = header_value
    response = httpx.get(feed_url, headers=headers, timeout=15.0)
    response.raise_for_status()
    return response.json()


def _read_feed_file(feed_file: Path | None) -> Any:
    assert feed_file is not None
    path = Path(feed_file).expanduser()
    if path.stat().st_size > MAX_TARGET_FEED_FILE_BYTES:
        raise ValueError("target feed file is too large: exceeds 64 MiB cap")
    return json.loads(path.read_text(encoding="utf-8"))


def _normalize_limit(limit: int | None) -> int:
    if limit is None:
        return 100
    value = int(limit)
    if value <= 0:
        raise ValueError("--limit must be greater than zero")
    return min(value, MAX_TARGET_FEED_IMPORT_ITEMS)


def _normalize_start_limit(start_limit: int | None) -> int | None:
    if start_limit is None:
        return None
    value = int(start_limit)
    if value <= 0:
        raise ValueError("--start-limit must be greater than zero")
    return value


def _normalize_min_start_source_count(value: int | None) -> int:
    try:
        normalized = int(value) if value is not None else 1
    except (TypeError, ValueError):
        raise ValueError("--min-start-source-count must be an integer") from None
    if normalized < 1:
        raise ValueError("--min-start-source-count must be at least 1")
    return min(normalized, 100)


def _coerce_feed_item(
    raw_item: object,
    *,
    signal_provider: Callable[[str], tuple[float | None, int | None]] | None = None,
) -> TargetFeedItem | None:
    if not isinstance(raw_item, dict):
        return None
    raw_target_type = str(raw_item.get("target_type") or "").strip().lower()
    if raw_target_type not in SUPPORTED_TARGET_TYPES:
        return None
    raw_target_value = str(raw_item.get("target_value") or "")
    target_value = raw_target_value.strip()
    if is_denied_target(target_value):
        return None
    try:
        normalized = _normalize_target_value(raw_target_type, raw_target_value)
    except ValueError:
        return None
    if normalized is None:
        return None
    target_type, canonical_value = normalized
    if is_denied_target(canonical_value):
        return None
    target_key = external_target_key(target_type, canonical_value)
    candidate_domain: str | None = None
    if target_type in {"domain", "subdomain"}:
        candidate_domain = canonical_value
    elif target_type in {"url", "apk_url"}:
        host = urlsplit(canonical_value).hostname or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            candidate_domain = host
    source_group = _bounded_text(
        raw_item.get("source_group") or raw_item.get("source_kind"), 120
    )
    source_groups = _coerce_source_groups(raw_item.get("source_groups"), fallback=source_group)
    source_count = _coerce_source_count(raw_item.get("source_count"), source_groups)
    raw_age = raw_item.get("age_years")
    raw_subdomains = raw_item.get("estimated_subdomains")
    age_years: float | None = None
    if raw_age is not None:
        try:
            age_years = float(raw_age)
        except (ValueError, TypeError):
            age_years = None
    estimated_subdomains: int | None = None
    if raw_subdomains is not None:
        try:
            estimated_subdomains = int(raw_subdomains)
        except (ValueError, TypeError):
            estimated_subdomains = None
    if candidate_domain and signal_provider is not None and (age_years is None or estimated_subdomains is None):
        try:
            produced_age, produced_surface = signal_provider(candidate_domain)
            age_years = age_years if age_years is not None else produced_age
            estimated_subdomains = (
                estimated_subdomains if estimated_subdomains is not None else produced_surface
            )
        except Exception:  # noqa: BLE001
            pass
    scan_eligible, scan_reason = target_scan_eligible(
        target_type,
        canonical_value,
        age_years=age_years,
        estimated_subdomains=estimated_subdomains,
    )
    if raw_item.get("scan_eligible") is False:
        scan_eligible = False
        scan_reason = _bounded_text(raw_item.get("scan_eligibility_reason"), 80) or "feed_marked_ineligible"
    return TargetFeedItem(
        target_type=target_type,
        target_value=target_value,
        canonical_value=canonical_value,
        target_key=target_key,
        source_kind=_bounded_text(raw_item.get("source_kind"), 80),
        source_group=source_group,
        source_groups=source_groups,
        source_count=source_count,
        priority=_coerce_priority(
            raw_item.get("priority"),
            source_count=source_count,
            scan_eligible=scan_eligible,
        ),
        scan_eligible=scan_eligible,
        scan_eligibility_reason=scan_reason,
        confidence=_coerce_confidence(raw_item.get("confidence")),
        first_seen_at=_bounded_text(raw_item.get("first_seen_at"), 80),
        provenance=_bounded_text(raw_item.get("provenance"), 240),
    )


def _normalize_target_value(raw_target_type: str, value: str) -> tuple[str, str] | None:
    target_type = TARGET_TYPE_ALIASES.get(raw_target_type, raw_target_type)
    if target_type == "auto":
        target_type = _classify_target_value(value)
    if target_type == "artifact_url":
        canonical_url = _canonical_http_url_value(value)
        if not canonical_url:
            return None
        target_type = "apk_url" if _is_mobile_bundle_target_url(canonical_url) else "url"
        if target_type == "url" and _url_is_cloud_target(canonical_url):
            target_type = "cloud_ref"
        return target_type, canonical_url
    if target_type not in CANONICAL_TARGET_TYPES:
        return None
    canonical_value = _canonical_target_value(target_type, value)
    if not canonical_value:
        return None
    if target_type in {"domain", "subdomain"} and _hostname_is_cloud_target(canonical_value):
        return "cloud_ref", canonical_value
    if target_type == "url" and _url_is_cloud_target(canonical_value):
        return "cloud_ref", canonical_value
    return target_type, canonical_value


def _canonical_target_value(target_type: str, value: str) -> str:
    if target_type in {"domain", "subdomain"}:
        return _canonical_domain_value(value)
    text = " ".join(str(value or "").strip().split())
    if not text:
        return ""
    if target_type in {"url", "apk_url"}:
        return _canonical_http_url_value(text)
    if target_type == "cloud_ref":
        return _canonical_cloud_target_value(text)
    if target_type == "email":
        candidate = text.lower()
        return candidate if re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", candidate) else ""
    if target_type == "phone":
        return _normalize_phone_target_value(text)
    if target_type == "username":
        username = text[1:] if text.startswith("@") else text
        if re.match(r"^[A-Za-z0-9_.\-]{2,32}$", username):
            return f"@{username.lower()}"
        return ""
    if target_type in {"ipv4", "ipv6"}:
        return _canonical_ip_target_value(text, target_type)
    if target_type in {"name", "company"}:
        return text[:160]
    return ""


def _canonical_domain_value(value: str) -> str:
    return canonicalize_domain(value)


def _canonical_http_url_value(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return ""
    host = (parsed.hostname or "").lower().strip(".")
    if not host:
        return ""
    netloc = f"[{host}]" if ":" in host and not host.startswith("[") else host
    try:
        port = parsed.port
    except ValueError:
        return ""
    if port:
        netloc = f"{netloc}:{port}"
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))


def _canonical_cloud_target_value(value: str) -> str:
    from forge.cloud_ref import parse_cloud_ref  # noqa: PLC0415

    parsed_ref = parse_cloud_ref(value)
    if parsed_ref is not None:
        return parsed_ref.canonical_value

    try:
        from forge.engagement_orchestrator import _canonical_cloud_ref_value  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        _canonical_cloud_ref_value = None

    if _canonical_cloud_ref_value is not None:
        canonical_ref = _canonical_cloud_ref_value(value)
        if canonical_ref:
            return canonical_ref

    canonical_url = _canonical_http_url_value(value)
    if canonical_url and _url_is_cloud_target(canonical_url):
        return canonical_url

    host = " ".join(str(value or "").strip().split()).lower().strip(".")
    if host and "://" not in host and "/" not in host and "@" not in host and _hostname_is_cloud_target(host):
        return host
    return ""


def _canonical_ip_target_value(value: str, target_type: str) -> str:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return ""
    if target_type == "ipv4" and parsed.version != 4:
        return ""
    if target_type == "ipv6" and parsed.version != 6:
        return ""
    return str(parsed)


def _classify_target_value(value: str) -> str:
    try:
        from forge.engagement_orchestrator import _classify_seed_value  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return _fallback_classify_target_value(value)
    target_type = str(_classify_seed_value(str(value or "")) or "").strip().lower()
    return target_type if target_type in CANONICAL_TARGET_TYPES else ""


def _fallback_classify_target_value(value: str) -> str:
    text = " ".join(str(value or "").strip().split())
    if not text:
        return ""
    lowered = text.lower()
    if re.match(r"^\+\d{6,15}$", text):
        return "phone"
    if re.match(r"^@[a-z0-9_.\-]{2,32}$", lowered):
        return "username"
    try:
        parsed_ip = ipaddress.ip_address(text)
        return "ipv6" if parsed_ip.version == 6 else "ipv4"
    except ValueError:
        pass
    if _canonical_cloud_target_value(text):
        return "cloud_ref"
    parsed = urlsplit(text)
    if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
        return "apk_url" if _is_mobile_bundle_target_url(text) else "url"
    if re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", text):
        return "email"
    if _hostname_is_cloud_target(lowered):
        return "cloud_ref"
    if _canonical_domain_value(lowered):
        return "domain"
    return ""


def _is_mobile_bundle_target_url(value: str) -> bool:
    try:
        from forge.engagement_orchestrator import _is_mobile_bundle_url  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        parsed = urlsplit(value)
        return parsed.scheme.lower() in {"http", "https"} and parsed.path.lower().endswith(
            (".apk", ".ipa", ".aab", ".apkm", ".apks", ".xapk")
        )
    return bool(_is_mobile_bundle_url(str(value or "")))


def _hostname_is_cloud_target(hostname: str) -> bool:
    try:
        from forge.engagement_orchestrator import _hostname_is_cloud_ref  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return False
    return bool(_hostname_is_cloud_ref(str(hostname or "")))


def _url_is_cloud_target(value: str) -> bool:
    parsed = urlsplit(str(value or ""))
    return bool(parsed.netloc and _hostname_is_cloud_target(parsed.netloc))


def _normalize_phone_target_value(value: str) -> str:
    try:
        from forge.engagement_orchestrator import _normalize_phone_seed_value  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        candidate = re.sub(r"[^\d+]", "", str(value or "").strip())
        if candidate.startswith("00") and len(candidate) > 3:
            candidate = f"+{candidate[2:]}"
        return candidate if re.match(r"^\+\d{6,15}$", candidate) else ""
    return str(_normalize_phone_seed_value(value) or "")


def _coerce_confidence(value: object) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.5
    return min(max(confidence, 0.0), 1.0)


def _coerce_source_groups(value: object, *, fallback: str) -> tuple[str, ...]:
    groups: list[str] = []
    if isinstance(value, list):
        for raw_group in value:
            group = _bounded_text(raw_group, 120)
            if group and group not in groups:
                groups.append(group)
    if fallback and fallback not in groups:
        groups.append(fallback)
    return tuple(groups)


def _coerce_source_count(value: object, source_groups: tuple[str, ...]) -> int:
    try:
        raw_count = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raw_count = len(source_groups)
    return max(raw_count, len(source_groups), 1)


def _coerce_priority(value: object, *, source_count: int, scan_eligible: bool) -> int:
    try:
        raw_priority = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raw_priority = 90 if source_count >= 2 else 60
    if not scan_eligible:
        raw_priority = min(raw_priority, 10)
    return max(0, min(raw_priority, 100))


def _bounded_text(value: object, max_len: int) -> str:
    return " ".join(str(value or "").strip().split())[:max_len]


def target_scan_eligible(
    target_type: str,
    canonical_value: str,
    *,
    age_years: float | int | None = None,
    estimated_subdomains: int | None = None,
) -> tuple[bool, str]:
    """Return whether an imported target should consume autonomous live scan budget."""
    if target_type in {"ipv4", "ipv6"}:
        try:
            parsed_ip = ipaddress.ip_address(canonical_value)
        except ValueError:
            return False, "invalid_ip"
        # Bulk import keeps private/reserved IPs out of automatic scan budget;
        # an explicit ROE '*' only ungates execution after a target is selected.
        if not parsed_ip.is_global:
            return False, "non_global_ip"
    if target_type in {"url", "apk_url"}:
        host = urlsplit(canonical_value).hostname or ""
        try:
            parsed_host_ip = ipaddress.ip_address(host)
        except ValueError:
            parsed_host_ip = None
        if parsed_host_ip is not None and not parsed_host_ip.is_global:
            return False, "non_global_url_host"

    candidate_domain: str | None = None
    if target_type in {"domain", "subdomain"}:
        candidate_domain = canonical_value
    elif target_type in {"url", "apk_url"}:
        host = urlsplit(canonical_value).hostname or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            candidate_domain = host

    if candidate_domain:
        skip, reason = mega_domain_decision(
            candidate_domain,
            age_years=age_years,
            estimated_subdomains=estimated_subdomains,
        )
        if skip:
            return False, f"mega_domain_{reason}"

    return True, "eligible"


def _create_or_reuse_engagement(
    cfg: ForgeConfig,
    item: TargetFeedItem,
    existing_targets: dict[str, int],
) -> tuple[int, bool]:
    existing_id = existing_targets.get(item.target_key)
    if existing_id is not None:
        return existing_id, False

    engagement_id, db_path = _allocate_empty_target_import_engagement(cfg)
    conn = get_engagement_db(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()
        metadata = {
            "external_feed": TARGET_FEED_SCHEMA_VERSION,
            "external_target_key": item.target_key,
            "source_kind": item.source_kind,
            "source_group": item.source_group,
            "source_groups": list(item.source_groups),
            "source_count": item.source_count,
            "scan_priority": item.priority,
            "provenance_summary": item.provenance,
            "target_type": item.target_type,
            "target_value": item.canonical_value,
            "first_seen_at": item.first_seen_at,
            "confidence": item.confidence,
            "imported_at": now,
        }
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator, metadata_json)
            VALUES (?, ?, ?, 'ACTIVE', ?, ?)
            """,
            (
                engagement_id,
                f"external-target-{item.target_key[:12]}",
                json.dumps(_scope_json_for_item(item), sort_keys=True),
                cfg.operator,
                json.dumps(metadata, sort_keys=True),
            ),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, confidence, metadata_json)
            VALUES (?, ?, ?, 'scope', ?, ?)
            """,
            (
                engagement_id,
                item.canonical_value,
                item.target_type,
                item.confidence,
                json.dumps(
                    {
                        "external_feed": TARGET_FEED_SCHEMA_VERSION,
                        "external_target_key": item.target_key,
                    },
                    sort_keys=True,
                ),
            ),
        )
        conn.commit()
    finally:
        conn.close()
    index_engagement_db_file(cfg.data_dir, db_path, engagement_id=engagement_id)
    existing_targets[item.target_key] = engagement_id
    return engagement_id, True


def _allocate_empty_target_import_engagement(cfg: ForgeConfig) -> tuple[int, Path]:
    for _attempt in range(100):
        engagement_id = allocate_engagement_id(cfg.data_dir)
        db_path = cfg.engagement_db_path(str(engagement_id))
        if not _engagement_db_has_existing_engagement(db_path):
            return engagement_id, db_path
    raise RuntimeError("could not allocate an empty engagement database for target import")


def _engagement_db_has_existing_engagement(db_path: Path) -> bool:
    if not db_path.exists():
        return False
    conn = sqlite3.connect(db_path)
    try:
        tables = {
            str(row[0])
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if "engagements" not in tables:
            return False
        row = conn.execute("SELECT 1 FROM engagements LIMIT 1").fetchone()
        return row is not None
    except sqlite3.Error:
        return True
    finally:
        conn.close()


def _ensure_target_import_monitoring(
    cfg: ForgeConfig,
    *,
    engagement_id: int,
    item: TargetFeedItem,
) -> None:
    from forge.monitoring.continuous import (  # noqa: PLC0415
        create_monitoring_snapshot,
        upsert_monitoring_policy,
    )

    db_path = cfg.engagement_db_path(str(engagement_id))
    con = get_engagement_db(db_path)
    try:
        policy_row = con.execute(
            """
            SELECT id, last_snapshot_id
            FROM monitoring_policies
            WHERE engagement_id=? AND name=?
            LIMIT 1
            """,
            (engagement_id, TARGET_IMPORT_MONITORING_POLICY_NAME),
        ).fetchone()
        if policy_row is None:
            policy = upsert_monitoring_policy(
                con,
                engagement_id=engagement_id,
                name=TARGET_IMPORT_MONITORING_POLICY_NAME,
                enabled=True,
                schedule_interval_minutes=TARGET_IMPORT_MONITORING_INTERVAL_MINUTES,
                mode="passive",
                metadata={
                    "external_feed": TARGET_FEED_SCHEMA_VERSION,
                    "external_target_key": item.target_key,
                    "refresh": {"type": "seed_exposure"},
                    "source": "target_import",
                    "target_type": item.target_type,
                },
            )
        else:
            policy = {
                "id": int(policy_row["id"]),
                "last_snapshot_id": (
                    int(policy_row["last_snapshot_id"])
                    if policy_row["last_snapshot_id"] is not None
                    else None
                ),
            }

        if policy.get("last_snapshot_id"):
            return
        snapshot = create_monitoring_snapshot(
            con,
            engagement_id=engagement_id,
            policy_id=int(policy["id"]),
            snapshot_kind="manual",
            refresh={
                "status": "completed",
                "source": "target_import",
                "target_type": item.target_type,
            },
        )
        con.execute(
            """
            INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
            VALUES (?, 'monitoring', 'target_import', 'monitoring_policy_seeded', ?, ?, ?)
            """,
            (
                engagement_id,
                TARGET_IMPORT_MONITORING_POLICY_NAME,
                f"snapshot={snapshot['snapshot']['id']} target={item.target_type}",
                cfg.operator,
            ),
        )
        con.commit()
    finally:
        con.close()


def _external_target_engagement_index(cfg: ForgeConfig) -> dict[str, int]:
    targets: dict[str, int] = {}
    for db_path in numeric_engagement_db_files(cfg.data_dir):
        conn = sqlite3.connect(db_path)
        try:
            row = conn.execute(
                "SELECT id, metadata_json FROM engagements ORDER BY id LIMIT 1"
            ).fetchone()
        except sqlite3.Error:
            continue
        finally:
            conn.close()
        if not row:
            continue
        try:
            metadata = json.loads(str(row[1] or "{}"))
        except json.JSONDecodeError:
            metadata = {}
        target_key = metadata.get("external_target_key") if isinstance(metadata, dict) else None
        if isinstance(target_key, str) and target_key:
            targets[target_key] = int(row[0])
    return targets


def _scope_json_for_item(
    item: TargetFeedItem,
    *,
    roe_scope: str | None = None,
) -> dict[str, Any]:
    if is_roe_wildcard({"roe_scope": str(roe_scope or "").strip()}):
        return {
            "roe_scope": "*",
            "domains": ["*"],
            "authorized_seeds": ["*"],
            "ip_ranges": ["0.0.0.0/0", "::/0"],
            "urls": ["*"],
        }

    scope: dict[str, list[str]] = {"domains": [], "urls": []}
    if item.target_type in {"domain", "subdomain"}:
        scope["domains"] = [item.canonical_value]
    elif item.target_type in {"url", "apk_url"}:
        host = str(urlsplit(item.canonical_value).hostname or "").lower().strip(".")
        scope["domains"] = [host] if host else []
        scope["urls"] = [item.canonical_value]
    elif item.target_type == "cloud_ref":
        from forge.cloud_ref import engagement_scope, parse_cloud_ref  # noqa: PLC0415

        reference = parse_cloud_ref(item.canonical_value)
        if reference is not None:
            return engagement_scope(reference)
        parsed = urlsplit(item.canonical_value)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            host = str(parsed.hostname or "").lower().strip(".")
            scope["domains"] = [host] if host else []
            scope["urls"] = [item.canonical_value]
        elif _hostname_is_cloud_target(item.canonical_value):
            scope["domains"] = [item.canonical_value]
        scope["authorized_seeds"] = [item.canonical_value]
    elif item.target_type in {"ipv4", "ipv6"}:
        parsed_ip = ipaddress.ip_address(item.canonical_value)
        prefix = 32 if parsed_ip.version == 4 else 128
        scope["ip_ranges"] = [f"{parsed_ip}/{prefix}"]
        scope["authorized_seeds"] = [item.canonical_value]
    else:
        scope["authorized_seeds"] = [item.canonical_value]
    return scope


def _write_engagement_scope_json(
    cfg: ForgeConfig,
    *,
    engagement_id: int,
    scope: dict[str, Any],
) -> None:
    conn = get_engagement_db(cfg.engagement_db_path(str(engagement_id)))
    try:
        conn.execute(
            "UPDATE engagements SET scope_json=? WHERE id=?",
            (json.dumps(scope, sort_keys=True), engagement_id),
        )
        conn.commit()
    finally:
        conn.close()


def _write_scope_manifest(
    cfg: ForgeConfig,
    engagement_id: int,
    item: TargetFeedItem,
    roe_id: str | None,
    roe_scope: str | None = None,
) -> Path:
    manifest_dir = cfg.data_dir / "target_imports"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / f"scope_{engagement_id}_{item.target_key[:12]}.json"
    scope = _scope_json_for_item(item, roe_scope=roe_scope)
    payload = {
        "roe_id": str(roe_id or "").strip(),
        **({"roe_scope": "*"} if is_roe_wildcard(scope) else {}),
        "domains": scope.get("domains", []),
        "ip_ranges": scope.get("ip_ranges", []),
        "urls": scope.get("urls", []),
        "authorized_seeds": (
            ["*"] if is_roe_wildcard(scope) else [item.canonical_value]
        ),
        "policy": {
            "destructive_actions_allowed": True,
            "post_exploitation_allowed": True,
        },
        "metadata": {
            "external_feed": TARGET_FEED_SCHEMA_VERSION,
            "external_target_key": item.target_key,
            "target_type": item.target_type,
        },
    }
    manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return manifest_path


def _has_kill_chain_run(cfg: ForgeConfig, engagement_id: int, seed: str) -> bool:
    """Return whether this seed has any kill-chain history in the engagement.

    Failed and cancelled runs are considered by the resume phase when their
    resume gates pass; starting them fresh here would hide the run and reason.
    """
    db_path = cfg.engagement_db_path(str(engagement_id))
    if not db_path.exists():
        return False
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT 1
            FROM engagement_runs
            WHERE engagement_id=?
              AND run_kind='kill_chain'
              AND seed_value=?
            LIMIT 1
            """,
            (engagement_id, seed),
        ).fetchone()
    except sqlite3.Error:
        return False
    finally:
        conn.close()
    return row is not None


def _start_kill_chain(
    *,
    engagement_id: int,
    seed: str,
    target_type: str = "other",
    roe_id: str,
    scope_manifest: Path,
    max_iter: int,
    max_runtime_minutes: int,
    parallel_fanout: int,
    engagement_db_path: Path,
    roe_strictness: str | None = None,
    config: ForgeConfig | None = None,
    sleep_fn: Callable[[float], None] | None = None,
    retry_after_seconds: float | None = None,
    roe_minimum_delay_seconds: float | None = None,
) -> None:
    runtime_minutes = _normalize_max_runtime_minutes(max_runtime_minutes)
    resolved_strictness = resolve_roe_strictness(roe_strictness, config=config)
    sleep = sleep_fn if sleep_fn is not None else _DEFAULT_SLEEP
    # Start delay before the kill chain starts.
    sleep(effective_start_delay(
        resolved_strictness,
        retry_after_seconds=retry_after_seconds,
        roe_minimum_delay_seconds=roe_minimum_delay_seconds,
    ))
    fanout_decision = cap_fanout(
        parallel_fanout,
        seed=seed,
        target_type=target_type,
        roe_strictness=resolved_strictness,
        requested_by="targets-import",
    )
    fanout = fanout_decision.effective
    command = [
        sys.executable,
        "-m",
        "forge.cli",
        "kill-chain",
        seed,
        "--engagement",
        str(engagement_id),
        "--roe-id",
        roe_id,
        "--scope-manifest",
        str(scope_manifest),
        "--target-type",
        target_type,
        "--max-iter",
        str(max(1, int(max_iter))),
        "--max-runtime-minutes",
        str(runtime_minutes),
        "--parallel-fanout",
        str(fanout),
    ]
    timeout_seconds = runtime_minutes * 60 + TARGET_IMPORT_CHILD_TIMEOUT_GRACE_SECONDS
    proc = run_contained_subprocess(
        command,
        timeout_seconds=timeout_seconds,
        timeout_stderr=f"target import child exceeded timeout_seconds={timeout_seconds}",
        success_when=lambda: _completed_kill_chain_run(
            engagement_db_path,
            engagement_id=engagement_id,
            seed=seed,
        ),
    )
    peak = getattr(proc, "peak_rss_kb", None)
    if isinstance(peak, int) and not isinstance(peak, bool) and peak > 0:
        try:
            record_child_memory_sample(
                peak, data_dir=config.data_dir if config is not None else None
            )
        except Exception:
            pass
    if proc.stdout:
        sys.stdout.write(proc.stdout)
        sys.stdout.flush()
    if proc.stderr:
        sys.stderr.write(proc.stderr)
        sys.stderr.flush()
    if proc.returncode == 0:
        return
    combined_output = f"{proc.stdout or ''}\n{proc.stderr or ''}"
    if _completed_kill_chain_run(
        engagement_db_path,
        engagement_id=engagement_id,
        seed=seed,
    ):
        return
    if proc.returncode == 2 and "Kill-chain complete" in combined_output and "Report:" in combined_output:
        return
    raise subprocess.CalledProcessError(
        proc.returncode,
        command,
        output=proc.stdout,
        stderr=proc.stderr,
    )


def _normalize_max_runtime_minutes(value: int | None) -> int:
    if value is None:
        return DEFAULT_TARGET_IMPORT_MAX_RUNTIME_MINUTES
    return max(1, min(1440, int(value)))


def _completed_kill_chain_run(
    db_path: Path,
    *,
    engagement_id: int,
    seed: str,
) -> bool:
    if not db_path.exists():
        return False
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT 1
            FROM engagement_runs
            WHERE engagement_id=?
              AND run_kind='kill_chain'
              AND seed_value=?
              AND status='completed'
            LIMIT 1
            """,
            (engagement_id, seed),
        ).fetchone()
    except sqlite3.Error:
        return False
    finally:
        conn.close()
    return row is not None
