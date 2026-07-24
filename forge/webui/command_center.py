from __future__ import annotations

import json
import sqlite3
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from forge.config import ForgeConfig
from forge.db.session import get_engagement_db
from forge.distributed.coordinator import QueueCoordinator
from forge.distributed.scheduler import ScheduledTask, TaskScheduler
from forge.models.pydantic_models import (
    CommandAction,
    CommandActionStatus,
    CommandActionType,
    CommandEvent,
    CommandPolicyOutcome,
    CommandRiskLevel,
    CommandTargetType,
    SentryConfigModel,
)
from forge.utils.playbooks import inherit_roe_scope_context
from forge.webui.automation_scope import (
    AutomationScopeError,
    assert_automation_target_in_scope,
    has_roe_scope_context,
)


PublishEvent = Callable[[CommandEvent], None]

_TERMINAL_ACTION_STATUSES = {
    CommandActionStatus.SUCCEEDED,
    CommandActionStatus.FAILED,
    CommandActionStatus.CANCELLED,
    CommandActionStatus.ROLLED_BACK,
}

_ACTION_STATUS_TRANSITIONS: dict[CommandActionStatus, set[CommandActionStatus]] = {
    CommandActionStatus.SUGGESTED: {
        CommandActionStatus.QUEUED,
        CommandActionStatus.RUNNING,
        CommandActionStatus.CANCELLED,
    },
    CommandActionStatus.QUEUED: {
        CommandActionStatus.RUNNING,
        CommandActionStatus.CANCELLED,
        CommandActionStatus.FAILED,
    },
    CommandActionStatus.RUNNING: {
        CommandActionStatus.SUCCEEDED,
        CommandActionStatus.FAILED,
        CommandActionStatus.CANCELLED,
        CommandActionStatus.ROLLED_BACK,
    },
    CommandActionStatus.SUCCEEDED: {CommandActionStatus.ROLLED_BACK},
    CommandActionStatus.FAILED: set(),
    CommandActionStatus.CANCELLED: set(),
    CommandActionStatus.ROLLED_BACK: set(),
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat()


def _json_loads(raw: str | None, fallback: Any) -> Any:
    if not raw:
        return fallback
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return fallback
    return parsed


def _json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True)


def _severity_rank(level: str) -> int:
    ordering = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return ordering.get(level.lower(), 0)


def _task_status_to_action_status(task_status: str) -> CommandActionStatus:
    normalized = task_status.strip().lower()
    if normalized == "queued":
        return CommandActionStatus.QUEUED
    if normalized == "running":
        return CommandActionStatus.RUNNING
    if normalized == "done":
        return CommandActionStatus.SUCCEEDED
    if normalized == "failed":
        return CommandActionStatus.FAILED
    return CommandActionStatus.SUGGESTED


def validate_action_transition(
    current: CommandActionStatus, next_status: CommandActionStatus
) -> None:
    if next_status == current:
        return
    allowed = _ACTION_STATUS_TRANSITIONS.get(current, set())
    if next_status not in allowed:
        raise ValueError(f"Invalid action transition: {current.value} -> {next_status.value}")


class CommandCenterService:
    def __init__(
        self,
        engagement_id: int,
        config: ForgeConfig,
        coordinator: QueueCoordinator,
        publish_event: PublishEvent,
    ) -> None:
        self.engagement_id = engagement_id
        self._config = config
        self._coordinator = coordinator
        self._publish_event = publish_event
        self._db_path = config.engagement_db_path(str(engagement_id))

    def scheduler(self) -> TaskScheduler:
        return TaskScheduler(
            db_path=self._db_path,
            queue=self._coordinator,
            event_publisher=self._publish_scheduler_event,
        )

    def _publish_scheduler_event(self, engagement_id: int, message: str, payload: dict[str, Any]) -> None:
        severity = "critical" if "failed" in message else "info"
        event = CommandEvent(
            event_id=uuid.uuid4().hex,
            event_type=message,
            engagement_id=engagement_id,
            timestamp=utc_now(),
            payload=payload,
            severity=severity,
        )
        self.record_event(event)
        task_key = str(payload.get("task_key") or "")
        if task_key:
            self.sync_action_status_for_task(task_key)

    def record_event(self, event: CommandEvent, con: sqlite3.Connection | None = None) -> None:
        local_con = con if con is not None else get_engagement_db(self._db_path)
        try:
            local_con.execute(
                """
                INSERT OR IGNORE INTO command_center_timeline (
                    event_id,
                    engagement_id,
                    event_type,
                    severity,
                    acknowledged,
                    timestamp,
                    expires_at,
                    payload_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.engagement_id,
                    event.event_type,
                    event.severity,
                    int(event.acknowledged),
                    event.timestamp.isoformat(),
                    event.expires_at.isoformat() if event.expires_at else None,
                    _json_dumps(event.payload),
                ),
            )
            if con is None:
                local_con.commit()
        finally:
            if con is None:
                local_con.close()
        self._publish_event(event)

    def list_timeline(self, limit: int = 100) -> list[dict[str, Any]]:
        max_rows = min(max(limit, 1), 500)
        con = get_engagement_db(self._db_path)
        try:
            rows = con.execute(
                """
                SELECT event_id, event_type, severity, acknowledged, timestamp, expires_at, payload_json
                FROM command_center_timeline
                WHERE engagement_id=?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (self.engagement_id, max_rows),
            ).fetchall()
        finally:
            con.close()
        return [
            {
                "event_id": str(row[0]),
                "event_type": str(row[1]),
                "engagement_id": self.engagement_id,
                "severity": str(row[2]),
                "acknowledged": bool(row[3]),
                "timestamp": str(row[4]),
                "expires_at": str(row[5]) if row[5] is not None else None,
                "payload": _json_loads(str(row[6]) if row[6] is not None else None, {}),
            }
            for row in rows
        ]

    def acknowledge_alert(self, event_id: str) -> dict[str, str]:
        con = get_engagement_db(self._db_path)
        try:
            con.execute(
                """
                UPDATE command_center_timeline
                SET acknowledged=1
                WHERE engagement_id=? AND event_id=?
                """,
                (self.engagement_id, event_id),
            )
            con.commit()
        finally:
            con.close()
        event = CommandEvent(
            event_id=uuid.uuid4().hex,
            event_type="alert_acknowledged",
            engagement_id=self.engagement_id,
            timestamp=utc_now(),
            payload={"acknowledged_event_id": event_id},
        )
        self.record_event(event)
        return {"status": "acknowledged"}

    def get_sentry_state(self) -> SentryConfigModel:
        con = get_engagement_db(self._db_path)
        try:
            return self._load_sentry_state(con)
        finally:
            con.close()

    def toggle_sentry(self, enabled: bool) -> dict[str, Any]:
        con = get_engagement_db(self._db_path)
        try:
            state = self._load_sentry_state(con)
            updated = state.model_copy(update={"enabled": enabled, "updated_at": utc_now()})
            self._save_sentry_state(con, updated)
            con.commit()
        finally:
            con.close()
        event = CommandEvent(
            event_id=uuid.uuid4().hex,
            event_type="sentry_state_changed",
            engagement_id=self.engagement_id,
            timestamp=utc_now(),
            payload={"enabled": enabled},
            severity="warning" if not enabled else "info",
        )
        self.record_event(event)
        return {"status": "updated", "state": updated.model_dump(mode="json")}

    def emergency_stop(self) -> dict[str, Any]:
        con = get_engagement_db(self._db_path)
        try:
            state = self._load_sentry_state(con)
            updated = state.model_copy(
                update={
                    "emergency_stop": True,
                    "enabled": False,
                    "paused_reason": "emergency_stop",
                    "updated_at": utc_now(),
                }
            )
            self._save_sentry_state(con, updated)
            rows = con.execute(
                """
                SELECT action_id, params_json
                FROM command_center_actions
                WHERE engagement_id=?
                  AND execution_mode='autonomous'
                  AND status='queued'
                """,
                (self.engagement_id,),
            ).fetchall()
            cancelled_action_ids: list[str] = []
            cancelled_task_keys: list[str] = []
            for row in rows:
                action_id = str(row[0])
                params = _json_loads(str(row[1]) if row[1] is not None else None, {})
                task_key = str(params.get("task_key") or "")
                self._update_action_status(
                    con,
                    action_id=action_id,
                    next_status=CommandActionStatus.CANCELLED,
                    policy_reason="Cancelled by emergency stop.",
                )
                cancelled_action_ids.append(action_id)
                if task_key:
                    cancelled_task_keys.append(task_key)
                    con.execute(
                        """
                        UPDATE distributed_tasks
                        SET status='failed', error='autonomous task cancelled by emergency stop', updated_at=CURRENT_TIMESTAMP
                        WHERE engagement_id=? AND task_key=? AND status='queued'
                        """,
                        (self.engagement_id, task_key),
                    )
                    con.execute(
                        """
                        UPDATE task_progress
                        SET status='failed', completed_at=CURRENT_TIMESTAMP, checkpoint=?
                        WHERE engagement_id=? AND task_key=? AND status='pending'
                        """,
                        (
                            _json_dumps({"error": "autonomous task cancelled by emergency stop"}),
                            self.engagement_id,
                            task_key,
                        ),
                    )
            con.commit()
        finally:
            con.close()
        event = CommandEvent(
            event_id=uuid.uuid4().hex,
            event_type="emergency_stop_triggered",
            engagement_id=self.engagement_id,
            timestamp=utc_now(),
            payload={"cancelled_action_ids": cancelled_action_ids, "cancelled_task_keys": cancelled_task_keys},
            severity="critical",
        )
        self.record_event(event)
        return {"status": "stopped", "cancelled_actions": cancelled_action_ids}

    def list_asset_tree(self) -> list[dict[str, Any]]:
        con = get_engagement_db(self._db_path)
        try:
            self._refresh_action_statuses(con)
            port_rows = con.execute(
                """
                SELECT host, port, service, version, scanned_at
                FROM port_scan_results
                WHERE engagement_id=?
                ORDER BY scanned_at DESC
                """,
                (self.engagement_id,),
            ).fetchall()
            crawl_rows = con.execute(
                """
                SELECT COALESCE(final_url, url), title, discovered_at
                FROM crawl_results
                WHERE engagement_id=?
                ORDER BY discovered_at DESC
                """,
                (self.engagement_id,),
            ).fetchall()
            known_hosts = {
                str(row[0])
                for row in con.execute(
                    "SELECT ip FROM hosts WHERE engagement_id=? ORDER BY discovered_at DESC",
                    (self.engagement_id,),
                ).fetchall()
                if row[0]
            }
            ports_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
            urls_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for row in port_rows:
                host = str(row[0]) if row[0] is not None else "unknown"
                ports_by_host[host].append(
                    {
                        "port": int(row[1]),
                        "service": str(row[2]) if row[2] is not None else "",
                        "version": str(row[3]) if row[3] is not None else None,
                        "scanned_at": str(row[4]),
                    }
                )
            for row in crawl_rows:
                raw_url = str(row[0]) if row[0] is not None else ""
                parsed = urlparse(raw_url)
                host = parsed.hostname or parsed.netloc or "unknown"
                urls_by_host[host].append(
                    {
                        "url": raw_url,
                        "title": str(row[1]) if row[1] is not None else "",
                        "discovered_at": str(row[2]),
                    }
                )
            action_rows = con.execute(
                """
                SELECT target_ref, status
                FROM command_center_actions
                WHERE engagement_id=? AND target_type='host'
                """,
                (self.engagement_id,),
            ).fetchall()
            action_summary: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
            for row in action_rows:
                action_summary[str(row[0])][str(row[1])] += 1
            all_hosts = sorted(known_hosts | set(ports_by_host.keys()) | set(urls_by_host.keys()))
            items: list[dict[str, Any]] = []
            for host in all_hosts:
                context = self._build_host_context(con, host)
                items.append(
                    {
                        "host": host,
                        "status": context["status"],
                        "os_family": context["os_family"],
                        "services": context["services"],
                        "ports": ports_by_host.get(host, []),
                        "urls": urls_by_host.get(host, []),
                        "latest_findings": context["latest_findings"],
                        "credential_count": context["credential_count"],
                        "action_summary": {
                            "suggested": int(action_summary[host].get("suggested", 0)),
                            "queued": int(action_summary[host].get("queued", 0)),
                            "running": int(action_summary[host].get("running", 0)),
                            "failed": int(action_summary[host].get("failed", 0)),
                            "succeeded": int(action_summary[host].get("succeeded", 0)),
                            "cancelled": int(action_summary[host].get("cancelled", 0)),
                        },
                    }
                )
            return items
        finally:
            con.close()

    def _refresh_action_statuses(self, con: sqlite3.Connection) -> None:
        rows = con.execute(
            """
            SELECT action_id, params_json
            FROM command_center_actions
            WHERE engagement_id=? AND status IN ('queued', 'running')
            """,
            (self.engagement_id,),
        ).fetchall()
        for row in rows:
            action_id = str(row[0])
            params = _json_loads(str(row[1]) if row[1] is not None else None, {})
            task_key = params.get("task_key")
            if task_key:
                self._sync_action_status_for_task(con, str(task_key))

    def get_host_context(self, host: str) -> dict[str, Any]:
        with get_engagement_db(self._db_path) as con:
            self._refresh_action_statuses(con)
            state = self._load_sentry_state(con)
            context = self._build_host_context(con, host)
            dispatchable_ids = self._sync_host_actions(con, host, context, state)
            self._ensure_asset_discovered_event(con, host, context)
            self._maybe_emit_critical_finding(con, host, context, state)
            con.commit()
        for action_id in dispatchable_ids:
            self._try_autonomous_dispatch(action_id)
        with get_engagement_db(self._db_path) as con:
            self._refresh_action_statuses(con)
            context = self._build_host_context(con, host)
            actions = self._fetch_actions(con, host, include_hidden=False)
            context["actions"] = [action.model_dump(mode="json") for action in actions]
            context["sentry"] = self._load_sentry_state(con).model_dump(mode="json")
            return context

    def list_host_actions(self, host: str, include_hidden: bool = False) -> list[dict[str, Any]]:
        with get_engagement_db(self._db_path) as con:
            self._refresh_action_statuses(con)
            state = self._load_sentry_state(con)
            context = self._build_host_context(con, host)
            dispatchable_ids = self._sync_host_actions(con, host, context, state)
            con.commit()
        for action_id in dispatchable_ids:
            self._try_autonomous_dispatch(action_id)
        with get_engagement_db(self._db_path) as con:
            self._refresh_action_statuses(con)
            actions = self._fetch_actions(con, host, include_hidden=include_hidden)
            return [action.model_dump(mode="json") for action in actions]

    def approve_action(
        self,
        action_id: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        action = self._get_action(action_id)
        if action.status not in {CommandActionStatus.QUEUED, CommandActionStatus.SUGGESTED}:
            raise ValueError(f"Action {action_id} is not awaiting approval.")
        if action.policy_outcome == CommandPolicyOutcome.HIDDEN:
            raise ValueError(f"Action {action_id} is hidden and cannot be approved.")
        dispatched = self.dispatch_action(
            action_id,
            autonomous=action.execution_mode == "autonomous",
            context=context,
        )
        return {"status": "approved", "action": dispatched.model_dump(mode="json")}

    def execute_action(
        self,
        action_id: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        action = self.dispatch_action(action_id, autonomous=False, context=context)
        return {"status": "queued", "action": action.model_dump(mode="json")}

    def _try_autonomous_dispatch(self, action_id: str) -> None:
        try:
            self.dispatch_action(action_id, autonomous=True)
        except ValueError as exc:
            self.record_event(
                CommandEvent(
                    event_id=uuid.uuid4().hex,
                    event_type="action_dispatch_blocked",
                    engagement_id=self.engagement_id,
                    timestamp=utc_now(),
                    payload={"action_id": action_id, "reason": str(exc)},
                    severity="warning",
                )
            )

    def dispatch_action(
        self,
        action_id: str,
        autonomous: bool,
        context: dict[str, Any] | None = None,
    ) -> CommandAction:
        con = get_engagement_db(self._db_path)
        try:
            state = self._load_sentry_state(con)
            action = self._load_action_from_db(con, action_id)
            if autonomous and (state.emergency_stop or state.paused_reason):
                raise ValueError("Sentry is paused and autonomous dispatch is blocked.")
            if autonomous and action.policy_outcome == CommandPolicyOutcome.AUTO_EXECUTE:
                running_auto = con.execute(
                    """
                    SELECT COUNT(*)
                    FROM command_center_actions
                    WHERE engagement_id=? AND execution_mode='autonomous' AND status='running'
                    """,
                    (self.engagement_id,),
                ).fetchone()
                running_count = int(running_auto[0]) if running_auto is not None else 0
                if running_count >= state.max_concurrent_auto:
                    raise ValueError("Autonomous concurrency limit reached.")
            if action.status in _TERMINAL_ACTION_STATUSES:
                raise ValueError(f"Action {action_id} is already terminal: {action.status.value}")
            target, task_type, extra_payload = self._task_spec_for_action(action)
            task_key = f"{task_type}:{target or action.target_ref}"
            dispatch_payload = self._scoped_dispatch_payload(
                con,
                action,
                task_type=task_type,
                target=target,
                extra_payload=extra_payload,
                context=context,
            )
            updated_params = {**dispatch_payload, "task_key": task_key}
            execution_mode = "autonomous" if autonomous else "manual"
            updated_action = action.model_copy(
                update={
                    "status": CommandActionStatus.QUEUED,
                    "updated_at": utc_now(),
                    "params": updated_params,
                    "execution_mode": execution_mode,
                    "policy_reason": action.policy_reason or "Queued for execution.",
                }
            )
            self._persist_action(con, updated_action)
            con.commit()
        finally:
            con.close()
        scheduler = self.scheduler()
        scheduler.schedule(
            ScheduledTask(
                engagement_id=self.engagement_id,
                task_key=task_key,
                payload={
                    "task_type": task_type,
                    "engagement_id": self.engagement_id,
                    "action_id": action_id,
                    "dispatch_mode": execution_mode,
                    **updated_params,
                },
            )
        )
        event = CommandEvent(
            event_id=uuid.uuid4().hex,
            event_type="action_status_changed",
            engagement_id=self.engagement_id,
            timestamp=utc_now(),
            payload={
                "action_id": action_id,
                "status": CommandActionStatus.QUEUED.value,
                "task_key": task_key,
                "dispatch_mode": execution_mode,
            },
        )
        self.record_event(event)
        return self._get_action(action_id)

    def _scoped_dispatch_payload(
        self,
        con: sqlite3.Connection,
        action: CommandAction,
        *,
        task_type: str,
        target: str,
        extra_payload: dict[str, Any],
        context: dict[str, Any] | None,
    ) -> dict[str, Any]:
        payload = inherit_roe_scope_context(
            context or {},
            {
                **action.params,
                **extra_payload,
                "task_type": task_type,
                "target": target,
            },
        )
        reason = ""
        if not has_roe_scope_context(payload):
            reason = "command center dispatch requires roe_id and scope_manifest"
        else:
            try:
                assert_automation_target_in_scope(payload, target)
            except AutomationScopeError as exc:
                reason = exc.reason
        if reason:
            con.execute(
                """
                INSERT INTO audit_log
                    (engagement_id, phase, module, action, target, result, operator)
                VALUES (?, 'webui', 'command_center', 'command_center_scope_denied',
                        ?, ?, 'webui')
                """,
                (
                    self.engagement_id,
                    target,
                    f"task_type={task_type} reason={reason}"[:500],
                ),
            )
            con.commit()
            raise ValueError(reason)
        return payload

    def sync_action_status_for_task(self, task_key: str) -> None:
        with get_engagement_db(self._db_path) as con:
            self._sync_action_status_for_task(con, task_key)
            con.commit()

    def _task_spec_for_action(self, action: CommandAction) -> tuple[str, str, dict[str, Any]]:
        if action.action_type == CommandActionType.SCAN_PORTS:
            return action.target_ref, "ports", {}
        if action.action_type in {CommandActionType.CRAWL, CommandActionType.CONTENT_DISCOVERY}:
            target = str(action.params.get("target") or action.target_ref)
            return target, "crawl", {}
        if action.action_type == CommandActionType.VULN_SCAN:
            target = str(action.params.get("target") or action.target_ref)
            return target, "passive", {}
        if action.action_type in {
            CommandActionType.CREDENTIAL_TEST,
            CommandActionType.BRUTE_FORCE_POLICY_CHECK,
            CommandActionType.SHARE_ENUMERATION,
        }:
            return action.target_ref, "credential_test", {}
        if action.action_type == CommandActionType.EXPLOIT_ATTEMPT:
            target = str(action.params.get("target") or action.target_ref)
            return target, "auth-bypass", {}
        raise ValueError(f"Unsupported action type: {action.action_type.value}")

    def _sync_host_actions(
        self,
        con: sqlite3.Connection,
        host: str,
        context: dict[str, Any],
        state: SentryConfigModel,
    ) -> list[str]:
        dispatchable_ids: list[str] = []
        generated = self._generate_actions(host, context, state)
        for action in generated:
            existing = self._load_action_from_db_optional(con, action.action_id)
            stored = action if existing is None else self._merge_action(existing, action)
            self._persist_action(con, stored)
            if existing is None:
                self.record_event(
                    CommandEvent(
                        event_id=uuid.uuid4().hex,
                        event_type="action_suggested",
                        engagement_id=self.engagement_id,
                        timestamp=utc_now(),
                        payload={
                            "action_id": stored.action_id,
                            "host": host,
                            "action_type": stored.action_type.value,
                            "policy_outcome": stored.policy_outcome.value,
                        },
                        severity="warning" if stored.risk_level == CommandRiskLevel.CRITICAL else "info",
                    ),
                    con=con
                )
            if (
                state.enabled
                and stored.policy_outcome == CommandPolicyOutcome.AUTO_EXECUTE
                and stored.execution_mode == "autonomous"
                and stored.status == CommandActionStatus.SUGGESTED
            ):
                dispatchable_ids.append(stored.action_id)
        return dispatchable_ids

    def _merge_action(self, existing: CommandAction, generated: CommandAction) -> CommandAction:
        if existing.status in _TERMINAL_ACTION_STATUSES or existing.status == CommandActionStatus.RUNNING:
            return existing
        next_status = existing.status
        if generated.execution_mode == "autonomous" and generated.policy_outcome == CommandPolicyOutcome.QUEUE:
            next_status = CommandActionStatus.QUEUED
        elif generated.policy_outcome in {CommandPolicyOutcome.SUGGEST, CommandPolicyOutcome.AUTO_EXECUTE}:
            next_status = CommandActionStatus.SUGGESTED
        validate_action_transition(existing.status, next_status)
        return existing.model_copy(
            update={
                "confidence_score": generated.confidence_score,
                "risk_level": generated.risk_level,
                "requires_approval": generated.requires_approval,
                "updated_at": utc_now(),
                "reasoning": generated.reasoning,
                "opsec_warnings": generated.opsec_warnings,
                "params": generated.params,
                "execution_mode": generated.execution_mode,
                "policy_outcome": generated.policy_outcome,
                "policy_reason": generated.policy_reason,
                "status": next_status,
            }
        )

    def _build_host_context(self, con: sqlite3.Connection, host: str) -> dict[str, Any]:
        port_rows = con.execute(
            """
            SELECT port, service, version, CAST(scanned_at AS TEXT), confidence, cdn_detected, waf_detected
            FROM port_scan_results
            WHERE engagement_id=? AND host=?
            ORDER BY scanned_at DESC, port ASC
            """,
            (self.engagement_id, host),
        ).fetchall()
        service_rows = con.execute(
            """
            SELECT s.port, s.service_name, s.version, h.os_family
            FROM services s
            JOIN hosts h ON h.id = s.host_id
            WHERE h.engagement_id=? AND h.ip=?
            ORDER BY s.port ASC
            """,
            (self.engagement_id, host),
        ).fetchall()
        host_row = con.execute(
            """
            SELECT os_family, host_context, CAST(discovered_at AS TEXT)
            FROM hosts
            WHERE engagement_id=? AND ip=?
            ORDER BY discovered_at DESC
            LIMIT 1
            """,
            (self.engagement_id, host),
        ).fetchone()
        crawl_rows = con.execute(
            """
            SELECT COALESCE(final_url, url), title, CAST(discovered_at AS TEXT)
            FROM crawl_results
            WHERE engagement_id=? AND (final_url LIKE ? OR url LIKE ?)
            ORDER BY discovered_at DESC
            LIMIT 20
            """,
            (self.engagement_id, f"%{host}%", f"%{host}%"),
        ).fetchall()
        urls = [str(row[0]) for row in crawl_rows if row[0] is not None]
        vuln_rows = []
        auth_rows = []
        if urls:
            placeholders = ",".join("?" for _ in urls)
            vuln_rows = con.execute(
                f"""
                SELECT vuln_id, plugin, url, severity, verified, CAST(discovered_at AS TEXT)
                FROM passive_vulns
                WHERE engagement_id=?
                  AND COALESCE(false_positive, 0)=0
                  AND url IN ({placeholders})
                ORDER BY discovered_at DESC
                LIMIT 20
                """,
                (self.engagement_id, *urls),
            ).fetchall()
            auth_rows = con.execute(
                f"""
                SELECT target_url, attack_type, success, CAST(tested_at AS TEXT)
                FROM auth_test_results
                WHERE engagement_id=? AND target_url IN ({placeholders})
                ORDER BY tested_at DESC
                LIMIT 20
                """,
                (self.engagement_id, *urls),
            ).fetchall()
        validated_creds = con.execute(
            """
            SELECT COUNT(*)
            FROM credentials
            WHERE engagement_id=? AND validated=1 AND validated_host=?
            """,
            (self.engagement_id, host),
        ).fetchone()
        unvalidated_creds = con.execute(
            """
            SELECT COUNT(*)
            FROM credentials
            WHERE engagement_id=? AND validated=0
            """,
            (self.engagement_id,),
        ).fetchone()
        host_context = _json_loads(str(host_row[1]) if host_row and host_row[1] is not None else None, {})
        service_map: dict[int, dict[str, Any]] = {}
        for row in service_rows:
            port = int(row[0])
            service_map[port] = {
                "port": port,
                "service": str(row[1]) if row[1] is not None else "",
                "version": str(row[2]) if row[2] is not None else None,
                "source": "hosts",
            }
        for row in port_rows:
            port = int(row[0])
            service_map[port] = {
                "port": port,
                "service": str(row[1]) if row[1] is not None else service_map.get(port, {}).get("service", ""),
                "version": str(row[2]) if row[2] is not None else service_map.get(port, {}).get("version"),
                "scanned_at": str(row[3]),
                "confidence": float(row[4]) if row[4] is not None else None,
                "cdn_detected": bool(row[5]),
                "waf_detected": bool(row[6]),
                "source": "scan",
            }
        services = sorted(service_map.values(), key=lambda item: int(item["port"]))
        latest_findings = [
            {
                "kind": "passive_vuln",
                "id": str(row[0]),
                "title": str(row[1]) if row[1] is not None else str(row[0]),
                "url": str(row[2]) if row[2] is not None else "",
                "severity": str(row[3] or "unknown").lower(),
                "verified": bool(row[4]),
                "timestamp": str(row[5]),
            }
            for row in vuln_rows[:5]
        ]
        for row in auth_rows[:3]:
            latest_findings.append(
                {
                    "kind": "auth_result",
                    "title": str(row[1] or "auth test"),
                    "url": str(row[0]),
                    "severity": "critical" if bool(row[2]) else "medium",
                    "verified": bool(row[2]),
                    "timestamp": str(row[3]),
                }
            )
        action_counts = con.execute(
            """
            SELECT status, COUNT(*)
            FROM command_center_actions
            WHERE engagement_id=? AND target_ref=?
            GROUP BY status
            """,
            (self.engagement_id, host),
        ).fetchall()
        counts = {str(row[0]): int(row[1]) for row in action_counts}
        critical_count = sum(
            1
            for finding in latest_findings
            if str(finding.get("severity", "")).lower() == "critical"
        )
        status = "critical" if critical_count else ("active" if services else "known")
        return {
            "host": host,
            "status": status,
            "os_family": (
                str(host_row[0])
                if host_row and host_row[0] is not None
                else str(service_rows[0][3]) if service_rows and service_rows[0][3] is not None else host_context.get("os_family")
            ),
            "services": services,
            "urls": [
                {
                    "url": str(row[0]),
                    "title": str(row[1]) if row[1] is not None else "",
                    "discovered_at": str(row[2]),
                }
                for row in crawl_rows
            ],
            "latest_findings": sorted(
                latest_findings,
                key=lambda item: (
                    _severity_rank(str(item.get("severity", "info"))),
                    str(item.get("timestamp", "")),
                ),
                reverse=True,
            ),
            "credential_count": {
                "validated": int(validated_creds[0]) if validated_creds is not None else 0,
                "available": int(unvalidated_creds[0]) if unvalidated_creds is not None else 0,
            },
            "action_counts": {
                "suggested": counts.get("suggested", 0),
                "queued": counts.get("queued", 0),
                "running": counts.get("running", 0),
                "failed": counts.get("failed", 0),
                "succeeded": counts.get("succeeded", 0),
                "cancelled": counts.get("cancelled", 0),
            },
            "discovered_at": str(host_row[2]) if host_row and host_row[2] is not None else None,
        }

    def _generate_actions(
        self, host: str, context: dict[str, Any], state: SentryConfigModel
    ) -> list[CommandAction]:
        generated: list[CommandAction] = []
        services = context["services"]
        urls = context["urls"]
        service_names = {str(service.get("service", "")).lower() for service in services}
        url_values = [str(item["url"]) for item in urls if item.get("url")]
        discovered_at = utc_now()
        if not services:
            generated.append(
                self._build_action(
                    host=host,
                    target_type=CommandTargetType.HOST,
                    target_ref=host,
                    action_type=CommandActionType.SCAN_PORTS,
                    confidence=88,
                    risk_level=CommandRiskLevel.LOW,
                    reasoning=f"Host {host} is known but has no recent service inventory.",
                    opsec_warnings=["Low-noise discovery only."],
                    params={"target": host},
                    state=state,
                )
            )
        http_services = [
            service
            for service in services
            if int(service.get("port", 0)) in {80, 443, 8080, 8443}
            or "http" in str(service.get("service", "")).lower()
        ]
        if http_services and not url_values:
            for service in http_services[:3]:
                port = int(service["port"])
                scheme = "https" if port in {443, 8443} else "http"
                target = f"{scheme}://{host}:{port}"
                generated.append(
                    self._build_action(
                        host=host,
                        target_type=CommandTargetType.SERVICE,
                        target_ref=f"{host}:{port}",
                        action_type=CommandActionType.CRAWL,
                        confidence=84,
                        risk_level=CommandRiskLevel.LOW,
                        reasoning=f"HTTP service {host}:{port} is present without crawl coverage.",
                        opsec_warnings=["Watch for rate limits and WAF telemetry."],
                        params={"target": target, "port": port},
                        state=state,
                    )
                )
        for url in url_values[:5]:
            generated.append(
                self._build_action(
                    host=host,
                    target_type=CommandTargetType.URL,
                    target_ref=url,
                    action_type=CommandActionType.VULN_SCAN,
                    confidence=72,
                    risk_level=CommandRiskLevel.MEDIUM,
                    reasoning=f"Crawled URL {url} is ready for passive vulnerability review.",
                    opsec_warnings=["Passive collection may still trigger application logging."],
                    params={"target": url},
                    state=state,
                )
            )
        if {"ssh", "smb", "ftp", "rdp"} & service_names and context["credential_count"]["available"] > 0:
            primary_service = next(
                iter(sorted({"ssh", "smb", "ftp", "rdp"} & service_names)),
                "ssh",
            )
            generated.append(
                self._build_action(
                    host=host,
                    target_type=CommandTargetType.HOST,
                    target_ref=host,
                    action_type=CommandActionType.CREDENTIAL_TEST,
                    confidence=96,
                    risk_level=CommandRiskLevel.CRITICAL,
                    reasoning=f"Unvalidated credentials exist and {primary_service.upper()} is exposed on {host}.",
                    opsec_warnings=["Respects lockout thresholds but still touches authentication controls."],
                    params={"host": host, "service": primary_service},
                    state=state,
                )
            )
        critical_http_target = next(
            (
                str(finding.get("url"))
                for finding in context["latest_findings"]
                if str(finding.get("severity", "")).lower() == "critical" and str(finding.get("url"))
            ),
            None,
        )
        if critical_http_target:
            generated.append(
                self._build_action(
                    host=host,
                    target_type=CommandTargetType.URL,
                    target_ref=critical_http_target,
                    action_type=CommandActionType.EXPLOIT_ATTEMPT,
                    confidence=55,
                    risk_level=CommandRiskLevel.HIGH,
                    reasoning=f"Critical finding exists for {critical_http_target}; operator-driven validation path is available.",
                    opsec_warnings=["High-risk action requires explicit operator confirmation."],
                    params={"target": critical_http_target},
                    state=state,
                )
            )
        return generated

    def _build_action(
        self,
        host: str,
        target_type: CommandTargetType,
        target_ref: str,
        action_type: CommandActionType,
        confidence: int,
        risk_level: CommandRiskLevel,
        reasoning: str,
        opsec_warnings: list[str],
        params: dict[str, Any],
        state: SentryConfigModel,
    ) -> CommandAction:
        policy_outcome, policy_reason, execution_mode = self._evaluate_policy(
            action_type=action_type,
            confidence_score=confidence,
            state=state,
            requires_approval=risk_level in {CommandRiskLevel.HIGH, CommandRiskLevel.CRITICAL},
        )
        initial_status = CommandActionStatus.SUGGESTED
        if execution_mode == "autonomous" and policy_outcome == CommandPolicyOutcome.QUEUE:
            initial_status = CommandActionStatus.QUEUED
        return CommandAction(
            action_id=uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{self.engagement_id}:{host}:{action_type.value}:{target_ref}",
            ).hex,
            engagement_id=self.engagement_id,
            target_type=target_type,
            target_ref=target_ref,
            action_type=action_type,
            confidence_score=confidence,
            risk_level=risk_level,
            requires_approval=risk_level in {CommandRiskLevel.HIGH, CommandRiskLevel.CRITICAL},
            status=initial_status,
            created_at=utc_now(),
            updated_at=utc_now(),
            reasoning=reasoning,
            opsec_warnings=opsec_warnings,
            params=params,
            execution_mode=execution_mode,
            policy_outcome=policy_outcome,
            policy_reason=policy_reason,
        )

    def _evaluate_policy(
        self,
        action_type: CommandActionType,
        confidence_score: int,
        state: SentryConfigModel,
        requires_approval: bool,
    ) -> tuple[CommandPolicyOutcome, str, str]:
        action_override = state.action_overrides.get(action_type.value)
        engagement_auto = state.engagement_overrides.get("auto_execute_threshold")
        effective_auto_threshold = (
            int(action_override)
            if action_override is not None
            else int(engagement_auto)
            if engagement_auto is not None
            else state.auto_execute_threshold
        )
        if confidence_score >= effective_auto_threshold:
            if action_type in set(state.whitelisted_action_types) and not requires_approval:
                mode = "autonomous" if state.enabled else "manual"
                return (
                    CommandPolicyOutcome.AUTO_EXECUTE,
                    f"Score {confidence_score} meets auto threshold {effective_auto_threshold} and action is whitelisted.",
                    mode,
                )
            return (
                CommandPolicyOutcome.QUEUE,
                f"Score {confidence_score} exceeds auto threshold but whitelist or approval gate blocks automatic execution.",
                "autonomous" if state.enabled else "manual",
            )
        if confidence_score >= 80:
            return (
                CommandPolicyOutcome.QUEUE,
                f"Score {confidence_score} falls in review queue band (80-94).",
                "autonomous" if state.enabled else "manual",
            )
        if confidence_score >= 60:
            return (
                CommandPolicyOutcome.SUGGEST,
                f"Score {confidence_score} falls in suggestion band (60-79).",
                "manual",
            )
        return (
            CommandPolicyOutcome.HIDDEN,
            f"Score {confidence_score} is below the visibility threshold.",
            "manual",
        )

    def _ensure_asset_discovered_event(
        self, con: sqlite3.Connection, host: str, context: dict[str, Any]
    ) -> None:
        row = con.execute(
            """
            SELECT 1
            FROM command_center_timeline
            WHERE engagement_id=? AND event_type='asset_discovered' AND payload_json LIKE ?
            LIMIT 1
            """,
            (self.engagement_id, f'%"{host}"%'),
        ).fetchone()
        if row is not None:
            return
        self.record_event(
            CommandEvent(
                event_id=uuid.uuid4().hex,
                event_type="asset_discovered",
                engagement_id=self.engagement_id,
                timestamp=utc_now(),
                payload={
                    "host": host,
                    "service_count": len(context["services"]),
                    "url_count": len(context["urls"]),
                },
            ),
            con=con
        )

    def _maybe_emit_critical_finding(
        self,
        con: sqlite3.Connection,
        host: str,
        context: dict[str, Any],
        state: SentryConfigModel,
    ) -> None:
        critical_findings = [
            finding
            for finding in context["latest_findings"]
            if str(finding.get("severity", "")).lower() == "critical"
        ]
        if not critical_findings:
            return
        finding = critical_findings[0]
        dedupe = con.execute(
            """
            SELECT 1
            FROM command_center_timeline
            WHERE engagement_id=? AND event_type='critical_finding_detected' AND payload_json LIKE ?
            LIMIT 1
            """,
            (self.engagement_id, f'%"{host}"%'),
        ).fetchone()
        if dedupe is None:
            self.record_event(
                CommandEvent(
                    event_id=uuid.uuid4().hex,
                    event_type="critical_finding_detected",
                    engagement_id=self.engagement_id,
                    timestamp=utc_now(),
                    payload={"host": host, "finding": finding},
                    severity="critical",
                    expires_at=utc_now() + timedelta(hours=8),
                ),
                con=con
            )
        if state.enabled and state.pause_on_new_critical_finding and not state.emergency_stop:
            updated = state.model_copy(
                update={
                    "enabled": False,
                    "paused_reason": f"critical_finding:{host}",
                    "updated_at": utc_now(),
                }
            )
            self._save_sentry_state(con, updated)
            self.record_event(
                CommandEvent(
                    event_id=uuid.uuid4().hex,
                    event_type="sentry_state_changed",
                    engagement_id=self.engagement_id,
                    timestamp=utc_now(),
                    payload={"enabled": False, "paused_reason": updated.paused_reason},
                    severity="critical",
                ),
                con=con
            )

    def _persist_action(self, con: sqlite3.Connection, action: CommandAction) -> None:
        con.execute(
            """
            INSERT INTO command_center_actions (
                action_id,
                engagement_id,
                target_type,
                target_ref,
                action_type,
                confidence_score,
                risk_level,
                requires_approval,
                status,
                created_at,
                updated_at,
                reasoning,
                opsec_warnings_json,
                params_json,
                execution_mode,
                policy_outcome,
                policy_reason
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(action_id) DO UPDATE SET
                confidence_score=excluded.confidence_score,
                risk_level=excluded.risk_level,
                requires_approval=excluded.requires_approval,
                status=excluded.status,
                updated_at=excluded.updated_at,
                reasoning=excluded.reasoning,
                opsec_warnings_json=excluded.opsec_warnings_json,
                params_json=excluded.params_json,
                execution_mode=excluded.execution_mode,
                policy_outcome=excluded.policy_outcome,
                policy_reason=excluded.policy_reason
            """,
            (
                action.action_id,
                action.engagement_id,
                action.target_type.value,
                action.target_ref,
                action.action_type.value,
                action.confidence_score,
                action.risk_level.value,
                int(action.requires_approval),
                action.status.value,
                action.created_at.isoformat(),
                action.updated_at.isoformat(),
                action.reasoning,
                _json_dumps(action.opsec_warnings),
                _json_dumps(action.params),
                action.execution_mode,
                action.policy_outcome.value,
                action.policy_reason,
            ),
        )

    def _load_action_from_db_optional(
        self, con: sqlite3.Connection, action_id: str
    ) -> CommandAction | None:
        row = con.execute(
            """
            SELECT
                action_id,
                engagement_id,
                target_type,
                target_ref,
                action_type,
                confidence_score,
                risk_level,
                requires_approval,
                status,
                created_at,
                updated_at,
                reasoning,
                opsec_warnings_json,
                params_json,
                execution_mode,
                policy_outcome,
                policy_reason
            FROM command_center_actions
            WHERE engagement_id=? AND action_id=?
            """,
            (self.engagement_id, action_id),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_action(row)

    def _load_action_from_db(self, con: sqlite3.Connection, action_id: str) -> CommandAction:
        action = self._load_action_from_db_optional(con, action_id)
        if action is None:
            raise ValueError(f"Unknown action_id: {action_id}")
        return action

    def _row_to_action(self, row: sqlite3.Row | tuple[Any, ...]) -> CommandAction:
        return CommandAction(
            action_id=str(row[0]),
            engagement_id=int(row[1]),
            target_type=CommandTargetType(str(row[2])),
            target_ref=str(row[3]),
            action_type=CommandActionType(str(row[4])),
            confidence_score=int(row[5]),
            risk_level=CommandRiskLevel(str(row[6])),
            requires_approval=bool(row[7]),
            status=CommandActionStatus(str(row[8])),
            created_at=datetime.fromisoformat(str(row[9])),
            updated_at=datetime.fromisoformat(str(row[10])),
            reasoning=str(row[11]),
            opsec_warnings=_json_loads(str(row[12]) if row[12] is not None else None, []),
            params=_json_loads(str(row[13]) if row[13] is not None else None, {}),
            execution_mode=str(row[14]),
            policy_outcome=CommandPolicyOutcome(str(row[15])),
            policy_reason=str(row[16] or ""),
        )

    def _fetch_actions(
        self, con: sqlite3.Connection, host: str, include_hidden: bool
    ) -> list[CommandAction]:
        rows = con.execute(
            """
            SELECT
                action_id,
                engagement_id,
                target_type,
                target_ref,
                action_type,
                confidence_score,
                risk_level,
                requires_approval,
                status,
                created_at,
                updated_at,
                reasoning,
                opsec_warnings_json,
                params_json,
                execution_mode,
                policy_outcome,
                policy_reason
            FROM command_center_actions
            WHERE engagement_id=?
              AND (target_ref=? OR target_ref LIKE ? OR target_ref LIKE ?)
            ORDER BY confidence_score DESC, updated_at DESC
            """,
            (self.engagement_id, host, f"{host}:%", f"%{host}%"),
        ).fetchall()
        items = [self._row_to_action(row) for row in rows]
        if include_hidden:
            return items
        return [item for item in items if item.policy_outcome != CommandPolicyOutcome.HIDDEN]

    def _sync_action_statuses(self, con: sqlite3.Connection) -> None:
        rows = con.execute(
            """
            SELECT action_id, params_json
            FROM command_center_actions
            WHERE engagement_id=? AND status IN ('queued','running')
            """,
            (self.engagement_id,),
        ).fetchall()
        for row in rows:
            params = _json_loads(str(row[1]) if row[1] is not None else None, {})
            task_key = str(params.get("task_key") or "")
            if task_key:
                self._sync_action_status_for_task(con, task_key, action_id=str(row[0]))

    def _sync_action_status_for_task(
        self,
        con: sqlite3.Connection,
        task_key: str,
        action_id: str | None = None,
    ) -> None:
        row = con.execute(
            """
            SELECT status, error
            FROM distributed_tasks
            WHERE engagement_id=? AND task_key=?
            ORDER BY updated_at DESC
            LIMIT 1
            """,
            (self.engagement_id, task_key),
        ).fetchone()
        if row is None:
            return
        next_status = _task_status_to_action_status(str(row[0]))
        action_row = None
        if action_id is None:
            action_row = con.execute(
                """
                SELECT action_id
                FROM command_center_actions
                WHERE engagement_id=? AND params_json LIKE ?
                LIMIT 1
                """,
                (self.engagement_id, f'%"{task_key}"%'),
            ).fetchone()
            if action_row is None:
                return
            action_id = str(action_row[0])
        existing = self._load_action_from_db(con, action_id)
        if existing.status == next_status:
            return
        validate_action_transition(existing.status, next_status)
        self._update_action_status(
            con,
            action_id=action_id,
            next_status=next_status,
            policy_reason=str(row[1] or existing.policy_reason),
        )
        self.record_event(
            CommandEvent(
                event_id=uuid.uuid4().hex,
                event_type="action_status_changed",
                engagement_id=self.engagement_id,
                timestamp=utc_now(),
                payload={"action_id": action_id, "status": next_status.value, "task_key": task_key},
                severity="critical" if next_status == CommandActionStatus.FAILED else "info",
            )
        )

    def _update_action_status(
        self,
        con: sqlite3.Connection,
        action_id: str,
        next_status: CommandActionStatus,
        policy_reason: str,
    ) -> None:
        action = self._load_action_from_db(con, action_id)
        validate_action_transition(action.status, next_status)
        updated = action.model_copy(
            update={"status": next_status, "updated_at": utc_now(), "policy_reason": policy_reason}
        )
        self._persist_action(con, updated)

    def _load_sentry_state(self, con: sqlite3.Connection) -> SentryConfigModel:
        row = con.execute(
            """
            SELECT
                engagement_id,
                enabled,
                emergency_stop,
                auto_execute_threshold,
                max_concurrent_auto,
                require_operator_approval,
                pause_on_new_critical_finding,
                paused_reason,
                whitelisted_action_types_json,
                action_overrides_json,
                engagement_overrides_json,
                updated_at
            FROM sentry_state
            WHERE engagement_id=?
            """,
            (self.engagement_id,),
        ).fetchone()
        if row is None:
            state = SentryConfigModel(engagement_id=self.engagement_id)
            self._save_sentry_state(con, state)
            return state
        action_values = _json_loads(str(row[8]) if row[8] is not None else None, [])
        whitelisted = [
            CommandActionType(str(item))
            for item in action_values
            if str(item) in {member.value for member in CommandActionType}
        ]
        if not whitelisted:
            whitelisted = [CommandActionType.CREDENTIAL_TEST]
        return SentryConfigModel(
            engagement_id=int(row[0]),
            enabled=bool(row[1]),
            emergency_stop=bool(row[2]),
            auto_execute_threshold=int(row[3]),
            max_concurrent_auto=int(row[4]),
            require_operator_approval=bool(row[5]),
            pause_on_new_critical_finding=bool(row[6]),
            paused_reason=str(row[7]) if row[7] is not None else None,
            whitelisted_action_types=whitelisted,
            action_overrides=_json_loads(str(row[9]) if row[9] is not None else None, {}),
            engagement_overrides=_json_loads(str(row[10]) if row[10] is not None else None, {}),
            updated_at=datetime.fromisoformat(str(row[11])),
        )

    def _save_sentry_state(self, con: sqlite3.Connection, state: SentryConfigModel) -> None:
        con.execute(
            """
            INSERT INTO sentry_state (
                engagement_id,
                enabled,
                emergency_stop,
                auto_execute_threshold,
                max_concurrent_auto,
                require_operator_approval,
                pause_on_new_critical_finding,
                paused_reason,
                whitelisted_action_types_json,
                action_overrides_json,
                engagement_overrides_json,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(engagement_id) DO UPDATE SET
                enabled=excluded.enabled,
                emergency_stop=excluded.emergency_stop,
                auto_execute_threshold=excluded.auto_execute_threshold,
                max_concurrent_auto=excluded.max_concurrent_auto,
                require_operator_approval=excluded.require_operator_approval,
                pause_on_new_critical_finding=excluded.pause_on_new_critical_finding,
                paused_reason=excluded.paused_reason,
                whitelisted_action_types_json=excluded.whitelisted_action_types_json,
                action_overrides_json=excluded.action_overrides_json,
                engagement_overrides_json=excluded.engagement_overrides_json,
                updated_at=excluded.updated_at
            """,
            (
                state.engagement_id,
                int(state.enabled),
                int(state.emergency_stop),
                state.auto_execute_threshold,
                state.max_concurrent_auto,
                int(state.require_operator_approval),
                int(state.pause_on_new_critical_finding),
                state.paused_reason,
                _json_dumps([item.value for item in state.whitelisted_action_types]),
                _json_dumps(state.action_overrides),
                _json_dumps(state.engagement_overrides),
                state.updated_at.isoformat(),
            ),
        )

    def _get_action(self, action_id: str) -> CommandAction:
        con = get_engagement_db(self._db_path)
        try:
            self._refresh_action_statuses(con)
            return self._load_action_from_db(con, action_id)
        finally:
            con.close()


def build_dashboard_html() -> str:
    return """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FORGE Command Center</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #08111f;
      --panel: #101b2d;
      --panel-2: #14233a;
      --border: #2a3b57;
      --text: #e5edf9;
      --muted: #93a4c3;
      --accent: #4f9cf9;
      --danger: #ef4444;
      --warn: #f59e0b;
      --ok: #22c55e;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Inter, Arial, sans-serif; background: var(--bg); color: var(--text); }
    header { display: flex; justify-content: space-between; gap: 12px; align-items: center; padding: 16px 20px; border-bottom: 1px solid var(--border); background: rgba(8,17,31,0.92); position: sticky; top: 0; z-index: 10; }
    h1, h2, h3 { margin: 0; }
    header .meta, .toolbar, .quick-actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    button, select, input { background: #0b1524; color: var(--text); border: 1px solid var(--border); border-radius: 10px; padding: 9px 12px; }
    button { cursor: pointer; }
    button:hover { border-color: var(--accent); }
    button:disabled { opacity: 0.45; cursor: not-allowed; }
    main { display: grid; grid-template-columns: 1.05fr 1.2fr 0.95fr; grid-template-areas: "targets battle alerts" "ops feed quick"; gap: 14px; padding: 14px; min-height: calc(100vh - 78px); }
    section { background: linear-gradient(180deg, var(--panel), var(--panel-2)); border: 1px solid var(--border); border-radius: 16px; padding: 14px; min-height: 220px; }
    #targetList { grid-area: targets; }
    #battleMap { grid-area: battle; }
    #criticalAlerts { grid-area: alerts; }
    #activeOps { grid-area: ops; }
    #progressFeed { grid-area: feed; }
    #quickActions { grid-area: quick; }
    .section-head { display: flex; justify-content: space-between; gap: 8px; align-items: center; margin-bottom: 12px; }
    .section-subtitle { font-size: 12px; color: var(--muted); }
    .stack { display: grid; gap: 10px; }
    .asset-card, .service-row, .timeline-row, .alert-card, .op-card { background: rgba(8,17,31,0.55); border: 1px solid var(--border); border-radius: 14px; padding: 12px; }
    .asset-card { cursor: pointer; }
    .asset-card:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .asset-title, .row-spread { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
    .pill-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
    .pill { display: inline-flex; align-items: center; gap: 6px; padding: 4px 9px; border-radius: 999px; border: 1px solid var(--border); font-size: 12px; white-space: nowrap; }
    .status-critical { border-color: rgba(239,68,68,0.5); color: #fecaca; }
    .status-active { border-color: rgba(34,197,94,0.5); color: #bbf7d0; }
    .status-known { border-color: rgba(79,156,249,0.5); color: #bfdbfe; }
    .risk-low { color: #bfdbfe; }
    .risk-medium { color: #fde68a; }
    .risk-high { color: #fdba74; }
    .risk-critical { color: #fecaca; }
    .service-grid, .action-grid { display: grid; gap: 8px; }
    .action-card { border: 1px solid var(--border); border-radius: 14px; padding: 12px; background: rgba(11,21,36,0.75); }
    .action-meta { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; }
    .action-actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
    .muted { color: var(--muted); font-size: 13px; }
    .metric { font-size: 12px; color: var(--muted); }
    .ring { width: 42px; height: 42px; border-radius: 50%; border: 4px solid rgba(79,156,249,0.18); border-top-color: var(--accent); display: inline-block; }
    .controls { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    dialog { border: 1px solid var(--border); border-radius: 18px; background: linear-gradient(180deg, #0b1524, #122238); color: var(--text); width: min(880px, 92vw); padding: 0; }
    dialog::backdrop { background: rgba(3, 7, 18, 0.72); }
    .dialog-body { padding: 18px; display: grid; gap: 14px; }
    .dialog-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .empty { padding: 20px 12px; border: 1px dashed var(--border); border-radius: 14px; text-align: center; color: var(--muted); }
    .feed { max-height: 52vh; overflow: auto; display: grid; gap: 8px; }
    .token-box { max-width: 230px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .hidden { display: none; }
    @media (max-width: 1100px) {
      main {
        grid-template-columns: 1fr;
        grid-template-areas:
          "targets"
          "battle"
          "alerts"
          "ops"
          "feed"
          "quick";
      }
      .two-col { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>FORGE Command Center</h1>
      <div class="section-subtitle" id="engagementLabel">No engagement selected</div>
    </div>
    <div class="toolbar">
      <input id="operator" aria-label="Operator handle" placeholder="operator handle">
      <button id="tokenButton" type="button">Mint Token</button>
      <select id="engagementSelect" aria-label="Engagement selector"></select>
      <button id="refreshButton" type="button">Refresh</button>
      <button id="sentryToggle" type="button" aria-pressed="false">Sentry Off</button>
      <button id="stopButton" type="button">Emergency Stop</button>
      <div class="token-box metric" id="tokenPreview" aria-live="polite"></div>
    </div>
  </header>
  <main>
    <section id="targetList" aria-labelledby="targetTitle">
      <div class="section-head">
        <div>
          <h2 id="targetTitle">Target List</h2>
          <div class="section-subtitle">Clickable asset cards with live action counts</div>
        </div>
        <div class="controls">
          <button id="refreshTargets" type="button">Refresh Targets</button>
        </div>
      </div>
      <div id="targetCards" class="stack" aria-live="polite"></div>
    </section>

    <section id="battleMap" aria-labelledby="battleTitle">
      <div class="section-head">
        <div>
          <h2 id="battleTitle">Battle Map</h2>
          <div class="section-subtitle" id="battleSubtitle">Select a host to inspect services, findings, and actions</div>
        </div>
      </div>
      <div id="battleContent" class="stack"></div>
    </section>

    <section id="criticalAlerts" aria-labelledby="alertsTitle">
      <div class="section-head">
        <div>
          <h2 id="alertsTitle">Critical Alerts</h2>
          <div class="section-subtitle">Visible until acknowledged or expired</div>
        </div>
      </div>
      <div id="alertCards" class="feed" aria-live="polite"></div>
    </section>

    <section id="activeOps" aria-labelledby="opsTitle">
      <div class="section-head">
        <div>
          <h2 id="opsTitle">Active Operations</h2>
          <div class="section-subtitle">Queue state, running actions, and worker activity</div>
        </div>
      </div>
      <div id="opsCards" class="stack"></div>
    </section>

    <section id="progressFeed" aria-labelledby="feedTitle">
      <div class="section-head">
        <div>
          <h2 id="feedTitle">Progress Feed</h2>
          <div class="section-subtitle">Timeline events, action state changes, and sentry signals</div>
        </div>
      </div>
      <div id="timelineFeed" class="feed" aria-live="polite"></div>
    </section>

    <section id="quickActions" aria-labelledby="quickTitle">
      <div class="section-head">
        <div>
          <h2 id="quickTitle">Quick Actions</h2>
          <div class="section-subtitle">Context-aware launchers and mission controls</div>
        </div>
      </div>
      <div class="quick-actions">
        <button id="runRecon" type="button" disabled>Full Recon</button>
        <button id="runVulnDiscovery" type="button" disabled>Vuln Discovery</button>
        <button id="openPanel" type="button" disabled>Open Control Panel</button>
        <button id="showLowConfidence" type="button">Toggle Low Confidence</button>
      </div>
      <div id="quickStatus" class="stack" style="margin-top: 14px;"></div>
    </section>
  </main>

  <dialog id="controlPanel" aria-labelledby="controlPanelTitle">
    <div class="dialog-body">
      <div class="dialog-head">
        <div>
          <h2 id="controlPanelTitle">Host Control Panel</h2>
          <div id="controlPanelSubtitle" class="section-subtitle"></div>
        </div>
        <button id="closePanel" type="button">Close</button>
      </div>
      <div class="two-col">
        <div class="stack">
          <div class="service-row">
            <h3>Host Context</h3>
            <div id="panelContext" class="stack"></div>
          </div>
          <div class="service-row">
            <h3>Latest Findings</h3>
            <div id="panelFindings" class="stack"></div>
          </div>
        </div>
        <div class="service-row">
          <h3>Available Actions</h3>
          <div id="panelActions" class="action-grid"></div>
        </div>
      </div>
    </div>
  </dialog>

  <script>
    let bearer = "";
    let selectedHost = null;
    let selectedContext = null;
    let ws = null;
    let showLowConfidence = false;

    const el = (id) => document.getElementById(id);

    function authHeaders() {
      return bearer ? { Authorization: "Bearer " + bearer } : {};
    }

    function selectedEngagement() {
      return Number(el("engagementSelect").value || "0");
    }

    async function requestJson(url, options = {}) {
      const response = await fetch(url, {
        headers: { ...(options.headers || {}), ...authHeaders() },
        ...options,
      });
      const text = await response.text();
      let payload = {};
      try { payload = text ? JSON.parse(text) : {}; } catch (_) { payload = { raw: text }; }
      if (!response.ok) {
        const detail = payload.message || payload.detail || payload.raw || "Request failed";
        throw new Error(detail);
      }
      return payload;
    }

    function riskClass(risk) {
      return "risk-" + String(risk || "low").toLowerCase();
    }

    function statusClass(status) {
      if (status === "critical") return "status-critical";
      if (status === "active") return "status-active";
      return "status-known";
    }

    function pill(text, cls = "") {
      return `<span class="pill ${cls}">${text}</span>`;
    }

    function renderEmpty(targetId, message) {
      el(targetId).innerHTML = `<div class="empty">${message}</div>`;
    }

    async function mintToken() {
      const operator = el("operator").value || "operator";
      const token = await requestJson("/api/token?operator=" + encodeURIComponent(operator));
      bearer = token.token || "";
      el("tokenPreview").textContent = bearer ? bearer.slice(0, 20) + "..." : "";
      await loadEngagements();
      connectWs();
    }

    async function loadEngagements() {
      const data = await requestJson("/api/engagements");
      const select = el("engagementSelect");
      const previous = select.value;
      select.innerHTML = `<option value="0">Select engagement</option>`;
      for (const item of data.items || []) {
        const option = document.createElement("option");
        option.value = String(item.id);
        option.textContent = `${item.id} · ${item.name}`;
        select.appendChild(option);
      }
      if (previous && [...select.options].some((item) => item.value === previous)) {
        select.value = previous;
      } else if ((data.items || [])[0]) {
        select.value = String(data.items[0].id);
      }
      await refreshDashboard();
    }

    async function refreshDashboard() {
      const engagement = selectedEngagement();
      if (!engagement) {
        el("engagementLabel").textContent = "No engagement selected";
        renderEmpty("targetCards", "Mint a token and choose an engagement to start.");
        renderEmpty("battleContent", "Select a host to view the battle map.");
        renderEmpty("alertCards", "No alerts.");
        renderEmpty("opsCards", "No operations loaded.");
        renderEmpty("timelineFeed", "No events loaded.");
        return;
      }
      el("engagementLabel").textContent = `Engagement ${engagement}`;
      await Promise.all([loadSentryState(), loadTargets(), loadTimeline(), loadOperations()]);
      updateQuickActions();
      if (selectedHost) {
        await loadHostContext(selectedHost, false);
      }
    }

    async function loadSentryState() {
      const engagement = selectedEngagement();
      if (!engagement) return;
      const state = await requestJson(`/api/sentry/state?engagement_id=${engagement}`);
      const button = el("sentryToggle");
      button.textContent = state.enabled ? "Sentry On" : "Sentry Off";
      button.setAttribute("aria-pressed", String(Boolean(state.enabled)));
      const status = [];
      status.push(`<div class="op-card"><div class="row-spread"><strong>Sentry</strong>${pill(state.enabled ? "Enabled" : "Disabled", state.enabled ? "status-active" : "status-known")}</div><div class="metric">Auto threshold ${state.auto_execute_threshold} · Max concurrent ${state.max_concurrent_auto}</div>${state.paused_reason ? `<div class="metric">Paused: ${state.paused_reason}</div>` : ""}${state.emergency_stop ? `<div class="metric">Emergency stop is active</div>` : ""}</div>`);
      el("quickStatus").innerHTML = status.join("");
    }

    async function loadTargets() {
      const engagement = selectedEngagement();
      if (!engagement) return;
      const data = await requestJson(`/api/engagements/${engagement}/asset-tree`);
      const root = el("targetCards");
      const items = data.items || [];
      if (!items.length) {
        renderEmpty("targetCards", "No target assets discovered yet.");
        return;
      }
      root.innerHTML = items.map((item) => `
        <button type="button" class="asset-card" data-host="${item.host}">
          <div class="asset-title">
            <strong>${item.host}</strong>
            ${pill(item.status, statusClass(item.status))}
          </div>
          <div class="metric">${item.os_family || "unknown OS"} · ${item.services.length} services · ${item.urls.length} URLs</div>
          <div class="pill-row">
            ${(item.services || []).slice(0, 5).map((service) => pill(`${service.service || "svc"}:${service.port}`)).join("")}
          </div>
          <div class="pill-row">
            ${pill(`Suggested ${item.action_summary.suggested || 0}`)}
            ${pill(`Queued ${item.action_summary.queued || 0}`)}
            ${pill(`Running ${item.action_summary.running || 0}`)}
            ${pill(`Creds ${item.credential_count.available || 0}`)}
          </div>
        </button>
      `).join("");
      for (const button of root.querySelectorAll(".asset-card")) {
        button.addEventListener("click", () => loadHostContext(button.dataset.host, false));
      }
    }

    async function loadHostContext(host, openPanelAfter) {
      selectedHost = host;
      const engagement = selectedEngagement();
      if (!engagement || !host) return;
      const context = await requestJson(`/api/assets/${encodeURIComponent(host)}/context?engagement_id=${engagement}`);
      selectedContext = context;
      renderBattleMap(context);
      renderControlPanel(context);
      updateQuickActions();
      if (openPanelAfter) {
        el("controlPanel").showModal();
      }
    }

    function renderBattleMap(context) {
      el("battleSubtitle").textContent = `${context.host} · ${context.status} · ${context.services.length} services · ${context.urls.length} URLs`;
      const services = (context.services || []).map((service) => `
        <div class="service-row">
          <div class="row-spread"><strong>${service.service || "service"}</strong><span class="metric">Port ${service.port}</span></div>
          <div class="metric">${service.version || "version unknown"}</div>
        </div>
      `).join("") || `<div class="empty">No services recorded.</div>`;
      const findings = (context.latest_findings || []).slice(0, 4).map((finding) => `
        <div class="service-row">
          <div class="row-spread"><strong>${finding.title || finding.kind}</strong>${pill(finding.severity || "info", riskClass(finding.severity || "low"))}</div>
          <div class="metric">${finding.url || ""}</div>
        </div>
      `).join("") || `<div class="empty">No recent findings.</div>`;
      el("battleContent").innerHTML = `
        <div class="service-row">
          <div class="row-spread"><strong>${context.host}</strong>${pill(context.status, statusClass(context.status))}</div>
          <div class="metric">${context.os_family || "unknown OS"}</div>
          <div class="pill-row">
            ${pill(`Validated creds ${context.credential_count.validated || 0}`)}
            ${pill(`Available creds ${context.credential_count.available || 0}`)}
            ${pill(`Queued ${context.action_counts.queued || 0}`)}
            ${pill(`Running ${context.action_counts.running || 0}`)}
          </div>
        </div>
        <div class="two-col">
          <div class="service-grid">${services}</div>
          <div class="service-grid">${findings}</div>
        </div>
      `;
    }

    function renderControlPanel(context) {
      el("controlPanelSubtitle").textContent = `${context.host} · ${context.services.length} services`;
      el("panelContext").innerHTML = `
        <div class="metric">Status: ${context.status}</div>
        <div class="metric">OS: ${context.os_family || "unknown"}</div>
        <div class="metric">URLs: ${context.urls.length}</div>
        <div class="metric">Suggested actions: ${context.action_counts.suggested || 0}</div>
      `;
      el("panelFindings").innerHTML = (context.latest_findings || []).map((finding) => `
        <div class="service-row">
          <div class="row-spread"><strong>${finding.title || finding.kind}</strong>${pill(finding.severity || "info", riskClass(finding.severity || "low"))}</div>
          <div class="metric">${finding.url || ""}</div>
        </div>
      `).join("") || `<div class="empty">No findings recorded.</div>`;
      const actions = (context.actions || []).filter((item) => showLowConfidence || item.policy_outcome !== "hidden");
      el("panelActions").innerHTML = actions.map((action) => `
        <article class="action-card">
          <div class="row-spread">
            <strong>${action.action_type.replaceAll("_", " ")}</strong>
            ${pill(action.status, statusClass(action.status === "running" ? "active" : action.status === "failed" ? "critical" : "known"))}
          </div>
          <div class="metric">${action.reasoning}</div>
          <div class="action-meta">
            ${pill(`Confidence ${action.confidence_score}`)}
            ${pill(action.risk_level, riskClass(action.risk_level))}
            ${pill(action.policy_outcome)}
            ${pill(action.execution_mode)}
          </div>
          <div class="metric">${(action.opsec_warnings || []).join(" · ")}</div>
          <div class="action-actions">
            <button type="button" data-action-run="${action.action_id}" ${["running","succeeded","cancelled"].includes(action.status) ? "disabled" : ""}>Execute</button>
            <button type="button" data-action-approve="${action.action_id}" ${action.status !== "queued" ? "disabled" : ""}>Approve</button>
          </div>
        </article>
      `).join("") || `<div class="empty">No actions available.</div>`;
      for (const button of el("panelActions").querySelectorAll("[data-action-run]")) {
        button.addEventListener("click", async () => {
          await executeAction(button.dataset.actionRun);
        });
      }
      for (const button of el("panelActions").querySelectorAll("[data-action-approve]")) {
        button.addEventListener("click", async () => {
          await approveAction(button.dataset.actionApprove);
        });
      }
    }

    async function executeAction(actionId) {
      const engagement = selectedEngagement();
      if (!engagement || !actionId) return;
      await requestJson(`/api/actions/${actionId}/execute`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      if (selectedHost) await loadHostContext(selectedHost, false);
      await Promise.all([loadOperations(), loadTimeline()]);
    }

    async function approveAction(actionId) {
      const engagement = selectedEngagement();
      if (!engagement || !actionId) return;
      await requestJson(`/api/actions/${actionId}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      if (selectedHost) await loadHostContext(selectedHost, false);
      await Promise.all([loadOperations(), loadTimeline()]);
    }

    async function loadTimeline() {
      const engagement = selectedEngagement();
      if (!engagement) return;
      const data = await requestJson(`/api/timeline?engagement_id=${engagement}`);
      const alerts = (data.items || []).filter((item) => item.severity === "critical" && !item.acknowledged);
      const feed = data.items || [];
      el("alertCards").innerHTML = alerts.length ? alerts.map((event) => `
        <div class="alert-card">
          <div class="row-spread"><strong>${event.event_type.replaceAll("_", " ")}</strong>${pill(event.severity, "status-critical")}</div>
          <div class="metric">${new Date(event.timestamp).toLocaleString()}</div>
          <div class="metric">${JSON.stringify(event.payload)}</div>
          <div class="action-actions"><button type="button" data-ack="${event.event_id}">Acknowledge</button></div>
        </div>
      `).join("") : `<div class="empty">No critical alerts.</div>`;
      for (const button of el("alertCards").querySelectorAll("[data-ack]")) {
        button.addEventListener("click", async () => {
          await requestJson(`/api/alerts/${button.dataset.ack}/acknowledge?engagement_id=${engagement}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
          });
          await loadTimeline();
        });
      }
      el("timelineFeed").innerHTML = feed.length ? feed.map((event) => `
        <div class="timeline-row">
          <div class="row-spread"><strong>${event.event_type.replaceAll("_", " ")}</strong>${pill(event.severity, riskClass(event.severity))}</div>
          <div class="metric">${new Date(event.timestamp).toLocaleString()}</div>
          <div class="metric">${JSON.stringify(event.payload)}</div>
        </div>
      `).join("") : `<div class="empty">No progress events yet.</div>`;
    }

    async function loadOperations() {
      const engagement = selectedEngagement();
      if (!engagement) return;
      const [tasks, queue] = await Promise.all([
        requestJson(`/api/tasks?engagement_id=${engagement}`),
        requestJson(`/api/queue/metrics?engagement_id=${engagement}`),
      ]);
      const rows = tasks.items || [];
      const running = rows.filter((item) => item.status === "running").slice(0, 6);
      const cards = [];
      cards.push(`
        <div class="op-card">
          <div class="row-spread"><strong>Queue Snapshot</strong><span class="ring" aria-hidden="true"></span></div>
          <div class="pill-row">
            ${pill(`Queued ${queue.live?.queued || 0}`)}
            ${pill(`Running ${queue.live?.running || 0}`)}
            ${pill(`Done ${queue.live?.done || 0}`)}
            ${pill(`Failed ${queue.live?.failed || 0}`)}
          </div>
        </div>
      `);
      for (const task of running) {
        cards.push(`
          <div class="op-card">
            <div class="row-spread"><strong>${task.task_key}</strong>${pill(task.status, "status-active")}</div>
            <div class="metric">Worker ${task.worker_id || "pending"} · Priority ${task.priority}</div>
          </div>
        `);
      }
      if (!running.length) {
        cards.push(`<div class="empty">No running operations.</div>`);
      }
      el("opsCards").innerHTML = cards.join("");
    }

    function updateQuickActions() {
      const enabled = Boolean(selectedHost && selectedContext);
      el("runRecon").disabled = !enabled;
      el("runVulnDiscovery").disabled = !enabled;
      el("openPanel").disabled = !enabled;
    }

    async function runPlaybook(playbook) {
      const engagement = selectedEngagement();
      if (!engagement || !selectedHost) return;
      await requestJson("/api/automation/playbook", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          engagement_id: engagement,
          playbook,
          target: selectedHost,
        }),
      });
      await Promise.all([loadOperations(), loadTimeline()]);
    }

    async function toggleSentry() {
      const engagement = selectedEngagement();
      if (!engagement) return;
      const currentPressed = el("sentryToggle").getAttribute("aria-pressed") === "true";
      await requestJson(`/api/sentry/toggle?engagement_id=${engagement}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !currentPressed }),
      });
      await Promise.all([refreshDashboard()]);
    }

    async function emergencyStop() {
      const engagement = selectedEngagement();
      if (!engagement) return;
      await requestJson(`/api/sentry/emergency-stop?engagement_id=${engagement}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      await Promise.all([refreshDashboard()]);
    }

    function connectWs() {
      if (!bearer) return;
      if (ws && ws.readyState === WebSocket.OPEN) return;
      ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws/progress");
      ws.onmessage = async (event) => {
        let payload = {};
        try { payload = JSON.parse(event.data); } catch (_) {}
        if (!selectedEngagement() || Number(payload.engagement_id) === selectedEngagement()) {
          await Promise.all([loadTimeline(), loadOperations(), loadTargets()]);
          if (selectedHost) await loadHostContext(selectedHost, false);
        }
      };
      ws.onclose = () => { ws = null; };
    }

    el("tokenButton").addEventListener("click", mintToken);
    el("refreshButton").addEventListener("click", refreshDashboard);
    el("refreshTargets").addEventListener("click", loadTargets);
    el("sentryToggle").addEventListener("click", toggleSentry);
    el("stopButton").addEventListener("click", emergencyStop);
    el("engagementSelect").addEventListener("change", refreshDashboard);
    el("runRecon").addEventListener("click", () => runPlaybook("recon_full"));
    el("runVulnDiscovery").addEventListener("click", () => runPlaybook("vuln_discovery"));
    el("openPanel").addEventListener("click", () => { if (selectedContext) el("controlPanel").showModal(); });
    el("closePanel").addEventListener("click", () => el("controlPanel").close());
    el("showLowConfidence").addEventListener("click", () => {
      showLowConfidence = !showLowConfidence;
      if (selectedContext) renderControlPanel(selectedContext);
    });
  </script>
</body>
</html>
    """
