from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, TextIO

from forge.remediation.workflow import remediation_item_payload
from forge.utils.artifact_url_sanitizer import strip_sensitive_url_query

_VALID_CONNECTORS = {
    "jsonl",
    "stdout",
    "webhook",
    "github_issues",
    "jira",
    "servicenow",
    "tines",
    "splunk_hec",
    "torq",
}
_GITHUB_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_JIRA_PROJECT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]+$")
_JIRA_ISSUE_KEY_RE = re.compile(r"\b[A-Z][A-Z0-9_]+-\d+\b")
_SERVICENOW_TABLE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_SERVICENOW_SYS_ID_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SERVICENOW_NUMBER_RE = re.compile(r"\b[A-Z]{2,10}\d{3,}\b")
_EXTERNAL_STATUS_MAP = {
    "accepted": "risk_accepted",
    "accepted risk": "risk_accepted",
    "assigned": "assigned",
    "backlog": "open",
    "closed": "resolved",
    "closed as fixed": "resolved",
    "done": "resolved",
    "false positive": "false_positive",
    "fixed": "resolved",
    "in progress": "in_progress",
    "in_progress": "in_progress",
    "new": "open",
    "open": "open",
    "reopened": "in_progress",
    "resolved": "resolved",
    "risk accepted": "risk_accepted",
    "to do": "open",
    "todo": "open",
    "won't fix": "risk_accepted",
    "wontfix": "risk_accepted",
}
_CONNECTOR_TICKET_SYSTEM = {
    "github_issues": "github",
    "jira": "jira",
    "servicenow": "servicenow",
}
_TICKET_CLOSE_POLICIES = {"trust_external_status", "require_retest_for_resolved"}


def _ensure_rows(con: sqlite3.Connection) -> None:
    if con.row_factory is None:
        con.row_factory = sqlite3.Row


def _utc_timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _destination_key(connector: str, destination: str | Path | None) -> str:
    if connector == "stdout":
        return "stdout"
    if connector == "jsonl":
        return str(Path(destination or "remediation_tickets.jsonl"))
    if connector in {"webhook", "tines", "torq"}:
        return _redacted_webhook_destination_key(destination)
    if connector == "splunk_hec":
        parsed = urllib.parse.urlsplit(str(destination or ""))
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    if connector == "github_issues":
        parsed = urllib.parse.urlsplit(str(destination or ""))
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    if connector == "jira":
        parsed = urllib.parse.urlsplit(str(destination or ""))
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    if connector == "servicenow":
        parsed = urllib.parse.urlsplit(str(destination or ""))
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    return str(destination or "")


def _redacted_webhook_destination_key(destination: str | Path | None) -> str:
    parsed = urllib.parse.urlsplit(str(destination or ""))
    path = parsed.path or "/"
    path_hash = hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, f"/redacted-webhook-path-{path_hash}", "", "")
    )


def _ticket_action(row: sqlite3.Row) -> str:
    return "update" if str(row["ticket_ref"] or row["ticket_url"] or "").strip() else "create"


def _safe_metadata(value: str | None) -> dict[str, Any]:
    try:
        loaded = json.loads(str(value or "{}"))
    except json.JSONDecodeError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _bounded_text(value: object, limit: int = 180) -> str:
    text = " ".join(str(value or "").strip().split())
    if not text:
        return ""
    return strip_sensitive_url_query(text)[:limit]


def _external_status(value: object) -> tuple[str, str]:
    raw_status = _bounded_text(value, 80)
    normalized = raw_status.lower().replace("-", " ").replace("_", " ")
    normalized = " ".join(normalized.split())
    mapped = _EXTERNAL_STATUS_MAP.get(normalized)
    if mapped:
        return mapped, raw_status
    compact = normalized.replace(" ", "")
    return _EXTERNAL_STATUS_MAP.get(compact, ""), raw_status


def _status_after_close_policy(
    status: str,
    *,
    close_policy: str,
) -> tuple[str, str, str]:
    policy = str(close_policy or "trust_external_status").strip().lower()
    if policy not in _TICKET_CLOSE_POLICIES:
        raise ValueError(
            "close_policy must be trust_external_status or require_retest_for_resolved"
        )
    if policy == "require_retest_for_resolved" and status == "resolved":
        return "retest_pending", "pending", "external_close_requires_retest"
    return status, "", ""


def _candidate_rows(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    connector: str,
    destination: str,
    item_id: int | None,
    force: bool,
    limit: int,
) -> list[sqlite3.Row]:
    item_filter = ""
    params: list[Any] = [connector, destination, engagement_id]
    if item_id is not None:
        item_filter = "AND r.id=?"
        params.append(item_id)
    delivered_filter = "" if force else "AND e.id IS NULL"
    params.append(max(1, int(limit)))
    return con.execute(
        f"""
        SELECT r.id, r.engagement_id, r.finding_table, r.finding_id, r.finding_ref,
               r.title, r.severity, r.owner, r.sla_due_at, r.status,
               r.risk_acceptance_reason, r.risk_accepted_by, r.risk_accepted_at,
               r.risk_acceptance_expires_at,
               r.retest_status, r.retest_requested_at, r.retested_at,
               r.ticket_system, r.ticket_ref, r.ticket_url, r.metadata_json,
               r.created_at, r.updated_at
        FROM remediation_items r
        LEFT JOIN remediation_ticket_events e
          ON e.remediation_item_id=r.id
         AND e.connector=?
         AND e.destination=?
         AND e.item_updated_at=COALESCE(r.updated_at, '')
         AND e.status='delivered'
        WHERE r.engagement_id=?
          {item_filter}
          {delivered_filter}
        ORDER BY
            CASE r.status
                WHEN 'open' THEN 0
                WHEN 'assigned' THEN 1
                WHEN 'in_progress' THEN 2
                WHEN 'retest_pending' THEN 3
                ELSE 4
            END,
            CASE r.severity
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 3
                ELSE 4
            END,
            COALESCE(r.sla_due_at, '9999-12-31') ASC,
            r.id DESC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()


def _payload(
    row: sqlite3.Row,
    *,
    connector: str,
    destination: str,
    operator: str,
    db_path: str | None,
) -> dict[str, Any]:
    item = remediation_item_payload(row)
    payload: dict[str, Any] = {
        "delivered_at": _utc_timestamp(),
        "connector": connector,
        "destination": destination,
        "action": _ticket_action(row),
        "operator": operator,
        "remediation_item": item,
    }
    if db_path:
        payload["db_path"] = db_path
    return payload


def _record_event(
    con: sqlite3.Connection,
    *,
    row: sqlite3.Row,
    connector: str,
    destination: str,
    action: str,
    status: str,
    delivered_at: str | None,
    error: str | None,
    metadata: dict[str, Any],
) -> None:
    con.execute(
        """
        INSERT INTO remediation_ticket_events
            (engagement_id, remediation_item_id, connector, destination,
             action, status, item_updated_at, attempt_count, last_error,
             delivered_at, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
        ON CONFLICT(remediation_item_id, connector, destination, item_updated_at) DO UPDATE SET
            action=excluded.action,
            status=excluded.status,
            attempt_count=remediation_ticket_events.attempt_count + 1,
            last_error=excluded.last_error,
            delivered_at=excluded.delivered_at,
            metadata_json=excluded.metadata_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            int(row["engagement_id"]),
            int(row["id"]),
            connector,
            destination,
            action,
            status,
            str(row["updated_at"] or ""),
            error,
            delivered_at,
            json.dumps(metadata, sort_keys=True),
        ),
    )


def _write_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def _write_stdout(stream: TextIO, payload: dict[str, Any]) -> None:
    stream.write(json.dumps(payload, sort_keys=True) + "\n")
    stream.flush()


def _post_webhook(
    url: str,
    payload: dict[str, Any],
    *,
    timeout_seconds: float,
    headers: dict[str, str] | None = None,
) -> None:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        status = int(getattr(response, "status", 200))
        if status < 200 or status >= 300:
            raise RuntimeError(f"webhook returned HTTP {status}")


def _optional_bearer_header(token_env: str | None) -> dict[str, str]:
    env_name = str(token_env or "").strip()
    if not env_name:
        return {}
    token = os.environ.get(env_name, "").strip()
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def _automation_payload(payload: dict[str, Any], *, platform: str) -> dict[str, Any]:
    item = payload["remediation_item"]
    return {
        "schema": "forge.remediation.automation_event.v1",
        "platform": platform,
        "event_type": "remediation.ticket",
        "delivered_at": payload["delivered_at"],
        "operator": payload["operator"],
        "action": payload["action"],
        "engagement_id": item.get("engagement_id"),
        "remediation_item_id": item.get("id"),
        "severity": item.get("severity"),
        "status": item.get("status"),
        "owner": item.get("owner"),
        "sla_due_at": item.get("sla_due_at"),
        "retest_status": item.get("retest_status"),
        "ticket_system": item.get("ticket_system"),
        "ticket_ref": item.get("ticket_ref"),
        "ticket_url": item.get("ticket_url"),
        "remediation_item": item,
    }


def _post_automation_webhook(
    url: str,
    payload: dict[str, Any],
    *,
    platform: str,
    token_env: str | None,
    timeout_seconds: float,
) -> None:
    _post_webhook(
        url,
        _automation_payload(payload, platform=platform),
        timeout_seconds=timeout_seconds,
        headers=_optional_bearer_header(token_env),
    )


def _splunk_hec_url(url: str | None) -> str:
    parsed = urllib.parse.urlsplit(str(url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("splunk_hec_url must be an http(s) URL")
    path = parsed.path.rstrip("/") or "/services/collector/event"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _splunk_hec_token(token_env: str) -> str:
    env_name = str(token_env or "FORGE_SPLUNK_HEC_TOKEN").strip()
    token = os.environ.get(env_name, "").strip()
    if not token:
        raise ValueError(f"{env_name} is required for Splunk HEC sync")
    return token


def _splunk_hec_event(
    payload: dict[str, Any],
    *,
    index: str,
    source: str,
    sourcetype: str,
) -> dict[str, Any]:
    item = payload["remediation_item"]
    event: dict[str, Any] = {
        "schema": "forge.remediation.automation_event.v1",
        "event_type": "remediation.ticket",
        "action": payload["action"],
        "operator": payload["operator"],
        "connector": payload["connector"],
        "engagement_id": item.get("engagement_id"),
        "remediation_item_id": item.get("id"),
        "severity": item.get("severity"),
        "status": item.get("status"),
        "owner": item.get("owner"),
        "sla_due_at": item.get("sla_due_at"),
        "retest_status": item.get("retest_status"),
        "ticket_system": item.get("ticket_system"),
        "ticket_ref": item.get("ticket_ref"),
        "remediation_item": item,
    }
    body: dict[str, Any] = {
        "source": source or "forge",
        "sourcetype": sourcetype or "forge:remediation:ticket",
        "event": event,
    }
    if index:
        body["index"] = index
    return body


def _handoff_safe_remediation_item(item: dict[str, Any]) -> dict[str, Any]:
    safe_item = {
        key: value
        for key, value in item.items()
        if key not in {"metadata", "owner_approval", "ticket_url"}
    }
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    safe_metadata: dict[str, str] = {}
    for key in ("source", "escalation", "validation_method", "provenance"):
        value = str(metadata.get(key) or "").strip()
        if value:
            safe_metadata[key] = value[:180]
    if safe_metadata:
        safe_item["metadata"] = safe_metadata
    ticket_url = str(item.get("ticket_url") or "").strip()
    if ticket_url:
        safe_item["ticket_url"] = strip_sensitive_url_query(ticket_url)
    return safe_item


def _handoff_payload(payload: dict[str, Any]) -> dict[str, Any]:
    safe_payload = dict(payload)
    safe_payload["remediation_item"] = _handoff_safe_remediation_item(
        payload.get("remediation_item") if isinstance(payload.get("remediation_item"), dict) else {}
    )
    return safe_payload


def _ticket_handoff_template(
    row: sqlite3.Row,
    *,
    connector: str,
    payload: dict[str, Any],
    raw_destination: str | Path | None,
    github_repo: str | None,
    github_api_url: str,
    jira_base_url: str | None,
    jira_project_key: str | None,
    jira_issue_type: str,
    servicenow_instance_url: str | None,
    servicenow_table: str,
    splunk_index: str,
    splunk_source: str,
    splunk_sourcetype: str,
) -> dict[str, Any]:
    item = payload["remediation_item"]
    action = str(payload.get("action") or _ticket_action(row))
    if connector == "github_issues":
        repo = _github_repo_path(github_repo)
        api_base = _github_api_base(github_api_url)
        issue_number = _github_issue_number(row)
        method = "PATCH" if issue_number else "POST"
        url = (
            f"{api_base}/repos/{repo}/issues/{issue_number}"
            if issue_number
            else f"{api_base}/repos/{repo}/issues"
        )
        body = {
            "title": _github_issue_title(item),
            "body": _github_issue_body(item),
        }
        if issue_number:
            body["state"] = _github_issue_state(item)
        return {"method": method, "url": url, "body": body}
    if connector == "jira":
        api_base = _jira_base_url(jira_base_url)
        project_key = _jira_project_key(jira_project_key)
        issue_key = _jira_issue_key(row)
        fields = {
            "summary": _jira_issue_title(item),
            "description": _jira_issue_description(item),
        }
        if issue_key:
            return {
                "method": "PUT",
                "url": f"{api_base}/rest/api/3/issue/{urllib.parse.quote(issue_key, safe='')}",
                "body": {"fields": fields},
            }
        return {
            "method": "POST",
            "url": f"{api_base}/rest/api/3/issue",
            "body": {
                "fields": {
                    **fields,
                    "project": {"key": project_key},
                    "issuetype": {"name": str(jira_issue_type or "Task").strip() or "Task"},
                }
            },
        }
    if connector == "servicenow":
        instance_url = _servicenow_instance_url(servicenow_instance_url)
        table = _servicenow_table_name(servicenow_table)
        sys_id = _servicenow_sys_id(row)
        body = {
            "short_description": _servicenow_summary(item),
            "description": _servicenow_description(item),
            "correlation_id": f"forge:{item.get('engagement_id')}:{item.get('id')}",
        }
        if sys_id:
            body["work_notes"] = (
                f"Forge remediation sync: status={item.get('status')} "
                f"owner={item.get('owner') or '-'} retest={item.get('retest_status') or '-'}"
            )
            return {
                "method": "PATCH",
                "url": f"{instance_url}/api/now/table/{table}/{urllib.parse.quote(sys_id, safe='')}",
                "body": body,
            }
        return {
            "method": "POST",
            "url": f"{instance_url}/api/now/table/{table}",
            "body": body,
        }
    if connector in {"tines", "torq"}:
        return {
            "method": "POST",
            "url": _destination_key(connector, raw_destination),
            "body": _automation_payload(payload, platform=connector),
        }
    if connector == "splunk_hec":
        return {
            "method": "POST",
            "url": _destination_key(connector, raw_destination),
            "body": _splunk_hec_event(
                payload,
                index=splunk_index,
                source=splunk_source,
                sourcetype=splunk_sourcetype,
            ),
        }
    if connector == "webhook":
        return {
            "method": "POST",
            "url": _destination_key(connector, raw_destination),
            "body": payload,
        }
    return {
        "method": "append" if connector == "jsonl" else "write",
        "url": _destination_key(connector, raw_destination),
        "body": payload,
        "action": action,
    }


def remediation_integration_runbook(
    *,
    systems: Iterable[str] = (
        "jsonl",
        "github_issues",
        "jira",
        "servicenow",
        "tines",
        "splunk_hec",
        "torq",
    ),
    close_policy: str = "trust_external_status",
    status_file: str = "statuses.jsonl",
) -> dict[str, Any]:
    """Return value-free operator runbook steps for remediation integrations."""
    policy = str(close_policy or "trust_external_status").strip()
    if policy not in _TICKET_CLOSE_POLICIES:
        raise ValueError(
            "close_policy must be trust_external_status or require_retest_for_resolved"
        )
    normalized = [str(system).strip().lower() for system in systems if str(system).strip()]
    if not normalized:
        normalized = ["jsonl"]
    invalid = [system for system in normalized if system not in _VALID_CONNECTORS]
    if invalid:
        raise ValueError(f"Unsupported remediation integration system: {invalid[0]}")
    status_path = str(status_file or "statuses.jsonl").strip() or "statuses.jsonl"
    system_notes = {
        "jsonl": {
            "mode": "free_local",
            "setup": ["Choose a local JSONL path for ticket event export."],
            "live_gates": ["None; local file write only."],
        },
        "stdout": {
            "mode": "free_local",
            "setup": ["Use stdout when another local scheduler or collector captures output."],
            "live_gates": ["None; console/stdout only."],
        },
        "webhook": {
            "mode": "operator_supplied_webhook",
            "setup": ["Create a scoped receiver URL owned by the operator."],
            "live_gates": ["Use dry-run handoff output before POSTing to the receiver."],
        },
        "github_issues": {
            "mode": "optional_write_connector",
            "setup": ["Create a least-privilege GitHub token in FORGE_GITHUB_TOKEN."],
            "live_gates": ["Confirm repo owner/name and review handoff-plan output before sync."],
        },
        "jira": {
            "mode": "optional_write_connector",
            "setup": ["Set FORGE_JIRA_EMAIL and FORGE_JIRA_API_TOKEN for a scoped Jira account."],
            "live_gates": ["Confirm site URL, project key, and issue type before sync."],
        },
        "servicenow": {
            "mode": "optional_write_connector",
            "setup": [
                "Set ServiceNow bearer token or username/password env vars for a scoped integration user."
            ],
            "live_gates": ["Confirm instance URL and table name before sync."],
        },
        "tines": {
            "mode": "optional_automation_webhook",
            "setup": ["Create an operator-owned Tines webhook action URL."],
            "live_gates": ["Review redacted handoff-plan output before enabling webhook delivery."],
        },
        "splunk_hec": {
            "mode": "optional_siem_event",
            "setup": ["Create a scoped Splunk HEC token in FORGE_SPLUNK_HEC_TOKEN."],
            "live_gates": ["Confirm HEC URL, index, source, and sourcetype before sync."],
        },
        "torq": {
            "mode": "optional_automation_webhook",
            "setup": ["Create an operator-owned Torq webhook trigger URL."],
            "live_gates": ["Review redacted handoff-plan output before enabling webhook delivery."],
        },
    }
    return {
        "schema": "forge.remediation.integration_runbook.v1",
        "systems": [
            {
                "system": system,
                **system_notes[system],
            }
            for system in normalized
        ],
        "workflow": [
            "Run `forge remediation review-queue --engagement N --json`.",
            "Run `forge remediation handoff-plan --engagement N --json` and review generated payloads.",
            "Run `forge remediation sync-tickets --data-dir FORGE_DATA_DIR --json` only after approving write-capable destinations.",
            (
                "Export ticket states to JSON/JSONL, then run "
                f"`forge remediation import-ticket-statuses --data-dir FORGE_DATA_DIR --file {status_path} --dry-run --json`."
            ),
            (
                "Install the scheduled importer with "
                f"`scripts\\install_remediation_ticket_status_import_task.ps1 -StatusFile {status_path}`; "
                "add `-Apply $true` only after dry-run review."
            ),
        ],
        "approval_policy": {
            "close_policy": policy,
            "requires_retest_for_external_closure": policy == "require_retest_for_resolved",
            "recommended_for_production": "require_retest_for_resolved",
        },
        "safety": {
            "free_first_default": True,
            "secrets_in_output": False,
            "network_calls": False,
            "file_writes": False,
        },
    }


def _post_splunk_hec(
    url: str,
    payload: dict[str, Any],
    *,
    token_env: str,
    index: str,
    source: str,
    sourcetype: str,
    timeout_seconds: float,
) -> None:
    body = json.dumps(
        _splunk_hec_event(payload, index=index, source=source, sourcetype=sourcetype),
        sort_keys=True,
    ).encode("utf-8")
    request = urllib.request.Request(
        _splunk_hec_url(url),
        data=body,
        headers={
            "Authorization": f"Splunk {_splunk_hec_token(token_env)}",
            "Content-Type": "application/json",
            "User-Agent": "forge-remediation-ticket-sync",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        status = int(getattr(response, "status", 200))
    if status < 200 or status >= 300:
        raise RuntimeError(f"Splunk HEC returned HTTP {status}")


def _github_repo_path(repo: str | None) -> str:
    repo_path = str(repo or "").strip().strip("/")
    if not _GITHUB_REPO_RE.fullmatch(repo_path):
        raise ValueError("github_repo must be in owner/repo format")
    return repo_path


def _github_api_base(api_url: str | None) -> str:
    parsed = urllib.parse.urlsplit(str(api_url or "https://api.github.com").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("github_api_url must be an http(s) URL")
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path.rstrip("/"),
            "",
            "",
        )
    )


def _github_issue_number(row: sqlite3.Row) -> str:
    ref = str(row["ticket_ref"] or "").strip()
    if ref.isdigit():
        return ref
    url = str(row["ticket_url"] or "").strip()
    match = re.search(r"/issues/(\d+)(?:$|[/?#])", url)
    return match.group(1) if match else ""


def _github_issue_title(item: dict[str, Any]) -> str:
    severity = str(item.get("severity") or "INFO").upper()
    title = str(item.get("title") or item.get("finding_ref") or "Remediation item").strip()
    return f"[FORGE] {severity} {title}"[:256]


def _github_issue_body(item: dict[str, Any]) -> str:
    lines = [
        "FORGE remediation item",
        "",
        f"- Engagement: {item.get('engagement_id')}",
        f"- Item: {item.get('id')}",
        f"- Source: {item.get('finding_table')}:{item.get('finding_ref')}",
        f"- Severity: {item.get('severity')}",
        f"- Status: {item.get('status')}",
        f"- Owner: {item.get('owner') or '-'}",
        f"- SLA: {item.get('sla_due_at') or '-'}",
        f"- Retest: {item.get('retest_status') or '-'}",
    ]
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    source = str(metadata.get("source") or "").strip()
    escalation = str(metadata.get("escalation") or "").strip()
    if source:
        lines.append(f"- Metadata source: {source}")
    if escalation:
        lines.append(f"- Escalation: {escalation}")
    return "\n".join(lines)


def _github_issue_state(item: dict[str, Any]) -> str:
    status = str(item.get("status") or "").strip().lower()
    return "closed" if status in {"resolved", "false_positive"} else "open"


def _jira_base_url(base_url: str | None) -> str:
    parsed = urllib.parse.urlsplit(str(base_url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("jira_base_url must be an http(s) URL")
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path.rstrip("/"),
            "",
            "",
        )
    )


def _jira_project_key(project_key: str | None) -> str:
    key = str(project_key or "").strip()
    if not _JIRA_PROJECT_RE.fullmatch(key):
        raise ValueError("jira_project_key must be a Jira project key")
    return key


def _jira_auth_header(email_env: str, token_env: str) -> str:
    email_env = str(email_env or "FORGE_JIRA_EMAIL").strip()
    token_env = str(token_env or "FORGE_JIRA_API_TOKEN").strip()
    email = os.environ.get(email_env, "").strip()
    token = os.environ.get(token_env, "").strip()
    if not email:
        raise ValueError(f"{email_env} is required for Jira sync")
    if not token:
        raise ValueError(f"{token_env} is required for Jira sync")
    encoded = base64.b64encode(f"{email}:{token}".encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"


def _jira_issue_key(row: sqlite3.Row) -> str:
    ref = str(row["ticket_ref"] or "").strip()
    if _JIRA_ISSUE_KEY_RE.fullmatch(ref):
        return ref
    url = str(row["ticket_url"] or "").strip()
    match = _JIRA_ISSUE_KEY_RE.search(url)
    return match.group(0) if match else ""


def _jira_issue_title(item: dict[str, Any]) -> str:
    severity = str(item.get("severity") or "INFO").upper()
    title = str(item.get("title") or item.get("finding_ref") or "Remediation item").strip()
    return f"[FORGE] {severity} {title}"[:255]


def _jira_issue_description(item: dict[str, Any]) -> dict[str, Any]:
    lines = [
        "FORGE remediation item",
        "",
        f"Engagement: {item.get('engagement_id')}",
        f"Item: {item.get('id')}",
        f"Source: {item.get('finding_table')}:{item.get('finding_ref')}",
        f"Severity: {item.get('severity')}",
        f"Status: {item.get('status')}",
        f"Owner: {item.get('owner') or '-'}",
        f"SLA: {item.get('sla_due_at') or '-'}",
        f"Retest: {item.get('retest_status') or '-'}",
    ]
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    source = str(metadata.get("source") or "").strip()
    escalation = str(metadata.get("escalation") or "").strip()
    if source:
        lines.append(f"Metadata source: {source}")
    if escalation:
        lines.append(f"Escalation: {escalation}")
    content: list[dict[str, Any]] = []
    for line in lines:
        paragraph: dict[str, Any] = {"type": "paragraph"}
        if line:
            paragraph["content"] = [{"type": "text", "text": line}]
        content.append(paragraph)
    return {"type": "doc", "version": 1, "content": content}


def _sync_jira_issue(
    con: sqlite3.Connection,
    *,
    row: sqlite3.Row,
    payload: dict[str, Any],
    jira_base_url: str | None,
    jira_project_key: str | None,
    jira_issue_type: str,
    jira_email_env: str,
    jira_token_env: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    api_base = _jira_base_url(jira_base_url)
    project_key = _jira_project_key(jira_project_key)
    issue_type = str(jira_issue_type or "Task").strip() or "Task"
    issue_key = _jira_issue_key(row)
    item = payload["remediation_item"]
    fields = {
        "summary": _jira_issue_title(item),
        "description": _jira_issue_description(item),
    }
    if issue_key:
        url = f"{api_base}/rest/api/3/issue/{urllib.parse.quote(issue_key, safe='')}"
        method = "PUT"
        body = {"fields": fields}
    else:
        url = f"{api_base}/rest/api/3/issue"
        method = "POST"
        body = {
            "fields": {
                **fields,
                "project": {"key": project_key},
                "issuetype": {"name": issue_type},
            }
        }
    request = urllib.request.Request(
        url,
        data=json.dumps(body, sort_keys=True).encode("utf-8"),
        headers={
            "Accept": "application/json",
            "Authorization": _jira_auth_header(jira_email_env, jira_token_env),
            "Content-Type": "application/json",
            "User-Agent": "forge-remediation-ticket-sync",
        },
        method=method,
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        status = int(getattr(response, "status", 200))
        raw_body = response.read().decode("utf-8")
    if status < 200 or status >= 300:
        raise RuntimeError(f"Jira API returned HTTP {status}")
    try:
        response_payload = json.loads(raw_body) if raw_body else {}
    except json.JSONDecodeError:
        response_payload = {}
    created_key = str(response_payload.get("key") or issue_key or "").strip()
    if not created_key:
        raise RuntimeError("Jira API response did not include an issue key")
    issue_url = f"{api_base}/browse/{urllib.parse.quote(created_key, safe='')}"
    if not issue_key:
        con.execute(
            """
            UPDATE remediation_items
            SET ticket_system='jira',
                ticket_ref=?,
                ticket_url=?,
                updated_at=CURRENT_TIMESTAMP
            WHERE engagement_id=? AND id=?
            """,
            (
                created_key,
                issue_url,
                int(row["engagement_id"]),
                int(row["id"]),
            ),
        )
    return {
        "jira_project_key": project_key,
        "jira_issue_key": created_key,
        "jira_issue_url": issue_url,
        "jira_method": method,
    }


def _servicenow_instance_url(instance_url: str | None) -> str:
    parsed = urllib.parse.urlsplit(str(instance_url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("servicenow_instance_url must be an http(s) URL")
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path.rstrip("/"),
            "",
            "",
        )
    )


def _servicenow_table_name(table: str | None) -> str:
    table_name = str(table or "incident").strip()
    if not _SERVICENOW_TABLE_RE.fullmatch(table_name):
        raise ValueError("servicenow_table must be a ServiceNow table name")
    return table_name


def _servicenow_auth_header(
    *,
    username_env: str,
    password_env: str,
    token_env: str | None,
) -> str:
    resolved_token_env = str(token_env or "").strip()
    if resolved_token_env:
        token = os.environ.get(resolved_token_env, "").strip()
        if token:
            return f"Bearer {token}"
    username_env = str(username_env or "FORGE_SERVICENOW_USERNAME").strip()
    password_env = str(password_env or "FORGE_SERVICENOW_PASSWORD").strip()
    username = os.environ.get(username_env, "").strip()
    password = os.environ.get(password_env, "").strip()
    if not username:
        raise ValueError(f"{username_env} is required for ServiceNow sync")
    if not password:
        raise ValueError(f"{password_env} is required for ServiceNow sync")
    encoded = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"


def _servicenow_sys_id(row: sqlite3.Row) -> str:
    ref = str(row["ticket_ref"] or "").strip()
    if _SERVICENOW_SYS_ID_RE.fullmatch(ref):
        return ref.lower()
    url = str(row["ticket_url"] or "").strip()
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qs(parsed.query)
    for values in query.values():
        for value in values:
            match = _SERVICENOW_SYS_ID_RE.search(value)
            if match:
                return match.group(0).lower()
    match = _SERVICENOW_SYS_ID_RE.search(url)
    return match.group(0).lower() if match else ""


def _servicenow_ticket_number(row: sqlite3.Row) -> str:
    ref = str(row["ticket_ref"] or "").strip()
    match = _SERVICENOW_NUMBER_RE.fullmatch(ref)
    if match:
        return match.group(0)
    url = str(row["ticket_url"] or "").strip()
    match = _SERVICENOW_NUMBER_RE.search(url)
    return match.group(0) if match else ""


def _servicenow_summary(item: dict[str, Any]) -> str:
    severity = str(item.get("severity") or "INFO").upper()
    title = str(item.get("title") or item.get("finding_ref") or "Remediation item").strip()
    return f"[FORGE] {severity} {title}"[:160]


def _servicenow_description(item: dict[str, Any]) -> str:
    lines = [
        "FORGE remediation item",
        "",
        f"Engagement: {item.get('engagement_id')}",
        f"Item: {item.get('id')}",
        f"Source: {item.get('finding_table')}:{item.get('finding_ref')}",
        f"Severity: {item.get('severity')}",
        f"Status: {item.get('status')}",
        f"Owner: {item.get('owner') or '-'}",
        f"SLA: {item.get('sla_due_at') or '-'}",
        f"Retest: {item.get('retest_status') or '-'}",
    ]
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    source = str(metadata.get("source") or "").strip()
    escalation = str(metadata.get("escalation") or "").strip()
    if source:
        lines.append(f"Metadata source: {source}")
    if escalation:
        lines.append(f"Escalation: {escalation}")
    return "\n".join(lines)


def _servicenow_record_url(instance_url: str, table: str, sys_id: str) -> str:
    uri = urllib.parse.quote(f"{table}.do?sys_id={sys_id}", safe="")
    return f"{instance_url}/nav_to.do?uri={uri}"


def _servicenow_request(
    url: str,
    *,
    method: str,
    body: dict[str, Any] | None,
    auth_header: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=(json.dumps(body, sort_keys=True).encode("utf-8") if body is not None else None),
        headers={
            "Accept": "application/json",
            "Authorization": auth_header,
            "Content-Type": "application/json",
            "User-Agent": "forge-remediation-ticket-sync",
        },
        method=method,
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        status = int(getattr(response, "status", 200))
        raw_body = response.read().decode("utf-8")
    if status < 200 or status >= 300:
        raise RuntimeError(f"ServiceNow Table API returned HTTP {status}")
    try:
        return json.loads(raw_body) if raw_body else {}
    except json.JSONDecodeError:
        return {}


def _lookup_servicenow_sys_id(
    *,
    instance_url: str,
    table: str,
    ticket_number: str,
    auth_header: str,
    timeout_seconds: float,
) -> tuple[str, str]:
    query = urllib.parse.urlencode(
        {
            "sysparm_query": f"number={ticket_number}",
            "sysparm_fields": "sys_id,number",
            "sysparm_limit": "1",
        }
    )
    payload = _servicenow_request(
        f"{instance_url}/api/now/table/{table}?{query}",
        method="GET",
        body=None,
        auth_header=auth_header,
        timeout_seconds=timeout_seconds,
    )
    records = payload.get("result") if isinstance(payload.get("result"), list) else []
    if not records:
        return "", ""
    first = records[0] if isinstance(records[0], dict) else {}
    return str(first.get("sys_id") or "").strip().lower(), str(first.get("number") or ticket_number).strip()


def _sync_servicenow_record(
    con: sqlite3.Connection,
    *,
    row: sqlite3.Row,
    payload: dict[str, Any],
    servicenow_instance_url: str | None,
    servicenow_table: str,
    servicenow_username_env: str,
    servicenow_password_env: str,
    servicenow_token_env: str | None,
    timeout_seconds: float,
) -> dict[str, Any]:
    instance_url = _servicenow_instance_url(servicenow_instance_url)
    table = _servicenow_table_name(servicenow_table)
    auth_header = _servicenow_auth_header(
        username_env=servicenow_username_env,
        password_env=servicenow_password_env,
        token_env=servicenow_token_env,
    )
    item = payload["remediation_item"]
    sys_id = _servicenow_sys_id(row)
    number = _servicenow_ticket_number(row)
    method = "PATCH"
    if not sys_id and number:
        sys_id, number = _lookup_servicenow_sys_id(
            instance_url=instance_url,
            table=table,
            ticket_number=number,
            auth_header=auth_header,
            timeout_seconds=timeout_seconds,
        )
    body = {
        "short_description": _servicenow_summary(item),
        "description": _servicenow_description(item),
        "correlation_id": f"forge:{item.get('engagement_id')}:{item.get('id')}",
    }
    if sys_id:
        body["work_notes"] = (
            f"Forge remediation sync: status={item.get('status')} "
            f"owner={item.get('owner') or '-'} retest={item.get('retest_status') or '-'}"
        )
        response_payload = _servicenow_request(
            f"{instance_url}/api/now/table/{table}/{urllib.parse.quote(sys_id, safe='')}",
            method=method,
            body=body,
            auth_header=auth_header,
            timeout_seconds=timeout_seconds,
        )
    else:
        method = "POST"
        response_payload = _servicenow_request(
            f"{instance_url}/api/now/table/{table}",
            method=method,
            body=body,
            auth_header=auth_header,
            timeout_seconds=timeout_seconds,
        )
    result = response_payload.get("result") if isinstance(response_payload.get("result"), dict) else {}
    sys_id = str(result.get("sys_id") or sys_id or "").strip().lower()
    number = str(result.get("number") or number or sys_id or "").strip()
    if not sys_id:
        raise RuntimeError("ServiceNow Table API response did not include a sys_id")
    record_url = _servicenow_record_url(instance_url, table, sys_id)
    if method == "POST":
        con.execute(
            """
            UPDATE remediation_items
            SET ticket_system='servicenow',
                ticket_ref=?,
                ticket_url=?,
                updated_at=CURRENT_TIMESTAMP
            WHERE engagement_id=? AND id=?
            """,
            (
                number,
                record_url,
                int(row["engagement_id"]),
                int(row["id"]),
            ),
        )
    return {
        "servicenow_table": table,
        "servicenow_sys_id": sys_id,
        "servicenow_number": number,
        "servicenow_record_url": record_url,
        "servicenow_method": method,
    }


def _sync_github_issue(
    con: sqlite3.Connection,
    *,
    row: sqlite3.Row,
    payload: dict[str, Any],
    github_repo: str | None,
    github_token_env: str,
    github_api_url: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    repo = _github_repo_path(github_repo)
    token_env = str(github_token_env or "FORGE_GITHUB_TOKEN").strip()
    token = os.environ.get(token_env, "").strip()
    if not token:
        raise ValueError(f"{token_env} is required for GitHub Issues sync")
    item = payload["remediation_item"]
    issue_number = _github_issue_number(row)
    api_base = _github_api_base(github_api_url)
    if issue_number:
        url = f"{api_base}/repos/{repo}/issues/{issue_number}"
        method = "PATCH"
        body = {
            "title": _github_issue_title(item),
            "body": _github_issue_body(item),
            "state": _github_issue_state(item),
        }
    else:
        url = f"{api_base}/repos/{repo}/issues"
        method = "POST"
        body = {
            "title": _github_issue_title(item),
            "body": _github_issue_body(item),
        }
    request = urllib.request.Request(
        url,
        data=json.dumps(body, sort_keys=True).encode("utf-8"),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "forge-remediation-ticket-sync",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method=method,
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        status = int(getattr(response, "status", 200))
        raw_body = response.read().decode("utf-8")
    if status < 200 or status >= 300:
        raise RuntimeError(f"GitHub Issues API returned HTTP {status}")
    try:
        response_payload = json.loads(raw_body) if raw_body else {}
    except json.JSONDecodeError:
        response_payload = {}
    number = str(response_payload.get("number") or issue_number or "")
    issue_url = str(response_payload.get("html_url") or "")
    if not issue_number and number:
        con.execute(
            """
            UPDATE remediation_items
            SET ticket_system='github',
                ticket_ref=?,
                ticket_url=?,
                updated_at=CURRENT_TIMESTAMP
            WHERE engagement_id=? AND id=?
            """,
            (
                number,
                issue_url or f"https://github.com/{repo}/issues/{number}",
                int(row["engagement_id"]),
                int(row["id"]),
            ),
        )
    return {
        "github_repo": repo,
        "github_issue_number": number,
        "github_issue_url": issue_url,
        "github_method": method,
    }


def _deliver_one(
    *,
    connector: str,
    destination: str,
    payload: dict[str, Any],
    stdout: TextIO,
    timeout_seconds: float,
) -> None:
    if connector == "jsonl":
        _write_jsonl(Path(destination), payload)
        return
    if connector == "stdout":
        _write_stdout(stdout, payload)
        return
    if connector == "webhook":
        _post_webhook(destination, payload, timeout_seconds=timeout_seconds)
        return
    if connector == "github_issues":
        raise ValueError("GitHub Issues delivery must use the GitHub adapter")
    if connector == "jira":
        raise ValueError("Jira delivery must use the Jira adapter")
    if connector == "servicenow":
        raise ValueError("ServiceNow delivery must use the ServiceNow adapter")
    raise ValueError(f"Unsupported remediation ticket connector: {connector}")


def _status_event_rows(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        loaded = json.loads(stripped)
        if not isinstance(loaded, list):
            raise ValueError("ticket status file JSON must be a list of objects")
        return [row for row in loaded if isinstance(row, dict)]
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        normalized = line.strip()
        if not normalized:
            continue
        try:
            row = json.loads(normalized)
        except json.JSONDecodeError as exc:
            raise ValueError(f"ticket status JSONL line {line_number} is invalid: {exc}") from exc
        if isinstance(row, dict):
            rows.append(row)
    return rows


def load_remediation_ticket_status_events(path: Path) -> list[dict[str, Any]]:
    """Load JSON or JSONL remediation ticket status events without applying them."""
    return _status_event_rows(path)


def _ticket_status_item_row(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    event: dict[str, Any],
) -> sqlite3.Row | None:
    item_id = event.get("remediation_item_id", event.get("item_id"))
    if item_id not in (None, ""):
        try:
            numeric_item_id = int(item_id)
        except (TypeError, ValueError):
            return None
        return con.execute(
            """
            SELECT id, engagement_id, finding_table, finding_id, finding_ref,
                   title, severity, owner, sla_due_at, status,
                   risk_acceptance_reason, risk_accepted_by, risk_accepted_at,
                   risk_acceptance_expires_at,
                   retest_status, retest_requested_at, retested_at,
                   ticket_system, ticket_ref, ticket_url, metadata_json,
                   created_at, updated_at
            FROM remediation_items
            WHERE engagement_id=? AND id=?
            """,
            (int(engagement_id), numeric_item_id),
        ).fetchone()
    ticket_ref = _bounded_text(event.get("ticket_ref") or event.get("external_ref"), 120)
    if not ticket_ref:
        return None
    connector = _bounded_text(event.get("connector") or event.get("ticket_system"), 80).lower()
    ticket_system = _CONNECTOR_TICKET_SYSTEM.get(connector, connector)
    params: list[Any] = [int(engagement_id), ticket_ref]
    system_filter = ""
    if ticket_system:
        system_filter = "AND LOWER(COALESCE(ticket_system, '')) IN (?, ?)"
        params.extend([ticket_system, connector])
    return con.execute(
        f"""
        SELECT id, engagement_id, finding_table, finding_id, finding_ref,
               title, severity, owner, sla_due_at, status,
               risk_acceptance_reason, risk_accepted_by, risk_accepted_at,
               risk_acceptance_expires_at,
               retest_status, retest_requested_at, retested_at,
               ticket_system, ticket_ref, ticket_url, metadata_json,
               created_at, updated_at
        FROM remediation_items
        WHERE engagement_id=?
          AND ticket_ref=?
          {system_filter}
        ORDER BY updated_at DESC, id DESC
        LIMIT 1
        """,
        tuple(params),
    ).fetchone()


def _ticket_status_metadata(
    row: sqlite3.Row,
    *,
    event: dict[str, Any],
    new_status: str,
    external_status: str,
    operator: str,
    imported_at: str,
    policy_action: str = "",
) -> str:
    metadata = _safe_metadata(str(row["metadata_json"] or "{}"))
    history = metadata.get("ticket_status_reconciliation")
    if not isinstance(history, list):
        history = []
    entry = {
        "imported_at": imported_at,
        "operator": _bounded_text(operator, 80),
        "connector": _bounded_text(event.get("connector") or event.get("ticket_system"), 80),
        "ticket_ref": _bounded_text(event.get("ticket_ref") or event.get("external_ref"), 120),
        "external_status": external_status,
        "previous_status": str(row["status"] or ""),
        "new_status": new_status,
    }
    if policy_action:
        entry["policy_action"] = policy_action
    external_url = _bounded_text(event.get("ticket_url") or event.get("external_url"), 240)
    if external_url:
        entry["ticket_url"] = external_url
    external_updated_at = _bounded_text(
        event.get("external_updated_at") or event.get("updated_at"),
        80,
    )
    if external_updated_at:
        entry["external_updated_at"] = external_updated_at
    history.append(entry)
    metadata["ticket_status_reconciliation"] = history[-20:]
    return json.dumps(metadata, sort_keys=True)


def import_remediation_ticket_statuses(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    status_events: Iterable[dict[str, Any]],
    operator: str = "remediation-ticket-status-import",
    dry_run: bool = False,
    close_policy: str = "trust_external_status",
) -> dict[str, Any]:
    """Import operator-supplied ticket status rows without calling external APIs."""
    _ensure_rows(con)
    imported_at = _utc_timestamp()
    results: list[dict[str, Any]] = []
    summary = {
        "input_count": 0,
        "matched_count": 0,
        "updated_count": 0,
        "unchanged_count": 0,
        "review_count": 0,
        "dry_run": bool(dry_run),
    }
    for event in status_events:
        if not isinstance(event, dict):
            continue
        summary["input_count"] += 1
        new_status, external_status = _external_status(
            event.get("external_status")
            or event.get("status")
            or event.get("state")
            or event.get("ticket_status")
        )
        row = _ticket_status_item_row(con, engagement_id=engagement_id, event=event)
        if row is None:
            summary["review_count"] += 1
            results.append(
                {
                    "action": "review",
                    "reason": "no_matching_remediation_item",
                    "ticket_ref": _bounded_text(event.get("ticket_ref") or event.get("external_ref"), 120),
                    "external_status": external_status,
                }
            )
            continue
        summary["matched_count"] += 1
        item_id = int(row["id"])
        old_status = str(row["status"] or "")
        if not new_status:
            summary["review_count"] += 1
            results.append(
                {
                    "action": "review",
                    "reason": "unknown_external_status",
                    "remediation_item_id": item_id,
                    "current_status": old_status,
                    "external_status": external_status,
                }
            )
            continue
        new_status, retest_status, policy_action = _status_after_close_policy(
            new_status,
            close_policy=close_policy,
        )
        if new_status == old_status:
            summary["unchanged_count"] += 1
            results.append(
                {
                    "action": "unchanged",
                    "remediation_item_id": item_id,
                    "status": old_status,
                    "external_status": external_status,
                }
            )
            continue
        metadata_json = _ticket_status_metadata(
            row,
            event=event,
            new_status=new_status,
            external_status=external_status,
            operator=operator,
            imported_at=imported_at,
            policy_action=policy_action,
        )
        if not dry_run:
            ticket_ref = _bounded_text(event.get("ticket_ref") or event.get("external_ref"), 120)
            ticket_url = _bounded_text(event.get("ticket_url") or event.get("external_url"), 240)
            ticket_system = _bounded_text(
                _CONNECTOR_TICKET_SYSTEM.get(
                    _bounded_text(event.get("connector") or event.get("ticket_system"), 80).lower(),
                    event.get("ticket_system") or event.get("connector"),
                ),
                80,
            )
            con.execute(
                """
                UPDATE remediation_items
                SET status=?,
                    retest_status=COALESCE(NULLIF(?, ''), retest_status),
                    ticket_system=COALESCE(NULLIF(?, ''), ticket_system),
                    ticket_ref=COALESCE(NULLIF(?, ''), ticket_ref),
                    ticket_url=COALESCE(NULLIF(?, ''), ticket_url),
                    metadata_json=?,
                    updated_at=CURRENT_TIMESTAMP
                WHERE engagement_id=? AND id=?
                """,
                (
                    new_status,
                    retest_status,
                    ticket_system,
                    ticket_ref,
                    ticket_url,
                    metadata_json,
                    int(engagement_id),
                    item_id,
                ),
            )
            con.execute(
                """
                INSERT INTO audit_log
                    (engagement_id, phase, module, action, target, result, operator)
                VALUES (?, 'remediation', 'remediation', 'remediation_ticket_status_import', ?, ?, ?)
                """,
                (
                    int(engagement_id),
                    f"remediation_items:{item_id}",
                    json.dumps(
                        {
                            "previous_status": old_status,
                            "new_status": new_status,
                            "external_status": external_status,
                            "policy_action": policy_action,
                        },
                        sort_keys=True,
                    ),
                    operator,
                ),
            )
        summary["updated_count"] += 1
        results.append(
            {
                "action": "would_update" if dry_run else "updated",
                "remediation_item_id": item_id,
                "previous_status": old_status,
                "new_status": new_status,
                "external_status": external_status,
                "policy_action": policy_action,
            }
        )
    if not dry_run:
        con.commit()
    return {
        "engagement_id": int(engagement_id),
        "mode": "dry_run" if dry_run else "apply",
        "summary": summary,
        "items": results,
    }


def import_remediation_ticket_status_file(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    path: Path,
    operator: str = "remediation-ticket-status-import",
    dry_run: bool = False,
    close_policy: str = "trust_external_status",
) -> dict[str, Any]:
    return import_remediation_ticket_statuses(
        con,
        engagement_id=engagement_id,
        status_events=_status_event_rows(path),
        operator=operator,
        dry_run=dry_run,
        close_policy=close_policy,
    )


def remediation_ticket_handoff_plan(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    connectors: Iterable[str] = ("jsonl",),
    jsonl_path: Path | None = None,
    webhook_url: str | None = None,
    github_repo: str | None = None,
    github_api_url: str = "https://api.github.com",
    jira_base_url: str | None = None,
    jira_project_key: str | None = None,
    jira_issue_type: str = "Task",
    servicenow_instance_url: str | None = None,
    servicenow_table: str = "incident",
    tines_webhook_url: str | None = None,
    splunk_hec_url: str | None = None,
    splunk_index: str = "",
    splunk_source: str = "forge",
    splunk_sourcetype: str = "forge:remediation:ticket",
    torq_webhook_url: str | None = None,
    db_path: str | None = None,
    operator: str = "remediation-ticket-handoff",
    item_id: int | None = None,
    limit: int = 100,
    force: bool = False,
) -> dict[str, Any]:
    """Build review-only remediation integration payloads without network or file writes."""
    _ensure_rows(con)
    normalized = [str(connector).strip().lower() for connector in connectors if str(connector).strip()]
    if not normalized:
        normalized = ["jsonl"]
    for connector in normalized:
        if connector not in _VALID_CONNECTORS:
            raise ValueError(f"Unsupported remediation ticket connector: {connector}")

    connector_results: list[dict[str, Any]] = []
    total_items = 0
    for connector in normalized:
        raw_destination: str | Path | None
        if connector == "jsonl":
            raw_destination = jsonl_path or Path("remediation_tickets.jsonl")
        elif connector == "webhook":
            if not webhook_url:
                raise ValueError("webhook_url is required for webhook remediation ticket handoff")
            raw_destination = webhook_url
        elif connector == "github_issues":
            repo_path = _github_repo_path(github_repo)
            raw_destination = f"{_github_api_base(github_api_url)}/repos/{repo_path}"
        elif connector == "jira":
            raw_destination = (
                f"{_jira_base_url(jira_base_url)}/rest/api/3/issue/"
                f"{_jira_project_key(jira_project_key)}"
            )
        elif connector == "servicenow":
            raw_destination = (
                f"{_servicenow_instance_url(servicenow_instance_url)}/api/now/table/"
                f"{_servicenow_table_name(servicenow_table)}"
            )
        elif connector == "tines":
            if not tines_webhook_url:
                raise ValueError("tines_webhook_url is required for Tines remediation handoff")
            raw_destination = tines_webhook_url
        elif connector == "splunk_hec":
            raw_destination = _splunk_hec_url(splunk_hec_url)
        elif connector == "torq":
            if not torq_webhook_url:
                raise ValueError("torq_webhook_url is required for Torq remediation handoff")
            raw_destination = torq_webhook_url
        else:
            raw_destination = "stdout"
        destination = _destination_key(connector, raw_destination)
        rows = _candidate_rows(
            con,
            engagement_id=engagement_id,
            connector=connector,
            destination=destination,
            item_id=item_id,
            force=force,
            limit=limit,
        )
        items: list[dict[str, Any]] = []
        for row in rows:
            payload = _handoff_payload(
                _payload(
                    row,
                    connector=connector,
                    destination=destination,
                    operator=operator,
                    db_path=db_path,
                )
            )
            items.append(
                {
                    "remediation_item_id": int(row["id"]),
                    "action": str(payload["action"]),
                    "template": _ticket_handoff_template(
                        row,
                        connector=connector,
                        payload=payload,
                        raw_destination=raw_destination,
                        github_repo=github_repo,
                        github_api_url=github_api_url,
                        jira_base_url=jira_base_url,
                        jira_project_key=jira_project_key,
                        jira_issue_type=jira_issue_type,
                        servicenow_instance_url=servicenow_instance_url,
                        servicenow_table=servicenow_table,
                        splunk_index=splunk_index,
                        splunk_source=splunk_source,
                        splunk_sourcetype=splunk_sourcetype,
                    ),
                }
            )
        total_items += len(items)
        connector_results.append(
            {
                "connector": connector,
                "destination": destination,
                "candidate_count": len(rows),
                "items": items,
            }
        )
    return {
        "engagement_id": int(engagement_id),
        "mode": "review_only",
        "network": "disabled",
        "file_writes": "disabled",
        "connector_count": len(connector_results),
        "item_template_count": total_items,
        "connectors": connector_results,
    }


def sync_remediation_tickets(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    connectors: Iterable[str] = ("jsonl",),
    jsonl_path: Path | None = None,
    webhook_url: str | None = None,
    github_repo: str | None = None,
    github_token_env: str = "FORGE_GITHUB_TOKEN",
    github_api_url: str = "https://api.github.com",
    jira_base_url: str | None = None,
    jira_project_key: str | None = None,
    jira_issue_type: str = "Task",
    jira_email_env: str = "FORGE_JIRA_EMAIL",
    jira_token_env: str = "FORGE_JIRA_API_TOKEN",
    servicenow_instance_url: str | None = None,
    servicenow_table: str = "incident",
    servicenow_username_env: str = "FORGE_SERVICENOW_USERNAME",
    servicenow_password_env: str = "FORGE_SERVICENOW_PASSWORD",
    servicenow_token_env: str | None = None,
    tines_webhook_url: str | None = None,
    tines_token_env: str = "FORGE_TINES_WEBHOOK_TOKEN",
    splunk_hec_url: str | None = None,
    splunk_hec_token_env: str = "FORGE_SPLUNK_HEC_TOKEN",
    splunk_index: str = "",
    splunk_source: str = "forge",
    splunk_sourcetype: str = "forge:remediation:ticket",
    torq_webhook_url: str | None = None,
    torq_token_env: str = "FORGE_TORQ_WEBHOOK_TOKEN",
    stdout: TextIO | None = None,
    db_path: str | None = None,
    operator: str = "remediation-ticket-sync",
    item_id: int | None = None,
    limit: int = 100,
    timeout_seconds: float = 10.0,
    force: bool = False,
) -> dict[str, Any]:
    _ensure_rows(con)
    output = stdout or sys.stdout
    normalized = [str(connector).strip().lower() for connector in connectors if str(connector).strip()]
    if not normalized:
        normalized = ["jsonl"]
    for connector in normalized:
        if connector not in _VALID_CONNECTORS:
            raise ValueError(f"Unsupported remediation ticket connector: {connector}")

    totals = {"sync_count": 0, "failure_count": 0}
    connector_results: list[dict[str, Any]] = []
    for connector in normalized:
        raw_destination: str | Path | None
        if connector == "jsonl":
            raw_destination = jsonl_path or Path("remediation_tickets.jsonl")
        elif connector == "webhook":
            if not webhook_url:
                raise ValueError("webhook_url is required for webhook remediation ticket sync")
            raw_destination = webhook_url
        elif connector == "github_issues":
            repo_path = _github_repo_path(github_repo)
            raw_destination = f"{_github_api_base(github_api_url)}/repos/{repo_path}"
        elif connector == "jira":
            raw_destination = (
                f"{_jira_base_url(jira_base_url)}/rest/api/3/issue/"
                f"{_jira_project_key(jira_project_key)}"
            )
        elif connector == "servicenow":
            raw_destination = (
                f"{_servicenow_instance_url(servicenow_instance_url)}/api/now/table/"
                f"{_servicenow_table_name(servicenow_table)}"
            )
        elif connector == "tines":
            if not tines_webhook_url:
                raise ValueError("tines_webhook_url is required for Tines remediation sync")
            raw_destination = tines_webhook_url
        elif connector == "splunk_hec":
            raw_destination = _splunk_hec_url(splunk_hec_url)
        elif connector == "torq":
            if not torq_webhook_url:
                raise ValueError("torq_webhook_url is required for Torq remediation sync")
            raw_destination = torq_webhook_url
        else:
            raw_destination = "stdout"
        destination = _destination_key(connector, raw_destination)
        rows = _candidate_rows(
            con,
            engagement_id=engagement_id,
            connector=connector,
            destination=destination,
            item_id=item_id,
            force=force,
            limit=limit,
        )
        delivered = 0
        failed = 0
        for row in rows:
            payload = _payload(
                row,
                connector=connector,
                destination=destination,
                operator=operator,
                db_path=db_path,
            )
            action = str(payload["action"])
            delivery_metadata: dict[str, Any] = {}
            try:
                if connector == "github_issues":
                    delivery_metadata = _sync_github_issue(
                        con,
                        row=row,
                        payload=payload,
                        github_repo=github_repo,
                        github_token_env=github_token_env,
                        github_api_url=github_api_url,
                        timeout_seconds=timeout_seconds,
                    )
                elif connector == "jira":
                    delivery_metadata = _sync_jira_issue(
                        con,
                        row=row,
                        payload=payload,
                        jira_base_url=jira_base_url,
                        jira_project_key=jira_project_key,
                        jira_issue_type=jira_issue_type,
                        jira_email_env=jira_email_env,
                        jira_token_env=jira_token_env,
                        timeout_seconds=timeout_seconds,
                    )
                elif connector == "servicenow":
                    delivery_metadata = _sync_servicenow_record(
                        con,
                        row=row,
                        payload=payload,
                        servicenow_instance_url=servicenow_instance_url,
                        servicenow_table=servicenow_table,
                        servicenow_username_env=servicenow_username_env,
                        servicenow_password_env=servicenow_password_env,
                        servicenow_token_env=servicenow_token_env,
                        timeout_seconds=timeout_seconds,
                    )
                elif connector == "tines":
                    _post_automation_webhook(
                        str(raw_destination),
                        payload,
                        platform="tines",
                        token_env=tines_token_env,
                        timeout_seconds=timeout_seconds,
                    )
                    delivery_metadata = {"automation_platform": "tines"}
                elif connector == "splunk_hec":
                    _post_splunk_hec(
                        str(raw_destination),
                        payload,
                        token_env=splunk_hec_token_env,
                        index=splunk_index,
                        source=splunk_source,
                        sourcetype=splunk_sourcetype,
                        timeout_seconds=timeout_seconds,
                    )
                    delivery_metadata = {
                        "automation_platform": "splunk_hec",
                        "splunk_source": splunk_source,
                        "splunk_sourcetype": splunk_sourcetype,
                    }
                    if splunk_index:
                        delivery_metadata["splunk_index"] = splunk_index
                elif connector == "torq":
                    _post_automation_webhook(
                        str(raw_destination),
                        payload,
                        platform="torq",
                        token_env=torq_token_env,
                        timeout_seconds=timeout_seconds,
                    )
                    delivery_metadata = {"automation_platform": "torq"}
                else:
                    _deliver_one(
                        connector=connector,
                        destination=str(raw_destination or destination),
                        payload=payload,
                        stdout=output,
                        timeout_seconds=timeout_seconds,
                    )
            except (OSError, RuntimeError, ValueError, urllib.error.URLError) as exc:
                failed += 1
                _record_event(
                    con,
                    row=row,
                    connector=connector,
                    destination=destination,
                    action=action,
                    status="failed",
                    delivered_at=None,
                    error=str(exc),
                    metadata={
                        "operator": operator,
                        "error_type": type(exc).__name__,
                    },
                )
                continue
            delivered += 1
            _record_event(
                con,
                row=row,
                connector=connector,
                destination=destination,
                action=action,
                status="delivered",
                delivered_at=str(payload["delivered_at"]),
                error=None,
                metadata={
                    "operator": operator,
                    "item_updated_at": str(row["updated_at"] or ""),
                    **delivery_metadata,
                },
            )
        totals["sync_count"] += delivered
        totals["failure_count"] += failed
        connector_results.append(
            {
                "connector": connector,
                "destination": destination,
                "candidate_count": len(rows),
                "synced": delivered,
                "failed": failed,
            }
        )
    con.commit()
    return {
        "engagement_id": engagement_id,
        "connectors": connector_results,
        **totals,
    }
