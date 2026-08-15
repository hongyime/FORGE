from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Iterable, TextIO

from forge.db.direct_connect import direct_connect
from forge.db.migrations import run_migrations
from forge.db.validation import validate_canonical_schema
from forge.engagement_ids import numeric_engagement_db_files
from forge.remediation.connectors import (
    import_remediation_ticket_statuses,
    load_remediation_ticket_status_events,
    sync_remediation_tickets,
)


def _open_engagement_db(db_path: Path) -> sqlite3.Connection:
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    run_migrations(con)
    validate_canonical_schema(con)
    return con


def sync_remediation_tickets_for_db(
    db_path: Path,
    *,
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
    operator: str = "remediation-ticket-sync",
    limit: int = 100,
    timeout_seconds: float = 10.0,
    force: bool = False,
) -> dict[str, Any]:
    normalized_connectors = tuple(
        str(connector).strip().lower()
        for connector in connectors
        if str(connector).strip()
    )
    con = _open_engagement_db(db_path)
    try:
        engagement_rows = con.execute(
            """
            SELECT id, name
            FROM engagements
            ORDER BY id
            """
        ).fetchall()
        engagement_results: list[dict[str, Any]] = []
        sync_count = 0
        failure_count = 0
        for engagement in engagement_rows:
            result = sync_remediation_tickets(
                con,
                engagement_id=int(engagement["id"]),
                connectors=normalized_connectors,
                jsonl_path=jsonl_path,
                webhook_url=webhook_url,
                github_repo=github_repo,
                github_token_env=github_token_env,
                github_api_url=github_api_url,
                jira_base_url=jira_base_url,
                jira_project_key=jira_project_key,
                jira_issue_type=jira_issue_type,
                jira_email_env=jira_email_env,
                jira_token_env=jira_token_env,
                servicenow_instance_url=servicenow_instance_url,
                servicenow_table=servicenow_table,
                servicenow_username_env=servicenow_username_env,
                servicenow_password_env=servicenow_password_env,
                servicenow_token_env=servicenow_token_env,
                tines_webhook_url=tines_webhook_url,
                tines_token_env=tines_token_env,
                splunk_hec_url=splunk_hec_url,
                splunk_hec_token_env=splunk_hec_token_env,
                splunk_index=splunk_index,
                splunk_source=splunk_source,
                splunk_sourcetype=splunk_sourcetype,
                torq_webhook_url=torq_webhook_url,
                torq_token_env=torq_token_env,
                stdout=stdout,
                db_path=str(db_path.resolve()),
                operator=operator,
                limit=limit,
                timeout_seconds=timeout_seconds,
                force=force,
            )
            sync_count += int(result["sync_count"])
            failure_count += int(result["failure_count"])
            engagement_results.append(
                {
                    "engagement_id": int(engagement["id"]),
                    "engagement_name": str(engagement["name"] or ""),
                    **result,
                }
            )
        return {
            "db_path": str(db_path.resolve()),
            "engagement_count": len(engagement_rows),
            "sync_count": sync_count,
            "failure_count": failure_count,
            "engagements": engagement_results,
            "errors": [],
        }
    finally:
        con.close()


def sync_remediation_tickets_for_data_dir(
    data_dir: Path,
    *,
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
    operator: str = "remediation-ticket-sync",
    limit: int = 100,
    timeout_seconds: float = 10.0,
    force: bool = False,
) -> dict[str, Any]:
    normalized_connectors = tuple(
        str(connector).strip().lower()
        for connector in connectors
        if str(connector).strip()
    )
    destination = jsonl_path or (data_dir / "remediation_tickets.jsonl")
    db_results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    totals = {
        "db_count": 0,
        "engagement_count": 0,
        "sync_count": 0,
        "failure_count": 0,
    }
    for db_path in numeric_engagement_db_files(data_dir):
        totals["db_count"] += 1
        try:
            result = sync_remediation_tickets_for_db(
                db_path,
                connectors=normalized_connectors,
                jsonl_path=destination,
                webhook_url=webhook_url,
                github_repo=github_repo,
                github_token_env=github_token_env,
                github_api_url=github_api_url,
                jira_base_url=jira_base_url,
                jira_project_key=jira_project_key,
                jira_issue_type=jira_issue_type,
                jira_email_env=jira_email_env,
                jira_token_env=jira_token_env,
                servicenow_instance_url=servicenow_instance_url,
                servicenow_table=servicenow_table,
                servicenow_username_env=servicenow_username_env,
                servicenow_password_env=servicenow_password_env,
                servicenow_token_env=servicenow_token_env,
                tines_webhook_url=tines_webhook_url,
                tines_token_env=tines_token_env,
                splunk_hec_url=splunk_hec_url,
                splunk_hec_token_env=splunk_hec_token_env,
                splunk_index=splunk_index,
                splunk_source=splunk_source,
                splunk_sourcetype=splunk_sourcetype,
                torq_webhook_url=torq_webhook_url,
                torq_token_env=torq_token_env,
                stdout=stdout,
                operator=operator,
                limit=limit,
                timeout_seconds=timeout_seconds,
                force=force,
            )
        except (OSError, sqlite3.Error, RuntimeError, ValueError) as exc:
            errors.append({"db_path": str(db_path.resolve()), "error": str(exc)})
            continue
        db_results.append(result)
        totals["engagement_count"] += int(result["engagement_count"])
        totals["sync_count"] += int(result["sync_count"])
        totals["failure_count"] += int(result["failure_count"])
    return {
        **totals,
        "jsonl_path": str(destination) if "jsonl" in normalized_connectors else "",
        "db_results": db_results,
        "errors": errors,
    }


def import_remediation_ticket_statuses_for_db(
    db_path: Path,
    *,
    status_events: Iterable[dict[str, Any]],
    operator: str = "remediation-ticket-status-import",
    dry_run: bool = False,
    close_policy: str = "trust_external_status",
) -> dict[str, Any]:
    events = [event for event in status_events if isinstance(event, dict)]
    con = _open_engagement_db(db_path)
    try:
        engagement_rows = con.execute(
            """
            SELECT id, name
            FROM engagements
            ORDER BY id
            """
        ).fetchall()
        by_engagement: dict[int, list[dict[str, Any]]] = {
            int(engagement["id"]): [] for engagement in engagement_rows
        }
        review_events: list[dict[str, Any]] = []
        for event in events:
            engagement_ref = event.get("engagement_id")
            if engagement_ref in (None, ""):
                review_events.append(
                    {
                        "action": "review",
                        "reason": "missing_engagement_id",
                        "event": {
                            key: value
                            for key, value in event.items()
                            if key in {"connector", "ticket_ref", "external_ref", "status", "state"}
                        },
                    }
                )
                continue
            try:
                engagement_id = int(engagement_ref)
            except (TypeError, ValueError):
                review_events.append(
                    {
                        "action": "review",
                        "reason": "invalid_engagement_id",
                        "engagement_id": str(engagement_ref),
                    }
                )
                continue
            if engagement_id not in by_engagement:
                review_events.append(
                    {
                        "action": "review",
                        "reason": "engagement_not_in_db",
                        "engagement_id": engagement_id,
                    }
                )
                continue
            by_engagement[engagement_id].append(event)

        engagement_results: list[dict[str, Any]] = []
        totals = {
            "engagement_count": len(engagement_rows),
            "input_count": len(events),
            "matched_count": 0,
            "updated_count": 0,
            "unchanged_count": 0,
            "review_count": len(review_events),
        }
        for engagement in engagement_rows:
            engagement_id = int(engagement["id"])
            result = import_remediation_ticket_statuses(
                con,
                engagement_id=engagement_id,
                status_events=by_engagement[engagement_id],
                operator=operator,
                dry_run=dry_run,
                close_policy=close_policy,
            )
            summary = result["summary"]
            totals["matched_count"] += int(summary["matched_count"])
            totals["updated_count"] += int(summary["updated_count"])
            totals["unchanged_count"] += int(summary["unchanged_count"])
            totals["review_count"] += int(summary["review_count"])
            engagement_results.append(
                {
                    "engagement_id": engagement_id,
                    "engagement_name": str(engagement["name"] or ""),
                    **result,
                }
            )
        return {
            "db_path": str(db_path.resolve()),
            "mode": "dry_run" if dry_run else "apply",
            **totals,
            "engagements": engagement_results,
            "review_events": review_events,
            "errors": [],
        }
    finally:
        con.close()


def import_remediation_ticket_statuses_for_data_dir(
    data_dir: Path,
    *,
    status_file: Path,
    operator: str = "remediation-ticket-status-import",
    dry_run: bool = False,
    close_policy: str = "trust_external_status",
) -> dict[str, Any]:
    events = load_remediation_ticket_status_events(status_file)
    db_results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    totals = {
        "db_count": 0,
        "engagement_count": 0,
        "input_count": len(events),
        "matched_count": 0,
        "updated_count": 0,
        "unchanged_count": 0,
        "review_count": 0,
    }
    for db_path in numeric_engagement_db_files(data_dir):
        totals["db_count"] += 1
        try:
            result = import_remediation_ticket_statuses_for_db(
                db_path,
                status_events=events,
                operator=operator,
                dry_run=dry_run,
                close_policy=close_policy,
            )
        except (OSError, sqlite3.Error, RuntimeError, ValueError) as exc:
            errors.append({"db_path": str(db_path.resolve()), "error": str(exc)})
            continue
        db_results.append(result)
        totals["engagement_count"] += int(result["engagement_count"])
        totals["matched_count"] += int(result["matched_count"])
        totals["updated_count"] += int(result["updated_count"])
        totals["unchanged_count"] += int(result["unchanged_count"])
        totals["review_count"] += int(result["review_count"])
    return {
        "mode": "dry_run" if dry_run else "apply",
        "status_file": str(status_file),
        **totals,
        "db_results": db_results,
        "errors": errors,
    }
