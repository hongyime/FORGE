from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from forge.config import ForgeConfig
from forge.db.direct_connect import direct_connect
from forge.db.migrations import run_migrations
from forge.db.validation import validate_canonical_schema
from forge.remediation.workflow import (
    apply_active_validation_retest_result,
    draft_remediation_from_asset_graph_candidates,
    propagate_asset_owners_to_remediation,
    request_active_validation_retest,
    remediation_review_queue,
)
from forge.remediation.connectors import (
    import_remediation_ticket_status_file,
    remediation_integration_runbook,
    remediation_ticket_handoff_plan,
)
from forge.remediation.runner import (
    import_remediation_ticket_statuses_for_data_dir,
    sync_remediation_tickets_for_data_dir,
)

console = Console(stderr=True)


def _open_db(engagement: str) -> sqlite3.Connection:
    cfg = ForgeConfig.load()
    con = direct_connect(cfg.engagement_db_path(str(engagement)))
    con.row_factory = sqlite3.Row
    run_migrations(con)
    validate_canonical_schema(con)
    return con


def _metadata_payload(value: str) -> dict[str, object]:
    text = str(value or "{}").strip() or "{}"
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"metadata-json must decode to an object: {exc}") from exc
    if not isinstance(payload, dict):
        raise typer.BadParameter("metadata-json must decode to an object")
    return payload


def register_remediation_commands(app: typer.Typer) -> None:
    @app.command("review-queue")
    def review_queue(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        limit: int = typer.Option(
            100,
            "--limit",
            min=1,
            help="Maximum review-queue items to return.",
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        con = _open_db(engagement)
        try:
            result = remediation_review_queue(
                con,
                engagement_id=int(engagement),
                limit=limit,
            )
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        summary = result["summary"]
        console.print(
            "[bold]Remediation review queue[/bold] "
            f"attention={summary['attention_required']} active={summary['active']} "
            f"sla_overdue={summary['sla_overdue']} "
            f"risk_review_due={summary['risk_acceptance_review_due']} "
            f"retest_pending={summary['retest_pending']} "
            f"retest_blocked={summary['retest_blocked']} "
            f"missing_owner={summary['missing_owner']} "
            f"missing_ticket={summary['missing_ticket']}"
        )
        for item in result["items"][:10]:
            console.print(
                f"- #{item['id']} {item['severity']} {item['title']} "
                f"({', '.join(item['queue_reason_labels'])})"
            )

    @app.command("propagate-owners")
    def propagate_owners(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        overwrite: bool = typer.Option(
            False,
            "--overwrite",
            help="Replace existing remediation owners with the resolved graph owner.",
        ),
        conflict_policy: str = typer.Option(
            "highest_confidence",
            "--conflict-policy",
            help="Owner conflict policy: highest_confidence or skip_conflicts.",
        ),
        min_confidence: float = typer.Option(
            0.0,
            "--min-confidence",
            min=0.0,
            max=1.0,
            help="Minimum graph owner confidence required before assignment.",
        ),
        limit: int = typer.Option(
            1000,
            "--limit",
            min=1,
            help="Maximum remediation items to scan.",
        ),
        operator: str = typer.Option("operator", "--operator"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        con = _open_db(engagement)
        try:
            result = propagate_asset_owners_to_remediation(
                con,
                engagement_id=int(engagement),
                operator=operator,
                overwrite=overwrite,
                conflict_policy=conflict_policy,
                min_confidence=min_confidence,
                limit=limit,
            )
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        console.print(
            "[bold]Remediation owner propagation[/bold] "
            f"scanned={result['scanned_count']} assigned={result['assigned_count']} "
            f"unresolved={result['unresolved_count']} "
            f"skipped_existing_owner={result['skipped_existing_owner_count']}"
        )

    @app.command("draft-from-asset-graph")
    def draft_from_asset_graph(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        limit: int = typer.Option(
            10,
            "--limit",
            min=1,
            help="Maximum asset graph minimal-fix candidates to draft.",
        ),
        operator: str = typer.Option("operator", "--operator"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        con = _open_db(engagement)
        try:
            result = draft_remediation_from_asset_graph_candidates(
                con,
                engagement_id=int(engagement),
                operator=operator,
                limit=limit,
            )
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        console.print(
            "[bold]Graph remediation drafts[/bold] "
            f"candidates={result['candidate_count']} drafted={result['drafted_count']}"
        )
        for item in result["items"][:10]:
            console.print(
                f"- #{item['id']} {item['severity']} {item['title']} "
                f"owner={item.get('owner') or 'unassigned'} status={item['status']}"
            )

    @app.command("request-retest")
    def request_retest(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        item_id: int = typer.Option(..., "--item-id"),
        target_ref: str = typer.Option(
            "",
            "--target",
            help="Optional target override. Defaults to item provenance or finding table/ref.",
        ),
        target_kind: str = typer.Option("", "--target-kind"),
        method: str = typer.Option("fix_verification", "--method"),
        mode: str = typer.Option("dry_run", "--mode"),
        expected_result: str = typer.Option(
            "",
            "--expected-result",
            help="Optional active-validation result required for a passed retest.",
        ),
        approve: bool = typer.Option(False, "--approve"),
        requested_by: str = typer.Option("operator", "--requested-by"),
        approved_by: str = typer.Option("", "--approved-by"),
        approval_note: str = typer.Option("", "--approval-note"),
        roe_id: str = typer.Option("", "--roe-id"),
        scope_manifest: str = typer.Option("", "--scope-manifest"),
        metadata_json: str = typer.Option("{}", "--metadata-json"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        con = _open_db(engagement)
        try:
            result = request_active_validation_retest(
                con,
                engagement_id=int(engagement),
                remediation_item_id=item_id,
                operator=requested_by,
                target_ref=target_ref,
                target_kind=target_kind,
                method=method,
                mode=mode,
                approved=approve,
                requested_by=requested_by,
                approved_by=approved_by,
                approval_note=approval_note,
                roe_id=roe_id,
                scope_manifest_ref=scope_manifest,
                expected_result=expected_result,
                metadata=_metadata_payload(metadata_json),
            )
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        item = result["remediation_item"]
        job = result["active_validation_job"]
        console.print(
            "[bold]Remediation retest requested[/bold] "
            f"item={item['id']} retest={item['retest_status']} "
            f"active_validation_job={job['id']} mode={job['mode']} method={job['method']}"
        )

    @app.command("apply-retest-run")
    def apply_retest_run(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        run_id: int = typer.Option(..., "--run-id"),
        operator: str = typer.Option("operator", "--operator"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        con = _open_db(engagement)
        try:
            result = apply_active_validation_retest_result(
                con,
                engagement_id=int(engagement),
                run_id=run_id,
                operator=operator,
            )
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        if not result.get("linked"):
            console.print(f"[bold]No remediation retest link[/bold] run={run_id}")
            return
        console.print(
            "[bold]Remediation retest applied[/bold] "
            f"item={result['remediation_item_id']} retest={result['retest_status']} "
            f"status={result['status']}"
        )

    @app.command("handoff-plan")
    def handoff_plan(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        jsonl_path: Optional[Path] = typer.Option(
            None,
            "--jsonl-path",
            help="Local JSONL ticket sink to preview.",
        ),
        stdout_sync: bool = typer.Option(
            False,
            "--stdout",
            help="Include stdout ticket payload previews.",
        ),
        webhook_url: Optional[str] = typer.Option(
            None,
            "--webhook-url",
            help="Optional generic webhook URL to preview with secret path redaction.",
        ),
        github_repo: Optional[str] = typer.Option(
            None,
            "--github-repo",
            help="Optional GitHub Issues target in owner/repo format.",
        ),
        github_api_url: str = typer.Option("https://api.github.com", "--github-api-url"),
        jira_base_url: Optional[str] = typer.Option(None, "--jira-base-url"),
        jira_project_key: Optional[str] = typer.Option(None, "--jira-project-key"),
        jira_issue_type: str = typer.Option("Task", "--jira-issue-type"),
        servicenow_instance_url: Optional[str] = typer.Option(None, "--servicenow-instance-url"),
        servicenow_table: str = typer.Option("incident", "--servicenow-table"),
        tines_webhook_url: Optional[str] = typer.Option(None, "--tines-webhook-url"),
        splunk_hec_url: Optional[str] = typer.Option(None, "--splunk-hec-url"),
        splunk_index: str = typer.Option("", "--splunk-index"),
        splunk_source: str = typer.Option("forge", "--splunk-source"),
        splunk_sourcetype: str = typer.Option(
            "forge:remediation:ticket",
            "--splunk-sourcetype",
        ),
        torq_webhook_url: Optional[str] = typer.Option(None, "--torq-webhook-url"),
        item_id: Optional[int] = typer.Option(None, "--item-id"),
        limit: int = typer.Option(100, "--limit", min=1),
        force: bool = typer.Option(
            False,
            "--force",
            help="Include items already synced at their current updated_at timestamp.",
        ),
        operator: str = typer.Option("remediation-ticket-handoff", "--operator"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        connectors = ["jsonl"]
        if stdout_sync:
            connectors.append("stdout")
        if webhook_url:
            connectors.append("webhook")
        if github_repo:
            connectors.append("github_issues")
        if jira_base_url or jira_project_key:
            connectors.append("jira")
        if servicenow_instance_url:
            connectors.append("servicenow")
        if tines_webhook_url:
            connectors.append("tines")
        if splunk_hec_url:
            connectors.append("splunk_hec")
        if torq_webhook_url:
            connectors.append("torq")
        con = _open_db(engagement)
        try:
            result = remediation_ticket_handoff_plan(
                con,
                engagement_id=int(engagement),
                connectors=connectors,
                jsonl_path=jsonl_path,
                webhook_url=webhook_url,
                github_repo=github_repo,
                github_api_url=github_api_url,
                jira_base_url=jira_base_url,
                jira_project_key=jira_project_key,
                jira_issue_type=jira_issue_type,
                servicenow_instance_url=servicenow_instance_url,
                servicenow_table=servicenow_table,
                tines_webhook_url=tines_webhook_url,
                splunk_hec_url=splunk_hec_url,
                splunk_index=splunk_index,
                splunk_source=splunk_source,
                splunk_sourcetype=splunk_sourcetype,
                torq_webhook_url=torq_webhook_url,
                operator=operator,
                item_id=item_id,
                limit=limit,
                force=force,
            )
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        console.print(
            "[bold]Remediation integration handoff plan[/bold] "
            f"connectors={result['connector_count']} templates={result['item_template_count']} "
            "network=disabled file_writes=disabled"
        )

    @app.command("integration-runbook")
    def integration_runbook(
        systems: Optional[list[str]] = typer.Option(
            None,
            "--system",
            help="Integration system to include. Repeat for multiple systems.",
        ),
        close_policy: str = typer.Option(
            "trust_external_status",
            "--close-policy",
            help=(
                "How external closed/fixed states are handled: trust_external_status "
                "or require_retest_for_resolved."
            ),
        ),
        status_file: str = typer.Option("statuses.jsonl", "--status-file"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        try:
            result = remediation_integration_runbook(
                systems=systems or (),
                close_policy=close_policy,
                status_file=status_file,
            )
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        console.print(
            "[bold]Remediation integration runbook[/bold] "
            f"systems={len(result['systems'])} close_policy={result['approval_policy']['close_policy']}"
        )

    @app.command("import-ticket-statuses")
    def import_ticket_statuses(
        engagement: Optional[str] = typer.Option(None, "--engagement", "-e"),
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            help="Run status import across all engagement DBs in this FORGE data directory.",
        ),
        file: Path = typer.Option(
            ...,
            "--file",
            exists=True,
            dir_okay=False,
            readable=True,
            help="JSON or JSONL status feed exported from a ticket system.",
        ),
        operator: str = typer.Option("remediation-ticket-status-import", "--operator"),
        dry_run: bool = typer.Option(
            False,
            "--dry-run",
            help="Preview matched status changes without updating remediation items.",
        ),
        close_policy: str = typer.Option(
            "trust_external_status",
            "--close-policy",
            help=(
                "How external closed/fixed states are handled: trust_external_status "
                "or require_retest_for_resolved."
            ),
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        if close_policy not in {"trust_external_status", "require_retest_for_resolved"}:
            raise typer.BadParameter(
                "close-policy must be trust_external_status or require_retest_for_resolved"
            )
        cfg = ForgeConfig.load()
        if engagement:
            con = _open_db(engagement)
            try:
                result = import_remediation_ticket_status_file(
                    con,
                    engagement_id=int(engagement),
                    path=file,
                    operator=operator,
                    dry_run=dry_run,
                    close_policy=close_policy,
                )
            finally:
                con.close()
        else:
            root = data_dir or cfg.data_dir
            result = import_remediation_ticket_statuses_for_data_dir(
                root,
                status_file=file,
                operator=operator,
                dry_run=dry_run,
                close_policy=close_policy,
            )
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        summary = result.get("summary", result)
        console.print(
            "[bold]Remediation ticket status import[/bold] "
            f"mode={result['mode']} input={summary['input_count']} "
            f"matched={summary['matched_count']} updated={summary['updated_count']} "
            f"unchanged={summary['unchanged_count']} review={summary['review_count']}"
        )

    @app.command("sync-tickets")
    def sync_tickets(
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            help="FORGE data directory. Defaults to FORGE_DATA_DIR.",
        ),
        jsonl_path: Optional[Path] = typer.Option(
            None,
            "--jsonl-path",
            help="Local JSONL ticket sink. Defaults to <data-dir>/remediation_tickets.jsonl.",
        ),
        stdout_sync: bool = typer.Option(
            False,
            "--stdout",
            help="Also write ticket payloads to stdout.",
        ),
        webhook_url: Optional[str] = typer.Option(
            None,
            "--webhook-url",
            help="Optional generic webhook URL for JSON POST ticket sync.",
        ),
        github_repo: Optional[str] = typer.Option(
            None,
            "--github-repo",
            help="Optional GitHub Issues target in owner/repo format.",
        ),
        github_token_env: str = typer.Option(
            "FORGE_GITHUB_TOKEN",
            "--github-token-env",
            help="Environment variable containing a GitHub token. The value is never printed.",
        ),
        github_api_url: str = typer.Option(
            "https://api.github.com",
            "--github-api-url",
            help="GitHub REST API base URL. Override for GitHub Enterprise.",
        ),
        jira_base_url: Optional[str] = typer.Option(
            None,
            "--jira-base-url",
            help="Optional Jira Cloud base URL, for example https://example.atlassian.net.",
        ),
        jira_project_key: Optional[str] = typer.Option(
            None,
            "--jira-project-key",
            help="Optional Jira project key for remediation tickets.",
        ),
        jira_issue_type: str = typer.Option(
            "Task",
            "--jira-issue-type",
            help="Jira issue type name to create when no existing Jira ticket is linked.",
        ),
        jira_email_env: str = typer.Option(
            "FORGE_JIRA_EMAIL",
            "--jira-email-env",
            help="Environment variable containing the Jira account email. The value is never printed.",
        ),
        jira_token_env: str = typer.Option(
            "FORGE_JIRA_API_TOKEN",
            "--jira-token-env",
            help="Environment variable containing the Jira API token. The value is never printed.",
        ),
        servicenow_instance_url: Optional[str] = typer.Option(
            None,
            "--servicenow-instance-url",
            help="Optional ServiceNow instance URL, for example https://example.service-now.com.",
        ),
        servicenow_table: str = typer.Option(
            "incident",
            "--servicenow-table",
            help="ServiceNow Table API table name for remediation tickets.",
        ),
        servicenow_username_env: str = typer.Option(
            "FORGE_SERVICENOW_USERNAME",
            "--servicenow-username-env",
            help="Environment variable containing the ServiceNow username. The value is never printed.",
        ),
        servicenow_password_env: str = typer.Option(
            "FORGE_SERVICENOW_PASSWORD",
            "--servicenow-password-env",
            help="Environment variable containing the ServiceNow password/token. The value is never printed.",
        ),
        servicenow_token_env: Optional[str] = typer.Option(
            None,
            "--servicenow-token-env",
            help="Optional environment variable containing a ServiceNow bearer token. The value is never printed.",
        ),
        tines_webhook_url: Optional[str] = typer.Option(
            None,
            "--tines-webhook-url",
            help="Optional Tines webhook action URL for remediation automation events.",
        ),
        tines_token_env: str = typer.Option(
            "FORGE_TINES_WEBHOOK_TOKEN",
            "--tines-token-env",
            help="Optional environment variable containing a Tines webhook bearer token. The value is never printed.",
        ),
        splunk_hec_url: Optional[str] = typer.Option(
            None,
            "--splunk-hec-url",
            help="Optional Splunk HEC /services/collector/event URL.",
        ),
        splunk_hec_token_env: str = typer.Option(
            "FORGE_SPLUNK_HEC_TOKEN",
            "--splunk-hec-token-env",
            help="Environment variable containing the Splunk HEC token. The value is never printed.",
        ),
        splunk_index: str = typer.Option(
            "",
            "--splunk-index",
            help="Optional Splunk HEC index name.",
        ),
        splunk_source: str = typer.Option(
            "forge",
            "--splunk-source",
            help="Splunk HEC source value.",
        ),
        splunk_sourcetype: str = typer.Option(
            "forge:remediation:ticket",
            "--splunk-sourcetype",
            help="Splunk HEC sourcetype value.",
        ),
        torq_webhook_url: Optional[str] = typer.Option(
            None,
            "--torq-webhook-url",
            help="Optional Torq webhook trigger URL for remediation automation events.",
        ),
        torq_token_env: str = typer.Option(
            "FORGE_TORQ_WEBHOOK_TOKEN",
            "--torq-token-env",
            help="Optional environment variable containing a Torq webhook bearer token. The value is never printed.",
        ),
        force: bool = typer.Option(
            False,
            "--force",
            help="Re-emit items already synced at their current updated_at timestamp.",
        ),
        operator: str = typer.Option(
            "remediation-ticket-sync",
            "--operator",
            help="Operator name stored in connector metadata.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Print machine-readable sync summary.",
        ),
    ) -> None:
        cfg = ForgeConfig.load()
        root = data_dir or cfg.data_dir
        connectors = ["jsonl"]
        if stdout_sync:
            connectors.append("stdout")
        if webhook_url:
            connectors.append("webhook")
        if github_repo:
            connectors.append("github_issues")
        if jira_base_url or jira_project_key:
            connectors.append("jira")
        if servicenow_instance_url:
            connectors.append("servicenow")
        if tines_webhook_url:
            connectors.append("tines")
        if splunk_hec_url:
            connectors.append("splunk_hec")
        if torq_webhook_url:
            connectors.append("torq")
        result = sync_remediation_tickets_for_data_dir(
            root,
            connectors=connectors,
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
            operator=operator,
            force=force,
        )
        if json_output:
            console.print(json.dumps(result, sort_keys=True))
            return
        console.print(
            "[bold]Remediation ticket sync[/bold] "
            f"dbs={result['db_count']} engagements={result['engagement_count']} "
            f"synced={result['sync_count']} failures={result['failure_count']} "
            f"errors={len(result['errors'])}"
        )
