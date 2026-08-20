from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from forge.config import ForgeConfig
from forge.connectors.cti import CtiObservationImportConfig, import_cti_observations
from forge.connectors.discovery import DiscoveryReportImportConfig, import_discovery_report
from forge.connectors.identity import IdentityExposureRunConfig, run_identity_exposure_connector
from forge.connectors.registry import (
    connector_install_plan,
    connector_plugin_dirs,
    connector_plugin_manifest_statuses,
    connector_statuses,
    connector_summary,
)
from forge.connectors.runner import (
    ConnectorRunConfig,
    SecretConnectorRunConfig,
    run_connector,
    run_secret_scan_connector,
)
from forge.connectors.secrets import (
    SECRET_MATERIAL_POLICY,
    connector_secret_key_plan,
    connector_secret_readiness,
    list_connector_secrets,
    store_connector_secret,
)
from forge.db.direct_connect import direct_connect
from forge.db.migrations import run_migrations
from forge.db.validation import validate_canonical_schema
from forge.secrets.importers import SecretScanImportConfig, import_secret_scan_report
from forge.secrets.lifecycle import secret_prevention_workflow_plan
from forge.utils.intel import provider_catalog_policy_summary

console = Console(stderr=True)


def register_connector_commands(app: typer.Typer) -> None:
    @app.command("list")
    def list_connectors(
        domain: str = typer.Option("", "--domain", help="Filter by connector domain."),
        engagement: int | None = typer.Option(
            None,
            "--engagement",
            "-e",
            help="Include encrypted secret-store readiness for this engagement.",
        ),
        include_paid: bool = typer.Option(
            False,
            "--include-paid/--free-first-only",
            help="Include optional paid adapters in the catalog output; free-first is the default.",
        ),
        plugin_dir: list[Path] | None = typer.Option(
            None,
            "--plugin-dir",
            exists=True,
            file_okay=False,
            help=(
                "Additional data-only connector plugin manifest directory. "
                "Default also checks FORGE_DATA_DIR/connector_plugins and "
                "FORGE_CONNECTOR_PLUGIN_DIR(S)."
            ),
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        try:
            cfg = ForgeConfig.load()
            resolved_plugin_dirs = connector_plugin_dirs(
                data_dir=cfg.data_dir,
                extra_dirs=plugin_dir or (),
            )
            stored_secret_statuses = _stored_connector_secret_statuses(engagement)
            rows = connector_statuses(
                domain=domain,
                include_paid=include_paid,
                stored_secret_statuses=stored_secret_statuses,
                plugin_dirs=resolved_plugin_dirs,
            )
        except (FileNotFoundError, LookupError, ValueError) as exc:
            raise typer.BadParameter(str(exc)) from exc
        summary = connector_summary(rows)
        if engagement is not None:
            summary["engagement_id"] = int(engagement)
            summary["secret_store_connector_count"] = len(stored_secret_statuses)
        if json_output:
            typer.echo(json.dumps({"connectors": rows, "summary": summary}, sort_keys=True))
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Connector", width=28)
        table.add_column("Domain", width=20)
        table.add_column("Cost", width=16)
        table.add_column("Readiness", width=28)
        table.add_column("Execution", width=20)
        table.add_column("Credentials", width=14)
        table.add_column("Safety")
        for row in rows:
            credential_source = "-"
            if row.get("env_configured"):
                credential_source = "env"
            elif row.get("secret_store_configured"):
                credential_source = "secret-store"
            elif row.get("secret_store_readiness") in {"stored_decrypt_failed", "stored_key_missing"}:
                credential_source = str(row.get("secret_store_readiness"))
            table.add_row(
                str(row["id"]),
                str(row["domain"]),
                str(row["cost_profile"]),
                str(row["readiness"]),
                str(row.get("execution_status") or "catalog_only"),
                credential_source,
                str(row["safety"]),
            )
        console.print(table)
        console.print(
            "[dim]"
            f"{summary['free_first_count']} free-first connectors; "
            f"{summary['optional_paid_count']} optional paid adapters. "
            "Secret values are never printed."
            "[/dim]"
        )

    @app.command("install-plan")
    def install_plan(
        include_paid: bool = typer.Option(
            False,
            "--include-paid/--free-first-only",
            help="Include optional paid adapters when calculating missing local binaries.",
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Print missing local binary install guidance without executing commands."""
        rows = connector_statuses(include_paid=include_paid, env=os.environ)
        plan = connector_install_plan(rows, env=os.environ)
        if json_output:
            typer.echo(json.dumps(plan, sort_keys=True))
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Binary", width=18)
        table.add_column("Installer", width=12)
        table.add_column("Connectors", width=34)
        table.add_column("Command")
        for item in plan["items"]:
            table.add_row(
                str(item["binary"]),
                str(item["installer"]),
                ", ".join(str(connector) for connector in item["connector_ids"]),
                str(item["command"] or item["notes"]),
            )
        console.print(table)
        console.print(
            "[dim]Install plan only; no command was executed. Rerun "
            "`forge doctor --json` after installing tools.[/dim]"
        )

    @app.command("secret-key-plan")
    def secret_key_plan(
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Print non-secret FORGE_ENGAGEMENT_KEY setup guidance."""
        plan = connector_secret_key_plan()
        if json_output:
            typer.echo(json.dumps(plan, sort_keys=True))
            return
        status = "configured" if plan["key_configured"] else "missing"
        console.print(
            "[bold]Connector secret key[/bold] "
            f"status={status} length={plan['key_length']} "
            f"fingerprint={plan['key_fingerprint'] or '-'}"
        )
        console.print(
            "[dim]No secret material is printed. Use the JSON output for "
            "platform-specific setup commands.[/dim]"
        )

    @app.command("policy-summary")
    def policy_summary(
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Summarize CTI/OSINT source policy without running providers."""
        summary = provider_catalog_policy_summary()
        if json_output:
            typer.echo(json.dumps(summary, sort_keys=True))
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Policy", width=28)
        table.add_column("Count", width=10)
        table.add_column("Providers")
        rows = [
            (
                "total",
                summary.get("total_count", 0),
                summary.get("default_provider_ids", []),
            ),
            (
                "offline_import",
                len(summary.get("offline_import_provider_ids", [])),
                summary.get("offline_import_provider_ids", []),
            ),
            (
                "live_or_api",
                len(summary.get("live_or_api_provider_ids", [])),
                summary.get("live_or_api_provider_ids", []),
            ),
            (
                "manual_opt_in",
                len(summary.get("manual_opt_in_provider_ids", [])),
                summary.get("manual_opt_in_provider_ids", []),
            ),
            (
                "operator_opt_in_gate",
                summary.get("required_gate_counts", {}).get("operator_opt_in", 0),
                [],
            ),
        ]
        for label, count, providers in rows:
            provider_text = ", ".join(str(item) for item in list(providers)[:8])
            if isinstance(providers, list) and len(providers) > 8:
                provider_text = f"{provider_text}, +{len(providers) - 8}"
            table.add_row(str(label), str(count), provider_text or "-")
        console.print(table)
        console.print(
            "[dim]Catalog policy summary only; no provider is contacted and no "
            "third-party command is executed.[/dim]"
        )

    @app.command("plugin-validate")
    def plugin_validate(
        plugin_dir: list[Path] | None = typer.Option(
            None,
            "--plugin-dir",
            exists=True,
            file_okay=False,
            help=(
                "Additional data-only connector plugin manifest directory. "
                "Default also checks FORGE_DATA_DIR/connector_plugins and "
                "FORGE_CONNECTOR_PLUGIN_DIR(S)."
            ),
        ),
        fail_on_invalid: bool = typer.Option(
            True,
            "--fail-on-invalid/--no-fail-on-invalid",
            help="Exit non-zero when any manifest is invalid.",
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        cfg = ForgeConfig.load()
        resolved_plugin_dirs = connector_plugin_dirs(
            data_dir=cfg.data_dir,
            extra_dirs=plugin_dir or (),
        )
        rows = connector_plugin_manifest_statuses(resolved_plugin_dirs)
        summary = {
            "checked_count": len(rows),
            "valid_count": sum(1 for row in rows if row["status"] == "valid"),
            "invalid_count": sum(1 for row in rows if row["status"] == "invalid"),
            "plugin_dirs": [str(path) for path in resolved_plugin_dirs],
            "schema": "forge.connector.plugin.v1",
            "execution_policy": "data_only_catalog; no plugin code is imported or executed",
        }
        if json_output:
            typer.echo(json.dumps({"items": rows, "summary": summary}, sort_keys=True))
        else:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Status", width=10)
            table.add_column("Connector", width=28)
            table.add_column("Domain", width=18)
            table.add_column("Path")
            for row in rows:
                table.add_row(
                    str(row["status"]),
                    str(row.get("id") or "-"),
                    str(row.get("domain") or "-"),
                    str(row["path"]),
                )
            console.print(table)
            console.print(
                "[dim]"
                f"{summary['valid_count']} valid; {summary['invalid_count']} invalid. "
                f"{summary['execution_policy']}."
                "[/dim]"
            )
        if fail_on_invalid and summary["invalid_count"]:
            raise typer.Exit(code=1)

    @app.command("secret-set")
    def secret_set(
        engagement: int = typer.Option(..., "--engagement", "-e"),
        connector: str = typer.Option(..., "--connector"),
        name: str = typer.Option(..., "--name", help="Connector secret name, usually an env var name."),
        value_env: str = typer.Option(
            "",
            "--value-env",
            help="Read the secret value from this environment variable.",
        ),
        value_file: Path | None = typer.Option(
            None,
            "--value-file",
            exists=True,
            dir_okay=False,
            help="Read the secret value from this file.",
        ),
        metadata_json: str = typer.Option("{}", "--metadata-json"),
        operator: str = typer.Option("connector-secret-store", "--operator"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        try:
            secret_value, secret_ref = _connector_secret_value(
                value_env=value_env,
                value_file=value_file,
            )
            metadata = _connector_secret_metadata(metadata_json)
            cfg = ForgeConfig.load()
            db_path = cfg.engagement_db_path(str(engagement))
            con = direct_connect(db_path)
            con.row_factory = sqlite3.Row
            try:
                run_migrations(con)
                validate_canonical_schema(con)
                result = store_connector_secret(
                    con,
                    engagement_id=int(engagement),
                    connector_id=connector,
                    secret_name=name,
                    secret_value=secret_value,
                    secret_ref=secret_ref,
                    operator=operator,
                    metadata=metadata,
                )
            finally:
                con.close()
        except (FileNotFoundError, LookupError, OSError, ValueError) as exc:
            raise typer.BadParameter(str(exc)) from exc

        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        console.print(
            "[bold]Connector secret stored[/bold] "
            f"{result['connector_id']}:{result['secret_name']} "
            f"source={result['secret_ref'] or 'operator_input'} "
            f"key={result['key_hint']}"
        )
        console.print(f"[dim]{SECRET_MATERIAL_POLICY}[/dim]")

    @app.command("secret-list")
    def secret_list(
        engagement: int = typer.Option(..., "--engagement", "-e"),
        connector: str = typer.Option("", "--connector"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        cfg = ForgeConfig.load()
        db_path = cfg.engagement_db_path(str(engagement))
        con = direct_connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            run_migrations(con)
            validate_canonical_schema(con)
            rows = list_connector_secrets(
                con,
                engagement_id=int(engagement),
                connector_id=connector,
            )
        except (FileNotFoundError, LookupError, ValueError) as exc:
            raise typer.BadParameter(str(exc)) from exc
        finally:
            con.close()

        summary = {
            "count": len(rows),
            "secret_material_policy": SECRET_MATERIAL_POLICY,
        }
        if json_output:
            typer.echo(json.dumps({"secrets": rows, "summary": summary}, sort_keys=True))
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Connector", width=28)
        table.add_column("Secret", width=28)
        table.add_column("Source", width=28)
        table.add_column("Key")
        table.add_column("Updated")
        for row in rows:
            table.add_row(
                str(row["connector_id"]),
                str(row["secret_name"]),
                str(row["secret_ref"]),
                str(row["key_hint"]),
                str(row["updated_at"]),
            )
        console.print(table)
        console.print(f"[dim]{SECRET_MATERIAL_POLICY}[/dim]")

    @app.command("run")
    def run(
        engagement: int = typer.Option(..., "--engagement", "-e"),
        connector: str = typer.Option("projectdiscovery_subfinder", "--connector"),
        target: str = typer.Option(..., "--target"),
        timeout_seconds: float = typer.Option(120.0, "--timeout-seconds", min=1.0, max=900.0),
        dry_run: bool = typer.Option(False, "--dry-run"),
        template_paths: list[str] | None = typer.Option(
            None,
            "--template",
            "-t",
            help="Explicit nuclei template path or ID; repeat for multiple templates.",
        ),
        severity_filter: list[str] | None = typer.Option(
            None,
            "--severity",
            help="Nuclei severity filter; repeat or use comma-separated values.",
        ),
        rate_limit_per_second: int = typer.Option(5, "--rate-limit", min=1, max=25),
        max_results: int = typer.Option(500, "--max-results", min=1, max=5000),
        operator: str = typer.Option("connector-runner", "--operator"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        cfg = ForgeConfig.load()
        db_path = cfg.engagement_db_path(str(engagement))
        con = direct_connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            run_migrations(con)
            validate_canonical_schema(con)
            result = run_connector(
                con,
                ConnectorRunConfig(
                    connector_id=connector,
                    engagement_id=int(engagement),
                    target=target,
                    timeout_seconds=timeout_seconds,
                    dry_run=dry_run,
                    operator=operator,
                    template_paths=tuple(template_paths or ()),
                    severity_filter=tuple(severity_filter or ()),
                    rate_limit_per_second=rate_limit_per_second,
                    max_results=max_results,
                ),
            )
        except (FileNotFoundError, LookupError, ValueError) as exc:
            raise typer.BadParameter(str(exc)) from exc
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        console.print(
            "[bold]Connector run[/bold] "
            f"{result['connector_id']} status={result['status']} "
            f"persisted={result['persisted_count']} skipped={result['skipped_count']}"
        )

    @app.command("import-secrets")
    def import_secrets(
        engagement: int = typer.Option(..., "--engagement", "-e"),
        connector: str = typer.Option("gitleaks_local", "--connector"),
        report_file: Path = typer.Option(..., "--report-file", exists=True, dir_okay=False),
        domain: str = typer.Option(..., "--domain"),
        repo_name: str = typer.Option("", "--repo-name"),
        operator: str = typer.Option("connector-import", "--operator"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        cfg = ForgeConfig.load()
        db_path = cfg.engagement_db_path(str(engagement))
        con = direct_connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            run_migrations(con)
            validate_canonical_schema(con)
            result = import_secret_scan_report(
                con,
                SecretScanImportConfig(
                    connector_id=connector,
                    engagement_id=int(engagement),
                    domain=domain,
                    report_path=report_file,
                    repo_name=repo_name,
                    operator=operator,
                ),
            )
        except (FileNotFoundError, LookupError, ValueError) as exc:
            raise typer.BadParameter(str(exc)) from exc
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        console.print(
            "[bold]Secret scan import[/bold] "
            f"{result['connector_id']} status={result['status']} "
            f"persisted={result['persisted_count']} skipped={result['skipped_count']} "
            f"lifecycle_synced={result['lifecycle_synced']}"
        )

    @app.command("import-discovery")
    def import_discovery(
        engagement: int = typer.Option(..., "--engagement", "-e"),
        connector: str = typer.Option("shodan_host_lookup", "--connector"),
        report_file: Path = typer.Option(..., "--report-file", exists=True, dir_okay=False),
        target: str = typer.Option("", "--target", help="Optional scoped domain/IP target filter."),
        operator: str = typer.Option("connector-import", "--operator"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        cfg = ForgeConfig.load()
        db_path = cfg.engagement_db_path(str(engagement))
        con = direct_connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            run_migrations(con)
            validate_canonical_schema(con)
            result = import_discovery_report(
                con,
                DiscoveryReportImportConfig(
                    connector_id=connector,
                    engagement_id=int(engagement),
                    report_path=report_file,
                    target=target,
                    operator=operator,
                ),
            )
        except (FileNotFoundError, LookupError, ValueError) as exc:
            raise typer.BadParameter(str(exc)) from exc
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        console.print(
            "[bold]Discovery report import[/bold] "
            f"{result['connector_id']} status={result['status']} "
            f"hosts={result['persisted_host_count']} "
            f"services={result['persisted_service_count']} "
            f"seeds={result['persisted_seed_count']} "
            f"urls={result.get('persisted_url_seed_count', 0)} "
            f"crawl={result.get('persisted_crawl_result_count', 0)} "
            f"skipped={result['skipped_count']}"
        )

    @app.command("import-cti")
    def import_cti(
        engagement: int = typer.Option(..., "--engagement", "-e"),
        connector: str = typer.Option("stix_taxii_import", "--connector"),
        report_file: Path = typer.Option(
            ...,
            "--report-file",
            exists=True,
            dir_okay=False,
            help="Offline CTI export file in JSON or CSV format.",
        ),
        provider: str = typer.Option("", "--provider", help="Override provider label."),
        source_url: str = typer.Option("", "--source-url", help="Safe provenance URL or feed ID."),
        collection_method: str = typer.Option("offline_import", "--collection-method"),
        promote_targets: bool = typer.Option(
            False,
            "--promote-targets",
            help="Promote target-feed-compatible observations into scoped engagement seeds.",
        ),
        dry_run: bool = typer.Option(
            False,
            "--dry-run",
            help="Parse and normalize the CTI file without writing observations, seeds, or audit rows.",
        ),
        limit: int | None = typer.Option(
            None,
            "--limit",
            min=1,
            max=100000,
            help="Maximum number of CTI items to process from the offline file.",
        ),
        min_confidence: float | None = typer.Option(
            None,
            "--min-confidence",
            min=0.0,
            max=1.0,
            help="Skip normalized observations below this confidence threshold.",
        ),
        max_tlp: str = typer.Option(
            "",
            "--max-tlp",
            help="Skip observations above this TLP level: clear, green, amber, or red.",
        ),
        since: str = typer.Option(
            "",
            "--since",
            help="Skip observations observed before this ISO timestamp.",
        ),
        until: str = typer.Option(
            "",
            "--until",
            help="Skip observations observed after this ISO timestamp.",
        ),
        fail_on_empty: bool = typer.Option(
            False,
            "--fail-on-empty",
            help="Exit non-zero when no observations survive normalization and filters.",
        ),
        operator: str = typer.Option("connector-import", "--operator"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        cfg = ForgeConfig.load()
        db_path = cfg.engagement_db_path(str(engagement))
        con = direct_connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            run_migrations(con)
            validate_canonical_schema(con)
            result = import_cti_observations(
                con,
                CtiObservationImportConfig(
                    connector_id=connector,
                    engagement_id=int(engagement),
                    report_path=report_file,
                    provider=provider,
                    source_url=source_url,
                    collection_method=collection_method,
                    promote_targets=promote_targets,
                    operator=operator,
                    dry_run=dry_run,
                    limit=limit,
                    min_confidence=min_confidence,
                    max_tlp=max_tlp,
                    since=since,
                    until=until,
                    fail_on_empty=fail_on_empty,
                ),
            )
        except (FileNotFoundError, LookupError, ValueError) as exc:
            raise typer.BadParameter(str(exc)) from exc
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        console.print(
            "[bold]CTI observation import[/bold] "
            f"{result['connector_id']} status={result['status']} "
            f"persisted={result['persisted_count']} "
            f"would_persist={result.get('would_persist_count', 0)} "
            f"duplicates={result['duplicate_count']} "
            f"would_duplicate={result.get('would_duplicate_count', 0)} "
            f"promoted={result['promoted_seed_count']} "
            f"would_promote={result.get('would_promote_seed_count', 0)} "
            f"skipped={result['skipped_count']} "
            f"filtered={result.get('filtered_count', 0)} "
            f"max_tlp={result.get('max_tlp') or ''} "
            f"since={result.get('since') or ''} "
            f"until={result.get('until') or ''} "
            f"limited={result.get('limited_item_count', 0)}"
        )

    @app.command("run-secrets")
    def run_secrets(
        engagement: int = typer.Option(..., "--engagement", "-e"),
        connector: str = typer.Option("gitleaks_local", "--connector"),
        source_path: Path = typer.Option(..., "--source-path", exists=True),
        domain: str = typer.Option(..., "--domain"),
        repo_name: str = typer.Option("", "--repo-name"),
        timeout_seconds: float = typer.Option(300.0, "--timeout-seconds", min=1.0, max=1800.0),
        dry_run: bool = typer.Option(False, "--dry-run"),
        operator: str = typer.Option("connector-runner", "--operator"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        cfg = ForgeConfig.load()
        db_path = cfg.engagement_db_path(str(engagement))
        con = direct_connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            run_migrations(con)
            validate_canonical_schema(con)
            result = run_secret_scan_connector(
                con,
                SecretConnectorRunConfig(
                    connector_id=connector,
                    engagement_id=int(engagement),
                    domain=domain,
                    source_path=source_path,
                    repo_name=repo_name,
                    timeout_seconds=timeout_seconds,
                    dry_run=dry_run,
                    operator=operator,
                ),
            )
        except (FileNotFoundError, LookupError, ValueError) as exc:
            raise typer.BadParameter(str(exc)) from exc
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        console.print(
            "[bold]Secret scan connector[/bold] "
            f"{result['connector_id']} status={result['status']} "
            f"persisted={result['persisted_count']} skipped={result['skipped_count']} "
            f"lifecycle_synced={result['lifecycle_synced']}"
        )

    @app.command("secret-prevention-plan")
    def secret_prevention_plan(
        engagement: int = typer.Option(..., "--engagement", "-e"),
        workflow: str = typer.Option(
            "all",
            "--workflow",
            help="Filter to all, pre-commit, pull_request, or push.",
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        cfg = ForgeConfig.load()
        db_path = cfg.engagement_db_path(str(engagement))
        con = direct_connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            run_migrations(con)
            validate_canonical_schema(con)
            result = secret_prevention_workflow_plan(
                con,
                int(engagement),
                workflow=workflow,
            )
        except (FileNotFoundError, LookupError, ValueError) as exc:
            raise typer.BadParameter(str(exc)) from exc
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Workflow", width=14)
        table.add_column("Tool", width=18)
        table.add_column("Findings", width=10)
        table.add_column("Target", width=34)
        table.add_column("Command")
        for workflow_row in result["workflows"]:
            target = workflow_row["target"]
            for command in workflow_row["commands"]:
                table.add_row(
                    str(workflow_row["workflow"]),
                    str(command["tool"]),
                    str(len(command["affected_finding_ids"])),
                    str(target["artifact"]),
                    str(command["command"]),
                )
        console.print(table)
        console.print(
            "[dim]"
            f"{result['summary']['command_count']} prevention commands across "
            f"{result['summary']['workflow_count']} workflows. "
            "Secret values are never printed."
            "[/dim]"
        )

    @app.command("run-identity")
    def run_identity(
        engagement: int = typer.Option(..., "--engagement", "-e"),
        connector: str = typer.Option("hibp_pwned_passwords", "--connector"),
        domain: str = typer.Option("", "--domain", help="Optional in-scope email domain filter."),
        offline_corpus: Path | None = typer.Option(
            None,
            "--offline-corpus",
            exists=True,
            dir_okay=False,
            help="Optional local Pwned Passwords corpus/range file.",
        ),
        timeout_seconds: float = typer.Option(30.0, "--timeout-seconds", min=1.0, max=120.0),
        dry_run: bool = typer.Option(False, "--dry-run"),
        operator: str = typer.Option("connector-runner", "--operator"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        cfg = ForgeConfig.load()
        db_path = cfg.engagement_db_path(str(engagement))
        con = direct_connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            run_migrations(con)
            validate_canonical_schema(con)
            result = run_identity_exposure_connector(
                con,
                IdentityExposureRunConfig(
                    connector_id=connector,
                    engagement_id=int(engagement),
                    domain=domain,
                    offline_corpus_path=offline_corpus,
                    timeout_seconds=timeout_seconds,
                    dry_run=dry_run,
                    operator=operator,
                ),
            )
        except (FileNotFoundError, LookupError, ValueError) as exc:
            raise typer.BadParameter(str(exc)) from exc
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        console.print(
            "[bold]Identity exposure connector[/bold] "
            f"{result['connector_id']} status={result['status']} "
            f"checked={result['checked_count']} exposed={result['exposed_count']} "
            f"skipped={result['skipped_count']}"
        )


def _connector_secret_value(
    *,
    value_env: str,
    value_file: Path | None,
) -> tuple[str, str]:
    env_name = str(value_env or "").strip()
    if bool(env_name) == bool(value_file):
        raise ValueError("provide exactly one of --value-env or --value-file")
    if env_name:
        if env_name not in os.environ:
            raise ValueError(f"environment variable is not set: {env_name}")
        return os.environ[env_name], f"env:{env_name}"
    if value_file is None:
        raise ValueError("provide exactly one of --value-env or --value-file")
    return value_file.read_text(encoding="utf-8").rstrip("\r\n"), f"file:{value_file.name}"


def _connector_secret_metadata(raw: str) -> dict[str, object]:
    try:
        payload = json.loads(str(raw or "{}"))
    except json.JSONDecodeError as exc:
        raise ValueError("--metadata-json must be a JSON object") from exc
    if not isinstance(payload, dict):
        raise ValueError("--metadata-json must be a JSON object")
    return payload


def _stored_connector_secret_statuses(engagement: int | None) -> dict[str, dict[str, str]]:
    if engagement is None:
        return {}
    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(str(engagement))
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        run_migrations(con)
        validate_canonical_schema(con)
        return connector_secret_readiness(con, engagement_id=int(engagement))
    finally:
        con.close()
