"""Cloud misconfiguration scanning CLI commands — Phase 4 cloud sub-app.

Extracted from forge/cli.py for modularity. All @cloud_app.command functions live here.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Optional

import typer

from forge.cli import cloud_app, console
from forge.cli_helpers import (
    _direct_cli_load_scope_lists,
    _direct_cli_require_roe,
    _normalise_output_format,
    _write_cloud_output,
)
from forge.db.direct_connect import direct_connect


@cloud_app.command("firebase")
def cloud_firebase(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    project_id: str = typer.Option(..., "--project-id", "--project-ref", help="Firebase project ID."),
    api_key: Optional[str] = typer.Option(
        None,
        "--api-key",
        envvar="FORGE_FIREBASE_API_KEY",
        help="Firebase web API key. If omitted, auto-fill discovery is used.",
    ),
    auto_discover_web: Optional[bool] = typer.Option(
        None,
        "--auto-discover-web/--no-auto-discover-web",
        help="Enable Firebase web endpoint key discovery.",
    ),
    scavenge_repos: Optional[bool] = typer.Option(
        None,
        "--scavenge-repos/--no-scavenge-repos",
        help="Enable repository scavenging for Firebase keys.",
    ),
    tests: str = typer.Option(
        "all",
        "--tests",
        help="Comma-separated test modules: auth,database,firestore,storage,functions,all",
    ),
    timeout: int = typer.Option(600, "--timeout", help="Subprocess kill timeout in seconds."),
    dry_run: bool = typer.Option(False, "--dry-run"),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before direct live Firebase audits.",
    ),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct Firebase audit gating.",
    ),
) -> None:
    """Audit a Firebase project via Agneyastra (Module 4-E). Requires agneyastra >= 1.0.0 on PATH.

    OPSEC: Active testing against live Firebase endpoints. Requires explicit
    engagement authorisation covering Firebase/GCP resources.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.phase4.cloud_audit import FirebaseAuditor  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    scope_values: list[str] = []
    url_prefixes: list[str] = []
    if not dry_run:
        _direct_cli_require_roe(roe_id, command_name="cloud firebase")
        scope_values, url_prefixes = _direct_cli_load_scope_lists(
            engagement_id=int(engagement),
            db_path=db_path,
            scope_manifest=scope_manifest,
            target=f"https://{project_id}.firebaseapp.com",
            seed_type="url",
        )
    test_list = [t.strip() for t in tests.split(",")]
    auditor = FirebaseAuditor(db_path=db_path, engagement_id=int(engagement))
    auditor.run(
        project_id=project_id,
        tests=test_list,
        api_key=api_key,
        auto_discover_web=(
            cfg.firebase_web_discovery if auto_discover_web is None else auto_discover_web
        ),
        repo_scavenge=(cfg.firebase_repo_scavenge if scavenge_repos is None else scavenge_repos),
        timeout=timeout,
        dry_run=dry_run,
        scope_values=scope_values,
        url_prefixes=url_prefixes,
        require_scope=not dry_run,
    )


@cloud_app.command("aws")
def cloud_aws(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    profile: Optional[str] = typer.Option(
        None,
        "--profile",
        help="AWS profile to use for authentication.",
    ),
    regions: Optional[str] = typer.Option(
        None,
        "--regions",
        help="Comma-separated AWS regions to audit (default: all available regions).",
    ),
    services: str = typer.Option(
        "all",
        "--services",
        help="Comma-separated AWS services to audit: iam,s3,rds,ec2,lambda,cloudtrail (default: all).",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview planned audit without API calls."),
    output_format: str = typer.Option(
        "json",
        "--output-format",
        help="Output format: json, csv, sarif.",
    ),
    output_path: Optional[str] = typer.Option(
        None,
        "--output",
        help="Optional output file path. Defaults under engagement artifacts.",
    ),
    timeout: int = typer.Option(600, "--timeout", help="Maximum execution time in seconds."),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before direct live AWS audits.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Skip the interactive confirmation after --roe-id; intended for kill-chain auto-run.",
    ),
) -> None:
    """Comprehensive AWS security audit (IAM, S3, RDS, EC2, Lambda, CloudTrail)."""
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.phase4.aws_audit import run_aws_audit  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    output_format = _normalise_output_format(output_format)
    profile_value = profile or cfg.cloud_aws_profile
    regions_value = regions
    if not regions_value and cfg.cloud_aws_regions:
        regions_value = ",".join(cfg.cloud_aws_regions)
    services_value = services
    if services == "all" and cfg.cloud_aws_services:
        services_value = ",".join(cfg.cloud_aws_services)
    regions_list = [item.strip() for item in regions_value.split(",") if item.strip()] if regions_value else None
    services_list = (
        [item.strip() for item in services_value.split(",") if item.strip()]
        if services_value != "all"
        else None
    )
    
    console.print(f"[bold blue]AWS Security Audit[/bold blue]")
    console.print(f"  Engagement: {engagement}")
    console.print(f"  Profile: {profile_value or 'default'}")
    console.print(f"  Regions: {regions_value or 'all'}")
    console.print(f"  Services: {services_value}")
    console.print(f"  Dry run: {dry_run}")
    console.print(f"  Output: {output_format}")
    yes = yes if isinstance(yes, bool) else False
    if not dry_run:
        _direct_cli_require_roe(roe_id, command_name="cloud aws")
        if not yes:
            import questionary  # noqa: PLC0415

            proceed = questionary.confirm(
                "Run AWS audit against live APIs for this engagement?"
            ).ask()
            if not proceed:
                raise typer.Exit()
    
    try:
        findings = run_aws_audit(
            db_path=db_path,
            engagement_id=int(engagement),
            profile=profile_value,
            regions=regions_list,
            services=services_list,
            dry_run=dry_run,
            timeout=timeout,
        )
        findings_payload = [finding.to_dict() for finding in findings]
        default_ext = "sarif" if output_format == "sarif" else output_format
        output_target = (
            Path(output_path)
            if output_path
            else (cfg.data_dir / "engagements" / str(engagement) / "reports" / f"aws_audit.{default_ext}")
        )
        _write_cloud_output(
            findings=findings_payload,
            provider="aws",
            output_format=output_format,
            output_path=output_target,
        )
        console.print(f"[green]✓ AWS audit completed: {len(findings)} findings[/green]")
        console.print(f"[green]✓ Output written:[/green] {output_target}")
        
    except Exception as exc:
        console.print(f"[red]✗ AWS audit failed: {exc}[/red]")
        raise typer.Exit(1)


@cloud_app.command("azure")
def cloud_azure(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    subscription_id: Optional[str] = typer.Option(
        None,
        "--subscription-id",
        help="Azure subscription ID (default: first available).",
    ),
    tenant_id: Optional[str] = typer.Option(
        None,
        "--tenant-id",
        help="Azure tenant ID for service principal authentication.",
    ),
    client_id: Optional[str] = typer.Option(
        None,
        "--client-id",
        help="Service principal client ID for authentication.",
    ),
    client_secret: Optional[str] = typer.Option(
        None,
        "--client-secret",
        envvar="FORGE_AZURE_CLIENT_SECRET",
        help="Service principal client secret for authentication.",
    ),
    services: str = typer.Option(
        "all",
        "--services",
        help="Comma-separated Azure services to audit: rbac,storage,sql,keyvault,appservice (default: all).",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview planned audit without API calls."),
    output_format: str = typer.Option(
        "json",
        "--output-format",
        help="Output format: json, csv, sarif.",
    ),
    output_path: Optional[str] = typer.Option(
        None,
        "--output",
        help="Optional output file path. Defaults under engagement artifacts.",
    ),
    timeout: int = typer.Option(600, "--timeout", help="Maximum execution time in seconds."),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before direct live Azure audits.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Skip the interactive confirmation after --roe-id; intended for kill-chain auto-run.",
    ),
) -> None:
    """Comprehensive Azure security audit (RBAC, Storage, SQL, Key Vault, App Service)."""
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.phase4.azure_audit import run_azure_audit  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    output_format = _normalise_output_format(output_format)
    subscription_value = subscription_id or cfg.cloud_azure_subscription_id
    tenant_value = tenant_id or cfg.cloud_azure_tenant_id
    client_value = client_id or cfg.cloud_azure_client_id
    services_value = services
    if services == "all" and cfg.cloud_azure_services:
        services_value = ",".join(cfg.cloud_azure_services)
    services_list = (
        [item.strip() for item in services_value.split(",") if item.strip()]
        if services_value != "all"
        else None
    )
    
    console.print(f"[bold blue]Azure Security Audit[/bold blue]")
    console.print(f"  Engagement: {engagement}")
    console.print(f"  Subscription: {subscription_value or 'auto-detect'}")
    console.print(f"  Services: {services_value}")
    console.print(f"  Dry run: {dry_run}")
    console.print(f"  Output: {output_format}")
    yes = yes if isinstance(yes, bool) else False
    if not dry_run:
        _direct_cli_require_roe(roe_id, command_name="cloud azure")
        if not yes:
            import questionary  # noqa: PLC0415

            proceed = questionary.confirm(
                "Run Azure audit against live APIs for this engagement?"
            ).ask()
            if not proceed:
                raise typer.Exit()
    
    try:
        findings = run_azure_audit(
            db_path=db_path,
            engagement_id=int(engagement),
            subscription_id=subscription_value,
            tenant_id=tenant_value,
            client_id=client_value,
            client_secret=client_secret,
            services=services_list,
            dry_run=dry_run,
            timeout=timeout,
        )
        findings_payload = [finding.to_dict() for finding in findings]
        default_ext = "sarif" if output_format == "sarif" else output_format
        output_target = (
            Path(output_path)
            if output_path
            else (cfg.data_dir / "engagements" / str(engagement) / "reports" / f"azure_audit.{default_ext}")
        )
        _write_cloud_output(
            findings=findings_payload,
            provider="azure",
            output_format=output_format,
            output_path=output_target,
        )
        console.print(f"[green]✓ Azure audit completed: {len(findings)} findings[/green]")
        console.print(f"[green]✓ Output written:[/green] {output_target}")
        
    except Exception as exc:
        console.print(f"[red]✗ Azure audit failed: {exc}[/red]")
        raise typer.Exit(1)


@cloud_app.command("firebase-extract")
def cloud_firebase_extract(
    engagement: Optional[str] = typer.Option(None, "--engagement", "-e"),
    apk: Optional[str] = typer.Option(None, "--apk", help="Path to Android APK, AAB, XAPK, APKM, or APKS file."),
    ipa: Optional[str] = typer.Option(None, "--ipa", help="Path to iOS IPA file."),
    target_url: Optional[str] = typer.Option(
        None, "--target-url", "-u",
        help="Web app URL to crawl for embedded Firebase config (auto-discovery).",
    ),
    output_json: Optional[str] = typer.Option(
        None,
        "--output-json",
        help="Write extracted config to JSON file.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct web Firebase extraction gating.",
    ),
) -> None:
    """Extract Firebase config from APK/AAB/XAPK/APKM/APKS/IPA bundles OR web app auto-discovery (Module 4-F).

    --apk / --ipa: Offline decompile of mobile bundle to find google-services.json.
    --target-url:  Crawl target web app JS/HTML to auto-extract embedded firebaseConfig.
                   No Firebase keys needed — discovers them FROM the target app.
    """
    from pathlib import Path as _Path  # noqa: PLC0415
    import sqlite3 as _sqlite3  # noqa: PLC0415

    from forge.config import ForgeConfig  # noqa: PLC0415

    if not apk and not ipa and not target_url:
        console.print("[bold red]ERROR:[/bold red] Provide --apk, --ipa, or --target-url.")
        raise typer.Exit(code=1)

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement) if engagement else None

    # --- Web auto-discovery (new) ---
    if target_url:
        from forge.phase4.firebase_extract import extract_firebase_config  # noqa: PLC0415
        if not dry_run and not engagement:
            raise typer.BadParameter("--engagement is required for live --target-url extraction.")
        if engagement and db_path:
            scope_values, url_prefixes = _direct_cli_load_scope_lists(
                engagement_id=int(engagement),
                db_path=db_path,
                scope_manifest=scope_manifest,
                target=target_url,
                seed_type="url",
            )
            scope = [*scope_values, *url_prefixes]
        else:
            scope = [target_url.split("//")[-1].split("/")[0]]
        conn = _sqlite3.connect(str(db_path)) if db_path else _sqlite3.connect(":memory:")
        conn.row_factory = _sqlite3.Row
        found = extract_firebase_config(
            engagement_id=int(engagement) if engagement else 0,
            engagement_scope=scope,
            target_url=target_url,
            eng_db_conn=conn,
            cfg=cfg,
            dry_run=dry_run,
        )
        conn.commit(); conn.close()
        if not found:
            console.print("[yellow]No Firebase config found in web app.[/yellow]")
        for c in found:
            _api_key_raw = str(c.get('api_key','') or '')
            _api_key_disp = (
                f"{_api_key_raw[:4]}...{_api_key_raw[-4:]}"
                if len(_api_key_raw) > 8 else "***"
            )
            console.print(f"  [green]Found:[/green] project_id={c.get('project_id')}  api_key={_api_key_disp}")
            console.print(f"  [dim]→ forge cloud firebase --project-id {c.get('project_id')}[/dim]")
        if output_json and found:
            import json as _json
            _Path(output_json).write_text(_json.dumps(found, indent=2))
            console.print(f"JSON written to {output_json}")
        return

    # --- Mobile bundle extraction (existing) ---
    from forge.phase4.mobile_config_parse import FirebaseExtractor  # noqa: PLC0415
    extractor = FirebaseExtractor(age_pubkey=None)
    projects = []
    supabase_configs = []
    if apk:
        projects.extend(extractor.extract_apk(_Path(apk)))
        supabase_configs.extend(extractor.extract_supabase_apk(_Path(apk)))
    if ipa:
        projects.extend(extractor.extract_ipa(_Path(ipa)))
        supabase_configs.extend(extractor.extract_supabase_ipa(_Path(ipa)))

    if not projects and not supabase_configs:
        console.print("[yellow]No Firebase or Supabase mobile config found.[/yellow]")
        return

    for p in projects:
        console.print(f"  [green]Firebase:[/green] {p.project_id}  (source: {p.source_file})")
        console.print(f"  [dim]→ forge cloud firebase --project-id {p.project_id}[/dim]")
    for config in supabase_configs:
        console.print(f"  [green]Supabase:[/green] {config.project_ref}  (source: {config.source_file})")
        console.print(f"  [dim]→ forge cloud supabase --engagement {engagement or '-'} --project-ref {config.project_ref}[/dim]")

    if engagement and db_path:
        written = extractor.store(projects, db_path, engagement_id=int(engagement))
        supabase_written = extractor.store_supabase_configs(
            supabase_configs,
            db_path,
            engagement_id=int(engagement),
        )
        console.print(f"Stored {written} Firebase project(s) and {supabase_written} Supabase config(s) in engagement evidence.")

    if output_json:
        if supabase_configs:
            extractor.emit_mobile_config_json(projects, supabase_configs, _Path(output_json))
        else:
            extractor.emit_json(projects, _Path(output_json))
        console.print(f"JSON written to {output_json}")


@cloud_app.command("supabase")
def cloud_supabase(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    project_ref: Optional[str] = typer.Option(
        None,
        "--project-ref",
        "--project-id",
        help="Supabase project reference ID (e.g. xyzxyzxyz). --project-id accepted as alias for parity with `cloud firebase`.",
    ),
    url: Optional[str] = typer.Option(
        None,
        "--url",
        help="Full Supabase base URL (alternative to --project-ref).",
    ),
    anon_key: Optional[str] = typer.Option(
        None,
        "--anon-key",
        envvar="FORGE_SUPABASE_ANON_KEY",
        help="Supabase anonymous public key (apikey header). Supports comma-separated key rotation.",
    ),
    auth_token: Optional[str] = typer.Option(
        None,
        "--auth-token",
        help="Authenticated JWT to test differential access.",
    ),
    auto_discover: Optional[bool] = typer.Option(
        None,
        "--auto-discover/--no-auto-discover",
        help="Enable in-scope Supabase anon key discovery from live endpoints.",
    ),
    mobile_extract: Optional[bool] = typer.Option(
        None,
        "--mobile-extract/--no-mobile-extract",
        help="Enable mobile-config Supabase key extraction fallback.",
    ),
    repo_scavenge: Optional[bool] = typer.Option(
        None,
        "--repo-scavenge/--no-repo-scavenge",
        help="Enable repository scavenging for Supabase keys.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before direct live Supabase scans.",
    ),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct Supabase scan gating.",
    ),
) -> None:
    """Test Supabase RLS policy misconfigurations via anonymous REST probing (Module 4-G).

    OPSEC: Active testing against live Supabase REST API. Write probes use a
    recognisable payload (__forge_probe__) — run `forge clean` after testing
    to document the probe record for the client's cleanup checklist.
    """
    if not project_ref and not url:
        console.print("[bold red]ERROR:[/bold red] Provide --project-ref or --url.")
        raise typer.Exit(code=1)

    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.phase4.api_policy_check import SupabaseScanner  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    scope_values: list[str] = []
    url_prefixes: list[str] = []
    if not dry_run:
        _direct_cli_require_roe(roe_id, command_name="cloud supabase")
        supabase_target = (url or "").strip() or f"https://{project_ref}.supabase.co"
        scope_values, url_prefixes = _direct_cli_load_scope_lists(
            engagement_id=int(engagement),
            db_path=db_path,
            scope_manifest=scope_manifest,
            target=supabase_target,
            seed_type="url",
        )
    scanner = SupabaseScanner(db_path=db_path, engagement_id=int(engagement))
    scanner.scan(
        project_ref=project_ref or "",
        base_url=url,
        anon_key=anon_key,
        auth_token=auth_token,
        auto_discover=(cfg.supabase_auto_discovery if auto_discover is None else auto_discover),
        mobile_extract=(cfg.mobile_assets_scan if mobile_extract is None else mobile_extract),
        repo_scavenge=(cfg.repo_key_scavenge if repo_scavenge is None else repo_scavenge),
        dry_run=dry_run,
        scope_values=scope_values,
        url_prefixes=url_prefixes,
        require_scope=not dry_run,
    )


