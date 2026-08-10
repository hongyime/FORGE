"""OSINT CLI commands — Phase 2 intelligence operations.

Extracted from forge/cli.py for modularity. All @osint_app.command functions live here.
"""

from __future__ import annotations

import ipaddress
import os
import sqlite3
from pathlib import Path
from typing import Optional

import typer

from forge.cli import osint_app, console
from forge.cli_helpers import (
    _cli_audit,
    _direct_cli_load_scope_lists,
    _identity_lookup_max_workers,
    _run_callable_batch,
)
from forge.db.direct_connect import direct_connect


@osint_app.command("breach")
def osint_breach(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    db: str = typer.Option(..., "--db", help="Path to breach database file."),
    fmt: Optional[str] = typer.Option(None, "--format", help="sqlite|text|csv|basequery"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Query breach database for engagement-scoped targets (Module 2-A)."""
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.data_connector import BreachFormat, run_breach_query  # noqa: PLC0415

    try:
        engagement_id = int(engagement)
    except ValueError as exc:
        raise typer.BadParameter("--engagement must be a numeric engagement id") from exc

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    conn = direct_connect(db_path)
    try:
        try:
            run_breach_query(
                engagement_id=engagement_id,
                db_path=Path(db),
                conn=conn,
                fmt=BreachFormat(fmt) if fmt else None,
                dry_run=dry_run,
                operator=cfg.operator,
            )
        except FileNotFoundError as exc:
            console.print(
                f"[yellow]Breach DB skipped:[/yellow] "
                f"{exc}. Drop a dump file at "
                "`.forge_data/breach/*.db` or `.forge_data/breach/*.csv` "
                "and re-run."
            )
        except RuntimeError as exc:
            console.print(f"[yellow]Breach lookup skipped:[/yellow] {str(exc)[:200]}")
    finally:
        conn.close()


@osint_app.command("validate")
def osint_validate(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    service: str = typer.Option(..., "--service", help="ssh|http|rdp|smb|ftp|dbms"),
    host: str = typer.Option(..., "--host"),
) -> None:
    """Validate harvested credentials against a live service (Module 2-B)."""
    from forge.utils.intel.auth_check import run_validation  # noqa: PLC0415

    run_validation(engagement_id=int(engagement), service=service, host=host)


@osint_app.command("keyscan")
def osint_keyscan(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    domain: str = typer.Option(
        ...,
        "--domain",
        "-d",
        help="Target domain to search for (must match engagement scope).",
    ),
    org: Optional[str] = typer.Option(
        None, "--org", help="GitHub organisation name to restrict code search."
    ),
    github_token: Optional[str] = typer.Option(
        None,
        "--github-token",
        envvar="FORGE_GITHUB_TOKEN",
        help="GitHub PAT for code search API. Supports comma-separated token rotation.",
    ),
    gitlab_token: Optional[str] = typer.Option(
        None,
        "--gitlab-token",
        envvar="FORGE_GITLAB_TOKEN",
        help="GitLab PAT for blob search (optional). Supports comma-separated token rotation.",
    ),
    validation_proxy: Optional[str] = typer.Option(
        None,
        "--validation-proxy",
        envvar="FORGE_VALIDATION_PROXY",
        help="Proxy URI for provider validation calls (e.g., socks5://127.0.0.1:9050).",
    ),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct keyscan gating.",
    ),
    no_validate: bool = typer.Option(
        False,
        "--no-validate",
        help="Pattern-match only; zero outbound provider calls. Findings stored as UNCONFIRMED.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Scan public repos for exposed API keys attributed to target domain (Module 2-J).

    OPSEC: GitHub code search queries are attributed to the PAT used.
    Always use a purpose-built throwaway account — never the operator's personal account.
    Validation calls are logged by AWS/Stripe/GitHub; route through --validation-proxy.
    """
    if not no_validate and validation_proxy is None:
        console.print(
            "[bold red]OPSEC ERROR:[/bold red] --validation-proxy is required unless "
            "--no-validate is set. Validation calls without a proxy expose operator IP.\n"
            "  Use: [bold]--validation-proxy socks5://127.0.0.1:9050[/bold]\n"
            "  Or:  [bold]--no-validate[/bold]  (findings stored as UNCONFIRMED)"
        )
        raise typer.Exit(code=1)

    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.secret_finder import run_key_scanner  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    _direct_cli_load_scope_lists(
        engagement_id=int(engagement),
        db_path=db_path,
        scope_manifest=scope_manifest,
        target=domain,
        seed_type="domain" if "." in domain else "other",
    )

    run_key_scanner(
        db_path=db_path,
        engagement_id=int(engagement),
        domain=domain,
        org=org,
        github_token=github_token,
        gitlab_token=gitlab_token,
        validation_proxy=validation_proxy,
        no_validate=no_validate,
        dry_run=dry_run,
        operator=cfg.operator,
    )


@osint_app.command("dehashed")
def osint_dehashed(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    query_type: str = typer.Option(
        ...,
        "--query-type",
        help="Query field: email | domain | username | ip_address",
    ),
    query_value: str = typer.Option(..., "--query-value", help="Value to search."),
    max_pages: int = typer.Option(10, "--max-pages", help="Maximum result pages to fetch."),
    cache_ttl: int = typer.Option(24, "--cache-ttl", help="Skip if synced within N hours."),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Query DeHashed breach intelligence API for target credentials (Module 2-C)."""
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.index_query import run_dehashed_query  # noqa: PLC0415

    cfg = ForgeConfig.load()
    try:
        run_dehashed_query(
            db_path=cfg.engagement_db_path(engagement),
            engagement_id=int(engagement),
            query_type=query_type,
            query_value=query_value,
            max_pages=max_pages,
            cache_ttl_hours=cache_ttl,
            dry_run=dry_run,
        )
    except RuntimeError as exc:
        # Missing FORGE_DEHASHED_* creds / scope violation / API error —
        # treat as clean SKIP so kill-chain doesn't abort.
        console.print(f"[yellow]DeHashed skipped:[/yellow] {str(exc)[:200]}")
    except FileNotFoundError as exc:
        console.print(f"[yellow]DeHashed skipped:[/yellow] missing dependency: {exc}")


@osint_app.command("xposed")
def osint_xposed(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    emails: Optional[str] = typer.Option(
        None,
        "--emails",
        help="Comma-separated email list override (default: from DB).",
    ),
    cache_ttl: int = typer.Option(48, "--cache-ttl", help="Skip if synced within N hours."),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Query XposedOrNot API for breach exposure metadata (Module 2-D)."""
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.exposure_check import run_xposed_query  # noqa: PLC0415

    cfg = ForgeConfig.load()
    email_list = [e.strip() for e in emails.split(",")] if emails else None
    run_xposed_query(
        db_path=cfg.engagement_db_path(engagement),
        engagement_id=int(engagement),
        email_list=email_list,
        cache_ttl_hours=cache_ttl,
        dry_run=dry_run,
    )


@osint_app.command("harvest")
def osint_harvest(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    domain: str = typer.Option(..., "--domain", "-d"),
    sources: str = typer.Option(
        "crtsh,duckduckgo,certspotter,dnsdumpster,rapiddns",
        "--sources",
        help="Comma-separated theHarvester source list.",
    ),
    timeout: int = typer.Option(300, "--timeout", help="Subprocess kill timeout in seconds."),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy",
        envvar="FORGE_PROXY",
        help="Optional HTTP/SOCKS proxy for theHarvester subprocess requests.",
    ),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct harvest gating.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Enumerate emails and subdomains via theHarvester >= 4.0.0 (Module 2-E)."""
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.contact_enum import run_harvester  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    _direct_cli_load_scope_lists(
        engagement_id=int(engagement),
        db_path=db_path,
        scope_manifest=scope_manifest,
        target=domain,
        seed_type="domain",
    )
    run_harvester(
        db_path=db_path,
        engagement_id=int(engagement),
        domain=domain,
        sources=sources,
        timeout=timeout,
        proxy=proxy,
        dry_run=dry_run,
    )


@osint_app.command("hibp")
def osint_hibp(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    api_key: Optional[str] = typer.Option(
        None,
        "--api-key",
        envvar="FORGE_HIBP_API_KEY",
        help="HIBP API key (optional — enables per-email lookup; domain search is always free).",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Query Have I Been Pwned for breach exposure on target emails/domains (Module 2-F).

    Free tier: domain-level breach listing (no passwords, no key needed).
    With API key: per-email breach confirmation.
    Use local_breach.py (Module 2-A) for actual credential lookup against COMB/Collection#1.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.phase2.hibp import query_hibp  # noqa: PLC0415
    import sqlite3  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)

    with direct_connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        scope = (
            cfg.get_engagement_scope(int(engagement), conn)
            if hasattr(cfg, "get_engagement_scope")
            else []
        )
        result = query_hibp(
            engagement_id=int(engagement),
            engagement_scope=scope,
            eng_db_conn=conn,
            api_key=api_key or None,
            dry_run=dry_run,
        )
    console.print(
        f"[green]HIBP complete.[/green] Domains checked. Breaches found: {len(result.get('breaches_by_name', {}))}"
    )
    for name, info in (result.get("breaches_by_name") or {}).items():
        console.print(
            f"  [yellow]{name}[/yellow] — {info.get('pwn_count', 0):,} records | {info.get('breach_date', '?')}"
        )


@osint_app.command("emailrep")
def osint_emailrep(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    emails: Optional[str] = typer.Option(
        None,
        "--emails",
        help="Comma-separated email list override (default: from DB).",
    ),
    api_key: Optional[str] = typer.Option(
        None,
        "--api-key",
        envvar="FORGE_EMAILREP_API_KEY",
        help="Optional EmailRep API key.",
    ),
    cache_ttl: int = typer.Option(24, "--cache-ttl", help="Skip if synced within N hours."),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """EmailRep email-reputation enrichment (Module 2-F)."""
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.reputation_lookup import run_reputation_lookup  # noqa: PLC0415

    cfg = ForgeConfig.load()
    email_list = [e.strip() for e in emails.split(",") if e.strip()] if emails else None
    run_reputation_lookup(
        db_path=cfg.engagement_db_path(engagement),
        engagement_id=int(engagement),
        api_key=api_key,
        emails=email_list,
        cache_ttl=cache_ttl,
        dry_run=dry_run,
        operator=cfg.operator,
    )


@osint_app.command("accounts")
def osint_accounts(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    emails: Optional[str] = typer.Option(
        None,
        "--emails",
        help="Comma-separated email list. Defaults to emails from the engagement DB.",
    ),
    max_workers: int = typer.Option(
        1,
        "--max-workers",
        envvar="FORGE_HOLEHE_MAX_WORKERS",
        min=1,
        max=4,
        help="Bounded outer Holehe email worker count. Defaults to 1.",
    ),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy",
        envvar="FORGE_PROXY",
        help="Optional HTTP/SOCKS proxy for Holehe subprocess requests.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Discover which services an email is registered on via holehe (Module 2-L).

    100+ free presence-check endpoints. All checks are attributed to the
    querying IP - route through a proxy if OPSEC-sensitive.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.account_exists import run_holehe  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    engagement_id = int(engagement)

    email_list = [e.strip() for e in emails.split(",")] if emails else None
    _cli_audit(
        db_path,
        engagement_id,
        "phase2",
        "holehe",
        "accounts_start",
        target=",".join(email_list) if email_list else "<from-db>",
        result=f"dry_run={dry_run} proxy_configured={bool(proxy)}",
    )
    try:
        n = run_holehe(
            db_path=db_path,
            engagement_id=engagement_id,
            emails=email_list,
            dry_run=dry_run,
            operator=cfg.operator,
            max_workers=max_workers,
            proxy=proxy,
        )
    except Exception as exc:
        _cli_audit(
            db_path,
            engagement_id,
            "phase2",
            "holehe",
            "accounts_failed",
            result=f"{type(exc).__name__}: {str(exc)[:180]}",
        )
        raise
    _cli_audit(
        db_path,
        engagement_id,
        "phase2",
        "holehe",
        "accounts_complete",
        result=f"accounts_upserted={n}",
    )
    console.print(f"[green]Holehe complete.[/green] Account-existence rows upserted: {n}")


@osint_app.command("phone")
def osint_phone(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    number: str = typer.Option(
        ..., "--number", "-n", help="Phone number in E.164 format (+15551234567)."
    ),
    no_online: bool = typer.Option(
        False, "--no-online", help="Skip PhoneInfoga (offline parse only)."
    ),
    max_dork_concurrency: int = typer.Option(
        1,
        "--max-dork-concurrency",
        envvar="FORGE_PHONE_DORK_MAX_CONCURRENCY",
        min=1,
        max=3,
        help="Bounded PhoneInfoga-derived public-search dork concurrency. Defaults to 1.",
    ),
) -> None:
    """Phone-number OSINT: country/carrier/type via phonenumbers, plus
    optional PhoneInfoga Google dorks + reputation checks if binary present."""
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.phone_lookup import lookup_phone  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    result = lookup_phone(
        number=number,
        engagement_id=int(engagement),
        db_path=db_path,
        include_online=not no_online,
        dork_max_workers=max_dork_concurrency,
    )
    parse = result.get("parse", {})
    console.print(f"[bold]Phone:[/bold] {number}")
    if parse.get("valid"):
        console.print(f"  region:   {parse.get('region')}")
        console.print(f"  carrier:  {parse.get('carrier')}")
        console.print(f"  type:     {parse.get('line_type')}")
        console.print(f"  format:   {parse.get('international')}")
    else:
        console.print(f"  [yellow]parse error:[/yellow] {parse.get('error')}")
    pi = result.get("phoneinfoga", {})
    if pi:
        if pi.get("available"):
            if "scanners" in pi:
                dc = pi.get("dork_count", {})
                total = pi.get("total_dorks", 0)
                console.print(
                    f"  [green]phoneinfoga scan:[/green] "
                    f"{len(pi['scanners'])} scanner(s), {total} dork URL(s)"
                )
                for scanner, count in dc.items():
                    console.print(f"    {scanner}: {count} dorks")
            elif "error" in pi:
                console.print(f"  [yellow]phoneinfoga error:[/yellow] {pi['error'][:80]}")
        else:
            console.print(f"  [dim]phoneinfoga:[/dim] {pi.get('reason', 'unavailable')}")

    accounts = result.get("accounts", {})
    if accounts:
        console.print(f"[bold]Account existence probes:[/bold]")
        for service, status in accounts.items():
            colour = {
                "REGISTERED": "green",
                "NOT_FOUND": "dim",
                "INVALID_FORMAT": "yellow",
                "UNVERIFIABLE": "dim",
                "UNKNOWN": "yellow",
                "ERROR": "red",
            }.get(status, "dim")
            console.print(f"  [{colour}]{service:<12}[/{colour}] {status}")

    mined = result.get("dork_mining", {})
    if mined and (
        mined.get("emails_found") or mined.get("usernames_found") or mined.get("sites_searched")
    ):
        console.print(f"[bold]Dork mining (via DDG):[/bold]")
        sites = mined.get("sites_searched", [])
        if sites:
            console.print(
                f"  sites queried: {', '.join(sites[:6])}"
                + (f"  (+{len(sites) - 6} more)" if len(sites) > 6 else "")
            )
        emails = mined.get("emails_found", [])
        if emails:
            console.print(
                f"  [green]emails discovered:[/green] "
                f"{', '.join(emails[:5])}"
                + (f"  (+{len(emails) - 5} more)" if len(emails) > 5 else "")
            )
        else:
            console.print(f"  [dim]emails discovered:[/dim] none")
        unames = mined.get("usernames_found", [])
        if unames:
            console.print(
                f"  [green]usernames discovered:[/green] "
                f"{', '.join(unames[:5])}"
                + (f"  (+{len(unames) - 5} more)" if len(unames) > 5 else "")
            )
        else:
            console.print(f"  [dim]usernames discovered:[/dim] none")

    persisted = result.get("persisted", {})
    if persisted:
        console.print(
            f"[bold]Persisted to engagement DB:[/bold] "
            f"{persisted.get('emails', 0)} email(s), "
            f"{persisted.get('social_profiles', 0)} social profile(s)"
        )


@osint_app.command("name")
def osint_name(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    name: str = typer.Option(
        ..., "--name", "-n", help='Full name in quotes, e.g. "FORGE Operator".'
    ),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy",
        envvar="FORGE_PROXY",
        help="HTTP/SOCKS proxy for the search queries (e.g. socks5://127.0.0.1:9050 for Tor).",
    ),
    max_concurrency: int = typer.Option(
        1,
        "--max-concurrency",
        envvar="FORGE_NAME_SEARCH_MAX_CONCURRENCY",
        min=1,
        max=3,
        help="Bounded public-search dork concurrency. Defaults to 1 to avoid provider rate limits.",
    ),
) -> None:
    """Full-name OSINT: SearXNG (over Tor if proxied) with site-restricted
    dorks on LinkedIn/GitHub/Twitter/Instagram/Medium/Keybase. Regex-extracts
    candidate profile handles, deduped."""
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.name_search import search_name  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    profiles = search_name(
        name=name,
        engagement_id=int(engagement),
        db_path=db_path,
        proxy=proxy,
        max_concurrency=max_concurrency,
    )
    console.print(f"[bold]Name search:[/bold] {name}")
    total = sum(len(v) for v in profiles.values())
    if total == 0:
        console.print("  [dim]no profile candidates surfaced[/dim]")
    for platform, handles in profiles.items():
        if handles:
            console.print(
                f"  [cyan]{platform}[/cyan]: {', '.join(handles[:5])}"
                + (f"  (+{len(handles) - 5} more)" if len(handles) > 5 else "")
            )


@osint_app.command("gravatar")
def osint_gravatar(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    emails: Optional[str] = typer.Option(
        None,
        "--emails",
        help="Comma-separated email list. Defaults to emails already stored in the engagement DB.",
    ),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy",
        envvar="FORGE_PROXY",
        help="Optional HTTP/SOCKS proxy for Gravatar public-profile requests.",
    ),
) -> None:
    """Gravatar public-profile enrichment (Module 2-O).

    For each email, computes MD5 and fetches gravatar.com/<md5>.json.
    Zero API key, zero signup. Yields display name, username, bio,
    location, and linked accounts (Twitter/GitHub/LinkedIn/TikTok/etc.).

    Discovered linked accounts get persisted to social_profiles so the
    kill-chain E5 fan-out picks them up for Sherlock on the next
    iteration.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.gravatar_lookup import (  # noqa: PLC0415
        lookup_gravatar,
        persist_gravatar_findings,
    )
    import sqlite3 as _sq3  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    eng_id = int(engagement)
    proxy_value = (
        str(proxy).strip()
        if isinstance(proxy, str)
        else os.environ.get("FORGE_PROXY", "").strip() or None
    )

    # Determine email list
    if emails:
        email_list = [e.strip() for e in emails.split(",") if e.strip()]
    else:
        con = _sq3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            try:
                rows = con.execute(
                    "SELECT DISTINCT email FROM emails WHERE engagement_id=?",
                    (eng_id,),
                ).fetchall()
                email_list = [r[0] for r in rows if r[0] and "@" in r[0]]
            except _sq3.OperationalError:
                email_list = []
        finally:
            con.close()

    if not email_list:
        console.print("[dim]No emails to look up. Pass --emails or seed some first.[/dim]")
        return

    total_hits = 0
    total_new_rows = 0
    gravatar_inputs = email_list[:20]
    identity_workers = _identity_lookup_max_workers()
    gravatar_results = _run_callable_batch(
        gravatar_inputs,
        lambda email: (email, lookup_gravatar(email, eng_id, db_path, proxy=proxy_value)),
        max_workers=min(identity_workers, len(gravatar_inputs)),
    )
    for email, result in gravatar_results:
        if result.get("found"):
            total_hits += 1
            p = result["profile"]
            new_rows = persist_gravatar_findings(email, eng_id, db_path, p)
            total_new_rows += new_rows
            console.print(f"[green]HIT[/green] {email}")
            console.print(f"  display: {p.get('display_name', '')}")
            console.print(f"  username: {p.get('preferred_username', '')}")
            if p.get("bio"):
                console.print(f"  bio: {p['bio'][:100]}")
            if p.get("location"):
                console.print(f"  location: {p['location']}")
            for acct in p.get("accounts", []):
                v = "[green]OK[/green]" if acct.get("verified") else "[dim]?[/dim]"
                console.print(
                    f"  {v} {acct.get('domain', '?'):<14} "
                    f"{acct.get('username', '?'):<20} "
                    f"{acct.get('url', '')[:60]}"
                )
        else:
            console.print(f"[dim]MISS {email}[/dim]")
    console.print(
        f"\n[bold]Summary:[/bold] {total_hits}/{len(gravatar_inputs)} email(s) "
        f"have Gravatar profiles. {total_new_rows} social_profiles rows written."
    )


@osint_app.command("google")
def osint_google(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    emails: Optional[str] = typer.Option(
        None,
        "--emails",
        help="Comma-separated emails. Defaults to emails in the engagement DB.",
    ),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy",
        envvar="FORGE_PROXY",
        help="Optional HTTP/SOCKS proxy for GHunt subprocess requests.",
    ),
) -> None:
    """Ghunt Google-account enrichment (Module 2-P).

    Uses your ghunt login session (creds.m) to pull Gaia ID, activated
    Google services (Maps/Meet/Drive/Photos/Play Games), public Calendar
    events if any, and Maps review count. Feeds discovered handles back
    to social_profiles so fan-out E5 Sherlocks them next iteration.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.google_account import (  # noqa: PLC0415
        lookup_google_account,
        persist_google_findings,
        _ghunt_creds_available,
    )
    import sqlite3 as _sq3  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    eng_id = int(engagement)
    proxy_value = (
        str(proxy).strip()
        if isinstance(proxy, str)
        else os.environ.get("FORGE_PROXY", "").strip() or None
    )

    if not _ghunt_creds_available():
        console.print(
            "[yellow]Ghunt creds not found.[/yellow] Run `ghunt login` "
            "first, then paste base64 auth from the Companion extension."
        )
        return

    if emails:
        email_list = [e.strip() for e in emails.split(",") if e.strip()]
    else:
        con = _sq3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            try:
                rows = con.execute(
                    "SELECT DISTINCT email FROM emails WHERE engagement_id=?",
                    (eng_id,),
                ).fetchall()
                email_list = [r[0] for r in rows if r[0] and "@" in r[0]]
            except _sq3.OperationalError:
                email_list = []
        finally:
            con.close()

    if not email_list:
        console.print("[dim]No emails to look up.[/dim]")
        return

    hits = 0
    google_inputs = email_list[:10]  # cap - Ghunt is slow
    identity_workers = _identity_lookup_max_workers()
    google_results = _run_callable_batch(
        google_inputs,
        lambda email: (email, lookup_google_account(email, eng_id, db_path, proxy=proxy_value)),
        max_workers=min(identity_workers, len(google_inputs)),
    )
    for email, result in google_results:
        if not result.get("found"):
            reason = result.get("error") or result.get("reason") or "not found"
            console.print(f"[dim]MISS[/dim] {email}  ({reason})")
            continue
        hits += 1
        profile = result.get("profile", {})
        rows_written = persist_google_findings(email, eng_id, db_path, profile)
        console.print(f"[green]HIT[/green] {email}")
        console.print(f"  gaia_id: {profile.get('gaia_id', '')}")
        for k in ("display_name", "last_edit"):
            v = profile.get(k)
            if v:
                console.print(f"  {k}: {v}")
        apps = profile.get("apps", []) or []
        if apps:
            console.print(f"  active services: {', '.join(apps)}")
        console.print(f"  [dim]{rows_written} social_profiles rows written[/dim]")
    console.print(f"\n[bold]Summary:[/bold] {hits}/{len(google_inputs)} Google accounts.")


@osint_app.command("linkedin")
def osint_linkedin(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    domain: str = typer.Option(..., "--domain", "-d", help="Company domain (e.g. acme.com)."),
    max_dorks: int = typer.Option(5, "--max-dorks", help="Number of dork queries to run."),
    max_concurrency: int = typer.Option(
        1,
        "--max-concurrency",
        envvar="FORGE_LINKEDIN_DORK_MAX_CONCURRENCY",
        min=1,
        max=2,
        help="Bounded LinkedIn public-search dork concurrency. Defaults to 1.",
    ),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct LinkedIn lookup gating.",
    ),
) -> None:
    """CrossLinked-style LinkedIn employee discovery (Module 2-Q).

    Uses Google dorks (via DDG/Bing/Startpage) to find `/in/<slug>`
    profiles referencing the target company, parses slugs to
    firstname/lastname pairs, generates candidate emails in 14+
    patterns. Persists candidate emails to `emails` and LinkedIn slugs
    to `social_profiles`.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.linkedin_scraper import (  # noqa: PLC0415
        enumerate_linkedin_employees,
        persist_linkedin_findings,
    )

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    _direct_cli_load_scope_lists(
        engagement_id=int(engagement),
        db_path=db_path,
        scope_manifest=scope_manifest,
        target=domain,
        seed_type="domain",
    )
    result = enumerate_linkedin_employees(
        domain=domain,
        engagement_id=int(engagement),
        db_path=db_path,
        max_dorks=max_dorks,
        max_concurrency=max_concurrency,
    )
    counts = persist_linkedin_findings(
        domain=domain,
        engagement_id=int(engagement),
        db_path=db_path,
        result=result,
    )
    console.print(f"[bold]LinkedIn scrape for {domain}:[/bold]")
    console.print(f"  raw dork hits:       {result.get('raw_hits', 0)}")
    console.print(f"  linkedin_slugs:      {len(result.get('linkedin_slugs', []))}")
    console.print(f"  parsed names:        {len(result.get('names', []))}")
    console.print(f"  candidate emails:    {len(result.get('candidate_emails', []))}")
    console.print(f"  company_slugs:       {len(result.get('company_slugs', []))}")
    console.print(
        f"  [dim]persisted -> emails: {counts.get('emails', 0)}, "
        f"social_profiles: {counts.get('social_profiles', 0)}[/dim]"
    )
    for slug in result.get("linkedin_slugs", [])[:5]:
        console.print(f"    [cyan]{slug}[/cyan]")


@osint_app.command("urlscan")
def osint_urlscan(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    hostname: str = typer.Option(..., "--hostname", "-H", help="Domain or hostname to search."),
    max_results: int = typer.Option(
        20, "--max-results", help="Cap on urlscan search results returned."
    ),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct urlscan lookup gating.",
    ),
) -> None:
    """URLScan.io public-search enrichment (Module 2-R).

    Queries urlscan.io for historical scans of a hostname. Extracts
    related domains, unique IPs, tech-stack servers. No API key required
    (rate-limited to 100 searches/day anon).
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.urlscan_lookup import (  # noqa: PLC0415
        search_urlscan,
        persist_urlscan_findings,
    )

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    _direct_cli_load_scope_lists(
        engagement_id=int(engagement),
        db_path=db_path,
        scope_manifest=scope_manifest,
        target=hostname,
        seed_type="domain",
    )
    result = search_urlscan(hostname, int(engagement), db_path, max_results=max_results)
    counts = persist_urlscan_findings(hostname, int(engagement), db_path, result)
    console.print(f"[bold]URLScan.io for {hostname}:[/bold]")
    console.print(f"  scans returned:      {len(result.get('scans', []))}")
    console.print(f"  unique IPs:          {len(result.get('unique_ips', []))}")
    console.print(f"  related domains:     {len(result.get('related_domains', []))}")
    console.print(f"  distinct servers:    {len(result.get('servers', []))}")
    console.print(f"  [dim]persisted -> hosts_written: {counts.get('hosts_written', 0)}[/dim]")
    for d in result.get("related_domains", [])[:5]:
        console.print(f"    [cyan]{d}[/cyan]")


@osint_app.command("instagram")
def osint_instagram(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    username: str = typer.Option(..., "--username", "-u", help="Instagram handle without @."),
) -> None:
    """Instagram profile enrichment (Module 2-S).

    Toutatis-style fetch of Instagram's anonymous web_profile_info
    endpoint. Extracts biography, external_url, follower count,
    verified flag, bio_links. Mines emails/URLs from bio, feeds
    discovered emails back into fan-out E on the next iteration.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.instagram_lookup import (  # noqa: PLC0415
        lookup_instagram,
        persist_instagram_findings,
    )

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    result = lookup_instagram(username.lstrip("@"), int(engagement), db_path)
    if not result.get("found"):
        reason = result.get("error", "not found or blocked")
        console.print(f"[dim]MISS[/dim] @{username}  ({reason})")
        return
    counts = persist_instagram_findings(username.lstrip("@"), int(engagement), db_path, result)
    p = result.get("profile", {})
    console.print(f"[green]HIT[/green] @{username}")
    console.print(f"  full_name:      {p.get('full_name', '')}")
    console.print(f"  is_verified:    {p.get('is_verified', False)}")
    console.print(f"  is_business:    {p.get('is_business', False)}")
    console.print(f"  follower_count: {p.get('follower_count', 0)}")
    if p.get("biography"):
        console.print(f"  bio:            {p['biography'][:100]}")
    if p.get("external_url"):
        console.print(f"  external_url:   {p['external_url']}")
    ems = p.get("emails_in_bio", [])
    if ems:
        console.print(f"  [green]emails discovered:[/green] {', '.join(ems)}")
    console.print(
        f"  [dim]persisted -> emails: {counts.get('emails', 0)}, "
        f"social_profiles: {counts.get('social_profiles', 0)}[/dim]"
    )


@osint_app.command("shodan")
def osint_shodan(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    target: str = typer.Option(..., "--target", "-t", help="IP address OR domain."),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct Shodan lookup gating.",
    ),
) -> None:
    """Shodan enrichment (Module 2-T).

    Uses FORGE_SHODAN_API_KEY from env. For domains: resolves root
    A/AAAA records, then caps host-detail enrichment from those IPs.
    For IPs: pulls port/service banners + known CVEs. Persists all
    discoveries to hosts/services/audit_log so kill-chain fan-outs pick
    them up next iteration.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.shodan_lookup import (  # noqa: PLC0415
        lookup_shodan_host,
        lookup_shodan_domain,
        persist_shodan_findings,
        _shodan_key,
    )

    if not _shodan_key():
        console.print("[yellow]No FORGE_SHODAN_API_KEY in env.[/yellow]")
        return

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    eng_id = int(engagement)
    try:
        ipaddress.ip_address(target.strip())
        seed_type = "ipv4"
    except ValueError:
        seed_type = "domain"
    _direct_cli_load_scope_lists(
        engagement_id=eng_id,
        db_path=db_path,
        scope_manifest=scope_manifest,
        target=target,
        seed_type=seed_type,
    )

    # Detect IP vs domain
    try:
        ipaddress.ip_address(target.strip())
        is_ip = True
    except ValueError:
        is_ip = False
    host_result: dict = {}
    domain_result: dict = {}
    if is_ip:
        host_result = lookup_shodan_host(target, eng_id, db_path)
    else:
        domain_result = lookup_shodan_domain(target, eng_id, db_path)
    counts = persist_shodan_findings(target, eng_id, db_path, host_result, domain_result)
    console.print(f"[bold]Shodan for {target} ({'IP' if is_ip else 'domain'}):[/bold]")
    if is_ip and host_result.get("found"):
        h = host_result.get("host", {})
        console.print(f"  org:        {h.get('org', '')}")
        console.print(f"  isp:        {h.get('isp', '')}")
        console.print(f"  country:    {h.get('country_name', '')}")
        console.print(f"  ports:      {h.get('ports', [])}")
        console.print(f"  hostnames:  {h.get('hostnames', [])}")
        cves = h.get("cves", [])
        if cves:
            console.print(f"  [red]CVEs:[/red] {', '.join(cves[:10])}")
    elif not is_ip:
        subs = domain_result.get("subdomains", []) or []
        console.print(f"  subdomains discovered: {len(subs)}")
        for s in subs[:10]:
            console.print(f"    [cyan]{s}[/cyan]")
        recs = domain_result.get("records", []) or []
        console.print(f"  DNS records:           {len(recs)}")
    console.print(
        f"  [dim]persisted -> hosts: {counts.get('hosts_inserted', 0)}, "
        f"services: {counts.get('services_inserted', 0)}, "
        f"CVEs: {len(counts.get('cves', []))}[/dim]"
    )


@osint_app.command("social")
def osint_social(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    emails: Optional[str] = typer.Option(
        None,
        "--emails",
        help="Comma-separated email list. Defaults to emails already stored in the engagement DB.",
    ),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy",
        envvar="FORGE_PROXY",
        help="Optional HTTP/SOCKS proxy for Epieos requests.",
    ),
    max_concurrency: int = typer.Option(
        1,
        "--max-concurrency",
        envvar="FORGE_EPIEOS_MAX_CONCURRENCY",
        min=1,
        max=4,
        help="Bounded Epieos lookup concurrency. Defaults to 1.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Enumerate social-media presence for target emails via Epieos (Module 2-G).

    All queries pass through the engagement scope gate. Results land in the
    ``social_profiles`` table with a hash-chained audit log entry per email.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.social_scraper import run_social_scraper  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    engagement_id = int(engagement)

    email_list = [e.strip() for e in emails.split(",")] if emails else None
    _cli_audit(
        db_path,
        engagement_id,
        "phase2",
        "social_scraper",
        "social_start",
        target=",".join(email_list) if email_list else "<from-db>",
        result=f"dry_run={dry_run}",
    )
    try:
        n = run_social_scraper(
            db_path=db_path,
            engagement_id=engagement_id,
            emails=email_list,
            proxy=proxy,
            dry_run=dry_run,
            operator=cfg.operator,
            max_concurrency=max_concurrency,
        )
    except Exception as exc:
        _cli_audit(
            db_path,
            engagement_id,
            "phase2",
            "social_scraper",
            "social_failed",
            result=f"{type(exc).__name__}: {str(exc)[:180]}",
        )
        raise
    _cli_audit(
        db_path,
        engagement_id,
        "phase2",
        "social_scraper",
        "social_complete",
        result=f"profiles_written={n}",
    )
    console.print(f"[green]Epieos complete.[/green] Social profiles upserted: {n}")


@osint_app.command("usernames")
def osint_usernames(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    username: Optional[str] = typer.Option(
        None,
        "--username",
        "-u",
        help="Single username to enumerate. Mutually inclusive with --usernames.",
    ),
    usernames: Optional[str] = typer.Option(
        None,
        "--usernames",
        help="Comma-separated list of usernames.",
    ),
    backend: Optional[str] = typer.Option(
        None,
        "--backend",
        help="Backend preference: whatsmyname | maigret | sherlock. Default: auto-select.",
    ),
    proxy_file: Optional[str] = typer.Option(
        None,
        "--proxy-file",
        help="Path to a newline-delimited proxy list for rotation.",
    ),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy",
        envvar="FORGE_PROXY",
        help="Optional HTTP/SOCKS proxy for username-enumeration subprocess requests.",
    ),
    max_workers: int = typer.Option(
        1,
        "--max-workers",
        envvar="FORGE_HANDLE_FINDER_MAX_WORKERS",
        min=1,
        max=4,
        help="Bounded username-enumeration worker count. Defaults to 1.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Enumerate usernames across social sites via WhatsMyName / Maigret / Sherlock (Module 2-H).

    Requires one of ``whatsmyname``, ``maigret`` or ``sherlock`` on PATH (or
    installed into the active venv). Recommended:
    ``pip install sherlock-project maigret holehe`` - all three land in the
    venv Scripts/ dir and are auto-detected.
    """
    from pathlib import Path as _Path  # noqa: PLC0415
    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.utils.intel.handle_finder import run_handle_finder  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    engagement_id = int(engagement)
    proxy_value = (
        str(proxy).strip()
        if isinstance(proxy, str)
        else os.environ.get("FORGE_PROXY", "").strip() or None
    )

    name_list: list[str] = []
    if usernames:
        name_list.extend([n.strip() for n in usernames.split(",") if n.strip()])
    if username:
        name_list.append(username)
    if not name_list:
        console.print("[bold red]ERROR:[/bold red] specify --username and/or --usernames")
        raise typer.Exit(code=2)

    _cli_audit(
        db_path,
        engagement_id,
        "phase2",
        "handle_finder",
        "usernames_start",
        target=",".join(name_list),
        result=f"dry_run={dry_run} backend={backend or 'auto'} proxy_configured={bool(proxy_value)}",
    )
    try:
        n = run_handle_finder(
            db_path=db_path,
            engagement_id=engagement_id,
            usernames=name_list,
            proxy_file=_Path(proxy_file) if proxy_file else None,
            dry_run=dry_run,
            operator=cfg.operator,
            backend=backend,
            proxy=proxy_value,
            max_workers=max_workers,
        )
    except TypeError:
        # run_handle_finder may not accept backend= kwarg in older signatures;
        # fall back to positional-friendly call.
        n = run_handle_finder(
            db_path=db_path,
            engagement_id=engagement_id,
            usernames=name_list,
            proxy_file=_Path(proxy_file) if proxy_file else None,
            dry_run=dry_run,
            operator=cfg.operator,
        )
    except Exception as exc:
        _cli_audit(
            db_path,
            engagement_id,
            "phase2",
            "handle_finder",
            "usernames_failed",
            result=f"{type(exc).__name__}: {str(exc)[:180]}",
        )
        raise
    _cli_audit(
        db_path,
        engagement_id,
        "phase2",
        "handle_finder",
        "usernames_complete",
        result=f"profiles_written={n}",
    )
    console.print(f"[green]Username enum complete.[/green] Profiles upserted: {n}")
