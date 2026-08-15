"""Authentication-testing command registration for the Forge CLI."""

from __future__ import annotations

import json
import time
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import typer
from rich.console import Console

from forge.cli_helpers import _direct_cli_load_scope_lists, _direct_cli_require_roe
from forge.config import ForgeConfig
from forge.db.direct_connect import direct_connect


def run_auth_brute(
    *,
    engagement: str,
    target: str,
    username: str,
    dictionary_type: str,
    max_attempts: Optional[int],
    roe_id: Optional[str],
    scope_manifest: Optional[str],
    console: Console,
    config_cls: Any = ForgeConfig,
    require_roe: Callable[..., None] = _direct_cli_require_roe,
    load_scope_lists: Callable[..., tuple[list[str], list[str]]] = _direct_cli_load_scope_lists,
) -> None:
    """Run the direct authentication brute-force command body."""

    import httpx  # noqa: PLC0415

    from forge.utils.intel.credential_generator import generate_dynamic_passwords  # noqa: PLC0415
    from forge.utils.intel.evasion import build_evasion_headers, evasion_sleep  # noqa: PLC0415

    cfg = config_cls.load()
    require_roe(roe_id, command_name="auth brute")
    db_path = cfg.engagement_db_path(engagement)
    load_scope_lists(
        engagement_id=int(engagement),
        db_path=db_path,
        scope_manifest=scope_manifest,
        target=target,
        seed_type="url",
    )
    attempts_limit = max_attempts or cfg.auth_max_attempts
    host = (urlparse(target).hostname or "target").strip()
    if dictionary_type == "dynamic":
        candidates = generate_dynamic_passwords(host, limit=attempts_limit)
    else:
        candidates = generate_dynamic_passwords(host, limit=attempts_limit)
    conn = direct_connect(db_path)
    success = 0
    tested = 0
    try:
        for password in candidates[:attempts_limit]:
            headers = build_evasion_headers()
            try:
                response = httpx.post(
                    target,
                    data={"username": username, "password": password},
                    headers=headers,
                    timeout=8.0,
                    follow_redirects=False,
                )
                body_lower = response.text.lower()
                ok = response.status_code in {200, 302} and any(
                    token in body_lower for token in ("dashboard", "logout", "welcome")
                )
                response_hint = body_lower[:200]
                status_code = response.status_code
            except Exception as exc:
                ok = False
                response_hint = str(exc)[:200]
                status_code = 0
            conn.execute(
                """
                INSERT INTO auth_test_results (
                    engagement_id, target_url, form_data, attack_type, success, response_data
                ) VALUES (?, ?, ?, 'brute-force', ?, ?)
                """,
                (
                    int(engagement),
                    target,
                    f'{{"username":"{username}","password":"***"}}',
                    1 if ok else 0,
                    f'{{"status_code":{status_code},"hint":{json.dumps(response_hint)}}}',
                ),
            )
            tested += 1
            if ok:
                success += 1
            if cfg.auth_rate_limit > 0:
                evasion_sleep()
                time.sleep(max(0.0, 60.0 / float(cfg.auth_rate_limit)))
        conn.commit()
    finally:
        conn.close()
    console.print(f"[green]Auth brute attempts:[/green] {tested}")
    console.print(f"[green]Auth brute successes:[/green] {success}")


def run_auth_bypass(
    *,
    engagement: str,
    target: str,
    technique: str,
    roe_id: Optional[str],
    scope_manifest: Optional[str],
    console: Console,
    config_cls: Any = ForgeConfig,
    require_roe: Callable[..., None] = _direct_cli_require_roe,
    load_scope_lists: Callable[..., tuple[list[str], list[str]]] = _direct_cli_load_scope_lists,
) -> None:
    """Run the direct authentication-bypass command body."""

    from forge.phase4.auth_bypass import run_bypass_assessment  # noqa: PLC0415

    cfg = config_cls.load()
    require_roe(roe_id, command_name="auth bypass")
    db_path = cfg.engagement_db_path(engagement)
    scope_values, url_prefixes = load_scope_lists(
        engagement_id=int(engagement),
        db_path=db_path,
        scope_manifest=scope_manifest,
        target=target,
        seed_type="url",
    )
    result = run_bypass_assessment(
        engagement_id=int(engagement),
        db_path=db_path,
        target_url=target,
        technique=technique,
        scope_values=scope_values,
        url_prefixes=url_prefixes,
        require_scope=True,
    )
    if result.success:
        console.print(
            f"[bold yellow]Potential bypass detected[/bold yellow] "
            f"{result.technique} @ {result.target_url}"
        )
    else:
        console.print(f"[green]No bypass detected[/green] {result.technique} @ {result.target_url}")


def register_auth_commands(
    auth_app: typer.Typer,
    *,
    console: Console,
    config_cls: Any = ForgeConfig,
    require_roe: Callable[..., None] = _direct_cli_require_roe,
    load_scope_lists: Callable[..., tuple[list[str], list[str]]] = _direct_cli_load_scope_lists,
) -> None:
    """Register authentication-testing commands on the auth sub-app."""

    @auth_app.command("brute")
    def auth_brute_command(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        target: str = typer.Option(..., "--target"),
        username: str = typer.Option("admin", "--username"),
        dictionary_type: str = typer.Option("dynamic", "--dictionary-type"),
        max_attempts: Optional[int] = typer.Option(None, "--max-attempts"),
        roe_id: Optional[str] = typer.Option(
            None,
            "--roe-id",
            envvar="FORGE_ROE_ID",
            help="ROE identifier required before direct live auth brute-force checks.",
        ),
        scope_manifest: Optional[str] = typer.Option(
            None,
            "--scope-manifest",
            help="Scope manifest path/JSON for direct live auth brute-force gating.",
        ),
    ) -> None:
        run_auth_brute(
            engagement=engagement,
            target=target,
            username=username,
            dictionary_type=dictionary_type,
            max_attempts=max_attempts,
            roe_id=roe_id,
            scope_manifest=scope_manifest,
            console=console,
            config_cls=config_cls,
            require_roe=require_roe,
            load_scope_lists=load_scope_lists,
        )

    @auth_app.command("bypass")
    def auth_bypass_command(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        target: str = typer.Option(..., "--target"),
        technique: str = typer.Option("sql-injection", "--technique"),
        roe_id: Optional[str] = typer.Option(
            None,
            "--roe-id",
            envvar="FORGE_ROE_ID",
            help="ROE identifier required before direct live auth-bypass checks.",
        ),
        scope_manifest: Optional[str] = typer.Option(
            None,
            "--scope-manifest",
            help="Scope manifest path/JSON for direct live auth-bypass gating.",
        ),
    ) -> None:
        run_auth_bypass(
            engagement=engagement,
            target=target,
            technique=technique,
            roe_id=roe_id,
            scope_manifest=scope_manifest,
            console=console,
            config_cls=config_cls,
            require_roe=require_roe,
            load_scope_lists=load_scope_lists,
        )


__all__ = ["register_auth_commands", "run_auth_brute", "run_auth_bypass"]
