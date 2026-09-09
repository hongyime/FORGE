"""Session enumeration CLI commands — ``forge sessions`` sub-app.

Provides ``forge sessions enum`` for BloodHound/SharpHound-style active-session
collection from Windows (NetSessionEnum) and Linux (who/w/last) targets.
All operations are scope-gated; ROE is required for live execution.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Optional

import typer

from forge.cli import console, sessions_app
from forge.cli_helpers import (
    _cli_audit,
    _direct_cli_load_scope_lists,
    _direct_cli_require_roe,
)


@sessions_app.command("enum")
def sessions_enum(
    engagement: str = typer.Option(..., "--engagement", "-e", help="Engagement ID."),
    target: Optional[str] = typer.Option(
        None,
        "--target",
        "-t",
        help=(
            "Target host for Windows NetSessionEnum (UNC or bare hostname). "
            "Omit to enumerate the local machine. Linux always collects locally."
        ),
    ),
    platform: str = typer.Option(
        "auto",
        "--platform",
        help="Platform: windows, linux, auto. 'auto' selects based on the current OS.",
    ),
    level: int = typer.Option(
        10,
        "--level",
        help="Windows SESSION_INFO level: 10 (default) or 502 (adds client type + transport).",
    ),
    output_format: str = typer.Option(
        "json",
        "--output-format",
        help="Output format: json, csv.",
    ),
    output_path: Optional[str] = typer.Option(
        None,
        "--output",
        help="Optional output file path. Defaults under engagement artifacts.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Log intent but do not enumerate."),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before live session enumeration.",
    ),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path or inline JSON for engagement scope gating.",
    ),
) -> None:
    """Enumerate active SMB/login sessions (BloodHound-style collection).

    On Windows, calls ``netapi32!NetSessionEnum`` against the target host
    (or the local machine when ``--target`` is omitted).  On Linux, parses
    ``who``, ``w``, and ``last`` command output for the local host.

    OPSEC: Windows enumeration makes an SMB/RPC call visible on the wire.
    ``ACCESS_DENIED`` on hardened targets is expected and returned as a
    structured result, never a crash.  All enumeration is recorded in the
    engagement audit log before and after execution.
    """
    from forge.config import ForgeConfig  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    engagement_id = int(engagement)

    platform_norm = platform.strip().lower()
    if platform_norm not in {"windows", "linux", "auto"}:
        console.print("[bold red]ERROR:[/bold red] --platform must be one of: windows, linux, auto")
        raise typer.Exit(code=1)

    output_fmt = output_format.strip().lower()
    if output_fmt not in {"json", "csv"}:
        console.print("[bold red]ERROR:[/bold red] --output-format must be one of: json, csv")
        raise typer.Exit(code=1)

    if level not in {10, 502}:
        console.print("[bold red]ERROR:[/bold red] --level must be 10 or 502")
        raise typer.Exit(code=1)

    # Resolve effective platform.
    effective_platform = platform_norm
    if effective_platform == "auto":
        effective_platform = "windows" if sys.platform == "win32" else "linux"

    # ---------------------------------------------------------------------- #
    # ROE gate
    # ---------------------------------------------------------------------- #
    if not dry_run:
        _direct_cli_require_roe(roe_id, command_name="sessions enum")

    # ---------------------------------------------------------------------- #
    # Scope manifest
    # ---------------------------------------------------------------------- #
    scope_values: list[str] = []
    _scope_dict: dict = {}
    if not dry_run:
        try:
            scope_values, _ = _direct_cli_load_scope_lists(
                engagement_id=engagement_id,
                db_path=db_path,
                scope_manifest=scope_manifest,
            )
        except typer.BadParameter as exc:
            console.print(f"[bold red]Scope error:[/bold red] {exc}")
            raise typer.Exit(code=1)
        # Build a minimal scope manifest dict for the collection layer.
        _scope_dict = _build_scope_dict(scope_manifest, scope_values, target)

    # ---------------------------------------------------------------------- #
    # Audit — intent
    # ---------------------------------------------------------------------- #
    _cli_audit(
        db_path=db_path,
        engagement_id=engagement_id,
        phase="collection",
        module="session_enumeration",
        action="start",
        target=target or "local",
        result="initiated" if not dry_run else "dry_run",
    )

    console.print("[bold blue]Session Enumeration[/bold blue]")
    console.print(f"  Engagement: {engagement}")
    console.print(f"  Platform:   {effective_platform}")
    console.print(f"  Target:     {target or 'local'}")
    console.print(f"  Level:      {level} (Windows only)")
    console.print(f"  Dry run:    {dry_run}")

    if dry_run:
        console.print("[yellow]Dry-run: no session enumeration performed.[/yellow]")
        _cli_audit(
            db_path=db_path,
            engagement_id=engagement_id,
            phase="collection",
            module="session_enumeration",
            action="complete",
            target=target or "local",
            result="dry_run_complete",
        )
        return

    # ---------------------------------------------------------------------- #
    # Enumerate
    # ---------------------------------------------------------------------- #
    started = time.monotonic()
    sessions_raw: list[dict] = []
    collection_error: str | None = None

    try:
        if effective_platform == "windows":
            from forge.collection.sessions.windows_sessions import enumerate_sessions  # noqa: PLC0415

            result = enumerate_sessions(
                target,
                engagement_id=engagement_id,
                scope_manifest=_scope_dict,
                db_path=db_path,
                level=level,
            )
            if result.get("ok"):
                sessions_raw = result.get("sessions", [])
                for s in sessions_raw:
                    s["platform"] = "windows"
                    s["target"] = result.get("server") or "local"
            else:
                collection_error = result.get("error") or "unknown_error"
        else:
            from forge.collection.sessions.linux_sessions import collect_linux_sessions  # noqa: PLC0415

            sessions_obj = collect_linux_sessions(
                engagement_id=engagement_id,
                scope_manifest=_scope_dict,
                db_path=db_path,
                local_target=target or "127.0.0.1",
            )
            for s in sessions_obj:
                d = {
                    "user": s.user,
                    "terminal": s.terminal,
                    "login_time": s.login_time,
                    "logout_time": s.logout_time,
                    "host": s.host,
                    "session_type": s.session_type,
                    "source": s.source,
                    "idle": s.idle,
                    "what": s.what,
                    "platform": "linux",
                    "target": target or "local",
                }
                sessions_raw.append(d)

    except Exception as exc:  # noqa: BLE001
        collection_error = type(exc).__name__
        console.print(f"[red]Session enumeration error: {exc}[/red]")

    elapsed_ms = (time.monotonic() - started) * 1000

    # ---------------------------------------------------------------------- #
    # Output
    # ---------------------------------------------------------------------- #
    output_target = Path(output_path) if output_path else (
        cfg.data_dir
        / "engagements"
        / str(engagement)
        / "reports"
        / f"sessions.{output_fmt}"
    )
    output_target.parent.mkdir(parents=True, exist_ok=True)

    if output_fmt == "json":
        output_target.write_text(
            json.dumps(sessions_raw, indent=2, default=str), encoding="utf-8"
        )
    else:
        import csv  # noqa: PLC0415

        if sessions_raw:
            all_keys: list[str] = []
            seen: set[str] = set()
            for row in sessions_raw:
                for k in row:
                    if k not in seen:
                        seen.add(k)
                        all_keys.append(k)
            with output_target.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=all_keys, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(sessions_raw)
        else:
            output_target.write_text("", encoding="utf-8")

    # ---------------------------------------------------------------------- #
    # Audit — completion
    # ---------------------------------------------------------------------- #
    result_label = (
        f"error:{collection_error} elapsed_ms={elapsed_ms:.0f}"
        if collection_error
        else f"ok count={len(sessions_raw)} elapsed_ms={elapsed_ms:.0f}"
    )
    _cli_audit(
        db_path=db_path,
        engagement_id=engagement_id,
        phase="collection",
        module="session_enumeration",
        action="complete",
        target=target or "local",
        result=result_label,
    )

    if collection_error:
        console.print(
            f"[yellow]Session enumeration returned error: {collection_error}[/yellow]"
        )
    else:
        console.print(
            f"[green]Session enumeration completed: {len(sessions_raw)} session(s)[/green]"
        )
    console.print(f"[green]Output written:[/green] {output_target}")

    if collection_error:
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _build_scope_dict(
    scope_manifest: Optional[str],
    scope_values: list[str],
    target: Optional[str],
) -> dict:
    """Build a minimal scope manifest dict for the collection layer.

    Tries to parse ``scope_manifest`` as JSON first; falls back to
    constructing a minimal dict from ``scope_values`` + the explicit
    ``target``.
    """
    if scope_manifest:
        raw = scope_manifest.strip()
        if raw.startswith("{"):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass
        else:
            from pathlib import Path as _Path  # noqa: PLC0415
            try:
                text = _Path(raw).read_text(encoding="utf-8")
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    return parsed
            except (OSError, json.JSONDecodeError):
                pass

    # Build minimal dict from scope_values — split IPs vs hostnames.
    import ipaddress  # noqa: PLC0415

    ip_ranges: list[str] = []
    hostnames: list[str] = []
    candidates = list(scope_values)
    if target:
        candidates.append(target)
    for entry in candidates:
        stripped = entry.strip()
        if not stripped:
            continue
        try:
            ipaddress.ip_network(stripped, strict=False)
            ip_ranges.append(stripped)
        except ValueError:
            try:
                ipaddress.ip_address(stripped)
                ip_ranges.append(stripped)
            except ValueError:
                hostnames.append(stripped)
    # Always include loopback so local enumeration passes.
    if "127.0.0.1" not in ip_ranges:
        ip_ranges.append("127.0.0.1")
    return {"ip_ranges": ip_ranges, "hostnames": hostnames}
