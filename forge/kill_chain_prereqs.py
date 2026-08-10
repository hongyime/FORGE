from __future__ import annotations

import os
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect


PrerequisiteRecord = dict[str, object]

_MOBILE_ARTIFACT_PATTERNS = ("*.apk", "*.aab", "*.xapk", "*.apkm", "*.apks", "*.ipa")


def handle_kill_chain_prerequisite_flow(
    detected: Sequence[PrerequisiteRecord],
    *,
    auto_run_detected: bool,
    parallel_workers: int,
    console_print: Callable[[str], None],
    log: Callable[[str, str], None],
    complete_run: Callable[[dict[str, object]], None],
    audit_auto_run: Callable[[str], None],
    audit_prompted: Callable[[str], None],
    run_inprocess_batch: Any,
    run_module_batch: Any,
    run_module: Callable[[list[str], str], int],
    make_dispatch_spec: Callable[[list[str], str], object],
    harden_child_argv: Callable[[Sequence[str]], list[str]],
    progress_callback: Any,
    is_tty: bool,
    input_func: Callable[[str], str] = input,
) -> None:
    if not detected:
        console_print(
            "\n[dim]No additional tools currently applicable. Add breach dumps to "
            ".forge_data/breach/, set AWS/Azure creds in .env, or place APKs/configs "
            "under data/mobile/, data/artifacts/, data/evidence/, or data/uploads/ "
            "to unlock more.[/dim]"
        )
        complete_run(
            {
                "prereq_detected_count": 0,
                "prereq_runnable_count": 0,
                "prereq_execution_mode": "none",
                "prereq_auto_run_enabled": bool(auto_run_detected),
            }
        )
        return

    console_print(
        f"\n[bold yellow]Additional tools available on this engagement[/bold yellow] "
        f"([dim]{len(detected)} detected[/dim]):"
    )
    for item in detected:
        marker = "[green]RUNNABLE[/green]" if item["runnable"] else "[dim]manual[/dim]"
        console_print(f"  [cyan]*[/cyan] [bold]{item['label']}[/bold] {marker} - {item['reason']}")
        if item["argv"] is not None:
            argv = item["argv"]
            preview = "forge " + " ".join(str(arg) for arg in argv)  # type: ignore[union-attr]
            console_print(f"       [dim]{preview}[/dim]")
        elif item["manual_hint"]:
            console_print(f"       [dim]{item['manual_hint']}[/dim]")

    runnable = [item for item in detected if item["runnable"]]
    if not runnable:
        console_print(
            "\n[dim]None are auto-runnable (all need --target-url or per-service "
            "params). Copy the suggested command when ready.[/dim]"
        )
        complete_run(
            {
                "prereq_detected_count": len(detected),
                "prereq_runnable_count": 0,
                "prereq_execution_mode": "manual_only",
                "prereq_auto_run_enabled": bool(auto_run_detected),
            }
        )
        return

    if auto_run_detected:
        _auto_run_prerequisites(
            runnable,
            detected_count=len(detected),
            parallel_workers=parallel_workers,
            console_print=console_print,
            log=log,
            complete_run=complete_run,
            audit_auto_run=audit_auto_run,
            run_inprocess_batch=run_inprocess_batch,
            run_module_batch=run_module_batch,
            run_module=run_module,
            make_dispatch_spec=make_dispatch_spec,
            harden_child_argv=harden_child_argv,
            progress_callback=progress_callback,
        )
        return

    if is_tty:
        _prompt_prerequisites(
            runnable,
            detected_count=len(detected),
            auto_run_detected=auto_run_detected,
            console_print=console_print,
            complete_run=complete_run,
            audit_prompted=audit_prompted,
            run_module=run_module,
            input_func=input_func,
        )
        return

    console_print(
        "\n[dim]Non-TTY invocation - not prompting. Re-run interactively "
        "or pass --auto-run-detected to execute the RUNNABLE entries.[/dim]"
    )
    complete_run(
        {
            "prereq_detected_count": len(detected),
            "prereq_runnable_count": len(runnable),
            "prereq_execution_mode": "non_tty_skipped",
            "prereq_auto_run_enabled": bool(auto_run_detected),
        }
    )


def _auto_run_prerequisites(
    runnable: Sequence[PrerequisiteRecord],
    *,
    detected_count: int,
    parallel_workers: int,
    console_print: Callable[[str], None],
    log: Callable[[str, str], None],
    complete_run: Callable[[dict[str, object]], None],
    audit_auto_run: Callable[[str], None],
    run_inprocess_batch: Any,
    run_module_batch: Any,
    run_module: Callable[[list[str], str], int],
    make_dispatch_spec: Callable[[list[str], str], object],
    harden_child_argv: Callable[[Sequence[str]], list[str]],
    progress_callback: Any,
) -> None:
    console_print(
        f"\n[bold cyan]--auto-run-detected set[/bold cyan] - running "
        f"{len(runnable)} runnable prereq(s) now."
    )
    prereq_inputs = [item for item in runnable if item.get("argv") is not None]
    if len(prereq_inputs) > 1 and parallel_workers > 1:
        log(
            "prereq spec prep",
            f"[dim]parallel parse x{min(parallel_workers, len(prereq_inputs))}[/dim]",
        )
    prereq_specs = run_inprocess_batch(
        prereq_inputs,
        lambda item: make_dispatch_spec(
            harden_child_argv([str(arg) for arg in item["argv"]]),  # type: ignore[index]
            f"prereq: {item['label']}",
        ),
        max_workers=parallel_workers,
        progress_label="prereq spec prep",
        progress_callback=progress_callback,
    )
    if len(prereq_specs) > 1 and parallel_workers > 1:
        log(
            "prereq auto-run",
            f"[dim]parallel dispatch x{min(parallel_workers, len(prereq_specs))}[/dim]",
        )
    prereq_results = run_module_batch(
        prereq_specs,
        run_module,
        max_workers=parallel_workers,
    )
    prereq_failures = sum(1 for result in prereq_results if int(result) != 0)
    audit_auto_run(
        f"ran={len(prereq_specs)} failed={prereq_failures} "
        f"workers={min(parallel_workers, len(prereq_specs) or 1)}"
    )
    complete_run(
        {
            "prereq_detected_count": detected_count,
            "prereq_runnable_count": len(runnable),
            "prereq_execution_mode": "auto_run",
            "prereq_auto_run_enabled": True,
            "prereq_auto_run_count": len(prereq_specs),
            "prereq_auto_run_failures": prereq_failures,
        }
    )


def _prompt_prerequisites(
    runnable: Sequence[PrerequisiteRecord],
    *,
    detected_count: int,
    auto_run_detected: bool,
    console_print: Callable[[str], None],
    complete_run: Callable[[dict[str, object]], None],
    audit_prompted: Callable[[str], None],
    run_module: Callable[[list[str], str], int],
    input_func: Callable[[str], str],
) -> None:
    console_print(
        f"\n[bold]{len(runnable)} tool(s) can be run now.[/bold] "
        "Press Y to run each, any other key to skip.\n"
    )
    ran = 0
    for item in runnable:
        try:
            resp = input_func(f"Run [{item['label']}]? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console_print("[dim]input cancelled - stopping prereq prompts[/dim]")
            break
        if resp == "y":
            argv = item["argv"]
            run_module([str(arg) for arg in argv], f"prereq: {item['label']}")  # type: ignore[union-attr]
            ran += 1
    audit_prompted(f"offered={len(runnable)} ran={ran}")
    complete_run(
        {
            "prereq_detected_count": detected_count,
            "prereq_runnable_count": len(runnable),
            "prereq_execution_mode": "prompted",
            "prereq_auto_run_enabled": bool(auto_run_detected),
            "prereq_prompted_count": len(runnable),
            "prereq_prompted_ran": ran,
        }
    )


def detect_kill_chain_prerequisites(
    *,
    db_path: Path,
    engagement_id: int,
    engagement: str,
    domain: str,
    include_offensive_prereqs: bool,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> list[PrerequisiteRecord]:
    """Return safe runnable prereqs plus optional manual-only offensive hints."""
    effective_env = env or os.environ
    effective_cwd = cwd or Path.cwd()
    detected: list[PrerequisiteRecord] = []

    def add(
        label: str,
        reason: str,
        *,
        argv: list[str] | None = None,
        manual_hint: str | None = None,
    ) -> None:
        detected.append(
            {
                "label": label,
                "reason": reason,
                "argv": argv,
                "manual_hint": manual_hint,
                "runnable": argv is not None,
            }
        )

    _add_safe_prereqs(
        add, engagement=engagement, domain=domain, cwd=effective_cwd, env=effective_env
    )
    if include_offensive_prereqs:
        _add_offensive_prereqs(
            add,
            db_path=db_path,
            engagement_id=engagement_id,
            engagement=engagement,
            env=effective_env,
        )
    return detected


def _add_safe_prereqs(
    add: Any,
    *,
    engagement: str,
    domain: str,
    cwd: Path,
    env: Mapping[str, str],
) -> None:
    if env.get("FORGE_DEHASHED_API_KEY") and env.get("FORGE_DEHASHED_EMAIL"):
        add(
            "osint dehashed (Module 2-C)",
            "FORGE_DEHASHED_* env vars are set",
            argv=[
                "osint",
                "dehashed",
                "--engagement",
                engagement,
                "--query-type",
                "domain",
                "--query-value",
                domain,
            ],
        )

    breach_dir = cwd / ".forge_data" / "breach"
    if breach_dir.is_dir():
        dumps = [path for path in breach_dir.glob("*") if path.is_file()]
        if dumps:
            add(
                "osint breach (Module 2-A)",
                f"{len(dumps)} breach dump(s) in .forge_data/breach/",
                argv=["osint", "breach", "--engagement", engagement, "--db", str(dumps[0])],
            )

    if env.get("AWS_PROFILE") or env.get("AWS_ACCESS_KEY_ID"):
        add(
            "cloud aws (Module 4)",
            "AWS creds detected in env",
            argv=["cloud", "aws", "--engagement", engagement],
        )

    if env.get("FORGE_AZURE_SUBSCRIPTION_ID") or env.get("AZURE_TENANT_ID"):
        add(
            "cloud azure (Module 4)",
            "Azure creds detected in env",
            argv=["cloud", "azure", "--engagement", engagement],
        )

    mobile_artifacts = _local_mobile_artifacts(cwd)
    if mobile_artifacts:
        from forge.engagement_orchestrator import default_local_artifact_roots

        local_artifact_roots = [path for path in default_local_artifact_roots(cwd) if path.is_dir()]
        visible_roots = ", ".join(path.as_posix() for path in local_artifact_roots[:4])
        add(
            "cloud firebase-extract (Module 4-F)",
            f"{len(mobile_artifacts)} mobile package(s) across {visible_roots}",
            argv=[
                "cloud",
                "firebase-extract",
                "--engagement",
                engagement,
                "--apk",
                str(mobile_artifacts[0]),
            ],
        )


def _local_mobile_artifacts(cwd: Path) -> list[Path]:
    from forge.engagement_orchestrator import default_local_artifact_roots

    artifacts: list[Path] = []
    for artifact_root in (path for path in default_local_artifact_roots(cwd) if path.is_dir()):
        for pattern in _MOBILE_ARTIFACT_PATTERNS:
            artifacts.extend(path for path in artifact_root.glob(pattern) if path.is_file())
    return artifacts


def _add_offensive_prereqs(
    add: Any,
    *,
    db_path: Path,
    engagement_id: int,
    engagement: str,
    env: Mapping[str, str],
) -> None:
    if str(env.get("FORGE_SAFE_MODE", "0")).strip() in ("0", "false", "no", ""):
        add(
            "evasion generate (Phase 3)",
            "FORGE_SAFE_MODE is off - payload generation available",
            manual_hint=(
                f"forge evasion generate --engagement {engagement} "
                "--technique <lolbin-technique> --os windows"
            ),
        )

    service_count = _optional_count(
        db_path,
        """
        SELECT COUNT(*) FROM services s JOIN hosts h ON s.host_id=h.id
        WHERE h.engagement_id=?
        """,
        (engagement_id,),
    )
    credential_count = _optional_count(
        db_path,
        "SELECT COUNT(*) FROM credentials WHERE engagement_id=?",
        (engagement_id,),
    )
    if service_count > 0:
        add(
            "vuln idor (Module 4-D)",
            f"{service_count} discovered service(s) - IDOR probing available",
            manual_hint=f"forge vuln idor --engagement {engagement} --target-url <url>",
        )
    if service_count > 0 and credential_count > 0:
        add(
            "auth brute (Phase 4)",
            f"{service_count} service(s) + {credential_count} credential(s) - brute-force ready",
            manual_hint=f"forge auth brute --engagement {engagement} --target <host> --service <svc>",
        )
    if service_count > 0:
        add(
            "auth bypass (Phase 4)",
            f"{service_count} service(s) with potential auth surfaces",
            manual_hint=f"forge auth bypass --engagement {engagement} --target-url <url>",
        )

    validated_count = _optional_count(
        db_path,
        "SELECT COUNT(*) FROM credentials WHERE engagement_id=? AND validated=1",
        (engagement_id,),
        default_on_error=0,
    )
    if validated_count > 0:
        add(
            "post {shell,beacon,lateral} (Phase 5)",
            f"{validated_count} VALIDATED credential(s) - post-ex viable "
            "(requires FORGE_SAFE_MODE=0 + written ROE)",
            manual_hint=(
                f"forge post shell --engagement {engagement} "
                "--target <host> --service ssh --cred-id <id>"
            ),
        )


def _optional_count(
    db_path: Path,
    sql: str,
    params: tuple[object, ...],
    *,
    default_on_error: int = 0,
) -> int:
    try:
        con = direct_connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            return int((con.execute(sql, params).fetchone() or [default_on_error])[0] or 0)
        except sqlite3.OperationalError:
            return default_on_error
        finally:
            con.close()
    except Exception:  # noqa: BLE001
        return default_on_error
