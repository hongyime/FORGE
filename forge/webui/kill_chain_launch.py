"""Web UI kill-chain launch option and command helpers."""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

from forge.utils.kill_chain_options import normalize_kill_chain_max_iter
from forge.webui.run_status import latest_running_engagement_run

VALID_REPORT_PROVIDERS = frozenset(
    {
        "auto",
        "template",
        "llama_cpp",
        "kiro_cli",
        "claude_code",
        "codex_cli",
        "gemini_cli",
        "bedrock_anthropic",
        "openai_compatible",
    }
)


class KillChainLaunchOptionError(ValueError):
    """Raised when a Web UI kill-chain launch request is invalid."""


class KillChainLaunchConflict(RuntimeError):
    """Raised when an engagement already has an active run."""


class KillChainLaunchNoSeeds(ValueError):
    """Raised when an engagement has no launchable seeds."""


@dataclass(frozen=True)
class KillChainLaunchOptions:
    resume_enabled: bool
    dry_run: bool
    attack_mode: bool
    auto_run_detected: bool
    roe_id: str
    scope_manifest: str
    skip_cloud: bool
    skip_keyscan: bool
    max_iter: int
    report_provider: str | None
    report_max_loops: int | None

    @property
    def report_provider_label(self) -> str:
        return self.report_provider or "default"


@dataclass(frozen=True)
class KillChainLaunchSpec:
    options: KillChainLaunchOptions
    primary_seed: str
    related_seeds: list[str]
    command: list[str]

    @property
    def seed_count(self) -> int:
        return 1 + len(self.related_seeds)

    @property
    def command_preview(self) -> str:
        return " ".join(self.command)

    def payload_fields(self) -> dict[str, Any]:
        return {
            "seed_count": self.seed_count,
            "primary_seed": self.primary_seed,
            "related_seeds": list(self.related_seeds),
            "command_preview": self.command_preview,
            "resume_enabled": self.options.resume_enabled,
            "dry_run": self.options.dry_run,
            "attack_mode": self.options.attack_mode,
            "auto_run_detected": self.options.auto_run_detected,
            "roe_id": self.options.roe_id,
            "scope_manifest": self.options.scope_manifest,
            "skip_cloud": self.options.skip_cloud,
            "skip_keyscan": self.options.skip_keyscan,
            "max_iter": self.options.max_iter,
            "report_provider": self.options.report_provider_label,
            "report_max_loops": self.options.report_max_loops,
        }


@dataclass(frozen=True)
class KillChainLaunchProcess:
    pid: int


def ordered_launch_seeds(con: sqlite3.Connection, engagement_id: int) -> list[dict[str, str]]:
    rows = con.execute(
        """
        SELECT seed_value, seed_type
        FROM engagement_seeds
        WHERE engagement_id=?
        ORDER BY depth ASC,
                 CASE seed_type
                     WHEN 'domain' THEN 0
                     WHEN 'url' THEN 1
                     WHEN 'apk_url' THEN 2
                     WHEN 'subdomain' THEN 3
                     WHEN 'email' THEN 4
                     WHEN 'phone' THEN 5
                     WHEN 'username' THEN 6
                     WHEN 'name' THEN 7
                     WHEN 'company' THEN 8
                     WHEN 'ipv4' THEN 9
                     WHEN 'ipv6' THEN 10
                     ELSE 11
                 END,
                 CASE
                     WHEN source='operator' THEN 0
                     WHEN source='scope' THEN 1
                     ELSE 2
                 END,
                 id ASC
        """,
        (engagement_id,),
    ).fetchall()
    ordered: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        seed_value = str(row["seed_value"] or "").strip()
        seed_type = str(row["seed_type"] or "").strip().lower()
        if not seed_value:
            continue
        seed_key = (seed_type, seed_value)
        if seed_key in seen:
            continue
        seen.add(seed_key)
        ordered.append({"seed_value": seed_value, "seed_type": seed_type})
    return ordered


def normalize_roe_id(value: object) -> str:
    return " ".join(str(value or "").strip().split())[:160]


def parse_report_max_loops(value: object) -> int | None:
    if value in (None, ""):
        return None
    try:
        report_max_loops = int(value)
    except (TypeError, ValueError) as exc:
        raise KillChainLaunchOptionError("report_max_loops must be an integer.") from exc
    if report_max_loops < 0 or report_max_loops > 10:
        raise KillChainLaunchOptionError("report_max_loops must be between 0 and 10.")
    return report_max_loops


def parse_kill_chain_launch_options(
    body: dict[str, Any] | None,
    *,
    force_resume: bool | None,
    env: Mapping[str, str] | None = None,
) -> KillChainLaunchOptions:
    options = body or {}
    launch_env = os.environ if env is None else env
    resume_enabled = bool(options.get("resume", True)) if force_resume is None else force_resume
    dry_run = bool(options.get("dry_run", False))
    attack_mode = bool(options.get("attack_mode", False))
    auto_run_detected = bool(options.get("auto_run_detected", False))
    roe_id = normalize_roe_id(options.get("roe_id") or launch_env.get("FORGE_ROE_ID", ""))
    scope_manifest = str(
        options.get("scope_manifest") or launch_env.get("FORGE_SCOPE_MANIFEST", "")
    ).strip()
    skip_cloud = bool(options.get("skip_cloud", False))
    skip_keyscan = bool(options.get("skip_keyscan", False))
    try:
        max_iter = normalize_kill_chain_max_iter(options.get("max_iter"), default=3)
    except ValueError as exc:
        raise KillChainLaunchOptionError(str(exc)) from exc
    report_provider = str(options.get("report_provider") or "").strip().lower() or None
    report_max_loops = parse_report_max_loops(options.get("report_max_loops"))
    if report_provider is not None and report_provider not in VALID_REPORT_PROVIDERS:
        raise KillChainLaunchOptionError(f"Invalid report provider: {report_provider}")
    live_launch = not dry_run
    if live_launch and not roe_id:
        raise KillChainLaunchOptionError(
            "Live kill-chain execution requires roe_id or FORGE_ROE_ID. "
            "Use dry_run to preview without live execution."
        )
    if live_launch and not scope_manifest:
        raise KillChainLaunchOptionError(
            "Live kill-chain execution requires scope_manifest or "
            "FORGE_SCOPE_MANIFEST so execution is bounded to explicit authorization. "
            "Use dry_run to preview without live execution."
        )
    return KillChainLaunchOptions(
        resume_enabled=resume_enabled,
        dry_run=dry_run,
        attack_mode=attack_mode,
        auto_run_detected=auto_run_detected,
        roe_id=roe_id,
        scope_manifest=scope_manifest,
        skip_cloud=skip_cloud,
        skip_keyscan=skip_keyscan,
        max_iter=max_iter,
        report_provider=report_provider,
        report_max_loops=report_max_loops,
    )


def launch_seed_values(seeds: Sequence[Mapping[str, Any]]) -> tuple[str, list[str]]:
    primary_seed = str(seeds[0]["seed_value"])
    related_seeds = [str(item["seed_value"]) for item in seeds[1:]]
    return primary_seed, related_seeds


def build_kill_chain_command(
    *,
    executable: str,
    engagement_id: int,
    primary_seed: str,
    related_seeds: Sequence[str],
    options: KillChainLaunchOptions,
) -> list[str]:
    command = [
        executable,
        "-m",
        "forge.cli",
        "--no-tor",
        "kill-chain",
        primary_seed,
        "--engagement",
        str(engagement_id),
        "--max-iter",
        str(options.max_iter),
    ]
    if not options.resume_enabled:
        command.append("--no-resume")
    if options.dry_run:
        command.append("--dry-run")
    if options.attack_mode:
        command.append("--attack-mode")
    if options.auto_run_detected:
        command.append("--auto-run-detected")
    if options.roe_id:
        command.extend(["--roe-id", options.roe_id])
    if options.scope_manifest:
        command.extend(["--scope-manifest", options.scope_manifest])
    if options.skip_cloud:
        command.append("--skip-cloud")
    if options.skip_keyscan:
        command.append("--skip-keyscan")
    if options.report_provider:
        command.extend(["--report-provider", options.report_provider])
    if options.report_max_loops is not None:
        command.extend(["--report-max-loops", str(options.report_max_loops)])
    for seed_value in related_seeds:
        command.extend(["--related-seed", seed_value])
    return command


def build_kill_chain_launch_spec(
    body: dict[str, Any] | None,
    *,
    engagement_id: int,
    seeds: Sequence[Mapping[str, Any]],
    force_resume: bool | None,
    env: Mapping[str, str] | None = None,
    executable: str | None = None,
) -> KillChainLaunchSpec:
    options = parse_kill_chain_launch_options(body, force_resume=force_resume, env=env)
    primary_seed, related_seeds = launch_seed_values(seeds)
    command = build_kill_chain_command(
        executable=executable or sys.executable,
        engagement_id=engagement_id,
        primary_seed=primary_seed,
        related_seeds=related_seeds,
        options=options,
    )
    return KillChainLaunchSpec(
        options=options,
        primary_seed=primary_seed,
        related_seeds=related_seeds,
        command=command,
    )


def spawn_kill_chain_process(
    command: Sequence[str],
    *,
    log_handle: TextIO,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    popen_factory: Callable[..., Any] = subprocess.Popen,
) -> KillChainLaunchProcess:
    launch_env = dict(os.environ if env is None else env)
    try:
        process = popen_factory(
            list(command),
            cwd=str(cwd),
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            env=launch_env,
        )
    except Exception:
        log_handle.close()
        raise
    log_handle.close()
    return KillChainLaunchProcess(pid=int(process.pid))


def launch_response_payload(
    *,
    launch_status: str,
    engagement_id: int,
    operator: str,
    pid: int,
    log_path: Path,
    launch: KillChainLaunchSpec,
) -> dict[str, Any]:
    return {
        "status": launch_status,
        "engagement_id": engagement_id,
        "operator": operator,
        "pid": pid,
        "log_path": log_path.as_posix(),
        **launch.payload_fields(),
    }


def launch_progress_message(launch_status: str) -> str:
    return f"engagement_run_{launch_status}"


def launch_progress_payload(
    *,
    operator: str,
    pid: int,
    log_path: Path,
    launch: KillChainLaunchSpec,
) -> dict[str, Any]:
    return {
        "operator": operator,
        "pid": pid,
        "log_path": log_path.as_posix(),
        **launch.payload_fields(),
    }


def publish_launch_progress(
    publish_sync: Callable[[int, str, dict[str, Any]], None],
    *,
    engagement_id: int,
    launch_status: str,
    operator: str,
    pid: int,
    log_path: Path,
    launch: KillChainLaunchSpec,
) -> None:
    publish_sync(
        engagement_id,
        launch_progress_message(launch_status),
        launch_progress_payload(
            operator=operator,
            pid=pid,
            log_path=log_path,
            launch=launch,
        ),
    )


def launch_kill_chain_run_payload(
    *,
    con: sqlite3.Connection,
    engagement_id: int,
    operator: str,
    body: dict[str, Any] | None,
    force_resume: bool | None,
    launch_status: str,
    logs_root: Path,
    clear_control_markers: Callable[[int], None],
    open_launch_log: Callable[[Path, int], tuple[Path, TextIO]],
    publish_sync: Callable[[int, str, dict[str, Any]], None],
    env: Mapping[str, str],
    cwd: Path,
    popen_factory: Callable[..., Any] = subprocess.Popen,
) -> dict[str, Any]:
    if latest_running_engagement_run(con, engagement_id) is not None:
        raise KillChainLaunchConflict("An engagement run is already active.")
    seeds = ordered_launch_seeds(con, engagement_id)
    if not seeds:
        raise KillChainLaunchNoSeeds("Engagement has no launchable seeds.")

    launch = build_kill_chain_launch_spec(
        body,
        engagement_id=engagement_id,
        seeds=seeds,
        force_resume=force_resume,
        env=env,
    )
    clear_control_markers(engagement_id)
    log_path, log_handle = open_launch_log(logs_root, engagement_id)
    process = spawn_kill_chain_process(
        launch.command,
        log_handle=log_handle,
        cwd=cwd,
        env=dict(env),
        popen_factory=popen_factory,
    )
    payload = launch_response_payload(
        launch_status=launch_status,
        engagement_id=engagement_id,
        operator=operator,
        pid=process.pid,
        log_path=log_path,
        launch=launch,
    )
    publish_launch_progress(
        publish_sync,
        engagement_id=engagement_id,
        launch_status=launch_status,
        operator=operator,
        pid=process.pid,
        log_path=log_path,
        launch=launch,
    )
    return payload


__all__ = [
    "KillChainLaunchConflict",
    "KillChainLaunchNoSeeds",
    "KillChainLaunchOptionError",
    "KillChainLaunchOptions",
    "KillChainLaunchProcess",
    "KillChainLaunchSpec",
    "VALID_REPORT_PROVIDERS",
    "build_kill_chain_command",
    "build_kill_chain_launch_spec",
    "launch_seed_values",
    "launch_progress_message",
    "launch_progress_payload",
    "launch_response_payload",
    "launch_kill_chain_run_payload",
    "normalize_roe_id",
    "ordered_launch_seeds",
    "parse_kill_chain_launch_options",
    "parse_report_max_loops",
    "publish_launch_progress",
    "spawn_kill_chain_process",
]
