from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from forge.config import ForgeConfig
from forge.subprocess_tree import run_contained_subprocess

SELF_HEAL_PLAN_SCHEMA_VERSION = "forge.automation_self_heal_plan.v1"
GUARDED_AUTOSTART_SCHEMA_VERSION = "forge.automation_guarded_autostart.v1"

PACKAGED_GO_TOOLS: tuple[dict[str, Any], ...] = (
    {"name": "nuclei", "binary": "nuclei.exe", "size_bytes": 189070848, "role": "templates"},
    {"name": "gopls", "binary": "gopls.exe", "size_bytes": 43044352, "role": "developer"},
    {"name": "gitleaks", "binary": "gitleaks.exe", "size_bytes": 13897728, "role": "secrets"},
    {"name": "amass", "binary": "amass.exe", "size_bytes": 51906048, "role": "asset_discovery"},
    {"name": "ffuf", "binary": "ffuf.exe", "size_bytes": 14524928, "role": "active_content"},
    {"name": "gobuster", "binary": "gobuster.exe", "size_bytes": 14392320, "role": "active_content"},
    {"name": "mapcidr", "binary": "mapcidr.exe", "size_bytes": 40351744, "role": "scope_planning"},
    {"name": "tlsx", "binary": "tlsx.exe", "size_bytes": 41943552, "role": "tls_fingerprint"},
    {"name": "uncover", "binary": "uncover.exe", "size_bytes": 41236480, "role": "provider_search"},
    {"name": "naabu", "binary": "naabu.exe", "size_bytes": 46626304, "role": "active_ports"},
    {"name": "dnsx", "binary": "dnsx.exe", "size_bytes": 38878208, "role": "dns_enrichment"},
    {"name": "httpx", "binary": "httpx.exe", "size_bytes": 68553728, "role": "http_probe"},
    {"name": "katana", "binary": "katana.exe", "size_bytes": 63511040, "role": "crawler"},
    {"name": "subfinder", "binary": "subfinder.exe", "size_bytes": 39931392, "role": "subdomains"},
)

DEFAULT_AUTOSTART_CONFIG_PATH = Path("imports") / "autostart.local.json"
DEFAULT_AUTOSTART_CONFIG: dict[str, Any] = {
    "enabled": False,
    "apply_enabled": False,
    "roe_id_env": "FORGE_ROE_ID",
    "min_free_memory_mb": 2048,
    "min_free_disk_gb": 5,
    "resume_limit": 10,
    "max_parallel": 2,
    "monitor_limit": 10,
    "start_limit": 2,
    "max_runtime_minutes": 10,
    "cooldown_minutes": 60,
    "failure_backoff_minutes": 120,
    "log_max_entries": 25,
}


def automation_self_heal_plan(
    *,
    repo_root: Path | None = None,
    data_dir: Path | None = None,
    min_free_memory_mb: int = 2048,
    min_free_disk_gb: int = 5,
    max_parallel: int = 2,
    probe_docker: bool = False,
) -> dict[str, Any]:
    root = Path(repo_root or Path.cwd())
    cfg_data_dir = data_dir or ForgeConfig.load().data_dir
    resource_status = _resource_status(
        root=root,
        min_free_memory_mb=min_free_memory_mb,
        min_free_disk_gb=min_free_disk_gb,
    )
    tool_rows = _packaged_tool_status(root)
    docker_status = _docker_status(root, probe=probe_docker)
    feed_file = root / "imports" / "target-feed.json"
    lock_file = Path(cfg_data_dir) / "target_imports" / "resume_batches" / "resume-run.lock"
    blockers = _blockers(
        resource_status=resource_status,
        tool_rows=tool_rows,
        docker_status=docker_status,
    )
    commands = {
        "review_readiness": ["forge", "automation", "self-heal-plan", "--json"],
        "feed_build_dry_run": ["forge", "automation", "feed-build", "--json"],
        "autopilot_dry_run": [
            "forge-autopilot.bat" if os.name == "nt" else "./forge-autopilot.sh",
            "--dry-run",
            "--feed-build",
            "--resume-limit",
            "10",
            "--max-parallel",
            str(max(1, min(int(max_parallel or 1), 4))),
            "--monitor-limit",
            "10",
        ],
        "autopilot_apply": [
            "forge-autopilot.bat" if os.name == "nt" else "./forge-autopilot.sh",
            "--feed-file",
            str(feed_file),
            "--roe-id",
            "ROE-ID",
            "--resume-limit",
            "10",
            "--max-parallel",
            str(max(1, min(int(max_parallel or 1), 4))),
            "--monitor-limit",
            "10",
        ],
        "docker_status": [
            "docker",
            "compose",
            "-f",
            str(root / "docker" / "docker-compose.dev.yml"),
            "ps",
            "--format",
            "json",
        ],
    }
    startup_policy = {
        "default_mode": "observe_or_dry_run",
        "apply_requires": [
            "explicit local operator config",
            "ROE ID",
            "target feed present or feed-build sources available",
            "resource guardrails passing",
            "single-instance lock available",
        ],
        "guardrails": [
            "skip live child work below memory threshold",
            "skip live child work below disk threshold",
            "cap resume parallelism at 4 and recommend 2 on small hosts",
            "back off after failures instead of retrying continuously",
            "probe Docker health before scheduled autopilot work",
        ],
    }
    total_checks = 4 + len(tool_rows)
    selected_checks = sum(1 for row in tool_rows if row["available"]) + sum(
        1
        for check in (
            resource_status["memory"]["ok"],
            resource_status["disk"]["ok"],
            docker_status["ok"],
            not lock_file.exists(),
        )
        if check
    )
    return {
        "schema_version": SELF_HEAL_PLAN_SCHEMA_VERSION,
        "execution_policy": "plan_only_no_autostart_or_live_commands_executed",
        "total_count": total_checks,
        "selected_count": selected_checks,
        "omitted_count": total_checks - selected_checks,
        "status": "ready" if not blockers else "blocked",
        "blockers": blockers,
        "resource_status": resource_status,
        "docker_status": docker_status,
        "packaged_go_tools": tool_rows,
        "paths": {
            "repo_root": str(root),
            "data_dir": str(cfg_data_dir),
            "feed_file": str(feed_file),
            "resume_lock": str(lock_file),
        },
        "startup_policy": startup_policy,
        "commands": commands,
    }


def run_guarded_autostart(
    *,
    config_path: Path | None = None,
    repo_root: Path | None = None,
    data_dir: Path | None = None,
    apply: bool = False,
    command_runner: Any | None = None,
) -> dict[str, Any]:
    root = Path(repo_root or Path.cwd())
    cfg_data_dir = data_dir or ForgeConfig.load().data_dir
    selected_config_path = Path(config_path or DEFAULT_AUTOSTART_CONFIG_PATH)
    config, config_errors = _load_autostart_config(selected_config_path)
    state_dir = Path(cfg_data_dir) / "automation"
    state_file = state_dir / "guarded-autostart-state.json"
    log_file = state_dir / "guarded-autostart.jsonl"
    lock_file = state_dir / "guarded-autostart.lock"
    now = datetime.now(timezone.utc)
    state = _read_json_object(state_file)
    lock_status = _guarded_autostart_lock_status(lock_file, now=now)
    cooldown_blockers = _cooldown_blockers(
        state=state,
        now=now,
        cooldown_minutes=int(config["cooldown_minutes"]),
        failure_backoff_minutes=int(config["failure_backoff_minutes"]),
    )
    self_heal = automation_self_heal_plan(
        repo_root=root,
        data_dir=cfg_data_dir,
        min_free_memory_mb=int(config["min_free_memory_mb"]),
        min_free_disk_gb=int(config["min_free_disk_gb"]),
        max_parallel=int(config["max_parallel"]),
        probe_docker=True,
    )
    mode = "apply" if apply else "dry_run"
    blockers: list[str] = []
    if config_errors:
        blockers.extend(config_errors)
    if not bool(config["enabled"]):
        blockers.append("autostart_config_disabled")
    if apply and not bool(config["apply_enabled"]):
        blockers.append("apply_requested_but_config_apply_disabled")
    if (
        apply
        and bool(config["apply_enabled"])
        and not os.environ.get(str(config["roe_id_env"]), "").strip()
    ):
        blockers.append("roe_id_env_missing")
    if lock_status["exists"]:
        if apply and lock_status["breakable"]:
            try:
                lock_file.unlink()
            except OSError:
                blockers.append("guarded_autostart_stale_lock_unlink_failed")
        else:
            blockers.append("guarded_autostart_lock_exists")
    blockers.extend(cooldown_blockers)
    blockers.extend(str(item) for item in self_heal["blockers"])
    commands = _guarded_autostart_commands(root=root, config=config)
    sensitive_values = _autostart_sensitive_values(config)
    result: dict[str, Any] = {
        "schema_version": GUARDED_AUTOSTART_SCHEMA_VERSION,
        "execution_policy": (
            "guarded_apply_may_run_autopilot_when_ready"
            if apply
            else "dry_run_no_autostart_or_live_commands_executed"
        ),
        "mode": mode,
        "config_path": str(selected_config_path),
        "state_file": str(state_file),
        "log_file": str(log_file),
        "lock_file": str(lock_file),
        "lock_status": lock_status,
        "config": _redacted_autostart_config(config),
        "self_heal": self_heal,
        "commands": commands,
        "blockers": blockers,
        "status": "blocked" if blockers else "ready",
        "runs": [],
        "total_count": len(commands),
        "selected_count": 0,
        "omitted_count": len(commands),
    }
    if blockers or not apply:
        if apply:
            _append_autostart_log(
                log_file,
                result,
                max_entries=int(config["log_max_entries"]),
                redactions=sensitive_values,
            )
        return result

    state_dir.mkdir(parents=True, exist_ok=True)
    try:
        _write_lock(lock_file, now)
    except FileExistsError:
        result["blockers"].append("guarded_autostart_lock_exists")
        result["status"] = "blocked"
        _append_autostart_log(
            log_file,
            result,
            max_entries=int(config["log_max_entries"]),
            redactions=sensitive_values,
        )
        return result
    try:
        timeout_seconds = int(config["max_runtime_minutes"]) * 60 + 120
        if command_runner is None:
            runner = lambda command, cwd: _run_command_with_options(
                command,
                cwd,
                timeout_seconds=timeout_seconds,
                redactions=sensitive_values,
            )
        else:
            runner = command_runner
        rehearsal = runner(_execution_command(commands["autopilot_dry_run"], config), root)
        result["runs"].append({"id": "autopilot_dry_run", **rehearsal})
        if rehearsal["returncode"] != 0:
            result["status"] = "failed"
            _write_autostart_state(
                state_file,
                {"last_failed_at": _iso(now), "last_status": "dry_run_failed"},
            )
            return result
        live = runner(_execution_command(commands["autopilot_apply"], config), root)
        result["runs"].append({"id": "autopilot_apply", **live})
        result["status"] = "completed" if live["returncode"] == 0 else "failed"
        _write_autostart_state(
            state_file,
            {
                "last_started_at": _iso(now),
                "last_status": result["status"],
                "last_returncode": live["returncode"],
                "last_failed_at": _iso(now) if live["returncode"] != 0 else "",
            },
        )
        result["selected_count"] = len(result["runs"])
        result["omitted_count"] = max(0, len(commands) - len(result["runs"]))
        _append_autostart_log(
            log_file,
            result,
            max_entries=int(config["log_max_entries"]),
            redactions=sensitive_values,
        )
        return result
    finally:
        try:
            lock_file.unlink()
        except FileNotFoundError:
            pass


def _load_autostart_config(config_path: Path) -> tuple[dict[str, Any], list[str]]:
    config = dict(DEFAULT_AUTOSTART_CONFIG)
    if not config_path.is_file():
        return config, ["autostart_config_missing"]
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return config, [f"autostart_config_unreadable:{type(exc).__name__}"]
    if not isinstance(payload, dict):
        return config, ["autostart_config_invalid:not_object"]
    for key in DEFAULT_AUTOSTART_CONFIG:
        if key in payload:
            config[key] = payload[key]
    errors = _validate_autostart_config(config)
    return config, errors


def _validate_autostart_config(config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    numeric_ranges = {
        "min_free_memory_mb": (128, 1048576),
        "min_free_disk_gb": (1, 1024),
        "resume_limit": (0, 100),
        "max_parallel": (1, 4),
        "monitor_limit": (0, 100),
        "start_limit": (0, 20),
        "max_runtime_minutes": (1, 60),
        "cooldown_minutes": (0, 1440),
        "failure_backoff_minutes": (0, 2880),
        "log_max_entries": (1, 500),
    }
    for key, (minimum, maximum) in numeric_ranges.items():
        try:
            value = int(config[key])
        except (TypeError, ValueError):
            errors.append(f"autostart_config_invalid:{key}")
            continue
        if value < minimum or value > maximum:
            errors.append(f"autostart_config_out_of_range:{key}")
        config[key] = max(minimum, min(maximum, value))
    for key in ("enabled", "apply_enabled"):
        if not isinstance(config[key], bool):
            errors.append(f"autostart_config_invalid_bool:{key}")
            config[key] = False
    config["roe_id_env"] = str(config.get("roe_id_env") or "FORGE_ROE_ID").strip()
    if not config["roe_id_env"]:
        errors.append("autostart_config_invalid:roe_id_env")
    return errors


def _guarded_autostart_commands(root: Path, config: dict[str, Any]) -> dict[str, list[str]]:
    launcher = "forge-autopilot.bat" if os.name == "nt" else "./forge-autopilot.sh"
    base = [
        launcher,
        "--feed-build",
        "--resume-limit",
        str(config["resume_limit"]),
        "--max-parallel",
        str(config["max_parallel"]),
        "--monitor-limit",
        str(config["monitor_limit"]),
        "--start-limit",
        str(config["start_limit"]),
        "--max-runtime-minutes",
        str(config["max_runtime_minutes"]),
    ]
    apply_cmd = [*base, "--feed-file", str(root / "imports" / "target-feed.json")]
    apply_cmd.extend(["--roe-id", f"${config['roe_id_env']}"])
    return {
        "self_heal_probe": ["forge", "automation", "self-heal-plan", "--json", "--probe-docker"],
        "autopilot_dry_run": [*base, "--dry-run"],
        "autopilot_apply": apply_cmd,
    }


def _redacted_autostart_config(config: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(config)
    redacted["roe_id_env"] = str(config.get("roe_id_env") or "")
    redacted["roe_id_present"] = bool(os.environ.get(redacted["roe_id_env"], "").strip())
    return redacted


def _execution_command(command: list[str], config: dict[str, Any]) -> list[str]:
    resolved = list(command)
    placeholder = f"${config['roe_id_env']}"
    for index, value in enumerate(resolved):
        if value == placeholder:
            resolved[index] = os.environ.get(str(config["roe_id_env"]), "").strip()
    return resolved


def _autostart_sensitive_values(config: dict[str, Any]) -> tuple[str, ...]:
    values = []
    roe_value = os.environ.get(str(config.get("roe_id_env") or ""), "").strip()
    if roe_value:
        values.append(roe_value)
    for key, value in os.environ.items():
        lowered = key.lower()
        if any(marker in lowered for marker in ("key", "secret", "token", "password", "credential")):
            clean = str(value or "").strip()
            if clean:
                values.append(clean)
    return tuple(dict.fromkeys(values))


def _redact_command_text(value: str, redactions: tuple[str, ...]) -> str:
    text = str(value or "")
    for secret in redactions:
        if secret and len(secret) >= 4:
            text = text.replace(secret, "[REDACTED]")
    patterns = (
        re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"),
        re.compile(r"\bsk-or-v1-[A-Za-z0-9_\-]{16,}"),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"\bASIA[0-9A-Z]{16}\b"),
        re.compile(r"\beyJ[A-Za-z0-9_\-=]{10,}"),
        re.compile(r"\bghp_[A-Za-z0-9]{20,}"),
        re.compile(r"\bgho_[A-Za-z0-9]{20,}"),
        re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}"),
        re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
    )
    for pattern in patterns:
        text = pattern.sub("[REDACTED]", text)
    return text


def _cooldown_blockers(
    *,
    state: dict[str, Any],
    now: datetime,
    cooldown_minutes: int,
    failure_backoff_minutes: int,
) -> list[str]:
    blockers: list[str] = []
    last_started = _parse_iso(str(state.get("last_started_at") or ""))
    if last_started and now - last_started < timedelta(minutes=cooldown_minutes):
        blockers.append("cooldown_active")
    last_failed = _parse_iso(str(state.get("last_failed_at") or ""))
    if last_failed and now - last_failed < timedelta(minutes=failure_backoff_minutes):
        blockers.append("failure_backoff_active")
    return blockers


def _parse_iso(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_autostart_state(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".autostart-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _append_autostart_log(
    path: Path,
    result: dict[str, Any],
    *,
    max_entries: int,
    redactions: tuple[str, ...],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                parsed = json.loads(line)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                entries.append(parsed)
    except OSError:
        entries = []
    entries.append(_autostart_log_entry(result, redactions=redactions))
    entries = entries[-max(1, int(max_entries)) :]
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".guarded-autostart-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for entry in entries:
                handle.write(json.dumps(entry, sort_keys=True))
                handle.write("\n")
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _autostart_log_entry(result: dict[str, Any], *, redactions: tuple[str, ...]) -> dict[str, Any]:
    runs = []
    for run in result.get("runs") or []:
        if not isinstance(run, dict):
            continue
        runs.append(
            {
                "id": str(run.get("id") or ""),
                "returncode": run.get("returncode"),
                "stdout_tail": _bounded_log_text(run.get("stdout_tail"), redactions=redactions),
                "stderr_tail": _bounded_log_text(run.get("stderr_tail"), redactions=redactions),
            }
        )
    return {
        "schema_version": "forge.automation_guarded_autostart_log.v1",
        "recorded_at": _iso(datetime.now(timezone.utc)),
        "mode": str(result.get("mode") or ""),
        "status": str(result.get("status") or ""),
        "blockers": [str(item) for item in (result.get("blockers") or [])[:25]],
        "runs": runs[:5],
        "selected_count": int(result.get("selected_count") or 0),
        "omitted_count": int(result.get("omitted_count") or 0),
    }


def _bounded_log_text(value: object, *, redactions: tuple[str, ...]) -> str:
    return _redact_command_text(str(value or ""), redactions)[-1000:]


def _write_lock(path: Path, now: datetime) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    fd = os.open(path, flags)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump({"pid": os.getpid(), "created_at": _iso(now)}, handle)
        handle.write("\n")


def _guarded_autostart_lock_status(lock_path: Path, *, now: datetime) -> dict[str, Any]:
    stale_minutes = int(DEFAULT_AUTOSTART_CONFIG["failure_backoff_minutes"])
    if not lock_path.exists():
        return {
            "exists": False,
            "breakable": False,
            "stale": False,
            "reason": "lock_missing",
            "pid": None,
            "pid_alive": None,
            "age_seconds": None,
            "stale_lock_minutes": stale_minutes,
            "metadata": {},
        }
    metadata = _read_json_object(lock_path)
    pid = _safe_int(metadata.get("pid"))
    pid_alive = _pid_alive(pid) if pid > 0 else None
    created_at = str(metadata.get("created_at") or "").strip()
    age_seconds = _lock_age_seconds(lock_path, created_at=created_at, now=now)
    stale_by_dead_pid = pid > 0 and pid_alive is False
    stale_by_age = (
        pid_alive is not True
        and age_seconds is not None
        and age_seconds >= stale_minutes * 60
    )
    stale = bool(stale_by_dead_pid or stale_by_age)
    reason = "active_lock"
    if stale_by_dead_pid:
        reason = "dead_pid"
    elif stale_by_age:
        reason = "stale_age"
    elif not metadata:
        reason = "unparsed_lock"
    public_metadata: dict[str, Any] = {}
    for key in ("pid", "created_at"):
        if key in metadata:
            public_metadata[key] = metadata[key]
    return {
        "exists": True,
        "breakable": stale,
        "stale": stale,
        "reason": reason,
        "pid": pid or None,
        "pid_alive": pid_alive,
        "age_seconds": age_seconds,
        "stale_lock_minutes": stale_minutes,
        "metadata": public_metadata,
    }


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _lock_age_seconds(lock_path: Path, *, created_at: str, now: datetime) -> float | None:
    created_epoch = _iso_epoch_seconds(created_at)
    if created_epoch is None:
        try:
            created_epoch = lock_path.stat().st_mtime
        except OSError:
            return None
    return max(0.0, now.timestamp() - created_epoch)


def _iso_epoch_seconds(value: str) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        return _windows_pid_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _windows_pid_alive(pid: int) -> bool:
    try:
        import ctypes
    except ImportError:  # pragma: no cover - ctypes is part of CPython on Windows.
        return True

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    process_query_limited_information = 0x1000
    handle = kernel32.OpenProcess(process_query_limited_information, False, int(pid))
    if handle:
        kernel32.CloseHandle(handle)
        return True
    error = ctypes.get_last_error()
    if error == 87:  # ERROR_INVALID_PARAMETER: no such process.
        return False
    return True


def _run_command(command: list[str], cwd: Path) -> dict[str, Any]:
    return _run_command_with_options(command, cwd, timeout_seconds=1800, redactions=())


def _run_command_with_options(
    command: list[str],
    cwd: Path,
    *,
    timeout_seconds: int,
    redactions: tuple[str, ...],
) -> dict[str, Any]:
    try:
        completed = run_contained_subprocess(
            command,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            timeout_stderr=f"guarded autostart child exceeded timeout_seconds={timeout_seconds}",
        )
    except OSError as exc:
        return {"returncode": 124, "error": type(exc).__name__}
    return {
        "returncode": completed.returncode,
        "stdout_tail": _redact_command_text(str(completed.stdout or "")[-2000:], redactions),
        "stderr_tail": _redact_command_text(str(completed.stderr or "")[-2000:], redactions),
    }


def _resource_status(
    *,
    root: Path,
    min_free_memory_mb: int,
    min_free_disk_gb: int,
) -> dict[str, Any]:
    free_memory_mb = _free_memory_mb()
    disk = shutil.disk_usage(root)
    free_disk_gb = disk.free / (1024**3)
    return {
        "memory": {
            "free_mb": free_memory_mb,
            "minimum_mb": int(min_free_memory_mb),
            "ok": free_memory_mb is not None and free_memory_mb >= int(min_free_memory_mb),
        },
        "disk": {
            "free_gb": round(free_disk_gb, 2),
            "minimum_gb": int(min_free_disk_gb),
            "ok": free_disk_gb >= int(min_free_disk_gb),
        },
        "cpu": {
            "logical_cores": os.cpu_count() or 1,
            "recommended_max_parallel": max(1, min((os.cpu_count() or 1) // 2 or 1, 4)),
        },
    }


def _free_memory_mb() -> int | None:
    if os.name == "nt":
        try:
            import ctypes

            class _MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            status = _MemoryStatus()
            status.dwLength = ctypes.sizeof(_MemoryStatus)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.ullAvailPhys / (1024 * 1024))
        except Exception:
            return None
    if hasattr(os, "sysconf"):
        try:
            pages = os.sysconf("SC_AVPHYS_PAGES")
            page_size = os.sysconf("SC_PAGE_SIZE")
            return int((int(pages) * int(page_size)) / (1024 * 1024))
        except (OSError, ValueError, TypeError):
            return None
    return None


def _packaged_tool_status(root: Path) -> list[dict[str, Any]]:
    search_roots = _tool_search_roots(root)
    rows: list[dict[str, Any]] = []
    for tool in PACKAGED_GO_TOOLS:
        path = _find_tool_path(tool["binary"], search_roots)
        actual_size = path.stat().st_size if path and path.is_file() else None
        rows.append(
            {
                "name": tool["name"],
                "binary": tool["binary"],
                "role": tool["role"],
                "expected_size_bytes": tool["size_bytes"],
                "path": str(path) if path else "",
                "available": path is not None,
                "size_matches_hint": actual_size in {None, int(tool["size_bytes"])},
                "actual_size_bytes": actual_size,
            }
        )
    return rows


def _tool_search_roots(root: Path) -> list[Path]:
    roots = [
        root / "tools" / "bin",
        root / "bin",
        root / ".forge_data" / "tools" / "bin",
        Path.home() / "go" / "bin",
    ]
    for env_name in ("FORGE_CONNECTOR_BIN_DIRS", "FORGE_CONNECTOR_BIN_DIR"):
        for value in str(os.environ.get(env_name, "")).split(os.pathsep):
            if value.strip():
                roots.append(Path(value.strip()))
    return roots


def _find_tool_path(binary: str, roots: list[Path]) -> Path | None:
    for root in roots:
        candidate = root / binary
        if candidate.is_file():
            return candidate
        non_windows = root / binary.removesuffix(".exe")
        if non_windows.is_file():
            return non_windows
    found = shutil.which(binary) or shutil.which(binary.removesuffix(".exe"))
    return Path(found) if found else None


def _docker_status(root: Path, *, probe: bool) -> dict[str, Any]:
    compose_file = root / "docker" / "docker-compose.dev.yml"
    if not compose_file.is_file():
        return {"ok": False, "probed": False, "reason": "compose_file_missing"}
    if not probe:
        return {
            "ok": True,
            "probed": False,
            "reason": "compose_file_present_probe_skipped",
        }
    try:
        completed = subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "ps", "--format", "json"],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "probed": True, "reason": type(exc).__name__}
    containers = _docker_ps_containers(completed.stdout)
    unhealthy = [
        row
        for row in containers
        if str(row.get("health") or "").lower() in {"unhealthy", "starting"}
        or str(row.get("state") or "").lower() in {"exited", "dead", "paused"}
    ]
    ok = completed.returncode == 0 and not unhealthy
    if completed.returncode != 0:
        reason = "docker_compose_ps_failed"
    elif unhealthy:
        reason = "docker_compose_unhealthy"
    else:
        reason = "docker_compose_ps_ok"
    return {
        "ok": ok,
        "probed": True,
        "returncode": completed.returncode,
        "reason": reason,
        "container_count": len(containers),
        "unhealthy_count": len(unhealthy),
        "containers": containers[:25],
    }


def _docker_ps_containers(stdout: str) -> list[dict[str, Any]]:
    text = str(stdout or "").strip()
    if not text:
        return []
    parsed_rows: list[Any] = []
    try:
        payload = json.loads(text)
        parsed_rows = payload if isinstance(payload, list) else [payload]
    except ValueError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed_rows.append(json.loads(line))
            except ValueError:
                continue
    containers: list[dict[str, Any]] = []
    for row in parsed_rows:
        if not isinstance(row, dict):
            continue
        name = row.get("Name") or row.get("name")
        service = row.get("Service") or row.get("service")
        state = row.get("State") or row.get("state")
        health = row.get("Health") or row.get("health")
        exit_code = row.get("ExitCode") or row.get("exit_code")
        containers.append(
            {
                "name": _bounded_docker_text(name, 120),
                "service": _bounded_docker_text(service, 80),
                "state": _bounded_docker_text(state, 40),
                "health": _bounded_docker_text(health, 40),
                "exit_code": _bounded_docker_text(exit_code, 20),
            }
        )
    return containers


def _bounded_docker_text(value: object, limit: int) -> str:
    return " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())[:limit]


def _blockers(
    *,
    resource_status: dict[str, Any],
    tool_rows: list[dict[str, Any]],
    docker_status: dict[str, Any],
) -> list[str]:
    blockers: list[str] = []
    if not resource_status["memory"]["ok"]:
        blockers.append("free_memory_below_threshold")
    if not resource_status["disk"]["ok"]:
        blockers.append("free_disk_below_threshold")
    if not docker_status["ok"]:
        blockers.append(str(docker_status["reason"]))
    missing_runtime = [
        row["name"]
        for row in tool_rows
        if not row["available"] and row["role"] != "developer"
    ]
    if missing_runtime:
        blockers.append("missing_packaged_runtime_tools:" + ",".join(missing_runtime))
    mismatched_runtime = [
        row["name"]
        for row in tool_rows
        if row["available"] and not row["size_matches_hint"] and row["role"] != "developer"
    ]
    if mismatched_runtime:
        blockers.append("packaged_runtime_tool_size_mismatch:" + ",".join(mismatched_runtime))
    return blockers
