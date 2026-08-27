from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from forge.config import ForgeConfig

SELF_HEAL_PLAN_SCHEMA_VERSION = "forge.automation_self_heal_plan.v1"

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
            "ok": free_memory_mb is None or free_memory_mb >= int(min_free_memory_mb),
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
            ["docker", "compose", "-f", str(compose_file), "ps"],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "probed": True, "reason": type(exc).__name__}
    return {
        "ok": completed.returncode == 0,
        "probed": True,
        "returncode": completed.returncode,
        "reason": "docker_compose_ps_ok" if completed.returncode == 0 else "docker_compose_ps_failed",
    }


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
