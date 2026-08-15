"""Web UI engagement log helpers."""
from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote


def logs_dir(data_dir: Path) -> Path:
    path = data_dir / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def engagement_log_files(logs_root: Path, engagement_id: int) -> list[Path]:
    return sorted(
        logs_root.glob(f"engagement_{engagement_id}_kill_chain_*.log"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )


def log_api_href(engagement_ref: str, log_name: str) -> str:
    return (
        f"/api/engagements/{quote(str(engagement_ref), safe='')}"
        f"/logs/{quote(str(log_name), safe='')}"
    )


def log_tail_api_href(engagement_ref: str, log_name: str) -> str:
    return f"{log_api_href(engagement_ref, log_name)}/tail"


def log_payload(
    engagement_ref: str,
    log_path: Path,
    *,
    format_size: Callable[[int], str],
    format_dt: Callable[[str], str],
) -> dict[str, Any]:
    stat = log_path.stat()
    modified_value = time.strftime(
        "%Y-%m-%dT%H:%M:%S",
        time.localtime(stat.st_mtime),
    )
    return {
        "name": log_path.name,
        "href": log_api_href(engagement_ref, log_path.name),
        "tail_api": log_tail_api_href(engagement_ref, log_path.name),
        "size_bytes": int(stat.st_size),
        "size_label": format_size(int(stat.st_size)),
        "modified_at": format_dt(modified_value),
    }


def resolve_log_file(logs_root: Path, engagement_id: int, log_name: str) -> Path | None:
    candidate = (logs_root / Path(log_name).name).resolve()
    resolved_root = logs_root.resolve()
    if not candidate.is_file() or resolved_root not in candidate.parents:
        return None
    expected_prefix = f"engagement_{engagement_id}_kill_chain_"
    if not candidate.name.startswith(expected_prefix):
        return None
    return candidate


def tail_lines(path: Path, max_lines: int) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:  # noqa: BLE001
        return ""
    return "\n".join(lines[-max_lines:])


def log_tail_payload(path: Path, requested_lines: int) -> dict[str, Any]:
    max_lines = min(max(requested_lines, 1), 1000)
    return {
        "name": path.name,
        "tail": tail_lines(path, max_lines),
        "requested_lines": max_lines,
    }


__all__ = [
    "engagement_log_files",
    "log_api_href",
    "log_payload",
    "log_tail_api_href",
    "log_tail_payload",
    "logs_dir",
    "resolve_log_file",
    "tail_lines",
]
