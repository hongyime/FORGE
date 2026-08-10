"""
forge/audit/logger.py - Append-only audit logger with secret redaction
and JSONL persistence.

Provides the AuditLogger class that records platform events to:
  1. An in-memory list (hot cache for read-back during the same process).
  2. (When configured) a JSONL append-only file persisted to disk.

Hardening (2026-05-26):
  * P0-3 - Added optional JSONL append-only file sink. When
    ``FORGE_AUDIT_LOG_PATH`` is set or ``log_path=`` is passed to the
    constructor, every entry is serialised to that file with fsync per
    write so the audit trail survives process crash.
  * P1-3 - ``redact_secrets`` now recurses into lists, tuples, and
    JSON-encoded string values; also detects high-entropy bearer-token
    patterns (sk-, AKIA, eyJ, ghp_, gho_) by VALUE.
  * P0-3 - Added ``close()`` method that flushes and closes the file
    handle.
  * P0-3 - Added classmethod ``from_env()`` that builds a logger
    configured from PlatformSettings.

Requirements: 7.1, 7.2, 7.3
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import IO, Any

from forge.audit.models import AuditEntry

__all__ = ["AuditLogger"]

_LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Value-pattern redaction (P1-3 hardening)
# ---------------------------------------------------------------------------

#: Compiled regexes that identify common secret-shape values regardless of
#: the dict key they live under. Each pattern matches the *whole* value;
#: partial matches are intentional (e.g. an Authorization header value
#: containing "Bearer eyJ..." still matches).
_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk-[A-Za-z0-9]{20,}"),  # OpenAI
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),  # AWS session key
    re.compile(r"\beyJ[A-Za-z0-9_\-=]{10,}"),  # JWT prefix (base64-encoded {)
    re.compile(r"\bghp_[A-Za-z0-9]{20,}"),  # GitHub PAT
    re.compile(r"\bgho_[A-Za-z0-9]{20,}"),  # GitHub OAuth
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}"),  # GitLab PAT
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),  # PEM
)


class AuditLogger:
    """Append-only audit log with optional JSONL file persistence.

    The logger appends every :class:`AuditEntry` to an internal list and,
    when configured with a ``log_path``, also writes a JSONL line to that
    file with ``fsync`` per write so the trail survives process crash.

    The internal list is a hot cache only - operators must rely on the
    file (or a downstream syslog/OTel sink) for evidence-grade persistence.

    Args:
        log_path: Optional path to a JSONL file. When ``None`` the logger
            is in-memory only. Parent directories are created on demand.
        fsync_per_write: When ``True`` (default), call ``os.fsync`` after
            every write. Set ``False`` for performance-sensitive tests
            where durability is not required.
    """

    # Secret-key-name patterns (case-insensitive) for redact_secrets.
    _REDACT_KEY_PATTERNS: list[str] = [
        "password",
        "secret",
        "token",
        "key",
        "credential",
        "api_key",
        "authorization",
        "cookie",
    ]

    def __init__(
        self,
        log_path: str | os.PathLike[str] | None = None,
        *,
        fsync_per_write: bool = True,
        hash_chain: bool = True,
        max_bytes: int | None = None,
        backup_count: int = 5,
    ) -> None:
        self._entries: list[AuditEntry] = []
        self._log_path: Path | None = None
        self._fh: IO[str] | None = None
        self._fsync = fsync_per_write
        self._lock = asyncio.Lock()
        self._hash_chain_enabled: bool = hash_chain
        self._prev_hash: str = "0" * 64  # genesis
        # B1: rotation. ``max_bytes=None`` disables rotation (default).
        # When set, rolls log_path -> log_path.1 -> log_path.2 ... up to
        # ``backup_count`` files, deleting the oldest. Each rotated file is
        # a self-contained hash chain (we reset _prev_hash to genesis when
        # opening a new file) so verification still works per-file.
        if max_bytes is not None and max_bytes <= 0:
            raise ValueError("max_bytes must be positive when set")
        self._max_bytes: int | None = max_bytes
        self._backup_count: int = max(0, int(backup_count))
        self._bytes_written: int = 0
        if log_path is not None:
            self._open_log(Path(log_path))

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> "AuditLogger":
        """Build a logger using ``PlatformSettings.audit_log_path``.

        Falls back to ``${FORGE_DATA_DIR or ~/.forge/data}/audit.jsonl``
        when the explicit setting is unset. Set
        ``FORGE_AUDIT_LOG_DISABLE=1`` to force in-memory-only mode.
        """
        if os.environ.get("FORGE_AUDIT_LOG_DISABLE", "0").strip() == "1":
            return cls(log_path=None)

        # Lazy import - PlatformSettings depends on pydantic-settings; the
        # logger module must remain importable in environments without it
        # (e.g. tooling that only needs AuditEntry).
        try:
            from forge.config import PlatformSettings  # noqa: PLC0415

            settings = PlatformSettings()
            log_path_str = getattr(settings, "audit_log_path", "") or ""
        except Exception:
            log_path_str = ""

        if log_path_str:
            return cls(log_path=log_path_str)

        # Default: ~/.forge/data/audit.jsonl
        data_dir = Path(
            os.environ.get("FORGE_DATA_DIR", str(Path.home() / ".forge" / "data"))
        ).expanduser()
        return cls(log_path=data_dir / "audit.jsonl")

    def _open_log(self, log_path: Path) -> None:
        """Open the JSONL log file for append, creating parents as needed."""
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log_path = log_path
        # Line buffering so each entry is flushed at newline boundaries
        # even before the explicit fsync. encoding="utf-8" makes the file
        # portable across platforms.
        self._fh = open(log_path, "a", encoding="utf-8", buffering=1)
        # Track current file size for rotation. Existing files contribute
        # their on-disk size; fresh files start at 0.
        try:
            self._bytes_written = log_path.stat().st_size
        except OSError:
            self._bytes_written = 0
        _LOG.info("AuditLogger: appending to %s", log_path)

    def _rotate(self) -> None:
        """Roll log_path -> log_path.1 -> log_path.2 ... up to backup_count.

        Each rotated file is a self-contained hash chain - we reset
        ``_prev_hash`` to the genesis value so the new file starts fresh.
        Verification therefore runs per-file rather than across rotations.
        Tradeoff: a rolled-over chain doesn't span boundaries, but log
        files stay bounded which is the operational requirement.
        """
        if self._log_path is None:
            return
        # Close current handle.
        if self._fh is not None:
            try:
                self._fh.flush()
                self._fh.close()
            except OSError:
                pass
            self._fh = None
        # Roll: log_path.(N-1) -> log_path.N, ... log_path -> log_path.1
        for i in range(self._backup_count, 0, -1):
            src = (
                self._log_path
                if i == 1
                else self._log_path.with_suffix(self._log_path.suffix + f".{i - 1}")
            )
            dst = self._log_path.with_suffix(self._log_path.suffix + f".{i}")
            if src.exists():
                if dst.exists():
                    try:
                        dst.unlink()
                    except OSError:
                        pass
                try:
                    src.rename(dst)
                except OSError as exc:  # pragma: no cover - best-effort
                    _LOG.warning("AuditLogger: rotation rename failed: %s", exc)
        # Reopen fresh log file.
        self._fh = open(self._log_path, "a", encoding="utf-8", buffering=1)
        self._bytes_written = 0
        # Reset the hash chain genesis for the new file.
        self._prev_hash = "0" * 64
        _LOG.info("AuditLogger: rotated %s", self._log_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def log_path(self) -> Path | None:
        """Return the configured JSONL file path, or ``None`` if in-memory."""
        return self._log_path

    @property
    def entries(self) -> list[AuditEntry]:
        """Read-only access to the in-memory hot cache."""
        return list(self._entries)

    async def log(self, entry: AuditEntry) -> None:
        """Append entry to the in-memory cache AND the JSONL file (if any).

        The redaction pass runs before persistence, so secrets never reach
        disk in cleartext.
        """
        if entry.input_params is not None:
            entry = entry.model_copy(
                update={"input_params": self.redact_secrets(entry.input_params)}
            )

        async with self._lock:
            self._entries.append(entry)
            if self._fh is not None:
                try:
                    # B1: estimate line size and rotate BEFORE computing the
                    # hash, so the rotated-into-new-file entry uses the
                    # fresh genesis prev_hash. Without this, the new file's
                    # first line carries a prev_hash from the old chain,
                    # making per-file verification fail.
                    if self._max_bytes is not None and self._bytes_written > 0:
                        # Rough byte estimate of the line we're about to
                        # write. Slight over-estimate is fine; we never
                        # under-rotate.
                        approx = len(entry.model_dump_json().encode("utf-8")) + 200
                        if self._bytes_written + approx > self._max_bytes:
                            self._rotate()
                    if self._hash_chain_enabled:
                        entry_json = entry.model_dump_json()
                        chained = (self._prev_hash + entry_json).encode("utf-8")
                        entry_hash = hashlib.sha256(chained).hexdigest()
                        wrapper = {
                            "entry": json.loads(entry_json),
                            "prev_hash": self._prev_hash,
                            "entry_hash": entry_hash,
                        }
                        line = json.dumps(wrapper, separators=(",", ":"))
                        self._prev_hash = entry_hash
                    else:
                        line = entry.model_dump_json()
                    line_bytes = len(line.encode("utf-8")) + 1
                    self._fh.write(line + "\n")
                    self._bytes_written += line_bytes
                    if self._fsync:
                        # The file handle's underlying fd; fsync forces
                        # the kernel to commit to disk so a power-loss
                        # within microseconds of return cannot lose the
                        # entry.
                        self._fh.flush()
                        os.fsync(self._fh.fileno())
                except Exception:  # noqa: BLE001 - log once, never crash audit
                    _LOG.exception(
                        "AuditLogger: failed to persist entry to %s",
                        self._log_path,
                    )

        _LOG.debug(
            "audit: %s correlation=%s agent=%s tool=%s seq=%d",
            entry.event_type.value,
            entry.correlation_id,
            entry.agent_role,
            entry.tool_name,
            entry.sequence_number,
        )

    async def close(self) -> None:
        """Flush and close the JSONL file handle (if any)."""
        async with self._lock:
            if self._fh is not None:
                try:
                    self._fh.flush()
                    if self._fsync:
                        try:
                            os.fsync(self._fh.fileno())
                        except OSError:
                            pass
                    self._fh.close()
                except Exception:  # noqa: BLE001 - best-effort cleanup
                    _LOG.debug("AuditLogger: error closing log file", exc_info=True)
                finally:
                    self._fh = None

    # ------------------------------------------------------------------
    # Redaction
    # ------------------------------------------------------------------

    def redact_secrets(self, params: object) -> Any:
        """Recursively redact secrets from a parameter tree.

        Handles dicts, lists, tuples, and JSON-encoded string values. The
        same redaction rules apply at every depth:

        - Dict KEY matches one of ``_REDACT_KEY_PATTERNS`` -> value -> "[REDACTED]"
        - String VALUE matches any ``_VALUE_PATTERNS`` -> value -> "[REDACTED]"
        - String VALUE that parses as JSON -> recurse into the parsed form,
          re-serialise the redacted result back into a string.
        - Tuples are coerced to lists (JSON has no tuple type) - this is
          a one-way conversion documented as part of the redactor's
          contract.
        """
        return self._redact(params)

    def _redact(self, value: Any) -> Any:
        if isinstance(value, dict):
            redacted_dict: dict[str, object] = {}
            for k, v in value.items():
                if not isinstance(k, str):
                    redacted_dict[str(k)] = self._redact(v)
                    continue
                if any(re.search(pat, k, re.IGNORECASE) for pat in self._REDACT_KEY_PATTERNS):
                    redacted_dict[k] = "[REDACTED]"
                else:
                    redacted_dict[k] = self._redact(v)
            return redacted_dict
        if isinstance(value, (list, tuple)):
            return [self._redact(v) for v in value]
        if isinstance(value, str):
            return self._redact_string(value)
        return value

    @classmethod
    def _redact_string(cls, value: str) -> str:
        """Apply value-pattern + JSON-string redaction to a single string."""
        # Cheap exit on short strings (no realistic secret fits in <16 chars
        # of the patterns we care about).
        if not value:
            return value

        # If the string parses as JSON, recurse into the parsed structure.
        if value and value[0] in "{[" and len(value) >= 2:
            try:
                parsed = json.loads(value)
            except (json.JSONDecodeError, ValueError):
                parsed = None
            if parsed is not None and isinstance(parsed, (dict, list)):
                # Build a transient logger to reuse the redaction logic
                # without mutating self.
                logger = cls.__new__(cls)
                logger._entries = []
                logger._log_path = None
                logger._fh = None
                logger._fsync = False
                logger._lock = asyncio.Lock()
                redacted = logger._redact(parsed)
                return json.dumps(redacted, default=str)

        # Apply value-pattern detection on the raw string.
        for pat in _VALUE_PATTERNS:
            if pat.search(value):
                return "[REDACTED]"
        return value
