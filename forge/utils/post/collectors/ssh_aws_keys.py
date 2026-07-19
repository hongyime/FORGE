from __future__ import annotations

from typing import Generator, Optional

from forge.utils.post.collectors.aws_collector import AwsCollector
from forge.utils.post.collectors.clipboard_collector import ClipboardCollector
from forge.utils.post.collectors.env_var_collector import EnvVarCollector
from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile
from forge.utils.post.collectors.ssh_collector import SshCollector


class SshAwsKeyCollector(BaseCollector):
    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        collectors = (
            SshCollector,
            AwsCollector,
            EnvVarCollector,
            ClipboardCollector,
        )
        for collector_cls in collectors:
            collector = collector_cls(
                self._db_path,
                self._engagement_id,
                self._session_key,
                self._staging_dir,
                self._stagger,
            )
            collector.configure_execution(roe_id=self._roe_id, require_roe=self._require_roe)
            yield from collector.discover()

    def collect(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        collector_map = {
            "ssh_key": SshCollector,
            "aws_credentials": AwsCollector,
            "environment_variables": EnvVarCollector,
            "clipboard": ClipboardCollector,
        }
        collector_cls = collector_map.get(artifact.artifact_family)
        if collector_cls is None:
            return None
        collector = collector_cls(
            self._db_path,
            self._engagement_id,
            self._session_key,
            self._staging_dir,
            self._stagger,
        )
        collector.configure_execution(roe_id=self._roe_id, require_roe=self._require_roe)
        return collector.collect(artifact)


__all__ = [
    "SshAwsKeyCollector",
    "EnvVarCollector",
    "ClipboardCollector",
]
