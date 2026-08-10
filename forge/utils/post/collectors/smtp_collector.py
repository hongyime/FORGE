from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile

_LOG = logging.getLogger(__name__)


class SmtpCollector(BaseCollector):
    """
    Collect SMTP and email client configuration.

    Targets:
      - ~/.msmtprc
      - ~/.muttrc
      - Thunderbird profiles
      - Outlook profiles (where accessible via filesystem)
    """

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        # 1. Simple client configs
        smtp_files = [(".msmtprc", "msmtp"), (".muttrc", "mutt"), (".mailrc", "mailrc")]

        for f, client_type in smtp_files:
            p = Path.home() / f
            if p.exists():
                yield ArtifactMetadata(
                    artifact_family="smtp_config",
                    artifact_subtype=client_type,
                    source_path=str(p),
                    source_platform=os.name,
                    collection_method="file_read",
                )

        # 2. Thunderbird profile discovery
        tb_dir = (
            Path.home() / ".thunderbird"
            if os.name != "nt"
            else Path(os.environ.get("APPDATA", "")) / "Thunderbird" / "Profiles"
        )
        if tb_dir.exists():
            yield ArtifactMetadata(
                artifact_family="smtp_config",
                artifact_subtype="thunderbird_profile",
                source_path=str(tb_dir),
                source_platform=os.name,
                collection_method="directory_discovery",
            )

        # 3. Outlook PST file
        outlook_paths = [
            Path.home() / "Documents" / "Outlook Files",
            Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Outlook",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Outlook",
        ]
        for path in outlook_paths:
            if path.exists():
                for match in path.rglob("*.pst"):
                    yield ArtifactMetadata(
                        artifact_family="smtp_config",
                        artifact_subtype="outlook_pst",
                        source_path=str(match),
                        source_platform=os.name,
                        collection_method="file_read",
                    )

    def collect(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        try:
            path = Path(artifact.source_path)
            if not path.exists():
                return None

            if artifact.collection_method == "directory_discovery":
                data, directory_summary = self._archive_directory(path)
                if not data:
                    return None
                artifact.report_safe_summary_fields = {
                    **artifact.report_safe_summary_fields,
                    **directory_summary,
                }
                return self._record_payload(
                    artifact=artifact,
                    raw_data=data,
                    logical_path=str(path),
                    ext=artifact.artifact_subtype or "smtp_dir",
                )

            data = path.read_bytes()
            return self._record_payload(
                artifact=artifact,
                raw_data=data,
                logical_path=str(path),
                ext=artifact.artifact_subtype or "smtp",
            )

        except PermissionError:
            _LOG.debug("Permission denied: %s", artifact.source_path)
        except Exception as exc:
            _LOG.debug("SMTP artifact collection error (%s): %s", artifact.source_path, exc)
        return None
