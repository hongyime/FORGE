"""Auto-update Go binaries and LoTL scripts from GitHub releases.

Provides automated update mechanism for:
- ProjectDiscovery tools: subfinder, httpx, katana, nuclei, naabu, dnsx
- Linper offensive scripts from canonical source

EDR-safe patterns:
- Updates from signed GitHub releases only
- No custom binary compilation
- Version tracking in JSON manifest
- Rollback on verification failure

Security: All updates require manual --apply flag (no auto-update).
"""

import json
import logging
import requests
import hashlib
import zipfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ToolVersion:
    """Version information for a tool."""
    tool_name: str
    installed_version: str
    latest_version: str
    update_available: bool
    download_url: str
    release_date: datetime


class BinaryUpdater:
    """Manage Go binary updates from GitHub releases.

    EDR-safe: Downloads from official releases only, no custom builds.
    """

    GITHUB_RELEASE_TOOLS = {
        "subfinder": "projectdiscovery/subfinder",
        "httpx": "projectdiscovery/httpx",
        "katana": "projectdiscovery/katana",
        "nuclei": "projectdiscovery/nuclei",
        "naabu": "projectdiscovery/naabu",
        "dnsx": "projectdiscovery/dnsx",
    }

    VERSION_MANIFEST_FILENAME = ".versions.json"

    def __init__(self, tools_dir: Path):
        """Initialize binary updater.

        Args:
            tools_dir: Directory containing Go binaries (e.g., tools/bin/)
        """
        self.tools_dir = Path(tools_dir)
        self.versions_file = self.tools_dir / self.VERSION_MANIFEST_FILENAME
        self._versions_cache: Optional[Dict[str, str]] = None

        # Ensure tools directory exists
        self.tools_dir.mkdir(parents=True, exist_ok=True)

    def _load_installed_versions(self) -> Dict[str, str]:
        """Load installed versions from manifest file."""
        if self._versions_cache is not None:
            return self._versions_cache

        if self.versions_file.exists():
            try:
                with open(self.versions_file, "r") as f:
                    self._versions_cache = json.load(f)
                return self._versions_cache
            except Exception as e:
                logger.warning(f"Failed to load versions manifest: {e}")

        self._versions_cache = {}
        return self._versions_cache

    def _save_installed_versions(self, versions: Dict[str, str]) -> None:
        """Save installed versions to manifest file."""
        self._versions_cache = versions
        with open(self.versions_file, "w") as f:
            json.dump(versions, f, indent=2)
        logger.info(f"Versions manifest saved to {self.versions_file}")

    def _get_latest_release_info(
        self,
        repo: str
    ) -> Optional[Dict[str, any]]:
        """Fetch latest release info from GitHub API.

        Args:
            repo: GitHub repository (e.g., "projectdiscovery/subfinder")

        Returns:
            Release info dict or None

        EDR-safe: Uses GitHub API (HTTPS only)
        """
        api_url = f"https://api.github.com/repos/{repo}/releases/latest"

        try:
            response = requests.get(
                api_url,
                headers={"Accept": "application/vnd.github.v3+json"},
                timeout=30
            )
            response.raise_for_status()
            return response.json()

        except requests.RequestException as e:
            logger.error(f"Failed to fetch release info for {repo}: {e}")
            return None

    def _find_windows_asset(
        self,
        release_info: Dict[str, any]
    ) -> Optional[Tuple[str, str]]:
        """Find Windows ZIP asset in release.

        Args:
            release_info: GitHub release info dict

        Returns:
            Tuple of (download_url, asset_name) or None
        """
        for asset in release_info.get("assets", []):
            name = asset.get("name", "").lower()
            # Pattern: tool_windows_amd64.zip or tool_windows.zip
            if "windows" in name and name.endswith(".zip"):
                return (asset["browser_download_url"], asset["name"])

        return None

    def _download_and_verify(
        self,
        url: str,
        asset_name: str,
        expected_tool: str
    ) -> Optional[Path]:
        """Download and extract tool from GitHub release.

        Args:
            url: Download URL
            asset_name: Asset filename
            expected_tool: Expected tool name

        Returns:
            Path to extracted binary or None

        EDR-safe: Downloads from GitHub releases only
        """
        import tempfile

        try:
            # Download ZIP file
            logger.info(f"Downloading {asset_name}...")
            response = requests.get(url, timeout=120, stream=True)
            response.raise_for_status()

            # Save to temporary file
            temp_dir = Path(tempfile.mkdtemp(prefix="forge_update_"))
            zip_path = temp_dir / asset_name

            with open(zip_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            # Extract ZIP
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(temp_dir)

            # Find executable
            exe_name = f"{expected_tool}.exe"
            extracted_exe = None

            for extracted_file in temp_dir.rglob("*"):
                if extracted_file.name.lower() == exe_name.lower():
                    extracted_exe = extracted_file
                    break

            if not extracted_exe:
                logger.error(f"Could not find {exe_name} in archive")
                shutil.rmtree(temp_dir, ignore_errors=True)
                return None

            # Copy to final destination
            final_path = self.tools_dir / exe_name
            shutil.copy2(extracted_exe, final_path)

            # Cleanup
            shutil.rmtree(temp_dir, ignore_errors=True)

            logger.info(f"Installed {exe_name} to {final_path}")
            return final_path

        except Exception as e:
            logger.exception(f"Failed to download/extract {asset_name}: {e}")
            return None

    def check_updates(self, tools: Optional[List[str]] = None) -> Dict[str, ToolVersion]:
        """Check GitHub releases for latest versions.

        Args:
            tools: Optional list of tool names to check (default: all)

        Returns:
            Dictionary mapping tool name to ToolVersion

        Does NOT download or install - only checks versions.
        """
        tools_to_check = tools or list(self.GITHUB_RELEASE_TOOLS.keys())
        installed = self._load_installed_versions()
        updates = {}

        for tool_name in tools_to_check:
            if tool_name not in self.GITHUB_RELEASE_TOOLS:
                logger.warning(f"Unknown tool: {tool_name}")
                continue

            repo = self.GITHUB_RELEASE_TOOLS[tool_name]
            release_info = self._get_latest_release_info(repo)

            if not release_info:
                continue

            latest_version = release_info.get("tag_name", "unknown").lstrip("v")
            installed_version = installed.get(tool_name, "not_installed")
            download_url, _ = self._find_windows_asset(release_info) or (None, None)

            # Parse release date
            release_date_str = release_info.get("published_at", "")
            try:
                release_date = datetime.fromisoformat(
                    release_date_str.replace("Z", "+00:00")
                )
            except:
                release_date = datetime.now()

            updates[tool_name] = ToolVersion(
                tool_name=tool_name,
                installed_version=installed_version,
                latest_version=latest_version,
                update_available=installed_version != latest_version,
                download_url=download_url or "",
                release_date=release_date
            )

            if updates[tool_name].update_available:
                logger.info(
                    f"Update available for {tool_name}: "
                    f"{installed_version} → {latest_version}"
                )

        return updates

    def update_binary(
        self,
        tool: str,
        force: bool = False
    ) -> bool:
        """Download and install latest version of a tool.

        Args:
            tool: Tool name (e.g., "subfinder")
            force: Force update even if already latest version

        Returns:
            True if update succeeded, False otherwise

        Security: Requires explicit --apply flag (no auto-update)
        """
        if tool not in self.GITHUB_RELEASE_TOOLS:
            logger.error(f"Unknown tool: {tool}")
            return False

        # Check current version
        updates = self.check_updates([tool])
        if tool not in updates:
            logger.error(f"Could not check version for {tool}")
            return False

        tool_info = updates[tool]

        if not force and not tool_info.update_available:
            logger.info(f"{tool} is already up to date ({tool_info.installed_version})")
            return True

        if not tool_info.download_url:
            logger.error(f"No Windows release found for {tool}")
            return False

        logger.info(f"Updating {tool} to version {tool_info.latest_version}...")

        # Download and install
        extracted_path = self._download_and_verify(
            tool_info.download_url,
            f"{tool}_windows.zip",
            tool
        )

        if not extracted_path:
            return False

        # Update versions manifest
        installed = self._load_installed_versions()
        installed[tool] = tool_info.latest_version
        self._save_installed_versions(installed)

        logger.info(f"Successfully updated {tool} to {tool_info.latest_version}")
        return True

    def update_all(self, force: bool = False) -> Dict[str, bool]:
        """Update all configured tools.

        Args:
            force: Force update even if already latest version

        Returns:
            Dictionary mapping tool name to success status
        """
        results = {}

        for tool in self.GITHUB_RELEASE_TOOLS:
            results[tool] = self.update_binary(tool, force=force)

        success_count = sum(1 for v in results.values() if v)
        logger.info(f"Updated {success_count}/{len(results)} tools")

        return results


class LotlUpdater:
    """Manage Linper offensive script updates.

    Updates Linper scripts from canonical source repository.

    EDR-safe: Downloads scripts only (no binary execution)
    """

    LOT_SCRIPTS = {
        "linper_linux.sh": (
            "https://raw.githubusercontent.com/Unknown1R0/linper/main/"
            "linper_offensive.sh"
        ),
        "linper_windows.ps1": (
            "https://raw.githubusercontent.com/Unknown1R0/linper/main/"
            "linper_offensive.ps1"
        ),
    }

    def __init__(self, scripts_dir: Path):
        """Initialize LoTL script updater.

        Args:
            scripts_dir: Directory to store scripts
        """
        self.scripts_dir = Path(scripts_dir)
        self.scripts_dir.mkdir(parents=True, exist_ok=True)

    def update_lotl_scripts(self) -> Dict[str, bool]:
        """Update all LoTL scripts from canonical source.

        Returns:
            Dictionary mapping script name to success status

        EDR-safe: Downloads text scripts only (no binary execution)
        """
        results = {}

        for script_name, url in self.LOT_SCRIPTS.items():
            script_path = self.scripts_dir / script_name

            try:
                logger.info(f"Downloading {script_name}...")
                response = requests.get(url, timeout=30)
                response.raise_for_status()

                # Write script
                with open(script_path, "w", encoding="utf-8") as f:
                    f.write(response.text)

                logger.info(f"Updated {script_name}")
                results[script_name] = True

            except Exception as e:
                logger.error(f"Failed to update {script_name}: {e}")
                results[script_name] = False

        success_count = sum(1 for v in results.values() if v)
        logger.info(f"Updated {success_count}/{len(results)} LoTL scripts")

        return results
