"""Unit tests for BinaryUpdater (T1.5).

Tests Go binary and LoTL script update functionality.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
from forge.tools.binary_updater import BinaryUpdater, ToolVersion


class TestBinaryUpdater:
    """Test BinaryUpdater class."""

    def test_init_creates_tools_dir(self, tmp_path):
        """BinaryUpdater creates tools_dir if it doesn't exist."""
        tools_dir = tmp_path / "bin"
        assert not tools_dir.exists()
        
        updater = BinaryUpdater(tools_dir)
        assert tools_dir.exists()

    def test_init_with_existing_dir(self, tmp_path):
        """BinaryUpdater works with existing tools_dir."""
        tools_dir = tmp_path / "bin"
        tools_dir.mkdir()
        
        updater = BinaryUpdater(tools_dir)
        assert updater.tools_dir == tools_dir

    def test_load_installed_versions_no_file(self, tmp_path):
        """Loading versions returns empty dict when no manifest exists."""
        updater = BinaryUpdater(tmp_path)
        versions = updater._load_installed_versions()
        assert versions == {}

    def test_load_installed_versions_with_file(self, tmp_path):
        """Loading versions reads from existing manifest."""
        versions_data = {"subfinder": "v2.6.0", "httpx": "v1.3.0"}
        versions_file = tmp_path / ".versions.json"
        versions_file.write_text(json.dumps(versions_data))
        
        updater = BinaryUpdater(tmp_path)
        loaded = updater._load_installed_versions()
        assert loaded == versions_data

    def test_load_installed_versions_caches(self, tmp_path):
        """Version cache is reused on subsequent calls."""
        versions_data = {"nuclei": "v3.1.0"}
        versions_file = tmp_path / ".versions.json"
        versions_file.write_text(json.dumps(versions_data))
        
        updater = BinaryUpdater(tmp_path)
        v1 = updater._load_installed_versions()
        v2 = updater._load_installed_versions()
        assert v1 is v2  # Same object (cached)

    def test_save_installed_versions(self, tmp_path):
        """Saving versions writes to manifest file."""
        updater = BinaryUpdater(tmp_path)
        versions = {"katana": "v1.0.0"}
        
        updater._save_installed_versions(versions)
        
        manifest_file = tmp_path / ".versions.json"
        assert manifest_file.exists()
        loaded = json.loads(manifest_file.read_text())
        assert loaded == versions

    def test_get_latest_release_info_success(self, tmp_path):
        """Fetching release info returns parsed JSON."""
        updater = BinaryUpdater(tmp_path)
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "tag_name": "v2.6.0",
            "assets": []
        }
        mock_response.raise_for_status = Mock()
        
        with patch('forge.tools.binary_updater.requests.get', return_value=mock_response):
            result = updater._get_latest_release_info("projectdiscovery/subfinder")
            assert result["tag_name"] == "v2.6.0"

    def test_get_latest_release_info_failure(self, tmp_path):
        """Fetching release info returns None on error."""
        updater = BinaryUpdater(tmp_path)
        
        with patch('forge.tools.binary_updater.requests.get', side_effect=Exception("Network error")):
            result = updater._get_latest_release_info("projectdiscovery/subfinder")
            assert result is None

    def test_find_windows_asset_found(self, tmp_path):
        """Finding Windows asset returns URL and name."""
        updater = BinaryUpdater(tmp_path)
        
        release_info = {
            "assets": [
                {"name": "subfinder_linux_amd64.zip", "browser_download_url": "url1"},
                {"name": "subfinder_windows_amd64.zip", "browser_download_url": "url2"},
            ]
        }
        
        result = updater._find_windows_asset(release_info)
        assert result == ("url2", "subfinder_windows_amd64.zip")

    def test_find_windows_asset_not_found(self, tmp_path):
        """Finding Windows asset returns None when not present."""
        updater = BinaryUpdater(tmp_path)
        
        release_info = {
            "assets": [
                {"name": "subfinder_linux_amd64.zip", "browser_download_url": "url1"},
            ]
        }
        
        result = updater._find_windows_asset(release_info)
        assert result is None

    def test_check_for_updates_no_installed_version(self, tmp_path):
        """check_for_updates returns available when no version installed."""
        updater = BinaryUpdater(tmp_path)
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "tag_name": "v2.6.0",
            "published_at": "2024-01-01T00:00:00Z",
            "assets": []
        }
        mock_response.raise_for_status = Mock()
        
        with patch('forge.tools.binary_updater.requests.get', return_value=mock_response):
            result = updater.check_for_updates("subfinder")
            assert result.update_available is True
            assert result.installed_version == "none"

    def test_check_for_updates_same_version(self, tmp_path):
        """check_for_updates returns no update when versions match."""
        updater = BinaryUpdater(tmp_path)
        updater._save_installed_versions({"subfinder": "v2.6.0"})
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "tag_name": "v2.6.0",
            "published_at": "2024-01-01T00:00:00Z",
            "assets": []
        }
        mock_response.raise_for_status = Mock()
        
        with patch('forge.tools.binary_updater.requests.get', return_value=mock_response):
            result = updater.check_for_updates("subfinder")
            assert result.update_available is False

    def test_check_for_updates_newer_version(self, tmp_path):
        """check_for_updates returns update when newer version available."""
        updater = BinaryUpdater(tmp_path)
        updater._save_installed_versions({"subfinder": "v2.5.0"})
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "tag_name": "v2.6.0",
            "published_at": "2024-01-01T00:00:00Z",
            "assets": []
        }
        mock_response.raise_for_status = Mock()
        
        with patch('forge.tools.binary_updater.requests.get', return_value=mock_response):
            result = updater.check_for_updates("subfinder")
            assert result.update_available is True

    def test_check_for_updates_unknown_tool(self, tmp_path):
        """check_for_updates raises error for unknown tool."""
        updater = BinaryUpdater(tmp_path)
        
        with pytest.raises(ValueError, match="Unknown tool"):
            updater.check_for_updates("unknown_tool")

    def test_list_tools(self, tmp_path):
        """list_tools returns all configured tools."""
        updater = BinaryUpdater(tmp_path)
        tools = updater.list_tools()
        assert "subfinder" in tools
        assert "httpx" in tools
        assert "nuclei" in tools
        assert len(tools) == 6  # 6 ProjectDiscovery tools

    def test_get_tool_path(self, tmp_path):
        """get_tool_path returns expected Windows path."""
        updater = BinaryUpdater(tmp_path)
        path = updater.get_tool_path("subfinder")
        # On Windows, tools typically have .exe suffix
        assert "subfinder" in str(path).lower()

    def test_rollback_on_failure(self, tmp_path):
        """update_tool restores backup on failure."""
        updater = BinaryUpdater(tmp_path)
        
        # Create existing tool file
        tool_file = tmp_path / "subfinder.exe"
        tool_file.write_text("old_version")
        
        # Create backup
        backup_file = tmp_path / ".subfinder.exe.backup"
        backup_file.write_text("backup_version")
        
        # Simulate download failure
        with patch.object(updater, '_download_and_verify', return_value=None):
            # Manifest should not be updated
            with patch.object(updater, '_save_installed_versions') as mock_save:
                result = updater.update_tool("subfinder", apply=False)
                # Dry run should not modify files
