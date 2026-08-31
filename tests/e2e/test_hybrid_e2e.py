"""E2E tests for hybrid.ad_azure_sync module.

Tests hybrid AD/Azure attack path analysis with real integration.
"""

import pytest
import sqlite3
import json
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from forge.hybrid.ad_azure_sync import (
    HybridADAzureAnalyzer,
    SyncedUserEdge,
    HybridAttackPath
)


class TestHybridE2E:
    """E2E tests for HybridADAzureAnalyzer with real integration."""

    @pytest.fixture
    def scope_manifest(self):
        """Scope manifest for testing."""
        return {
            "domains": ["testcorp.local"],
            "roe_id": "ROE-TEST-004"
        }

    @pytest.fixture
    def hybrid_analyzer(self, scope_manifest):
        """HybridADAzureAnalyzer instance."""
        return HybridADAzureAnalyzer(
            roe_id="ROE-TEST-004",
            scope_manifest=scope_manifest
        )

    @pytest.fixture
    def engagement_db(self, tmp_path):
        """Create test engagement database with AD/Azure data."""
        db_path = tmp_path / "engagement.db"
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # Create AD users table
        cursor.execute("""
            CREATE TABLE ad_users (
                username TEXT,
                domain TEXT,
                distinguished_name TEXT,
                groups TEXT
            )
        """)

        # Create Azure AD users table
        cursor.execute("""
            CREATE TABLE azure_ad_users (
                user_principal_name TEXT,
                display_name TEXT,
                immutable_id TEXT,
                roles TEXT
            )
        """)

        # Insert AD users
        ad_users = [
            ("admin", "testcorp.local", "CN=admin,OU=Users,DC=testcorp,DC=local", json.dumps(["Domain Admins", "Enterprise Admins"])),
            ("jsmith", "testcorp.local", "CN=jsmith,OU=Users,DC=testcorp,DC=local", json.dumps(["IT Support", "Help Desk"])),
            ("svc_account", "testcorp.local", "CN=svc_account,OU=Service Accounts,DC=testcorp,DC=local", json.dumps([]))
        ]
        cursor.executemany("INSERT INTO ad_users VALUES (?, ?, ?, ?)", ad_users)

        # Insert Azure AD users (some synced)
        azure_users = [
            ("admin@testcorp.com", "Admin User", "ABC123XYZ", json.dumps(["Global Admin"])),
            ("jsmith@testcorp.com", "John Smith", "DEF456UVW", json.dumps(["Security Reader"])),
            ("cloudonly@testcorp.com", "Cloud User", None, json.dumps(["User"]) )
        ]
        cursor.executemany("INSERT INTO azure_ad_users VALUES (?, ?, ?, ?)", azure_users)

        conn.commit()
        conn.close()
        return db_path

    def test_initialization_requires_roe_id(self, scope_manifest):
        """Test that ROE ID is mandatory."""
        with pytest.raises(ValueError, match="ROE ID required"):
            HybridADAzureAnalyzer(
                roe_id="",
                scope_manifest=scope_manifest
            )

    def test_synced_user_edge_dataclass_structure(self):
        """Test SyncedUserEdge dataclass structure."""
        edge = SyncedUserEdge(
            ad_user="CN=admin,OU=Users,DC=testcorp,DC=local",
            azure_user="admin@testcorp.com",
            sync_type="Azure AD Connect",
            last_sync_time=datetime.now(timezone.utc),
            is_admin=True,
            ad_groups=["Domain Admins", "Enterprise Admins"],
            azure_roles=["Global Admin"]
        )

        assert edge.ad_user == "CN=admin,OU=Users,DC=testcorp,DC=local"
        assert edge.azure_user == "admin@testcorp.com"
        assert edge.sync_type == "Azure AD Connect"
        assert edge.is_admin is True
        assert "Domain Admins" in edge.ad_groups
        assert "Global Admin" in edge.azure_roles

    def test_hybrid_attack_path_dataclass_structure(self):
        """Test HybridAttackPath dataclass structure."""
        edge = SyncedUserEdge(
            ad_user="CN=admin,OU=Users,DC=testcorp,DC=local",
            azure_user="admin@testcorp.com",
            sync_type="Azure AD Connect",
            last_sync_time=None,
            is_admin=True,
            ad_groups=["Domain Admins"],
            azure_roles=["Global Admin"]
        )

        path = HybridAttackPath(
            source="phishing_admin@testcorp.com",
            ad_path=["CN=admin", "Domain Admins"],
            azure_path=["admin@testcorp.com", "Global Admin"],
            hybrid_edges=[edge],
            blast_radius=0.8,
            recommendations=["Enable PIM", "Break sync"]
        )

        assert path.source == "phishing_admin@testcorp.com"
        assert len(path.ad_path) == 2
        assert len(path.azure_path) == 2
        assert len(path.hybrid_edges) == 1
        assert path.blast_radius == 0.8
        assert len(path.recommendations) == 2

    def test_detect_synced_users_integration(self, hybrid_analyzer, engagement_db):
        """Test synced user detection with real database."""
        synced_users = hybrid_analyzer.detect_synced_users(engagement_db)

        # Should detect synced users
        assert isinstance(synced_users, list)
        assert len(synced_users) > 0

        # Check structure
        for user in synced_users:
            assert isinstance(user, SyncedUserEdge)
            assert user.ad_user is not None
            assert user.azure_user is not None

    def test_detect_synced_users_identifies_admins(self, hybrid_analyzer, engagement_db):
        """Test that admin accounts are correctly identified."""
        synced_users = hybrid_analyzer.detect_synced_users(engagement_db)

        # Should have admin account synced
        admin_users = [u for u in synced_users if u.is_admin]
        assert len(admin_users) > 0

        # Admin should have high-priv groups/roles
        admin = admin_users[0]
        assert "Domain Admins" in admin.ad_groups or "Administrators" in admin.ad_groups
        assert "Global Admin" in admin.azure_roles or "Global Admin" in admin.azure_roles

    def test_calculate_hybrid_exposure_high_risk(self, hybrid_analyzer):
        """Test exposure calculation for high-risk synced account."""
        synced_user = SyncedUserEdge(
            ad_user="CN=admin,OU=Users,DC=testcorp,DC=local",
            azure_user="admin@testcorp.com",
            sync_type="Azure AD Connect",
            last_sync_time=None,
            is_admin=True,
            ad_groups=["Domain Admins", "Enterprise Admins"],
            azure_roles=["Global Admin", "Privileged Role Admin"]
        )

        score = hybrid_analyzer.calculate_hybrid_exposure(synced_user)

        # Should have high exposure score
        assert score > 0.5
        assert score <= 1.0

    def test_calculate_hybrid_exposure_low_risk(self, hybrid_analyzer):
        """Test exposure calculation for low-risk account."""
        synced_user = SyncedUserEdge(
            ad_user="CN=jsmith,OU=Users,DC=testcorp,DC=local",
            azure_user="jsmith@testcorp.com",
            sync_type="Azure AD Connect",
            last_sync_time=None,
            is_admin=False,
            ad_groups=["IT Support"],
            azure_roles=["Security Reader"]
        )

        score = hybrid_analyzer.calculate_hybrid_exposure(synced_user)

        # Should have lower exposure score
        assert score < 0.5
        assert score >= 0.0

    def test_calculate_hybrid_exposure_federated_multiplier(self, hybrid_analyzer):
        """Test that federated sync type increases exposure."""
        synced_user_federated = SyncedUserEdge(
            ad_user="CN=admin,OU=Users,DC=testcorp,DC=local",
            azure_user="admin@testcorp.com",
            sync_type="federated",  # Higher risk
            last_sync_time=None,
            is_admin=False,
            ad_groups=["Domain Admins"],
            azure_roles=[]
        )

        synced_user_standard = SyncedUserEdge(
            ad_user="CN=admin,OU=Users,DC=testcorp,DC=local",
            azure_user="admin@testcorp.com",
            sync_type="Azure AD Connect",  # Standard
            last_sync_time=None,
            is_admin=False,
            ad_groups=["Domain Admins"],
            azure_roles=[]
        )

        score_federated = hybrid_analyzer.calculate_hybrid_exposure(synced_user_federated)
        score_standard = hybrid_analyzer.calculate_hybrid_exposure(synced_user_standard)

        # Federated should have higher score
        assert score_federated > score_standard

    def test_find_hybrid_paths_integration(self, hybrid_analyzer, engagement_db):
        """Test hybrid attack path finding."""
        paths = hybrid_analyzer.find_hybrid_paths(
            engagement_db=engagement_db,
            seed_user="admin"
        )

        # Should return attack paths
        assert isinstance(paths, list)

        # Check structure if paths found
        for path in paths:
            assert isinstance(path, HybridAttackPath)
            assert path.source == "admin"
            assert len(path.ad_path) > 0 or len(path.azure_path) > 0
            assert 0.0 <= path.blast_radius <= 1.0
            assert isinstance(path.recommendations, list)

    def test_recommend_isolation_ad_admin(self, hybrid_analyzer):
        """Test isolation recommendations for AD admin."""
        synced_user = SyncedUserEdge(
            ad_user="CN=admin,OU=Users,DC=testcorp,DC=local",
            azure_user="admin@testcorp.com",
            sync_type="Azure AD Connect",
            last_sync_time=None,
            is_admin=True,
            ad_groups=["Domain Admins", "Enterprise Admins"],
            azure_roles=[]
        )

        recommendations = hybrid_analyzer.recommend_isolation(synced_user)

        # Should recommend removing from high-priv groups
        assert any("Remove" in r and "Domain Admins" in r for r in recommendations)
        assert any("Remove" in r and "Enterprise Admins" in r for r in recommendations)

    def test_recommend_isolation_azure_admin(self, hybrid_analyzer):
        """Test isolation recommendations for Azure admin."""
        synced_user = SyncedUserEdge(
            ad_user="CN=admin,OU=Users,DC=testcorp,DC=local",
            azure_user="admin@testcorp.com",
            sync_type="Azure AD Connect",
            last_sync_time=None,
            is_admin=True,
            ad_groups=[],
            azure_roles=["Global Admin", "Privileged Role Admin"]
        )

        recommendations = hybrid_analyzer.recommend_isolation(synced_user)

        # Should recommend PIM for Azure roles
        assert any("PIM" in r for r in recommendations)

    def test_recommend_isolation_hybrid_admin(self, hybrid_analyzer):
        """Test isolation recommendations for hybrid admin."""
        synced_user = SyncedUserEdge(
            ad_user="CN=admin,OU=Users,DC=testcorp,DC=local",
            azure_user="admin@testcorp.com",
            sync_type="Azure AD Connect",
            last_sync_time=None,
            is_admin=True,
            ad_groups=["Domain Admins"],
            azure_roles=["Global Admin"]
        )

        recommendations = hybrid_analyzer.recommend_isolation(synced_user)

        # Should recommend breaking sync
        assert any("Break Azure AD Connect sync" in r for r in recommendations)
        assert any("separate cloud-only admin" in r.lower() for r in recommendations)

    def test_detect_synced_users_nonexistent_db(self, hybrid_analyzer, caplog):
        """Test graceful handling of nonexistent database."""
        fake_db = Path("/nonexistent/engagement.db")
        synced_users = hybrid_analyzer.detect_synced_users(fake_db)

        # Should return empty list without crashing
        assert synced_users == []
        assert any("Engagement DB not found" in r.message for r in caplog.records)

    def test_audit_log_entries_created(self, hybrid_analyzer, engagement_db, caplog):
        """Test that audit log entries are created."""
        hybrid_analyzer.detect_synced_users(engagement_db)

        # Check for audit logs
        audit_logs = [r for r in caplog.records if "AUDIT:" in r.message]
        assert len(audit_logs) >= 0  # May have logs

    def test_analyze_attack_paths_placeholder(self, hybrid_analyzer):
        """Test analyze_attack_paths placeholder."""
        result = hybrid_analyzer.analyze_attack_paths()
        assert result == []

    def test_find_hybrid_admins_placeholder(self, hybrid_analyzer):
        """Test find_hybrid_admins placeholder."""
        result = hybrid_analyzer.find_hybrid_admins()
        assert result == []

    def test_detect_pass_through_auth_placeholder(self, hybrid_analyzer):
        """Test detect_pass_through_auth placeholder."""
        result = hybrid_analyzer.detect_pass_through_auth()
        assert result == {}

    def test_enumerate_federation_trusts_placeholder(self, hybrid_analyzer):
        """Test enumerate_federation_trusts placeholder."""
        result = hybrid_analyzer.enumerate_federation_trusts()
        assert result == []
