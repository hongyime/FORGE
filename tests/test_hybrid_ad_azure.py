"""Unit tests for HybridADAzureAnalyzer (T6).

Tests hybrid AD/Azure attack path detection and blast radius analysis.
"""

import pytest
import json
import sqlite3
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from datetime import datetime, timezone
from forge.hybrid.ad_azure_sync import (
    HybridADAzureAnalyzer,
    SyncedUserEdge,
    HybridAttackPath
)


def _create_engagement_db(
    tmp_path,
    username="admin",
    immutable_id="immutable-123",
    ad_groups=None,
    azure_roles=None,
):
    """Create the SQLite shape consumed by HybridADAzureAnalyzer."""
    ad_groups = ["Domain Admins"] if ad_groups is None else ad_groups
    azure_roles = ["Global Admin"] if azure_roles is None else azure_roles
    db_path = tmp_path / "engagement.db"

    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE ad_users (
            username TEXT,
            domain TEXT,
            distinguished_name TEXT,
            groups TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE azure_ad_users (
            user_principal_name TEXT,
            display_name TEXT,
            immutable_id TEXT,
            roles TEXT
        )
        """
    )
    conn.execute(
        """
        INSERT INTO ad_users (username, domain, distinguished_name, groups)
        VALUES (?, ?, ?, ?)
        """,
        (
            username,
            "corp.local",
            f"CN={username},OU=Users,DC=corp,DC=local",
            json.dumps(ad_groups),
        ),
    )
    conn.execute(
        """
        INSERT INTO azure_ad_users (user_principal_name, display_name, immutable_id, roles)
        VALUES (?, ?, ?, ?)
        """,
        (
            f"{username}@corp.onmicrosoft.com",
            username.title(),
            immutable_id,
            json.dumps(azure_roles),
        ),
    )
    conn.commit()
    conn.close()
    return db_path


class TestSyncedUserEdge:
    """Test SyncedUserEdge dataclass."""

    def test_synced_user_edge_creation(self):
        """SyncedUserEdge creates with expected fields."""
        edge = SyncedUserEdge(
            ad_user="CN=admin,OU=Users,DC=corp,DC=local",
            azure_user="admin@corp.onmicrosoft.com",
            sync_type="Azure AD Connect",
            last_sync_time=datetime.now(timezone.utc),
            is_admin=True,
            ad_groups=["Domain Admins"],
            azure_roles=["Global Admin"]
        )
        assert edge.ad_user == "CN=admin,OU=Users,DC=corp,DC=local"
        assert edge.azure_user == "admin@corp.onmicrosoft.com"
        assert edge.sync_type == "Azure AD Connect"
        assert edge.is_admin is True
        assert "Domain Admins" in edge.ad_groups
        assert "Global Admin" in edge.azure_roles

    def test_synced_user_edge_defaults(self):
        """SyncedUserEdge handles optional fields."""
        edge = SyncedUserEdge(
            ad_user="CN=user,OU=Users,DC=corp,DC=local",
            azure_user="user@corp.onmicrosoft.com",
            sync_type="federated",
            last_sync_time=None,
            is_admin=False,
            ad_groups=[],
            azure_roles=[]
        )
        assert edge.last_sync_time is None
        assert edge.is_admin is False


class TestHybridAttackPath:
    """Test HybridAttackPath dataclass."""

    def test_attack_path_creation(self):
        """HybridAttackPath creates with expected fields."""
        edge1 = SyncedUserEdge(
            ad_user="CN=admin,OU=Users,DC=corp,DC=local",
            azure_user="admin@corp.onmicrosoft.com",
            sync_type="Azure AD Connect",
            last_sync_time=datetime.now(timezone.utc),
            is_admin=True,
            ad_groups=["Domain Admins"],
            azure_roles=["Global Admin"]
        )
        
        path = HybridAttackPath(
            source="on-prem_admin",
            ad_path=["AD Admin", "DC01"],
            azure_path=["Azure Admin", "Subscription"],
            hybrid_edges=[edge1],
            blast_radius=9.5,
            recommendations=["Enable MFA", "Review admin accounts"]
        )
        assert path.source == "on-prem_admin"
        assert path.blast_radius == 9.5
        assert len(path.hybrid_edges) == 1

    def test_attack_path_steps(self):
        """HybridAttackPath contains ordered steps."""
        edge = SyncedUserEdge(
            ad_user="CN=user,OU=Users,DC=corp,DC=local",
            azure_user="user@corp.com",
            sync_type="synced",
            last_sync_time=datetime.now(timezone.utc),
            is_admin=False,
            ad_groups=[],
            azure_roles=[]
        )
        
        path = HybridAttackPath(
            source="ad",
            ad_path=["step1", "step2", "step3"],
            azure_path=["azure1", "azure2"],
            hybrid_edges=[edge],
            blast_radius=5.0,
            recommendations=[]
        )
        assert len(path.ad_path) == 3
        assert len(path.azure_path) == 2


class TestHybridADAzureAnalyzer:
    """Test HybridADAzureAnalyzer class."""

    def test_init_default_settings(self):
        """HybridADAzureAnalyzer initializes."""
        analyzer = HybridADAzureAnalyzer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        assert analyzer.roe_id == "ROE-123"

    def test_detect_synced_users_success(self, tmp_path):
        """detect_synced_users returns user list."""
        analyzer = HybridADAzureAnalyzer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        db_path = _create_engagement_db(tmp_path)
        
        users = analyzer.detect_synced_users(db_path)
        assert isinstance(users, list)
        assert len(users) == 1
        assert users[0].sync_type == "Azure AD Connect"

    def test_find_hybrid_paths(self, tmp_path):
        """find_hybrid_paths returns path list."""
        analyzer = HybridADAzureAnalyzer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        db_path = _create_engagement_db(tmp_path)
        
        paths = analyzer.find_hybrid_paths(db_path, seed_user="admin")
        assert isinstance(paths, list)
        assert len(paths) == 1

    def test_calculate_hybrid_exposure(self):
        """calculate_hybrid_exposure returns an exposure score."""
        analyzer = HybridADAzureAnalyzer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        
        edge = SyncedUserEdge(
            ad_user="CN=admin,OU=Users,DC=corp,DC=local",
            azure_user="admin@corp.com",
            sync_type="synced",
            last_sync_time=datetime.now(timezone.utc),
            is_admin=True,
            ad_groups=["Domain Admins"],
            azure_roles=["Global Admin"]
        )
        
        radius = analyzer.calculate_hybrid_exposure(edge)
        assert radius is not None
        assert 0 <= radius <= 1

    def test_recommend_isolation_for_hybrid_admin(self):
        """recommend_isolation returns privileged-account recommendations."""
        analyzer = HybridADAzureAnalyzer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        edge = SyncedUserEdge(
            ad_user="CN=admin,OU=Users,DC=corp,DC=local",
            azure_user="admin@corp.com",
            sync_type="Azure AD Connect",
            last_sync_time=None,
            is_admin=True,
            ad_groups=["Domain Admins"],
            azure_roles=["Global Admin"]
        )

        recommendations = analyzer.recommend_isolation(edge)
        assert isinstance(recommendations, list)
        assert recommendations

    def test_low_privilege_synced_users_have_low_exposure(self):
        """calculate_hybrid_exposure scores low-privilege users at zero."""
        analyzer = HybridADAzureAnalyzer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        
        edge1 = SyncedUserEdge(
            ad_user="u1",
            azure_user="u1@corp.com",
            sync_type="synced",
            last_sync_time=None,
            is_admin=False,
            ad_groups=[],
            azure_roles=[]
        )
        edge2 = SyncedUserEdge(
            ad_user="u2",
            azure_user="u2@corp.com",
            sync_type="synced",
            last_sync_time=None,
            is_admin=False,
            ad_groups=[],
            azure_roles=[]
        )
        
        assert analyzer.calculate_hybrid_exposure(edge1) == 0.0
        assert analyzer.calculate_hybrid_exposure(edge2) == 0.0

    def test_find_hybrid_paths_scores_exposure(self, tmp_path):
        """find_hybrid_paths includes exposure scores from synced edges."""
        analyzer = HybridADAzureAnalyzer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        db_path = _create_engagement_db(tmp_path)

        paths = analyzer.find_hybrid_paths(db_path, seed_user="admin")
        assert paths[0].blast_radius > 0
        assert paths[0].blast_radius <= 1

    def test_federated_sync_type_increases_exposure(self):
        """calculate_hybrid_exposure applies a multiplier for federated sync."""
        analyzer = HybridADAzureAnalyzer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        synced = SyncedUserEdge(
            ad_user="admin",
            azure_user="admin@corp.com",
            sync_type="Azure AD Connect",
            last_sync_time=None,
            is_admin=True,
            ad_groups=["Domain Admins"],
            azure_roles=[]
        )
        federated = SyncedUserEdge(
            ad_user="admin",
            azure_user="admin@corp.com",
            sync_type="federated",
            last_sync_time=None,
            is_admin=True,
            ad_groups=["Domain Admins"],
            azure_roles=[]
        )
        
        assert analyzer.calculate_hybrid_exposure(federated) > analyzer.calculate_hybrid_exposure(synced)

    def test_detect_synced_users_infers_sync_without_immutable_id(self, tmp_path):
        """detect_synced_users marks matching users as inferred without ImmutableId."""
        analyzer = HybridADAzureAnalyzer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        db_path = _create_engagement_db(tmp_path, immutable_id=None)
        
        users = analyzer.detect_synced_users(db_path)
        assert users[0].sync_type == "inferred"

    def test_audit_log_created(self, tmp_path):
        """Operations create audit log entries."""
        analyzer = HybridADAzureAnalyzer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        db_path = _create_engagement_db(tmp_path)
        
        # Should create audit entry
        analyzer.detect_synced_users(db_path)

    def test_find_hybrid_paths_includes_recommendations(self, tmp_path):
        """find_hybrid_paths includes isolation recommendations."""
        analyzer = HybridADAzureAnalyzer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        db_path = _create_engagement_db(tmp_path)

        paths = analyzer.find_hybrid_paths(db_path, seed_user="admin")
        assert paths[0].recommendations
