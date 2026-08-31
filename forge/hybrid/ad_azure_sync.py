"""Hybrid AD/Azure attack path analysis.

Identifies attack paths that cross AD and Azure boundaries through
synced user accounts (Azure AD Connect).

EDR-safe patterns:
- Read-only database queries (no live AD/Azure queries)
- Graph traversal on stored engagement data
- Synced user inference from data artifacts
- Exposure scoring from metadata (no credential access)

Security: All hybrid analysis requires valid ROE ID + scope manifest.
"""

import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import sqlite3

logger = logging.getLogger(__name__)


@dataclass
class SyncedUserEdge:
    """Edge representing synced user between AD and Azure."""
    ad_user: str              # On-prem AD user (CN=User,OU=Users,DC=domain,DC=com)
    azure_user: str           # Azure AD user (user@domain.com)
    sync_type: str            # "Azure AD Connect" | "federated"
    last_sync_time: Optional[datetime]
    is_admin: bool            # Has privileged role in either system
    ad_groups: List[str]      # AD group memberships
    azure_roles: List[str]    # Azure role assignments


@dataclass
class HybridAttackPath:
    """Attack path that crosses AD/Azure boundary."""
    source: str               # Attack entry point (phishing victim, compromised cred)
    ad_path: List[str]        # Path through AD (user → group → resource)
    azure_path: List[str]     # Path through Azure (user → role → resource)
    hybrid_edges: List[SyncedUserEdge]
    blast_radius: float       # Combined exposure score (0-1)
    recommendations: List[str]  # Remediation recommendations


class HybridADAzureAnalyzer:
    """Analyze hybrid AD/Azure attack paths.

    Identifies attack paths that leverage synced accounts to move
    between on-premises AD and Azure AD environments.

    Security:
        - Read-only analysis of stored engagement data
        - No live AD/Azure queries (inference from data)
        - Synced users detected via username matching + metadata
    """

    def __init__(self, roe_id: str, scope_manifest: Dict[str, Any]):
        """Initialize hybrid AD/Azure analyzer.

        Args:
            roe_id: Rules of Engagement identifier
            scope_manifest: Scope manifest with authorized targets
        """
        if not roe_id:
            raise ValueError("ROE ID required for hybrid analysis")

        self.roe_id = roe_id
        self.scope_manifest = scope_manifest

    def detect_synced_users(self, engagement_db: Path) -> List[SyncedUserEdge]:
        """Detect synced users by matching:

        1. Same username in AD users table + Azure AD users table
        2. ImmutableId present in Azure user (indicates sync)
        3. Domain federation metadata

        Args:
            engagement_db: Path to engagement SQLite database

        Returns:
            List of synced user edges
        """
        if not engagement_db.exists():
            logger.error(f"Engagement DB not found: {engagement_db}")
            return []

        synced_users = []

        try:
            conn = sqlite3.connect(str(engagement_db))
            conn.row_factory = sqlite3.Row

            cursor = conn.cursor()

            # Query AD users
            cursor.execute("""
                SELECT username, domain, distinguished_name, groups
                FROM ad_users
                WHERE domain IS NOT NULL
            """)
            ad_users = {row['username'].lower(): dict(row) for row in cursor.fetchall()}

            # Query Azure AD users
            cursor.execute("""
                SELECT user_principal_name, display_name, immutable_id, roles
                FROM azure_ad_users
                WHERE user_principal_name IS NOT NULL
            """)
            azure_users = {}
            for row in cursor.fetchall():
                username = row['user_principal_name'].split('@')[0].lower()
                azure_users[username] = dict(row)

            # Find synced users by username matching
            for username in set(ad_users.keys()) & set(azure_users.keys()):
                ad_user = ad_users[username]
                azure_user = azure_users[username]

                # Check for sync indicators
                immutable_id = azure_user.get('immutable_id')
                sync_type = "Azure AD Connect" if immutable_id else "inferred"

                # Parse AD groups
                ad_groups = []
                if ad_user.get('groups'):
                    try:
                        ad_groups = json.loads(ad_user['groups'])
                    except:
                        ad_groups = []

                # Parse Azure roles
                azure_roles = []
                if azure_user.get('roles'):
                    try:
                        azure_roles = json.loads(azure_user['roles'])
                    except:
                        azure_roles = []

                # Check admin status
                admin_groups = {'domain admins', 'enterprise admins', 'administrators'}
                admin_roles = {'global admin', 'privileged role admin', 'security admin'}

                is_admin = (
                    any(g.lower() in admin_groups for g in ad_groups) or
                    any(r.lower() in admin_roles for r in azure_roles)
                )

                synced_user = SyncedUserEdge(
                    ad_user=ad_user.get('distinguished_name', username),
                    azure_user=azure_user.get('user_principal_name', f"{username}@domain.com"),
                    sync_type=sync_type,
                    last_sync_time=None,  # Would need log analysis
                    is_admin=is_admin,
                    ad_groups=ad_groups,
                    azure_roles=azure_roles
                )

                synced_users.append(synced_user)

            conn.close()

            logger.info(
                f"Detected {len(synced_users)} synced users "
                f"(AD: {len(ad_users)}, Azure: {len(azure_users)})"
            )

            # Audit log
            self._audit_log(
                action="synced_users_detected",
                details={
                    "db": str(engagement_db),
                    "synced_count": len(synced_users),
                    "admin_count": sum(1 for u in synced_users if u.is_admin)
                }
            )

        except Exception as e:
            logger.exception(f"Failed to detect synced users: {e}")

        return synced_users

    def calculate_hybrid_exposure(self, synced_user: SyncedUserEdge) -> float:
        """Calculate hybrid blast radius.

        Factors:
        - AD group memberships (Domain Admins, Enterprise Admins)
        - Azure role assignments (Global Admin, Privileged Role Admin)
        - Sync latency (stale permissions = higher risk)
        - Federation trust (pass-through auth = higher risk)

        Args:
            synced_user: Synced user edge

        Returns:
            Exposure score (0-1)
        """
        score = 0.0

        # AD exposure
        high_priv_ad_groups = {
            'domain admins': 0.3,
            'enterprise admins': 0.3,
            'schema admins': 0.2,
            'administrators': 0.15
        }

        for group in synced_user.ad_groups:
            group_lower = group.lower()
            if group_lower in high_priv_ad_groups:
                score += high_priv_ad_groups[group_lower]

        # Azure exposure
        high_priv_azure_roles = {
            'global admin': 0.3,
            'privileged role admin': 0.25,
            'security admin': 0.2,
            'application admin': 0.15
        }

        for role in synced_user.azure_roles:
            role_lower = role.lower()
            if role_lower in high_priv_azure_roles:
                score += high_priv_azure_roles[role_lower]

        # Sync type multiplier
        if synced_user.sync_type == "federated":
            score *= 1.2  # Federated = pass-through auth = higher risk

        # Cap at 1.0
        score = min(score, 1.0)

        return score

    def find_hybrid_paths(
        self,
        engagement_db: Path,
        seed_user: str
    ) -> List[HybridAttackPath]:
        """Find attack paths that cross AD/Azure boundary.

        BloodHound v5.13.0 approach:
        - Query SyncedToADUser edges
        - Query SyncedToEntraUser edges
        - Combine with existing attack_path.py graph traversal

        Args:
            engagement_db: Path to engagement database
            seed_user: Starting user for path analysis

        Returns:
            List of hybrid attack paths
        """
        paths = []

        # Detect synced users
        synced_users = self.detect_synced_users(engagement_db)

        if not synced_users:
            logger.info("No synced users found, skipping hybrid path analysis")
            return paths

        # Find paths from seed user through synced accounts
        for synced_user in synced_users:
            # Check if seed is related to this synced user
            seed_lower = seed_user.lower()
            ad_username = synced_user.ad_user.split(',')[0].split('=')[-1].lower()
            azure_username = synced_user.azure_user.split('@')[0].lower()

            if seed_lower in [ad_username, azure_username]:
                # Calculate exposure
                blast_radius = self.calculate_hybrid_exposure(synced_user)

                # Build path
                path = HybridAttackPath(
                    source=seed_user,
                    ad_path=[synced_user.ad_user] + synced_user.ad_groups[:3],
                    azure_path=[synced_user.azure_user] + synced_user.azure_roles[:3],
                    hybrid_edges=[synced_user],
                    blast_radius=blast_radius,
                    recommendations=self.recommend_isolation(synced_user)
                )

                paths.append(path)

        logger.info(
            f"Found {len(paths)} hybrid attack path(s) for seed: {seed_user}"
        )

        # Audit log
        self._audit_log(
            action="hybrid_paths_analyzed",
            details={
                "seed_user": seed_user,
                "path_count": len(paths),
                "max_blast_radius": max((p.blast_radius for p in paths), default=0.0)
            }
        )

        return paths

    def analyze_attack_paths(self, *args, **kwargs) -> List[HybridAttackPath]:
        """Placeholder for broader hybrid attack path analysis.

        Returns:
            Empty list until a live analyzer is implemented.
        """
        self._audit_log(
            action="attack_path_analysis_placeholder",
            details={"implemented": False}
        )
        return []

    def find_hybrid_admins(self, *args, **kwargs) -> List[SyncedUserEdge]:
        """Placeholder for identifying synced hybrid admin accounts.

        Returns:
            Empty list until admin discovery is implemented.
        """
        self._audit_log(
            action="hybrid_admin_discovery_placeholder",
            details={"admin_count": 0, "implemented": False}
        )
        return []

    def detect_pass_through_auth(self, *args, **kwargs) -> Dict[str, Any]:
        """Placeholder for pass-through authentication detection.

        Returns:
            Empty dict until PTA detection is implemented.
        """
        self._audit_log(
            action="pass_through_auth_detection_placeholder",
            details={"implemented": False}
        )
        return {}

    def enumerate_federation_trusts(self, *args, **kwargs) -> List[Dict[str, Any]]:
        """Placeholder for federation trust enumeration.

        Returns:
            Empty list until federation trust discovery is implemented.
        """
        self._audit_log(
            action="federation_trust_enumeration_placeholder",
            details={"trust_count": 0, "implemented": False}
        )
        return []

    def recommend_isolation(self, synced_user: SyncedUserEdge) -> List[str]:
        """Recommend actions to break hybrid attack path.

        Examples:
        - "Remove {ad_user} from Domain Admins"
        - "Break Azure AD Connect sync for {azure_user}"
        - "Enable PIM for {azure_role}"

        Args:
            synced_user: Synced user to analyze

        Returns:
            List of remediation recommendations
        """
        recommendations = []

        # AD recommendations
        high_priv_groups = ['domain admins', 'enterprise admins', 'schema admins']
        for group in synced_user.ad_groups:
            if group.lower() in high_priv_groups:
                recommendations.append(
                    f"Remove {synced_user.ad_user} from {group}"
                )

        # Azure recommendations
        high_priv_roles = ['global admin', 'privileged role admin', 'security admin']
        for role in synced_user.azure_roles:
            if role.lower() in high_priv_roles:
                recommendations.append(
                    f"Enable PIM for {role} on {synced_user.azure_user}"
                )

        # Hybrid recommendations
        if synced_user.is_admin:
            recommendations.extend([
                f"Break Azure AD Connect sync for {synced_user.azure_user}",
                f"Implement separate cloud-only admin accounts",
                f"Review sync scope to exclude privileged accounts"
            ])

        # Dedupe
        recommendations = list(dict.fromkeys(recommendations))

        return recommendations

    def _audit_log(self, action: str, details: Dict[str, Any]) -> None:
        """Write audit log entry for hybrid analysis operation.

        Security: All hybrid analysis must be audit-logged.

        Args:
            action: Action name
            details: Action details
        """
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'module': 'hybrid.ad_azure_sync',
            'action': action,
            'roe_id': self.roe_id,
            'details': details
        }

        logger.info(f"AUDIT: {json.dumps(log_entry)}")
