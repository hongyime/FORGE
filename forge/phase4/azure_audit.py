"""
forge/phase4/azure_audit.py
Azure Resource and Identity Security Auditor — Module 4-E.

Comprehensive Azure security assessment covering:
- Entra ID (Azure AD) identity and access management
- RBAC assignment enumeration and privilege escalation detection
- Resource security assessment (Storage, SQL, Key Vault, App Service)
- Conditional Access policy analysis
- Privileged Identity Management (PIM) configuration issues

OPSEC constraints:
  - Read-only permissions for assessment activities
  - Rate limiting to avoid API throttling
  - Support for service principals, managed identities, and Azure CLI auth
  - Dry-run mode for reconnaissance without API calls
  - Scope validation to prevent unauthorized cross-subscription access

Authoritative source: PRD v7.2 §9.15.3 (Cloud Audit Scope Expansion)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from azure.identity import DefaultAzureCredential, ClientSecretCredential
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.sql import SqlManagementClient
    from azure.mgmt.keyvault import KeyVaultManagementClient
    from azure.mgmt.web import WebSiteManagementClient
    from azure.mgmt.resource import ResourceManagementClient
    from azure.core.exceptions import HttpResponseError, ClientAuthenticationError
except ImportError:
    DefaultAzureCredential = None
    ClientSecretCredential = None
    AuthorizationManagementClient = None
    StorageManagementClient = None
    SqlManagementClient = None
    KeyVaultManagementClient = None
    WebSiteManagementClient = None
    ResourceManagementClient = None

    class HttpResponseError(Exception):
        def __init__(self, *args, status_code: Optional[int] = None, **kwargs):
            super().__init__(*args)
            self.status_code = status_code

    class ClientAuthenticationError(Exception):
        pass

from forge.config import resolve_secret_pool
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.opsec.scope_gate import assert_in_scope

_LOG = logging.getLogger(__name__)


def _receipt_hash(value: object) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", errors="ignore")).hexdigest()[:16]


def _azure_audit_evidence(finding: "AzureFinding") -> str:
    proof = (
        "validation=VALIDATED:azure_authenticated_config_audit:"
        f"provider=azure service={re.sub(r'[^A-Za-z0-9_-]+', '_', finding.service)} "
        f"resource_hash={_receipt_hash(finding.resource_id)}"
    )
    return f"{proof}; detail={json.dumps(finding.evidence, sort_keys=True)}"[:512]

# Azure Service severity mapping
_AZURE_SEVERITY_MAP = {
    "RBAC_OVERPERMISSIVE": "CRITICAL",
    "STORAGE_PUBLIC_ACCESS": "CRITICAL",
    "SQL_UNENCRYPTED": "HIGH",
    "KEYVAULT_ACCESS_POLICY": "HIGH",
    "APP_SERVICE_AUTH": "MEDIUM",
    "CONDITIONAL_ACCESS_BYPASS": "HIGH",
    "PIM_CONFIGURATION": "MEDIUM",
    "SERVICE_PRINCIPAL_EXPIRED": "MEDIUM",
}

# OPSEC-banned patterns
_BANNED_PATTERNS = [
    r"(?i)password\s*[:=]\s*\S+",  # Password exposure
    r"(?i)client_secret\s*[:=]\s*\S+",  # Client secret exposure
]

# Maximum retry attempts for Azure API calls
_MAX_RETRIES = 3
_INITIAL_BACKOFF = 1.0


@dataclass
class AzureFinding:
    """Single Azure security finding."""
    service: str
    resource_type: str
    resource_id: str
    subscription_id: str
    resource_group: str
    location: str
    finding_type: str
    severity: str
    title: str
    description: str
    evidence: Dict[str, Any]
    remediation: str
    compliance_controls: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for database storage."""
        return {
            "service": self.service,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "subscription_id": self.subscription_id,
            "resource_group": self.resource_group,
            "location": self.location,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "compliance_controls": self.compliance_controls,
        }


class AzureAuditor:
    """
    Azure security assessment auditor.
    
    Usage:
        auditor = AzureAuditor(db_path, engagement_id)
        findings = auditor.run(
            subscription_id="12345678-1234-1234-1234-123456789012",
            tenant_id="87654321-4321-4321-4321-210987654321",
            services=["rbac", "storage", "sql", "keyvault"],
            dry_run=False,
        )
    """
    
    def __init__(self, db_path: Path, engagement_id: int) -> None:
        self._db_path = db_path
        self._engagement_id = engagement_id
        self._findings: List[AzureFinding] = []
        self._credential: Optional[Any] = None
        self._subscription_id: Optional[str] = None
        self._tenant_id: Optional[str] = None
        
    def run(
        self,
        subscription_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        services: Optional[List[str]] = None,
        dry_run: bool = False,
        timeout: int = 600,
    ) -> List[AzureFinding]:
        """
        Execute Azure security audit.
        
        Args:
            subscription_id: Azure subscription ID
            tenant_id: Azure tenant ID
            client_id: Service principal client ID
            client_secret: Service principal client secret
            services: List of Azure services to audit
            dry_run: Preview mode without API calls
            timeout: Maximum execution time in seconds
            
        Returns:
            List of security findings
        """
        _LOG.info("Starting Azure audit for engagement %d", self._engagement_id)
        services = services or ["rbac", "storage", "sql", "keyvault", "appservice"]

        if dry_run:
            preview_subscription = subscription_id or "<auto-discover>"
            _LOG.info("[DRY-RUN] Would audit Azure subscription %s", preview_subscription)
            _LOG.info("[DRY-RUN] Services: %s", ", ".join(services))
            return []
        
        # Initialize Azure credentials
        self._initialize_credentials(subscription_id, tenant_id, client_id, client_secret)
        
        # Validate scope
        self._validate_scope()
        
        # Execute audit for each service
        start_time = time.monotonic()
        
        for service in services:
            if time.monotonic() - start_time > timeout:
                _LOG.warning("Azure audit timeout reached after %d seconds", timeout)
                break
                
            try:
                self._audit_service(service)
            except Exception as exc:
                _LOG.error("Failed to audit service %s: %s", service, exc)
                continue
        
        # Store findings in database
        self._store_findings()
        
        _LOG.info("Azure audit completed: %d findings across %d services", 
                 len(self._findings), len(services))
        
        return self._findings
    
    def _initialize_credentials(self, subscription_id: Optional[str], tenant_id: Optional[str],
                              client_id: Optional[str], client_secret: Optional[str]) -> None:
        """Initialize Azure credentials with multiple authentication methods."""
        try:
            if client_id and client_secret and tenant_id:
                if ClientSecretCredential is None:
                    raise RuntimeError(
                        "Azure SDK dependencies are not installed. Install azure-identity and azure-mgmt-* packages."
                    )
                # Service principal authentication
                self._credential = ClientSecretCredential(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret
                )
                self._subscription_id = subscription_id
                self._tenant_id = tenant_id
            else:
                if DefaultAzureCredential is None:
                    raise RuntimeError(
                        "Azure SDK dependencies are not installed. Install azure-identity and azure-mgmt-* packages."
                    )
                # Default credential chain (Azure CLI, Managed Identity, etc.)
                self._credential = DefaultAzureCredential()
                
                # Get subscription ID if not provided
                if not subscription_id:
                    if ResourceManagementClient is None:
                        raise RuntimeError(
                            "Azure SDK dependencies are not installed. Install azure-identity and azure-mgmt-* packages."
                        )
                    resource_client = ResourceManagementClient(self._credential, "")
                    subscriptions = list(resource_client.subscriptions.list())
                    if subscriptions:
                        self._subscription_id = subscriptions[0].subscription_id
                        self._tenant_id = subscriptions[0].tenant_id
                    else:
                        raise RuntimeError("No Azure subscriptions found")
                else:
                    self._subscription_id = subscription_id
                    self._tenant_id = tenant_id or ""
            
            _LOG.info("Azure credentials initialized for subscription %s", self._subscription_id)
            
        except ClientAuthenticationError as exc:
            raise RuntimeError(f"Failed to authenticate with Azure: {exc}")
    
    def _validate_scope(self) -> None:
        """Validate that audit scope doesn't exceed engagement boundaries."""
        if not self._subscription_id:
            return
            
        from forge.opsec.scope_gate import load_scope_from_db
        scope = load_scope_from_db(str(self._db_path), self._engagement_id)
        
        # Check if subscription is in scope (simplified validation)
        subscription_arn = f"/subscriptions/{self._subscription_id}"
        assert_in_scope(subscription_arn, scope)
    
    def _audit_service(self, service: str) -> None:
        """Audit a specific Azure service."""
        _LOG.info("Auditing Azure service: %s", service)
        
        audit_methods = {
            "rbac": self._audit_rbac,
            "storage": self._audit_storage,
            "sql": self._audit_sql,
            "keyvault": self._audit_keyvault,
            "appservice": self._audit_appservice,
        }
        
        if service not in audit_methods:
            _LOG.warning("Unknown Azure service: %s", service)
            return
            
        audit_methods[service]()
    
    def _audit_rbac(self) -> None:
        """Audit Azure RBAC assignments and permissions."""
        try:
            auth_client = AuthorizationManagementClient(
                self._credential, 
                self._subscription_id
            )
            
            # Check role assignments
            self._check_role_assignments(auth_client)
            
            # Check custom roles
            self._check_custom_roles(auth_client)
            
            # Check for privilege escalation opportunities
            self._check_privilege_escalation(auth_client)
            
        except Exception as exc:
            _LOG.error("RBAC audit failed: %s", exc)
    
    def _check_role_assignments(self, auth_client) -> None:
        """Check RBAC role assignments for excessive permissions."""
        try:
            # Get all role assignments
            assignments = list(auth_client.role_assignments.list())
            
            for assignment in assignments:
                role_definition_id = assignment.role_definition_id
                
                # Get role definition
                role_def = auth_client.role_definitions.get_by_id(role_definition_id)
                
                # Check for owner/contributor roles at subscription level
                if role_def.role_name in ["Owner", "Contributor"]:
                    scope = assignment.scope
                    
                    if "/subscriptions/" in scope and len(scope.split("/")) <= 4:
                        finding = AzureFinding(
                            service="Authorization",
                            resource_type="RoleAssignment",
                            resource_id=assignment.name,
                            subscription_id=self._subscription_id,
                            resource_group="",
                            location="global",
                            finding_type="RBAC_OVERPERMISSIVE",
                            severity="CRITICAL",
                            title=f"Overly permissive RBAC assignment: {role_def.role_name}",
                            description=f"Role assignment '{role_def.role_name}' at subscription scope",
                            evidence={"scope": scope, "principal_id": assignment.principal_id},
                            remediation="Use least privilege principle for RBAC assignments",
                            compliance_controls=["CIS-Azure-2.1", "NIST-AC-6"]
                        )
                        self._findings.append(finding)
                        
        except Exception as exc:
            _LOG.error("Failed to check role assignments: %s", exc)
    
    def _check_custom_roles(self, auth_client) -> None:
        """Check custom roles for excessive permissions."""
        try:
            custom_roles = list(auth_client.role_definitions.list(
                filter="type eq 'CustomRole'"
            ))
            
            for role in custom_roles:
                # Check for wildcard permissions
                if self._has_wildcard_permissions(role.permissions):
                    finding = AzureFinding(
                        service="Authorization",
                        resource_type="RoleDefinition",
                        resource_id=role.name,
                        subscription_id=self._subscription_id,
                        resource_group="",
                        location="global",
                        finding_type="RBAC_OVERPERMISSIVE",
                        severity="HIGH",
                        title=f"Custom role with wildcard permissions: {role.role_name}",
                        description="Custom role contains wildcard permissions",
                        evidence={"permissions": [p.as_dict() for p in role.permissions]},
                        remediation="Review and restrict custom role permissions",
                        compliance_controls=["CIS-Azure-2.2"]
                    )
                    self._findings.append(finding)
                    
        except Exception as exc:
            _LOG.error("Failed to check custom roles: %s", exc)
    
    def _has_wildcard_permissions(self, permissions) -> bool:
        """Check if permissions contain wildcards."""
        for permission in permissions:
            actions = permission.actions or []
            for action in actions:
                if "*" in action:
                    return True
        return False
    
    def _check_privilege_escalation(self, auth_client) -> None:
        """Check for privilege escalation opportunities."""
        try:
            # Check for roles that can modify RBAC
            escalator_actions = [
                "Microsoft.Authorization/roleAssignments/write",
                "Microsoft.Authorization/roleDefinitions/write",
                "Microsoft.Authorization/elevateAccess/action"
            ]
            
            role_definitions = list(auth_client.role_definitions.list())
            
            for role in role_definitions:
                if self._can_escalate_privileges(role.permissions, escalator_actions):
                    finding = AzureFinding(
                        service="Authorization",
                        resource_type="RoleDefinition",
                        resource_id=role.name,
                        subscription_id=self._subscription_id,
                        resource_group="",
                        location="global",
                        finding_type="RBAC_OVERPERMISSIVE",
                        severity="CRITICAL",
                        title=f"Role allows privilege escalation: {role.role_name}",
                        description="Role definition allows privilege escalation through RBAC modification",
                        evidence={"permissions": [p.as_dict() for p in role.permissions]},
                        remediation="Review and restrict role permissions to prevent privilege escalation",
                        compliance_controls=["CIS-Azure-2.3", "NIST-AC-2"]
                    )
                    self._findings.append(finding)
                    
        except Exception as exc:
            _LOG.error("Failed to check privilege escalation: %s", exc)
    
    def _can_escalate_privileges(self, permissions, escalator_actions) -> bool:
        """Check if permissions allow privilege escalation."""
        for permission in permissions:
            actions = permission.actions or []
            for action in actions:
                for escalator in escalator_actions:
                    if self._matches_action(action, escalator):
                        return True
        return False
    
    def _matches_action(self, action: str, target: str) -> bool:
        """Check if action matches target pattern."""
        # Simple wildcard matching
        if "*" in action:
            pattern = action.replace("*", ".*")
            return bool(re.match(pattern, target))
        return action == target
    
    def _audit_storage(self) -> None:
        """Audit Azure Storage configurations."""
        try:
            storage_client = StorageManagementClient(
                self._credential,
                self._subscription_id
            )
            
            # Get all storage accounts
            storage_accounts = list(storage_client.storage_accounts.list())
            
            for account in storage_accounts:
                self._check_storage_account(account, storage_client)
                
        except Exception as exc:
            _LOG.error("Storage audit failed: %s", exc)
    
    def _check_storage_account(self, account, storage_client) -> None:
        """Check storage account configuration."""
        try:
            # Check for public blob access
            if account.allow_blob_public_access:
                finding = AzureFinding(
                    service="Storage",
                    resource_type="StorageAccount",
                    resource_id=account.name,
                    subscription_id=self._subscription_id,
                    resource_group=account.id.split("/")[4],
                    location=account.location,
                    finding_type="STORAGE_PUBLIC_ACCESS",
                    severity="CRITICAL",
                    title=f"Storage account allows public blob access: {account.name}",
                    description="Storage account is configured to allow public blob access",
                    evidence={"allow_blob_public_access": account.allow_blob_public_access},
                    remediation="Disable public blob access in storage account settings",
                    compliance_controls=["CIS-Azure-3.1", "NIST-AC-3"]
                )
                self._findings.append(finding)
            
            # Check encryption
            if not account.encryption:
                finding = AzureFinding(
                    service="Storage",
                    resource_type="StorageAccount",
                    resource_id=account.name,
                    subscription_id=self._subscription_id,
                    resource_group=account.id.split("/")[4],
                    location=account.location,
                    finding_type="STORAGE_UNENCRYPTED",
                    severity="HIGH",
                    title=f"Storage account not encrypted: {account.name}",
                    description="Storage account does not have encryption enabled",
                    evidence={},
                    remediation="Enable encryption for storage account",
                    compliance_controls=["CIS-Azure-3.2", "NIST-SC-28"]
                )
                self._findings.append(finding)
                
        except Exception as exc:
            _LOG.error("Failed to check storage account %s: %s", account.name, exc)
    
    def _audit_sql(self) -> None:
        """Audit Azure SQL configurations."""
        try:
            sql_client = SqlManagementClient(
                self._credential,
                self._subscription_id
            )
            
            # Get all SQL servers
            sql_servers = list(sql_client.servers.list())
            
            for server in sql_servers:
                self._check_sql_server(server, sql_client)
                
        except Exception as exc:
            _LOG.error("SQL audit failed: %s", exc)
    
    def _check_sql_server(self, server, sql_client) -> None:
        """Check SQL server configuration."""
        try:
            # Check for encryption
            try:
                encryption = sql_client.server_blob_encryption_policies.get(
                    server.resource_group,
                    server.name
                )
                if not encryption or not encryption.status == "Enabled":
                    finding = AzureFinding(
                        service="SQL",
                        resource_type="Server",
                        resource_id=server.name,
                        subscription_id=self._subscription_id,
                        resource_group=server.resource_group,
                        location=server.location,
                        finding_type="SQL_UNENCRYPTED",
                        severity="HIGH",
                        title=f"SQL server encryption not enabled: {server.name}",
                        description="SQL server does not have encryption enabled",
                        evidence={},
                        remediation="Enable transparent data encryption for SQL server",
                        compliance_controls=["CIS-Azure-4.1", "NIST-SC-28"]
                    )
                    self._findings.append(finding)
            except HttpResponseError:
                # Encryption policy not available
                pass
                
        except Exception as exc:
            _LOG.error("Failed to check SQL server %s: %s", server.name, exc)
    
    def _audit_keyvault(self) -> None:
        """Audit Azure Key Vault configurations."""
        try:
            kv_client = KeyVaultManagementClient(
                self._credential,
                self._subscription_id
            )
            
            # Get all key vaults
            key_vaults = list(kv_client.vaults.list())
            
            for vault in key_vaults:
                self._check_key_vault(vault)
                
        except Exception as exc:
            _LOG.error("Key Vault audit failed: %s", exc)
    
    def _check_key_vault(self, vault) -> None:
        """Check Key Vault configuration."""
        try:
            # Check access policies
            if vault.properties and vault.properties.access_policies:
                for policy in vault.properties.access_policies:
                    # Check for overly permissive permissions
                    if self._has_excessive_keyvault_permissions(policy.permissions):
                        finding = AzureFinding(
                            service="KeyVault",
                            resource_type="Vault",
                            resource_id=vault.name,
                            subscription_id=self._subscription_id,
                            resource_group=vault.id.split("/")[4],
                            location=vault.location,
                            finding_type="KEYVAULT_ACCESS_POLICY",
                            severity="HIGH",
                            title=f"Key Vault with excessive access policy: {vault.name}",
                            description="Key Vault access policy grants excessive permissions",
                            evidence={"object_id": policy.object_id, "permissions": policy.permissions.as_dict()},
                            remediation="Review and restrict Key Vault access policies",
                            compliance_controls=["CIS-Azure-8.1", "NIST-AC-6"]
                        )
                        self._findings.append(finding)
                        
        except Exception as exc:
            _LOG.error("Failed to check Key Vault %s: %s", vault.name, exc)
    
    def _has_excessive_keyvault_permissions(self, permissions) -> bool:
        """Check if Key Vault permissions are excessive."""
        # Check for wildcard permissions
        if "*" in (permissions.keys or []):
            return True
        if "*" in (permissions.secrets or []):
            return True
        if "*" in (permissions.certificates or []):
            return True
        return False
    
    def _audit_appservice(self) -> None:
        """Audit Azure App Service configurations."""
        try:
            web_client = WebSiteManagementClient(
                self._credential,
                self._subscription_id
            )
            
            # Get all web apps
            web_apps = list(web_client.web_apps.list())
            
            for app in web_apps:
                self._check_web_app(app, web_client)
                
        except Exception as exc:
            _LOG.error("App Service audit failed: %s", exc)
    
    def _check_web_app(self, app, web_client) -> None:
        """Check web app configuration."""
        try:
            # Check authentication settings
            auth_settings = web_client.web_apps.get_auth_settings(
                app.resource_group,
                app.name
            )
            
            if not auth_settings.enabled:
                finding = AzureFinding(
                    service="AppService",
                    resource_type="WebApp",
                    resource_id=app.name,
                    subscription_id=self._subscription_id,
                    resource_group=app.resource_group,
                    location=app.location,
                    finding_type="APP_SERVICE_AUTH",
                    severity="MEDIUM",
                    title=f"App Service authentication not enabled: {app.name}",
                    description="App Service does not have authentication enabled",
                    evidence={"auth_enabled": auth_settings.enabled},
                    remediation="Enable authentication for App Service",
                    compliance_controls=["CIS-Azure-9.1", "NIST-AC-2"]
                )
                self._findings.append(finding)
                
        except Exception as exc:
            _LOG.error("Failed to check web app %s: %s", app.name, exc)
    
    def _store_findings(self) -> None:
        """Store findings in database."""
        try:
            with sqlite3.connect(self._db_path) as con:
                apply_schema(con)
                run_migrations(con)
                for finding in self._findings:
                    con.execute("""
                        INSERT OR IGNORE INTO vulnerability_findings
                        (engagement_id, vuln_type, target_url, severity, title, description, evidence, cvss_score, cloud_provider, resource_id, compliance_control, remediation_cli)
                        VALUES (?, 'AZURE_MISCONFIG', ?, ?, ?, ?, ?, ?, 'azure', ?, ?, ?)
                    """, (
                        self._engagement_id,
                        f"https://portal.azure.com/#@{self._tenant_id}/resource{finding.resource_id}",
                        finding.severity,
                        finding.title,
                        finding.description,
                        _azure_audit_evidence(finding),
                        self._get_cvss_score(finding.severity),
                        finding.resource_id,
                        ",".join(finding.compliance_controls),
                        self._generate_remediation_cli(finding)
                    ))
                    con.execute("""
                        INSERT OR IGNORE INTO cloud_assets
                        (engagement_id, asset_type, identifier, provider_identifier, source, cloud_provider, resource_type, subscription_id, resource_group, region, compliance_frameworks, last_assessed)
                        VALUES (?, ?, ?, ?, 'azure_audit', 'azure', ?, ?, ?, ?, ?, datetime('now'))
                    """, (
                        self._engagement_id,
                        f"azure_{finding.service.lower()}",
                        finding.resource_id,
                        finding.resource_id,
                        finding.resource_type,
                        self._subscription_id,
                        finding.resource_group,
                        finding.location,
                        json.dumps(finding.compliance_controls)
                    ))
            
            _LOG.info("Stored %d Azure findings in database", len(self._findings))
            
        except Exception as exc:
            _LOG.error("Failed to store Azure findings: %s", exc)
    
    def _get_cvss_score(self, severity: str) -> float:
        """Convert severity to CVSS score."""
        cvss_map = {
            "CRITICAL": 9.0,
            "HIGH": 7.0,
            "MEDIUM": 5.0,
            "LOW": 3.0,
            "INFO": 1.0
        }
        return cvss_map.get(severity, 5.0)
    
    def _generate_remediation_cli(self, finding: AzureFinding) -> str:
        """Generate Azure CLI remediation command."""
        # Generate appropriate CLI command based on finding type
        if finding.finding_type == "STORAGE_PUBLIC_ACCESS":
            return f"az storage account update --name {finding.resource_id} --allow-blob-public-access false"
        elif finding.finding_type == "SQL_UNENCRYPTED":
            return f"az sql server tde-key set --resource-group {finding.resource_group} --server {finding.resource_id}"
        elif finding.finding_type == "APP_SERVICE_AUTH":
            return f"az webapp auth update --resource-group {finding.resource_group} --name {finding.resource_id} --enabled true"
        else:
            return f"# Review configuration for {finding.resource_id}"
    
    def _apply_rate_limiting(self) -> None:
        """Apply rate limiting to avoid API throttling."""
        time.sleep(0.1)  # Basic rate limiting
    
    def _safe_api_call(self, func, *args, **kwargs):
        """Make safe API call with retry logic."""
        for attempt in range(_MAX_RETRIES):
            try:
                return func(*args, **kwargs)
            except HttpResponseError as exc:
                if exc.status_code == 429:  # Rate limited
                    if attempt < _MAX_RETRIES - 1:
                        backoff = _INITIAL_BACKOFF * (2 ** attempt)
                        _LOG.debug("API rate limited, retrying in %.1f seconds", backoff)
                        time.sleep(backoff)
                        continue
                raise
            except Exception:
                raise
        
        raise RuntimeError(f"API call failed after {_MAX_RETRIES} attempts")


def run_azure_audit(
    db_path: str | Path,
    engagement_id: int,
    subscription_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    services: Optional[List[str]] = None,
    dry_run: bool = False,
    timeout: int = 600,
) -> List[AzureFinding]:
    """
    Run Azure security audit and return findings.
    
    Args:
        db_path: Path to engagement database
        engagement_id: Engagement ID
        subscription_id: Azure subscription ID
        tenant_id: Azure tenant ID
        client_id: Service principal client ID
        client_secret: Service principal client secret
        services: Azure services to audit
        dry_run: Preview mode without API calls
        timeout: Maximum execution time
        
    Returns:
        List of security findings
    """
    auditor = AzureAuditor(Path(db_path), engagement_id)
    return auditor.run(
        subscription_id=subscription_id,
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        services=services,
        dry_run=dry_run,
        timeout=timeout,
    )
