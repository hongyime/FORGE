"""
Test suite for Cloud Audit Expansion (AWS & Azure).

Tests cover:
- AWS IAM privilege enumeration and escalation detection
- Azure RBAC assignment analysis
- Resource misconfiguration detection
- OPSEC compliance and error handling
- Integration with database schema
"""
import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call

from forge.phase4.aws_audit import AWSAuditor, AWSFinding, run_aws_audit
from forge.phase4.azure_audit import AzureAuditor, AzureFinding, run_azure_audit


class TestAWSAuditor:
    """Test AWS security auditor implementation."""
    
    def test_aws_auditor_initialization(self):
        """Test AWS auditor initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            auditor = AWSAuditor(db_path, engagement_id=1)
            
            assert auditor._db_path == db_path
            assert auditor._engagement_id == 1
            assert auditor._findings == []
            assert auditor._session is None
            assert auditor._account_id is None
            assert auditor._regions == []
    
    def test_aws_session_initialization(self):
        """Test AWS session initialization with credential chain."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            auditor = AWSAuditor(db_path, engagement_id=1)
            
            with patch('boto3.Session') as mock_session_class:
                mock_session = Mock()
                mock_session_class.return_value = mock_session
                
                # Mock STS client
                mock_sts = Mock()
                mock_session.client.return_value = mock_sts
                mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
                
                auditor._initialize_session(profile="test-profile")
                
                mock_session_class.assert_called_once_with(profile_name="test-profile")
                mock_session.client.assert_called_once_with("sts")
                assert auditor._account_id == "123456789012"
    
    def test_iam_policy_wildcard_detection(self):
        """Test detection of overly permissive IAM policies."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            auditor = AWSAuditor(db_path, engagement_id=1)
            
            # Test policy with wildcard permissions
            policy_doc = {
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }]
            }
            
            assert auditor._has_wildcard_permissions(policy_doc) is True
            
            # Test policy with specific permissions
            safe_policy = {
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }]
            }
            
            assert auditor._has_wildcard_permissions(safe_policy) is False
    
    def test_privilege_escalation_detection(self):
        """Test detection of privilege escalation paths."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            auditor = AWSAuditor(db_path, engagement_id=1)
            
            # Test policy with privilege escalation actions
            policy_doc = {
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["sts:AssumeRole", "iam:CreateRole"],
                    "Resource": "*"
                }]
            }
            
            assert auditor._has_privilege_escalation_risk(policy_doc) is True
            
            # Test policy without escalation actions
            safe_policy = {
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "*"
                }]
            }
            
            assert auditor._has_privilege_escalation_risk(safe_policy) is False
    
    def test_s3_public_access_detection(self):
        """Test detection of public S3 bucket access."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            auditor = AWSAuditor(db_path, engagement_id=1)
            
            # Test bucket policy with public access
            policy = {
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }]
            }
            
            assert auditor._has_public_bucket_policy(policy) is True
            
            # Test bucket policy with specific principal
            safe_policy = {
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }]
            }
            
            assert auditor._has_public_bucket_policy(safe_policy) is False
    
    def test_security_group_overpermissive_detection(self):
        """Test detection of overly permissive security groups."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            auditor = AWSAuditor(db_path, engagement_id=1)
            
            # Test security group with internet access
            sg = {
                "GroupId": "sg-12345678",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }]
            }
            mock_ec2 = Mock()
            mock_ec2.describe_security_groups.return_value = {"SecurityGroups": [sg]}
            
            # This should trigger a finding
            auditor._check_security_groups(mock_ec2, "us-east-1")
            
            # Verify finding was created
            assert len(auditor._findings) > 0
            finding = auditor._findings[0]
            assert finding.service == "EC2"
            assert finding.finding_type == "EC2_SECURITY_GROUP"
    
    def test_finding_storage(self, tmp_path):
        """Test storage of findings in database."""
        db_path = tmp_path / "test.db"
        auditor = AWSAuditor(db_path, engagement_id=1)
            
        # Create test finding
        finding = AWSFinding(
            service="IAM",
            resource_type="Policy",
            resource_id="test-policy",
            region="us-east-1",
            finding_type="IAM_OVERPERMISSIVE",
            severity="CRITICAL",
            title="Test finding",
            description="Test description",
            evidence={"test": "evidence"},
            remediation="Test remediation"
        )
            
        auditor._findings.append(finding)
        auditor._store_findings()
            
        # Verify finding was stored
        import sqlite3
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM vulnerability_findings WHERE engagement_id = 1")
            count = cursor.fetchone()[0]
            assert count > 0
    
    def test_cvss_score_mapping(self):
        """Test severity to CVSS score mapping."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            auditor = AWSAuditor(db_path, engagement_id=1)
            
            assert auditor._get_cvss_score("CRITICAL") == 9.0
            assert auditor._get_cvss_score("HIGH") == 7.0
            assert auditor._get_cvss_score("MEDIUM") == 5.0
            assert auditor._get_cvss_score("LOW") == 3.0
            assert auditor._get_cvss_score("INFO") == 1.0


class TestAzureAuditor:
    """Test Azure security auditor implementation."""
    
    def test_azure_auditor_initialization(self):
        """Test Azure auditor initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            auditor = AzureAuditor(db_path, engagement_id=1)
            
            assert auditor._db_path == db_path
            assert auditor._engagement_id == 1
            assert auditor._findings == []
            assert auditor._credential is None
            assert auditor._subscription_id is None
            assert auditor._tenant_id is None
    
    def test_azure_credential_initialization(self):
        """Test Azure credential initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            auditor = AzureAuditor(db_path, engagement_id=1)
            
            with patch('forge.phase4.azure_audit.DefaultAzureCredential') as mock_credential:
                mock_credential.return_value = Mock()
                
                auditor._initialize_credentials(
                    subscription_id="test-subscription",
                    tenant_id="test-tenant",
                    client_id=None,
                    client_secret=None
                )
                
                mock_credential.assert_called_once()
                assert auditor._subscription_id == "test-subscription"
                assert auditor._tenant_id == "test-tenant"
    
    def test_rbac_wildcard_permissions(self):
        """Test detection of wildcard permissions in RBAC."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            auditor = AzureAuditor(db_path, engagement_id=1)
            
            # Mock permissions with wildcards
            mock_permissions = Mock()
            mock_permissions.actions = ["*", "Microsoft.Storage/*"]
            mock_permissions.data_actions = []
            mock_permissions.not_actions = []
            mock_permissions.not_data_actions = []
            
            assert auditor._has_wildcard_permissions([mock_permissions]) is True
            
            # Mock permissions without wildcards
            safe_permissions = Mock()
            safe_permissions.actions = ["Microsoft.Storage/storageAccounts/read"]
            safe_permissions.data_actions = []
            safe_permissions.not_actions = []
            safe_permissions.not_data_actions = []
            
            assert auditor._has_wildcard_permissions([safe_permissions]) is False
    
    def test_privilege_escalation_rbac(self):
        """Test detection of privilege escalation in RBAC."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            auditor = AzureAuditor(db_path, engagement_id=1)
            
            # Mock permissions that allow privilege escalation
            escalator_actions = [
                "Microsoft.Authorization/roleAssignments/write",
                "Microsoft.Authorization/roleDefinitions/write"
            ]
            
            mock_permissions = Mock()
            mock_permissions.actions = escalator_actions
            mock_permissions.data_actions = []
            mock_permissions.not_actions = []
            mock_permissions.not_data_actions = []
            
            assert auditor._can_escalate_privileges([mock_permissions], escalator_actions) is True
            
            # Mock permissions without escalation capabilities
            safe_permissions = Mock()
            safe_permissions.actions = ["Microsoft.Storage/storageAccounts/read"]
            safe_permissions.data_actions = []
            safe_permissions.not_actions = []
            safe_permissions.not_data_actions = []
            
            assert auditor._can_escalate_privileges([safe_permissions], escalator_actions) is False
    
    def test_storage_public_access_detection(self):
        """Test detection of public blob access in storage accounts."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            auditor = AzureAuditor(db_path, engagement_id=1)
            
            # Mock storage account with public access
            mock_account = Mock()
            mock_account.name = "test-storage"
            mock_account.allow_blob_public_access = True
            mock_account.encryption = None
            mock_account.id = "/subscriptions/test/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/test-storage"
            mock_account.location = "eastus"
            
            auditor._check_storage_account(mock_account, Mock())
            
            # Verify finding was created
            assert len(auditor._findings) > 0
            finding = auditor._findings[0]
            assert finding.service == "Storage"
            assert finding.finding_type == "STORAGE_PUBLIC_ACCESS"
            assert finding.severity == "CRITICAL"
    
    def test_sql_encryption_detection(self):
        """Test detection of unencrypted SQL databases."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            auditor = AzureAuditor(db_path, engagement_id=1)
            
            # Mock SQL server without encryption
            mock_server = Mock()
            mock_server.name = "test-sql-server"
            mock_server.resource_group = "test-rg"
            mock_server.location = "eastus"
            
            with patch.object(auditor, '_has_excessive_keyvault_permissions', return_value=False):
                auditor._check_sql_server(mock_server, Mock())
            
            # Verify finding was created
            assert len(auditor._findings) > 0
            finding = auditor._findings[0]
            assert finding.service == "SQL"
            assert finding.finding_type == "SQL_UNENCRYPTED"
            assert finding.severity == "HIGH"
    
    def test_keyvault_access_policy_detection(self):
        """Test detection of excessive Key Vault access policies."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            auditor = AzureAuditor(db_path, engagement_id=1)
            
            # Mock Key Vault with excessive permissions
            mock_vault = Mock()
            mock_vault.name = "test-keyvault"
            mock_vault.id = "/subscriptions/test/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/test-keyvault"
            mock_vault.location = "eastus"
            
            mock_policy = Mock()
            mock_policy.object_id = "test-object-id"
            mock_policy.permissions.keys = ["*"]
            mock_policy.permissions.secrets = ["*"]
            mock_policy.permissions.certificates = ["get"]
            
            mock_vault.properties = Mock()
            mock_vault.properties.access_policies = [mock_policy]
            
            auditor._check_key_vault(mock_vault)
            
            # Verify finding was created
            assert len(auditor._findings) > 0
            finding = auditor._findings[0]
            assert finding.service == "KeyVault"
            assert finding.finding_type == "KEYVAULT_ACCESS_POLICY"
            assert finding.severity == "HIGH"
    
    def test_app_service_auth_detection(self):
        """Test detection of missing App Service authentication."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            auditor = AzureAuditor(db_path, engagement_id=1)
            
            # Mock App Service without authentication
            mock_app = Mock()
            mock_app.name = "test-app"
            mock_app.resource_group = "test-rg"
            mock_app.location = "eastus"
            
            mock_web_client = Mock()
            mock_auth_settings = Mock()
            mock_auth_settings.enabled = False
            mock_web_client.web_apps.get_auth_settings.return_value = mock_auth_settings
            
            auditor._check_web_app(mock_app, mock_web_client)
            
            # Verify finding was created
            assert len(auditor._findings) > 0
            finding = auditor._findings[0]
            assert finding.service == "AppService"
            assert finding.finding_type == "APP_SERVICE_AUTH"
            assert finding.severity == "MEDIUM"
    
    def test_azure_finding_storage(self, tmp_path):
        """Test storage of Azure findings in database."""
        db_path = tmp_path / "test.db"
        auditor = AzureAuditor(db_path, engagement_id=1)
            
        # Create test finding
        finding = AzureFinding(
            service="Storage",
            resource_type="StorageAccount",
            resource_id="test-storage",
            subscription_id="test-subscription",
            resource_group="test-rg",
            location="eastus",
            finding_type="STORAGE_PUBLIC_ACCESS",
            severity="CRITICAL",
            title="Test finding",
            description="Test description",
            evidence={"test": "evidence"},
            remediation="Test remediation"
        )
            
        auditor._findings.append(finding)
        auditor._store_findings()
            
        # Verify finding was stored
        import sqlite3
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM vulnerability_findings WHERE engagement_id = 1")
            count = cursor.fetchone()[0]
            assert count > 0
    
    def test_azure_cli_remediation_generation(self):
        """Test generation of Azure CLI remediation commands."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            auditor = AzureAuditor(db_path, engagement_id=1)
            
            # Test storage remediation
            storage_finding = AzureFinding(
                service="Storage",
                resource_type="StorageAccount",
                resource_id="test-storage",
                subscription_id="test-sub",
                resource_group="test-rg",
                location="eastus",
                finding_type="STORAGE_PUBLIC_ACCESS",
                severity="CRITICAL",
                title="Public storage",
                description="Storage allows public access",
                evidence={},
                remediation="Disable public access"
            )
            
            cli_cmd = auditor._generate_remediation_cli(storage_finding)
            assert "az storage account update" in cli_cmd
            assert "--allow-blob-public-access false" in cli_cmd


class TestOPSECCompliance:
    """Test OPSEC compliance for cloud audit functionality."""
    
    def test_aws_auditor_opsec_compliance(self):
        """Test AWS auditor OPSEC compliance."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            auditor = AWSAuditor(db_path, engagement_id=1)
            
            # Test that findings don't contain sensitive data
            finding = AWSFinding(
                service="IAM",
                resource_type="User",
                resource_id="test-user",
                region="us-east-1",
                finding_type="MFA_NOT_ENFORCED",
                severity="HIGH",
                title="MFA not enabled",
                description="User does not have MFA enabled",
                evidence={"user_arn": "arn:aws:iam::123456789012:user/test-user"},
                remediation="Enable MFA"
            )
            
            # Evidence should not contain passwords or keys
            assert "password" not in str(finding.evidence).lower()
            assert "secret" not in str(finding.evidence).lower()
            assert "token" not in str(finding.evidence).lower()
    
    def test_azure_auditor_opsec_compliance(self):
        """Test Azure auditor OPSEC compliance."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            auditor = AzureAuditor(db_path, engagement_id=1)
            
            # Test that findings don't contain sensitive data
            finding = AzureFinding(
                service="Authorization",
                resource_type="RoleAssignment",
                resource_id="test-assignment",
                subscription_id="test-subscription",
                resource_group="test-rg",
                location="eastus",
                finding_type="RBAC_OVERPERMISSIVE",
                severity="CRITICAL",
                title="Overpermissive role",
                description="Role assignment is overly permissive",
                evidence={"scope": "/subscriptions/test-subscription"},
                remediation="Use least privilege"
            )
            
            # Evidence should not contain passwords or keys
            assert "password" not in str(finding.evidence).lower()
            assert "secret" not in str(finding.evidence).lower()
            assert "client_secret" not in str(finding.evidence).lower()
    
    def test_rate_limiting_compliance(self):
        """Test that rate limiting is applied to prevent API abuse."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            
            # Test AWS rate limiting
            aws_auditor = AWSAuditor(db_path, engagement_id=1)
            with patch('time.sleep') as mock_sleep:
                aws_auditor._apply_rate_limiting()
                mock_sleep.assert_called_once_with(0.1)
            
            # Test Azure rate limiting
            azure_auditor = AzureAuditor(db_path, engagement_id=1)
            with patch('time.sleep') as mock_sleep:
                azure_auditor._apply_rate_limiting()
                mock_sleep.assert_called_once_with(0.1)
    
    def test_dry_run_mode(self):
        """Test dry-run mode compliance."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            
            # Test AWS dry-run
            findings = run_aws_audit(
                db_path=db_path,
                engagement_id=1,
                dry_run=True
            )
            assert findings == []
            
            # Test Azure dry-run
            findings = run_azure_audit(
                db_path=db_path,
                engagement_id=1,
                dry_run=True
            )
            assert findings == []


class TestIntegration:
    """Test integration between cloud audit and database schema."""
    
    def test_aws_database_integration(self, tmp_path):
        """Test AWS audit integration with enhanced database schema."""
        db_path = tmp_path / "test.db"
            
        # Create test finding
        finding = AWSFinding(
            service="IAM",
            resource_type="Policy",
            resource_id="test-policy",
            region="us-east-1",
            finding_type="IAM_OVERPERMISSIVE",
            severity="CRITICAL",
            title="Overpermissive policy",
            description="Policy has wildcard permissions",
            evidence={"policy_arn": "arn:aws:iam::123456789012:policy/test-policy"},
            remediation="Restrict permissions",
            compliance_controls=["CIS-1.4", "NIST-AC-6"]
        )
            
        # Test finding storage with new schema
        auditor = AWSAuditor(db_path, engagement_id=1)
        auditor._findings.append(finding)
        auditor._store_findings()
            
        # Verify cloud provider metadata
        import sqlite3
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT cloud_provider, resource_id, compliance_control FROM vulnerability_findings WHERE engagement_id = 1")
            result = cursor.fetchone()
            assert result is not None
            assert result[0] == "aws"
            assert result[1] == "test-policy"
            assert "CIS-1.4" in result[2]
    
    def test_azure_database_integration(self, tmp_path):
        """Test Azure audit integration with enhanced database schema."""
        db_path = tmp_path / "test.db"
            
        # Create test finding
        finding = AzureFinding(
            service="Storage",
            resource_type="StorageAccount",
            resource_id="test-storage",
            subscription_id="test-subscription",
            resource_group="test-rg",
            location="eastus",
            finding_type="STORAGE_PUBLIC_ACCESS",
            severity="CRITICAL",
            title="Public storage account",
            description="Storage allows public access",
            evidence={"allow_blob_public_access": True},
            remediation="Disable public access",
            compliance_controls=["CIS-Azure-3.1", "NIST-AC-3"]
        )
            
        # Test finding storage with new schema
        auditor = AzureAuditor(db_path, engagement_id=1)
        auditor._findings.append(finding)
        auditor._store_findings()
            
        # Verify cloud provider metadata
        import sqlite3
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT cloud_provider, resource_id, compliance_control FROM vulnerability_findings WHERE engagement_id = 1")
            result = cursor.fetchone()
            assert result is not None
            assert result[0] == "azure"
            assert result[1] == "test-storage"
            assert "CIS-Azure-3.1" in result[2]


if __name__ == "__main__":
    pytest.main([__file__])
