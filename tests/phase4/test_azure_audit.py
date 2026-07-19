from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.phase4.azure_audit import AzureAuditor, AzureFinding, run_azure_audit


def test_azure_audit_dry_run_returns_no_findings(tmp_path: Path):
    db_path = tmp_path / "azure_test.db"
    findings = run_azure_audit(db_path=db_path, engagement_id=1, dry_run=True)
    assert findings == []


def test_azure_audit_stores_cloud_metadata(tmp_path: Path):
    db_path = tmp_path / "azure_test.db"
    auditor = AzureAuditor(db_path=db_path, engagement_id=1)
    auditor._findings.append(
        AzureFinding(
            service="Storage",
            resource_type="StorageAccount",
            resource_id="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a1",
            subscription_id="s1",
            resource_group="rg",
            location="eastus",
            finding_type="STORAGE_PUBLIC_ACCESS",
            severity="CRITICAL",
            title="Public storage account",
            description="Storage account allows public access",
            evidence={"allow_blob_public_access": True},
            remediation="Disable public blob access",
            compliance_controls=["CIS-Azure-3.1"],
        )
    )
    auditor._store_findings()
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT cloud_provider, resource_id, compliance_control "
            "FROM vulnerability_findings WHERE engagement_id=1 ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert row is not None
    assert row[0] == "azure"
    assert "Microsoft.Storage/storageAccounts/a1" in row[1]
    assert "CIS-Azure-3.1" in row[2]
