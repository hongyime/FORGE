from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.phase4.aws_audit import AWSAuditor, AWSFinding, run_aws_audit


def test_aws_audit_dry_run_returns_no_findings(tmp_path: Path):
    db_path = tmp_path / "aws_test.db"
    findings = run_aws_audit(db_path=db_path, engagement_id=1, dry_run=True)
    assert findings == []


def test_aws_audit_stores_cloud_metadata(tmp_path: Path):
    db_path = tmp_path / "aws_test.db"
    auditor = AWSAuditor(db_path=db_path, engagement_id=1)
    auditor._findings.append(
        AWSFinding(
            service="IAM",
            resource_type="Policy",
            resource_id="arn:aws:iam::123456789012:policy/test",
            region="us-east-1",
            finding_type="IAM_OVERPERMISSIVE",
            severity="CRITICAL",
            title="Overly permissive policy",
            description="Policy allows wildcard actions",
            evidence={"statement": "*"},
            remediation="Restrict policy actions",
            compliance_controls=["CIS-1.4", "NIST-AC-6"],
        )
    )
    auditor._store_findings()
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT cloud_provider, resource_id, compliance_control "
            "FROM vulnerability_findings WHERE engagement_id=1 ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert row is not None
    assert row[0] == "aws"
    assert "arn:aws:iam::123456789012:policy/test" in row[1]
    assert "CIS-1.4" in row[2]
