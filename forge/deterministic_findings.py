from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.utils.cloud_exposure_gate import (
    CLOUD_DATA_VALIDATION_METHODS,
    STORAGE_CLOUD_ASSET_TYPES,
    STORAGE_LISTING_VALIDATION_METHODS,
    STORAGE_METADATA_VALIDATION_METHODS,
    is_reportable_cloud_validation,
    latest_cloud_validation_reportability_index,
)
from forge.utils.key_validation_gate import (
    key_validation_detail_is_reportable,
    linked_key_validation_reportability,
)
from forge.utils.validation_proof import parse_validated_detail
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@dataclass
class FindingSynthesisSummary:
    inserted: int = 0
    updated: int = 0
    removed: int = 0
    active_findings: int = 0
    severity_summary: dict[str, int] = field(default_factory=dict)


@dataclass
class FindingSpec:
    vuln_type: str
    target_url: str
    parameter: str
    severity: str
    title: str
    description: str
    evidence: str
    cloud_provider: str | None = None
    resource_id: str | None = None
    compliance_control: str | None = None
    remediation_cli: str | None = None


def finding_synthesis_audit_result(
    summary: FindingSynthesisSummary,
    *,
    pass_label: str,
) -> str:
    return (
        f"pass={pass_label} "
        f"inserted={summary.inserted} "
        f"updated={summary.updated} "
        f"removed={summary.removed} "
        f"active={summary.active_findings} "
        f"severity_summary={json.dumps(summary.severity_summary, sort_keys=True)}"
    )


def finding_synthesis_log_message(summary: FindingSynthesisSummary) -> str | None:
    if not (summary.inserted or summary.updated or summary.removed):
        return None
    return (
        f"inserted={summary.inserted} "
        f"updated={summary.updated} "
        f"removed={summary.removed} "
        f"active={summary.active_findings}"
    )


def _table_columns(con: sqlite3.Connection, table_name: str) -> set[str]:
    try:
        return {str(row[1]) for row in con.execute(f"PRAGMA table_info({table_name})").fetchall()}
    except sqlite3.OperationalError:
        return set()


def _truncate(value: str | None, limit: int) -> str:
    return str(value or "")[:limit]


def _audit(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    action: str,
    target: str,
    result: str,
) -> None:
    try:
        con.execute(
            """
            INSERT INTO audit_log
                (engagement_id, phase, module, action, target, result, operator)
            VALUES (?, 'phase4', 'deterministic_findings', ?, ?, ?, 'system')
            """,
            (engagement_id, action, target[:512], result[:1024]),
        )
    except sqlite3.OperationalError:
        return


def _normalize_asset_type(value: str) -> str:
    text = str(value or "").strip().lower()
    if text == "s3":
        return "aws_s3"
    if text == "digitalocean_spaces":
        return "do_spaces"
    if text == "google_cloud_storage":
        return "gcs"
    if text == "azure_blob_storage":
        return "azure_blob"
    return text


def _cloud_provider(asset_type: str) -> str | None:
    return {
        "firebase": "firebase",
        "supabase": "supabase",
        "aws_s3": "aws",
        "do_spaces": "digitalocean",
        "gcs": "gcp",
        "azure_blob": "azure",
    }.get(asset_type)


def _validation_asset_types_for_key_service(service: str) -> tuple[str, ...]:
    normalized = _normalize_asset_type(service)
    return {
        "amazon": ("aws_s3",),
        "aws": ("aws_s3",),
        "azure": ("azure_blob",),
        "digitalocean": ("do_spaces",),
        "do": ("do_spaces",),
        "firebase": ("firebase",),
        "gcp": ("gcs",),
        "google": ("gcs",),
        "supabase": ("supabase",),
    }.get(normalized, (normalized,) if normalized else ())


def _asset_label(asset_type: str) -> str:
    return {
        "firebase": "Firebase project",
        "supabase": "Supabase project",
        "aws_s3": "S3 bucket",
        "do_spaces": "DigitalOcean Spaces bucket",
        "gcs": "Google Cloud Storage bucket",
        "azure_blob": "Azure Blob container",
    }.get(asset_type, asset_type.replace("_", " ").title() or "cloud asset")


def _recommendation_for_cloud(asset_type: str) -> str:
    return {
        "firebase": "Tighten Firebase rules, rotate exposed client credentials, and move sensitive access behind authenticated server-side flows.",
        "supabase": "Review anon-key exposure, enforce row-level security, and route privileged queries through authenticated backend services.",
        "aws_s3": "Block public bucket access, review bucket policies and ACLs, and confirm only intended principals retain object access.",
        "do_spaces": "Disable unintended public Spaces access, review bucket permissions and CDN exposure, and confirm only approved principals can enumerate objects.",
        "gcs": "Restrict public bucket access, review IAM bindings and signed URL policies, and confirm object exposure is intentional.",
        "azure_blob": "Disable unintended anonymous container access, review SAS and RBAC assignments, and confirm only approved principals can enumerate blobs.",
    }.get(
        asset_type,
        "Restrict external access, review exposure controls, and rotate any linked credentials before revalidating the asset.",
    )


def _recommendation_for_key(service: str) -> str:
    return {
        "aws": "Rotate the exposed AWS access key pair, review IAM permissions and CloudTrail activity, and remove long-lived credentials from distributed artifacts.",
        "firebase": "Rotate the exposed Firebase key, audit client-side configuration, and ensure sensitive operations require authenticated backend mediation.",
        "slack": "Rotate the exposed Slack token, review granted app scopes and workspace audit logs, and remove chat-automation credentials from distributed artifacts.",
        "supabase": "Rotate the exposed Supabase key, verify row-level security coverage, and keep privileged keys out of distributed client artifacts.",
        "aws_s3": "Rotate any exposed AWS credentials, review IAM policies, and confirm bucket access is not granted through embedded client secrets.",
        "do_spaces": "Rotate any exposed DigitalOcean Spaces credentials, review bucket policies, and remove object-storage secrets from distributed client artifacts.",
        "gcs": "Rotate any exposed Google Cloud credentials, review IAM bindings, and remove bucket access from distributed client artifacts.",
        "azure": "Rotate the exposed Azure storage account key, review storage access policies and diagnostics, and remove long-lived storage credentials from distributed artifacts.",
        "azure_blob": "Rotate any exposed Azure storage credentials or SAS tokens, review RBAC assignments, and remove them from distributed client artifacts.",
    }.get(
        service,
        "Rotate the exposed credential, remove it from distributed artifacts, and confirm replacement secrets are scoped to least privilege.",
    )


def _storage_listing_title(asset_type: str) -> str:
    return {
        "aws_s3": "Validated public S3 bucket listing exposure",
        "do_spaces": "Validated public DigitalOcean Spaces bucket listing exposure",
        "gcs": "Validated public Google Cloud Storage bucket listing exposure",
        "azure_blob": "Validated public Azure Blob container listing exposure",
    }.get(asset_type, f"Validated public {_asset_label(asset_type)} listing exposure")


def _is_low_signal_public_cloud_metadata(
    asset_type: str,
    validation_method: str,
) -> bool:
    method = str(validation_method or "").strip().lower()
    asset = str(asset_type or "").strip().lower()
    return asset == "firebase" and method in {
        "firebase_init_json",
        "firebase_web_app_init_json",
    }


def _is_reportable_linked_key_validation(row: sqlite3.Row) -> bool:
    status = str(row["validation_status"] or "").upper().strip()
    if status != "VALIDATED":
        return False
    method = str(row["validation_method"] or "").strip()
    proof = str(row["evidence"] or row["notes"] or "").strip()
    parsed = parse_validated_detail(f"VALIDATED:{method}:{proof}")
    return parsed["validation_status"] == "VALIDATED"


class DeterministicFindingEngine:
    def __init__(self, db_path: Path, engagement_id: int) -> None:
        self._db_path = db_path
        self._engagement_id = engagement_id

    def run(self) -> FindingSynthesisSummary:
        summary = FindingSynthesisSummary()
        con = direct_connect(self._db_path)
        con.row_factory = sqlite3.Row
        try:
            apply_schema(con)
            run_migrations(con)
            columns = _table_columns(con, "vulnerability_findings")
            validation_columns = _table_columns(con, "cloud_validation_results")
            checked_expr = (
                "COALESCE(checked_at, '')" if "checked_at" in validation_columns else "''"
            )
            id_expr = "id" if "id" in validation_columns else "0"
            validation_index = self._validation_index(con)

            cloud_validation_rows = con.execute(
                f"""
                SELECT asset_type, identifier, validation_status, validation_method,
                       http_status, evidence, notes, {checked_expr} AS checked_at_sort,
                       {id_expr} AS id_sort
                FROM cloud_validation_results
                WHERE engagement_id=?
                """,
                (self._engagement_id,),
            ).fetchall()
            cloud_validation_rows = sorted(
                cloud_validation_rows,
                key=lambda row: (
                    _normalize_asset_type(str(row["asset_type"] or "")),
                    str(row["identifier"] or "").strip().lower(),
                    str(row["checked_at_sort"] or ""),
                    int(row["id_sort"] or 0),
                ),
            )
            for row in cloud_validation_rows:
                spec = self._build_cloud_finding(row)
                if spec is None:
                    target_url = self._cloud_target_url(
                        _normalize_asset_type(str(row["asset_type"] or "")),
                        str(row["identifier"] or ""),
                    )
                    removed = self._delete_finding(
                        con,
                        "DETERMINISTIC_CLOUD_EXPOSURE",
                        target_url,
                        _normalize_asset_type(str(row["asset_type"] or "")),
                    )
                    summary.removed += removed
                    _audit(
                        con,
                        self._engagement_id,
                        action="deterministic_finding_rule_skipped",
                        target=target_url,
                        result=(
                            "rule=DETERMINISTIC_CLOUD_EXPOSURE "
                            f"asset_type={_normalize_asset_type(str(row['asset_type'] or ''))} "
                            f"identifier={str(row['identifier'] or '').strip()} "
                            f"validation_status={str(row['validation_status'] or '').strip().upper()} "
                            f"validation_method={str(row['validation_method'] or '').strip()} "
                            f"removed={removed}"
                        ),
                    )
                    continue
                inserted, updated = self._upsert_finding(con, spec, columns)
                summary.inserted += inserted
                summary.updated += updated
                _audit(
                    con,
                    self._engagement_id,
                    action="deterministic_finding_rule_applied",
                    target=spec.target_url,
                    result=(
                        f"rule={spec.vuln_type} severity={spec.severity} "
                        f"asset_type={spec.parameter} resource_id={spec.resource_id or ''} "
                        f"validation_status={str(row['validation_status'] or '').strip().upper()} "
                        f"validation_method={str(row['validation_method'] or '').strip()} "
                        f"inserted={inserted} updated={updated}"
                    ),
                )

            for row in con.execute(
                """
                SELECT service, domain, pattern_name, source_backend, source_url, repo_name, key_redacted, validation_state, validation_detail
                FROM key_scanner_findings
                WHERE engagement_id=?
                ORDER BY id ASC
                """,
                (self._engagement_id,),
            ).fetchall():
                spec = self._build_key_finding(row, validation_index)
                service = _normalize_asset_type(str(row["service"] or ""))
                domain = str(row["domain"] or "").strip()
                target_url = (
                    str(row["source_url"] or "").strip()
                    or str(row["repo_name"] or "").strip()
                    or (f"{service}://{domain}" if domain else f"{service}://unknown")
                )
                parameter = f"{service}:{str(row['pattern_name'] or '').strip()}"
                if spec is None:
                    summary.removed += self._delete_finding(
                        con,
                        "DETERMINISTIC_KEY_EXPOSURE",
                        target_url,
                        parameter,
                    )
                    continue
                inserted, updated = self._upsert_finding(con, spec, columns)
                summary.inserted += inserted
                summary.updated += updated

            summary.severity_summary = self._severity_summary(con)
            summary.active_findings = sum(summary.severity_summary.values())
            con.commit()
        finally:
            con.close()
        return summary

    def _validation_index(self, con: sqlite3.Connection) -> dict[tuple[str, str], bool]:
        return latest_cloud_validation_reportability_index(
            con,
            self._engagement_id,
            require_stable_proof=True,
        )

    @staticmethod
    def _cloud_target_url(asset_type: str, identifier: str) -> str:
        return f"{asset_type}://{identifier.strip()}"

    def _build_cloud_finding(self, row: sqlite3.Row) -> FindingSpec | None:
        asset_type = _normalize_asset_type(str(row["asset_type"] or ""))
        identifier = str(row["identifier"] or "").strip()
        validation_status = str(row["validation_status"] or "").upper().strip()
        validation_method = str(row["validation_method"] or "").strip()
        evidence = _truncate(str(row["evidence"] or "").strip(), 512)
        notes = _truncate(str(row["notes"] or "").strip(), 280)

        if not asset_type or not identifier or _cloud_provider(asset_type) is None:
            return None

        title = ""
        description = ""
        severity = ""
        if not is_reportable_cloud_validation(
            asset_type,
            validation_status,
            validation_method,
            evidence=evidence,
            notes=notes,
            require_stable_proof=True,
        ):
            return None

        if validation_status == "VALIDATED":
            if (
                asset_type == "firebase"
                and validation_method in CLOUD_DATA_VALIDATION_METHODS["firebase"]
            ):
                severity = "HIGH"
                title = "Validated Firebase data exposure"
                description = (
                    f"Deterministic validation confirmed that the Firebase database for `{identifier}` "
                    f"returned live data through `{validation_method}` without requiring an authenticated session."
                )
            elif asset_type == "supabase" and validation_method == "supabase_rest_root":
                severity = "HIGH"
                title = "Validated Supabase data exposure"
                description = (
                    f"Deterministic validation confirmed that the Supabase REST endpoint for `{identifier}` "
                    f"returned live data through `{validation_method}` using the discovered project credential."
                )
            elif _is_low_signal_public_cloud_metadata(asset_type, validation_method):
                return None
            elif (
                asset_type in STORAGE_CLOUD_ASSET_TYPES
                and validation_method in STORAGE_LISTING_VALIDATION_METHODS
            ):
                severity = "HIGH"
                title = _storage_listing_title(asset_type)
                description = (
                    f"Deterministic validation confirmed that `{identifier}` allowed unauthenticated enumeration "
                    f"of real object metadata through `{validation_method}`."
                )
            elif (
                asset_type in STORAGE_CLOUD_ASSET_TYPES
                and validation_method in STORAGE_METADATA_VALIDATION_METHODS
            ):
                severity = "LOW"
                title = f"Externally reachable {_asset_label(asset_type)} detected"
                description = (
                    f"Deterministic validation confirmed that `{identifier}` responded successfully "
                    f"to a low-impact probe. Additional policy review is required before escalating beyond metadata exposure."
                )
            else:
                return None
        else:
            return None

        if notes:
            description = f"{description} {notes}"

        return FindingSpec(
            vuln_type="DETERMINISTIC_CLOUD_EXPOSURE",
            target_url=self._cloud_target_url(asset_type, identifier),
            parameter=asset_type,
            severity=severity,
            title=title,
            description=_truncate(description, 1024),
            evidence=evidence
            or _truncate(f"validation_method={validation_method} status={validation_status}", 512),
            cloud_provider=_cloud_provider(asset_type),
            resource_id=identifier,
            compliance_control="ACCESS_CONTROL",
            remediation_cli=_recommendation_for_cloud(asset_type),
        )

    def _build_key_finding(
        self,
        row: sqlite3.Row,
        validation_index: dict[tuple[str, str], bool],
    ) -> FindingSpec | None:
        service = _normalize_asset_type(str(row["service"] or ""))
        domain = str(row["domain"] or "").strip()
        pattern_name = str(row["pattern_name"] or "").strip()
        source_backend = str(row["source_backend"] or "").strip()
        source_url = str(row["source_url"] or "").strip()
        repo_name = str(row["repo_name"] or "").strip()
        key_redacted = str(row["key_redacted"] or "").strip()
        validation_state = str(row["validation_state"] or "").upper().strip()
        validation_detail = _truncate(str(row["validation_detail"] or "").strip(), 280)
        if validation_state != "ACTIVE" or not service:
            return None

        linked_reportable = linked_key_validation_reportability(
            validation_index,
            service,
            domain,
            validation_detail,
            asset_aliases=_validation_asset_types_for_key_service(service),
        )
        if linked_reportable is not None:
            confirmed = linked_reportable
        else:
            confirmed = key_validation_detail_is_reportable(service, validation_detail)
        if not confirmed:
            return None
        description = (
            f"A deterministic validator marked the exposed `{service}` credential reference as ACTIVE. "
            f"The secret was discovered in `{source_url or repo_name or domain or service}` via pattern `{pattern_name}`."
        )
        if validation_detail:
            description = f"{description} {validation_detail}"
        target_url = (
            source_url
            or repo_name
            or (f"{service}://{domain}" if domain else f"{service}://unknown")
        )
        evidence_parts = [
            f"key={key_redacted}" if key_redacted else f"pattern={pattern_name}",
            f"backend={source_backend}" if source_backend else "",
            f"source={source_url}" if source_url else "",
            f"repo={repo_name}" if repo_name else "",
            f"validation={validation_detail}" if validation_detail else "",
        ]
        evidence = "; ".join(part for part in evidence_parts if part)
        return FindingSpec(
            vuln_type="DETERMINISTIC_KEY_EXPOSURE",
            target_url=target_url,
            parameter=f"{service}:{pattern_name}",
            severity="HIGH",
            title=f"Validated exposed {service} credential reference",
            description=_truncate(description, 1024),
            evidence=_truncate(evidence, 512),
            cloud_provider=_cloud_provider(service),
            resource_id=domain or None,
            compliance_control="SECRET_MANAGEMENT",
            remediation_cli=_recommendation_for_key(service),
        )

    def _delete_finding(
        self,
        con: sqlite3.Connection,
        vuln_type: str,
        target_url: str,
        parameter: str,
    ) -> int:
        before = con.total_changes
        con.execute(
            """
            DELETE FROM vulnerability_findings
            WHERE engagement_id=? AND vuln_type=? AND target_url=? AND parameter=?
            """,
            (self._engagement_id, vuln_type, target_url, parameter),
        )
        return 1 if con.total_changes > before else 0

    def _upsert_finding(
        self,
        con: sqlite3.Connection,
        spec: FindingSpec,
        columns: set[str],
    ) -> tuple[int, int]:
        row = con.execute(
            """
            SELECT severity, title, description, evidence
            FROM vulnerability_findings
            WHERE engagement_id=? AND vuln_type=? AND target_url=? AND parameter=?
            """,
            (self._engagement_id, spec.vuln_type, spec.target_url, spec.parameter),
        ).fetchone()

        payload: dict[str, Any] = {
            "engagement_id": self._engagement_id,
            "vuln_type": spec.vuln_type,
            "target_url": spec.target_url,
            "parameter": spec.parameter,
            "severity": spec.severity,
            "title": spec.title,
            "description": spec.description,
            "evidence": spec.evidence,
            "cvss_score": None,
        }
        if "cloud_provider" in columns:
            payload["cloud_provider"] = spec.cloud_provider
        if "resource_id" in columns:
            payload["resource_id"] = spec.resource_id
        if "compliance_control" in columns:
            payload["compliance_control"] = spec.compliance_control
        if "remediation_cli" in columns:
            payload["remediation_cli"] = spec.remediation_cli

        if row is None:
            cols = ", ".join(payload.keys())
            placeholders = ", ".join("?" for _ in payload)
            con.execute(
                f"INSERT INTO vulnerability_findings ({cols}) VALUES ({placeholders})",
                tuple(payload.values()),
            )
            return 1, 0

        if (
            str(row["severity"] or "") == spec.severity
            and str(row["title"] or "") == spec.title
            and str(row["description"] or "") == spec.description
            and str(row["evidence"] or "") == spec.evidence
        ):
            return 0, 0

        assignments = ", ".join(
            f"{key}=?"
            for key in payload.keys()
            if key not in {"engagement_id", "vuln_type", "target_url", "parameter"}
        )
        update_values = [
            value
            for key, value in payload.items()
            if key not in {"engagement_id", "vuln_type", "target_url", "parameter"}
        ]
        con.execute(
            f"""
            UPDATE vulnerability_findings
            SET {assignments}, found_at=CURRENT_TIMESTAMP
            WHERE engagement_id=? AND vuln_type=? AND target_url=? AND parameter=?
            """,
            (
                *update_values,
                self._engagement_id,
                spec.vuln_type,
                spec.target_url,
                spec.parameter,
            ),
        )
        return 0, 1

    def _severity_summary(self, con: sqlite3.Connection) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for row in con.execute(
            """
            SELECT UPPER(COALESCE(severity, 'INFO')) AS severity, COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=?
            GROUP BY UPPER(COALESCE(severity, 'INFO'))
            """,
            (self._engagement_id,),
        ).fetchall():
            severity = str(row[0] or "INFO").upper()
            if severity not in counts:
                counts[severity] = 0
            counts[severity] += int(row[1] or 0)

        try:
            passive_rows = con.execute(
                """
                SELECT UPPER(COALESCE(severity, 'INFO')) AS severity, COUNT(*)
                FROM passive_vulns
                WHERE engagement_id=? AND COALESCE(false_positive, 0)=0
                GROUP BY UPPER(COALESCE(severity, 'INFO'))
                """,
                (self._engagement_id,),
            ).fetchall()
        except sqlite3.OperationalError:
            passive_rows = []
        for row in passive_rows:
            severity = str(row[0] or "INFO").upper()
            if severity not in counts:
                counts[severity] = 0
            counts[severity] += int(row[1] or 0)
        return counts
