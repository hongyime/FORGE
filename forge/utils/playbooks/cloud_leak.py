"""Playbook 2: Cloud Leak Exploitation Loop.

Trigger: key_scanner (Module 2-J) finds a cloud key.
Steps:
  1. Auto-Validation — confirm key is active via cloud provider API
  2. Auto-Enumeration — list accessible resources if key is valid
  3. Queue-Extraction — scan readable storage for sensitive files

OPSEC: Strict rate limiting. Proxy mandatory for validation calls.
Checks _SHUTDOWN at top of every step.
"""
from __future__ import annotations

import logging
import sqlite3
import sys
from typing import Any, Optional

from forge.opsec.rate_limiter import AdaptiveRateLimiter
from forge.opsec.resilience import _SHUTDOWN, _interruptible_sleep, wait_for_internet, with_internet_retry
from forge.phase5.approval_gate import ActionClassification, request_approval
from forge.utils.cloud_exposure_gate import (
    is_reportable_cloud_validation,
    normalize_cloud_exposure_asset_type,
)
from forge.utils.validation_proof import parse_validated_detail

_LOG = logging.getLogger(__name__)

_RATE_LIMITER = AdaptiveRateLimiter(base_delay=2.0, max_delay=30.0, min_delay=2.0)


def _validation_asset_types_for_key_service(service: str) -> list[str]:
    normalized = normalize_cloud_exposure_asset_type(service)
    return {
        "amazon": ["aws_s3"],
        "aws": ["aws_s3"],
        "azure": ["azure_blob"],
        "digitalocean": ["do_spaces"],
        "do": ["do_spaces"],
        "firebase": ["firebase"],
        "gcp": ["gcs"],
        "google": ["gcs"],
        "supabase": ["supabase"],
    }.get(normalized, [normalized] if normalized else [])


def _linked_cloud_validation_is_reportable(
    conn: sqlite3.Connection,
    engagement_id: int,
    service: str,
    domain: str,
) -> bool:
    identifier = str(domain or "").strip().lower()
    if not identifier:
        return False
    for asset_type in _validation_asset_types_for_key_service(service):
        try:
            rows = conn.execute(
                """
                SELECT validation_status, validation_method
                FROM cloud_validation_results
                WHERE engagement_id=? AND asset_type=? AND lower(identifier)=?
                ORDER BY COALESCE(checked_at, '') DESC, id DESC
                """,
                (engagement_id, asset_type, identifier),
            ).fetchall()
        except sqlite3.Error:
            continue
        if any(
            is_reportable_cloud_validation(asset_type, row[0], row[1])
            for row in rows
        ):
            return True
    return False


def _active_key_is_reportable(
    conn: sqlite3.Connection,
    engagement_id: int,
    service: str,
    domain: str,
    validation_detail: object,
) -> bool:
    proof = parse_validated_detail(validation_detail)
    if str(proof["validation_status"] or "").strip().upper() == "VALIDATED":
        return True
    return _linked_cloud_validation_is_reportable(conn, engagement_id, service, domain)


def run_cloud_leak_playbook(
    engagement_id: int,
    key_finding_id: int,
    eng_db_conn: sqlite3.Connection,
    validation_proxy: Optional[str] = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Execute Cloud Leak playbook for a discovered key finding.

    Returns: {'validated': bool, 'resources': list, 'sensitive_files': list}
    """
    if _SHUTDOWN.is_set():
        return _empty_result()

    # Load key finding
    row = eng_db_conn.execute(
        """
        SELECT service, key_enc, validation_state, domain, validation_detail
        FROM key_scanner_findings
        WHERE id=? AND engagement_id=?
        """,
        (key_finding_id, engagement_id),
    ).fetchone()

    if not row:
        _LOG.error("Cloud Leak: finding %d not found", key_finding_id)
        return _empty_result()

    service, key_enc, validation_state, domain, validation_detail = row

    print(f"[CLOUD LEAK] Playbook starting for {service} key in finding {key_finding_id}", flush=True)
    sys.stdout.flush()

    # --- Step 1: Validation ---
    if _SHUTDOWN.is_set():
        return _empty_result()

    if validation_state == "ACTIVE" and not _active_key_is_reportable(
        eng_db_conn,
        engagement_id,
        service,
        domain,
        validation_detail,
    ):
        print("[CLOUD LEAK] Key ACTIVE state lacks deterministic proof — playbook stopped.", flush=True)
        return _empty_result()

    if validation_state != "ACTIVE":
        validated = _validate_key(service, key_enc, validation_proxy)
        if not validated:
            print(f"[CLOUD LEAK] Key not active — playbook stopped at validation.", flush=True)
            return {"validated": False, "resources": [], "sensitive_files": []}

        eng_db_conn.execute(
            "UPDATE key_scanner_findings SET validation_state='ACTIVE', validated_at=datetime('now') WHERE id=?",
            (key_finding_id,),
        )
        eng_db_conn.commit()
    else:
        validated = True

    print(f"[CLOUD LEAK] Step 1 PASS: key validated as ACTIVE", flush=True)

    # --- Step 2: Enumeration ---
    if _SHUTDOWN.is_set():
        return {"validated": validated, "resources": [], "sensitive_files": []}

    resources = _enumerate_resources(service, key_enc, validation_proxy, dry_run)
    print(f"[CLOUD LEAK] Step 2: {len(resources)} resources enumerated", flush=True)
    sys.stdout.flush()

    # --- Step 3: Sensitive file extraction queue ---
    if _SHUTDOWN.is_set():
        return {"validated": validated, "resources": resources, "sensitive_files": []}

    sensitive_files = []
    for resource in resources:
        if _SHUTDOWN.is_set():
            break
        approved = request_approval(
            "cloud_file_extraction",
            f"Scan {resource['name']} for sensitive files",
            engagement_id,
            eng_db_conn,
            ActionClassification.DESTRUCTIVE,
        )
        if approved and not dry_run:
            files = _scan_storage(service, key_enc, resource, validation_proxy)
            sensitive_files.extend(files)
            _interruptible_sleep(2.0)

    print(f"[CLOUD LEAK] Step 3: {len(sensitive_files)} sensitive files found", flush=True)
    sys.stdout.flush()

    return {"validated": validated, "resources": resources, "sensitive_files": sensitive_files}


def _validate_key(service: str, key_enc: Optional[str], proxy: Optional[str]) -> bool:
    if not key_enc:
        return False
    if not wait_for_internet():
        return False
    _RATE_LIMITER.wait(f"https://validation.{service}.com")
    try:
        from forge.opsec.crypto import decrypt_string
        key = decrypt_string(key_enc)
    except Exception:
        return False

    # Service-specific validation
    if service == "aws":
        return _validate_aws(key, proxy)
    if service == "github":
        from forge.phase2.key_scanner import GithubPatValidator, ValidationState
        result = GithubPatValidator().validate(key, proxy=proxy)
        return result.state == ValidationState.ACTIVE
    if service == "stripe":
        from forge.phase2.key_scanner import StripeKeyValidator, ValidationState
        result = StripeKeyValidator().validate(key, proxy=proxy)
        return result.state == ValidationState.ACTIVE
    return False


def _validate_aws(key: str, proxy: Optional[str]) -> bool:
    return False  # AWS requires key+secret pair — UNCONFIRMED by default


def _enumerate_resources(service: str, key_enc: Optional[str], proxy: Optional[str], dry_run: bool) -> list[dict]:
    if dry_run:
        return [{"name": f"[dry-run-{service}-bucket]", "type": "storage"}]
    if service == "aws":
        return _enumerate_aws_buckets(key_enc, proxy)
    if service in ("firebase", "supabase"):
        return [{"name": f"{service}-project", "type": "database"}]
    return []


def _enumerate_aws_buckets(key_enc: Optional[str], proxy: Optional[str]) -> list[dict]:
    return []  # requires boto3 or signed requests — stub


def _scan_storage(service: str, key_enc: Optional[str], resource: dict, proxy: Optional[str]) -> list[str]:
    from forge.phase5.exfiltration import PRIORITY_PATTERNS
    return []  # stub — real impl fetches file listing and matches PRIORITY_PATTERNS


def _empty_result() -> dict[str, Any]:
    return {"validated": False, "resources": [], "sensitive_files": []}
