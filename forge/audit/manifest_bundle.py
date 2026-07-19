"""Portable export bundles for run audit manifests."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from forge.audit.manifest import (
    read_run_audit_manifest,
    verify_run_audit_manifest,
)

_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


@dataclass(frozen=True)
class AuditManifestBundle:
    path: Path
    bundle_sha256: str
    manifest_hash: str
    verification_ok: bool
    files: tuple[str, ...]


def export_run_audit_manifest_bundle(
    conn: sqlite3.Connection,
    *,
    db_path: Path,
    engagement_id: int,
    run_id: int,
    output_path: Path | None = None,
    exported_at: str | None = None,
) -> AuditManifestBundle:
    """Write a portable manifest bundle suitable for external archival."""
    record = read_run_audit_manifest(conn, engagement_id=engagement_id, run_id=run_id)
    if record is None:
        raise ValueError("manifest not found")

    verification = verify_run_audit_manifest(
        conn,
        db_path=db_path,
        engagement_id=engagement_id,
        run_id=run_id,
    )
    exported_at = exported_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    verification_payload = {
        "schema": "forge.run_audit_manifest_bundle.v1",
        "exported_at": exported_at,
        "engagement_id": int(engagement_id),
        "run_id": int(run_id),
        "database_name": Path(db_path).name,
        "manifest_hash": record.manifest_hash,
        "previous_manifest_hash": record.previous_manifest_hash,
        "verification": {
            "ok": verification.ok,
            "stored_hash": verification.stored_hash,
            "recomputed_hash": verification.recomputed_hash,
            "reason": verification.reason,
        },
    }
    manifest_bytes = record.manifest_json.encode("utf-8")
    verification_bytes = _pretty_json_bytes(verification_payload)
    readme_bytes = _readme_text(verification_payload).encode("utf-8")
    files = {
        "README.md": readme_bytes,
        "manifest.json": manifest_bytes,
        "verification.json": verification_bytes,
    }
    checksums = _checksum_lines(files).encode("utf-8")
    files["checksums.sha256"] = checksums

    bundle_path = output_path or _default_bundle_path(
        engagement_id=engagement_id,
        run_id=run_id,
        manifest_hash=record.manifest_hash,
    )
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    _write_zip(bundle_path, files)
    return AuditManifestBundle(
        path=bundle_path,
        bundle_sha256=hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
        manifest_hash=record.manifest_hash,
        verification_ok=verification.ok,
        files=tuple(sorted(files)),
    )


def _default_bundle_path(
    *,
    engagement_id: int,
    run_id: int,
    manifest_hash: str,
) -> Path:
    short_hash = manifest_hash[:12] or "nohash"
    return Path("reports") / f"engagement_{engagement_id}_run_{run_id}_manifest_{short_hash}.zip"


def _pretty_json_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def _checksum_lines(files: dict[str, bytes]) -> str:
    lines = [
        f"{hashlib.sha256(data).hexdigest()}  {name}"
        for name, data in sorted(files.items())
    ]
    return "\n".join(lines) + "\n"


def _write_zip(path: Path, files: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, mode="w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, _ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, data)


def _readme_text(payload: dict[str, Any]) -> str:
    ok = "yes" if payload["verification"]["ok"] else "no"
    reason = payload["verification"]["reason"] or "none"
    return "\n".join(
        [
            "# FORGE Run Audit Manifest Bundle",
            "",
            f"Engagement: {payload['engagement_id']}",
            f"Run: {payload['run_id']}",
            f"Manifest hash: {payload['manifest_hash']}",
            f"Verified at export: {ok}",
            f"Verification reason: {reason}",
            "",
            "Files:",
            "- manifest.json: stored hash-chain manifest from the engagement DB.",
            "- verification.json: export-time verification receipt.",
            "- checksums.sha256: SHA-256 checksums for files in this bundle.",
            "",
            "The manifest contains deterministic hashes and row references, not raw DB rows.",
            "",
        ]
    )
