"""Portable export bundles for run audit manifests."""

from __future__ import annotations

import hashlib
import hmac
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
_SIGNATURE_SCHEMA = "forge.run_audit_manifest_signature.v1"
_SIGNATURE_ALGORITHM = "HMAC-SHA256"


@dataclass(frozen=True)
class AuditManifestBundle:
    path: Path
    bundle_sha256: str
    manifest_hash: str
    verification_ok: bool
    files: tuple[str, ...]
    signature_present: bool = False


@dataclass(frozen=True)
class AuditManifestBundleSignatureVerification:
    ok: bool
    reason: str | None = None
    signer_id: str | None = None
    actual_signature: str | None = None
    expected_signature: str | None = None


def export_run_audit_manifest_bundle(
    conn: sqlite3.Connection,
    *,
    db_path: Path,
    engagement_id: int,
    run_id: int,
    output_path: Path | None = None,
    exported_at: str | None = None,
    signing_key: str | bytes | None = None,
    signer_id: str | None = None,
    signed_at: str | None = None,
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
    if signing_key is not None:
        files["signature.json"] = _signature_bytes(
            files,
            signing_key=signing_key,
            signer_id=signer_id,
            signed_at=signed_at or exported_at,
        )

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
        signature_present=signing_key is not None,
    )


def verify_run_audit_manifest_bundle_signature(
    bundle_path: Path,
    *,
    signing_key: str | bytes,
) -> AuditManifestBundleSignatureVerification:
    """Verify a signed manifest bundle without requiring the engagement DB."""
    key = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
    if not key:
        return AuditManifestBundleSignatureVerification(ok=False, reason="signing key is empty")
    try:
        with zipfile.ZipFile(bundle_path) as archive:
            names = archive.namelist()
            duplicate = _first_duplicate(names)
            if duplicate is not None:
                return AuditManifestBundleSignatureVerification(
                    ok=False,
                    reason=f"duplicate zip entry: {duplicate}",
                )
            try:
                payload = json.loads(archive.read("signature.json"))
            except KeyError:
                return AuditManifestBundleSignatureVerification(
                    ok=False,
                    reason="signature.json not found",
                )
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                return AuditManifestBundleSignatureVerification(
                    ok=False,
                    reason=f"invalid signature.json: {exc}",
                )
            if not isinstance(payload, dict):
                return AuditManifestBundleSignatureVerification(
                    ok=False,
                    reason="signature payload is not an object",
                )
            if payload.get("schema") != _SIGNATURE_SCHEMA:
                return AuditManifestBundleSignatureVerification(
                    ok=False,
                    reason="unsupported signature schema",
                )
            if payload.get("algorithm") != _SIGNATURE_ALGORITHM:
                return AuditManifestBundleSignatureVerification(
                    ok=False,
                    reason="unsupported signature algorithm",
                )
            actual_signature = payload.get("signature")
            if not isinstance(actual_signature, str) or not actual_signature:
                return AuditManifestBundleSignatureVerification(
                    ok=False,
                    reason="signature is missing",
                )
            signed_files = payload.get("signed_files")
            if not isinstance(signed_files, dict):
                return AuditManifestBundleSignatureVerification(
                    ok=False,
                    reason="signed_files is missing",
                )
            unsigned = sorted(set(names) - (set(signed_files) | {"signature.json"}))
            if unsigned:
                return AuditManifestBundleSignatureVerification(
                    ok=False,
                    reason=f"unsigned zip entry: {unsigned[0]}",
                )
            for name, expected_hash in signed_files.items():
                if (
                    name == "signature.json"
                    or not isinstance(name, str)
                    or not _safe_zip_name(name)
                ):
                    return AuditManifestBundleSignatureVerification(
                        ok=False,
                        reason="invalid signed file entry",
                    )
                if not isinstance(expected_hash, str) or not _is_sha256(expected_hash):
                    return AuditManifestBundleSignatureVerification(
                        ok=False,
                        reason=f"invalid signed file hash: {name}",
                    )
                try:
                    actual_hash = hashlib.sha256(archive.read(name)).hexdigest()
                except KeyError:
                    return AuditManifestBundleSignatureVerification(
                        ok=False,
                        reason=f"signed file missing: {name}",
                    )
                if actual_hash != str(expected_hash):
                    return AuditManifestBundleSignatureVerification(
                        ok=False,
                        reason=f"signed file hash mismatch: {name}",
                    )
    except zipfile.BadZipFile:
        return AuditManifestBundleSignatureVerification(ok=False, reason="invalid zip bundle")
    except FileNotFoundError:
        return AuditManifestBundleSignatureVerification(ok=False, reason="bundle not found")
    except OSError as exc:
        return AuditManifestBundleSignatureVerification(
            ok=False,
            reason=f"bundle read failed: {exc}",
        )

    unsigned = {key_name: payload[key_name] for key_name in payload if key_name != "signature"}
    expected_signature = hmac.new(
        key,
        _canonical_json(unsigned).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    ok = hmac.compare_digest(actual_signature, expected_signature)
    return AuditManifestBundleSignatureVerification(
        ok=ok,
        reason=None if ok else "signature mismatch",
        signer_id=str(payload.get("signer_id") or ""),
        actual_signature=actual_signature,
        expected_signature=expected_signature,
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


def _signature_bytes(
    files: dict[str, bytes],
    *,
    signing_key: str | bytes,
    signer_id: str | None,
    signed_at: str,
) -> bytes:
    key = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
    if not key:
        raise ValueError("signing key must not be empty")
    payload = {
        "schema": "forge.run_audit_manifest_signature.v1",
        "algorithm": "HMAC-SHA256",
        "signed_at": signed_at,
        "signer_id": signer_id or "unspecified",
        "signed_files": {
            name: hashlib.sha256(data).hexdigest()
            for name, data in sorted(files.items())
        },
    }
    signature = hmac.new(key, _canonical_json(payload).encode("utf-8"), hashlib.sha256)
    return _pretty_json_bytes({**payload, "signature": signature.hexdigest()})


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _first_duplicate(names: list[str]) -> str | None:
    seen: set[str] = set()
    for name in names:
        if name in seen:
            return name
        seen.add(name)
    return None


def _safe_zip_name(name: str) -> bool:
    parts = name.replace("\\", "/").split("/")
    return (
        bool(name)
        and not name.startswith("/")
        and all(part not in {"", ".", ".."} for part in parts)
    )


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


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
