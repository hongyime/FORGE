"""Append-only remote storage for exported run audit manifest bundles."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import url2pathname

from forge.audit.manifest_bundle import AuditManifestBundle

REMOTE_AUDIT_BUNDLE_URI_ENV = "FORGE_AUDIT_BUNDLE_REMOTE_URI"
REMOTE_AUDIT_BUNDLE_SCOPE_ENV = "FORGE_AUDIT_BUNDLE_REMOTE_SCOPE"
_RECEIPT_SCHEMA = "forge.run_audit_manifest_remote_store.v1"
_SCOPE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")


@dataclass(frozen=True)
class RemoteAuditBundleStore:
    """Validated append-only storage target for manifest bundles."""

    root: Path
    scope: str
    source_uri: str


@dataclass(frozen=True)
class RemoteAuditBundleReceipt:
    """Receipt for an append-only bundle storage attempt."""

    storage_path: Path
    receipt_path: Path
    bundle_sha256: str
    manifest_hash: str
    scope: str
    already_present: bool
    receipt_already_present: bool

    def as_payload(self) -> dict[str, object]:
        return {
            "schema": _RECEIPT_SCHEMA,
            "storage_path": str(self.storage_path),
            "receipt_path": str(self.receipt_path),
            "bundle_sha256": self.bundle_sha256,
            "manifest_hash": self.manifest_hash,
            "scope": self.scope,
            "already_present": self.already_present,
            "receipt_already_present": self.receipt_already_present,
        }


def remote_store_from_env(
    env: Mapping[str, str] | None = None,
    *,
    uri_env: str = REMOTE_AUDIT_BUNDLE_URI_ENV,
    scope_env: str = REMOTE_AUDIT_BUNDLE_SCOPE_ENV,
) -> RemoteAuditBundleStore | None:
    """Return configured remote storage or ``None`` when it is fully disabled."""

    environ = env if env is not None else os.environ
    uri = str(environ.get(uri_env, "")).strip()
    scope = str(environ.get(scope_env, "")).strip()
    if not uri and not scope:
        return None
    if not uri or not scope:
        raise ValueError(f"remote audit bundle storage requires both {uri_env} and {scope_env}")
    return parse_remote_store(uri, scope=scope)


def parse_remote_store(uri: str, *, scope: str) -> RemoteAuditBundleStore:
    """Validate an explicit mounted-directory or ``file://`` remote store."""

    normalized_scope = _validate_scope(scope)
    root = _path_from_uri(uri)
    if not root.is_absolute():
        raise ValueError("remote audit bundle storage path must be absolute")
    return RemoteAuditBundleStore(root=root, scope=normalized_scope, source_uri=uri)


def store_audit_manifest_bundle_remote(
    bundle: AuditManifestBundle,
    *,
    engagement_id: int,
    run_id: int,
    store: RemoteAuditBundleStore,
    stored_at: str | None = None,
) -> RemoteAuditBundleReceipt:
    """Append a manifest bundle to configured storage without overwriting evidence."""

    source_bytes = bundle.path.read_bytes()
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    if source_sha256 != bundle.bundle_sha256:
        raise ValueError("bundle hash mismatch before remote storage")

    target_dir = store.root / store.scope / f"engagement_{int(engagement_id)}" / f"run_{int(run_id)}"
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / (
        f"engagement_{int(engagement_id)}_run_{int(run_id)}_"
        f"manifest_{bundle.manifest_hash[:12]}_bundle_{bundle.bundle_sha256}.zip"
    )
    receipt_path = target_path.with_name(f"{target_path.name}.receipt.json")

    already_present = _write_once(target_path, source_bytes, expected_sha256=bundle.bundle_sha256)
    receipt_payload = {
        "schema": _RECEIPT_SCHEMA,
        "stored_at": stored_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "storage_scope": store.scope,
        "engagement_id": int(engagement_id),
        "run_id": int(run_id),
        "manifest_hash": bundle.manifest_hash,
        "bundle_sha256": bundle.bundle_sha256,
        "verification_ok": bundle.verification_ok,
        "signature_present": bundle.signature_present,
        "files": list(bundle.files),
        "source_bundle_name": bundle.path.name,
        "storage_filename": target_path.name,
        "append_only": True,
    }
    receipt_already_present = _write_receipt_once(receipt_path, receipt_payload)
    return RemoteAuditBundleReceipt(
        storage_path=target_path,
        receipt_path=receipt_path,
        bundle_sha256=bundle.bundle_sha256,
        manifest_hash=bundle.manifest_hash,
        scope=store.scope,
        already_present=already_present,
        receipt_already_present=receipt_already_present,
    )


def store_audit_manifest_bundle_remote_from_env(
    bundle: AuditManifestBundle,
    *,
    engagement_id: int,
    run_id: int,
    env: Mapping[str, str] | None = None,
    uri_env: str = REMOTE_AUDIT_BUNDLE_URI_ENV,
    scope_env: str = REMOTE_AUDIT_BUNDLE_SCOPE_ENV,
    stored_at: str | None = None,
) -> RemoteAuditBundleReceipt:
    """Store a bundle using explicit env-var configuration."""

    store = remote_store_from_env(env, uri_env=uri_env, scope_env=scope_env)
    if store is None:
        raise ValueError(f"remote audit bundle storage is not configured via {uri_env} and {scope_env}")
    return store_audit_manifest_bundle_remote(
        bundle,
        engagement_id=engagement_id,
        run_id=run_id,
        store=store,
        stored_at=stored_at,
    )


def _path_from_uri(uri: str) -> Path:
    raw = uri.strip()
    if not raw:
        raise ValueError("remote audit bundle storage URI is empty")
    if re.match(r"^[A-Za-z]:[\\/]", raw) or raw.startswith("\\\\"):
        return Path(raw).expanduser()

    parsed = urlparse(raw)
    if parsed.scheme and parsed.scheme != "file":
        raise ValueError("remote audit bundle storage supports only file:// or mounted paths")
    if parsed.scheme == "file":
        if parsed.netloc:
            return Path(f"//{parsed.netloc}{url2pathname(parsed.path)}").expanduser()
        return Path(url2pathname(parsed.path)).expanduser()
    return Path(raw).expanduser()


def _validate_scope(scope: str) -> str:
    normalized = scope.strip()
    if not _SCOPE_PATTERN.fullmatch(normalized):
        raise ValueError(
            "remote audit bundle scope must be 1-80 chars of letters, numbers, dot, underscore, or dash"
        )
    return normalized


def _write_once(
    path: Path,
    data: bytes,
    *,
    expected_sha256: str | None,
) -> bool:
    try:
        with path.open("xb") as handle:
            handle.write(data)
        return False
    except FileExistsError:
        existing_hash = _file_sha256(path)
        if expected_sha256 is None or existing_hash != expected_sha256:
            raise ValueError(f"remote audit bundle path already exists with different content: {path}")
        return True
    except OSError as exc:
        raise ValueError(f"remote audit bundle write failed: {exc}") from exc


def _write_receipt_once(path: Path, payload: dict[str, object]) -> bool:
    data = _json_bytes(payload)
    try:
        with path.open("xb") as handle:
            handle.write(data)
        return False
    except FileExistsError:
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"remote audit receipt already exists but is unreadable: {path}") from exc
        for key in ("schema", "bundle_sha256", "manifest_hash", "storage_filename"):
            if existing.get(key) != payload.get(key):
                raise ValueError(f"remote audit receipt already exists with different content: {path}")
        return True
    except OSError as exc:
        raise ValueError(f"remote audit receipt write failed: {exc}") from exc


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(shutil.COPY_BUFSIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_bytes(payload: dict[str, object]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
