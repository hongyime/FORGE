from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
from collections.abc import Mapping
from typing import Any

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from forge.connectors.registry import list_connector_definitions

SECRET_MATERIAL_POLICY = (
    "Connector secrets are encrypted at rest with FORGE_ENGAGEMENT_KEY; "
    "list/audit outputs never include plaintext values."
)

_SECRET_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_SECRET_KEYWORDS = ("secret", "token", "password", "credential", "apikey", "api_key", "key")
_SECRET_TOKEN_PREFIXES = (
    "ghp_",
    "github_pat_",
    "sk-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "AKIA",
)
_KDF_SALT = b"forge.connector-secrets.v1"
_KDF_ITERATIONS = 200_000


def store_connector_secret(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    connector_id: str,
    secret_name: str,
    secret_value: str,
    secret_ref: str = "",
    operator: str = "connector-secret-store",
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Encrypt and upsert one engagement-scoped connector secret."""
    connector = _normalize_connector_id(connector_id)
    name = _normalize_connector_secret_name(connector, secret_name)
    value = str(secret_value)
    if not value.strip():
        raise ValueError("connector secret value cannot be empty")

    metadata_json = _metadata_json(metadata, forbidden_values=(value,))
    context = _secret_context(
        engagement_id=int(engagement_id),
        connector_id=connector,
        secret_name=name,
    )
    encrypted_value = _encrypt_secret_value(value, context=context)
    key_hint = _key_hint()
    source_ref = _safe_secret_ref(secret_ref, secret_value=value)
    actor = _bounded_text(operator, 128) or "connector-secret-store"

    con.execute(
        """
        INSERT INTO connector_secrets
            (
                engagement_id,
                connector_id,
                secret_name,
                secret_value_enc,
                secret_ref,
                key_hint,
                metadata_json,
                created_by,
                updated_by
            )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, connector_id, secret_name) DO UPDATE SET
            secret_value_enc=excluded.secret_value_enc,
            secret_ref=excluded.secret_ref,
            key_hint=excluded.key_hint,
            metadata_json=excluded.metadata_json,
            updated_by=excluded.updated_by,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            int(engagement_id),
            connector,
            name,
            encrypted_value,
            source_ref,
            key_hint,
            metadata_json,
            actor,
            actor,
        ),
    )
    _audit_connector_secret_store(
        con,
        engagement_id=int(engagement_id),
        connector_id=connector,
        secret_name=name,
        secret_ref=source_ref,
        key_hint=key_hint,
        operator=actor,
    )
    con.commit()
    return get_connector_secret(
        con,
        engagement_id=int(engagement_id),
        connector_id=connector,
        secret_name=name,
    )


def list_connector_secrets(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    connector_id: str = "",
) -> list[dict[str, Any]]:
    """Return redacted connector secret metadata for one engagement."""
    connector = str(connector_id or "").strip()
    params: list[object] = [int(engagement_id)]
    where = "WHERE engagement_id=?"
    if connector:
        _normalize_connector_id(connector)
        where += " AND connector_id=?"
        params.append(connector)
    rows = con.execute(
        f"""
        SELECT
            id,
            engagement_id,
            connector_id,
            secret_name,
            secret_ref,
            key_hint,
            metadata_json,
            created_by,
            updated_by,
            created_at,
            updated_at
        FROM connector_secrets
        {where}
        ORDER BY connector_id, secret_name
        """,
        params,
    ).fetchall()
    return [_secret_payload(row) for row in rows]


def get_connector_secret(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    connector_id: str,
    secret_name: str,
) -> dict[str, Any]:
    """Return one redacted connector secret metadata row."""
    row = con.execute(
        """
        SELECT
            id,
            engagement_id,
            connector_id,
            secret_name,
            secret_ref,
            key_hint,
            metadata_json,
            created_by,
            updated_by,
            created_at,
            updated_at
        FROM connector_secrets
        WHERE engagement_id=? AND connector_id=? AND secret_name=?
        """,
        (
            int(engagement_id),
            _normalize_connector_id(connector_id),
            _normalize_secret_name(secret_name),
        ),
    ).fetchone()
    if row is None:
        raise LookupError("connector secret not found")
    return _secret_payload(row)


def resolve_connector_secret_value(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    connector_id: str,
    secret_name: str,
    key_material: str | None = None,
) -> str:
    """Decrypt one connector secret for connector execution paths."""
    connector = _normalize_connector_id(connector_id)
    name = _normalize_secret_name(secret_name)
    row = con.execute(
        """
        SELECT secret_value_enc
        FROM connector_secrets
        WHERE engagement_id=? AND connector_id=? AND secret_name=?
        """,
        (int(engagement_id), connector, name),
    ).fetchone()
    if row is None:
        raise LookupError("connector secret not found")
    context = _secret_context(
        engagement_id=int(engagement_id),
        connector_id=connector,
        secret_name=name,
    )
    return _decrypt_secret_value(
        str(row["secret_value_enc"] or ""),
        context=context,
        key_material=key_material,
    )


def _encrypt_secret_value(
    value: str,
    *,
    context: str,
    key_material: str | None = None,
) -> str:
    nonce = get_random_bytes(12)
    cipher = AES.new(_derived_key(key_material), AES.MODE_GCM, nonce=nonce)
    cipher.update(context.encode("utf-8"))
    ciphertext, tag = cipher.encrypt_and_digest(value.encode("utf-8"))
    envelope = {
        "v": 1,
        "alg": "AES-256-GCM",
        "kdf": f"PBKDF2-HMAC-SHA256:{_KDF_ITERATIONS}",
        "nonce": _b64(nonce),
        "tag": _b64(tag),
        "ciphertext": _b64(ciphertext),
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"))


def _decrypt_secret_value(
    envelope_json: str,
    *,
    context: str,
    key_material: str | None = None,
) -> str:
    try:
        envelope = json.loads(envelope_json)
        if not isinstance(envelope, dict) or envelope.get("alg") != "AES-256-GCM":
            raise ValueError("unsupported connector secret envelope")
        nonce = _unb64(str(envelope["nonce"]))
        tag = _unb64(str(envelope["tag"]))
        ciphertext = _unb64(str(envelope["ciphertext"]))
        cipher = AES.new(_derived_key(key_material), AES.MODE_GCM, nonce=nonce)
        cipher.update(context.encode("utf-8"))
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            "failed to decrypt connector secret; FORGE_ENGAGEMENT_KEY may not match"
        ) from exc
    return plaintext.decode("utf-8")


def connector_secret_readiness(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    key_material: str | None = None,
) -> dict[str, dict[str, str]]:
    """Return value-free decryptability state for stored connector secrets."""
    statuses: dict[str, dict[str, str]] = {}
    for item in list_connector_secrets(con, engagement_id=int(engagement_id)):
        connector_id = str(item.get("connector_id") or "")
        secret_name = str(item.get("secret_name") or "")
        if not connector_id or not secret_name:
            continue
        try:
            resolve_connector_secret_value(
                con,
                engagement_id=int(engagement_id),
                connector_id=connector_id,
                secret_name=secret_name,
                key_material=key_material,
            )
        except LookupError:
            status = "stored_key_missing"
        except ValueError:
            status = "stored_decrypt_failed"
        else:
            status = "stored_configured"
        statuses.setdefault(connector_id, {})[secret_name] = status
    return statuses


def _derived_key(key_material: str | None = None) -> bytes:
    value = _master_key_material() if key_material is None else str(key_material).strip()
    if len(value) < 32:
        raise ValueError(
            "FORGE_ENGAGEMENT_KEY must be set to at least 32 characters "
            "before reading connector secrets"
        )
    return hashlib.pbkdf2_hmac(
        "sha256",
        value.encode("utf-8"),
        _KDF_SALT,
        _KDF_ITERATIONS,
        dklen=32,
    )


def _master_key_material() -> str:
    value = os.environ.get("FORGE_ENGAGEMENT_KEY", "").strip()
    if len(value) < 32:
        raise ValueError(
            "FORGE_ENGAGEMENT_KEY must be set to at least 32 characters "
            "before storing connector secrets"
        )
    return value


def _key_hint() -> str:
    digest = hashlib.sha256(_master_key_material().encode("utf-8")).hexdigest()
    return f"sha256:{digest[:12]}"


def _secret_context(
    *,
    engagement_id: int,
    connector_id: str,
    secret_name: str,
) -> str:
    return f"forge.connector_secrets.v1:{int(engagement_id)}:{connector_id}:{secret_name}"


def _normalize_connector_id(connector_id: str) -> str:
    value = str(connector_id or "").strip()
    known = {definition.id for definition in list_connector_definitions()}
    if value not in known:
        raise ValueError(f"unknown connector: {connector_id}")
    return value


def _normalize_connector_secret_name(connector_id: str, secret_name: str) -> str:
    name = _normalize_secret_name(secret_name)
    definition = next(
        item for item in list_connector_definitions() if item.id == connector_id
    )
    allowed = {env_name for option in definition.env_options for env_name in option}
    if not allowed:
        raise ValueError(f"connector does not accept stored secrets: {connector_id}")
    if name not in allowed:
        raise ValueError(
            f"connector secret name is not declared for {connector_id}: {secret_name}"
        )
    return name


def _normalize_secret_name(secret_name: str) -> str:
    value = str(secret_name or "").strip()
    if not _SECRET_NAME_RE.match(value):
        raise ValueError(
            "connector secret name must be 1-128 characters and contain only "
            "letters, numbers, dot, underscore, colon, or dash"
        )
    return value


def _metadata_json(
    metadata: Mapping[str, Any] | None,
    *,
    forbidden_values: tuple[str, ...] = (),
) -> str:
    if metadata is None:
        payload: Mapping[str, Any] = {}
    elif isinstance(metadata, Mapping):
        payload = metadata
    else:
        raise ValueError("connector secret metadata must be a JSON object")
    redacted = _redact_secret_bearing_metadata(
        payload,
        forbidden_values=forbidden_values,
    )
    return json.dumps(redacted, sort_keys=True)


def _redact_secret_bearing_metadata(
    value: Any,
    *,
    forbidden_values: tuple[str, ...] = (),
) -> Any:
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            if any(token in lowered for token in _SECRET_KEYWORDS):
                redacted[key_text] = "[redacted]"
            else:
                redacted[key_text] = _redact_secret_bearing_metadata(
                    item,
                    forbidden_values=forbidden_values,
                )
        return redacted
    if isinstance(value, list):
        return [
            _redact_secret_bearing_metadata(
                item,
                forbidden_values=forbidden_values,
            )
            for item in value
        ]
    if isinstance(value, str):
        if _contains_forbidden_secret(value, forbidden_values) or _looks_secret_like(value):
            return "[redacted]"
        return value
    if value is None or isinstance(value, str | int | float | bool):
        return value
    return str(value)


def _safe_secret_ref(secret_ref: object, *, secret_value: str) -> str:
    text = _bounded_text(secret_ref, 256)
    if not text:
        return "api:request-body"
    if _contains_forbidden_secret(text, (secret_value,)):
        return "api:request-body"
    lowered = text.lower()
    if "bearer " in lowered or "?" in text or "@" in text or "://" in text:
        return "api:request-body"
    if text == "api:request-body":
        return text
    if text.startswith("env:"):
        name = text.removeprefix("env:").strip()
        return f"env:{name}" if _SECRET_NAME_RE.match(name) else "api:request-body"
    if text.startswith("file:"):
        name = text.removeprefix("file:").strip().replace("\\", "/").split("/")[-1]
        if name and len(name) <= 128 and not any(char in name for char in ("?", "#", "@")):
            return f"file:{name}"
    return "api:request-body"


def _contains_forbidden_secret(text: str, forbidden_values: tuple[str, ...]) -> bool:
    for secret in forbidden_values:
        value = str(secret or "")
        if len(value) >= 8 and value in text:
            return True
    return False


def _looks_secret_like(text: str) -> bool:
    value = text.strip()
    if len(value) < 32 or any(char.isspace() for char in value):
        return False
    if any(value.startswith(prefix) for prefix in _SECRET_TOKEN_PREFIXES):
        return True
    if not re.fullmatch(r"[A-Za-z0-9_.:/+=-]{32,}", value):
        return False
    character_classes = sum(
        bool(re.search(pattern, value))
        for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[_./+=:-]")
    )
    return character_classes >= 2 and len(set(value)) >= 16


def _secret_payload(row: sqlite3.Row) -> dict[str, Any]:
    metadata = _json_object(row["metadata_json"])
    return {
        "id": int(row["id"]),
        "engagement_id": int(row["engagement_id"]),
        "connector_id": str(row["connector_id"] or ""),
        "secret_name": str(row["secret_name"] or ""),
        "secret_ref": str(row["secret_ref"] or ""),
        "key_hint": str(row["key_hint"] or ""),
        "metadata": metadata,
        "created_by": str(row["created_by"] or ""),
        "updated_by": str(row["updated_by"] or ""),
        "created_at": str(row["created_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
        "secret_material_policy": SECRET_MATERIAL_POLICY,
    }


def _json_object(raw: object) -> dict[str, Any]:
    try:
        parsed = json.loads(str(raw or "{}"))
    except json.JSONDecodeError:
        return {}
    if isinstance(parsed, dict):
        return parsed
    return {}


def _audit_connector_secret_store(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    connector_id: str,
    secret_name: str,
    secret_ref: str,
    key_hint: str,
    operator: str,
) -> None:
    if not _table_exists(con, "audit_log"):
        return
    result = {
        "status": "stored",
        "secret_ref": secret_ref,
        "key_hint": key_hint,
        "secret_material_policy": "redacted",
    }
    con.execute(
        """
        INSERT INTO audit_log
            (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'connectors', ?, 'connector_secret_store', ?, ?, ?)
        """,
        (
            int(engagement_id),
            connector_id,
            secret_name,
            json.dumps(result, sort_keys=True),
            operator,
        ),
    )


def _table_exists(con: sqlite3.Connection, table_name: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _bounded_text(value: object, max_len: int) -> str:
    text = str(value or "").strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "..."


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))
