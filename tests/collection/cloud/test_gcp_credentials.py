"""Tests for forge.collection.cloud.gcp_credentials."""

from __future__ import annotations

import hashlib
import io
import json
import sqlite3
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from forge.collection.cloud import gcp_credentials as gcp
from forge.collection.cloud.gcp_credentials import (
    GCPCredential,
    harvest_gcp_credentials,
)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _write_service_account(path: Path, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "type": "service_account",
        "project_id": "my-project-123",
        "private_key_id": "abc123keyid",
        "private_key": (
            "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n"
        ),
        "client_email": "svc@my-project-123.iam.gserviceaccount.com",
        "client_id": "10101010101010101",
    }
    payload.update(overrides)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return payload


# ---------------------------------------------------------------------------
# Env-var harvest
# ---------------------------------------------------------------------------

def test_env_google_application_credentials_parses_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sa = tmp_path / "sa.json"
    payload = _write_service_account(sa)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GCP_SERVICE_ACCOUNT", raising=False)

    creds = harvest_gcp_credentials(home=tmp_path, include_metadata=False)

    assert len(creds) == 1
    c = creds[0]
    assert c.type == "service_account"
    assert c.source == "env:GOOGLE_APPLICATION_CREDENTIALS"
    assert c.project_id == payload["project_id"]
    assert c.client_email == payload["client_email"]
    assert c.private_key_id_hash == _sha256(payload["private_key_id"])
    # Raw private key material must NOT appear anywhere.
    dumped = json.dumps(c.to_dict())
    assert "BEGIN PRIVATE KEY" not in dumped
    assert "MIIE" not in dumped


def test_env_gcp_project_and_service_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setenv("GCP_PROJECT", "explicit-project")
    monkeypatch.setenv("GCP_SERVICE_ACCOUNT", "runner@explicit.iam")

    creds = harvest_gcp_credentials(home=tmp_path, include_metadata=False)

    assert any(
        c.type == "env_project"
        and c.project_id == "explicit-project"
        and c.client_email == "runner@explicit.iam"
        for c in creds
    )


def test_env_missing_file_graceful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "GOOGLE_APPLICATION_CREDENTIALS", str(tmp_path / "nope.json")
    )
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GCP_SERVICE_ACCOUNT", raising=False)
    assert harvest_gcp_credentials(home=tmp_path, include_metadata=False) == []


def test_env_malformed_json_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json", encoding="utf-8")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(bad))
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GCP_SERVICE_ACCOUNT", raising=False)

    assert harvest_gcp_credentials(home=tmp_path, include_metadata=False) == []


def test_env_json_without_project_id_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sa = tmp_path / "sa.json"
    sa.write_text(
        json.dumps({"type": "service_account", "client_email": "x@y"}),
        encoding="utf-8",
    )
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GCP_SERVICE_ACCOUNT", raising=False)

    assert harvest_gcp_credentials(home=tmp_path, include_metadata=False) == []


# ---------------------------------------------------------------------------
# credentials.db (SQLite) harvest
# ---------------------------------------------------------------------------

def _seed_credentials_db(path: Path, rows: list[tuple[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE credentials (account_id TEXT PRIMARY KEY, value TEXT)"
        )
        conn.executemany(
            "INSERT INTO credentials(account_id, value) VALUES (?, ?)", rows
        )
        conn.commit()
    finally:
        conn.close()


def test_credentials_db_parsed_and_hashed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GCP_SERVICE_ACCOUNT", raising=False)

    db_path = tmp_path / ".config" / "gcloud" / "credentials.db"
    token = "ya29.SECRET_ACCESS_TOKEN_XYZ"
    value = json.dumps(
        {
            "access_token": token,
            "project_id": "db-project",
            "client_email": "user@db.iam",
        }
    )
    _seed_credentials_db(db_path, [("user@db.iam", value)])

    creds = harvest_gcp_credentials(home=tmp_path, include_metadata=False)

    matches = [c for c in creds if c.type == "gcloud_access_token"]
    assert len(matches) == 1
    c = matches[0]
    assert c.project_id == "db-project"
    assert c.client_email == "user@db.iam"
    assert c.access_token_hash == _sha256(token)
    # Raw token must not appear.
    assert token not in json.dumps(c.to_dict())


def test_credentials_db_row_without_project_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GCP_SERVICE_ACCOUNT", raising=False)

    db_path = tmp_path / ".config" / "gcloud" / "credentials.db"
    _seed_credentials_db(
        db_path,
        [("noproj@x", json.dumps({"access_token": "t"}))],
    )
    creds = harvest_gcp_credentials(home=tmp_path, include_metadata=False)
    assert [c for c in creds if c.type == "gcloud_access_token"] == []


def test_credentials_db_missing_graceful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GCP_SERVICE_ACCOUNT", raising=False)
    assert harvest_gcp_credentials(home=tmp_path, include_metadata=False) == []


# ---------------------------------------------------------------------------
# gcloud config INI harvest
# ---------------------------------------------------------------------------

def test_gcloud_config_parsed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GCP_SERVICE_ACCOUNT", raising=False)

    cfg_dir = tmp_path / ".config" / "gcloud" / "configurations"
    cfg_dir.mkdir(parents=True)
    cfg = cfg_dir / "config_default"
    cfg.write_text(
        "[core]\nproject = ini-project\naccount = ini@example.iam\n",
        encoding="utf-8",
    )

    creds = harvest_gcp_credentials(home=tmp_path, include_metadata=False)
    matches = [c for c in creds if c.type == "gcloud_config"]
    assert len(matches) == 1
    c = matches[0]
    assert c.project_id == "ini-project"
    assert c.client_email == "ini@example.iam"
    assert c.source == "gcloud_config:config_default"


def test_gcloud_config_malformed_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GCP_SERVICE_ACCOUNT", raising=False)

    cfg_dir = tmp_path / ".config" / "gcloud" / "configurations"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "config_broken").write_text(
        "\x00\x00not an ini\x00", encoding="utf-8"
    )
    (cfg_dir / "config_noproject").write_text(
        "[core]\naccount = only@acct\n", encoding="utf-8"
    )
    creds = harvest_gcp_credentials(home=tmp_path, include_metadata=False)
    assert [c for c in creds if c.type == "gcloud_config"] == []


# ---------------------------------------------------------------------------
# Metadata service
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def test_metadata_service_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GCP_SERVICE_ACCOUNT", raising=False)

    token = "ya29.META_TOKEN"

    def fake_urlopen(req: Any, timeout: float = 0) -> _FakeResponse:
        # Verify header + timeout.
        assert req.get_header("Metadata-flavor") == "Google"
        assert timeout <= 2.0
        if req.full_url.endswith("/token"):
            return _FakeResponse(
                json.dumps(
                    {
                        "access_token": token,
                        "expires_in": 3599,
                        "token_type": "Bearer",
                    }
                ).encode()
            )
        if req.full_url.endswith("/project-id"):
            return _FakeResponse(b"meta-project")
        raise AssertionError(f"unexpected URL: {req.full_url}")

    with mock.patch.object(gcp.urlrequest, "urlopen", side_effect=fake_urlopen):
        creds = harvest_gcp_credentials(home=tmp_path, include_metadata=True)

    matches = [c for c in creds if c.type == "metadata_service"]
    assert len(matches) == 1
    c = matches[0]
    assert c.project_id == "meta-project"
    assert c.access_token_hash == _sha256(token)
    assert token not in json.dumps(c.to_dict())


def test_metadata_service_timeout_returns_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GCP_SERVICE_ACCOUNT", raising=False)

    def raiser(*_a: Any, **_kw: Any) -> Any:
        raise TimeoutError("boom")

    with mock.patch.object(gcp.urlrequest, "urlopen", side_effect=raiser):
        creds = harvest_gcp_credentials(
            home=tmp_path, include_metadata=True, metadata_timeout=0.01
        )
    assert [c for c in creds if c.type == "metadata_service"] == []


def test_metadata_service_urlerror_returns_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GCP_SERVICE_ACCOUNT", raising=False)

    from urllib.error import URLError

    with mock.patch.object(
        gcp.urlrequest, "urlopen", side_effect=URLError("no route")
    ):
        creds = harvest_gcp_credentials(home=tmp_path, include_metadata=True)
    assert creds == []


# ---------------------------------------------------------------------------
# Structural / contract
# ---------------------------------------------------------------------------

def test_credential_object_required_fields() -> None:
    c = GCPCredential(type="t", source="s", project_id="p")
    d = c.to_dict()
    for key in (
        "type",
        "source",
        "project_id",
        "client_email",
        "private_key_id_hash",
        "access_token_hash",
    ):
        assert key in d, f"missing required field {key}"


def test_all_secrets_are_hashed_across_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Combined: env SA JSON + credentials.db + metadata service.
    sa = tmp_path / "sa.json"
    sa_payload = _write_service_account(sa, private_key_id="ENV_KEY_ID")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GCP_SERVICE_ACCOUNT", raising=False)

    db_path = tmp_path / ".config" / "gcloud" / "credentials.db"
    db_token = "DB_TOKEN_SECRET"
    _seed_credentials_db(
        db_path,
        [
            (
                "db@user",
                json.dumps(
                    {"access_token": db_token, "project_id": "db-project"}
                ),
            )
        ],
    )

    meta_token = "META_TOKEN_SECRET"

    def fake_urlopen(req: Any, timeout: float = 0) -> _FakeResponse:
        if req.full_url.endswith("/token"):
            return _FakeResponse(
                json.dumps(
                    {"access_token": meta_token, "project_id": "meta-project"}
                ).encode()
            )
        return _FakeResponse(b"meta-project")

    with mock.patch.object(gcp.urlrequest, "urlopen", side_effect=fake_urlopen):
        creds = harvest_gcp_credentials(home=tmp_path, include_metadata=True)

    dumped = json.dumps([c.to_dict() for c in creds])
    # No raw secret material should ever surface.
    for secret in (
        sa_payload["private_key"],
        sa_payload["private_key_id"],
        db_token,
        meta_token,
    ):
        assert secret not in dumped, f"raw secret leaked: {secret[:8]}..."

    # Every credential that carries a secret has the corresponding hash set.
    for c in creds:
        if c.type == "service_account":
            assert c.private_key_id_hash == _sha256(sa_payload["private_key_id"])
        if c.type == "gcloud_access_token":
            assert c.access_token_hash == _sha256(db_token)
        if c.type == "metadata_service":
            assert c.access_token_hash == _sha256(meta_token)


def test_all_four_sources_checked_in_one_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # env
    sa = tmp_path / "sa.json"
    _write_service_account(sa)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GCP_SERVICE_ACCOUNT", raising=False)
    # db
    db_path = tmp_path / ".config" / "gcloud" / "credentials.db"
    _seed_credentials_db(
        db_path,
        [
            (
                "u@x",
                json.dumps({"access_token": "T", "project_id": "db-project"}),
            )
        ],
    )
    # config
    cfg_dir = tmp_path / ".config" / "gcloud" / "configurations"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "config_default").write_text(
        "[core]\nproject = ini-project\n", encoding="utf-8"
    )
    # metadata
    def fake_urlopen(req: Any, timeout: float = 0) -> _FakeResponse:
        if req.full_url.endswith("/token"):
            return _FakeResponse(
                json.dumps(
                    {"access_token": "M", "project_id": "meta-project"}
                ).encode()
            )
        return _FakeResponse(b"meta-project")

    with mock.patch.object(gcp.urlrequest, "urlopen", side_effect=fake_urlopen):
        creds = harvest_gcp_credentials(home=tmp_path, include_metadata=True)

    types = {c.type for c in creds}
    assert "service_account" in types
    assert "gcloud_access_token" in types
    assert "gcloud_config" in types
    assert "metadata_service" in types
    # every credential has project_id (per DO NOT include credentials without project_id)
    assert all(c.project_id for c in creds)
