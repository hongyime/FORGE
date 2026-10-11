"""Tests for :mod:`forge.onboard.service_connections`.

Covers:

- CRUD across the full :data:`SUPPORTED_SERVICES` matrix.
- Credential provenance enforcement (``--token-env`` / ``--token-stdin``
  only; literal ``token`` values require ``credential_sources``).
- Idempotent replace semantics.
- Atomic on-disk writes (schema version, dedupe).
- ``read_env_credential`` / ``read_stdin_credential`` reject empty input.
- Redaction never leaks credential bodies in the ``--json`` summary while
  the on-disk file retains plaintext values (operator explicitly opted in).
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from forge.onboard.service_connections import (
    CONNECTION_SCHEMA_VERSION,
    CONNECTIONS_FILENAME,
    SUPPORTED_SERVICES,
    ConnectionError,
    ServiceConnection,
    ServiceConnectionManager,
    read_env_credential,
    read_stdin_credential,
)


def test_add_github_connection_persists_plaintext_token(tmp_path: Path) -> None:
    manager = ServiceConnectionManager(tmp_path)
    manager.add_connection(
        "github",
        token="ghp_" + "a" * 40,
        orgs=["myorg"],
        users=["myuser"],
        credential_sources={"token": "env:FORGE_GITHUB_TOKEN"},
    )

    stored = json.loads((tmp_path / CONNECTIONS_FILENAME).read_text(encoding="utf-8"))
    assert stored["schema_version"] == CONNECTION_SCHEMA_VERSION
    assert stored["connections"][0]["service"] == "github"
    # Operator explicitly chose plaintext storage.
    assert stored["connections"][0]["config"]["token"].startswith("ghp_")
    assert stored["connections"][0]["config"]["orgs"] == ["myorg"]
    assert stored["connections"][0]["credential_sources"] == {
        "token": "env:FORGE_GITHUB_TOKEN"
    }


def test_add_connection_rejects_credential_without_source(tmp_path: Path) -> None:
    manager = ServiceConnectionManager(tmp_path)
    with pytest.raises(ConnectionError, match="credential_source"):
        manager.add_connection("shodan", key="shodan-key-redacted")


def test_add_connection_rejects_missing_required_fields(tmp_path: Path) -> None:
    manager = ServiceConnectionManager(tmp_path)
    with pytest.raises(ConnectionError, match="required fields"):
        manager.add_connection(
            "censys",
            api_id="abc",
            credential_sources={"api_id": "env:CENSYS_ID"},
        )


def test_add_connection_rejects_unknown_fields(tmp_path: Path) -> None:
    manager = ServiceConnectionManager(tmp_path)
    with pytest.raises(ConnectionError, match="unknown fields"):
        manager.add_connection(
            "shodan",
            key="key",
            unexpected="value",
            credential_sources={"key": "env:SHODAN"},
        )


def test_add_connection_replaces_existing_by_default(tmp_path: Path) -> None:
    manager = ServiceConnectionManager(tmp_path)
    manager.add_connection(
        "shodan", key="first", credential_sources={"key": "env:FIRST"}
    )
    manager.add_connection(
        "shodan", key="second", credential_sources={"key": "env:SECOND"}
    )
    stored = manager.list_connections()
    assert len(stored) == 1
    assert stored[0].config["key"] == "second"
    assert stored[0].credential_sources == {"key": "env:SECOND"}


def test_add_connection_can_refuse_replace(tmp_path: Path) -> None:
    manager = ServiceConnectionManager(tmp_path)
    manager.add_connection(
        "shodan", key="first", credential_sources={"key": "env:FIRST"}
    )
    with pytest.raises(ConnectionError, match="already exists"):
        manager.add_connection(
            "shodan",
            key="second",
            replace=False,
            credential_sources={"key": "env:SECOND"},
        )


def test_add_rejects_unsupported_service(tmp_path: Path) -> None:
    manager = ServiceConnectionManager(tmp_path)
    with pytest.raises(ConnectionError, match="unsupported service"):
        manager.add_connection("google")


def test_remove_connection_returns_true_when_removed(tmp_path: Path) -> None:
    manager = ServiceConnectionManager(tmp_path)
    manager.add_connection(
        "shodan", key="x", credential_sources={"key": "env:X"}
    )
    assert manager.remove_connection("shodan") is True
    assert manager.list_connections() == []
    # Idempotent — second remove returns False.
    assert manager.remove_connection("shodan") is False


def test_get_connection_returns_none_when_missing(tmp_path: Path) -> None:
    manager = ServiceConnectionManager(tmp_path)
    assert manager.get_connection("github") is None


def test_list_sorted_by_service(tmp_path: Path) -> None:
    manager = ServiceConnectionManager(tmp_path)
    manager.add_connection(
        "shodan", key="x", credential_sources={"key": "env:X"}
    )
    manager.add_connection(
        "github", token="y", credential_sources={"token": "env:Y"}
    )
    assert [c.service for c in manager.list_connections()] == ["github", "shodan"]


def test_to_summary_redacts_credential_fields(tmp_path: Path) -> None:
    manager = ServiceConnectionManager(tmp_path)
    manager.add_connection(
        "censys",
        api_id="id-plain",
        api_secret="secret-plain",
        credential_sources={
            "api_id": "env:CENSYS_ID",
            "api_secret": "env:CENSYS_SECRET",
        },
    )
    summary = manager.to_summary(redact=True)
    assert summary["schema_version"] == CONNECTION_SCHEMA_VERSION
    assert summary["connections"][0]["config"]["api_id"] == "<redacted>"
    assert summary["connections"][0]["config"]["api_secret"] == "<redacted>"
    # Credential provenance remains visible.
    assert summary["connections"][0]["credential_sources"] == {
        "api_id": "env:CENSYS_ID",
        "api_secret": "env:CENSYS_SECRET",
    }


def test_to_summary_without_redact_returns_plaintext(tmp_path: Path) -> None:
    manager = ServiceConnectionManager(tmp_path)
    manager.add_connection(
        "shodan", key="shodan-secret", credential_sources={"key": "env:SHODAN"}
    )
    summary = manager.to_summary(redact=False)
    assert summary["connections"][0]["config"]["key"] == "shodan-secret"


def test_available_services_matches_registry(tmp_path: Path) -> None:
    manager = ServiceConnectionManager(tmp_path)
    assert set(manager.available_services()) == set(SUPPORTED_SERVICES)


def test_orgs_users_dedupe_and_sort(tmp_path: Path) -> None:
    manager = ServiceConnectionManager(tmp_path)
    manager.add_connection(
        "github",
        token="t",
        orgs=["b", "a", "a"],
        credential_sources={"token": "env:T"},
    )
    stored = manager.get_connection("github")
    assert stored is not None
    assert stored.config["orgs"] == ["a", "b"]


def test_orgs_users_accept_comma_separated(tmp_path: Path) -> None:
    manager = ServiceConnectionManager(tmp_path)
    manager.add_connection(
        "github",
        token="t",
        orgs="first,second,second",
        credential_sources={"token": "env:T"},
    )
    stored = manager.get_connection("github")
    assert stored is not None
    assert stored.config["orgs"] == ["first", "second"]


def test_read_env_credential_rejects_empty_or_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FORGE_EMPTY_TOKEN", raising=False)
    with pytest.raises(ConnectionError, match="unset"):
        read_env_credential("FORGE_EMPTY_TOKEN")
    monkeypatch.setenv("FORGE_EMPTY_TOKEN", "   ")
    with pytest.raises(ConnectionError, match="unset"):
        read_env_credential("FORGE_EMPTY_TOKEN")


def test_read_env_credential_returns_value_and_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORGE_SAMPLE_TOKEN", "abc123")
    value, source = read_env_credential("FORGE_SAMPLE_TOKEN")
    assert value == "abc123"
    assert source == "env:FORGE_SAMPLE_TOKEN"


def test_read_stdin_credential_strips_whitespace() -> None:
    stream = io.StringIO("ghp_value\n")
    value, source = read_stdin_credential(stream)
    assert value == "ghp_value"
    assert source == "stdin"


def test_read_stdin_credential_rejects_empty() -> None:
    stream = io.StringIO("   \n")
    with pytest.raises(ConnectionError, match="no data"):
        read_stdin_credential(stream)


def test_service_connection_from_dict_round_trip() -> None:
    original = ServiceConnection(
        service="github",
        added_at="2026-10-11T00:00:00+00:00",
        config={"token": "x"},
        credential_sources={"token": "env:T"},
    )
    serialized = original.to_dict()
    restored = ServiceConnection.from_dict(serialized)
    assert restored.service == original.service
    assert restored.added_at == original.added_at
    assert dict(restored.config) == dict(original.config)


def test_corrupt_connections_file_raises_connection_error(tmp_path: Path) -> None:
    (tmp_path / CONNECTIONS_FILENAME).write_text("{not-json", encoding="utf-8")
    manager = ServiceConnectionManager(tmp_path)
    with pytest.raises(ConnectionError, match="not valid JSON"):
        manager.list_connections()


def test_write_is_atomic_via_tmp_file(tmp_path: Path) -> None:
    manager = ServiceConnectionManager(tmp_path)
    manager.add_connection(
        "shodan", key="x", credential_sources={"key": "env:X"}
    )
    # No stray *.tmp file should linger.
    stray = list(tmp_path.glob("*.tmp"))
    assert stray == []
