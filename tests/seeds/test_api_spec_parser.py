"""Tests for the Wave 2 #21 api_spec seed type + parser."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from forge.db.migrations import TARGET_VERSION, run_migrations
from forge.db.schema import apply_schema
from forge.db.validation import validate_canonical_schema
from forge.seeds.api_spec_parser import (
    API_SPEC_SUFFIXES,
    ApiSpecParseError,
    MAX_SPEC_FILE_BYTES,
    classify_api_spec_value,
    extract_url_seeds,
    parse_api_spec_file,
    parse_api_spec_text,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


_OPENAPI_FIXTURE: dict = {
    "openapi": "3.0.3",
    "info": {"title": "Acme API", "version": "1.0.0"},
    "servers": [
        {"url": "https://api.acme.example/v1"},
        {"url": "https://staging-api.acme.example/v1"},
    ],
    "paths": {
        "/users": {
            "get": {"summary": "list users"},
            "post": {"summary": "create user"},
        },
        "/users/{id}": {
            "get": {"summary": "get user"},
        },
        "/health": {
            "get": {"summary": "health"},
        },
    },
}


_SWAGGER_FIXTURE: dict = {
    "swagger": "2.0",
    "info": {"title": "Legacy API", "version": "0.9"},
    "host": "legacy.acme.example",
    "basePath": "/v2",
    "schemes": ["https"],
    "paths": {
        "/accounts": {"get": {}, "post": {}},
        "/accounts/{id}": {"delete": {}},
    },
}


_POSTMAN_FIXTURE: dict = {
    "info": {
        "name": "Acme Collection",
        "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        "_postman_id": "abc-123",
    },
    "item": [
        {
            "name": "List users",
            "request": {
                "method": "GET",
                "url": {
                    "raw": "{{base_url}}/users?limit=10",
                    "protocol": "https",
                    "host": ["api", "acme", "example"],
                    "path": ["users"],
                },
            },
        },
        {
            "name": "Nested",
            "item": [
                {
                    "name": "Admin logs",
                    "request": {
                        "method": "GET",
                        "url": "https://api.acme.example/admin/logs",
                    },
                },
            ],
        },
    ],
    "variable": [{"key": "base_url", "value": "https://api.acme.example"}],
}


_SCOPE_MANIFEST: dict = {"domains": ["acme.example"]}


def _write_spec(tmp_path: Path, name: str, document: dict) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Parser contract
# ---------------------------------------------------------------------------


def test_parse_openapi3_extracts_servers_and_endpoints(tmp_path: Path) -> None:
    path = _write_spec(tmp_path, "openapi.json", _OPENAPI_FIXTURE)
    spec = parse_api_spec_file(path)
    assert spec["format"] == "openapi3"
    assert spec["title"] == "Acme API"
    assert spec["version"] == "1.0.0"
    assert spec["base_urls"] == [
        "https://api.acme.example/v1",
        "https://staging-api.acme.example/v1",
    ]
    assert {entry["path"] for entry in spec["endpoints"]} == {
        "/users",
        "/users/{id}",
        "/health",
    }
    methods_on_users = {
        entry["method"]
        for entry in spec["endpoints"]
        if entry["path"] == "/users"
    }
    assert methods_on_users == {"GET", "POST"}


def test_parse_swagger2_builds_base_url_from_host_and_basepath(tmp_path: Path) -> None:
    path = _write_spec(tmp_path, "swagger.json", _SWAGGER_FIXTURE)
    spec = parse_api_spec_file(path)
    assert spec["format"] == "swagger2"
    assert spec["base_urls"] == ["https://legacy.acme.example/v2"]
    assert set(spec["paths"]) == {"/accounts", "/accounts/{id}"}


def test_parse_postman_v2_expands_variables_and_items(tmp_path: Path) -> None:
    path = _write_spec(tmp_path, "postman.json", _POSTMAN_FIXTURE)
    spec = parse_api_spec_file(path)
    assert spec["format"] == "postman2"
    assert "https://api.acme.example" in spec["base_urls"]
    endpoint_paths = {entry["path"] for entry in spec["endpoints"]}
    assert "/users" in endpoint_paths
    assert "/admin/logs" in endpoint_paths


def test_parse_rejects_unsupported_document(tmp_path: Path) -> None:
    path = tmp_path / "random.json"
    path.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    with pytest.raises(ApiSpecParseError):
        parse_api_spec_file(path)


def test_parse_rejects_oversized_file(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "big.json"
    path.write_text(json.dumps(_OPENAPI_FIXTURE), encoding="utf-8")
    monkeypatch.setattr("forge.seeds.api_spec_parser.MAX_SPEC_FILE_BYTES", 10)
    with pytest.raises(ApiSpecParseError):
        parse_api_spec_file(path)


def test_parse_empty_text_rejected() -> None:
    with pytest.raises(ApiSpecParseError):
        parse_api_spec_text("")


def test_api_spec_suffixes_cover_json_and_yaml() -> None:
    assert ".json" in API_SPEC_SUFFIXES
    assert ".yaml" in API_SPEC_SUFFIXES
    assert ".yml" in API_SPEC_SUFFIXES


def test_parse_openapi3_yaml_text() -> None:
    yaml_payload = (
        "openapi: '3.0.0'\n"
        "info:\n"
        "  title: YAML API\n"
        "  version: '1.0'\n"
        "servers:\n"
        "  - url: https://api.acme.example\n"
        "paths:\n"
        "  /ping:\n"
        "    get: {}\n"
    )
    spec = parse_api_spec_text(yaml_payload, suffix=".yaml")
    assert spec["format"] == "openapi3"
    assert spec["base_urls"] == ["https://api.acme.example"]
    assert spec["endpoints"] == [{"method": "GET", "path": "/ping"}]


# ---------------------------------------------------------------------------
# URL extraction + scope enforcement
# ---------------------------------------------------------------------------


def test_extract_url_seeds_scope_filters_out_of_scope_servers(tmp_path: Path) -> None:
    spec = parse_api_spec_file(_write_spec(tmp_path, "openapi.json", _OPENAPI_FIXTURE))
    scope = {"domains": ["acme.example"]}
    result = extract_url_seeds(spec, scope_manifest=scope)
    assert result["base_urls"] == [
        "https://api.acme.example/v1",
        "https://staging-api.acme.example/v1",
    ]
    assert "https://api.acme.example/v1/users" in result["urls"]
    assert "https://staging-api.acme.example/v1/users" in result["urls"]
    assert result["out_of_scope_count"] == 0
    assert result["endpoint_count"] >= 3


def test_extract_url_seeds_strict_wildcard_domain_match(tmp_path: Path) -> None:
    spec = parse_api_spec_file(_write_spec(tmp_path, "openapi.json", _OPENAPI_FIXTURE))
    scope = {"domains": ["*.acme.example"]}
    result = extract_url_seeds(spec, scope_manifest=scope)
    assert "https://staging-api.acme.example/v1/users" in result["urls"]
    assert "https://api.acme.example/v1/users" in result["urls"]


def test_extract_url_seeds_drops_endpoints_outside_scope(tmp_path: Path) -> None:
    document = {
        "openapi": "3.0.0",
        "info": {"title": "x", "version": "1"},
        "servers": [
            {"url": "https://api.acme.example"},
            {"url": "https://api.other.example"},
        ],
        "paths": {"/data": {"get": {}}},
    }
    spec = parse_api_spec_file(_write_spec(tmp_path, "openapi.json", document))
    scope = {"domains": ["acme.example"]}
    result = extract_url_seeds(spec, scope_manifest=scope)
    assert result["urls"] == ["https://api.acme.example/data"]
    assert result["base_urls"] == ["https://api.acme.example"]


def test_extract_url_seeds_without_scope_returns_nothing(tmp_path: Path) -> None:
    spec = parse_api_spec_file(_write_spec(tmp_path, "openapi.json", _OPENAPI_FIXTURE))
    result = extract_url_seeds(spec, scope_manifest=None)
    assert result["urls"] == []
    assert result["base_urls"] == []
    assert result["out_of_scope_count"] >= 1


def test_extract_url_seeds_respects_url_prefix_scope(tmp_path: Path) -> None:
    document = {
        "openapi": "3.0.0",
        "info": {"title": "x", "version": "1"},
        "servers": [{"url": "https://portal.acme.example/api"}],
        "paths": {
            "/public/health": {"get": {}},
            "/admin/users": {"get": {}},
        },
    }
    spec = parse_api_spec_file(_write_spec(tmp_path, "openapi.json", document))
    scope = {"urls": ["https://portal.acme.example/api/public/"]}
    result = extract_url_seeds(spec, scope_manifest=scope)
    assert result["urls"] == [
        "https://portal.acme.example/api/public/health",
    ]


def test_extract_url_seeds_base_url_override_still_scope_checked(tmp_path: Path) -> None:
    document = {
        "openapi": "3.0.0",
        "info": {"title": "x", "version": "1"},
        "paths": {"/ping": {"get": {}}},
    }
    spec = parse_api_spec_file(_write_spec(tmp_path, "openapi.json", document))
    allowed = extract_url_seeds(
        spec,
        scope_manifest={"domains": ["acme.example"]},
        base_url_override="https://api.acme.example",
    )
    assert allowed["urls"] == ["https://api.acme.example/ping"]
    blocked = extract_url_seeds(
        spec,
        scope_manifest={"domains": ["acme.example"]},
        base_url_override="https://api.other.example",
    )
    assert blocked["urls"] == []


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


def test_classify_api_spec_value_detects_openapi(tmp_path: Path) -> None:
    path = _write_spec(tmp_path, "openapi.json", _OPENAPI_FIXTURE)
    assert classify_api_spec_value(str(path)) is True


def test_classify_api_spec_value_rejects_random_json(tmp_path: Path) -> None:
    path = tmp_path / "random.json"
    path.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    assert classify_api_spec_value(str(path)) is False


def test_classify_api_spec_value_rejects_missing_file(tmp_path: Path) -> None:
    assert classify_api_spec_value(str(tmp_path / "missing.json")) is False


def test_classify_api_spec_value_handles_file_uri(tmp_path: Path) -> None:
    path = _write_spec(tmp_path, "openapi.json", _OPENAPI_FIXTURE)
    uri = "file://" + str(path).replace("\\", "/")
    assert classify_api_spec_value(uri) is True


def test_classify_api_spec_value_ignores_non_spec_suffixes(tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_text(json.dumps(_OPENAPI_FIXTURE), encoding="utf-8")
    assert classify_api_spec_value(str(path)) is False


# ---------------------------------------------------------------------------
# Integration: kill-chain classifier picks up api_spec seeds
# ---------------------------------------------------------------------------


def test_engagement_orchestrator_classifier_returns_api_spec(tmp_path: Path) -> None:
    path = _write_spec(tmp_path, "openapi.json", _OPENAPI_FIXTURE)
    from forge.engagement_orchestrator import _classify_seed_value

    assert _classify_seed_value(str(path)) == "api_spec"


def test_webui_classifier_returns_api_spec(tmp_path: Path) -> None:
    path = _write_spec(tmp_path, "openapi.json", _OPENAPI_FIXTURE)
    from forge.webui.seeds import classify_seed_value

    assert classify_seed_value(str(path)) == "api_spec"


# ---------------------------------------------------------------------------
# Schema + migration
# ---------------------------------------------------------------------------


def _build_db(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    apply_schema(con)
    run_migrations(con)
    validate_canonical_schema(con)
    con.execute(
        """
        INSERT INTO engagements (id, name, scope_json, status, operator)
        VALUES (2001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'tester')
        """
    )
    con.commit()
    return con


def test_schema_accepts_api_spec_seed_type(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "schema.db")
    try:
        con.execute(
            """
            INSERT INTO engagement_seeds (engagement_id, seed_value, seed_type)
            VALUES (2001, 'file:///tmp/openapi.json', 'api_spec')
            """
        )
        con.commit()
        rows = con.execute(
            "SELECT seed_type FROM engagement_seeds WHERE engagement_id=2001"
        ).fetchall()
        assert [row["seed_type"] for row in rows] == ["api_spec"]
    finally:
        con.close()


def test_target_version_covers_api_spec(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "ver.db")
    try:
        row = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()
        assert int(row[0]) == TARGET_VERSION
        assert TARGET_VERSION >= 52
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------


def test_extract_url_seeds_bounded(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("forge.seeds.api_spec_parser.MAX_EXTRACTED_URL_SEEDS", 2)
    document = {
        "openapi": "3.0.0",
        "info": {"title": "x", "version": "1"},
        "servers": [{"url": "https://api.acme.example"}],
        "paths": {f"/path{n}": {"get": {}} for n in range(5)},
    }
    spec = parse_api_spec_file(_write_spec(tmp_path, "big.json", document))
    result = extract_url_seeds(spec, scope_manifest=_SCOPE_MANIFEST)
    assert result["limit_reached"] is True
    assert len(result["urls"]) == 2


def test_max_spec_file_bytes_constant_is_reasonable() -> None:
    # 10 MiB cap by default — plenty for every real spec but still bounded.
    assert MAX_SPEC_FILE_BYTES == 10 * 1024 * 1024
