"""Tests for :class:`forge.onboard.supabase_scanner.SupabaseDeepScanner`.

The scanner's HTTP getter is injectable so these tests never touch the
live Supabase Data API. The ``_MockHttp`` responder returns a routed
response for the Data API OpenAPI root plus one page per table.
"""

from __future__ import annotations

from typing import Any

import pytest

from forge.onboard.supabase_scanner import (
    SUPABASE_DEEP_SCANNER_SCHEMA_VERSION,
    SupabaseDeepScanner,
    SupabaseScanResult,
    SupabaseScannerError,
)


# ---------------------------------------------------------------------------
# Mock HTTP responder
# ---------------------------------------------------------------------------


class _MockHttp:
    def __init__(self, routes: list[tuple[str, dict[str, Any]]]) -> None:
        self.routes = routes
        self.called: list[tuple[str, dict[str, str]]] = []

    def __call__(self, url: str, *, headers: dict[str, str]) -> dict[str, Any]:
        self.called.append((url, dict(headers)))
        for needle, response in self.routes:
            if needle in url:
                # Allow dynamic responses based on the Range header for
                # pagination tests. The route value may be a dict (static)
                # or a callable (dynamic).
                if callable(response):
                    return response(url, headers)
                return response
        return {"status": 404, "headers": {}, "json": {"message": "not found"}}


class _MockPost:
    def __init__(self, responder: Any) -> None:
        self.responder = responder
        self.called: list[
            tuple[str, dict[str, Any], dict[str, str]]
        ] = []

    def __call__(
        self,
        url: str,
        *,
        body: dict[str, Any],
        headers: dict[str, str],
    ) -> dict[str, Any]:
        self.called.append((url, dict(body), dict(headers)))
        return self.responder(url, body, headers)


def test_supabase_http_layer_retries_429_and_records_backoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(
        "forge.onboard.rate_limit.time.sleep", lambda seconds: sleeps.append(seconds)
    )
    responses = iter(
        [
            {"status": 429, "headers": {"Retry-After": "4"}, "json": {}},
            {"status": 200, "headers": {}, "json": {"paths": {}}},
        ]
    )
    scanner = SupabaseDeepScanner(
        "abc123",
        "key",
        http_get=lambda _url, *, headers: next(responses),
    )
    result = SupabaseScanResult(project_ref="abc123")

    response = scanner._call(
        "https://abc123.supabase.co/rest/v1/",
        result=result,
        context="discover_tables",
    )

    assert response is not None and response["status"] == 200
    assert sleeps == [4.0]
    assert result.rate_limit["backoff_events"][0]["context"] == "discover_tables"


def test_supabase_management_post_uses_rate_limit_backoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(
        "forge.onboard.rate_limit.time.sleep", lambda seconds: sleeps.append(seconds)
    )
    responses = iter(
        [
            {"status": 429, "headers": {"Retry-After": "3"}, "json": {}},
            {"status": 200, "headers": {}, "json": []},
        ]
    )
    scanner = SupabaseDeepScanner(
        "abc123",
        management_pat="hidden-value",
        http_post=lambda _url, *, body, headers: next(responses),
    )
    result = SupabaseScanResult(project_ref="abc123")

    response = scanner._management_query("select 1", result=result, context="query")

    assert response is not None and response["status"] == 200
    assert sleeps == [3.0]


def test_supabase_wait_cap_records_skipped_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forge.onboard.rate_limit import request_with_rate_limit_backoff as retry

    def _short_budget(request: Any, **kwargs: Any) -> Any:
        kwargs["max_total_wait_seconds"] = 1
        kwargs["sleep_fn"] = lambda _seconds: None
        return retry(request, **kwargs)

    monkeypatch.setattr(
        "forge.onboard.supabase_scanner.request_with_rate_limit_backoff",
        _short_budget,
    )
    scanner = SupabaseDeepScanner(
        "abc123",
        "key",
        http_get=lambda _url, *, headers: {
            "status": 429,
            "headers": {"Retry-After": "2"},
            "json": {},
        },
    )
    result = SupabaseScanResult(project_ref="abc123")

    response = scanner._call(
        "https://abc123.supabase.co/rest/v1/",
        result=result,
        context="discover_tables",
    )

    assert response is None
    assert result.rate_limit["backoff_events"][-1]["reason"] == "total_wait_cap"
    assert any(
        error["detail"] == "rate_limit_request_skipped"
        and error["reason"] == "total_wait_cap"
        for error in result.source_errors
    )


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------


def test_supabase_scanner_schema_version() -> None:
    assert SUPABASE_DEEP_SCANNER_SCHEMA_VERSION == "forge.supabase_deep_scanner.v1"


def test_supabase_scanner_rejects_empty_project_ref() -> None:
    with pytest.raises(SupabaseScannerError, match="project_ref"):
        SupabaseDeepScanner("", "anon-key")


def test_supabase_scanner_rejects_invalid_project_ref() -> None:
    with pytest.raises(SupabaseScannerError, match="invalid"):
        SupabaseDeepScanner("project/invalid", "anon-key")


def test_supabase_scanner_rejects_empty_key() -> None:
    with pytest.raises(SupabaseScannerError, match="API key"):
        SupabaseDeepScanner("abc123", "")


def test_supabase_scanner_resolves_base_url_from_project_ref() -> None:
    scanner = SupabaseDeepScanner("abc123", "anon-key")
    assert scanner.base_url == "https://abc123.supabase.co"


def test_supabase_scanner_overrides_base_url() -> None:
    scanner = SupabaseDeepScanner(
        "abc123", "anon-key", base_url="https://sb.corp-target.io"
    )
    assert scanner.base_url == "https://sb.corp-target.io"


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_scan_all_discovers_tables_from_openapi_root() -> None:
    openapi_body = {
        "paths": {
            "/": {},
            "/orders": {},
            "/orders/{id}": {},
            "/users": {},
            "/rpc/calculate": {},  # RPC, not a table
        }
    }
    routes = [
        ("rest/v1/orders", {"status": 200, "headers": {}, "json": []}),
        ("rest/v1/users", {"status": 200, "headers": {}, "json": []}),
        ("rest/v1/", {"status": 200, "headers": {}, "json": openapi_body}),
    ]
    http = _MockHttp(routes)
    scanner = SupabaseDeepScanner("abc123", "anon-key", http_get=http)
    result = scanner.scan_all()
    assert result.tables_total == 2
    assert result.tables_scanned == 2
    assert {t.name for t in result.tables} == {"orders", "users"}


def test_scan_all_falls_back_to_definitions_section() -> None:
    openapi_body = {
        "paths": {"/": {}},
        "definitions": {
            "users": {"type": "object"},
            "profiles": {"type": "object"},
            "public.events": {"type": "object"},
        },
    }
    routes = [
        ("rest/v1/users", {"status": 200, "headers": {}, "json": []}),
        ("rest/v1/profiles", {"status": 200, "headers": {}, "json": []}),
        ("rest/v1/events", {"status": 200, "headers": {}, "json": []}),
        ("rest/v1/", {"status": 200, "headers": {}, "json": openapi_body}),
    ]
    http = _MockHttp(routes)
    scanner = SupabaseDeepScanner("abc123", "anon-key", http_get=http)
    result = scanner.scan_all()
    assert {t.name for t in result.tables} == {"users", "profiles", "events"}


def test_scan_all_handles_missing_tables_gracefully() -> None:
    routes = [
        ("rest/v1/", {"status": 404, "headers": {}, "json": {}}),
    ]
    http = _MockHttp(routes)
    scanner = SupabaseDeepScanner("abc123", "anon-key", http_get=http)
    result = scanner.scan_all()
    assert result.tables_total == 0
    assert result.tables_scanned == 0
    assert any(err["context"] == "discover_tables" for err in result.source_errors)


# ---------------------------------------------------------------------------
# Row scanning + seed extraction
# ---------------------------------------------------------------------------


def test_scan_table_extracts_seeds_from_string_cells() -> None:
    openapi_body = {"paths": {"/users": {}}}
    users_rows = [
        {
            "id": 1,
            "email": "admin@corp-target.io",
            "profile_url": "https://portal.corp-target.io/u/1",
            "last_ip": "10.0.0.5",
            "handle": "@admin_bot",
            "notes": "owns api.corp-target.io",
        },
        {
            "id": 2,
            "email": "ops@corp-target.io",
            "profile_url": "https://portal.corp-target.io/u/2",
            "last_ip": "10.0.0.9",
            "notes": "aws_account_id = '123456789012'",
        },
    ]
    routes = [
        ("rest/v1/users", {"status": 200, "headers": {}, "json": users_rows}),
        ("rest/v1/", {"status": 200, "headers": {}, "json": openapi_body}),
    ]
    http = _MockHttp(routes)
    scanner = SupabaseDeepScanner("abc123", "anon-key", http_get=http)
    result = scanner.scan_all()

    seed_values = {(s["target_type"], s["target_value"]) for s in result.seeds}
    assert ("email", "admin@corp-target.io") in seed_values
    assert ("email", "ops@corp-target.io") in seed_values
    assert ("url", "https://portal.corp-target.io/u/1") in seed_values
    assert ("domain", "portal.corp-target.io") in seed_values
    assert ("ipv4", "10.0.0.5") in seed_values
    assert ("ipv4", "10.0.0.9") in seed_values
    assert ("domain", "api.corp-target.io") in seed_values
    assert ("cloud_ref", "cloud_ref:aws_account:123456789012") in seed_values


def test_scan_table_scans_nested_json_cells() -> None:
    openapi_body = {"paths": {"/events": {}}}
    events_rows = [
        {
            "id": 1,
            "payload": {
                "endpoint": "https://api.corp-target.io/v1/health",
                "contact": "ops@corp-target.io",
                "tags": ["prod", "db-primary.corp-target.io"],
            },
        }
    ]
    routes = [
        ("rest/v1/events", {"status": 200, "headers": {}, "json": events_rows}),
        ("rest/v1/", {"status": 200, "headers": {}, "json": openapi_body}),
    ]
    http = _MockHttp(routes)
    scanner = SupabaseDeepScanner("abc123", "anon-key", http_get=http)
    result = scanner.scan_all()

    seed_values = {(s["target_type"], s["target_value"]) for s in result.seeds}
    assert ("url", "https://api.corp-target.io/v1/health") in seed_values
    assert ("email", "ops@corp-target.io") in seed_values
    assert ("domain", "db-primary.corp-target.io") in seed_values


def test_scan_table_classifies_bare_cloud_values_in_columns() -> None:
    openapi_body = {"paths": {"/accounts": {}}}
    rows = [
        {
            "id": 1,
            "aws_account_id": "123456789012",
            "azure_tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        }
    ]
    routes = [
        ("rest/v1/accounts", {"status": 200, "headers": {}, "json": rows}),
        ("rest/v1/", {"status": 200, "headers": {}, "json": openapi_body}),
    ]
    http = _MockHttp(routes)
    scanner = SupabaseDeepScanner("abc123", "anon-key", http_get=http)
    result = scanner.scan_all()

    cloud = {s["target_value"] for s in result.seeds if s["target_type"] == "cloud_ref"}
    assert "cloud_ref:aws_account:123456789012" in cloud
    assert (
        "cloud_ref:azure_tenant:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" in cloud
    )


def test_scan_table_detects_secret_hits() -> None:
    openapi_body = {"paths": {"/config": {}}}
    rows = [
        {
            "name": "aws",
            "value": "AKIAIOSFODNN7EXAMPLE and ghp_" + "x" * 40,
        }
    ]
    routes = [
        ("rest/v1/config", {"status": 200, "headers": {}, "json": rows}),
        ("rest/v1/", {"status": 200, "headers": {}, "json": openapi_body}),
    ]
    http = _MockHttp(routes)
    scanner = SupabaseDeepScanner("abc123", "anon-key", http_get=http)
    result = scanner.scan_all()
    labels = {h["label"] for h in result.secret_hits}
    assert "aws_access_key" in labels
    assert "github_pat" in labels
    for hit in result.secret_hits:
        if hit["label"] == "aws_access_key":
            assert "AKIAIOSFODNN7EXAMPLE" not in hit["redacted_sample"]
            assert hit["table"] == "config"
            assert hit["column"] == "value"


def test_scan_table_marks_significant_columns() -> None:
    openapi_body = {"paths": {"/profiles": {}}}
    rows = [
        {"id": 1, "email": "foo@corp-target.io", "handle": "@foo"},
    ]
    routes = [
        ("rest/v1/profiles", {"status": 200, "headers": {}, "json": rows}),
        ("rest/v1/", {"status": 200, "headers": {}, "json": openapi_body}),
    ]
    http = _MockHttp(routes)
    scanner = SupabaseDeepScanner("abc123", "anon-key", http_get=http)
    result = scanner.scan_all()
    profiles_summary = next(t for t in result.tables if t.name == "profiles")
    assert "email" in profiles_summary.significant_columns
    assert "handle" in profiles_summary.significant_columns
    assert "email" in profiles_summary.columns_sampled
    assert "handle" in profiles_summary.columns_sampled


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


def test_scan_table_paginates_rows() -> None:
    openapi_body = {"paths": {"/orders": {}}}

    def _orders_response(url: str, headers: dict[str, str]) -> dict[str, Any]:
        range_header = headers.get("Range", "")
        start = int(range_header.split("-")[0]) if range_header else 0
        page: list[dict[str, Any]] = []
        if start == 0:
            page = [
                {"id": i, "email": f"user{i}@corp-target.io"} for i in range(1000)
            ]
        elif start == 1000:
            page = [
                {"id": i, "email": f"user{i}@corp-target.io"}
                for i in range(1000, 1500)
            ]
        return {
            "status": 200,
            "headers": {"Content-Range": f"{start}-{start + len(page) - 1}/1500"},
            "json": page,
        }

    routes = [
        ("rest/v1/orders", _orders_response),
        ("rest/v1/", {"status": 200, "headers": {}, "json": openapi_body}),
    ]
    http = _MockHttp(routes)
    scanner = SupabaseDeepScanner(
        "abc123", "anon-key", http_get=http, page_size=1000
    )
    result = scanner.scan_all()
    orders_summary = next(t for t in result.tables if t.name == "orders")
    assert orders_summary.rows_scanned == 1500
    # Every user email should surface as a seed.
    emails = {s["target_value"] for s in result.seeds if s["target_type"] == "email"}
    assert "user0@corp-target.io" in emails
    assert "user1499@corp-target.io" in emails


def test_scan_table_respects_max_rows_cap() -> None:
    openapi_body = {"paths": {"/orders": {}}}

    def _large_response(url: str, headers: dict[str, str]) -> dict[str, Any]:
        range_header = headers.get("Range", "0-999")
        start = int(range_header.split("-")[0]) if range_header else 0
        end = int(range_header.split("-")[1]) if range_header else 999
        page = [
            {"id": i, "email": f"user{i}@corp-target.io"}
            for i in range(start, end + 1)
        ]
        return {"status": 200, "headers": {}, "json": page}

    routes = [
        ("rest/v1/orders", _large_response),
        ("rest/v1/", {"status": 200, "headers": {}, "json": openapi_body}),
    ]
    http = _MockHttp(routes)
    scanner = SupabaseDeepScanner(
        "abc123",
        "anon-key",
        http_get=http,
        max_rows_per_table=200,
        page_size=100,
    )
    result = scanner.scan_all()
    orders_summary = next(t for t in result.tables if t.name == "orders")
    assert orders_summary.rows_scanned == 200
    assert orders_summary.truncated is True


def test_scan_all_respects_max_tables_cap() -> None:
    openapi_body = {"paths": {f"/t{i}": {} for i in range(5)}}
    routes: list[tuple[str, Any]] = []
    # Table rows: empty
    for i in range(5):
        routes.append(
            (f"rest/v1/t{i}", {"status": 200, "headers": {}, "json": []})
        )
    routes.append(
        ("rest/v1/", {"status": 200, "headers": {}, "json": openapi_body})
    )
    http = _MockHttp(routes)
    scanner = SupabaseDeepScanner(
        "abc123", "anon-key", http_get=http, max_tables=2
    )
    result = scanner.scan_all()
    assert result.tables_total == 5
    assert result.tables_scanned == 2


# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------


def test_scan_all_dedupes_seeds_across_tables() -> None:
    openapi_body = {"paths": {"/a": {}, "/b": {}}}
    rows = [{"email": "shared@corp-target.io"}]
    routes = [
        ("rest/v1/a", {"status": 200, "headers": {}, "json": rows}),
        ("rest/v1/b", {"status": 200, "headers": {}, "json": rows}),
        ("rest/v1/", {"status": 200, "headers": {}, "json": openapi_body}),
    ]
    http = _MockHttp(routes)
    scanner = SupabaseDeepScanner("abc123", "anon-key", http_get=http)
    result = scanner.scan_all()
    emails = [s for s in result.seeds if s["target_type"] == "email"]
    assert sum(
        1 for s in emails if s["target_value"] == "shared@corp-target.io"
    ) == 1


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def test_scan_table_records_http_errors() -> None:
    openapi_body = {"paths": {"/forbidden": {}}}
    routes = [
        ("rest/v1/forbidden", {"status": 403, "headers": {}, "json": {}}),
        ("rest/v1/", {"status": 200, "headers": {}, "json": openapi_body}),
    ]
    http = _MockHttp(routes)
    scanner = SupabaseDeepScanner("abc123", "anon-key", http_get=http)
    result = scanner.scan_all()
    forbidden = next(t for t in result.tables if t.name == "forbidden")
    assert forbidden.status == "error"
    assert any("HTTP 403" in err["detail"] for err in result.source_errors)


def test_scan_table_contains_http_exceptions() -> None:
    openapi_body = {"paths": {"/boom": {}}}

    def _flaky(url: str, headers: dict[str, str]) -> dict[str, Any]:
        if "rest/v1/boom" in url:
            raise RuntimeError("connection reset")
        return {"status": 200, "headers": {}, "json": openapi_body}

    scanner = SupabaseDeepScanner("abc123", "anon-key", http_get=_flaky)
    result = scanner.scan_all()
    assert any("connection reset" in err["detail"] for err in result.source_errors)


# ---------------------------------------------------------------------------
# Auth headers
# ---------------------------------------------------------------------------


def test_scanner_sends_apikey_and_bearer_headers() -> None:
    openapi_body = {"paths": {"/users": {}}}
    routes = [
        ("rest/v1/users", {"status": 200, "headers": {}, "json": []}),
        ("rest/v1/", {"status": 200, "headers": {}, "json": openapi_body}),
    ]
    http = _MockHttp(routes)
    scanner = SupabaseDeepScanner("abc123", "sek-key-value", http_get=http)
    scanner.scan_all()
    for _, headers in http.called:
        assert headers.get("apikey") == "sek-key-value"
        assert headers.get("Authorization") == "Bearer sek-key-value"


def test_scanner_sets_range_header_when_fetching_rows() -> None:
    openapi_body = {"paths": {"/users": {}}}
    routes = [
        (
            "rest/v1/users",
            {"status": 200, "headers": {}, "json": []},
        ),
        ("rest/v1/", {"status": 200, "headers": {}, "json": openapi_body}),
    ]
    http = _MockHttp(routes)
    scanner = SupabaseDeepScanner(
        "abc123", "anon-key", http_get=http, page_size=100
    )
    scanner.scan_all()
    range_headers = [
        headers.get("Range")
        for url, headers in http.called
        if "rest/v1/users" in url and "Range" in headers
    ]
    assert any(r == "0-99" for r in range_headers)


# ---------------------------------------------------------------------------
# No-op cases
# ---------------------------------------------------------------------------


def test_scan_table_with_zero_rows_returns_ok_summary() -> None:
    openapi_body = {"paths": {"/empty": {}}}
    routes = [
        ("rest/v1/empty", {"status": 200, "headers": {}, "json": []}),
        ("rest/v1/", {"status": 200, "headers": {}, "json": openapi_body}),
    ]
    http = _MockHttp(routes)
    scanner = SupabaseDeepScanner("abc123", "anon-key", http_get=http)
    result = scanner.scan_all()
    empty = next(t for t in result.tables if t.name == "empty")
    assert empty.status == "ok"
    assert empty.rows_scanned == 0
    assert empty.seeds_added == 0


def test_scan_result_to_dict_shape() -> None:
    openapi_body = {"paths": {"/users": {}}}
    routes = [
        ("rest/v1/users", {"status": 200, "headers": {}, "json": []}),
        ("rest/v1/", {"status": 200, "headers": {}, "json": openapi_body}),
    ]
    http = _MockHttp(routes)
    scanner = SupabaseDeepScanner("abc123", "anon-key", http_get=http)
    result = scanner.scan_all()
    payload = result.to_dict()
    assert payload["schema_version"] == SUPABASE_DEEP_SCANNER_SCHEMA_VERSION
    assert payload["project_ref"] == "abc123"
    assert payload["base_url"] == "https://abc123.supabase.co"
    assert isinstance(payload["tables"], list)
    assert isinstance(payload["seeds"], list)
    assert isinstance(payload["secret_hits"], list)


# ---------------------------------------------------------------------------
# Management API transport
# ---------------------------------------------------------------------------


def test_management_api_pat_can_replace_api_key() -> None:
    post = _MockPost(
        lambda *_: {"status": 201, "headers": {}, "json": []}
    )
    get = _MockHttp([])
    scanner = SupabaseDeepScanner(
        "abc123",
        "dead-api-key",
        management_pat="sbp_test_placeholder",
        http_get=get,
        http_post=post,
    )
    result = scanner.scan_all()
    assert result.project_ref == "abc123"
    assert len(post.called) == 1
    assert get.called == []


def test_management_api_rejects_empty_project_ref() -> None:
    with pytest.raises(SupabaseScannerError, match="project_ref"):
        SupabaseDeepScanner("", management_pat="sbp_test_placeholder")


def test_management_api_rejects_missing_credentials() -> None:
    with pytest.raises(SupabaseScannerError, match="API key or Management API PAT"):
        SupabaseDeepScanner("abc123")


def test_management_api_discovers_schema_qualified_tables() -> None:
    pat = "sbp_test_placeholder"
    post = _MockPost(
        lambda *_: {
            "status": 201,
            "headers": {},
            "json": [
                {"schemaname": "auth", "tablename": "users"},
                {"schemaname": "public", "tablename": "people"},
            ],
        }
    )
    scanner = SupabaseDeepScanner(
        "abc123", management_pat=pat, http_post=post
    )
    result = scanner.scan_all()
    assert result.tables_total == 2
    assert [table.name for table in result.tables] == [
        "auth.users",
        "public.people",
    ]
    assert post.called[0][1]["query"] == (
        "SELECT schemaname, tablename FROM pg_tables "
        "WHERE schemaname NOT IN ('pg_catalog','information_schema') "
        "ORDER BY schemaname, tablename"
    )
    assert post.called[0][0] == (
        "https://api.supabase.com/v1/projects/abc123/database/query"
    )
    assert post.called[0][2] == {
        "Authorization": f"Bearer {pat}",
        "Content-Type": "application/json",
    }
    assert result.endpoints_called == [post.called[0][0]] * 3


def test_management_api_fetches_quoted_rows_into_seed_extraction() -> None:
    def _respond(_url: str, body: dict[str, Any], _headers: dict[str, str]):
        query = body["query"]
        if query.startswith("SELECT schemaname"):
            rows = [{"schemaname": "public", "tablename": "people"}]
        elif 'FROM "public"."people"' in query:
            rows = [
                {
                    "email": "ops@corp-target.io",
                    "value": "ghp_" + "x" * 40,
                }
            ]
        else:
            rows = []
        return {"status": 201, "headers": {}, "json": rows}

    post = _MockPost(_respond)
    scanner = SupabaseDeepScanner(
        "abc123",
        management_pat="sbp_test_placeholder",
        http_post=post,
        page_size=20,
    )
    result = scanner.scan_all()
    queries = [call[1]["query"] for call in post.called]
    assert 'SELECT * FROM "public"."people" LIMIT 20 OFFSET 0' in queries
    assert result.rows_scanned == 1
    assert any(
        seed["target_type"] == "email"
        and seed["target_value"] == "ops@corp-target.io"
        for seed in result.seeds
    )
    assert any(hit["label"] == "github_pat" for hit in result.secret_hits)


def test_management_api_skips_invalid_identifiers_before_query() -> None:
    post = _MockPost(
        lambda _url, body, _headers: {
            "status": 201,
            "headers": {},
            "json": (
                [{"schemaname": 'public"; DROP TABLE users;--', "tablename": "users"}]
                if body["query"].startswith("SELECT schemaname")
                else []
            ),
        }
    )
    scanner = SupabaseDeepScanner(
        "abc123", management_pat="sbp_test_placeholder", http_post=post
    )
    result = scanner.scan_all()
    assert result.tables_total == 1
    assert result.tables[0].status == "skipped"
    assert result.tables[0].detail == "invalid_table_identifier"
    assert len(post.called) == 1
    assert result.source_errors == [
        {
            "context": "supabase:abc123:fetch",
            "detail": "invalid_table_identifier",
        }
    ]


def test_management_api_errors_never_include_pat() -> None:
    pat = "sbp_test_placeholder"

    def _raise_pat(_url: str, _body: dict[str, Any], _headers: dict[str, str]):
        raise RuntimeError(f"request failed with {pat}")

    scanner = SupabaseDeepScanner(
        "abc123", management_pat=pat, http_post=_MockPost(_raise_pat)
    )
    result = scanner.scan_all()
    assert result.source_errors == [
        {"context": "discover_tables", "detail": "request_failed"}
    ]
    assert pat not in str(result.source_errors)

    rejected = SupabaseDeepScanner(
        "abc123",
        management_pat=pat,
        http_post=_MockPost(
            lambda *_: {
                "status": 401,
                "headers": {},
                "json": {"message": pat},
                "text": pat,
            }
        ),
    ).scan_all()
    assert rejected.source_errors == [
        {"context": "discover_tables", "detail": "HTTP 401"}
    ]
    assert pat not in str(rejected.source_errors)
