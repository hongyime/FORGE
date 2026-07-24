from __future__ import annotations

import json
import sqlite3
import sys
import types
from pathlib import Path

from forge.db.schema import apply_schema
from forge.utils.intel import shodan_lookup as shodan_module
from forge.utils.intel import http_pacing
from forge.utils.intel import urlscan_lookup as urlscan_module
from forge.utils.intel.shodan_lookup import lookup_shodan_domain
from forge.utils.intel.shodan_lookup import persist_shodan_findings
from forge.utils.intel.urlscan_lookup import persist_urlscan_findings
from forge.utils.intel.urlscan_lookup import search_urlscan


def _bootstrap_engagement(db_path: Path, engagement_id: int = 1001) -> None:
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (?, ?, ?, 'ACTIVE', ?)
            ON CONFLICT(id) DO NOTHING
            """,
            (engagement_id, f"engagement-{engagement_id}", '["acme.example"]', "tester"),
        )
        con.commit()
    finally:
        con.close()


def test_persist_shodan_findings_uses_synthetic_ip_for_bare_subdomains_and_counts_exactly(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "eng.db"
    _bootstrap_engagement(db_path)

    stats = persist_shodan_findings(
        "acme.example",
        1001,
        db_path,
        host_result=None,
        domain_result={
            "domain": "acme.example",
            "subdomains": ["app", "cdn", "api"],
            "records": [
                {"subdomain": "app", "type": "A", "value": "203.0.113.10"},
                {"subdomain": "api", "type": "A", "value": "203.0.113.11"},
            ],
            "tags": [],
        },
    )

    assert stats["hosts_inserted"] == 3

    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            """
            SELECT hostname, ip, host_context
            FROM hosts
            WHERE engagement_id=1001
            ORDER BY hostname
            """
        ).fetchall()
    finally:
        con.close()

    host_map = {str(row[0]): (str(row[1]), json.loads(str(row[2] or "{}"))) for row in rows}
    assert host_map["app.acme.example"][0] == "203.0.113.10"
    assert host_map["api.acme.example"][0] == "203.0.113.11"
    assert host_map["cdn.acme.example"][0].startswith("198.18.")
    assert host_map["cdn.acme.example"][0] != "cdn.acme.example"
    assert host_map["cdn.acme.example"][1]["discovery"] == "shodan_dns"
    assert host_map["cdn.acme.example"][1]["synthetic_ip"] is True


def test_persist_shodan_findings_promotes_web_services_to_recursive_url_seeds(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "eng.db"
    _bootstrap_engagement(db_path)

    stats = persist_shodan_findings(
        "acme.example",
        1001,
        db_path,
        host_result={
            "ip": "203.0.113.10",
            "found": True,
            "host": {
                "ip": "203.0.113.10",
                "hostnames": ["www.acme.example", "api.acme.example", "other.example"],
                "ports": [22, 443, 8443],
                "services": [
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "service": "nginx",
                        "version": "1.25",
                        "banner": "HTTP/1.1 200 OK",
                    },
                    {
                        "port": 8443,
                        "protocol": "tcp",
                        "service": "https-alt",
                        "version": "",
                        "banner": "",
                    },
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "service": "ssh",
                        "version": "OpenSSH",
                        "banner": "SSH-2.0-OpenSSH",
                    },
                ],
                "cves": [],
            },
        },
        domain_result={"domain": "acme.example", "subdomains": [], "records": [], "tags": []},
    )

    assert stats["url_seeds_inserted"] == 4

    con = sqlite3.connect(db_path)
    try:
        seed_rows = {
            (str(row[0]), str(row[1])): json.loads(str(row[2] or "{}"))
            for row in con.execute(
                """
                SELECT seed_value, seed_type, metadata_json
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        crawl_rows = {
            str(row[0]): json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT final_url, tech_stack_json
                FROM crawl_results
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()

    assert ("https://www.acme.example", "url") in seed_rows
    assert ("https://api.acme.example:8443", "url") in seed_rows
    assert all("other.example" not in url for url, _seed_type in seed_rows)
    assert all(":22" not in url for url, _seed_type in seed_rows)
    assert seed_rows[("https://www.acme.example", "url")]["provider_sources"] == ["shodan"]
    assert seed_rows[("https://www.acme.example", "url")]["port"] == 443
    assert crawl_rows["https://www.acme.example"]["discovered_from"] == "shodan_host_service"
    assert crawl_rows["https://www.acme.example"]["provider_sources"] == ["shodan"]


def test_persist_shodan_findings_preserves_in_scope_http_location_paths(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "eng.db"
    _bootstrap_engagement(db_path)

    stats = persist_shodan_findings(
        "203.0.113.30",
        1001,
        db_path,
        host_result={
            "ip": "203.0.113.30",
            "found": True,
            "host": {
                "ip": "203.0.113.30",
                "hostnames": [],
                "ports": [443],
                "services": [
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "service": "https",
                        "http": {
                            "host": "portal.acme.example",
                            "location": (
                                "https://portal.acme.example/login?"
                                "token=shodan-token-do-not-store&view=public"
                            ),
                            "redirect": "https://outside.example/login",
                        },
                    },
                ],
                "cves": [],
            },
        },
        domain_result={"domain": "acme.example", "subdomains": [], "records": [], "tags": []},
    )

    assert stats["url_seeds_inserted"] == 2

    con = sqlite3.connect(db_path)
    try:
        seed_rows = {
            (str(row[0]), str(row[1])): json.loads(str(row[2] or "{}"))
            for row in con.execute(
                """
                SELECT seed_value, seed_type, metadata_json
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        crawl_rows = {
            str(row[0]): json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT final_url, tech_stack_json
                FROM crawl_results
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()

    location_url = "https://portal.acme.example/login?view=public"
    assert ("https://portal.acme.example", "url") in seed_rows
    assert (location_url, "url") in seed_rows
    assert all("outside.example" not in url for url, _seed_type in seed_rows)
    assert all("shodan-token-do-not-store" not in url for url, _seed_type in seed_rows)
    assert seed_rows[(location_url, "url")]["provider_sources"] == ["shodan"]
    assert seed_rows[(location_url, "url")]["shodan_http_field"] == "location"
    assert crawl_rows[location_url]["discovered_from"] == "shodan_host_service"
    assert crawl_rows[location_url]["provider_sources"] == ["shodan"]


def test_persist_shodan_findings_promotes_service_level_hostnames_to_recursive_url_seeds(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "eng.db"
    _bootstrap_engagement(db_path)

    stats = persist_shodan_findings(
        "203.0.113.20",
        1001,
        db_path,
        host_result={
            "ip": "203.0.113.20",
            "found": True,
            "host": {
                "ip": "203.0.113.20",
                "hostnames": [],
                "ports": [80, 443, 8080, 9443],
                "services": [
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "service": "https",
                        "http": {"host": "admin.acme.example:443"},
                        "ssl": {
                            "cert": {
                                "subject": {"CN": "cert.acme.example"},
                                "extensions": {
                                    "subjectAltName": "DNS:san.acme.example, DNS:outside.example"
                                },
                            }
                        },
                    },
                    {
                        "port": 8080,
                        "protocol": "tcp",
                        "service": "http",
                        "http": {"host": "console.acme.example:8080"},
                    },
                    {
                        "port": 9443,
                        "protocol": "tcp",
                        "service": "https-alt",
                        "ssl": {"server_name": "sni.acme.example"},
                    },
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "service": "http",
                        "http": {"host": "outside.example"},
                    },
                ],
                "cves": [],
            },
        },
        domain_result={"domain": "acme.example", "subdomains": [], "records": [], "tags": []},
    )

    assert stats["url_seeds_inserted"] == 5

    con = sqlite3.connect(db_path)
    try:
        seed_rows = {
            (str(row[0]), str(row[1])): json.loads(str(row[2] or "{}"))
            for row in con.execute(
                """
                SELECT seed_value, seed_type, metadata_json
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        crawl_rows = {
            str(row[0]): json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT final_url, tech_stack_json
                FROM crawl_results
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()

    for expected_url in {
        "https://admin.acme.example",
        "https://cert.acme.example",
        "https://san.acme.example",
        "http://console.acme.example:8080",
        "https://sni.acme.example:9443",
    }:
        assert (expected_url, "url") in seed_rows
        assert seed_rows[(expected_url, "url")]["provider_sources"] == ["shodan"]
        assert crawl_rows[expected_url]["discovered_from"] == "shodan_host_service"

    assert all("outside.example" not in url for url, _seed_type in seed_rows)


def test_lookup_shodan_domain_paces_requests_and_respects_retry_after(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "eng.db"
    _bootstrap_engagement(db_path)
    monkeypatch.setenv("FORGE_SHODAN_API_KEY", "test-key")
    monkeypatch.setenv("FORGE_SHODAN_REQUEST_DELAY_SECONDS", "0.25")
    monkeypatch.setenv("FORGE_SHODAN_RATE_LIMIT_RETRIES", "1")
    monkeypatch.setenv("FORGE_SHODAN_MAX_RETRY_AFTER_SECONDS", "1")
    http_pacing._clear_rate_limit_cooldowns_for_tests()
    sleeps: list[float] = []
    monkeypatch.setattr(shodan_module.time, "sleep", lambda seconds: sleeps.append(float(seconds)))

    class _Response:
        def __init__(
            self,
            status_code: int,
            payload: dict[str, object],
            headers: dict[str, str] | None = None,
        ) -> None:
            self.status_code = status_code
            self._payload = payload
            self.headers = headers or {}

        def json(self) -> dict[str, object]:
            return self._payload

    responses = [
        _Response(200, {"acme.example": "203.0.113.10"}),
        _Response(429, {}, {"Retry-After": "2"}),
        _Response(
            200,
            {
                "hostnames": ["www.acme.example"],
                "domains": [],
            },
        ),
    ]
    calls: list[tuple[str, dict[str, object]]] = []

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> "_Client":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def get(self, url: str, *, params: dict[str, object]) -> _Response:
            calls.append((url, dict(params)))
            return responses.pop(0)

    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_Client))

    result = lookup_shodan_domain("acme.example", 1001, db_path)

    assert "error" not in result
    assert result["records"] == [
        {"subdomain": "acme.example", "type": "A", "value": "203.0.113.10", "last_seen": ""}
    ]
    assert result["subdomains"] == ["www"]
    assert [call[0] for call in calls] == [
        "https://api.shodan.io/dns/resolve",
        "https://api.shodan.io/shodan/host/203.0.113.10",
        "https://api.shodan.io/shodan/host/203.0.113.10",
    ]
    assert sleeps == [0.25, 0.25, 1.0, 0.25]


def test_lookup_shodan_domain_uses_dns_resolve_and_caps_host_enrichment(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "eng.db"
    _bootstrap_engagement(db_path)
    monkeypatch.setenv("FORGE_SHODAN_API_KEY", "test-key")
    monkeypatch.setenv("FORGE_SHODAN_REQUEST_DELAY_SECONDS", "0")
    monkeypatch.setenv("FORGE_SHODAN_RATE_LIMIT_RETRIES", "0")
    http_pacing._clear_rate_limit_cooldowns_for_tests()

    class _Response:
        def __init__(self, status_code: int, payload: dict[str, object]) -> None:
            self.status_code = status_code
            self._payload = payload
            self.headers: dict[str, str] = {}

        def json(self) -> dict[str, object]:
            return self._payload

    calls: list[tuple[str, dict[str, object]]] = []

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> "_Client":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def get(self, url: str, *, params: dict[str, object]) -> _Response:
            calls.append((url, dict(params)))
            if url.endswith("/dns/resolve"):
                return _Response(
                    200,
                    {
                        "acme.example": "203.0.113.10",
                        "www.acme.example": "203.0.113.11",
                        "api.acme.example": "203.0.113.12",
                        "cdn.acme.example": "203.0.113.13",
                    },
                )
            if "/shodan/host/" in url:
                return _Response(
                    200,
                    {
                        "hostnames": ["www.acme.example", "api.acme.example", "outside.example"],
                        "domains": ["acme.example", "other.example"],
                    },
                )
            raise AssertionError(url)

    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_Client))

    result = lookup_shodan_domain("acme.example", 1001, db_path)

    assert "error" not in result
    assert set(result["subdomains"]) == {"api", "www"}
    assert calls[0][0] == "https://api.shodan.io/dns/resolve"
    host_calls = [call for call in calls if "/shodan/host/" in call[0]]
    assert len(host_calls) == 3
    assert all("/dns/domain" not in call[0] for call in calls)
    assert {call[1]["minify"] for call in host_calls} == {"true"}
    assert {call[1]["key"] for call in calls} == {"test-key"}


def test_search_urlscan_paces_requests_and_respects_retry_after(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "eng.db"
    _bootstrap_engagement(db_path)
    monkeypatch.setenv("FORGE_URLSCAN_REQUEST_DELAY_SECONDS", "0.5")
    monkeypatch.setenv("FORGE_URLSCAN_RATE_LIMIT_RETRIES", "1")
    monkeypatch.setenv("FORGE_URLSCAN_MAX_RETRY_AFTER_SECONDS", "2")
    http_pacing._clear_rate_limit_cooldowns_for_tests()
    sleeps: list[float] = []
    monkeypatch.setattr(urlscan_module.time, "sleep", lambda seconds: sleeps.append(float(seconds)))

    class _Response:
        def __init__(
            self,
            status_code: int,
            payload: dict[str, object],
            headers: dict[str, str] | None = None,
        ) -> None:
            self.status_code = status_code
            self._payload = payload
            self.headers = headers or {}

        def json(self) -> dict[str, object]:
            return self._payload

    responses = [
        _Response(429, {}, {"Retry-After": "5"}),
        _Response(
            200,
            {
                "total": 1,
                "results": [
                    {
                        "_id": "scan-1",
                        "_score": 42,
                        "task": {
                            "time": "2026-07-14T00:00:00Z",
                            "url": "https://portal.acme.example/login",
                        },
                        "page": {
                            "domain": "portal.acme.example",
                            "url": "https://portal.acme.example",
                            "ip": "203.0.113.20",
                            "server": "nginx",
                        },
                    }
                ],
            },
        ),
    ]
    calls: list[tuple[str, dict[str, object]]] = []

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> "_Client":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def get(self, url: str, **kwargs: object) -> _Response:
            calls.append((url, dict(kwargs)))
            return responses.pop(0)

    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_Client))

    result = search_urlscan("acme.example", 1001, db_path, max_results=5)

    assert "error" not in result
    assert result["found"] is True
    assert result["related_domains"] == ["portal.acme.example"]
    assert result["scans"][0]["task_url"] == "https://portal.acme.example/login"
    assert result["unique_ips"] == ["203.0.113.20"]
    assert [call[0] for call in calls] == [
        "https://urlscan.io/api/v1/search/",
        "https://urlscan.io/api/v1/search/",
    ]
    assert calls[0][1]["params"] == {"q": "domain:acme.example", "size": 5}
    assert sleeps == [0.5, 2.0, 0.5]


def test_persist_urlscan_findings_marks_synthetic_placeholder_rows_explicitly(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "eng.db"
    _bootstrap_engagement(db_path)

    summary = persist_urlscan_findings(
        "acme.example",
        1001,
        db_path,
        {
            "hostname": "acme.example",
            "total": 2,
            "scans": [
                {
                    "domain": "portal.acme.example",
                    "ip": "203.0.113.20",
                    "url": "https://portal.acme.example",
                    "task_url": (
                        "https://portal.acme.example/login?"
                        "token=urlscan-token-do-not-store&view=public"
                    ),
                    "urls": [
                        (
                            "https://cdn.acme.example/static/app.js?"
                            "access_token=urlscan-cdn-token-do-not-store&asset=1"
                        ),
                        "https://outside.example/ignore?asset=1",
                    ],
                }
            ],
            "related_domains": ["portal.acme.example", "cdn.acme.example"],
            "unique_ips": ["203.0.113.20"],
            "servers": ["nginx"],
        },
    )

    assert summary["hosts_written"] == 2
    assert summary["url_seeds_written"] == 3

    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            """
            SELECT hostname, ip, host_context
            FROM hosts
            WHERE engagement_id=1001
            ORDER BY hostname
            """
        ).fetchall()
        seed_rows = {
            (str(row[0]), str(row[1])): json.loads(str(row[2] or "{}"))
            for row in con.execute(
                """
                SELECT seed_value, seed_type, metadata_json
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        crawl_rows = {
            str(row[0]): json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT final_url, tech_stack_json
                FROM crawl_results
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        db_dump = "\n".join(con.iterdump())
    finally:
        con.close()

    host_map = {str(row[0]): (str(row[1]), json.loads(str(row[2] or "{}"))) for row in rows}
    assert host_map["portal.acme.example"][0] == "203.0.113.20"
    assert host_map["portal.acme.example"][1]["synthetic_ip"] is False
    assert host_map["cdn.acme.example"][0].startswith("198.18.")
    assert host_map["cdn.acme.example"][1]["synthetic_ip"] is True
    assert ("https://portal.acme.example", "url") in seed_rows
    assert ("https://portal.acme.example/login?view=public", "url") in seed_rows
    assert ("https://cdn.acme.example/static/app.js?asset=1", "url") in seed_rows
    assert ("https://outside.example/ignore?asset=1", "url") not in seed_rows
    assert seed_rows[("https://portal.acme.example", "url")]["provider_sources"] == ["urlscan"]
    assert seed_rows[("https://portal.acme.example", "url")]["url_role"] == "page"
    assert (
        seed_rows[("https://portal.acme.example/login?view=public", "url")]["url_role"]
        == "task"
    )
    assert (
        seed_rows[("https://cdn.acme.example/static/app.js?asset=1", "url")]["url_role"]
        == "observed"
    )
    assert crawl_rows["https://portal.acme.example"]["discovered_from"] == "urlscan_page"
    assert crawl_rows["https://portal.acme.example"]["provider_sources"] == ["urlscan"]
    assert "urlscan-token-do-not-store" not in db_dump
    assert "urlscan-cdn-token-do-not-store" not in db_dump
