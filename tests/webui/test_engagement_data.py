import sqlite3

from forge.webui.engagement_data import (
    asset_tree_payload,
    asset_tree_route_payload,
    engagement_assets_payload,
    engagement_assets_route_payload,
    vulnerability_summary_payload,
    vulnerability_summary_route_payload,
)


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.executescript(
        """
        CREATE TABLE crawl_results (
            engagement_id INTEGER,
            final_url TEXT,
            url TEXT,
            title TEXT,
            screenshot_path TEXT,
            tech_stack_json TEXT,
            discovered_at TEXT
        );

        CREATE TABLE port_scan_results (
            engagement_id INTEGER,
            host TEXT,
            port INTEGER,
            service TEXT,
            version TEXT,
            confidence REAL,
            cdn_detected INTEGER,
            waf_detected INTEGER,
            scanned_at TEXT
        );

        CREATE TABLE passive_vulns (
            engagement_id INTEGER,
            vuln_id TEXT,
            plugin TEXT,
            url TEXT,
            severity TEXT,
            verified INTEGER,
            false_positive INTEGER,
            discovered_at TEXT
        );

        CREATE TABLE auth_test_results (
            engagement_id INTEGER,
            target_url TEXT,
            attack_type TEXT,
            success INTEGER,
            tested_at TEXT
        );

        CREATE TABLE vulnerability_findings (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            host_id INTEGER,
            severity TEXT,
            vuln_type TEXT,
            title TEXT,
            target_url TEXT,
            parameter TEXT,
            evidence TEXT,
            cloud_provider TEXT,
            resource_id TEXT,
            found_at TEXT
        );
        """
    )
    return con


def _seed_report_data(con: sqlite3.Connection) -> None:
    con.execute(
        """
        INSERT INTO crawl_results
            (engagement_id, final_url, url, title, screenshot_path, tech_stack_json, discovered_at)
        VALUES
            (1001, 'https://app.acme.example/login', 'https://app.acme.example',
             'Login', 'screens/login.png', '{"react":true}', '2026-08-13T10:00:00')
        """
    )
    con.execute(
        """
        INSERT INTO port_scan_results
            (engagement_id, host, port, service, version, confidence, cdn_detected, waf_detected, scanned_at)
        VALUES
            (1001, 'app.acme.example', 443, 'https', 'nginx', 0.96, 1, 0,
             '2026-08-13T10:01:00')
        """
    )
    con.executemany(
        """
        INSERT INTO passive_vulns
            (engagement_id, vuln_id, plugin, url, severity, verified, false_positive, discovered_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                1001,
                "pv-1",
                "headers",
                "https://app.acme.example",
                "HIGH",
                1,
                0,
                "2026-08-13T10:02:00",
            ),
            (
                1001,
                "pv-fp",
                "headers",
                "https://app.acme.example",
                "CRITICAL",
                1,
                1,
                "2026-08-13T10:03:00",
            ),
        ],
    )
    con.executemany(
        """
        INSERT INTO auth_test_results
            (engagement_id, target_url, attack_type, success, tested_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            (1001, "https://app.acme.example/login", "default_creds", 1, "2026-08-13T10:04:00"),
            (1001, "https://app.acme.example/login", "password_spray", 0, "2026-08-13T10:05:00"),
        ],
    )
    con.execute(
        """
        INSERT INTO vulnerability_findings
            (id, engagement_id, severity, vuln_type, title, target_url, parameter, evidence, found_at)
        VALUES
            (1, 1001, 'CRITICAL', 'XSS', 'Validated XSS',
             'https://app.acme.example/search', 'q', '', '2026-08-13T10:06:00')
        """
    )
    con.commit()


def test_engagement_assets_payload_shapes_report_data_and_filters_false_positives() -> None:
    con = _connect()
    try:
        _seed_report_data(con)

        payload = engagement_assets_payload(con, 1001)

        assert payload["crawl"] == [
            {
                "final_url": "https://app.acme.example/login",
                "title": "Login",
                "screenshot_path": "screens/login.png",
                "tech_stack_json": '{"react":true}',
                "discovered_at": "2026-08-13T10:00:00",
            }
        ]
        assert payload["ports"][0]["host"] == "app.acme.example"
        assert payload["ports"][0]["cdn_detected"] is True
        assert payload["ports"][0]["waf_detected"] is False
        assert [item["vuln_id"] for item in payload["passive_vulns"]] == ["pv-1"]
        assert payload["auth_results"][0]["success"] is False
        assert payload["cloud_assets"] == []
    finally:
        con.close()


def test_engagement_assets_route_payload_delegates_to_report_data_shape() -> None:
    con = _connect()
    try:
        _seed_report_data(con)

        payload = engagement_assets_route_payload(con, 1001)

        assert payload["crawl"][0]["final_url"] == "https://app.acme.example/login"
        assert [item["vuln_id"] for item in payload["passive_vulns"]] == ["pv-1"]
    finally:
        con.close()


def test_vulnerability_summary_payload_uses_reportability_gate() -> None:
    con = _connect()
    try:
        _seed_report_data(con)

        payload = vulnerability_summary_payload(con, 1001)

        assert payload == {
            "passive_vulns": {"HIGH": 1},
            "vulnerability_findings": {"CRITICAL": 1},
            "auth_tests": {"success": 1, "failed": 1},
        }
    finally:
        con.close()


def test_vulnerability_summary_route_payload_uses_reportability_gate() -> None:
    con = _connect()
    try:
        _seed_report_data(con)

        assert vulnerability_summary_route_payload(con, 1001) == {
            "passive_vulns": {"HIGH": 1},
            "vulnerability_findings": {"CRITICAL": 1},
            "auth_tests": {"success": 1, "failed": 1},
        }
    finally:
        con.close()


def test_asset_tree_payload_groups_ports_and_urls_by_host() -> None:
    con = _connect()
    try:
        _seed_report_data(con)

        payload = asset_tree_payload(con, 1001)

        assert payload == {
            "items": [
                {
                    "host": "app.acme.example",
                    "ports": [
                        {
                            "port": 443,
                            "service": "https",
                            "scanned_at": "2026-08-13T10:01:00",
                        }
                    ],
                    "urls": [
                        {
                            "url": "https://app.acme.example/login",
                            "title": "Login",
                            "discovered_at": "2026-08-13T10:00:00",
                        }
                    ],
                }
            ]
        }
    finally:
        con.close()


def test_asset_tree_route_payload_groups_ports_and_urls_by_host() -> None:
    con = _connect()
    try:
        _seed_report_data(con)

        payload = asset_tree_route_payload(con, 1001)

        assert payload["items"][0]["host"] == "app.acme.example"
        assert payload["items"][0]["ports"][0]["port"] == 443
        assert payload["items"][0]["urls"][0]["url"] == "https://app.acme.example/login"
    finally:
        con.close()
