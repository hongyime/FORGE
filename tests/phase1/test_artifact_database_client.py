from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

import pytest

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _artifact_format_label,
    _classify_remote_artifact_url,
    _select_remote_artifact_filename,
)
from forge.utils.artifact_database_client import (
    database_client_config_artifact_label,
    database_client_endpoint_candidates,
    database_client_host_candidates,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


@pytest.mark.parametrize(
    ("value", "label"),
    [
        ("DBeaverData/workspace/.metadata/.plugins/org.jkiss.dbeaver.core/data-sources.json", "dbeaver-datasources"),
        (".dbeaver/data-sources.xml", "dbeaver-datasources"),
        (".idea/dataSources.xml", "jetbrains-datasources"),
        ("DataGrip/project/.idea/dataSources.local.xml", "jetbrains-datasources"),
        ("TablePlus/Connections.plist", "tableplus-connections"),
        ("SQL Developer/system/connections.xml", "sqldeveloper-connections"),
        ("pgAdmin/servers.json", "pgadmin-servers"),
        ("HeidiSQL/heidisql.ini", "heidisql-config"),
        ("DbVisualizer/connections.xml", "dbvis-connections"),
        ("data-sources.json.dbeaver-datasources", "dbeaver-datasources"),
    ],
)
def test_database_client_config_artifact_label_recognizes_source_paths(
    value: str,
    label: str,
) -> None:
    assert database_client_config_artifact_label(value) == label


@pytest.mark.parametrize(
    "value",
    [
        "data-sources.json",
        "dataSources.xml",
        "connections.xml",
        "servers.json",
        "Bookmarks/prod.duck",
        "notes/tableplus-connections.txt",
    ],
)
def test_database_client_config_artifact_label_avoids_generic_configs(
    value: str,
) -> None:
    assert database_client_config_artifact_label(value) == ""


def test_database_client_host_candidates_extracts_common_shapes() -> None:
    payload = """
    {"host": "dbeaver-db.acme.example", "database": "prod"}
    {"host": "192.0.2.44"}
    {"host": "db-primary"}
    {"host": "db-primary:5432"}
    {"host": "db_primary"}
    {"host": "[2001:db8::1]"}
    {"server": "2001:db8::2"}
    {"server": "[2001:db8::3]:5432"}
    <property name="server" value="datagrip-db.acme.example" />
    <property value="reverse-db.acme.example" name="hostname" />
    <host>sqldeveloper-db.acme.example</host>
    <key>Host</key><string>tableplus-db.acme.example</string>
    Host=heidi-db.acme.example
    Host=localhost
    Database=not-a-host
    """

    assert database_client_host_candidates(payload) == [
        "dbeaver-db.acme.example",
        "192.0.2.44",
        "db-primary",
        "db_primary",
        "2001:db8::1",
        "2001:db8::2",
        "2001:db8::3",
        "datagrip-db.acme.example",
        "reverse-db.acme.example",
        "sqldeveloper-db.acme.example",
        "tableplus-db.acme.example",
        "heidi-db.acme.example",
    ]


def test_database_client_host_candidates_rejects_non_ipv6_bracketed_values() -> None:
    payload = """
    {"host": "[deaf]"}
    {"host": "[123]"}
    {"host": "[abc.def]"}
    {"host": "[dead:beef]"}
    {"host": "[abc:]"}
    {"host": "[:abc]"}
    {"host": "[1:2:3:4:5:6:7:8:9]"}
    {"host": "[192.0.2.1]"}
    {"host": "999.999.999.999"}
    {"host": "127.0.0.1"}
    {"host": "0.0.0.0"}
    {"host": "224.0.0.1"}
    {"host": "::1"}
    {"host": "[::]"}
    {"host": "db-primary:99999"}
    {"host": "123"}
    {"host": "db-"}
    """

    assert database_client_host_candidates(payload) == []


def test_database_client_endpoint_candidates_preserve_driver_port_and_database() -> None:
    payload = """
    driver = com.mysql.cj.jdbc.Driver
    host = mysql-db.acme.example
    port = 3306
    database = prod
    password = mysql-password-do-not-store
    """

    assert database_client_endpoint_candidates(payload) == [
        "mysql://mysql-db.acme.example:3306/prod",
    ]


def test_database_client_endpoint_candidates_strip_userinfo_and_secret_query() -> None:
    payload = """
    url = mysql://db-user:db-password-do-not-store@mysql-db.acme.example:3306/prod?password=secret&sslmode=require
    jdbc = jdbc:postgresql://pg-user:pg-password-do-not-store@warehouse.acme.example:5432/reporting?token=secret
    """

    assert database_client_endpoint_candidates(payload) == [
        "mysql://mysql-db.acme.example:3306/prod",
        "postgresql://warehouse.acme.example:5432/reporting",
    ]


def test_database_client_endpoint_candidates_preserve_host_only_recursive_fallback() -> None:
    payload = """
    host = ambiguous-db.acme.example
    database = prod
    """

    assert database_client_endpoint_candidates(payload) == [
        "postgres://ambiguous-db.acme.example",
    ]


def test_database_client_structured_payload_uses_detected_scheme_not_postgres_default(
    tmp_path: Path,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)
    payload = """
    driver = mysql
    host = mysql-db.acme.example
    port = 3306
    database = prod
    password = mysql-password-do-not-store
    """

    structured = processor._database_client_structured_payload_text(
        payload,
        source_hint=".dbeaver/data-sources.json",
    )

    assert structured == "mysql://mysql-db.acme.example:3306/prod"
    assert "postgres://" not in structured
    assert "password" not in structured


def test_artifact_queue_processor_extracts_database_client_configs(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_database_clients"
    dbeaver_root = artifact_root / "DBeaverData" / "workspace" / ".metadata" / ".plugins" / "org.jkiss.dbeaver.core"
    dbeaver_root.mkdir(parents=True)
    bootstrap_engagement(db_path, name="Database Client Config Test")

    dbeaver_path = dbeaver_root / "data-sources.json"
    dbeaver_path.write_text(
        json.dumps(
            {
                "connections": {
                    "prod": {
                        "host": "dbeaver-db.acme.example",
                        "url": "jdbc:postgresql://warehouse.acme.example:5432/prod",
                        "owner": "dbeaver-owner@acme.example",
                        "dashboard": "https://dbeaver.acme.example/docs",
                        "firebase": "https://dbeaver-firebase.firebaseio.com",
                        "bucket": "s3://acme-dbeaver-bucket/backups/prod.sql",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    datagrip_bundle = artifact_root / "datagrip-project.zip"
    with zipfile.ZipFile(datagrip_bundle, "w") as zf:
        zf.writestr(
            "project/.idea/dataSources.xml",
            "\n".join(
                [
                    "<project><component name='DataSourceManagerImpl'>",
                    "<data-source name='prod'>",
                    '<property name="host" value="datagrip-db.acme.example" />',
                    '<property name="owner" value="datagrip-owner@acme.example" />',
                    '<property name="gcs" value="gs://acme-datagrip-gcs/exports/prod.sql" />',
                    "</data-source></component></project>",
                ]
            ),
        )

    assert _classify_remote_artifact_url("https://downloads.acme.example/.dbeaver/data-sources.json") == "config"
    assert _classify_remote_artifact_url("https://downloads.acme.example/project/.idea/dataSources.xml") == "config"
    assert _artifact_format_label(dbeaver_path) == "dbeaver-datasources"
    assert _artifact_format_label("dataSources.xml.jetbrains-datasources") == "jetbrains-datasources"
    assert (
        _select_remote_artifact_filename(
            77,
            "https://downloads.acme.example/.dbeaver/data-sources.json",
            "config",
        )
        == "data-sources.json.dbeaver-datasources"
    )

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=4)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 2
    assert summary.processed >= 2
    assert summary.discovered_seeds >= 5

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute(
                "SELECT email FROM emails WHERE engagement_id=1001"
            ).fetchall()
        }
        assert "dbeaver-owner@acme.example" in emails
        assert "datagrip-owner@acme.example" in emails

        seeds = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT seed_value, seed_type
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert ("dbeaver-db.acme.example", "subdomain") in seeds
        assert ("datagrip-db.acme.example", "subdomain") in seeds
        assert ("warehouse.acme.example", "subdomain") in seeds
        assert ("https://dbeaver.acme.example/docs", "url") in seeds

        cloud_assets = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT asset_type, identifier
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert ("aws_s3", "acme-dbeaver-bucket") in cloud_assets
        assert ("firebase", "dbeaver-firebase") in cloud_assets
        assert ("gcs", "acme-datagrip-gcs") in cloud_assets

        artifact_meta = {
            row[0]: json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert artifact_meta[dbeaver_path.resolve().as_posix()]["format"] == "dbeaver-datasources"
        assert artifact_meta[datagrip_bundle.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()
