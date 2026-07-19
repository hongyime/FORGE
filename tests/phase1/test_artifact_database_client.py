from __future__ import annotations

import pytest

from forge.utils.artifact_database_client import (
    database_client_config_artifact_label,
    database_client_host_candidates,
)


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
