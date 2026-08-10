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
from forge.utils.artifact_connection_client import (
    connection_client_config_artifact_label,
    connection_client_host_candidates,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


@pytest.mark.parametrize(
    ("value", "label"),
    [
        ("WinSCP.ini", "winscp-config"),
        ("MobaXterm.ini", "mobaxterm-config"),
        ("Sessions.mxtsessions", "mobaxterm-sessions"),
        ("prod.ini.securecrt-session", "securecrt-session"),
        ("SecureCRT/Sessions/prod.ini", "securecrt-session"),
        ("SuperPuTTY/Sessions.xml", "superputty-config"),
        ("SuperPuTTY/Sessions/prod.xml", "superputty-config"),
        ("FileZilla/sitemanager.xml", "filezilla-config"),
        ("FileZilla/recentservers.xml", "filezilla-config"),
        ("sitemanager.xml.filezilla-config", "filezilla-config"),
        ("Cyberduck/Bookmarks/prod.duck", "cyberduck-bookmark"),
        ("Transmit/Favorites.xml", "transmit-favorites"),
        (".lftp/bookmarks", "lftp-config"),
        (".ncftp/bookmarks", "ncftp-config"),
        ("prod.remmina", "remmina-config"),
        ("remmina/prod.remmina", "remmina-config"),
        ("download.prod.remmina.remmina-config", "remmina-config"),
        ("PuTTY.reg", "putty-config"),
    ],
)
def test_connection_client_config_artifact_label_recognizes_source_paths(
    value: str,
    label: str,
) -> None:
    assert connection_client_config_artifact_label(value) == label


@pytest.mark.parametrize(
    "value",
    [
        "settings.ini",
        "sessions.xml",
        "config/SOFTWARE",
        "browser/History",
        "mobaxterm.log",
        "SuperPuTTY/theme.xml",
        "SuperPuTTY/misc.settings",
        "sitemanager.xml",
        "recentservers.xml",
        "Bookmarks/prod.duck",
        "Transmit/theme.xml",
        "lftp-bookmarks.txt",
        "prod.remmina.txt",
    ],
)
def test_connection_client_config_artifact_label_avoids_generic_configs(
    value: str,
) -> None:
    assert connection_client_config_artifact_label(value) == ""


def test_connection_client_host_candidates_extracts_fields_and_commands() -> None:
    payload = """
    HostName=winscp-sftp.acme.example
    "HostName"="putty-edge.acme.example"
    Host: securecrt.acme.example
    Bookmark1=ssh -p 2222 deploy@mobax.acme.example
    Bookmark2=sftp admin@198.51.100.42
    Bookmark3=ftp ftp-cli.acme.example
    Bookmark4=lftp ftp://lftp.acme.example/drop
    server=rdp.acme.example:3389
    ssh_tunnel_server=bastion.acme.example
    HostName=localhost
    ssh -p 22
    """

    assert connection_client_host_candidates(payload) == [
        "winscp-sftp.acme.example",
        "putty-edge.acme.example",
        "securecrt.acme.example",
        "rdp.acme.example",
        "bastion.acme.example",
        "mobax.acme.example",
        "198.51.100.42",
        "ftp-cli.acme.example",
        "lftp.acme.example",
    ]


def test_connection_client_host_candidates_extracts_xml_and_plist_hosts() -> None:
    payload = """
    <Server><Host>filezilla.acme.example</Host></Server>
    <dict><key>Hostname</key><string>cyberduck.acme.example</string></dict>
    <dict><key>Server</key><string>transmit.acme.example</string></dict>
    <Host>localhost</Host>
    """

    assert connection_client_host_candidates(payload) == [
        "filezilla.acme.example",
        "cyberduck.acme.example",
        "transmit.acme.example",
    ]


def test_connection_client_host_candidates_ignores_hyphenated_tools() -> None:
    payload = """
    # ssh-keygen -t ed25519 -f ~/.ssh/deploy.internal.example.com_key
    # ssh-copy-id deploy@copyid.internal.example.com
    ftp-mirror mirror.internal.example.com
    """

    assert connection_client_host_candidates(payload) == []


def test_connection_client_host_candidates_handles_scp_remote_specs() -> None:
    payload = """
    scp file.txt user@prod.acme.example:/var/www/html
    scp deploy@logs.acme.example:archive/app.log local.tar.gz
    scp -p user@preserve.acme.example:/var/www/html localfile.txt
    scp -P 2222 user@port.acme.example:/var/www/html localfile.txt
    """

    assert connection_client_host_candidates(payload) == [
        "prod.acme.example",
        "logs.acme.example",
        "preserve.acme.example",
        "port.acme.example",
    ]


def test_connection_client_host_candidates_ignores_trailing_command_args() -> None:
    payload = """
    ssh deploy@prod.acme.example systemctl status app.service
    sftp user@sftp.acme.example archive.tar.gz
    """

    assert connection_client_host_candidates(payload) == [
        "prod.acme.example",
        "sftp.acme.example",
    ]


def test_connection_client_host_candidates_skips_command_option_values() -> None:
    payload = """
    ssh -F myconfig.bak -E ssh.log deploy@prod.acme.example
    ssh -D 127.0.0.1:1080 deploy@dynamic.acme.example
    sftp -F sftp.conf user@sftp.acme.example
    scp -F scp.conf file.txt user@scp.acme.example:/var/www/html
    """

    assert connection_client_host_candidates(payload) == [
        "prod.acme.example",
        "dynamic.acme.example",
        "sftp.acme.example",
        "scp.acme.example",
    ]


def test_connection_client_host_candidates_skips_quoted_option_values() -> None:
    payload = """
    ssh -o ProxyCommand='ssh -W %h:%p jump.acme.example' deploy@prod.acmehost.example
    """

    assert connection_client_host_candidates(payload) == ["prod.acmehost.example"]


def test_artifact_queue_processor_extracts_connection_client_configs(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_connection_clients"
    filezilla_root = artifact_root / "FileZilla"
    securecrt_root = artifact_root / "SecureCRT" / "Sessions"
    remmina_root = artifact_root / "remmina"
    filezilla_root.mkdir(parents=True)
    securecrt_root.mkdir(parents=True)
    remmina_root.mkdir(parents=True)
    bootstrap_engagement(db_path, name="Connection Client Config Test")

    winscp_path = artifact_root / "WinSCP.ini"
    winscp_path.write_text(
        "\n".join(
            [
                "[Sessions\\prod-sftp]",
                "HostName=winscp-sftp.acme.example",
                "UserName=winscp-owner@acme.example",
                "Dashboard=https://winscp.acme.example/files",
                "Firebase=https://winscp-firebase.firebaseio.com",
                "Bucket=s3://acme-winscp-bucket/sessions/prod.ini",
            ]
        ),
        encoding="utf-8",
    )

    putty_path = artifact_root / "PuTTY.reg"
    putty_path.write_text(
        "\n".join(
            [
                "Windows Registry Editor Version 5.00",
                r"[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\prod]",
                '"HostName"="putty-edge.acme.example"',
                '"UserName"="putty-owner@acme.example"',
                '"Supabase"="https://puttyvault.supabase.co/rest/v1/sessions"',
            ]
        ),
        encoding="utf-16",
    )

    securecrt_path = securecrt_root / "prod.ini"
    securecrt_path.write_text(
        "\n".join(
            [
                'S:"Hostname"=securecrt.acme.example',
                'S:"Username"=securecrt-owner@acme.example',
                'S:"GcsBucket"=gs://acme-securecrt-gcs/sessions/prod.ini',
            ]
        ),
        encoding="utf-8",
    )

    filezilla_path = filezilla_root / "sitemanager.xml"
    filezilla_path.write_text(
        "\n".join(
            [
                "<Servers><Server>",
                "<Host>filezilla.acme.example</Host>",
                "<User>filezilla-owner@acme.example</User>",
                "<Dashboard>https://filezilla.acme.example/uploads</Dashboard>",
                "<Firebase>https://filezilla-firebase.firebaseio.com</Firebase>",
                "</Server></Servers>",
            ]
        ),
        encoding="utf-8",
    )

    remmina_path = remmina_root / "prod.remmina"
    remmina_path.write_text(
        "\n".join(
            [
                "[remmina]",
                "name=Production RDP",
                "protocol=RDP",
                "server=rdp.acme.example:3389",
                "ssh_tunnel_server=bastion.acme.example",
                "owner=remmina-owner@acme.example",
                "dashboard=https://remmina.acme.example/sessions",
                "firebase=https://remmina-firebase.firebaseio.com",
            ]
        ),
        encoding="utf-8",
    )

    mobax_bundle = artifact_root / "mobaxterm-sessions.zip"
    with zipfile.ZipFile(mobax_bundle, "w") as zf:
        zf.writestr(
            "Sessions.mxtsessions",
            "\n".join(
                [
                    "[Bookmarks]",
                    "Bookmark1=ssh -p 2222 deploy@mobax.acme.example",
                    "Bookmark2=sftp admin@198.51.100.42",
                    "Owner=mobax-owner@acme.example",
                    "Firebase=https://mobax-firebase.firebaseio.com",
                ]
            ),
        )

    cyberduck_bundle = artifact_root / "cyberduck-bookmarks.zip"
    with zipfile.ZipFile(cyberduck_bundle, "w") as zf:
        zf.writestr(
            "Cyberduck/Bookmarks/prod.duck",
            "\n".join(
                [
                    "<plist><dict>",
                    "<key>Hostname</key><string>cyberduck.acme.example</string>",
                    "<key>Owner</key><string>cyberduck-owner@acme.example</string>",
                    "<key>Bucket</key><string>gs://acme-cyberduck-gcs/bookmarks/prod.duck</string>",
                    "</dict></plist>",
                ]
            ),
        )

    assert _classify_remote_artifact_url("https://downloads.acme.example/WinSCP.ini") == "config"
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/SecureCRT/Sessions/prod.ini")
        == "config"
    )
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/FileZilla/sitemanager.xml")
        == "config"
    )
    assert _classify_remote_artifact_url("https://downloads.acme.example/prod.remmina") == "config"
    assert _artifact_format_label(winscp_path) == "winscp-config"
    assert _artifact_format_label(putty_path) == "putty-config"
    assert _artifact_format_label(securecrt_path) == "securecrt-session"
    assert _artifact_format_label(filezilla_path) == "filezilla-config"
    assert _artifact_format_label(remmina_path) == "remmina-config"
    assert _artifact_format_label("prod.ini.securecrt-session") == "securecrt-session"
    assert _artifact_format_label("prod.duck.cyberduck-bookmark") == "cyberduck-bookmark"
    assert _artifact_format_label("prod.remmina.remmina-config") == "remmina-config"
    assert (
        _select_remote_artifact_filename(
            77,
            "https://downloads.acme.example/SecureCRT/Sessions/prod.ini",
            "config",
        )
        == "prod.ini.securecrt-session"
    )
    assert (
        _select_remote_artifact_filename(
            77,
            "https://downloads.acme.example/FileZilla/sitemanager.xml",
            "config",
        )
        == "sitemanager.xml.filezilla-config"
    )
    assert (
        _select_remote_artifact_filename(
            77,
            "https://downloads.acme.example/prod.remmina",
            "config",
        )
        == "prod.remmina"
    )

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=4)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 6
    assert summary.processed >= 6
    assert summary.discovered_seeds >= 8

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "winscp-owner@acme.example" in emails
        assert "putty-owner@acme.example" in emails
        assert "securecrt-owner@acme.example" in emails
        assert "filezilla-owner@acme.example" in emails
        assert "mobax-owner@acme.example" in emails
        assert "cyberduck-owner@acme.example" in emails
        assert "remmina-owner@acme.example" in emails

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
        assert ("winscp-sftp.acme.example", "subdomain") in seeds
        assert ("putty-edge.acme.example", "subdomain") in seeds
        assert ("securecrt.acme.example", "subdomain") in seeds
        assert ("filezilla.acme.example", "subdomain") in seeds
        assert ("mobax.acme.example", "subdomain") in seeds
        assert ("cyberduck.acme.example", "subdomain") in seeds
        assert ("rdp.acme.example", "subdomain") in seeds
        assert ("bastion.acme.example", "subdomain") in seeds
        assert ("198.51.100.42", "ipv4") in seeds
        assert ("https://winscp.acme.example/files", "url") in seeds
        assert ("https://filezilla.acme.example/uploads", "url") in seeds
        assert ("https://remmina.acme.example/sessions", "url") in seeds
        assert ("https://puttyvault.supabase.co/rest/v1/sessions", "url") in seeds
        assert ("puttyvault.supabase.co", "subdomain") not in seeds
        assert ("rdp.acme.example:3389", "subdomain") not in seeds

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
        assert ("aws_s3", "acme-winscp-bucket") in cloud_assets
        assert ("firebase", "filezilla-firebase") in cloud_assets
        assert ("firebase", "mobax-firebase") in cloud_assets
        assert ("firebase", "remmina-firebase") in cloud_assets
        assert ("firebase", "winscp-firebase") in cloud_assets
        assert ("gcs", "acme-cyberduck-gcs") in cloud_assets
        assert ("gcs", "acme-securecrt-gcs") in cloud_assets
        assert ("supabase", "puttyvault") in cloud_assets

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
        assert artifact_meta[winscp_path.resolve().as_posix()]["format"] == "winscp-config"
        assert artifact_meta[putty_path.resolve().as_posix()]["format"] == "putty-config"
        assert artifact_meta[securecrt_path.resolve().as_posix()]["format"] == "securecrt-session"
        assert artifact_meta[filezilla_path.resolve().as_posix()]["format"] == "filezilla-config"
        assert artifact_meta[remmina_path.resolve().as_posix()]["format"] == "remmina-config"
        assert artifact_meta[mobax_bundle.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[cyberduck_bundle.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()
