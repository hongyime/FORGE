from __future__ import annotations

import pytest

from forge.utils.artifact_connection_client import (
    connection_client_config_artifact_label,
    connection_client_host_candidates,
)


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
    HostName=localhost
    ssh -p 22
    """

    assert connection_client_host_candidates(payload) == [
        "winscp-sftp.acme.example",
        "putty-edge.acme.example",
        "securecrt.acme.example",
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
