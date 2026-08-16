from __future__ import annotations

import base64
import json
import sqlite3
import threading
import time
import zipfile
from pathlib import Path
from textwrap import dedent
from typing import Any

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _classify_artifact_name,
    _classify_remote_artifact_url,
    _extract_artifact_network_endpoint_seeds,
    _select_remote_artifact_filename,
    _suffix_from_content_type,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_remote_access_host_fields() -> None:
    seeds = set(
        _extract_artifact_network_endpoint_seeds(
            "\n".join(
                [
                    "full address:s:ops-rdp.acme.example",
                    "gatewayhostname:s:https://rdpvault.supabase.co/rest/v1/sessions",
                    "Address=ica-gateway.acme.example:1494",
                    "SSLProxyHost=sslproxy.acme.example:443",
                    "ClientName=ica-owner@acme.example",
                ]
            )
        )
    )

    assert ("ops-rdp.acme.example", "subdomain") in seeds
    assert ("ica-gateway.acme.example", "subdomain") in seeds
    assert ("sslproxy.acme.example", "subdomain") in seeds
    assert ("acme.example", "domain") in seeds
    assert ("rdpvault.supabase.co", "subdomain") not in seeds
    assert ("ica-owner@acme.example", "email") not in seeds


def run_ansible_inventory_hosts() -> None:
    text = dedent(
        """
        [web]
        web1.acme.example ansible_user=ops@example.com
        api01 ansible_host=api.internal.acme.example
        db01 ansible_ssh_host=10.24.50.20
        github ansible_host=github.com
        managed ansible_host=https://ansiblevault.supabase.co/rest/v1
        """
    )

    seeds = set(_extract_artifact_network_endpoint_seeds(text, source_file="ansible/inventory"))
    generic_seeds = set(_extract_artifact_network_endpoint_seeds(text, source_file="notes.txt"))

    assert ("web1.acme.example", "subdomain") in seeds
    assert ("api.internal.acme.example", "subdomain") in seeds
    assert ("10.24.50.20", "ipv4") in seeds
    assert ("acme.example", "domain") in seeds
    assert ("github.com", "domain") not in seeds
    assert ("ansiblevault.supabase.co", "subdomain") not in seeds
    assert ("ops@example.com", "email") not in seeds
    assert ("web1.acme.example", "subdomain") not in generic_seeds
    assert ("api.internal.acme.example", "subdomain") not in generic_seeds


def run_vagrantfile_hostnames() -> None:
    text = dedent(
        """
        Vagrant.configure("2") do |config|
          config.vm.hostname = "web.vagrant.acme.example"
          api.vm.hostname = 'api.vagrant.acme.example'
          config.vm.hostname = "https://vagrantvault.supabase.co/rest/v1/vms"
          config.vm.hostname = "localhost"
        end
        """
    )

    seeds = set(_extract_artifact_network_endpoint_seeds(text, source_file="Vagrantfile"))
    generic_seeds = set(_extract_artifact_network_endpoint_seeds(text, source_file="notes.rb"))

    assert ("web.vagrant.acme.example", "subdomain") in seeds
    assert ("api.vagrant.acme.example", "subdomain") in seeds
    assert ("acme.example", "domain") in seeds
    assert ("vagrantvault.supabase.co", "subdomain") not in seeds
    assert ("localhost", "domain") not in seeds
    assert ("web.vagrant.acme.example", "subdomain") not in generic_seeds
    assert ("api.vagrant.acme.example", "subdomain") not in generic_seeds


def run_ansible_inventory_line_tokenization_uses_bounded_workers_and_preserves_order(
    monkeypatch: Any,
) -> None:
    import forge.engagement_orchestrator as orchestrator

    monkeypatch.setenv("FORGE_STATIC_ARTIFACT_MAX_WORKERS", "4")
    original_entry = orchestrator._ansible_inventory_line_host_tokens
    lines = [
        "alpha.acme.example ansible_user=ops",
        "beta01 ansible_host=beta.acme.example",
        "db01 ansible_ssh_host=10.24.50.20",
        "gamma.acme.example ansible_port=22",
    ]
    active = 0
    peak = 0
    lock = threading.Lock()

    def _fake_ansible_inventory_line_host_tokens(raw_line: str) -> list[str]:
        nonlocal active, peak
        assert raw_line in lines
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_entry(raw_line)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        orchestrator,
        "_ansible_inventory_line_host_tokens",
        _fake_ansible_inventory_line_host_tokens,
    )

    seeds = orchestrator._extract_artifact_network_endpoint_seeds(
        "\n".join(lines),
        source_file="ansible/inventory",
    )

    assert peak == 4
    assert seeds == [
        ("alpha.acme.example", "subdomain"),
        ("acme.example", "domain"),
        ("beta.acme.example", "subdomain"),
        ("10.24.50.20", "ipv4"),
        ("gamma.acme.example", "subdomain"),
    ]


def run_network_endpoint_family_dispatch_uses_bounded_workers_and_preserves_order(
    monkeypatch: Any,
) -> None:
    import forge.engagement_orchestrator as orchestrator

    monkeypatch.setenv("FORGE_STATIC_ARTIFACT_MAX_WORKERS", "6")
    original_entry = orchestrator._artifact_network_endpoint_family_seed_entries
    expected_families = {
        "ssh",
        "remote_access",
        "dns_zone",
        "hosts_file",
        "dhcp_lease",
        "vpn_endpoint",
    }
    active = 0
    peak = 0
    lock = threading.Lock()

    def _fake_network_endpoint_family_seed_entries(
        entry: tuple[str, str],
    ) -> list[tuple[str, str]]:
        nonlocal active, peak
        family, text = entry
        assert family in expected_families
        assert "ssh-edge.acme.example" in text
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_entry(entry)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        orchestrator,
        "_artifact_network_endpoint_family_seed_entries",
        _fake_network_endpoint_family_seed_entries,
    )

    seeds = orchestrator._extract_artifact_network_endpoint_seeds(
        dedent(
            """
            postgres://user:pass@db.acme.example:5432/app
            ssh-edge.acme.example ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC
            full address:s:rdp.acme.example
            $ORIGIN acme.example.
            www 300 IN A 203.0.113.24
            10.24.30.40 hosts.acme.example
            1700000000 aa:bb:cc:dd:ee:ff 10.24.30.51 lease.acme.example *
            Endpoint = vpn.acme.example:51820
            """
        )
    )

    assert peak == orchestrator.ArtifactQueueProcessor._MAX_STATIC_BATCH_WORKERS
    assert seeds == [
        ("db.acme.example", "subdomain"),
        ("acme.example", "domain"),
        ("ssh-edge.acme.example", "subdomain"),
        ("rdp.acme.example", "subdomain"),
        ("www.acme.example", "subdomain"),
        ("hosts.acme.example", "subdomain"),
        ("lease.acme.example", "subdomain"),
        ("vpn.acme.example", "subdomain"),
    ]


def run_queue_processor_extracts_ssh_artifacts_for_recursive_hosts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_ssh_hosts"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    known_hosts = artifact_root / "known_hosts"
    known_hosts.write_text(
        dedent(
            """
            bastion.acme.example,203.0.113.77 ssh-ed25519 AAAAknownhost ops@acme.example
            [git.acme.example]:2222 ssh-rsa AAAAgitkey
            github.com ssh-ed25519 AAAAgithub
            [gitlab.com]:22 ssh-rsa AAAAgitlab
            support.taplink.ws ssh-ed25519 AAAAtaplink
            msha.ke ssh-ed25519 AAAAmilkshake
            bento.me ssh-ed25519 AAAAbento
            hoo.be ssh-ed25519 AAAAhoobe
            |1|hashed-host|hashed-key ssh-ed25519 AAAAhashed
            @cert-authority *.corp.acme.example ecdsa-sha2-nistp256 AAAAca
            """
        ).strip(),
        encoding="utf-8",
    )

    authorized_keys = artifact_root / "authorized_keys"
    authorized_keys.write_text(
        ("ssh-ed25519 AAAAauthorized deploy@acme.example https://jump.acme.example/admin\n"),
        encoding="utf-8",
    )

    ssh_bundle = artifact_root / "ssh-evidence.zip"
    with zipfile.ZipFile(ssh_bundle, "w") as zf:
        zf.writestr(
            ".ssh/ssh_config",
            dedent(
                """
                Host production-jump
                  HostName jumpbox.acme.example
                  User deploy
                """
            ).strip(),
        )
        zf.writestr(
            ".ssh/ssh_known_hosts",
            "edge.acme.example ssh-ed25519 AAAAedge edge-owner@acme.example\n",
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 3
    assert summary.processed >= 3
    assert summary.discovered_seeds >= 8

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "deploy@acme.example" in emails
        assert "edge-owner@acme.example" in emails
        assert "ops@acme.example" in emails

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
        assert ("203.0.113.77", "ipv4") in seeds
        assert ("acme.example", "domain") in seeds
        assert ("bastion.acme.example", "subdomain") in seeds
        assert ("corp.acme.example", "subdomain") in seeds
        assert ("edge.acme.example", "subdomain") in seeds
        assert ("git.acme.example", "subdomain") in seeds
        assert ("jumpbox.acme.example", "subdomain") in seeds
        assert ("https://jump.acme.example/admin", "url") in seeds
        assert ("github.com", "domain") not in seeds
        assert ("gitlab.com", "domain") not in seeds
        assert ("support.taplink.ws", "subdomain") not in seeds
        assert ("taplink.ws", "domain") not in seeds
        assert ("msha.ke", "domain") not in seeds
        assert ("bento.me", "domain") not in seeds
        assert ("hoo.be", "domain") not in seeds
        assert ("|1|hashed-host|hashed-key", "other") not in seeds

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
        assert artifact_meta[known_hosts.resolve().as_posix()]["format"] == "known_hosts"
        assert artifact_meta[authorized_keys.resolve().as_posix()]["format"] == "authorized_keys"
        assert artifact_meta[ssh_bundle.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[ssh_bundle.resolve().as_posix()]["payload_count"] >= 2
    finally:
        con.close()


def run_ssh_host_seed_extraction_uses_bounded_static_workers_and_preserves_order(
    monkeypatch: Any,
) -> None:
    import forge.engagement_orchestrator as orchestrator

    monkeypatch.setenv("FORGE_STATIC_ARTIFACT_MAX_WORKERS", "4")
    original_entry = orchestrator._ssh_known_host_token_seed_entries
    active = 0
    peak = 0
    lock = threading.Lock()
    delays = {
        "bastion.acme.example": 0.05,
        "203.0.113.77": 0.04,
        "[git.acme.example]:2222": 0.03,
        "*.corp.acme.example": 0.02,
        "github.com": 0.01,
        "msha.ke": 0.01,
        "bento.me": 0.01,
        "hoo.be": 0.01,
        "jumpbox.acme.example": 0.02,
    }

    def _fake_ssh_known_host_token_seed_entries(raw_host: str) -> list[tuple[str, str]]:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(delays.get(str(raw_host), 0.01))
            return original_entry(raw_host)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        orchestrator,
        "_ssh_known_host_token_seed_entries",
        _fake_ssh_known_host_token_seed_entries,
    )

    seeds = orchestrator._extract_artifact_ssh_host_seeds(
        dedent(
            """
            bastion.acme.example,203.0.113.77 ssh-ed25519 AAAAknownhost ops@acme.example
            [git.acme.example]:2222 ssh-rsa AAAAgitkey
            github.com ssh-ed25519 AAAAgithub
            msha.ke ssh-ed25519 AAAAmilkshake
            bento.me ssh-ed25519 AAAAbento
            hoo.be ssh-ed25519 AAAAhoobe
            @cert-authority *.corp.acme.example ecdsa-sha2-nistp256 AAAAca
            HostName jumpbox.acme.example
            """
        ).strip()
    )

    assert peak == 4
    assert seeds == [
        ("bastion.acme.example", "subdomain"),
        ("acme.example", "domain"),
        ("203.0.113.77", "ipv4"),
        ("git.acme.example", "subdomain"),
        ("corp.acme.example", "subdomain"),
        ("jumpbox.acme.example", "subdomain"),
    ]


def run_dns_zone_records() -> None:
    seeds = set(
        _extract_artifact_network_endpoint_seeds(
            dedent(
                """
                zone "internal.acme.example" { type master; file "/etc/bind/db.internal.acme.example"; };
                $ORIGIN acme.example.
                @ 3600 IN SOA ns1.acme.example. hostmaster.acme.example. 2026071701 7200 3600 1209600 3600
                @ IN NS ns1.acme.example.
                @ IN MX 10 mail.acme.example.
                www 300 IN A 203.0.113.24
                api 300 IN CNAME api-edge.acme.example.
                _sip._tcp 300 IN SRV 0 5 5060 sip.acme.example.
                """
            )
        )
    )

    assert ("internal.acme.example", "subdomain") in seeds
    assert ("acme.example", "domain") in seeds
    assert ("ns1.acme.example", "subdomain") in seeds
    assert ("mail.acme.example", "subdomain") in seeds
    assert ("www.acme.example", "subdomain") in seeds
    assert ("api.acme.example", "subdomain") in seeds
    assert ("api-edge.acme.example", "subdomain") in seeds
    assert ("sip.acme.example", "subdomain") in seeds


def run_dns_zone_line_parsing_uses_bounded_workers_and_preserves_origin_order(
    monkeypatch: Any,
) -> None:
    import forge.engagement_orchestrator as orchestrator

    monkeypatch.setenv("FORGE_STATIC_ARTIFACT_MAX_WORKERS", "4")
    original_entry = orchestrator._dns_zone_line_host_token_entry
    record_lines = [
        "@ IN NS ns1.acme.example.",
        "www 300 IN A 203.0.113.24",
        "api 300 IN CNAME api-edge.acme.example.",
        "_sip._tcp 300 IN SRV 0 5 5060 sip.acme.example.",
    ]
    active = 0
    peak = 0
    lock = threading.Lock()

    def _fake_dns_zone_line_host_token_entry(entry: tuple[str, str]) -> list[str]:
        nonlocal active, peak
        raw_line, origin = entry
        assert raw_line in record_lines
        assert origin == "acme.example"
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_entry(entry)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        orchestrator,
        "_dns_zone_line_host_token_entry",
        _fake_dns_zone_line_host_token_entry,
    )

    seeds = orchestrator._extract_artifact_network_endpoint_seeds(
        "\n".join(["$ORIGIN acme.example.", *record_lines])
    )

    assert peak == 4
    assert seeds == [
        ("acme.example", "domain"),
        ("ns1.acme.example", "subdomain"),
        ("www.acme.example", "subdomain"),
        ("api.acme.example", "subdomain"),
        ("api-edge.acme.example", "subdomain"),
        ("sip.acme.example", "subdomain"),
    ]


def run_hosts_file_aliases() -> None:
    seeds = set(
        _extract_artifact_network_endpoint_seeds(
            dedent(
                """
                127.0.0.1 localhost local-only.acme.example
                10.24.30.40 portal.acme.example portal
                10.24.30.41 api.acme.example api-edge.acme.example
                """
            )
        )
    )

    assert ("portal.acme.example", "subdomain") in seeds
    assert ("api.acme.example", "subdomain") in seeds
    assert ("api-edge.acme.example", "subdomain") in seeds
    assert ("acme.example", "domain") in seeds
    assert ("local-only.acme.example", "subdomain") not in seeds
    assert ("localhost", "domain") not in seeds


def run_hosts_file_line_tokenization_uses_bounded_workers_and_preserves_order(
    monkeypatch: Any,
) -> None:
    import forge.engagement_orchestrator as orchestrator

    monkeypatch.setenv("FORGE_STATIC_ARTIFACT_MAX_WORKERS", "4")
    original_entry = orchestrator._hosts_file_line_host_tokens
    lines = [
        "10.24.30.40 alpha.acme.example",
        "10.24.30.41 beta.acme.example",
        "10.24.30.42 alpha.acme.example",
        "10.24.30.43 gamma.acme.example",
    ]
    active = 0
    peak = 0
    lock = threading.Lock()

    def _fake_hosts_file_line_host_tokens(raw_line: str) -> list[str]:
        nonlocal active, peak
        assert raw_line in lines
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_entry(raw_line)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        orchestrator,
        "_hosts_file_line_host_tokens",
        _fake_hosts_file_line_host_tokens,
    )

    seeds = orchestrator._extract_artifact_network_endpoint_seeds("\n".join(lines))

    assert peak == 4
    assert seeds == [
        ("alpha.acme.example", "subdomain"),
        ("acme.example", "domain"),
        ("beta.acme.example", "subdomain"),
        ("gamma.acme.example", "subdomain"),
    ]


def run_dhcp_lease_hostnames() -> None:
    seeds = set(
        _extract_artifact_network_endpoint_seeds(
            dedent(
                """
                lease 10.24.30.50 {
                  client-hostname "dhcp-client.acme.example";
                  set ddns-fwd-name = "dhcp-edge.acme.example.";
                }
                1700000000 aa:bb:cc:dd:ee:ff 10.24.30.51 dnsmasq-client.acme.example *
                10.24.30.52,aa:bb:cc:dd:ee:11,,3600,2026-07-17,1,1,kea-client.acme.example,0,{}
                """
            )
        )
    )

    assert ("dhcp-client.acme.example", "subdomain") in seeds
    assert ("dhcp-edge.acme.example", "subdomain") in seeds
    assert ("dnsmasq-client.acme.example", "subdomain") in seeds
    assert ("kea-client.acme.example", "subdomain") in seeds
    assert ("acme.example", "domain") in seeds


def run_dhcp_lease_line_tokenization_uses_bounded_workers_and_preserves_order(
    monkeypatch: Any,
) -> None:
    import forge.engagement_orchestrator as orchestrator

    monkeypatch.setenv("FORGE_STATIC_ARTIFACT_MAX_WORKERS", "4")
    original_entry = orchestrator._dhcp_lease_line_host_tokens
    lines = [
        "1700000000 aa:bb:cc:dd:ee:01 10.24.30.51 alpha.acme.example *",
        "1700000001 aa:bb:cc:dd:ee:02 10.24.30.52 beta.acme.example *",
        "1700000002 aa:bb:cc:dd:ee:03 10.24.30.53 alpha.acme.example *",
        "1700000003 aa:bb:cc:dd:ee:04 10.24.30.54 gamma.acme.example *",
    ]
    active = 0
    peak = 0
    lock = threading.Lock()

    def _fake_dhcp_lease_line_host_tokens(raw_line: str) -> list[str]:
        nonlocal active, peak
        assert raw_line in lines
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_entry(raw_line)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        orchestrator,
        "_dhcp_lease_line_host_tokens",
        _fake_dhcp_lease_line_host_tokens,
    )

    seeds = orchestrator._extract_artifact_network_endpoint_seeds("\n".join(lines))

    assert peak == 4
    assert seeds == [
        ("alpha.acme.example", "subdomain"),
        ("acme.example", "domain"),
        ("beta.acme.example", "subdomain"),
        ("gamma.acme.example", "subdomain"),
    ]


def run_vpn_endpoint_hosts() -> None:
    seeds = set(
        _extract_artifact_network_endpoint_seeds(
            dedent(
                """
                [Peer]
                Endpoint = wg.acme.example:51820
                PublicKey = ignored
                remote ovpn.acme.example 1194 udp
                remote backup-vpn.acme.example 443 tcp
                remote https://managed-vpn.supabase.co/rest/v1/profiles
                """
            )
        )
    )

    assert ("wg.acme.example", "subdomain") in seeds
    assert ("ovpn.acme.example", "subdomain") in seeds
    assert ("backup-vpn.acme.example", "subdomain") in seeds
    assert ("acme.example", "domain") in seeds
    assert ("managed-vpn.supabase.co", "subdomain") not in seeds


def run_dns_zone_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_dns_zones"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    zone_path = artifact_root / "acme.zone"
    zone_path.write_text(
        dedent(
            """
            $ORIGIN acme.example.
            @ 3600 IN SOA ns1.acme.example. hostmaster.acme.example. 2026071701 7200 3600 1209600 3600
            @ IN NS ns1.acme.example.
            @ IN MX 10 mail.acme.example.
            www 300 IN A 203.0.113.24
            api 300 IN CNAME api-edge.acme.example.
            firebase IN TXT "https://dnszone-firebase.firebaseio.com"
            supabase IN TXT "https://dnszonevault.supabase.co/rest/v1/zones"
            backups IN TXT "s3://acme-zone-bucket/dns/acme.zone"
            """
        ),
        encoding="utf-8",
    )

    named_conf_path = artifact_root / "named.conf.local"
    named_conf_path.write_text(
        'zone "internal.acme.example" { type master; file "/etc/bind/db.internal.acme.example"; };',
        encoding="utf-8",
    )

    archive_path = artifact_root / "dns-bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr(
            "zones/db.internal.acme.example",
            dedent(
                """
                $ORIGIN internal.acme.example.
                @ IN NS ns1.internal.acme.example.
                portal IN CNAME portal-edge.internal.acme.example.
                storage IN TXT "gs://acme-zone-gcs/dns/internal.zone"
                """
            ),
        )

    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/zones/acme.zone") == "config"
    )
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/bind/db.acme.example")
        == "config"
    )
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/named.conf.local")
        == "config"
    )
    assert _suffix_from_content_type("text/dns") == ".zone"
    assert _suffix_from_content_type("application/x-zone-file") == ".zone"

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 3
    assert summary.processed >= 3
    assert summary.discovered_seeds >= 12
    assert summary.firebase_projects >= 1

    con = sqlite3.connect(db_path)
    try:
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
        assert ("acme.example", "domain") in seeds
        assert ("internal.acme.example", "subdomain") in seeds
        assert ("ns1.acme.example", "subdomain") in seeds
        assert ("mail.acme.example", "subdomain") in seeds
        assert ("www.acme.example", "subdomain") in seeds
        assert ("api.acme.example", "subdomain") in seeds
        assert ("api-edge.acme.example", "subdomain") in seeds
        assert ("ns1.internal.acme.example", "subdomain") in seeds
        assert ("portal.internal.acme.example", "subdomain") in seeds
        assert ("portal-edge.internal.acme.example", "subdomain") in seeds
        assert ("203.0.113.24", "ipv4") in seeds
        assert ("https://dnszonevault.supabase.co/rest/v1/zones", "url") in seeds
        assert ("dnszonevault.supabase.co", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-zone-bucket") in cloud_assets
        assert ("firebase", "dnszone-firebase") in cloud_assets
        assert ("gcs", "acme-zone-gcs") in cloud_assets
        assert ("supabase", "dnszonevault") in cloud_assets

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
        assert artifact_meta[zone_path.resolve().as_posix()]["format"] == "zone"
        assert artifact_meta[zone_path.resolve().as_posix()]["parser"] == "config"
        assert artifact_meta[named_conf_path.resolve().as_posix()]["format"] == "zone"
        assert artifact_meta[named_conf_path.resolve().as_posix()]["parser"] == "config"
        assert artifact_meta[archive_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[archive_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()


def run_queue_processor_extracts_dns_resolver_and_takeover_outputs(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_dns_resolver_outputs"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    massdns_path = artifact_root / "massdns-results.txt"
    massdns_path.write_text(
        "massdns.acme.example. A 203.0.113.80 massdns-owner@acme.example\n",
        encoding="utf-8",
    )

    puredns_path = artifact_root / "puredns-resolve.txt"
    puredns_path.write_text(
        "puredns.acme.example\n"
        "https://puredns.acme.example/status?token=puredns-token-do-not-store&view=public\n",
        encoding="utf-8",
    )

    dnsrecon_path = artifact_root / "dnsrecon.json"
    dnsrecon_path.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "name": "dnsrecon.acme.example",
                        "address": "203.0.113.81",
                        "owner": "dnsrecon-owner@acme.example",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    dnsenum_path = artifact_root / "dnsenum-report.xml"
    dnsenum_path.write_text(
        """
        <dnsenum>
          <host>dnsenum.acme.example</host>
          <owner>dnsenum-owner@acme.example</owner>
          <url>https://dnsenum.acme.example/report?api_key=dnsenum-token-do-not-store&amp;download=1</url>
        </dnsenum>
        """.strip(),
        encoding="utf-8",
    )

    subjack_path = artifact_root / "subjack-takeovers.json"
    subjack_path.write_text(
        json.dumps(
            {
                "host": "takeover.acme.example",
                "url": "https://takeover.acme.example",
                "owner": "subjack-owner@acme.example",
            }
        ),
        encoding="utf-8",
    )

    subzy_path = artifact_root / "subzy-results.json"
    subzy_path.write_text(
        json.dumps(
            {
                "result": {
                    "hostname": "subzy.acme.example",
                    "url": "https://subzy.acme.example/check?session=subzy-token-do-not-store&state=open",
                    "archive": "s3://acme-subzy-results/latest.json",
                },
                "owner": "subzy-owner@acme.example",
            }
        ),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 6
    assert summary.processed >= 6
    assert summary.discovered_seeds >= 12

    con = sqlite3.connect(db_path)
    try:
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
        for expected_seed in {
            ("massdns.acme.example", "subdomain"),
            ("puredns.acme.example", "subdomain"),
            ("https://puredns.acme.example/status?view=public", "url"),
            ("https://dnsrecon.acme.example", "url"),
            ("https://dnsenum.acme.example/report?download=1", "url"),
            ("https://takeover.acme.example", "url"),
            ("https://subzy.acme.example/check?state=open", "url"),
            ("massdns-owner@acme.example", "email"),
            ("dnsrecon-owner@acme.example", "email"),
            ("dnsenum-owner@acme.example", "email"),
            ("subjack-owner@acme.example", "email"),
            ("subzy-owner@acme.example", "email"),
        }:
            assert expected_seed in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-subzy-results") in cloud_assets

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
        assert artifact_meta[massdns_path.resolve().as_posix()]["format"] == "massdns-output"
        assert artifact_meta[puredns_path.resolve().as_posix()]["format"] == "puredns-output"
        assert artifact_meta[dnsrecon_path.resolve().as_posix()]["format"] == "dnsrecon-output"
        assert artifact_meta[dnsenum_path.resolve().as_posix()]["format"] == "dnsenum-output"
        assert artifact_meta[subjack_path.resolve().as_posix()]["format"] == "subjack-output"
        assert artifact_meta[subzy_path.resolve().as_posix()]["format"] == "subzy-output"

        db_dump = "\n".join(con.iterdump())
        assert "puredns-token-do-not-store" not in db_dump
        assert "dnsenum-token-do-not-store" not in db_dump
        assert "subzy-token-do-not-store" not in db_dump
    finally:
        con.close()


def run_vpn_endpoint_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_vpn_endpoints"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    wireguard_path = artifact_root / "wg0.conf"
    wireguard_path.write_text(
        dedent(
            """
            [Interface]
            Address = 10.80.0.2/32
            [Peer]
            Endpoint = wg.acme.example:51820
            # passive cloud refs discovered in the profile
            https://vpnprofile-firebase.firebaseio.com
            https://vpnprofilevault.supabase.co/rest/v1/profiles
            s3://acme-vpn-profile-bucket/wireguard/wg0.conf
            """
        ),
        encoding="utf-8",
    )

    ovpn_path = artifact_root / "client.ovpn"
    ovpn_path.write_text(
        dedent(
            """
            client
            remote ovpn.acme.example 1194 udp
            remote backup-vpn.acme.example 443 tcp
            """
        ),
        encoding="utf-8",
    )

    archive_path = artifact_root / "vpn-bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr(
            "profiles/backup.conf",
            dedent(
                """
                [Peer]
                Endpoint = nested-wg.acme.example:51820
                gs://acme-vpn-profile-gcs/wireguard/backup.conf
                """
            ),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 3
    assert summary.processed >= 3
    assert summary.discovered_seeds >= 10
    assert summary.firebase_projects >= 1

    con = sqlite3.connect(db_path)
    try:
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
        assert ("wg.acme.example", "subdomain") in seeds
        assert ("ovpn.acme.example", "subdomain") in seeds
        assert ("backup-vpn.acme.example", "subdomain") in seeds
        assert ("nested-wg.acme.example", "subdomain") in seeds
        assert ("acme.example", "domain") in seeds
        assert ("10.80.0.2", "ipv4") in seeds
        assert ("https://vpnprofilevault.supabase.co/rest/v1/profiles", "url") in seeds
        assert ("vpnprofilevault.supabase.co", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-vpn-profile-bucket") in cloud_assets
        assert ("firebase", "vpnprofile-firebase") in cloud_assets
        assert ("gcs", "acme-vpn-profile-gcs") in cloud_assets
        assert ("supabase", "vpnprofilevault") in cloud_assets

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
        assert artifact_meta[wireguard_path.resolve().as_posix()]["format"] == "conf"
        assert artifact_meta[wireguard_path.resolve().as_posix()]["parser"] == "config"
        assert artifact_meta[ovpn_path.resolve().as_posix()]["format"] == "ovpn"
        assert artifact_meta[ovpn_path.resolve().as_posix()]["parser"] == "config"
        assert artifact_meta[archive_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[archive_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()


def run_tunnel_config_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)
    payload = dedent(
        """
        hostname: cloudflared.acme.example
        service: http://localhost:8080
        service: https://origin-tunnel.acme.example
        public_url=https://ngrok-public.acme.example/app
        hostname: ${tenant}.acme.example
        """
    )
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self: Any, items: Any, worker: Any, *, default_factory: Any) -> Any:
        materialized = list(items)
        if materialized and "cloudflared.acme.example" in materialized:
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._tunnel_config_structured_payload_text(
        payload,
        source_hint="cloudflared/config.yml",
    )

    assert observed_candidate_batches == [
        [
            "cloudflared.acme.example",
            "https://origin-tunnel.acme.example",
            "https://ngrok-public.acme.example/app",
        ]
    ]
    assert result.splitlines() == [
        "https://cloudflared.acme.example",
        "https://origin-tunnel.acme.example",
        "https://ngrok-public.acme.example/app",
    ]
    assert (
        processor._tunnel_config_structured_payload_text(
            payload,
            source_hint="config.yml",
        )
        == ""
    )


def run_tunnel_config_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_tunnel_configs"
    ngrok_dir = artifact_root / "ngrok"
    cloudflared_dir = artifact_root / "cloudflared"
    tailscale_dir = artifact_root / "tailscale"
    localtunnel_dir = artifact_root / "localtunnel"
    for directory in (ngrok_dir, cloudflared_dir, tailscale_dir, localtunnel_dir):
        directory.mkdir(parents=True)
    bootstrap_engagement(db_path)

    ngrok_path = ngrok_dir / "ngrok.yml"
    ngrok_path.write_text(
        dedent(
            """
            tunnels:
              web:
                proto: http
                hostname: ngrok.acme.example
                public_url: https://ngrok-public.acme.example/app
                owner: ngrok-owner@acme.example
                firebase: https://tunnel-firebase.firebaseio.com
                backup: s3://acme-tunnel-bucket/ngrok.yml
            """
        ),
        encoding="utf-8",
    )

    cloudflared_path = cloudflared_dir / "config.yml"
    cloudflared_path.write_text(
        dedent(
            """
            tunnel: acme
            ingress:
              - hostname: cloudflared.acme.example
                service: http://localhost:8080
              - hostname: ${tenant}.acme.example
                service: https://origin-tunnel.acme.example
            supabase: https://tunnelvault.supabase.co/rest/v1
            mirror: gs://acme-tunnel-gcs/config.yml
            """
        ),
        encoding="utf-8",
    )

    tailscale_path = tailscale_dir / "serve.json"
    tailscale_path.write_text(
        json.dumps(
            {
                "HTTPS": {
                    "tailnet.acme.ts.net": {
                        "Handlers": {
                            "/": {
                                "Proxy": "https://tailscale.acme.example/app",
                            }
                        }
                    }
                },
                "owner": "tailscale-owner@acme.example",
            }
        ),
        encoding="utf-8",
    )

    localtunnel_path = localtunnel_dir / "lt.yml"
    localtunnel_path.write_text(
        dedent(
            """
            host: https://loca-tunnel.acme.example
            endpoint: http://127.0.0.1:8080
            """
        ),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 4
    assert summary.processed >= 4
    assert summary.discovered_seeds >= 12
    assert summary.firebase_projects >= 1

    con = sqlite3.connect(db_path)
    try:
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
        assert ("https://ngrok.acme.example", "url") in seeds
        assert ("https://ngrok-public.acme.example/app", "url") in seeds
        assert ("https://cloudflared.acme.example", "url") in seeds
        assert ("https://origin-tunnel.acme.example", "url") in seeds
        assert ("https://tailscale.acme.example/app", "url") in seeds
        assert ("https://loca-tunnel.acme.example", "url") in seeds
        assert ("ngrok-owner@acme.example", "email") in seeds
        assert ("tailscale-owner@acme.example", "email") in seeds

        serialized_seeds = "\n".join(f"{value} {seed_type}" for value, seed_type in seeds)
        assert "localhost" not in serialized_seeds
        assert "127.0.0.1" not in serialized_seeds
        assert "${tenant}" not in serialized_seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-tunnel-bucket") in cloud_assets
        assert ("firebase", "tunnel-firebase") in cloud_assets
        assert ("gcs", "acme-tunnel-gcs") in cloud_assets
        assert ("supabase", "tunnelvault") in cloud_assets

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
        assert artifact_meta[ngrok_path.resolve().as_posix()]["format"] == "ngrok-config"
        assert artifact_meta[ngrok_path.resolve().as_posix()]["parser"] == "config"
        assert (
            artifact_meta[cloudflared_path.resolve().as_posix()]["format"]
            == "cloudflared-config"
        )
        assert artifact_meta[cloudflared_path.resolve().as_posix()]["parser"] == "config"
        assert (
            artifact_meta[tailscale_path.resolve().as_posix()]["format"]
            == "tailscale-serve-config"
        )
        assert (
            artifact_meta[localtunnel_path.resolve().as_posix()]["format"]
            == "localtunnel-config"
        )
    finally:
        con.close()


def run_ansible_inventory_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_ansible_inventory"
    ansible_dir = artifact_root / "ansible"
    group_vars_dir = artifact_root / "group_vars"
    ansible_dir.mkdir(parents=True)
    group_vars_dir.mkdir(parents=True)
    bootstrap_engagement(db_path)

    inventory_path = ansible_dir / "inventory"
    inventory_path.write_text(
        dedent(
            """
            [web]
            web1.acme.example ansible_user=ansible-owner@acme.example
            api01 ansible_host=api.ansible.acme.example
            db01 ansible_ssh_host=10.24.60.20
            github ansible_host=github.com
            status_url=https://ansible.acme.example/status
            supabase=https://ansiblevault.supabase.co/rest/v1/inventory
            backups=s3://acme-ansible-bucket/inventory/latest.ini
            """
        ).strip(),
        encoding="utf-8",
    )

    group_vars_path = group_vars_dir / "all.yml"
    group_vars_path.write_text(
        dedent(
            """
            ansible_host: groupvars.acme.example
            owner: groupvars-owner@acme.example
            firebase: https://ansible-firebase.firebaseio.com
            mirror: gs://acme-ansible-gcs/group_vars/all.yml
            """
        ).strip(),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 2
    assert summary.processed >= 2
    assert summary.discovered_seeds >= 8
    assert summary.firebase_projects >= 1

    con = sqlite3.connect(db_path)
    try:
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
        assert ("web1.acme.example", "subdomain") in seeds
        assert ("api.ansible.acme.example", "subdomain") in seeds
        assert ("groupvars.acme.example", "subdomain") in seeds
        assert ("10.24.60.20", "ipv4") in seeds
        assert ("acme.example", "domain") in seeds
        assert ("ansible-owner@acme.example", "email") in seeds
        assert ("groupvars-owner@acme.example", "email") in seeds
        assert ("https://ansible.acme.example/status", "url") in seeds
        assert ("github.com", "domain") not in seeds
        assert ("ansiblevault.supabase.co", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-ansible-bucket") in cloud_assets
        assert ("firebase", "ansible-firebase") in cloud_assets
        assert ("gcs", "acme-ansible-gcs") in cloud_assets
        assert ("supabase", "ansiblevault") in cloud_assets

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
        assert artifact_meta[inventory_path.resolve().as_posix()]["format"] == "ansible-inventory"
        assert artifact_meta[group_vars_path.resolve().as_posix()]["format"] == "ansible-inventory"
    finally:
        con.close()


def run_cloud_init_hosts() -> None:
    text = dedent(
        """
        #cloud-config
        fqdn: web.cloudinit.acme.example
        hostname: api.cloudinit.acme.example
        local-hostname: 10.30.40.50
        public_hostname: https://cloudinitvault.supabase.co/rest/v1/hosts
        """
    )

    seeds = _extract_artifact_network_endpoint_seeds(
        text,
        source_file="cloud-init/user-data",
    )

    assert ("web.cloudinit.acme.example", "subdomain") in seeds
    assert ("api.cloudinit.acme.example", "subdomain") in seeds
    assert ("10.30.40.50", "ipv4") in seeds
    assert ("acme.example", "domain") in seeds
    assert ("cloudinitvault.supabase.co", "subdomain") not in seeds

    generic_seeds = _extract_artifact_network_endpoint_seeds(
        text,
        source_file="notes/user-data",
    )
    assert ("web.cloudinit.acme.example", "subdomain") not in generic_seeds
    assert ("api.cloudinit.acme.example", "subdomain") not in generic_seeds


def run_cloud_init_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_cloud_init"
    cloud_init_dir = artifact_root / "cloud-init"
    cloud_init_dir.mkdir(parents=True)
    bootstrap_engagement(db_path)

    user_data_path = cloud_init_dir / "user-data"
    user_data_path.write_text(
        dedent(
            """
            #cloud-config
            fqdn: web.cloudinit.acme.example
            hostname: api.cloudinit.acme.example
            owner: cloudinit-owner@acme.example
            status_url: https://cloudinit.acme.example/status
            firebase: https://cloudinit-firebase.firebaseio.com
            backup_bucket: s3://acme-cloudinit-bucket/bootstrap/latest.yml
            supabase: https://cloudinitvault.supabase.co/rest/v1/bootstrap
            """
        ).strip(),
        encoding="utf-8",
    )

    meta_data_path = cloud_init_dir / "meta-data"
    meta_data_path.write_text(
        dedent(
            """
            instance-id: acme-cloudinit-01
            local-hostname: meta.cloudinit.acme.example
            support: meta-cloudinit-owner@acme.example
            mirror: gs://acme-cloudinit-gcs/meta-data
            """
        ).strip(),
        encoding="utf-8",
    )

    assert _classify_artifact_name(Path("cloud-init/user-data")) == "config"
    assert _classify_artifact_name(Path("notes/user-data")) is None
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/cloud-init/user-data")
        == "config"
    )
    assert _classify_remote_artifact_url("https://downloads.acme.example/user-data") is None
    assert (
        _select_remote_artifact_filename(
            42,
            "https://downloads.acme.example/cloud-init/user-data",
            "config",
        )
        == "user-data"
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 2
    assert summary.processed >= 2
    assert summary.discovered_seeds >= 8
    assert summary.firebase_projects >= 1

    con = sqlite3.connect(db_path)
    try:
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
        assert ("web.cloudinit.acme.example", "subdomain") in seeds
        assert ("api.cloudinit.acme.example", "subdomain") in seeds
        assert ("meta.cloudinit.acme.example", "subdomain") in seeds
        assert ("acme.example", "domain") in seeds
        assert ("cloudinit-owner@acme.example", "email") in seeds
        assert ("meta-cloudinit-owner@acme.example", "email") in seeds
        assert ("https://cloudinit.acme.example/status", "url") in seeds
        assert ("cloudinitvault.supabase.co", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-cloudinit-bucket") in cloud_assets
        assert ("firebase", "cloudinit-firebase") in cloud_assets
        assert ("gcs", "acme-cloudinit-gcs") in cloud_assets
        assert ("supabase", "cloudinitvault") in cloud_assets

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
        assert artifact_meta[user_data_path.resolve().as_posix()]["format"] == "cloud-init"
        assert artifact_meta[meta_data_path.resolve().as_posix()]["format"] == "cloud-init"
    finally:
        con.close()


def run_os_installer_hosts() -> None:
    text = dedent(
        """
        network --bootproto=dhcp --hostname=web.kickstart.acme.example --nameserver=10.41.0.53
        nfs --server=nfs.kickstart.acme.example --dir=/exports/os
        d-i netcfg/get_hostname string preseed-web.acme.example
        d-i netcfg/get_domain string preseed.acme.example
        d-i mirror/http/hostname string mirror.preseed.acme.example
        """
    )

    seeds = _extract_artifact_network_endpoint_seeds(
        text,
        source_file="kickstart/ks.cfg",
    )

    assert ("web.kickstart.acme.example", "subdomain") in seeds
    assert ("nfs.kickstart.acme.example", "subdomain") in seeds
    assert ("10.41.0.53", "ipv4") in seeds
    assert ("preseed-web.acme.example", "subdomain") in seeds
    assert ("preseed.acme.example", "subdomain") in seeds
    assert ("mirror.preseed.acme.example", "subdomain") in seeds
    assert ("acme.example", "domain") in seeds

    generic_seeds = _extract_artifact_network_endpoint_seeds(
        text,
        source_file="notes/ks",
    )
    assert ("web.kickstart.acme.example", "subdomain") not in generic_seeds
    assert ("preseed-web.acme.example", "subdomain") not in generic_seeds


def run_os_installer_host_extraction_uses_bounded_workers_and_preserves_order(
    monkeypatch: Any,
) -> None:
    import forge.engagement_orchestrator as orchestrator

    monkeypatch.setenv("FORGE_STATIC_ARTIFACT_MAX_WORKERS", "4")
    original_entry = orchestrator._remote_access_host_field_seed_entries
    expected_values = [
        "web.kickstart.acme.example",
        "10.41.0.53",
        "nfs.kickstart.acme.example",
        "preseed-web.acme.example",
    ]
    active = 0
    peak = 0
    lock = threading.Lock()

    def _fake_remote_access_host_field_seed_entries(raw_value: str) -> list[tuple[str, str]]:
        nonlocal active, peak
        assert raw_value in expected_values
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_entry(raw_value)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        orchestrator,
        "_remote_access_host_field_seed_entries",
        _fake_remote_access_host_field_seed_entries,
    )

    seeds = orchestrator._extract_artifact_network_endpoint_seeds(
        dedent(
            """
            network --bootproto=dhcp --hostname=web.kickstart.acme.example --nameserver=10.41.0.53
            nfs --server=nfs.kickstart.acme.example --dir=/exports/os
            d-i netcfg/get_hostname string preseed-web.acme.example
            """
        ),
        source_file="kickstart/ks.cfg",
    )

    assert peak == 4
    assert seeds == [
        ("web.kickstart.acme.example", "subdomain"),
        ("acme.example", "domain"),
        ("10.41.0.53", "ipv4"),
        ("nfs.kickstart.acme.example", "subdomain"),
        ("preseed-web.acme.example", "subdomain"),
    ]


def run_os_installer_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_os_installer"
    kickstart_dir = artifact_root / "kickstart"
    preseed_dir = artifact_root / "preseed"
    kickstart_dir.mkdir(parents=True)
    preseed_dir.mkdir(parents=True)
    bootstrap_engagement(db_path)

    kickstart_path = kickstart_dir / "ks.cfg"
    kickstart_path.write_text(
        dedent(
            """
            network --bootproto=dhcp --hostname=web.kickstart.acme.example --nameserver=10.41.0.53
            nfs --server=nfs.kickstart.acme.example --dir=/exports/os
            url --url=https://kickstart.acme.example/os
            repo --name=app --baseurl=https://repos.kickstart.acme.example/base
            %post
            echo "owner=kickstart-owner@acme.example" > /etc/acme-owner
            echo "firebase=https://kickstart-firebase.firebaseio.com" >> /etc/acme-cloud
            echo "bucket=s3://acme-kickstart-bucket/bootstrap/ks.cfg" >> /etc/acme-cloud
            %end
            """
        ).strip(),
        encoding="utf-8",
    )

    preseed_path = preseed_dir / "preseed"
    preseed_path.write_text(
        dedent(
            """
            d-i netcfg/get_hostname string preseed-web.acme.example
            d-i netcfg/get_domain string preseed.acme.example
            d-i mirror/http/hostname string mirror.preseed.acme.example
            d-i preseed/late_command string in-target curl https://preseed.acme.example/late
            d-i preseed/include string https://preseed.acme.example/include.cfg
            d-i debian-installer/comment string preseed-owner@acme.example
            d-i debian-installer/cloud string https://preseedvault.supabase.co/rest/v1/install
            d-i debian-installer/mirror string gs://acme-preseed-gcs/bootstrap
            """
        ).strip(),
        encoding="utf-8",
    )

    assert _classify_artifact_name(Path("kickstart/ks.cfg")) == "config"
    assert _classify_artifact_name(Path("preseed/preseed")) == "config"
    assert _classify_artifact_name(Path("notes/preseed")) is None
    assert _classify_remote_artifact_url("https://downloads.acme.example/kickstart/ks") == "config"
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/preseed/preseed")
        == "config"
    )
    assert _classify_remote_artifact_url("https://downloads.acme.example/preseed") is None
    assert (
        _select_remote_artifact_filename(
            42,
            "https://downloads.acme.example/kickstart/ks",
            "config",
        )
        == "ks"
    )
    assert _suffix_from_content_type("text/x-kickstart") == ".ks"
    assert _suffix_from_content_type("text/x-preseed") == ".preseed"

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 2
    assert summary.processed >= 2
    assert summary.discovered_seeds >= 11
    assert summary.firebase_projects >= 1

    con = sqlite3.connect(db_path)
    try:
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
        assert ("web.kickstart.acme.example", "subdomain") in seeds
        assert ("nfs.kickstart.acme.example", "subdomain") in seeds
        assert ("10.41.0.53", "ipv4") in seeds
        assert ("preseed-web.acme.example", "subdomain") in seeds
        assert ("mirror.preseed.acme.example", "subdomain") in seeds
        assert ("acme.example", "domain") in seeds
        assert ("kickstart-owner@acme.example", "email") in seeds
        assert ("preseed-owner@acme.example", "email") in seeds
        assert ("https://kickstart.acme.example/os", "url") in seeds
        assert ("https://preseed.acme.example/include.cfg", "url") in seeds
        assert ("preseedvault.supabase.co", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-kickstart-bucket") in cloud_assets
        assert ("firebase", "kickstart-firebase") in cloud_assets
        assert ("gcs", "acme-preseed-gcs") in cloud_assets
        assert ("supabase", "preseedvault") in cloud_assets

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
        assert artifact_meta[kickstart_path.resolve().as_posix()]["format"] == "kickstart"
        assert artifact_meta[preseed_path.resolve().as_posix()]["format"] == "preseed"
    finally:
        con.close()


def run_ignition_and_butane_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_ignition_butane"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    ignition_path = artifact_root / "bootstrap.ign"
    ignition_path.write_text(
        json.dumps(
            {
                "ignition": {"version": "3.4.0"},
                "storage": {
                    "files": [
                        {
                            "path": "/etc/acme.conf",
                            "contents": {
                                "source": (
                                    "data:,owner=ignition-owner@acme.example%0A"
                                    "url=https://ignition.acme.example/bootstrap%0A"
                                    "firebase=https://ignition-firebase.firebaseio.com%0A"
                                    "bucket=s3://acme-ignition-bucket/bootstrap/config"
                                )
                            },
                        },
                        {
                            "path": "/etc/acme-b64.conf",
                            "contents": {
                                "source": (
                                    "data:text/plain;base64,"
                                    + base64.b64encode(
                                        b"owner=ignition-b64-owner@acme.example\n"
                                        b"url=https://ignition-b64.acme.example/config\n"
                                        b"mirror=gs://acme-ignition-gcs/b64"
                                    ).decode("ascii")
                                )
                            },
                        },
                    ]
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    butane_path = artifact_root / "worker.bu"
    butane_path.write_text(
        dedent(
            """
            variant: fcos
            version: 1.5.0
            passwd:
              users:
                - name: core
            systemd:
              units:
                - name: acme.service
                  contents: |
                    [Service]
                    Environment=OWNER=butane-owner@acme.example
                    Environment=SUPABASE=https://butanevault.supabase.co/rest/v1/bootstrap
                    Environment=GCS=gs://acme-butane-gcs/bootstrap/worker
                    ExecStart=/usr/bin/curl https://butane.acme.example/health
            """
        ).strip(),
        encoding="utf-8",
    )

    assert _classify_artifact_name("bootstrap.ign") == "config"
    assert _classify_artifact_name("worker.bu") == "config"
    assert _classify_remote_artifact_url("https://downloads.acme.example/bootstrap.ign") == "config"
    assert _classify_remote_artifact_url("https://downloads.acme.example/worker.bu") == "config"
    assert _suffix_from_content_type("application/vnd.coreos.ignition+json") == ".ign"
    assert _suffix_from_content_type("application/vnd.coreos.butane+yaml") == ".bu"

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 2
    assert summary.processed >= 2
    assert summary.discovered_seeds >= 7
    assert summary.firebase_projects >= 1

    con = sqlite3.connect(db_path)
    try:
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
        assert ("ignition-owner@acme.example", "email") in seeds
        assert ("ignition-b64-owner@acme.example", "email") in seeds
        assert ("butane-owner@acme.example", "email") in seeds
        assert ("https://ignition.acme.example/bootstrap", "url") in seeds
        assert ("https://ignition-b64.acme.example/config", "url") in seeds
        assert ("https://butane.acme.example/health", "url") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-ignition-bucket") in cloud_assets
        assert ("firebase", "ignition-firebase") in cloud_assets
        assert ("gcs", "acme-ignition-gcs") in cloud_assets
        assert ("gcs", "acme-butane-gcs") in cloud_assets
        assert ("supabase", "butanevault") in cloud_assets

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
        assert artifact_meta[ignition_path.resolve().as_posix()]["format"] == "ign"
        assert artifact_meta[butane_path.resolve().as_posix()]["format"] == "bu"
    finally:
        con.close()


def run_dhcp_lease_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_dhcp_leases"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    dhcpd_path = artifact_root / "dhcpd.leases"
    dhcpd_path.write_text(
        dedent(
            """
            lease 10.24.30.50 {
              starts 5 2026/07/17 03:00:00;
              ends 5 2026/07/17 09:00:00;
              client-hostname "dhcp-client.acme.example";
              set ddns-fwd-name = "dhcp-edge.acme.example.";
            }
            https://dhcplease-firebase.firebaseio.com
            https://dhcpleasevault.supabase.co/rest/v1/leases
            s3://acme-dhcp-lease-bucket/dhcp/dhcpd.leases
            """
        ),
        encoding="utf-8",
    )

    kea_path = artifact_root / "kea-leases4.csv"
    kea_path.write_text(
        dedent(
            """
            address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context
            10.24.30.52,aa:bb:cc:dd:ee:11,,3600,2026-07-17,1,1,1,kea-client.acme.example,0,{}
            """
        ).strip(),
        encoding="utf-8",
    )

    archive_path = artifact_root / "leases-bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr(
            "dnsmasq/dnsmasq.leases",
            dedent(
                """
                1700000000 aa:bb:cc:dd:ee:ff 10.24.30.51 dnsmasq-client.acme.example *
                gs://acme-dhcp-lease-gcs/dnsmasq/leases
                """
            ),
        )

    assert _classify_remote_artifact_url("https://downloads.acme.example/dhcpd.leases") == "config"
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/dnsmasq.leases")
        == "config"
    )
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/kea-leases4.csv")
        == "config"
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 3
    assert summary.processed >= 3
    assert summary.discovered_seeds >= 10
    assert summary.firebase_projects >= 1

    con = sqlite3.connect(db_path)
    try:
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
        assert ("dhcp-client.acme.example", "subdomain") in seeds
        assert ("dhcp-edge.acme.example", "subdomain") in seeds
        assert ("dnsmasq-client.acme.example", "subdomain") in seeds
        assert ("kea-client.acme.example", "subdomain") in seeds
        assert ("acme.example", "domain") in seeds
        assert ("10.24.30.50", "ipv4") in seeds
        assert ("10.24.30.51", "ipv4") in seeds
        assert ("10.24.30.52", "ipv4") in seeds
        assert ("https://dhcpleasevault.supabase.co/rest/v1/leases", "url") in seeds
        assert ("dhcpleasevault.supabase.co", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-dhcp-lease-bucket") in cloud_assets
        assert ("firebase", "dhcplease-firebase") in cloud_assets
        assert ("gcs", "acme-dhcp-lease-gcs") in cloud_assets
        assert ("supabase", "dhcpleasevault") in cloud_assets

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
        assert artifact_meta[dhcpd_path.resolve().as_posix()]["format"] == "leases"
        assert artifact_meta[dhcpd_path.resolve().as_posix()]["parser"] == "config"
        assert artifact_meta[kea_path.resolve().as_posix()]["format"] == "leases"
        assert artifact_meta[kea_path.resolve().as_posix()]["parser"] == "config"
        assert artifact_meta[archive_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[archive_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()


def run_hosts_file_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_hosts_files"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    hosts_path = artifact_root / "hosts"
    hosts_path.write_text(
        dedent(
            """
            127.0.0.1 localhost
            10.24.30.40 portal.acme.example portal
            10.24.30.41 api.acme.example api-edge.acme.example
            # cloud refs discovered beside host mappings
            https://hostfile-firebase.firebaseio.com
            https://hostfilevault.supabase.co/rest/v1/hosts
            s3://acme-hostfile-bucket/etc/hosts
            """
        ),
        encoding="utf-8",
    )

    archive_path = artifact_root / "hosts-bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr(
            "windows/lmhosts",
            dedent(
                """
                10.24.30.42 winhost.acme.example winhost
                10.24.30.43 files.acme.example files
                gs://acme-hostfile-gcs/windows/lmhosts
                """
            ),
        )

    assert _classify_remote_artifact_url("https://downloads.acme.example/etc/hosts") == "config"
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/windows/lmhosts")
        == "config"
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 2
    assert summary.processed >= 2
    assert summary.discovered_seeds >= 10
    assert summary.firebase_projects >= 1

    con = sqlite3.connect(db_path)
    try:
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
        assert ("portal.acme.example", "subdomain") in seeds
        assert ("api.acme.example", "subdomain") in seeds
        assert ("api-edge.acme.example", "subdomain") in seeds
        assert ("winhost.acme.example", "subdomain") in seeds
        assert ("files.acme.example", "subdomain") in seeds
        assert ("acme.example", "domain") in seeds
        assert ("10.24.30.40", "ipv4") in seeds
        assert ("10.24.30.41", "ipv4") in seeds
        assert ("https://hostfilevault.supabase.co/rest/v1/hosts", "url") in seeds
        assert ("hostfilevault.supabase.co", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-hostfile-bucket") in cloud_assets
        assert ("firebase", "hostfile-firebase") in cloud_assets
        assert ("gcs", "acme-hostfile-gcs") in cloud_assets
        assert ("supabase", "hostfilevault") in cloud_assets

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
        assert artifact_meta[hosts_path.resolve().as_posix()]["format"] == "hosts"
        assert artifact_meta[hosts_path.resolve().as_posix()]["parser"] == "config"
        assert artifact_meta[archive_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[archive_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()
