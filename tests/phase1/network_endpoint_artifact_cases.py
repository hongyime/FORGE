from __future__ import annotations

import threading
import time
from textwrap import dedent
from typing import Any

from forge.engagement_orchestrator import _extract_artifact_network_endpoint_seeds


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
