from __future__ import annotations

import pytest

from forge.utils.artifact_tunnel_config import (
    tunnel_config_artifact_label,
    tunnel_config_endpoint_candidates,
    tunnel_config_public_payload_text,
)


@pytest.mark.parametrize(
    ("value", "label"),
    [
        ("ngrok/ngrok.yml", "ngrok-config"),
        (".ngrok2/ngrok.yaml", "ngrok-config"),
        ("cloudflared/config.yml", "cloudflared-config"),
        (".cloudflared/tunnel.yaml", "cloudflared-config"),
        ("tailscale/serve.json", "tailscale-serve-config"),
        ("tailscale/tailscale-funnel.yaml", "tailscale-serve-config"),
        (".localtunnelrc", "localtunnel-config"),
        ("localtunnel/lt.yml", "localtunnel-config"),
        ("config.yml.cloudflared-config", "cloudflared-config"),
    ],
)
def test_tunnel_config_artifact_label_recognizes_source_paths(
    value: str,
    label: str,
) -> None:
    assert tunnel_config_artifact_label(value) == label


@pytest.mark.parametrize(
    "value",
    [
        "config.yml",
        "tunnel.yaml",
        "serve.json",
        "lt.json",
        "notes/cloudflared-config.txt",
        ".github/workflows/tunnel.yml",
    ],
)
def test_tunnel_config_artifact_label_avoids_generic_configs(value: str) -> None:
    assert tunnel_config_artifact_label(value) == ""


def test_tunnel_config_endpoint_candidates_extracts_public_endpoints_only() -> None:
    payload = """
    hostname: cloudflared.acme.example
    service: http://localhost:8080
    service: https://origin-tunnel.acme.example
    public_url=https://ngrok-public.acme.example/app
    endpoint = "https://toml-tunnel.acme.example/status"
    {"url": "https://json-tunnel.acme.example/api"}
    <hostname>xml-tunnel.acme.example</hostname>
    <key>public_url</key><string>https://plist-tunnel.acme.example</string>
    hostname: ${tenant}.acme.example
    hostname: 10.0.0.4
    hostname: example.local
    """

    assert tunnel_config_endpoint_candidates(payload) == [
        "cloudflared.acme.example",
        "https://origin-tunnel.acme.example",
        "https://ngrok-public.acme.example/app",
        "https://toml-tunnel.acme.example/status",
        "https://json-tunnel.acme.example/api",
        "xml-tunnel.acme.example",
        "https://plist-tunnel.acme.example",
    ]


def test_tunnel_config_public_payload_text_drops_local_origin_lines() -> None:
    payload = """
    hostname: cloudflared.acme.example
    service: http://localhost:8080
    endpoint: http://127.0.0.1:8080
    <hostname>
      10.0.0.4
    </hostname>
    <key>public_url</key>
    <string>
      http://192.168.1.5:8080
    </string>
    public_url=https://ngrok-public.acme.example/app
    hostname: ${tenant}.acme.example
    firebase=https://tunnel-firebase.firebaseio.com
    """

    filtered = tunnel_config_public_payload_text(payload)

    assert "cloudflared.acme.example" in filtered
    assert "ngrok-public.acme.example" in filtered
    assert "tunnel-firebase.firebaseio.com" in filtered
    assert "localhost" not in filtered
    assert "127.0.0.1" not in filtered
    assert "10.0.0.4" not in filtered
    assert "192.168.1.5" not in filtered
    assert "${tenant}" not in filtered
