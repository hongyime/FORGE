from __future__ import annotations

import json

from forge.utils.artifact_agent_card_metadata import agent_card_urls
from forge.utils.artifact_api_catalog_metadata import api_catalog_urls
from forge.utils.artifact_mercure_metadata import mercure_urls
from forge.utils.artifact_open_resource_discovery import open_resource_discovery_urls
from forge.utils.artifact_webweaver_metadata import webweaver_urls


def test_api_application_metadata_helpers_strip_sensitive_query_parameters() -> None:
    cases = [
        (
            agent_card_urls,
            json.dumps({"url": "https://agent.acme.test/a2a?token=hidden&view=public"}),
            "https://agent.acme.test/.well-known/agent-card.json",
            "https://agent.acme.test/a2a?view=public",
            "https://agent.acme.test/a2a?token=hidden&view=public",
        ),
        (
            api_catalog_urls,
            json.dumps(
                {"apis": [{"url": ("https://api.acme.test/catalog?api_key=hidden&view=public")}]}
            ),
            "https://api.acme.test/.well-known/api-catalog",
            "https://api.acme.test/catalog?view=public",
            "https://api.acme.test/catalog?api_key=hidden&view=public",
        ),
        (
            open_resource_discovery_urls,
            json.dumps(
                {"resources": ["https://resources.acme.test/ord?signature=hidden&view=public"]}
            ),
            "https://resources.acme.test/.well-known/open-resource-discovery",
            "https://resources.acme.test/ord?view=public",
            "https://resources.acme.test/ord?signature=hidden&view=public",
        ),
        (
            mercure_urls,
            "hub=https://mercure.acme.test/hub?token=hidden&view=public",
            "https://mercure.acme.test/.well-known/mercure",
            "https://mercure.acme.test/hub?view=public",
            "https://mercure.acme.test/hub?token=hidden&view=public",
        ),
        (
            webweaver_urls,
            json.dumps(
                {"endpoint": ("https://webweaver.acme.test/api?api_key=hidden&view=public")}
            ),
            "https://webweaver.acme.test/.well-known/webweaver.json",
            "https://webweaver.acme.test/api?view=public",
            "https://webweaver.acme.test/api?api_key=hidden&view=public",
        ),
    ]

    for parser, text, base_url, expected_url, raw_url in cases:
        urls = parser(text, base_url=base_url)
        assert expected_url in urls
        assert raw_url not in urls
