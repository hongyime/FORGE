"""Tests for :mod:`forge.onboard.github_spider`.

The real GitHub API is never called. :func:`spider_github` accepts a
``http_get`` callable so these tests feed deterministic payloads and
verify URL/IP/domain extraction, secret detection, deny-listing, and
rate-limit propagation.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest

from forge.onboard.github_spider import (
    GITHUB_SPIDER_SCHEMA_VERSION,
    GitHubSpiderError,
    extract_seeds_from_text,
    parse_github_repo_payload,
    spider_github,
)


# ---------------------------------------------------------------------------
# extract_seeds_from_text
# ---------------------------------------------------------------------------


def test_extract_seeds_from_text_finds_urls_domains_ips_emails() -> None:
    text = (
        "Our dashboard lives at https://app.example.com/login. "
        "DNS entry api.example.com. Internal 10.0.0.5 and admin@example.com."
    )
    seeds = extract_seeds_from_text(text, source_label="readme")
    types = {(s["target_type"], s["target_value"]) for s in seeds}
    assert ("url", "https://app.example.com/login") in types
    assert ("domain", "app.example.com") in types
    assert ("domain", "api.example.com") in types
    assert ("ipv4", "10.0.0.5") in types
    assert ("email", "admin@example.com") in types


def test_extract_seeds_from_text_denylist_strips_github_hosts() -> None:
    text = "see https://github.com/org/repo and https://raw.githubusercontent.com/x"
    seeds = extract_seeds_from_text(text)
    assert all("github" not in s["target_value"] for s in seeds)


def test_extract_seeds_from_text_denylist_strips_localhost() -> None:
    text = "dev server at http://localhost:3000 and 127.0.0.1"
    seeds = extract_seeds_from_text(text)
    assert seeds == []


def test_extract_seeds_from_text_dedupes_within_single_call() -> None:
    text = "example.com example.com example.com https://example.com"
    seeds = extract_seeds_from_text(text)
    hosts = [s for s in seeds if s["target_type"] == "domain"]
    # Only one domain entry for example.com even with repeated occurrences.
    assert sum(1 for h in hosts if h["target_value"] == "example.com") == 1


# ---------------------------------------------------------------------------
# parse_github_repo_payload
# ---------------------------------------------------------------------------


def test_parse_github_repo_payload_extracts_homepage_and_description() -> None:
    payload = {
        "full_name": "myorg/webapp",
        "name": "webapp",
        "description": "Routes traffic through api.example.com",
        "homepage": "https://portal.example.com",
    }
    seeds, secrets = parse_github_repo_payload(payload)
    types = {(s["target_type"], s["target_value"]) for s in seeds}
    assert ("url", "https://portal.example.com") in types
    assert ("domain", "portal.example.com") in types
    assert ("domain", "api.example.com") in types
    assert secrets == []


def test_parse_github_repo_payload_scans_readme_for_secrets() -> None:
    readme = (
        "## Deploy\n"
        "Set AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE and GH token ghp_"
        + "x" * 40
        + "\n"
    )
    seeds, secrets = parse_github_repo_payload(
        {"full_name": "myorg/webapp"},
        readme_text=readme,
    )
    assert any(s["label"] == "aws_access_key" for s in secrets)
    assert any(s["label"] == "github_pat" for s in secrets)
    # Secret values themselves are not leaked into seed list.
    for seed in seeds:
        assert "AKIA" not in seed["target_value"]
        assert "ghp_" not in seed["target_value"]


def test_parse_github_repo_payload_scans_workflow_files() -> None:
    workflows = [
        {
            "name": "deploy.yml",
            "path": ".github/workflows/deploy.yml",
            "content": "runs-on: ubuntu-latest\nurl: https://ci.example.com/webhook",
        }
    ]
    seeds, _ = parse_github_repo_payload(
        {"full_name": "myorg/webapp"},
        workflows=workflows,
    )
    assert any(s["target_value"] == "https://ci.example.com/webhook" for s in seeds)
    assert any(s["target_value"] == "ci.example.com" for s in seeds)


# ---------------------------------------------------------------------------
# spider_github (mock HTTP)
# ---------------------------------------------------------------------------


class _MockHttp:
    """Deterministic HTTP responder.

    Resolves URLs against a routing table built in the test setup.
    Each entry is ``(url_substring, response_dict)``.
    """

    def __init__(self, routes: list[tuple[str, dict[str, Any]]]) -> None:
        self.routes = routes
        self.called: list[str] = []

    def __call__(self, url: str, *, headers: dict[str, str]) -> dict[str, Any]:
        self.called.append(url)
        for needle, response in self.routes:
            if needle in url:
                return response
        return {"status": 404, "headers": {}, "json": {"message": "not found"}}


def _b64(body: str) -> str:
    return base64.b64encode(body.encode("utf-8")).decode("ascii")


def test_spider_github_rejects_empty_token() -> None:
    with pytest.raises(GitHubSpiderError, match="PAT"):
        spider_github("", orgs=["myorg"])


def test_spider_github_rejects_when_no_owner_supplied() -> None:
    with pytest.raises(GitHubSpiderError, match="org or user"):
        spider_github("ghp_token", orgs=[], users=[])


def test_spider_github_scans_mock_repos_and_extracts_seeds() -> None:
    repo_list = [
        {
            "full_name": "myorg/webapp",
            "name": "webapp",
            "description": "Hosted at api.example.com",
            "homepage": "https://portal.example.com",
        },
        {
            "full_name": "myorg/other",
            "name": "other",
            "description": "no urls here",
            "homepage": "",
        },
    ]
    readme_payload = {
        "encoding": "base64",
        "content": _b64("Internal api at 10.0.0.5 and admin@example.com"),
    }
    workflows_listing = [
        {
            "type": "file",
            "name": "deploy.yml",
            "path": ".github/workflows/deploy.yml",
            "download_url": "https://raw.githubusercontent.com/myorg/webapp/main/.github/workflows/deploy.yml",
        }
    ]
    workflow_body = {"status": 200, "headers": {}, "text": "env:\n  URL: https://ci.example.com"}

    routes = [
        ("orgs/myorg/repos", {"status": 200, "headers": {"X-RateLimit-Remaining": "4999"}, "json": repo_list}),
        ("repos/myorg/webapp/readme", {"status": 200, "headers": {}, "json": readme_payload}),
        ("repos/myorg/other/readme", {"status": 200, "headers": {}, "json": {"encoding": "base64", "content": ""}}),
        ("repos/myorg/webapp/contents/.github/workflows", {"status": 200, "headers": {}, "json": workflows_listing}),
        ("repos/myorg/other/contents/.github/workflows", {"status": 200, "headers": {}, "json": []}),
        ("raw.githubusercontent.com/myorg/webapp/main/.github/workflows/deploy.yml", workflow_body),
    ]
    http = _MockHttp(routes)

    result = spider_github(
        "ghp_token",
        orgs=["myorg"],
        http_get=http,
        max_repos=5,
    )
    assert result.schema_version == GITHUB_SPIDER_SCHEMA_VERSION
    assert result.repos_scanned == 2
    assert result.repos_total == 2
    assert result.rate_limit.get("remaining") == "4999"

    values = {(s["target_type"], s["target_value"]) for s in result.seeds}
    assert ("domain", "api.example.com") in values
    assert ("domain", "portal.example.com") in values
    assert ("url", "https://portal.example.com") in values
    assert ("ipv4", "10.0.0.5") in values
    assert ("email", "admin@example.com") in values
    assert ("url", "https://ci.example.com") in values
    assert ("domain", "ci.example.com") in values


def test_spider_github_respects_max_repos_cap() -> None:
    repo_list = [
        {"full_name": f"myorg/repo-{i}", "name": f"repo-{i}", "description": ""}
        for i in range(5)
    ]
    routes = [
        ("orgs/myorg/repos", {"status": 200, "headers": {}, "json": repo_list}),
        ("readme", {"status": 404, "headers": {}, "json": {}}),
        ("contents/.github/workflows", {"status": 404, "headers": {}, "json": {}}),
    ]
    http = _MockHttp(routes)
    result = spider_github(
        "ghp_token", orgs=["myorg"], http_get=http, max_repos=2
    )
    assert result.repos_scanned == 2
    # Scanning stops after cap even though 5 repos were listed.
    assert result.repos_total == 5


def test_spider_github_records_http_errors_without_raising() -> None:
    routes = [
        ("orgs/myorg/repos", {"status": 403, "headers": {"X-RateLimit-Remaining": "0"}, "json": {}}),
    ]
    http = _MockHttp(routes)
    result = spider_github("ghp_token", orgs=["myorg"], http_get=http)
    assert result.repos_scanned == 0
    assert any(err["detail"] == "HTTP 403" for err in result.source_errors)


def test_spider_github_handles_getter_exception() -> None:
    def _boom(url: str, *, headers: dict[str, str]) -> dict[str, Any]:
        raise RuntimeError("network outage")

    result = spider_github("ghp_token", orgs=["myorg"], http_get=_boom)
    assert result.repos_scanned == 0
    assert any("network outage" in err["detail"] for err in result.source_errors)
