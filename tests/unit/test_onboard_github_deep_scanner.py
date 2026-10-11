"""Tests for :class:`forge.onboard.github_spider.GitHubDeepScanner`.

Every endpoint is injectable so these tests never touch the live
GitHub API. The ``_MockHttp`` responder routes GET requests to
deterministic payloads based on URL substrings.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest

from forge.onboard.github_spider import (
    GITHUB_DEEP_SCANNER_SCHEMA_VERSION,
    GitHubDeepScanner,
    GitHubSpiderError,
    GitHubSpiderResult,
)


# ---------------------------------------------------------------------------
# Mock HTTP helper
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


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------


def test_deep_scanner_rejects_empty_token() -> None:
    with pytest.raises(GitHubSpiderError, match="PAT"):
        GitHubDeepScanner("")


def test_deep_scanner_exposes_schema_version() -> None:
    assert GITHUB_DEEP_SCANNER_SCHEMA_VERSION == "forge.github_deep_scanner.v1"


def test_deep_scanner_initializes_with_sane_defaults() -> None:
    scanner = GitHubDeepScanner("ghp_token")
    assert scanner.max_repos == 500
    assert scanner.max_branches_per_repo == 50
    assert scanner.max_commits_per_branch == 100
    assert scanner.max_pull_requests_per_repo == 100
    assert scanner.include_branches is True
    assert scanner.include_commits is True
    assert scanner.include_pull_requests is True
    assert scanner.include_actions is True
    assert scanner.include_pages is True


# ---------------------------------------------------------------------------
# Full deep scan: orgs, repos, metadata, branches, commits, PRs, env, actions,
# key files, config files, pages
# ---------------------------------------------------------------------------


@pytest.fixture
def deep_routes() -> list[tuple[str, dict[str, Any]]]:
    """Rich set of mock responses for a single org/repo deep scan."""
    org_list = [{"login": "myorg"}]
    repo_list = [
        {
            "full_name": "myorg/webapp",
            "name": "webapp",
            "description": "Hosted at api.corp-target.io",
            "homepage": "https://portal.corp-target.io",
            "topics": ["prod", "corp-target.io", "api-gateway"],
        }
    ]
    branches = [
        {"name": "main"},
        {"name": "feature/corp-target.io-login"},
    ]
    commits = [
        {
            "sha": "abc123def4567890",
            "commit": {
                "message": "Fix auth on https://ci.corp-target.io/jenkins",
                "author": {
                    "email": "dev@corp-target.io",
                    "name": "Dev",
                },
            },
        },
        {
            "sha": "ff00ff00ff00ff00",
            "commit": {
                "message": "Add AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE for integration",
                "author": {"email": "ops@corp-target.io"},
            },
        },
    ]
    pulls = [
        {
            "number": 42,
            "title": "Introduce staging.corp-target.io",
            "body": "Replaces old 10.0.0.5 host; see https://docs.corp-target.io/pr/42",
        }
    ]
    environments = {
        "environments": [
            {
                "name": "production",
                "html_url": "https://api.github.com/repos/myorg/webapp/environments/production",
                "deployment_url": "https://prod.corp-target.io/health",
            },
            {
                "name": "staging",
                "deployment_url": "https://staging.corp-target.io/health",
            },
        ]
    }
    workflows_listing = [
        {
            "type": "file",
            "name": "deploy.yml",
            "path": ".github/workflows/deploy.yml",
            "download_url": (
                "https://raw.githubusercontent.com/myorg/webapp/main/"
                ".github/workflows/deploy.yml"
            ),
        }
    ]
    workflow_body = {
        "status": 200,
        "headers": {},
        "text": (
            "name: deploy\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    env:\n"
            "      WEBHOOK_URL: https://hooks.corp-target.io/deploy\n"
            "      AWS_ACCOUNT_ID: '123456789012'\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n"
            "      - run: echo ${{ secrets.AWS_ACCESS_KEY_ID }}\n"
        ),
    }
    readme_payload = {
        "encoding": "base64",
        "content": _b64(
            "# Webapp\n\n"
            "Public: https://portal.corp-target.io\n"
            "Internal API: 10.0.0.5\n"
            "Owner: admin@corp-target.io\n"
        ),
    }
    docker_compose = {
        "encoding": "base64",
        "content": _b64(
            "services:\n"
            "  app:\n"
            "    image: ghcr.io/myorg/webapp:latest\n"
            "    environment:\n"
            "      DB_HOST: db.corp-target.io\n"
            "      REDIS_URL: redis://cache.corp-target.io:6379\n"
        ),
    }
    env_example = {
        "encoding": "base64",
        "content": _b64(
            "SUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co\n"
            "SUPABASE_ANON_KEY=\n"
            "DATABASE_URL=postgres://db.corp-target.io:5432/app\n"
        ),
    }
    pages_body = {
        "html_url": "https://docs.corp-target.io",
        "cname": "docs.corp-target.io",
    }
    return [
        ("user/orgs", {"status": 200, "headers": {}, "json": org_list}),
        ("user/repos", {"status": 200, "headers": {}, "json": []}),
        (
            "orgs/myorg/repos",
            {
                "status": 200,
                "headers": {"X-RateLimit-Remaining": "4999"},
                "json": repo_list,
            },
        ),
        (
            "repos/myorg/webapp/branches",
            {"status": 200, "headers": {}, "json": branches},
        ),
        (
            "repos/myorg/webapp/commits",
            {"status": 200, "headers": {}, "json": commits},
        ),
        (
            "repos/myorg/webapp/pulls",
            {"status": 200, "headers": {}, "json": pulls},
        ),
        (
            "repos/myorg/webapp/environments",
            {"status": 200, "headers": {}, "json": environments},
        ),
        (
            "repos/myorg/webapp/contents/.github/workflows",
            {"status": 200, "headers": {}, "json": workflows_listing},
        ),
        (
            "raw.githubusercontent.com/myorg/webapp/main/.github/workflows/deploy.yml",
            workflow_body,
        ),
        (
            "repos/myorg/webapp/readme",
            {"status": 200, "headers": {}, "json": readme_payload},
        ),
        (
            "repos/myorg/webapp/contents/docker-compose.yml",
            {"status": 200, "headers": {}, "json": docker_compose},
        ),
        (
            "repos/myorg/webapp/contents/.env.example",
            {"status": 200, "headers": {}, "json": env_example},
        ),
        (
            "repos/myorg/webapp/pages",
            {"status": 200, "headers": {}, "json": pages_body},
        ),
    ]


def test_deep_scan_discovers_orgs_via_user_orgs_endpoint(
    deep_routes: list[tuple[str, dict[str, Any]]],
) -> None:
    http = _MockHttp(deep_routes)
    scanner = GitHubDeepScanner("ghp_token", http_get=http, max_repos=5)
    result = scanner.scan_all()
    assert "myorg" in result.orgs_scanned
    # /user/orgs endpoint was hit.
    assert any("user/orgs" in url for url in http.called)


def test_deep_scan_scans_repo_metadata(
    deep_routes: list[tuple[str, dict[str, Any]]],
) -> None:
    http = _MockHttp(deep_routes)
    scanner = GitHubDeepScanner("ghp_token", http_get=http, max_repos=5)
    result = scanner.scan_all(orgs=["myorg"])
    types = {(s["target_type"], s["target_value"]) for s in result.seeds}
    assert ("url", "https://portal.corp-target.io") in types
    assert ("domain", "portal.corp-target.io") in types
    assert ("domain", "api.corp-target.io") in types


def test_deep_scan_scans_branches_names(
    deep_routes: list[tuple[str, dict[str, Any]]],
) -> None:
    http = _MockHttp(deep_routes)
    scanner = GitHubDeepScanner("ghp_token", http_get=http)
    result = scanner.scan_all(orgs=["myorg"])
    assert any("repos/myorg/webapp/branches" in url for url in http.called)


def test_deep_scan_scans_commits_and_captures_urls(
    deep_routes: list[tuple[str, dict[str, Any]]],
) -> None:
    http = _MockHttp(deep_routes)
    scanner = GitHubDeepScanner("ghp_token", http_get=http)
    result = scanner.scan_all(orgs=["myorg"])
    urls = {s["target_value"] for s in result.seeds if s["target_type"] == "url"}
    assert "https://ci.corp-target.io/jenkins" in urls
    emails = {s["target_value"] for s in result.seeds if s["target_type"] == "email"}
    assert "dev@corp-target.io" in emails
    assert "ops@corp-target.io" in emails


def test_deep_scan_commit_secret_hits_are_redacted(
    deep_routes: list[tuple[str, dict[str, Any]]],
) -> None:
    http = _MockHttp(deep_routes)
    scanner = GitHubDeepScanner("ghp_token", http_get=http)
    result = scanner.scan_all(orgs=["myorg"])
    aws_hits = [h for h in result.secret_hits if h.get("label") == "aws_access_key"]
    assert aws_hits
    for hit in aws_hits:
        assert "AKIAIOSFODNN7EXAMPLE" not in hit.get("redacted_sample", "")


def test_deep_scan_scans_pull_requests(
    deep_routes: list[tuple[str, dict[str, Any]]],
) -> None:
    http = _MockHttp(deep_routes)
    scanner = GitHubDeepScanner("ghp_token", http_get=http)
    result = scanner.scan_all(orgs=["myorg"])
    domains = {s["target_value"] for s in result.seeds if s["target_type"] == "domain"}
    assert "staging.corp-target.io" in domains
    assert "docs.corp-target.io" in domains
    ips = {s["target_value"] for s in result.seeds if s["target_type"] == "ipv4"}
    assert "10.0.0.5" in ips


def test_deep_scan_scans_environments_for_deploy_urls(
    deep_routes: list[tuple[str, dict[str, Any]]],
) -> None:
    http = _MockHttp(deep_routes)
    scanner = GitHubDeepScanner("ghp_token", http_get=http)
    result = scanner.scan_all(orgs=["myorg"])
    urls = {s["target_value"] for s in result.seeds if s["target_type"] == "url"}
    assert "https://prod.corp-target.io/health" in urls
    assert "https://staging.corp-target.io/health" in urls


def test_deep_scan_scans_actions_workflow_bodies(
    deep_routes: list[tuple[str, dict[str, Any]]],
) -> None:
    http = _MockHttp(deep_routes)
    scanner = GitHubDeepScanner("ghp_token", http_get=http)
    result = scanner.scan_all(orgs=["myorg"])
    urls = {s["target_value"] for s in result.seeds if s["target_type"] == "url"}
    assert "https://hooks.corp-target.io/deploy" in urls
    # AWS account id in workflow env YAML is extracted via explicit context.
    cloud_refs = {
        s["target_value"] for s in result.seeds if s["target_type"] == "cloud_ref"
    }
    assert "cloud_ref:aws_account:123456789012" in cloud_refs


def test_deep_scan_records_github_actions_secret_names(
    deep_routes: list[tuple[str, dict[str, Any]]],
) -> None:
    http = _MockHttp(deep_routes)
    scanner = GitHubDeepScanner("ghp_token", http_get=http)
    result = scanner.scan_all(orgs=["myorg"])
    labels = {
        (h.get("label"), h.get("secret_name"))
        for h in result.secret_hits
        if h.get("label") == "github_actions_secret_name"
    }
    assert ("github_actions_secret_name", "DEPLOY_TOKEN") in labels
    assert ("github_actions_secret_name", "AWS_ACCESS_KEY_ID") in labels


def test_deep_scan_scans_readme_via_contents_endpoint(
    deep_routes: list[tuple[str, dict[str, Any]]],
) -> None:
    http = _MockHttp(deep_routes)
    scanner = GitHubDeepScanner("ghp_token", http_get=http)
    result = scanner.scan_all(orgs=["myorg"])
    emails = {s["target_value"] for s in result.seeds if s["target_type"] == "email"}
    assert "admin@corp-target.io" in emails


def test_deep_scan_scans_config_files_for_cloud_refs(
    deep_routes: list[tuple[str, dict[str, Any]]],
) -> None:
    http = _MockHttp(deep_routes)
    scanner = GitHubDeepScanner("ghp_token", http_get=http)
    result = scanner.scan_all(orgs=["myorg"])
    cloud_refs = {
        s["target_value"] for s in result.seeds if s["target_type"] == "cloud_ref"
    }
    # Supabase hostname context promotes the project ref.
    assert "cloud_ref:supabase:abcdefghijklmnopqrst" in cloud_refs
    # Config file internal hostnames surface as domain seeds.
    domains = {s["target_value"] for s in result.seeds if s["target_type"] == "domain"}
    assert "db.corp-target.io" in domains
    assert "cache.corp-target.io" in domains


def test_deep_scan_scans_pages_for_cname(
    deep_routes: list[tuple[str, dict[str, Any]]],
) -> None:
    http = _MockHttp(deep_routes)
    scanner = GitHubDeepScanner("ghp_token", http_get=http)
    result = scanner.scan_all(orgs=["myorg"])
    urls = {s["target_value"] for s in result.seeds if s["target_type"] == "url"}
    assert "https://docs.corp-target.io" in urls


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


def test_deep_scan_follows_link_header_for_pagination() -> None:
    page1_repos = [
        {"full_name": "myorg/repo-1"},
        {"full_name": "myorg/repo-2"},
    ]
    page2_repos = [
        {"full_name": "myorg/repo-3"},
    ]
    routes = [
        (
            "orgs/myorg/repos?per_page=100&sort=updated",
            {
                "status": 200,
                "headers": {
                    "Link": (
                        '<https://api.github.com/orgs/myorg/repos?page=2'
                        '&per_page=100&sort=updated>; rel="next"'
                    ),
                },
                "json": page1_repos,
            },
        ),
        (
            "orgs/myorg/repos?page=2",
            {"status": 200, "headers": {}, "json": page2_repos},
        ),
        ("user/orgs", {"status": 200, "headers": {}, "json": []}),
        ("user/repos", {"status": 200, "headers": {}, "json": []}),
    ]
    http = _MockHttp(routes)
    scanner = GitHubDeepScanner(
        "ghp_token",
        http_get=http,
        max_repos=10,
        include_branches=False,
        include_commits=False,
        include_pull_requests=False,
        include_environments=False,
        include_actions=False,
        include_metadata=True,
        include_key_files=False,
        include_config_files=False,
        include_pages=False,
    )
    result = scanner.scan_all(orgs=["myorg"])
    assert result.repos_total == 3
    assert result.repos_scanned == 3


def test_deep_scan_respects_max_repos_cap() -> None:
    repos = [{"full_name": f"myorg/repo-{i}"} for i in range(5)]
    routes = [
        ("user/orgs", {"status": 200, "headers": {}, "json": []}),
        ("user/repos", {"status": 200, "headers": {}, "json": []}),
        ("orgs/myorg/repos", {"status": 200, "headers": {}, "json": repos}),
    ]
    http = _MockHttp(routes)
    scanner = GitHubDeepScanner(
        "ghp_token",
        http_get=http,
        max_repos=2,
        include_branches=False,
        include_commits=False,
        include_pull_requests=False,
        include_environments=False,
        include_actions=False,
        include_key_files=False,
        include_config_files=False,
        include_pages=False,
    )
    result = scanner.scan_all(orgs=["myorg"])
    assert result.repos_scanned == 2


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def test_deep_scan_handles_rate_limit_403(
    deep_routes: list[tuple[str, dict[str, Any]]],
) -> None:
    routes = [
        ("user/orgs", {"status": 200, "headers": {}, "json": []}),
        ("user/repos", {"status": 200, "headers": {}, "json": []}),
        (
            "orgs/myorg/repos",
            {
                "status": 403,
                "headers": {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1"},
                "json": {"message": "rate limited"},
            },
        ),
    ]
    http = _MockHttp(routes)
    scanner = GitHubDeepScanner("ghp_token", http_get=http)
    result = scanner.scan_all(orgs=["myorg"])
    assert result.repos_scanned == 0
    assert any(err["detail"] == "HTTP 403" for err in result.source_errors)
    assert result.rate_limit.get("remaining") == "0"


def test_deep_scan_contains_http_exceptions() -> None:
    def _boom(url: str, *, headers: dict[str, str]) -> dict[str, Any]:
        raise RuntimeError("socket closed")

    scanner = GitHubDeepScanner("ghp_token", http_get=_boom)
    result = scanner.scan_all(orgs=["myorg"])
    assert result.repos_scanned == 0
    assert any("socket closed" in err["detail"] for err in result.source_errors)


# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------


def test_deep_scan_dedupes_seeds_across_sources(
    deep_routes: list[tuple[str, dict[str, Any]]],
) -> None:
    http = _MockHttp(deep_routes)
    scanner = GitHubDeepScanner("ghp_token", http_get=http)
    result = scanner.scan_all(orgs=["myorg"])
    seen_keys = [
        (s["target_type"], s["target_value"]) for s in result.seeds
    ]
    # No duplicates in final output.
    assert len(seen_keys) == len(set(seen_keys))


def test_deep_scan_filters_github_hosts_from_final_seeds(
    deep_routes: list[tuple[str, dict[str, Any]]],
) -> None:
    http = _MockHttp(deep_routes)
    scanner = GitHubDeepScanner("ghp_token", http_get=http)
    result = scanner.scan_all(orgs=["myorg"])
    for seed in result.seeds:
        if seed["target_type"] in {"domain", "url"}:
            assert "github.com" not in seed["target_value"]
            assert "githubusercontent.com" not in seed["target_value"]


# ---------------------------------------------------------------------------
# Toggle individual phases
# ---------------------------------------------------------------------------


def test_deep_scan_phase_toggles_are_respected() -> None:
    routes = [
        ("user/orgs", {"status": 200, "headers": {}, "json": []}),
        ("user/repos", {"status": 200, "headers": {}, "json": []}),
        (
            "orgs/myorg/repos",
            {"status": 200, "headers": {}, "json": [{"full_name": "myorg/webapp"}]},
        ),
    ]
    http = _MockHttp(routes)
    scanner = GitHubDeepScanner(
        "ghp_token",
        http_get=http,
        include_branches=False,
        include_commits=False,
        include_pull_requests=False,
        include_environments=False,
        include_actions=False,
        include_metadata=True,
        include_key_files=False,
        include_config_files=False,
        include_pages=False,
    )
    scanner.scan_all(orgs=["myorg"])
    # None of the disabled endpoints should have been hit.
    assert not any("branches" in url for url in http.called)
    assert not any("commits" in url for url in http.called)
    assert not any("pulls" in url for url in http.called)
    assert not any("environments" in url for url in http.called)
    assert not any("workflows" in url for url in http.called)
    assert not any("pages" in url for url in http.called)


# ---------------------------------------------------------------------------
# Authenticated-user flow
# ---------------------------------------------------------------------------


def test_deep_scan_lists_authenticated_user_repos() -> None:
    user_repos = [
        {
            "full_name": "me/personal",
            "name": "personal",
            "description": "owned at owner.corp-target.io",
            "homepage": "",
        }
    ]
    routes = [
        ("user/orgs", {"status": 200, "headers": {}, "json": []}),
        ("user/repos", {"status": 200, "headers": {}, "json": user_repos}),
    ]
    http = _MockHttp(routes)
    scanner = GitHubDeepScanner(
        "ghp_token",
        http_get=http,
        include_branches=False,
        include_commits=False,
        include_pull_requests=False,
        include_environments=False,
        include_actions=False,
        include_metadata=True,
        include_key_files=False,
        include_config_files=False,
        include_pages=False,
    )
    result = scanner.scan_all()
    assert result.repos_scanned == 1
    domains = {s["target_value"] for s in result.seeds if s["target_type"] == "domain"}
    assert "owner.corp-target.io" in domains


def test_deep_scan_result_dedupes_same_repo_across_orgs_and_user_endpoints() -> None:
    repo_list = [{"full_name": "myorg/webapp", "description": ""}]
    routes = [
        ("user/orgs", {"status": 200, "headers": {}, "json": []}),
        ("user/repos", {"status": 200, "headers": {}, "json": repo_list}),
        ("orgs/myorg/repos", {"status": 200, "headers": {}, "json": repo_list}),
    ]
    http = _MockHttp(routes)
    scanner = GitHubDeepScanner(
        "ghp_token",
        http_get=http,
        include_branches=False,
        include_commits=False,
        include_pull_requests=False,
        include_environments=False,
        include_actions=False,
        include_metadata=True,
        include_key_files=False,
        include_config_files=False,
        include_pages=False,
    )
    result = scanner.scan_all(orgs=["myorg"])
    # Same repo returned from both /orgs/myorg/repos and /user/repos should
    # count only once in repos_scanned.
    assert result.repos_scanned == 1
