"""GitHub repository spider for seed extraction.

The spider is a small, deliberately conservative tool: it visits the
GitHub REST API using an operator-supplied PAT and extracts
seed-shaped values from repository metadata, README files, and GitHub
Actions workflow definitions. It never clones repositories or
executes workflow code.

Design constraints:

- The HTTP layer is injectable so tests can run entirely offline
  with mock payloads. Pass ``http_get=my_fn`` to :func:`spider_github`;
  the default resolves to a thin ``httpx`` call behind a lazy import.
- Secrets detected in text are intentionally **not** returned verbatim.
  Only their type label and the containing repo are reported so the
  spider never persists credential bodies into the target feed. The
  :func:`extract_seeds_from_text` helper is unit-testable in isolation.
- Only ``target-feed.v1``-compatible shapes are emitted so callers can
  pipe the output directly into ``forge targets import --feed-file``.

Rate limiting: the spider stops after ``max_repos`` repositories per
org/user and surfaces ``X-RateLimit-Remaining`` / ``X-RateLimit-Reset``
headers in :attr:`GitHubSpiderResult.rate_limit`. Live calls that fail
with an HTTP 403/429 return a partial result annotated with the error
rather than raising; the caller decides how to proceed.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping, Sequence


GITHUB_SPIDER_SCHEMA_VERSION = "forge.github_spider.v1"


class GitHubSpiderError(RuntimeError):
    """Raised for configuration errors inside the spider (not HTTP errors)."""


@dataclass
class GitHubSpiderResult:
    """Aggregate spider output."""

    schema_version: str = GITHUB_SPIDER_SCHEMA_VERSION
    repos_scanned: int = 0
    repos_total: int = 0
    seeds: list[dict[str, Any]] = field(default_factory=list)
    secret_hits: list[dict[str, Any]] = field(default_factory=list)
    source_errors: list[dict[str, Any]] = field(default_factory=list)
    rate_limit: dict[str, Any] = field(default_factory=dict)
    started_at: str = ""
    finished_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ----------------------------------------------------------------------
# Regexes
# ----------------------------------------------------------------------


_URL_RE = re.compile(
    r"https?://[^\s`'\"<>)\]]+",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
_IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
)
_DOMAIN_RE = re.compile(
    r"\b(?=[a-z0-9])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|dev|app|co|us|uk|ca|de|fr|jp|cn|au|edu|gov|mil|info|biz|cloud|site|tech)\b",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(
    r"\b[a-z0-9][a-z0-9._%+\-]*@[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}\b",
    re.IGNORECASE,
)

#: Secret detectors — tuples of ``(label, pattern)``. Patterns are kept
#: deliberately coarse because the goal is only "flag a hit for the
#: operator"; the exact value is never returned verbatim.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github_pat", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key", re.compile(r"aws[_-]?secret[_-]?access[_-]?key", re.IGNORECASE)),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----")),
    ("stripe_key", re.compile(r"sk_(live|test)_[A-Za-z0-9]{24,}")),
    ("generic_bearer", re.compile(r"Bearer\s+[A-Za-z0-9\.\-_]{20,}")),
)

#: Common noisy hostnames surfaced by README/CI metadata we never want
#: to promote into a target feed. ``example.com`` etc. remain allowed
#: because the operator may legitimately own them, but IANA reserved
#: localhost strings and GitHub-internal infrastructure are filtered.
_HOST_DENYLIST = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "github.com",
    "www.github.com",
    "raw.githubusercontent.com",
    "api.github.com",
    "github.io",
    "actions.githubusercontent.com",
    "codeload.github.com",
    "schemas.microsoft.com",
    "schemas.openxmlformats.org",
}


# ----------------------------------------------------------------------
# Public helpers
# ----------------------------------------------------------------------


def extract_seeds_from_text(
    text: str,
    *,
    source_label: str = "",
) -> list[dict[str, Any]]:
    """Return deduped ``target-feed.v1`` candidates found in ``text``.

    URLs, bare domains, IPs, and email addresses are returned.
    Deny-listed hostnames (``localhost``, ``github.com``, …) are
    silently excluded; the operator sees a cleaner feed.
    """
    body = str(text or "")
    if not body:
        return []
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for match in _URL_RE.finditer(body):
        url = match.group(0).rstrip(".,;:)]")
        host = _host_from_url(url)
        if not host or host in _HOST_DENYLIST:
            continue
        _add_seed(results, seen, "url", url, source_label, source_detail=host)
        _add_seed(results, seen, "domain", host, source_label)

    for match in _DOMAIN_RE.finditer(body):
        host = match.group(0).lower().rstrip(".")
        if not host or host in _HOST_DENYLIST:
            continue
        _add_seed(results, seen, "domain", host, source_label)

    for match in _IPV4_RE.finditer(body):
        value = match.group(0)
        if value in _HOST_DENYLIST:
            continue
        _add_seed(results, seen, "ipv4", value, source_label)

    for match in _IPV6_RE.finditer(body):
        value = match.group(0)
        if value in _HOST_DENYLIST:
            continue
        _add_seed(results, seen, "ipv6", value, source_label)

    for match in _EMAIL_RE.finditer(body):
        value = match.group(0).lower()
        _add_seed(results, seen, "email", value, source_label)

    return results


def parse_github_repo_payload(
    payload: Mapping[str, Any],
    *,
    readme_text: str | None = None,
    workflows: Sequence[Mapping[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Extract seeds + secret hits from one repo's metadata.

    Returns ``(seeds, secret_hits)``.
    """
    seeds: list[dict[str, Any]] = []
    secrets: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    repo_full = str(payload.get("full_name") or payload.get("name") or "")
    html_url = str(payload.get("html_url") or "")
    homepage = str(payload.get("homepage") or "")

    if homepage and homepage.startswith(("http://", "https://")):
        host = _host_from_url(homepage)
        if host and host not in _HOST_DENYLIST:
            _add_seed(seeds, seen, "url", homepage, repo_full, source_detail="homepage")
            _add_seed(seeds, seen, "domain", host, repo_full)

    description = str(payload.get("description") or "")
    for candidate in extract_seeds_from_text(description, source_label=f"{repo_full}:description"):
        key = (candidate["target_type"], candidate["target_value"])
        if key in seen:
            continue
        seen.add(key)
        seeds.append(candidate)

    if readme_text:
        for candidate in extract_seeds_from_text(readme_text, source_label=f"{repo_full}:readme"):
            key = (candidate["target_type"], candidate["target_value"])
            if key in seen:
                continue
            seen.add(key)
            seeds.append(candidate)
        secrets.extend(_scan_secrets(readme_text, repo_full, source="readme"))

    for workflow in workflows or []:
        name = str(workflow.get("name") or workflow.get("path") or "workflow")
        content = str(workflow.get("content") or "")
        if not content:
            continue
        for candidate in extract_seeds_from_text(
            content, source_label=f"{repo_full}:workflow:{name}"
        ):
            key = (candidate["target_type"], candidate["target_value"])
            if key in seen:
                continue
            seen.add(key)
            seeds.append(candidate)
        secrets.extend(
            _scan_secrets(content, repo_full, source=f"workflow:{name}")
        )

    # html_url is informational — do not promote the GitHub repo URL
    # itself to the target feed; it is already deny-listed.
    _ = html_url
    return seeds, secrets


def spider_github(
    token: str,
    *,
    orgs: Iterable[str] | None = None,
    users: Iterable[str] | None = None,
    max_repos: int = 100,
    http_get: Callable[..., Any] | None = None,
    include_readmes: bool = True,
    include_workflows: bool = True,
    base_url: str = "https://api.github.com",
) -> GitHubSpiderResult:
    """Spider GitHub for seed-shaped values across org/user repos.

    Args:
        token: GitHub PAT. An empty token aborts with
            :class:`GitHubSpiderError` — the GitHub API's rate limit for
            unauthenticated clients is too low to be worth attempting.
        orgs: Iterable of GitHub org slugs.
        users: Iterable of GitHub user slugs.
        max_repos: Upper bound on repositories scanned across every
            org/user combined. Defaults to 100.
        http_get: Callable returning a dict payload for a given URL
            + headers. When None the spider imports ``httpx`` lazily.
        include_readmes: Fetch README.md for each repo (default True).
        include_workflows: Fetch ``.github/workflows/*.yml`` for each
            repo (default True).
        base_url: GitHub API base URL. Overridable for GitHub Enterprise.

    Returns:
        :class:`GitHubSpiderResult`.
    """
    if not str(token or "").strip():
        raise GitHubSpiderError("GitHub spider requires a non-empty PAT token")
    orgs_list = [o.strip() for o in (orgs or []) if o and o.strip()]
    users_list = [u.strip() for u in (users or []) if u and u.strip()]
    if not orgs_list and not users_list:
        raise GitHubSpiderError(
            "GitHub spider requires at least one org or user slug"
        )
    max_repos = max(1, int(max_repos))

    getter = http_get or _default_http_get
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token.strip()}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    result = GitHubSpiderResult(started_at=_now_iso())
    seen_seed_keys: set[tuple[str, str]] = set()

    for owner_type, owners in (("orgs", orgs_list), ("users", users_list)):
        for owner in owners:
            if result.repos_scanned >= max_repos:
                break
            repos_url = f"{base_url}/{owner_type}/{owner}/repos?per_page=30&sort=updated"
            response = _call(
                getter,
                repos_url,
                headers=headers,
                result=result,
                context=f"{owner_type}/{owner}:repos",
            )
            if response is None:
                continue
            repos = response.get("json") or []
            headers_received = response.get("headers") or {}
            _record_rate_limit(result, headers_received)
            if not isinstance(repos, list):
                result.source_errors.append(
                    {
                        "context": f"{owner_type}/{owner}:repos",
                        "detail": "response body was not a JSON list",
                    }
                )
                continue
            result.repos_total += len(repos)
            for repo in repos:
                if result.repos_scanned >= max_repos:
                    break
                if not isinstance(repo, Mapping):
                    continue
                repo_full_name = str(repo.get("full_name") or "").strip()
                if not repo_full_name:
                    continue
                readme_text = ""
                if include_readmes:
                    readme_text = _fetch_readme(
                        getter,
                        base_url,
                        repo_full_name,
                        headers,
                        result,
                    )
                workflows: list[dict[str, Any]] = []
                if include_workflows:
                    workflows = _fetch_workflows(
                        getter,
                        base_url,
                        repo_full_name,
                        headers,
                        result,
                    )
                seeds, secrets = parse_github_repo_payload(
                    repo,
                    readme_text=readme_text or None,
                    workflows=workflows or None,
                )
                for seed in seeds:
                    key = (seed["target_type"], seed["target_value"])
                    if key in seen_seed_keys:
                        continue
                    seen_seed_keys.add(key)
                    result.seeds.append(seed)
                for secret in secrets:
                    result.secret_hits.append(secret)
                result.repos_scanned += 1

    result.finished_at = _now_iso()
    return result


# ----------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------


def _add_seed(
    out: list[dict[str, Any]],
    seen: set[tuple[str, str]],
    target_type: str,
    target_value: str,
    source_label: str,
    *,
    source_detail: str = "",
) -> None:
    value = target_value.strip()
    if not value:
        return
    key = (target_type, value)
    if key in seen:
        return
    seen.add(key)
    out.append(
        {
            "target_type": target_type,
            "target_value": value,
            "source_kind": "github_spider",
            "source_group": "github_spider",
            "provenance": source_label,
            "source_detail": source_detail,
            "first_seen_at": _now_iso(),
        }
    )


def _scan_secrets(
    text: str, repo: str, *, source: str
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for label, pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            hits.append(
                {
                    "label": label,
                    "repo": repo,
                    "source": source,
                }
            )
    return hits


def _host_from_url(url: str) -> str:
    from urllib.parse import urlsplit  # noqa: PLC0415

    try:
        parsed = urlsplit(url)
    except ValueError:
        return ""
    host = (parsed.hostname or "").lower()
    return host.strip(".")


def _record_rate_limit(result: GitHubSpiderResult, headers: Mapping[str, Any]) -> None:
    remaining = headers.get("X-RateLimit-Remaining")
    reset = headers.get("X-RateLimit-Reset")
    if remaining is not None:
        result.rate_limit["remaining"] = remaining
    if reset is not None:
        result.rate_limit["reset"] = reset


def _call(
    getter: Callable[..., Any],
    url: str,
    *,
    headers: Mapping[str, str],
    result: GitHubSpiderResult,
    context: str,
) -> dict[str, Any] | None:
    try:
        response = getter(url, headers=dict(headers))
    except Exception as exc:  # noqa: BLE001
        result.source_errors.append(
            {
                "context": context,
                "detail": f"{exc.__class__.__name__}: {str(exc)[:200]}",
            }
        )
        return None
    if not isinstance(response, Mapping):
        result.source_errors.append(
            {
                "context": context,
                "detail": "http_get did not return a mapping",
            }
        )
        return None
    status = int(response.get("status", 0))
    if status >= 400:
        result.source_errors.append(
            {
                "context": context,
                "detail": f"HTTP {status}",
            }
        )
        return None
    return dict(response)


def _fetch_readme(
    getter: Callable[..., Any],
    base_url: str,
    repo_full_name: str,
    headers: Mapping[str, str],
    result: GitHubSpiderResult,
) -> str:
    url = f"{base_url}/repos/{repo_full_name}/readme"
    response = _call(
        getter, url, headers=headers, result=result, context=f"{repo_full_name}:readme"
    )
    if response is None:
        return ""
    body = response.get("json")
    if not isinstance(body, Mapping):
        return ""
    encoding = body.get("encoding")
    content = body.get("content") or ""
    if encoding == "base64":
        try:
            return base64.b64decode(content).decode("utf-8", errors="replace")
        except (ValueError, binascii_error_class()) as exc:
            result.source_errors.append(
                {
                    "context": f"{repo_full_name}:readme_decode",
                    "detail": f"base64 decode failed: {exc.__class__.__name__}",
                }
            )
            return ""
    return str(content)


def _fetch_workflows(
    getter: Callable[..., Any],
    base_url: str,
    repo_full_name: str,
    headers: Mapping[str, str],
    result: GitHubSpiderResult,
) -> list[dict[str, Any]]:
    list_url = f"{base_url}/repos/{repo_full_name}/contents/.github/workflows"
    response = _call(
        getter,
        list_url,
        headers=headers,
        result=result,
        context=f"{repo_full_name}:workflows_list",
    )
    if response is None:
        return []
    body = response.get("json")
    if not isinstance(body, list):
        return []
    workflows: list[dict[str, Any]] = []
    for entry in body:
        if not isinstance(entry, Mapping):
            continue
        if str(entry.get("type") or "") != "file":
            continue
        path = str(entry.get("path") or entry.get("name") or "")
        if not path.endswith((".yml", ".yaml")):
            continue
        download_url = str(entry.get("download_url") or "")
        content = ""
        if download_url:
            raw = _call(
                getter,
                download_url,
                headers=headers,
                result=result,
                context=f"{repo_full_name}:workflow:{path}",
            )
            if raw is not None:
                content = str(raw.get("text") or raw.get("body") or "")
        workflows.append({"name": entry.get("name"), "path": path, "content": content})
    return workflows


def _default_http_get(url: str, *, headers: Mapping[str, str]) -> dict[str, Any]:
    """Default HTTP getter — thin wrapper around :mod:`httpx`."""
    import httpx  # noqa: PLC0415

    with httpx.Client(timeout=15.0) as client:
        resp = client.get(url, headers=dict(headers))
    headers_dict = dict(resp.headers)
    body: Any = None
    text: str = ""
    try:
        body = resp.json()
    except (ValueError, json.JSONDecodeError):
        text = resp.text
    return {
        "status": resp.status_code,
        "headers": headers_dict,
        "json": body,
        "text": text,
    }


def binascii_error_class() -> type[Exception]:
    """Return the class of binascii errors for base64 decode fallbacks."""
    import binascii  # noqa: PLC0415

    return binascii.Error


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "GITHUB_SPIDER_SCHEMA_VERSION",
    "GitHubSpiderError",
    "GitHubSpiderResult",
    "extract_seeds_from_text",
    "parse_github_repo_payload",
    "spider_github",
]
