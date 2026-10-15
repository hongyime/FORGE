"""GitHub repository spider for seed extraction.

Two layers live in this module:

- :class:`GitHubDeepScanner` — a thorough scanner that walks orgs,
  users, repos, branches, commits, pull requests, environments,
  workflows, repo metadata, README/docs, config files, and GitHub Pages.
  Every endpoint is injectable so tests run entirely offline.
- :func:`spider_github` + :func:`parse_github_repo_payload` — the
  original lightweight helpers kept for backwards compatibility with
  :mod:`forge.onboard.cli` and existing tests. ``spider_github`` is now
  a thin shim over :class:`GitHubDeepScanner` with the same bounded
  per-repo README/workflow scan it had before.

Design constraints:

- The HTTP layer is injectable so tests can run entirely offline with
  mock payloads. Pass ``http_get=my_fn`` to the scanner; the default
  resolves to a thin ``httpx`` call behind a lazy import.
- Secrets detected in text are intentionally **not** returned verbatim.
  :mod:`forge.onboard.patterns` emits only a redacted sample label +
  offset so the spider never persists credential bodies into the
  target feed or audit log.
- Only ``target-feed.v1``-compatible shapes are emitted so callers can
  pipe the output directly into ``forge targets import --feed-file``.

Rate limiting: the scanner stops after ``max_repos`` repositories per
org/user, records quota headers, and retries 429s or 403s with an
exhausted primary quota using bounded backoff. Requests are skipped when
their retry count or total wait budget is reached.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from forge.onboard.patterns import (
    DENY_LIST_DOMAINS,
    extract_seeds_from_text as _patterns_extract_seeds,
    is_denied_target,
    scan_secrets as _patterns_scan_secrets,
)
from forge.onboard.rate_limit import request_with_rate_limit_backoff


GITHUB_SPIDER_SCHEMA_VERSION = "forge.github_spider.v2"
GITHUB_DEEP_SCANNER_SCHEMA_VERSION = "forge.github_deep_scanner.v1"


#: Default list of key repository files worth downloading for seed
#: extraction. The scanner stops at the first few matches per repo so
#: large repositories do not cause unbounded fetches.
_DEFAULT_KEY_FILES: tuple[str, ...] = (
    "README.md",
    "README.rst",
    "README.txt",
    "README",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "ARCHITECTURE.md",
    "docs/README.md",
    "docs/index.md",
    "docs/overview.md",
    "docs/architecture.md",
)


#: Default list of config files worth downloading. These typically
#: carry service URLs, cloud references, and sometimes example secret
#: patterns (which :func:`scan_secrets` catches without re-leaking).
_DEFAULT_CONFIG_FILES: tuple[str, ...] = (
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dev",
    ".env.local",
    "docker-compose.yml",
    "docker-compose.yaml",
    "docker-compose.prod.yml",
    "docker-compose.dev.yml",
    "docker-compose.staging.yml",
    "Dockerfile",
    "package.json",
    "pyproject.toml",
    "Cargo.toml",
    "requirements.txt",
    "go.mod",
    "composer.json",
    "Gemfile",
    "serverless.yml",
    "serverless.yaml",
    "terraform.tf",
    "main.tf",
    "variables.tf",
    "providers.tf",
    "vercel.json",
    "netlify.toml",
    "wrangler.toml",
    "app.yaml",
    "cloudbuild.yaml",
    "fly.toml",
    "render.yaml",
)


class GitHubSpiderError(RuntimeError):
    """Raised for configuration errors inside the spider (not HTTP errors)."""


@dataclass
class GitHubSpiderResult:
    """Aggregate spider output."""

    schema_version: str = GITHUB_SPIDER_SCHEMA_VERSION
    repos_scanned: int = 0
    repos_total: int = 0
    orgs_scanned: list[str] = field(default_factory=list)
    users_scanned: list[str] = field(default_factory=list)
    seeds: list[dict[str, Any]] = field(default_factory=list)
    secret_hits: list[dict[str, Any]] = field(default_factory=list)
    source_errors: list[dict[str, Any]] = field(default_factory=list)
    endpoints_called: list[str] = field(default_factory=list)
    rate_limit: dict[str, Any] = field(default_factory=dict)
    started_at: str = ""
    finished_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    # Helpers for :class:`GitHubDeepScanner` --------------------------------

    def record_endpoint(self, url: str) -> None:
        """Record an endpoint call for operator diagnostics."""
        if len(self.endpoints_called) < 2000:
            self.endpoints_called.append(url)


# ----------------------------------------------------------------------
# Compatibility helpers (retained for existing tests / CLI)
# ----------------------------------------------------------------------

#: Deny-list of hostnames surfaced through the legacy
#: :func:`extract_seeds_from_text` and :func:`parse_github_repo_payload`
#: helpers. Mirrors :data:`forge.onboard.patterns.DENY_LIST_DOMAINS` but
#: exposed as a plain set for legacy import compatibility.
_HOST_DENYLIST: frozenset[str] = DENY_LIST_DOMAINS


def extract_seeds_from_text(
    text: str,
    *,
    source_label: str = "",
) -> list[dict[str, Any]]:
    """Return deduped ``target-feed.v1`` candidates found in ``text``.

    Thin wrapper around :func:`forge.onboard.patterns.extract_seeds_from_text`
    so legacy call sites keep working while new scanners pull patterns
    from the shared module.
    """
    return _patterns_extract_seeds(text, source_label=source_label)


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
    homepage = str(payload.get("homepage") or "")

    if homepage and homepage.startswith(("http://", "https://")):
        for candidate in extract_seeds_from_text(
            homepage, source_label=f"{repo_full}:homepage"
        ):
            key = (candidate["target_type"], candidate["target_value"])
            if key in seen:
                continue
            seen.add(key)
            seeds.append(candidate)

    description = str(payload.get("description") or "")
    for candidate in extract_seeds_from_text(
        description, source_label=f"{repo_full}:description"
    ):
        key = (candidate["target_type"], candidate["target_value"])
        if key in seen:
            continue
        seen.add(key)
        seeds.append(candidate)

    if readme_text:
        for candidate in extract_seeds_from_text(
            readme_text, source_label=f"{repo_full}:readme"
        ):
            key = (candidate["target_type"], candidate["target_value"])
            if key in seen:
                continue
            seen.add(key)
            seeds.append(candidate)
        secrets.extend(
            _normalize_secret_hits(
                _patterns_scan_secrets(
                    readme_text, source_label=f"{repo_full}:readme"
                ),
                repo=repo_full,
                source="readme",
            )
        )

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
            _normalize_secret_hits(
                _patterns_scan_secrets(
                    content, source_label=f"{repo_full}:workflow:{name}"
                ),
                repo=repo_full,
                source=f"workflow:{name}",
            )
        )
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
    data_dir: Path | str | None = None,
) -> GitHubSpiderResult:
    """Spider GitHub for seed-shaped values across org/user repos.

    Thin convenience wrapper around :class:`GitHubDeepScanner`. The
    default behavior matches the historical ``spider_github``: list
    repos per org/user, fetch README + ``.github/workflows/*.yml`` for
    each, extract seeds + redacted secret hits, and cap at
    ``max_repos`` repositories across all owners combined.
    """
    orgs_list = [o.strip() for o in (orgs or []) if o and o.strip()]
    users_list = [u.strip() for u in (users or []) if u and u.strip()]
    if not orgs_list and not users_list:
        raise GitHubSpiderError(
            "GitHub spider requires at least one org or user slug"
        )
    scanner = GitHubDeepScanner(
        token=token,
        http_get=http_get,
        max_repos=max_repos,
        base_url=base_url,
        data_dir=data_dir,
        include_readmes=include_readmes,
        include_workflows=include_workflows,
        # Narrow scanner — keep legacy behavior bounded.
        include_authenticated_user_repos=False,
        include_branches=False,
        include_commits=False,
        include_pull_requests=False,
        include_environments=False,
        include_metadata=True,
        include_key_files=include_readmes,
        include_config_files=False,
        include_pages=False,
    )
    return scanner.scan_all(orgs=orgs_list, users=users_list)


# ----------------------------------------------------------------------
# Deep scanner
# ----------------------------------------------------------------------


class GitHubDeepScanner:
    """Thorough GitHub repository scanner.

    The scanner walks everything the supplied PAT can see:

    - Every accessible organization (``/user/orgs``).
    - Every accessible repository (``/user/repos`` for the authenticated
      user, plus ``/orgs/{org}/repos`` / ``/users/{user}/repos`` for
      explicit owners).
    - Per repository:

        A. All branches (``/branches``).
        B. Recent commits per branch (``/commits``). Only commit
           messages/authors are scanned; FORGE never pulls diffs here.
        C. Open + closed pull requests (``/pulls?state=all``). Titles
           and bodies are scanned.
        D. Deployment environments (``/environments``).
        E. GitHub Actions workflows (``.github/workflows/*.yml``). Both
           the workflow bodies and their listed secret names (**not**
           the secret values) are recorded.
        F. Repo metadata (``topics``, ``description``, ``homepage``).
        G. Key doc files (``README.md``, ``docs/*``, …).
        H. Config files (``.env.example``, ``docker-compose.yml``,
           ``package.json``, ``Dockerfile``, ``terraform/*.tf``, …).
        I. GitHub Pages URL (``/pages``) when enabled.

    Each step is independently togglable so operators who only want
    the metadata pass can disable the heavier commit/PR crawl.

    All seed and secret extraction is delegated to
    :mod:`forge.onboard.patterns` so the extraction rules are shared
    with other FORGE scanners.
    """

    def __init__(
        self,
        token: str,
        *,
        http_get: Callable[..., Any] | None = None,
        base_url: str = "https://api.github.com",
        max_repos: int = 500,
        max_branches_per_repo: int = 50,
        max_commits_per_branch: int = 100,
        max_pull_requests_per_repo: int = 100,
        max_workflow_files: int = 30,
        max_key_files_per_repo: int = 20,
        max_config_files_per_repo: int = 40,
        include_authenticated_user_repos: bool = True,
        include_branches: bool = True,
        include_commits: bool = True,
        include_pull_requests: bool = True,
        include_environments: bool = True,
        include_actions: bool = True,
        include_metadata: bool = True,
        include_key_files: bool = True,
        include_config_files: bool = True,
        include_pages: bool = True,
        include_readmes: bool = True,
        include_workflows: bool = True,
        key_files: Sequence[str] | None = None,
        config_files: Sequence[str] | None = None,
        data_dir: Path | str | None = None,
    ) -> None:
        token_value = str(token or "").strip()
        if not token_value:
            raise GitHubSpiderError(
                "GitHub deep scanner requires a non-empty PAT token"
            )
        self._token = token_value
        self.data_dir = data_dir
        self._http = http_get or _default_http_get
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"token {self._token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        # Bounded crawl parameters -----------------------------------------
        self.max_repos = max(1, int(max_repos))
        self.max_branches_per_repo = max(1, int(max_branches_per_repo))
        self.max_commits_per_branch = max(1, int(max_commits_per_branch))
        self.max_pull_requests_per_repo = max(1, int(max_pull_requests_per_repo))
        self.max_workflow_files = max(1, int(max_workflow_files))
        self.max_key_files_per_repo = max(1, int(max_key_files_per_repo))
        self.max_config_files_per_repo = max(1, int(max_config_files_per_repo))
        # Phase toggles ----------------------------------------------------
        self.include_authenticated_user_repos = bool(include_authenticated_user_repos)
        self.include_branches = bool(include_branches)
        self.include_commits = bool(include_commits)
        self.include_pull_requests = bool(include_pull_requests)
        self.include_environments = bool(include_environments)
        self.include_actions = bool(include_actions) and bool(include_workflows)
        self.include_metadata = bool(include_metadata)
        self.include_key_files = bool(include_key_files) and bool(include_readmes)
        self.include_config_files = bool(include_config_files)
        self.include_pages = bool(include_pages)
        self.key_files: tuple[str, ...] = tuple(key_files or _DEFAULT_KEY_FILES)
        self.config_files: tuple[str, ...] = tuple(config_files or _DEFAULT_CONFIG_FILES)

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def scan_all(
        self,
        *,
        orgs: Iterable[str] | None = None,
        users: Iterable[str] | None = None,
    ) -> GitHubSpiderResult:
        """Full deep scan.

        Enumerates orgs and users supplied by the caller plus — when
        ``include_authenticated_user_repos`` is True — every repo
        reachable via ``/user/repos``.
        """
        orgs_list = [self._normalize_slug(o) for o in (orgs or []) if self._normalize_slug(o)]
        users_list = [self._normalize_slug(u) for u in (users or []) if self._normalize_slug(u)]

        result = GitHubSpiderResult(
            schema_version=GITHUB_SPIDER_SCHEMA_VERSION,
            started_at=_now_iso(),
        )
        seen_seed_keys: set[tuple[str, str]] = set()
        seen_repo_names: set[str] = set()

        # 1. Expand orgs the token can see on top of explicit list.
        if self.include_authenticated_user_repos:
            discovered = self._list_user_orgs(result)
            for org in discovered:
                if org and org not in orgs_list:
                    orgs_list.append(org)

        # 2. Scan per-owner repos.
        for owner in orgs_list:
            if result.repos_scanned >= self.max_repos:
                break
            result.orgs_scanned.append(owner)
            for repo in self._list_owner_repos(owner, kind="orgs", result=result):
                if result.repos_scanned >= self.max_repos:
                    break
                self._scan_repo_dispatch(
                    repo,
                    result=result,
                    seen_seed_keys=seen_seed_keys,
                    seen_repo_names=seen_repo_names,
                )
        for owner in users_list:
            if result.repos_scanned >= self.max_repos:
                break
            result.users_scanned.append(owner)
            for repo in self._list_owner_repos(owner, kind="users", result=result):
                if result.repos_scanned >= self.max_repos:
                    break
                self._scan_repo_dispatch(
                    repo,
                    result=result,
                    seen_seed_keys=seen_seed_keys,
                    seen_repo_names=seen_repo_names,
                )

        # 3. Scan authenticated user's own repos (including private + fork).
        if self.include_authenticated_user_repos:
            for repo in self._list_authenticated_user_repos(result):
                if result.repos_scanned >= self.max_repos:
                    break
                self._scan_repo_dispatch(
                    repo,
                    result=result,
                    seen_seed_keys=seen_seed_keys,
                    seen_repo_names=seen_repo_names,
                )

        result.finished_at = _now_iso()
        self._dedupe_and_classify(result)
        return result

    def scan_repo(
        self,
        repo: Mapping[str, Any],
        *,
        result: GitHubSpiderResult | None = None,
    ) -> list[dict[str, Any]]:
        """Scan one repo and return its seeds (used in tests).

        The returned seeds are also appended to ``result.seeds`` when
        ``result`` is provided.
        """
        current = result or GitHubSpiderResult(
            schema_version=GITHUB_SPIDER_SCHEMA_VERSION,
            started_at=_now_iso(),
        )
        seen: set[tuple[str, str]] = {
            (s["target_type"], s["target_value"]) for s in current.seeds
        }
        self._scan_repo_dispatch(
            repo,
            result=current,
            seen_seed_keys=seen,
            seen_repo_names=set(),
        )
        if result is None:
            current.finished_at = _now_iso()
            self._dedupe_and_classify(current)
        return [s for s in current.seeds if s.get("provenance", "").startswith(
            str(repo.get("full_name") or "")
        )]

    # ------------------------------------------------------------------
    # Repo-level dispatch
    # ------------------------------------------------------------------

    def _scan_repo_dispatch(
        self,
        repo: Mapping[str, Any],
        *,
        result: GitHubSpiderResult,
        seen_seed_keys: set[tuple[str, str]],
        seen_repo_names: set[str],
    ) -> None:
        if not isinstance(repo, Mapping):
            return
        repo_full = str(repo.get("full_name") or "").strip()
        if not repo_full or repo_full in seen_repo_names:
            return
        seen_repo_names.add(repo_full)
        result.repos_scanned += 1

        # A. Metadata (homepage/topics/description).
        if self.include_metadata:
            self._extend_seeds(result, seen_seed_keys, self._scan_repo_metadata(repo))

        # B. Key doc files.
        if self.include_key_files:
            self._extend_seeds(
                result,
                seen_seed_keys,
                self._scan_key_files(repo, result=result),
            )

        # C. Config files.
        if self.include_config_files:
            self._extend_seeds(
                result,
                seen_seed_keys,
                self._scan_config_files(repo, result=result),
            )

        # D. Branches.
        if self.include_branches:
            self._extend_seeds(
                result,
                seen_seed_keys,
                self._scan_branches(repo, result=result),
            )

        # E. Commits.
        if self.include_commits:
            self._extend_seeds(
                result,
                seen_seed_keys,
                self._scan_commits(repo, result=result),
            )

        # F. Pull requests.
        if self.include_pull_requests:
            self._extend_seeds(
                result,
                seen_seed_keys,
                self._scan_pull_requests(repo, result=result),
            )

        # G. Environments.
        if self.include_environments:
            self._extend_seeds(
                result,
                seen_seed_keys,
                self._scan_environments(repo, result=result),
            )

        # H. Workflows.
        if self.include_actions:
            self._extend_seeds(
                result,
                seen_seed_keys,
                self._scan_actions(repo, result=result),
            )

        # I. GitHub Pages.
        if self.include_pages:
            self._extend_seeds(
                result,
                seen_seed_keys,
                self._scan_pages(repo, result=result),
            )

    # ------------------------------------------------------------------
    # Enumerators
    # ------------------------------------------------------------------

    def _list_user_orgs(self, result: GitHubSpiderResult) -> list[str]:
        """GET /user/orgs — orgs reachable through the token."""
        url = f"{self.base_url}/user/orgs?per_page=100"
        response = self._call(url, result=result, context="user:orgs")
        if response is None:
            return []
        body = response.get("json")
        if not isinstance(body, list):
            return []
        orgs: list[str] = []
        for entry in body:
            if isinstance(entry, Mapping):
                login = str(entry.get("login") or "").strip()
                if login:
                    orgs.append(login)
        return orgs

    def _list_authenticated_user_repos(
        self, result: GitHubSpiderResult
    ) -> list[dict[str, Any]]:
        """GET /user/repos — paginate all repos accessible to the token."""
        return list(
            self._paginate(
                f"{self.base_url}/user/repos?per_page=100&sort=updated",
                context="user:repos",
                result=result,
                max_items=self.max_repos,
                count_toward_total=True,
            )
        )

    def _list_owner_repos(
        self,
        owner: str,
        *,
        kind: str,
        result: GitHubSpiderResult,
    ) -> list[dict[str, Any]]:
        """Paginate ``/orgs/{owner}/repos`` or ``/users/{owner}/repos``."""
        url = f"{self.base_url}/{kind}/{owner}/repos?per_page=100&sort=updated"
        return list(
            self._paginate(
                url,
                context=f"{kind}/{owner}:repos",
                result=result,
                max_items=self.max_repos,
                count_toward_total=True,
            )
        )

    # ------------------------------------------------------------------
    # Per-repo scanners
    # ------------------------------------------------------------------

    def _scan_repo_metadata(self, repo: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Extract seeds from the repo metadata object."""
        repo_full = str(repo.get("full_name") or "").strip()
        seeds: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        homepage = str(repo.get("homepage") or "").strip()
        if homepage:
            seeds.extend(
                self._merge_seeds(
                    extract_seeds_from_text(
                        homepage, source_label=f"{repo_full}:homepage"
                    ),
                    seen,
                )
            )
        description = str(repo.get("description") or "").strip()
        if description:
            seeds.extend(
                self._merge_seeds(
                    extract_seeds_from_text(
                        description, source_label=f"{repo_full}:description"
                    ),
                    seen,
                )
            )
        topics = repo.get("topics") or []
        if isinstance(topics, (list, tuple)):
            joined = " ".join(str(t) for t in topics if t)
            if joined:
                seeds.extend(
                    self._merge_seeds(
                        extract_seeds_from_text(
                            joined, source_label=f"{repo_full}:topics"
                        ),
                        seen,
                    )
                )
        return seeds

    def _scan_branches(
        self,
        repo: Mapping[str, Any],
        *,
        result: GitHubSpiderResult,
    ) -> list[dict[str, Any]]:
        """GET /repos/{owner}/{repo}/branches."""
        repo_full = str(repo.get("full_name") or "").strip()
        if not repo_full:
            return []
        url = f"{self.base_url}/repos/{repo_full}/branches?per_page=100"
        branches = list(
            self._paginate(
                url,
                context=f"{repo_full}:branches",
                result=result,
                max_items=self.max_branches_per_repo,
            )
        )
        seeds: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for branch in branches:
            if not isinstance(branch, Mapping):
                continue
            name = str(branch.get("name") or "").strip()
            if not name:
                continue
            # Only scan the branch name itself (short string) for cloud
            # references; feature-branch slugs sometimes carry targets.
            seeds.extend(
                self._merge_seeds(
                    extract_seeds_from_text(
                        name, source_label=f"{repo_full}:branch:{name}"
                    ),
                    seen,
                )
            )
        # Remember branch names on the repo object so a later _scan_commits
        # can iterate them.
        repo_dict = dict(repo)
        repo_dict["_scanned_branches"] = [
            str(b.get("name") or "").strip()
            for b in branches
            if isinstance(b, Mapping) and b.get("name")
        ]
        if isinstance(repo, dict):
            repo["_scanned_branches"] = repo_dict["_scanned_branches"]
        return seeds

    def _scan_commits(
        self,
        repo: Mapping[str, Any],
        *,
        result: GitHubSpiderResult,
    ) -> list[dict[str, Any]]:
        """GET /repos/{owner}/{repo}/commits — scan commit messages."""
        repo_full = str(repo.get("full_name") or "").strip()
        if not repo_full:
            return []
        branches = repo.get("_scanned_branches") or [None]
        if not branches:
            branches = [None]
        seeds: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for branch in branches:
            if branch:
                url = (
                    f"{self.base_url}/repos/{repo_full}/commits?per_page=100"
                    f"&sha={branch}"
                )
                label_prefix = f"{repo_full}:commits:{branch}"
            else:
                url = f"{self.base_url}/repos/{repo_full}/commits?per_page=100"
                label_prefix = f"{repo_full}:commits"
            commits = self._fetch_json_list(
                url,
                context=label_prefix,
                result=result,
                max_items=self.max_commits_per_branch,
            )
            for commit in commits:
                if not isinstance(commit, Mapping):
                    continue
                commit_block = commit.get("commit")
                if not isinstance(commit_block, Mapping):
                    continue
                message = str(commit_block.get("message") or "")
                author = commit_block.get("author") or {}
                author_email = (
                    str(author.get("email") or "") if isinstance(author, Mapping) else ""
                )
                combined = f"{message} {author_email}".strip()
                if not combined:
                    continue
                sha = str(commit.get("sha") or "")[:12]
                seeds.extend(
                    self._merge_seeds(
                        extract_seeds_from_text(
                            combined, source_label=f"{label_prefix}:{sha}"
                        ),
                        seen,
                    )
                )
                # Record redacted secret indicator hits.
                result.secret_hits.extend(
                    _normalize_secret_hits(
                        _patterns_scan_secrets(
                            combined, source_label=f"{label_prefix}:{sha}"
                        ),
                        repo=repo_full,
                        source=f"commit:{sha}",
                    )
                )
        return seeds

    def _scan_pull_requests(
        self,
        repo: Mapping[str, Any],
        *,
        result: GitHubSpiderResult,
    ) -> list[dict[str, Any]]:
        """GET /repos/{owner}/{repo}/pulls?state=all."""
        repo_full = str(repo.get("full_name") or "").strip()
        if not repo_full:
            return []
        url = (
            f"{self.base_url}/repos/{repo_full}/pulls?state=all&per_page=100"
            "&sort=updated&direction=desc"
        )
        prs = self._fetch_json_list(
            url,
            context=f"{repo_full}:pulls",
            result=result,
            max_items=self.max_pull_requests_per_repo,
        )
        seeds: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for pr in prs:
            if not isinstance(pr, Mapping):
                continue
            number = pr.get("number") or 0
            title = str(pr.get("title") or "")
            body = str(pr.get("body") or "")
            text = f"{title}\n{body}".strip()
            if not text:
                continue
            seeds.extend(
                self._merge_seeds(
                    extract_seeds_from_text(
                        text, source_label=f"{repo_full}:pr#{number}"
                    ),
                    seen,
                )
            )
            result.secret_hits.extend(
                _normalize_secret_hits(
                    _patterns_scan_secrets(
                        text, source_label=f"{repo_full}:pr#{number}"
                    ),
                    repo=repo_full,
                    source=f"pr#{number}",
                )
            )
        return seeds

    def _scan_environments(
        self,
        repo: Mapping[str, Any],
        *,
        result: GitHubSpiderResult,
    ) -> list[dict[str, Any]]:
        """GET /repos/{owner}/{repo}/environments."""
        repo_full = str(repo.get("full_name") or "").strip()
        if not repo_full:
            return []
        url = f"{self.base_url}/repos/{repo_full}/environments?per_page=100"
        response = self._call(url, result=result, context=f"{repo_full}:environments")
        if response is None:
            return []
        body = response.get("json")
        environments: list[Any] = []
        if isinstance(body, Mapping):
            environments = list(body.get("environments") or [])
        elif isinstance(body, list):
            environments = body
        seeds: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for env in environments:
            if not isinstance(env, Mapping):
                continue
            name = str(env.get("name") or "")
            if not name:
                continue
            # Deployment URL fields vary — try all known shapes.
            text_parts: list[str] = [name]
            html_url = env.get("html_url") or env.get("url") or ""
            if isinstance(html_url, str):
                text_parts.append(html_url)
            deployment_url = env.get("deployment_url")
            if isinstance(deployment_url, str):
                text_parts.append(deployment_url)
            protection_rules = env.get("protection_rules") or []
            if isinstance(protection_rules, list):
                for rule in protection_rules:
                    if isinstance(rule, Mapping):
                        text_parts.append(json.dumps(rule, sort_keys=True))
            combined = " ".join(part for part in text_parts if part)
            seeds.extend(
                self._merge_seeds(
                    extract_seeds_from_text(
                        combined, source_label=f"{repo_full}:env:{name}"
                    ),
                    seen,
                )
            )
        return seeds

    def _scan_actions(
        self,
        repo: Mapping[str, Any],
        *,
        result: GitHubSpiderResult,
    ) -> list[dict[str, Any]]:
        """Enumerate ``.github/workflows/*.yml`` files and scan contents."""
        repo_full = str(repo.get("full_name") or "").strip()
        if not repo_full:
            return []
        url = f"{self.base_url}/repos/{repo_full}/contents/.github/workflows"
        response = self._call(url, result=result, context=f"{repo_full}:workflows_list")
        if response is None:
            return []
        body = response.get("json")
        if not isinstance(body, list):
            return []
        seeds: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        count = 0
        for entry in body:
            if count >= self.max_workflow_files:
                break
            if not isinstance(entry, Mapping):
                continue
            if str(entry.get("type") or "") != "file":
                continue
            path = str(entry.get("path") or entry.get("name") or "")
            if not path.endswith((".yml", ".yaml")):
                continue
            content = self._fetch_file_content(entry, result=result, repo=repo_full)
            if not content:
                continue
            # Workflow files mention secret names as ``${{ secrets.NAME }}``;
            # record those as metadata (names only, never values).
            secret_names = sorted(set(_WORKFLOW_SECRETS_RE.findall(content)))
            if secret_names:
                for secret_name in secret_names:
                    result.secret_hits.append(
                        {
                            "label": "github_actions_secret_name",
                            "repo": repo_full,
                            "source": f"workflow:{path}",
                            "secret_name": secret_name,
                        }
                    )
            seeds.extend(
                self._merge_seeds(
                    extract_seeds_from_text(
                        content, source_label=f"{repo_full}:workflow:{path}"
                    ),
                    seen,
                )
            )
            result.secret_hits.extend(
                _normalize_secret_hits(
                    _patterns_scan_secrets(
                        content, source_label=f"{repo_full}:workflow:{path}"
                    ),
                    repo=repo_full,
                    source=f"workflow:{path}",
                )
            )
            count += 1
        return seeds

    def _scan_key_files(
        self,
        repo: Mapping[str, Any],
        *,
        result: GitHubSpiderResult,
    ) -> list[dict[str, Any]]:
        """Fetch README + docs files and scan them."""
        repo_full = str(repo.get("full_name") or "").strip()
        if not repo_full:
            return []
        seeds: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        count = 0

        # Fetch the preferred README via the dedicated endpoint first.
        readme = self._fetch_readme(repo_full, result)
        if readme:
            seeds.extend(
                self._merge_seeds(
                    extract_seeds_from_text(
                        readme, source_label=f"{repo_full}:readme"
                    ),
                    seen,
                )
            )
            result.secret_hits.extend(
                _normalize_secret_hits(
                    _patterns_scan_secrets(
                        readme, source_label=f"{repo_full}:readme"
                    ),
                    repo=repo_full,
                    source="readme",
                )
            )
            count += 1

        for path in self.key_files:
            if count >= self.max_key_files_per_repo:
                break
            if path.lower().startswith("readme"):
                continue  # already fetched
            content = self._fetch_contents_file(repo_full, path, result=result)
            if not content:
                continue
            seeds.extend(
                self._merge_seeds(
                    extract_seeds_from_text(
                        content, source_label=f"{repo_full}:file:{path}"
                    ),
                    seen,
                )
            )
            result.secret_hits.extend(
                _normalize_secret_hits(
                    _patterns_scan_secrets(
                        content, source_label=f"{repo_full}:file:{path}"
                    ),
                    repo=repo_full,
                    source=f"file:{path}",
                )
            )
            count += 1
        return seeds

    def _scan_config_files(
        self,
        repo: Mapping[str, Any],
        *,
        result: GitHubSpiderResult,
    ) -> list[dict[str, Any]]:
        """Fetch common config files and scan them."""
        repo_full = str(repo.get("full_name") or "").strip()
        if not repo_full:
            return []
        seeds: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        count = 0
        for path in self.config_files:
            if count >= self.max_config_files_per_repo:
                break
            content = self._fetch_contents_file(repo_full, path, result=result)
            if not content:
                continue
            seeds.extend(
                self._merge_seeds(
                    extract_seeds_from_text(
                        content, source_label=f"{repo_full}:config:{path}"
                    ),
                    seen,
                )
            )
            result.secret_hits.extend(
                _normalize_secret_hits(
                    _patterns_scan_secrets(
                        content, source_label=f"{repo_full}:config:{path}"
                    ),
                    repo=repo_full,
                    source=f"config:{path}",
                )
            )
            count += 1
        return seeds

    def _scan_pages(
        self,
        repo: Mapping[str, Any],
        *,
        result: GitHubSpiderResult,
    ) -> list[dict[str, Any]]:
        """GET /repos/{owner}/{repo}/pages — GitHub Pages site URL."""
        repo_full = str(repo.get("full_name") or "").strip()
        if not repo_full:
            return []
        url = f"{self.base_url}/repos/{repo_full}/pages"
        response = self._call(url, result=result, context=f"{repo_full}:pages")
        if response is None:
            return []
        body = response.get("json")
        if not isinstance(body, Mapping):
            return []
        pages_url = str(body.get("html_url") or body.get("url") or "").strip()
        if not pages_url:
            return []
        cname = str(body.get("cname") or "").strip()
        combined = f"{pages_url} {cname}".strip()
        seeds: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        seeds.extend(
            self._merge_seeds(
                extract_seeds_from_text(
                    combined, source_label=f"{repo_full}:pages"
                ),
                seen,
            )
        )
        return seeds

    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------

    def _fetch_readme(
        self, repo_full: str, result: GitHubSpiderResult
    ) -> str:
        """GET /repos/{owner}/{repo}/readme — base64 decoded."""
        url = f"{self.base_url}/repos/{repo_full}/readme"
        response = self._call(url, result=result, context=f"{repo_full}:readme")
        if response is None:
            return ""
        body = response.get("json")
        if not isinstance(body, Mapping):
            return ""
        return _decode_github_file(body, result=result, context=f"{repo_full}:readme")

    def _fetch_contents_file(
        self,
        repo_full: str,
        path: str,
        *,
        result: GitHubSpiderResult,
    ) -> str:
        """GET /repos/{owner}/{repo}/contents/{path}."""
        url = f"{self.base_url}/repos/{repo_full}/contents/{path}"
        response = self._call(
            url, result=result, context=f"{repo_full}:contents:{path}"
        )
        if response is None:
            return ""
        body = response.get("json")
        if isinstance(body, list):
            return ""  # directory, not a file
        if not isinstance(body, Mapping):
            return ""
        return _decode_github_file(
            body, result=result, context=f"{repo_full}:contents:{path}"
        )

    def _fetch_file_content(
        self,
        entry: Mapping[str, Any],
        *,
        result: GitHubSpiderResult,
        repo: str,
    ) -> str:
        """Resolve the file body for a directory listing entry."""
        download_url = str(entry.get("download_url") or "").strip()
        if download_url:
            raw = self._call(
                download_url,
                result=result,
                context=f"{repo}:download:{entry.get('name') or ''}",
            )
            if raw is not None:
                text = raw.get("text")
                if isinstance(text, str) and text:
                    return text
                body = raw.get("json")
                if isinstance(body, str):
                    return body
        # Fall back to the base64-encoded contents endpoint.
        path = str(entry.get("path") or "")
        if path:
            return self._fetch_contents_file(repo, path, result=result)
        return ""

    def _paginate(
        self,
        url: str,
        *,
        context: str,
        result: GitHubSpiderResult,
        max_items: int,
        max_pages: int = 20,
        count_toward_total: bool = False,
    ) -> Iterable[dict[str, Any]]:
        """Yield items across GitHub's paginated endpoints.

        Follows ``Link: <...>; rel="next"`` headers. ``max_items`` and
        ``max_pages`` are bounded to keep large-org scans from running
        wild. When ``count_toward_total`` is True, every item observed
        in the API response increments ``result.repos_total`` (used
        when enumerating repo lists so the operator sees the full
        listing size, not just the slice that fit under ``max_repos``).
        """
        current = url
        page = 0
        yielded = 0
        while current and page < max_pages and yielded < max_items:
            page += 1
            response = self._call(current, result=result, context=context)
            if response is None:
                return
            body = response.get("json")
            if not isinstance(body, list):
                return
            if count_toward_total:
                result.repos_total += len(body)
            for item in body:
                if not isinstance(item, Mapping):
                    continue
                yield dict(item)
                yielded += 1
                if yielded >= max_items:
                    return
            current = _next_page_url(response.get("headers") or {})

    def _fetch_json_list(
        self,
        url: str,
        *,
        context: str,
        result: GitHubSpiderResult,
        max_items: int,
    ) -> list[Mapping[str, Any]]:
        return list(
            self._paginate(
                url,
                context=context,
                result=result,
                max_items=max_items,
            )
        )

    def _call(
        self,
        url: str,
        *,
        result: GitHubSpiderResult,
        context: str,
    ) -> dict[str, Any] | None:
        """Invoke the injected HTTP getter with error containment."""
        result.record_endpoint(url)
        try:
            backoff = request_with_rate_limit_backoff(
                lambda: self._http(url, headers=dict(self.headers)),
                context=context,
                data_dir=self.data_dir,
                on_response=lambda item: _record_response_rate_limit(result, item),
            )
            response = backoff.response
        except Exception as exc:  # noqa: BLE001
            result.source_errors.append(
                {
                    "context": context,
                    "detail": f"{exc.__class__.__name__}: {str(exc)[:200]}",
                }
            )
            return None
        if backoff.events:
            result.rate_limit.setdefault("backoff_events", []).extend(backoff.events)
        if backoff.skipped:
            result.source_errors.append(
                {
                    "context": context,
                    "detail": "rate_limit_request_skipped",
                    "reason": backoff.skip_reason,
                    "status": _response_status(response),
                    "total_wait_seconds": round(backoff.total_wait_seconds, 3),
                }
            )
        if not isinstance(response, Mapping):
            result.source_errors.append(
                {
                    "context": context,
                    "detail": "http_get did not return a mapping",
                }
            )
            return None
        status = _response_status(response)
        if status >= 400:
            result.source_errors.append(
                {
                    "context": context,
                    "detail": f"HTTP {status}",
                }
            )
            return None
        return dict(response)

    # ------------------------------------------------------------------
    # Final cleanup
    # ------------------------------------------------------------------

    def _dedupe_and_classify(self, result: GitHubSpiderResult) -> None:
        """Collapse duplicate seeds and strip deny-listed hosts.

        :mod:`forge.onboard.patterns` already dedupes within a single
        call, but the per-repo loop can emit the same ``example.com``
        from multiple sources. This final pass normalizes everything
        into a single ``(type, value)``-unique list, preserving the
        earliest provenance.
        """
        unique: dict[tuple[str, str], dict[str, Any]] = {}
        for seed in result.seeds:
            key = (
                str(seed.get("target_type") or seed.get("type") or ""),
                str(seed.get("target_value") or seed.get("value") or ""),
            )
            if not key[0] or not key[1]:
                continue
            if is_denied_target(key[1]):
                continue
            unique.setdefault(key, seed)
        result.seeds = list(unique.values())

        # Dedupe secret hits using (label, repo, source[, secret_name]).
        unique_secrets: list[dict[str, Any]] = []
        secret_keys: set[tuple[str, str, str, str]] = set()
        for secret in result.secret_hits:
            label = str(secret.get("label") or "")
            repo = str(secret.get("repo") or "")
            source = str(secret.get("source") or "")
            extra = str(
                secret.get("secret_name")
                or secret.get("redacted_sample")
                or secret.get("offset")
                or ""
            )
            key = (label, repo, source, extra)
            if key in secret_keys:
                continue
            secret_keys.add(key)
            unique_secrets.append(secret)
        result.secret_hits = unique_secrets

    # ------------------------------------------------------------------
    # Little helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_slug(value: str) -> str:
        return str(value or "").strip().lstrip("/@").split("/", 1)[0]

    @staticmethod
    def _extend_seeds(
        result: GitHubSpiderResult,
        seen: set[tuple[str, str]],
        new_seeds: Sequence[Mapping[str, Any]],
    ) -> None:
        for seed in new_seeds:
            key = (
                str(seed.get("target_type") or ""),
                str(seed.get("target_value") or ""),
            )
            if not key[0] or not key[1] or key in seen:
                continue
            seen.add(key)
            result.seeds.append(dict(seed))

    @staticmethod
    def _merge_seeds(
        new_seeds: Sequence[Mapping[str, Any]],
        seen: set[tuple[str, str]],
    ) -> list[dict[str, Any]]:
        """Return new_seeds that aren't yet in the per-repo ``seen`` set."""
        out: list[dict[str, Any]] = []
        for seed in new_seeds:
            key = (
                str(seed.get("target_type") or ""),
                str(seed.get("target_value") or ""),
            )
            if not key[0] or not key[1] or key in seen:
                continue
            seen.add(key)
            out.append(dict(seed))
        return out


# ----------------------------------------------------------------------
# Module-level helpers
# ----------------------------------------------------------------------


_WORKFLOW_SECRETS_RE = re.compile(r"\${{\s*secrets\.([A-Z0-9_]+)\s*}}", re.IGNORECASE)
_LINK_HEADER_NEXT_RE = re.compile(r"<([^>]+)>;\s*rel=\"next\"", re.IGNORECASE)


def _next_page_url(headers: Mapping[str, Any]) -> str | None:
    """Extract the ``Link: <...>; rel="next"`` URL from a header map."""
    link = ""
    for key, value in headers.items():
        if str(key).lower() == "link":
            link = str(value or "")
            break
    if not link:
        return None
    match = _LINK_HEADER_NEXT_RE.search(link)
    if not match:
        return None
    return match.group(1)


def _record_rate_limit(result: GitHubSpiderResult, headers: Mapping[str, Any]) -> None:
    for key, value in headers.items():
        header = str(key)
        if header.lower() == "x-ratelimit-remaining":
            result.rate_limit["remaining"] = value
        elif header.lower() == "x-ratelimit-reset":
            result.rate_limit["reset"] = value
        elif header.lower() == "x-ratelimit-used":
            result.rate_limit["used"] = value


def _record_response_rate_limit(
    result: GitHubSpiderResult, response: Mapping[str, Any]
) -> None:
    headers = response.get("headers") or {}
    if isinstance(headers, Mapping):
        _record_rate_limit(result, headers)


def _response_status(response: object) -> int:
    if not isinstance(response, Mapping):
        return 0
    try:
        return int(response.get("status", 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def _decode_github_file(
    body: Mapping[str, Any],
    *,
    result: GitHubSpiderResult,
    context: str,
) -> str:
    encoding = str(body.get("encoding") or "").lower()
    content = body.get("content") or ""
    if not isinstance(content, str):
        return ""
    if encoding == "base64":
        try:
            # Strip whitespace/newlines inserted by GitHub.
            cleaned = re.sub(r"\s+", "", content)
            return base64.b64decode(cleaned).decode("utf-8", errors="replace")
        except (ValueError, binascii.Error) as exc:
            result.source_errors.append(
                {
                    "context": f"{context}:decode",
                    "detail": f"base64 decode failed: {exc.__class__.__name__}",
                }
            )
            return ""
    return content


def _normalize_secret_hits(
    hits: Iterable[Mapping[str, Any]],
    *,
    repo: str,
    source: str,
) -> list[dict[str, Any]]:
    """Normalize :func:`forge.onboard.patterns.scan_secrets` output.

    Attaches ``repo`` + ``source`` so downstream consumers always see
    where the hit came from.
    """
    out: list[dict[str, Any]] = []
    for hit in hits:
        payload = dict(hit)
        payload["repo"] = repo
        payload.setdefault("source", source)
        out.append(payload)
    return out


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
    return binascii.Error


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "GITHUB_DEEP_SCANNER_SCHEMA_VERSION",
    "GITHUB_SPIDER_SCHEMA_VERSION",
    "GitHubDeepScanner",
    "GitHubSpiderError",
    "GitHubSpiderResult",
    "extract_seeds_from_text",
    "parse_github_repo_payload",
    "spider_github",
]
