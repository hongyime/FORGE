from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit

import httpx

from forge.db.session import get_engagement_db
from forge.governance.scope_gate import EngagementScope, ScopeGate
from forge.opsec.scope_gate import ScopeViolationError, assert_in_scope, load_scope_from_db


@dataclass(frozen=True)
class CrawlResult:
    engagement_id: int
    url: str
    final_url: str
    title: str
    screenshot_path: str | None
    tech_stack_json: str


def _float_env(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = float(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = int(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _crawl_request_delay_seconds() -> float:
    return _float_env(
        "FORGE_WEB_FETCH_REQUEST_DELAY_SECONDS",
        0.0,
        minimum=0.0,
        maximum=60.0,
    )


def _crawl_rate_limit_backoff_seconds() -> float:
    return _float_env(
        "FORGE_WEB_FETCH_RATE_LIMIT_BACKOFF_SECONDS",
        5.0,
        minimum=0.0,
        maximum=300.0,
    )


def _crawl_rate_limit_retries() -> int:
    return _int_env(
        "FORGE_WEB_FETCH_RATE_LIMIT_RETRIES",
        1,
        minimum=0,
        maximum=5,
    )


def _retry_after_seconds(headers: httpx.Headers | dict[str, str]) -> float | None:
    raw_value = ""
    try:
        raw_value = str(headers.get("retry-after") or headers.get("Retry-After") or "").strip()
    except AttributeError:
        return None
    if not raw_value:
        return None
    try:
        seconds = float(raw_value)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(raw_value)
        except (TypeError, ValueError):
            return None
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=timezone.utc)
        seconds = (retry_at - datetime.now(timezone.utc)).total_seconds()
    return max(0.0, min(300.0, seconds))


class _HrefCollector(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self._base_url = base_url
        self.links: list[str] = []

    def handle_starttag(self, _tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name.lower() != "href":
                continue
            raw = str(value or "").strip()
            if not raw or raw.startswith("#") or raw.lower().startswith("javascript:"):
                continue
            self.links.append(urljoin(self._base_url, raw))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)


def _extract_links(base_url: str, html: str) -> list[str]:
    collector = _HrefCollector(base_url)
    collector.feed(html)
    return collector.links


def _canonical_crawl_url(value: str) -> str | None:
    try:
        parsed = urlsplit(str(value or "").strip())
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return None
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = f"{host_part}:{port}" if port is not None and not default_port else host_part
    path = parsed.path or "/"
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def _extract_title(html: str) -> str:
    lower = html.lower()
    start = lower.find("<title>")
    if start == -1:
        return ""
    end = lower.find("</title>", start)
    if end == -1:
        return ""
    return html[start + 7 : end].strip()


def _detect_stack(headers: httpx.Headers, html: str) -> dict[str, str]:
    stack: dict[str, str] = {}
    powered_by = headers.get("x-powered-by")
    server = headers.get("server")
    if powered_by:
        stack["powered_by"] = powered_by
    if server:
        stack["server"] = server
    markers = {
        "react": "react",
        "vue": "vue",
        "angular": "angular",
        "next": "__next",
        "nuxt": "__nuxt",
        "svelte": "svelte",
    }
    haystack = html.lower()
    for name, token in markers.items():
        if token in haystack:
            stack[name] = "detected"
    return stack


async def _crawl_http(
    seed_url: str,
    depth: int,
    timeout: float,
    request_delay: float | None = None,
    scope_filter: Callable[[str], bool] | None = None,
) -> list[tuple[str, str, dict[str, str]]]:
    seed_canonical = _canonical_crawl_url(seed_url)
    if seed_canonical is None:
        return []
    seed_host = urlsplit(seed_canonical).netloc
    queued: set[str] = {seed_canonical}
    processed: set[str] = set()
    queue: list[tuple[str, int]] = [(seed_canonical, 0)]
    output: list[tuple[str, str, dict[str, str]]] = []
    delay_seconds = _crawl_request_delay_seconds() if request_delay is None else max(0.0, request_delay)
    rate_limit_retries = _crawl_rate_limit_retries()
    fallback_backoff = _crawl_rate_limit_backoff_seconds()
    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
        while queue:
            current_url, current_depth = queue.pop(0)
            if current_url in processed:
                continue
            if scope_filter is not None and not scope_filter(current_url):
                processed.add(current_url)
                continue
            processed.add(current_url)
            resp = None
            for attempt in range(rate_limit_retries + 1):
                try:
                    if delay_seconds > 0:
                        await asyncio.sleep(delay_seconds)
                    resp = await client.get(current_url)
                except Exception:
                    resp = None
                    break
                status_code = int(getattr(resp, "status_code", 0) or 0)
                if status_code not in {429, 503}:
                    break
                if attempt >= rate_limit_retries:
                    resp = None
                    break
                retry_delay = _retry_after_seconds(getattr(resp, "headers", {})) or fallback_backoff
                if retry_delay > 0:
                    await asyncio.sleep(retry_delay)
            if resp is None:
                continue
            status_code = int(getattr(resp, "status_code", 0) or 0)
            if 300 <= status_code < 400:
                location = str(getattr(resp, "headers", {}).get("location", "") or "").strip()
                redirect_url = _canonical_crawl_url(urljoin(current_url, location)) if location else None
                if redirect_url is None:
                    continue
                if urlsplit(redirect_url).netloc != seed_host:
                    queued.add(redirect_url)
                    continue
                if scope_filter is not None and not scope_filter(redirect_url):
                    queued.add(redirect_url)
                    continue
                if redirect_url not in queued and redirect_url not in processed:
                    queued.add(redirect_url)
                    queue.append((redirect_url, current_depth))
                continue
            final_url = _canonical_crawl_url(str(resp.url))
            if final_url is None:
                continue
            if scope_filter is not None and not scope_filter(final_url):
                queued.add(final_url)
                continue
            if final_url != current_url:
                queued.add(final_url)
                if final_url in processed:
                    continue
                processed.add(final_url)
            body = resp.text
            output.append((final_url, body, _detect_stack(resp.headers, body)))
            if current_depth >= depth:
                continue
            for raw_link in _extract_links(final_url, body):
                link = _canonical_crawl_url(raw_link)
                if link is None:
                    continue
                if urlsplit(link).netloc != seed_host:
                    continue
                if scope_filter is not None and not scope_filter(link):
                    continue
                if link not in queued and link not in processed:
                    queued.add(link)
                    queue.append((link, current_depth + 1))
    return output


def _scope_filter_from_values(
    *,
    scope_values: Sequence[str] | None,
    url_prefixes: Sequence[str] | None,
) -> Callable[[str], bool] | None:
    domains: list[str] = []
    ip_ranges: list[str] = []
    prefixes = [str(value) for value in url_prefixes or [] if str(value or "").strip()]
    for value in scope_values or []:
        text = str(value or "").strip()
        if not text:
            continue
        if text.startswith(("http://", "https://")):
            prefixes.append(text)
            host = urlparse(text).hostname
            if host:
                domains.append(host)
        elif "/" in text:
            ip_ranges.append(text)
        else:
            domains.append(text)
    domains = list(dict.fromkeys(domains))
    ip_ranges = list(dict.fromkeys(ip_ranges))
    prefixes = list(dict.fromkeys(prefixes))
    if not domains and not ip_ranges and not prefixes:
        return None
    gate = ScopeGate(EngagementScope(domains=domains, ip_ranges=ip_ranges, urls=prefixes))
    return gate.is_in_scope


def _assert_crawl_target_in_scope(
    *,
    engagement_id: int,
    target_url: str,
    db_path: Path,
    scope_values: Sequence[str] | None = None,
    url_prefixes: Sequence[str] | None = None,
    require_scope: bool = False,
) -> Callable[[str], bool] | None:
    scope = (
        [str(item) for item in scope_values if str(item or "").strip()]
        if scope_values is not None
        else load_scope_from_db(str(db_path), engagement_id)
    )
    prefixes = [str(item) for item in url_prefixes or [] if str(item or "").strip()]
    if require_scope and not scope and not prefixes:
        raise ScopeViolationError(target_url, [])
    scope_filter = _scope_filter_from_values(scope_values=scope, url_prefixes=prefixes)
    if scope_filter is not None:
        if not scope_filter(target_url):
            raise ScopeViolationError(target_url, list(scope) + prefixes)
        return scope_filter
    assert_in_scope(target_url, scope)
    return None


async def crawl_target(
    engagement_id: int,
    target_url: str,
    db_path: Path,
    depth: int = 2,
    timeout: float = 15.0,
    screenshot: bool = False,
    screenshot_dir: Path | None = None,
    request_delay: float | None = None,
    scope_values: Sequence[str] | None = None,
    url_prefixes: Sequence[str] | None = None,
    require_scope: bool = False,
) -> list[CrawlResult]:
    snapshots: dict[str, str] = {}
    scope_filter = _assert_crawl_target_in_scope(
        engagement_id=engagement_id,
        target_url=target_url,
        db_path=db_path,
        scope_values=scope_values,
        url_prefixes=url_prefixes,
        require_scope=require_scope,
    )
    delay_seconds = _crawl_request_delay_seconds() if request_delay is None else max(0.0, request_delay)
    if screenshot and screenshot_dir is not None:
        screenshot_dir.mkdir(parents=True, exist_ok=True)
        try:
            from playwright.async_api import async_playwright
        except Exception:
            async_playwright = None  # type: ignore[assignment]
        if async_playwright is not None:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                try:
                    if scope_filter is not None:
                        async def _guard_route(route: object) -> None:
                            request = getattr(route, "request", None)
                            request_url = str(getattr(request, "url", "") or "")
                            parsed = urlparse(request_url)
                            if parsed.scheme in {"http", "https"} and not scope_filter(request_url):
                                await route.abort()
                                return
                            await route.continue_()

                        await page.route("**/*", _guard_route)
                    if delay_seconds > 0:
                        await asyncio.sleep(delay_seconds)
                    response = await page.goto(target_url, timeout=int(timeout * 1000))
                    browser_final_url = str(
                        getattr(page, "url", "")
                        or getattr(response, "url", "")
                        or target_url
                    )
                    if scope_filter is None or scope_filter(browser_final_url):
                        file_name = "root.png"
                        output_path = screenshot_dir / file_name
                        await page.screenshot(path=str(output_path), full_page=True)
                        snapshots[target_url] = str(output_path)
                finally:
                    await browser.close()
    crawled = await _crawl_http(
        target_url,
        depth=depth,
        timeout=timeout,
        request_delay=delay_seconds,
        scope_filter=scope_filter,
    )
    results: list[CrawlResult] = []
    for final_url, body, stack in crawled:
        results.append(
            CrawlResult(
                engagement_id=engagement_id,
                url=target_url,
                final_url=final_url,
                title=_extract_title(body),
                screenshot_path=snapshots.get(final_url) or snapshots.get(target_url),
                tech_stack_json=json.dumps(stack, ensure_ascii=False),
            )
        )
    con = get_engagement_db(db_path)
    try:
        for row in results:
            con.execute(
                """
                INSERT INTO crawl_results (
                    engagement_id, url, final_url, title, screenshot_path, tech_stack_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    row.engagement_id,
                    row.url,
                    row.final_url,
                    row.title,
                    row.screenshot_path,
                    row.tech_stack_json,
                ),
            )
        con.commit()
    finally:
        con.close()
    return results


def crawl_target_sync(
    engagement_id: int,
    target_url: str,
    db_path: Path,
    depth: int = 2,
    timeout: float = 15.0,
    screenshot: bool = False,
    screenshot_dir: Path | None = None,
    request_delay: float | None = None,
    scope_values: Sequence[str] | None = None,
    url_prefixes: Sequence[str] | None = None,
    require_scope: bool = False,
) -> list[CrawlResult]:
    return asyncio.run(
        crawl_target(
            engagement_id=engagement_id,
            target_url=target_url,
            db_path=db_path,
            depth=depth,
            timeout=timeout,
            screenshot=screenshot,
            screenshot_dir=screenshot_dir,
            request_delay=request_delay,
            scope_values=scope_values,
            url_prefixes=url_prefixes,
            require_scope=require_scope,
        )
    )
