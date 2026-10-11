"""Tests for :mod:`forge.feeds` free-feed fetchers.

Each test monkeypatches the HTTP transport (via ``_http_get_bytes`` /
``_http_get_json``) so no network calls happen. The orchestrator test
asserts that a single-source failure never aborts the aggregate run.
"""

from __future__ import annotations

import gzip
import io
import json
import subprocess  # noqa: S404 — test monkeypatches run()
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

import httpx
import pytest
from typer.testing import CliRunner

from forge.feeds import (
    CisaKevFetcher,
    EpssFetcher,
    FeedFetcher,
    NucleiTemplateFetcher,
    NvdCveFetcher,
    SecurityRssFetcher,
    UrlscanPublicFetcher,
    fetch_all_free_feeds,
)
from forge.feeds import nuclei_templates as nuclei_mod
from forge.feeds.base import BaseFeedFetcher


# ----------------------------------------------------------------------
# Shared helpers
# ----------------------------------------------------------------------


class _FakeResponse:
    """Minimal duck-typed ``httpx.Response`` substitute."""

    def __init__(
        self,
        *,
        status_code: int = 200,
        content: bytes = b"",
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.content = content
        self.headers = dict(headers or {})


class _FakeClient:
    """Context-manager-safe fake httpx.Client that returns a canned response."""

    def __init__(self, *, response: _FakeResponse | None = None, raises: BaseException | None = None, **_kwargs: Any) -> None:
        self._response = response or _FakeResponse()
        self._raises = raises
        self.calls: list[dict[str, Any]] = []

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *_exc: Any) -> None:
        return None

    def get(self, url: str, params: Mapping[str, Any] | None = None, **kwargs: Any) -> _FakeResponse:
        self.calls.append({"url": url, "params": dict(params or {}), "kwargs": dict(kwargs)})
        if self._raises is not None:
            raise self._raises
        return self._response


def _no_sleep(_seconds: float) -> None:  # pragma: no cover — called by fetchers
    return None


def _make_factory(response: _FakeResponse) -> Any:
    """Return a factory that always yields a _FakeClient with ``response``."""

    def _factory(**_kwargs: Any) -> _FakeClient:
        return _FakeClient(response=response)

    return _factory


# ----------------------------------------------------------------------
# NVD CVE fetcher
# ----------------------------------------------------------------------


def _nvd_payload() -> dict[str, Any]:
    return {
        "totalResults": 2,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-9999",
                    "published": "2026-10-05T00:00:00.000",
                    "lastModified": "2026-10-05T00:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "Example buffer overflow."}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                }
                            }
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {"criteria": "cpe:2.3:a:example:app:1.0:*:*:*:*:*:*:*"}
                                    ]
                                }
                            ]
                        }
                    ],
                    "references": [
                        {"url": "https://example.com/advisory/9999"},
                        {"url": "https://example.com/patch"},
                    ],
                }
            },
            {
                "cve": {
                    "id": "CVE-2026-9998",
                    "published": "2026-10-04T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Minor issue."}],
                    "metrics": {},
                    "references": [],
                }
            },
            {
                # Row with no CVE id must be skipped, not raise.
                "cve": {"id": "", "descriptions": []}
            },
        ],
    }


def test_nvd_cve_fetch_parses_and_writes(tmp_path: Path) -> None:
    response = _FakeResponse(content=json.dumps(_nvd_payload()).encode())
    fetcher = NvdCveFetcher(
        tmp_path,
        max_age_days=7,
        sleep_fn=_no_sleep,
        http_client_factory=_make_factory(response),
    )

    result = fetcher.fetch(timeout=30)

    assert result["status"] == "ok"
    assert result["source_id"] == "nvd_cve"
    assert result["count"] == 2
    out_path = tmp_path / "nvd-cve-feed.local.json"
    assert out_path.is_file()
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["_meta"]["source_id"] == "nvd_cve"
    assert payload["_meta"]["item_count"] == 2
    assert payload["items"][0]["cve_id"] == "CVE-2026-9999"
    assert payload["items"][0]["cvss"]["base_score"] == 9.8
    assert payload["items"][0]["cvss"]["severity"] == "CRITICAL"
    assert "https://example.com/advisory/9999" in payload["urls"]
    assert "https://example.com/patch" in payload["urls"]
    assert "cpe:2.3:a:example:app:1.0:*:*:*:*:*:*:*" in payload["items"][0]["cpes"]


def test_nvd_cve_handles_http_error(tmp_path: Path) -> None:
    response = _FakeResponse(status_code=500, content=b"server error")
    fetcher = NvdCveFetcher(
        tmp_path,
        sleep_fn=_no_sleep,
        http_client_factory=_make_factory(response),
    )
    result = fetcher.fetch(timeout=5)
    assert result["status"] == "error"
    assert "http_500" in result["error"]
    assert not (tmp_path / "nvd-cve-feed.local.json").exists()


def test_nvd_cve_handles_network_failure(tmp_path: Path) -> None:
    def _factory(**_kwargs: Any) -> _FakeClient:
        return _FakeClient(raises=httpx.ConnectError("dns failure"))

    fetcher = NvdCveFetcher(
        tmp_path,
        sleep_fn=_no_sleep,
        http_client_factory=_factory,
    )
    result = fetcher.fetch(timeout=5)
    assert result["status"] == "error"
    assert "dns failure" in result["error"]


def test_nvd_cve_rejects_non_object_response(tmp_path: Path) -> None:
    response = _FakeResponse(content=b"[]")
    fetcher = NvdCveFetcher(
        tmp_path,
        sleep_fn=_no_sleep,
        http_client_factory=_make_factory(response),
    )
    result = fetcher.fetch(timeout=5)
    assert result["status"] == "error"
    assert "nvd_response_not_object" in result["error"]


def test_nvd_cve_rate_limit_sleep_invoked(tmp_path: Path) -> None:
    """The pre-fetch sleep MUST be called with the configured rate limit."""
    recorded: list[float] = []
    response = _FakeResponse(content=json.dumps(_nvd_payload()).encode())
    fetcher = NvdCveFetcher(
        tmp_path,
        sleep_fn=recorded.append,
        http_client_factory=_make_factory(response),
    )
    fetcher.fetch(timeout=5)
    assert recorded == [6.0]


# ----------------------------------------------------------------------
# CISA KEV fetcher
# ----------------------------------------------------------------------


def _kev_payload() -> dict[str, Any]:
    return {
        "title": "Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2026.10.11",
        "dateReleased": "2026-10-11T00:00:00Z",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-1234",
                "vendorProject": "Acme",
                "product": "Widget",
                "vulnerabilityName": "Acme Widget RCE",
                "dateAdded": "2024-05-01",
                "shortDescription": "A remote code execution flaw.",
                "requiredAction": "Apply vendor patch.",
                "dueDate": "2024-05-22",
                "knownRansomwareCampaignUse": "Known",
                "cwes": ["CWE-78"],
            },
            {
                # Missing cveID must be skipped.
                "vendorProject": "Nope",
            },
            {
                "cveID": "CVE-2025-1111",
                "vendorProject": "Globex",
                "product": "Thing",
                "vulnerabilityName": "Globex Thing path traversal",
                "dateAdded": "2025-03-01",
                "shortDescription": "Path traversal.",
                "requiredAction": "Patch.",
                "dueDate": "2025-03-22",
                "knownRansomwareCampaignUse": "Unknown",
            },
        ],
    }


def test_cisa_kev_fetch_parses_payload(tmp_path: Path) -> None:
    response = _FakeResponse(content=json.dumps(_kev_payload()).encode())
    fetcher = CisaKevFetcher(
        tmp_path,
        sleep_fn=_no_sleep,
        http_client_factory=_make_factory(response),
    )
    result = fetcher.fetch(timeout=5)
    assert result["status"] == "ok"
    assert result["count"] == 2
    payload = json.loads((tmp_path / "cisa-kev-feed.local.json").read_text())
    assert payload["_meta"]["catalog_version"] == "2026.10.11"
    assert payload["cve_ids"] == ["CVE-2024-1234", "CVE-2025-1111"]
    assert payload["items"][0]["cwes"] == ["CWE-78"]
    assert payload["items"][0]["known_ransomware_use"] == "Known"


def test_cisa_kev_handles_malformed_json(tmp_path: Path) -> None:
    response = _FakeResponse(content=b"not json")
    fetcher = CisaKevFetcher(
        tmp_path,
        sleep_fn=_no_sleep,
        http_client_factory=_make_factory(response),
    )
    result = fetcher.fetch(timeout=5)
    assert result["status"] == "error"
    assert "invalid_json" in result["error"]


# ----------------------------------------------------------------------
# EPSS fetcher
# ----------------------------------------------------------------------


def _build_epss_gzip() -> bytes:
    csv_text = (
        "#model_version:v2024.03.01,score_date:2026-10-11T00:00:00+0000\n"
        "cve,epss,percentile\n"
        "CVE-2024-1234,0.95,0.99\n"
        "CVE-2024-5678,0.05,0.40\n"
        "garbage,0.1,0.2\n"
        "CVE-2024-9999,,0.5\n"
    )
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb") as handle:
        handle.write(csv_text.encode("utf-8"))
    return buffer.getvalue()


def test_epss_fetch_parses_scores(tmp_path: Path) -> None:
    response = _FakeResponse(content=_build_epss_gzip())
    fetcher = EpssFetcher(
        tmp_path,
        high_risk_threshold=0.5,
        sleep_fn=_no_sleep,
        http_client_factory=_make_factory(response),
    )
    result = fetcher.fetch(timeout=5)
    assert result["status"] == "ok"
    assert result["count"] == 2  # garbage row + missing-score row skipped
    payload = json.loads((tmp_path / "epss-scores.local.json").read_text())
    assert payload["items"][0]["cve_id"] == "CVE-2024-1234"
    assert payload["items"][0]["epss"] == 0.95
    assert payload["high_risk"] == ["CVE-2024-1234"]
    assert payload["_meta"]["high_risk_threshold"] == 0.5
    assert payload["_meta"]["model_date"] == "2026-10-11T00:00:00+0000"


def test_epss_handles_bad_gzip(tmp_path: Path) -> None:
    response = _FakeResponse(content=b"not-gzip")
    fetcher = EpssFetcher(
        tmp_path,
        sleep_fn=_no_sleep,
        http_client_factory=_make_factory(response),
    )
    result = fetcher.fetch(timeout=5)
    assert result["status"] == "error"
    assert "gzip_decompress_failed" in result["error"]


# ----------------------------------------------------------------------
# Security RSS aggregator
# ----------------------------------------------------------------------


_SAMPLE_RSS = b"""<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Sample</title>
    <item>
      <title>CVE-2024-1234 in Acme Widget</title>
      <link>https://example.com/post/1</link>
      <description>See https://example.com/advisory for details. Affects acme.io.</description>
      <pubDate>Mon, 11 Oct 2026 00:00:00 +0000</pubDate>
      <guid>abc</guid>
    </item>
    <item>
      <title>Unrelated advisory</title>
      <link>https://example.com/post/2</link>
      <description>no cves here</description>
      <guid>def</guid>
    </item>
  </channel>
</rss>
"""

_SAMPLE_ATOM = b"""<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Atom feed</title>
  <entry>
    <title>GHSA-xxxx-yyyy-zzzz CVE-2025-1111</title>
    <link href="https://github.com/advisories/GHSA-xxxx"/>
    <summary>Patch available. Affects pkg at https://pkg.example.</summary>
    <updated>2026-10-10T00:00:00Z</updated>
    <id>ghsa-xxxx</id>
  </entry>
</feed>
"""


def test_security_rss_aggregates_multiple_sources(tmp_path: Path) -> None:
    rss_source = SimpleNamespace(key="rss", url="https://example.com/rss")
    atom_source = SimpleNamespace(key="atom", url="https://example.com/atom")
    broken_source = SimpleNamespace(key="broken", url="https://broken.example")

    responses = {
        rss_source.url: _FakeResponse(content=_SAMPLE_RSS),
        atom_source.url: _FakeResponse(content=_SAMPLE_ATOM),
        broken_source.url: _FakeResponse(status_code=503, content=b""),
    }

    class _MultiFactory:
        def __call__(self, **_kwargs: Any) -> "_MultiClient":
            return _MultiClient(responses)

    class _MultiClient:
        def __init__(self, mapping: dict[str, _FakeResponse]) -> None:
            self._mapping = mapping

        def __enter__(self) -> "_MultiClient":
            return self

        def __exit__(self, *_exc: Any) -> None:
            return None

        def get(self, url: str, params: Mapping[str, Any] | None = None, **_kwargs: Any) -> _FakeResponse:
            return self._mapping[url]

    fetcher = SecurityRssFetcher(
        tmp_path,
        sources=(rss_source, atom_source, broken_source),
        inter_source_delay_seconds=0.0,
        sleep_fn=_no_sleep,
        http_client_factory=_MultiFactory(),
    )
    result = fetcher.fetch(timeout=5)
    assert result["status"] == "ok"
    assert result["count"] == 3

    payload = json.loads((tmp_path / "security-rss-feed.local.json").read_text())
    source_rows = {row["source"]: row for row in payload["sources"]}
    assert source_rows["rss"]["status"] == "ok"
    assert source_rows["atom"]["status"] == "ok"
    assert source_rows["broken"]["status"] == "error"
    assert any(entry["cves"] == ["CVE-2024-1234"] for entry in payload["items"])
    assert any(entry.get("cves") == ["CVE-2025-1111"] for entry in payload["items"])
    # URL extraction picked up at least the two advisory URLs.
    assert "https://example.com/advisory" in payload["urls"]
    assert "https://pkg.example" in payload["urls"]
    # Domain extraction normalized to lowercase.
    assert "acme.io" in payload["domains"]


def test_security_rss_malformed_xml_is_handled(tmp_path: Path) -> None:
    bad_source = SimpleNamespace(key="bad", url="https://bad.example")
    response = _FakeResponse(content=b"<rss>unterminated")
    fetcher = SecurityRssFetcher(
        tmp_path,
        sources=(bad_source,),
        inter_source_delay_seconds=0.0,
        sleep_fn=_no_sleep,
        http_client_factory=_make_factory(response),
    )
    result = fetcher.fetch(timeout=5)
    # Even with every source failing, the aggregator still writes a
    # payload — the overall fetcher status is OK because the ``_meta``
    # block was persisted; errors live in the per-source list.
    payload = json.loads((tmp_path / "security-rss-feed.local.json").read_text())
    assert payload["sources"][0]["status"] == "error"
    assert "xml_parse_error" in payload["sources"][0]["error"]
    assert result["status"] == "ok"


# ----------------------------------------------------------------------
# Nuclei templates fetcher
# ----------------------------------------------------------------------


def _write_template(path: Path, body: str, mtime: float | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    if mtime is not None:
        import os

        os.utime(path, (mtime, mtime))


def test_nuclei_templates_parses_recent_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data_dir = tmp_path / "data"
    imports_dir = tmp_path / "imports"
    repo_dir = data_dir / "nuclei-templates"
    (repo_dir / ".git").mkdir(parents=True)

    # Recent template with CVE in id and tags
    _write_template(
        repo_dir / "cves" / "2024" / "CVE-2024-1234.yaml",
        """id: CVE-2024-1234
info:
  name: Acme Widget RCE
  severity: critical
  tags: cve,rce,acme
  reference:
    - https://example.com/advisory
""",
    )
    # Stale template; mtime far in the past so it's filtered out.
    _write_template(
        repo_dir / "exposures" / "panel.yaml",
        "id: panel-exposure\ninfo:\n  severity: low\n  tags: panel\n",
        mtime=0.0,
    )

    monkeypatch.setattr(nuclei_mod, "_which_git", lambda: "git")

    def _fake_run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(nuclei_mod.subprocess, "run", _fake_run)

    fetcher = NucleiTemplateFetcher(
        data_dir,
        imports_dir=imports_dir,
        max_age_days=30,
        sleep_fn=_no_sleep,
    )
    result = fetcher.fetch(timeout=10)
    assert result["status"] == "ok"
    assert result["count"] == 1
    payload = json.loads((imports_dir / "nuclei-templates-update.local.json").read_text())
    assert payload["items"][0]["template_id"] == "CVE-2024-1234"
    assert payload["items"][0]["severity"] == "critical"
    assert "cve" in payload["items"][0]["tags"]
    assert payload["cve_ids"] == ["CVE-2024-1234"]
    assert payload["_meta"]["repo_action"] == "pulled"


def test_nuclei_templates_errors_when_git_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(nuclei_mod, "_which_git", lambda: None)
    fetcher = NucleiTemplateFetcher(
        tmp_path / "data",
        imports_dir=tmp_path / "imports",
        sleep_fn=_no_sleep,
    )
    result = fetcher.fetch(timeout=5)
    assert result["status"] == "error"
    assert "git_not_found_on_path" in result["error"]


def test_nuclei_templates_errors_on_pull_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data_dir = tmp_path / "data"
    imports_dir = tmp_path / "imports"
    (data_dir / "nuclei-templates" / ".git").mkdir(parents=True)

    monkeypatch.setattr(nuclei_mod, "_which_git", lambda: "git")

    def _raise(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.CalledProcessError(1, argv, b"", b"non-fast-forward")

    monkeypatch.setattr(nuclei_mod.subprocess, "run", _raise)

    fetcher = NucleiTemplateFetcher(
        data_dir,
        imports_dir=imports_dir,
        sleep_fn=_no_sleep,
    )
    result = fetcher.fetch(timeout=5)
    assert result["status"] == "error"
    assert "git_pull_failed" in result["error"]


# ----------------------------------------------------------------------
# urlscan.io public fetcher
# ----------------------------------------------------------------------


def _urlscan_payload() -> dict[str, Any]:
    return {
        "has_more": False,
        "total": 2,
        "results": [
            {
                "_id": "scan-1",
                "page": {
                    "url": "https://login.phish.example/update",
                    "domain": "login.phish.example",
                    "ip": "203.0.113.5",
                    "asn": "AS65000",
                    "asnname": "EXAMPLE-ASN",
                    "server": "nginx",
                    "tlsVersion": "TLS 1.3",
                    "tlsIssuer": "Let's Encrypt",
                    "country": "US",
                },
                "task": {
                    "time": "2026-10-10T22:00:00Z",
                    "url": "https://login.phish.example/update",
                    "tags": ["phishing", "credential-theft"],
                },
                "stats": {"totalRequests": 42, "uniqIPs": 3},
                "result": "https://urlscan.io/result/scan-1/",
            },
            {
                "_id": "scan-2",
                "page": {
                    "url": "https://benign.example/",
                    "domain": "benign.example",
                    "ip": "198.51.100.9",
                    "asn": "AS65001",
                },
                "task": {
                    "time": "2026-10-10T20:00:00Z",
                    "tags": ["generic"],
                },
                "stats": {"totalRequests": 10, "uniqIPs": 1},
            },
        ],
    }


def test_urlscan_public_fetch_parses_results(tmp_path: Path) -> None:
    response = _FakeResponse(content=json.dumps(_urlscan_payload()).encode())
    fetcher = UrlscanPublicFetcher(
        tmp_path,
        sleep_fn=_no_sleep,
        http_client_factory=_make_factory(response),
    )
    result = fetcher.fetch(timeout=5)
    assert result["status"] == "ok"
    assert result["count"] == 2
    payload = json.loads((tmp_path / "urlscan-public-feed.local.json").read_text())
    assert payload["_meta"]["flagged_count"] == 1
    assert payload["flagged"][0]["domain"] == "login.phish.example"
    assert "login.phish.example" in payload["domains"]
    assert "benign.example" in payload["domains"]
    assert "https://login.phish.example/update" in payload["urls"]
    assert "203.0.113.5" in payload["ips"]


# ----------------------------------------------------------------------
# BaseFeedFetcher contract
# ----------------------------------------------------------------------


def test_base_write_json_is_atomic(tmp_path: Path) -> None:
    class _Dummy(BaseFeedFetcher):
        source_id = "dummy"
        source_url = "https://example.com/dummy"
        output_filename = "dummy.local.json"
        schema_version = "forge.feeds.dummy.v1"

        def _fetch(self, *, timeout: int) -> dict[str, Any]:
            return {"items": [{"a": 1}], "extra": "yes"}

    fetcher = _Dummy(tmp_path, sleep_fn=_no_sleep)
    result = fetcher.fetch(timeout=1)
    assert result["status"] == "ok"
    payload = json.loads((tmp_path / "dummy.local.json").read_text())
    assert payload["_meta"]["source_id"] == "dummy"
    assert payload["extra"] == "yes"
    # No .tmp sibling left over.
    assert not (tmp_path / "dummy.local.json.tmp").exists()


def test_base_fetcher_catches_subclass_errors(tmp_path: Path) -> None:
    class _Broken(BaseFeedFetcher):
        source_id = "broken"
        source_url = "https://example.com/broken"
        output_filename = "broken.local.json"
        schema_version = "forge.feeds.broken.v1"

        def _fetch(self, *, timeout: int) -> dict[str, Any]:
            raise RuntimeError("intentional failure")

    fetcher = _Broken(tmp_path, sleep_fn=_no_sleep)
    result = fetcher.fetch(timeout=1)
    assert result["status"] == "error"
    assert "intentional failure" in result["error"]
    assert not (tmp_path / "broken.local.json").exists()


def test_base_fetcher_rejects_non_mapping_payload(tmp_path: Path) -> None:
    class _NonMapping(BaseFeedFetcher):
        source_id = "nonmap"
        source_url = "https://example.com/nonmap"
        output_filename = "nonmap.local.json"
        schema_version = "forge.feeds.nonmap.v1"

        def _fetch(self, *, timeout: int) -> dict[str, Any]:
            return []  # type: ignore[return-value]

    fetcher = _NonMapping(tmp_path, sleep_fn=_no_sleep)
    result = fetcher.fetch(timeout=1)
    assert result["status"] == "error"
    assert "invalid_payload_type" in result["error"]


# ----------------------------------------------------------------------
# Orchestrator
# ----------------------------------------------------------------------


class _StubFetcher(BaseFeedFetcher):
    """Minimal fetcher that returns a canned dict without touching HTTP."""

    def __init__(self, imports_dir: Path, *, source_id: str, status: str, count: int, raises: bool = False) -> None:
        self.source_id = source_id  # type: ignore[misc]  # instance override is fine for tests
        self.source_url = f"https://example.com/{source_id}"
        self.output_filename = f"{source_id}.local.json"
        self.schema_version = f"forge.feeds.{source_id}.v1"
        self._stub_status = status
        self._stub_count = count
        self._stub_raises = raises
        super().__init__(imports_dir, sleep_fn=_no_sleep)

    def _fetch(self, *, timeout: int) -> dict[str, Any]:
        if self._stub_raises:
            raise RuntimeError("stub-raised")
        items = [{"idx": i} for i in range(self._stub_count)]
        if self._stub_status == "error":
            raise ValueError("stub-error")
        return {"items": items}


def test_fetch_all_tallies_mixed_results(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    imports_dir = tmp_path / "imports"
    fetchers = [
        _StubFetcher(imports_dir, source_id="alpha", status="ok", count=3),
        _StubFetcher(imports_dir, source_id="beta", status="error", count=0),
        _StubFetcher(imports_dir, source_id="gamma", status="ok", count=5),
    ]
    orchestrator = FeedFetcher(imports_dir=imports_dir, data_dir=data_dir, fetchers=fetchers)

    payload = orchestrator.fetch_all(timeout_per_source=10)

    assert payload["schema_version"].startswith("forge.feeds.orchestrator")
    assert payload["overall_status"] == "partial"
    assert payload["status_counts"] == {"ok": 2, "error": 1}
    assert payload["total_item_count"] == 8
    assert payload["results"]["alpha"]["status"] == "ok"
    assert payload["results"]["beta"]["status"] == "error"
    assert payload["results"]["gamma"]["status"] == "ok"


def test_fetch_all_survives_fetcher_raising_outside_contract(tmp_path: Path) -> None:
    class _ExplodingFetcher(BaseFeedFetcher):
        source_id = "boom"
        source_url = "https://example.com/boom"
        output_filename = "boom.local.json"
        schema_version = "forge.feeds.boom.v1"

        def fetch(self, *, timeout: int = 60) -> dict[str, Any]:  # noqa: ARG002
            raise OSError("filesystem gone")

        def _fetch(self, *, timeout: int) -> dict[str, Any]:  # pragma: no cover
            raise NotImplementedError

    fetchers = [
        _StubFetcher(tmp_path, source_id="alpha", status="ok", count=1),
        _ExplodingFetcher(tmp_path, sleep_fn=_no_sleep),
    ]
    orchestrator = FeedFetcher(imports_dir=tmp_path, data_dir=tmp_path, fetchers=fetchers)
    payload = orchestrator.fetch_all(timeout_per_source=5)

    assert payload["status_counts"]["ok"] == 1
    assert payload["status_counts"]["error"] == 1
    assert "filesystem gone" in payload["results"]["boom"]["error"]


def test_fetch_one_unknown_source_raises(tmp_path: Path) -> None:
    orchestrator = FeedFetcher(imports_dir=tmp_path, data_dir=tmp_path, fetchers=[])
    with pytest.raises(LookupError):
        orchestrator.fetch_one("nope")


def test_status_reports_existing_meta_blocks(tmp_path: Path) -> None:
    stub = _StubFetcher(tmp_path, source_id="alpha", status="ok", count=2)
    orchestrator = FeedFetcher(imports_dir=tmp_path, data_dir=tmp_path, fetchers=[stub])
    orchestrator.fetch_all(timeout_per_source=5)
    status = orchestrator.status()
    assert status["sources"][0]["source_id"] == "alpha"
    assert status["sources"][0]["exists"] is True
    assert status["sources"][0]["item_count"] == 2


def test_fetch_all_free_feeds_convenience(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``fetch_all_free_feeds`` builds the orchestrator with defaults.

    We stub each sub-fetcher to avoid network IO; the test proves the
    convenience wrapper threads imports_dir/data_dir through correctly.
    """
    imports_dir = tmp_path / "imports"
    data_dir = tmp_path / "data"

    calls: list[dict[str, Any]] = []

    class _CapturingFetcher(FeedFetcher):
        def fetch_all(self, *, timeout_per_source: int = 60) -> dict[str, Any]:
            calls.append(
                {
                    "imports_dir": str(self.imports_dir),
                    "data_dir": str(self.data_dir),
                    "timeout": timeout_per_source,
                }
            )
            return {
                "schema_version": "forge.feeds.orchestrator.v1",
                "overall_status": "ok",
                "status_counts": {"ok": 0},
                "total_item_count": 0,
                "results": {},
            }

    monkeypatch.setattr("forge.feeds.FeedFetcher", _CapturingFetcher)
    monkeypatch.setattr("forge.feeds.fetcher.FeedFetcher", _CapturingFetcher)

    payload = fetch_all_free_feeds(imports_dir, data_dir=data_dir, timeout_per_source=15)
    assert payload["overall_status"] == "ok"
    assert calls == [
        {
            "imports_dir": str(imports_dir),
            "data_dir": str(data_dir),
            "timeout": 15,
        }
    ]


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------


def test_feeds_list_cli(tmp_path: Path) -> None:
    from forge.cli import app

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "feeds",
            "list",
            "--imports-dir",
            str(tmp_path),
            "--data-dir",
            str(tmp_path),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    source_ids = {row["source_id"] for row in payload["sources"]}
    expected = {
        "nvd_cve",
        "cisa_kev",
        "epss",
        "security_rss",
        "nuclei_templates",
        "urlscan_public",
    }
    assert expected <= source_ids


def test_feeds_status_cli_without_fetch(tmp_path: Path) -> None:
    from forge.cli import app

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "feeds",
            "status",
            "--imports-dir",
            str(tmp_path),
            "--data-dir",
            str(tmp_path),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    for row in payload["sources"]:
        assert row["exists"] is False
        assert row["item_count"] == 0


def test_feeds_fetch_unknown_source_cli(tmp_path: Path) -> None:
    from forge.cli import app

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "feeds",
            "fetch",
            "--source",
            "nosuchfeed",
            "--imports-dir",
            str(tmp_path),
            "--data-dir",
            str(tmp_path),
            "--json",
        ],
    )
    assert result.exit_code != 0
    assert "unknown feed source" in result.output


# ----------------------------------------------------------------------
# Autopilot integration — feed_fetch phase
# ----------------------------------------------------------------------


def test_autopilot_feed_fetch_phase_registered(tmp_path: Path) -> None:
    from forge.autopilot.loop import ForgeAutopilot

    autopilot = ForgeAutopilot(
        data_dir=tmp_path / "data",
        imports_dir=tmp_path / "imports",
        reports_dir=tmp_path / "reports",
    )
    assert "feed_fetch" in autopilot._PHASE_DISPATCH


def test_autopilot_feed_fetch_phase_skips_in_dry_run(tmp_path: Path) -> None:
    from forge.autopilot.loop import ForgeAutopilot

    autopilot = ForgeAutopilot(
        data_dir=tmp_path / "data",
        imports_dir=tmp_path / "imports",
        reports_dir=tmp_path / "reports",
    )
    result = autopilot._phase_feed_fetch(dry_run=True)
    assert result.name == "feed_fetch"
    assert result.status == "skipped"
    assert "dry_run" in result.detail
