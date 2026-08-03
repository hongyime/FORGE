"""Tests for the ``recon subdomains`` stdout summary formatter.

P2/P3 audit item #5: after subdomain enumeration finished, operators saw a
count-only line (or nothing, when the logger was silent). We now print a
bounded sample of the hostnames plus an ``... and N more`` tail so the
terminal always shows actionable output.
"""

from __future__ import annotations

from io import StringIO

import pytest
from rich.console import Console

from forge.cli import _print_recon_subdomain_summary, _RECON_SUBDOMAIN_STDOUT_SAMPLE


def _capture(found) -> str:
    """Render the summary into a plain-string buffer for assertions."""
    buffer = StringIO()
    console = Console(file=buffer, width=200, color_system=None, force_terminal=False)
    _print_recon_subdomain_summary(console, "example.com", found)
    return buffer.getvalue()


def test_summary_zero_results_prints_count_only() -> None:
    out = _capture([])
    assert "Found 0 subdomain" in out
    assert "example.com" in out
    # no bullet lines when there is nothing to enumerate
    assert "•" not in out
    assert "and " not in out


def test_summary_prints_all_hostnames_when_below_sample_limit() -> None:
    found = ["a.example.com", "b.example.com", "c.example.com"]
    out = _capture(found)
    assert "Found 3 subdomains" in out
    for host in found:
        assert host in out
    assert "and " not in out  # no truncation tail


def test_summary_truncates_and_reports_remaining() -> None:
    found = [f"host{i}.example.com" for i in range(_RECON_SUBDOMAIN_STDOUT_SAMPLE + 5)]
    out = _capture(found)
    assert f"Found {_RECON_SUBDOMAIN_STDOUT_SAMPLE + 5} subdomains" in out
    for host in found[:_RECON_SUBDOMAIN_STDOUT_SAMPLE]:
        assert host in out
    assert "and 5 more" in out
    # tail-truncated hosts must not appear literally
    assert found[-1] not in out


def test_summary_accepts_dict_rows_with_hostname_keys() -> None:
    found = [
        {"hostname": "a.example.com"},
        {"host": "b.example.com"},
        {"subdomain": "c.example.com"},
        {"name": "d.example.com"},
        {"other": "should-be-ignored"},
    ]
    out = _capture(found)
    assert "Found 4 subdomains" in out
    assert "a.example.com" in out
    assert "d.example.com" in out
    assert "should-be-ignored" not in out


def test_summary_singularises_one_result() -> None:
    out = _capture(["only.example.com"])
    assert "Found 1 subdomain " in out or "Found 1 subdomain\n" in out
    assert "subdomains " not in out  # no plural
