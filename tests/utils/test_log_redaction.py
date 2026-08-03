"""Tests for forge.utils.log_redaction — secret query param scrubbing."""

from __future__ import annotations

import logging
import re

import pytest

from forge.utils.log_redaction import (
    SecretQueryRedactionFilter,
    install_query_redaction_filter,
)


def _make_record(msg: str, *args: object) -> logging.LogRecord:
    return logging.LogRecord(
        name="httpx",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=msg,
        args=args or None,
        exc_info=None,
    )


def test_shodan_key_query_param_is_redacted() -> None:
    filt = SecretQueryRedactionFilter()
    record = _make_record(
        "HTTP Request: GET https://api.shodan.io/shodan/host/1.2.3.4?key=abcd1234EFGH5678 HTTP/1.1"
    )
    assert filt.filter(record) is True
    assert "abcd1234EFGH5678" not in record.getMessage()
    assert "?key=[REDACTED]" in record.getMessage()


def test_github_access_token_is_redacted() -> None:
    filt = SecretQueryRedactionFilter()
    record = _make_record(
        "GET https://api.github.com/search/code?access_token=ghp_xxxxxxxxxxxxxxxxxx&q=forge"
    )
    filt.filter(record)
    msg = record.getMessage()
    assert "ghp_xxxxxxxxxxxxxxxxxx" not in msg
    assert "?access_token=[REDACTED]" in msg
    # unrelated query params kept
    assert "q=forge" in msg


def test_azure_sas_signature_is_redacted() -> None:
    filt = SecretQueryRedactionFilter()
    record = _make_record(
        "GET https://acct.blob.core.windows.net/ct/b?sv=2021-08-06&se=2026-08-04T00%3A00Z&sig=REDACT_ME_PLEASE"
    )
    filt.filter(record)
    msg = record.getMessage()
    assert "REDACT_ME_PLEASE" not in msg
    assert "&sig=[REDACTED]" in msg


def test_aws_sigv4_query_params_are_redacted() -> None:
    filt = SecretQueryRedactionFilter()
    record = _make_record(
        "GET https://s3.example.com/o?X-Amz-Credential=AKIAIOSFODNN7EXAMPLE"
        "%2F20260804%2Fus-east-1&X-Amz-Signature=SIGNATURE_HEX_HERE_DO_NOT_LEAK"
    )
    filt.filter(record)
    msg = record.getMessage()
    assert "AKIAIOSFODNN7EXAMPLE" not in msg
    assert "SIGNATURE_HEX_HERE_DO_NOT_LEAK" not in msg
    assert "X-Amz-Credential=[REDACTED]" in msg
    assert "X-Amz-Signature=[REDACTED]" in msg


def test_percent_format_args_are_scrubbed() -> None:
    filt = SecretQueryRedactionFilter()
    record = _make_record(
        "requesting %s",
        "https://api.shodan.io/dns/domain/example.com?key=SUPER_SECRET",
    )
    filt.filter(record)
    msg = record.getMessage()
    assert "SUPER_SECRET" not in msg
    assert "?key=[REDACTED]" in msg


def test_record_without_secrets_is_untouched() -> None:
    filt = SecretQueryRedactionFilter()
    record = _make_record("HTTP Request: GET https://example.com/health HTTP/1.1")
    original = record.getMessage()
    filt.filter(record)
    assert record.getMessage() == original


def test_install_query_redaction_filter_is_idempotent() -> None:
    logger = logging.getLogger("httpx")
    # snapshot filters that already exist before install
    before = list(logger.filters)
    install_query_redaction_filter(("httpx",))
    install_query_redaction_filter(("httpx",))
    matching = [f for f in logger.filters if isinstance(f, SecretQueryRedactionFilter)]
    try:
        assert len(matching) == 1
    finally:
        # restore original filter list
        for extra in matching:
            logger.removeFilter(extra)
        for existing in before:
            if existing not in logger.filters:
                logger.addFilter(existing)


def test_install_applies_to_httpx_logger_end_to_end(caplog: pytest.LogCaptureFixture) -> None:
    install_query_redaction_filter(("httpx",))
    httpx_logger = logging.getLogger("httpx")
    prior_level = httpx_logger.level
    httpx_logger.setLevel(logging.DEBUG)
    try:
        with caplog.at_level(logging.DEBUG, logger="httpx"):
            httpx_logger.info(
                "HTTP Request: GET https://api.shodan.io/dns/resolve?hostnames=x.com&key=%s HTTP/1.1",
                "LEAK_ME_IF_YOU_CAN",
            )
    finally:
        httpx_logger.setLevel(prior_level)
    joined = "\n".join(caplog.messages)
    assert "LEAK_ME_IF_YOU_CAN" not in joined
    assert "&key=[REDACTED]" in joined or "?key=[REDACTED]" in joined


def test_query_regex_covers_all_documented_params() -> None:
    """Regression guard: every param listed as sensitive must match."""
    sensitive = (
        "key", "api_key", "token", "access_token", "client_secret",
        "X-Amz-Credential", "X-Amz-Signature", "X-Amz-Security-Token",
        "X-Goog-Credential", "X-Goog-Signature", "X-Goog-Algorithm",
        "X-Goog-SignedHeaders", "AWSAccessKeyId", "Signature", "sig",
        "se", "sp", "sv", "sr", "spr", "skoid", "sktid", "skt", "ske", "sks", "skv",
    )
    filt = SecretQueryRedactionFilter()
    for param in sensitive:
        record = _make_record(f"GET https://svc.example.com/x?{param}=SECRET_VALUE_XYZ")
        filt.filter(record)
        assert "SECRET_VALUE_XYZ" not in record.getMessage(), f"failed to redact ?{param}="
        assert re.search(re.escape(param) + r"=\[REDACTED\]", record.getMessage()), (
            f"redaction sentinel missing for ?{param}="
        )
