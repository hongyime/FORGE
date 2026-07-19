from __future__ import annotations

from forge.utils.validation_summary import safe_validation_summary


def test_safe_validation_summary_redacts_common_validation_secrets() -> None:
    raw = (
        "GET https://bucket.s3.amazonaws.com/file?"
        "X-Amz-Credential=AKIAABCDEFGHIJKLMNOP/20260719/us-east-1/s3/aws4_request&"
        "X-Amz-Signature=abcdef1234567890abcdef1234567890 "
        "Set-Cookie: sessionid=secret-cookie; HttpOnly "
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghijklmno.abcdefghijklmnop "
        "token=raw-validation-secret "
        "api_key=raw-key-value "
        "abcdEFGHijklMNOPqrstUVWXyz0123456789abcdEFGHijklMNOP"
    )

    summary = safe_validation_summary(raw)

    assert "AKIAABCDEFGHIJKLMNOP" not in summary
    assert "abcdef1234567890abcdef1234567890" not in summary
    assert "secret-cookie" not in summary
    assert "eyJhbGciOiJIUzI1NiJ9" not in summary
    assert "raw-validation-secret" not in summary
    assert "raw-key-value" not in summary
    assert "abcdEFGHijklMNOPqrstUVWXyz0123456789abcdEFGHijklMNOP" not in summary
    assert "X-Amz-Credential=[REDACTED]" in summary
    assert "X-Amz-Signature=[REDACTED]" in summary
    assert "Set-Cookie: [REDACTED]" in summary
    assert "Authorization: [REDACTED]" in summary
    assert "token=[REDACTED]" in summary
    assert "api_key=[REDACTED]" in summary


def test_safe_validation_summary_redacts_cookie_pairs_and_full_auth_headers() -> None:
    raw = (
        "Cookie: session=abc123; theme=dark; csrf=xyz789 "
        "Authorization: AWS4-HMAC-SHA256 "
        "Credential=AKIAABCDEFGHIJKLMNOP/20260719/us-east-1/s3/aws4_request, "
        "SignedHeaders=host, Signature=abcdef1234567890 "
        "HTTP 200"
    )

    summary = safe_validation_summary(raw)

    assert "abc123" not in summary
    assert "csrf=xyz789" not in summary
    assert "AKIAABCDEFGHIJKLMNOP" not in summary
    assert "abcdef1234567890" not in summary
    assert "Cookie: [REDACTED]" in summary
    assert "Authorization: [REDACTED]" in summary
    assert "HTTP 200" in summary


def test_safe_validation_summary_truncates_after_redaction() -> None:
    summary = safe_validation_summary("safe " * 200, max_length=40)

    assert len(summary) == 40
    assert summary.endswith("...")
