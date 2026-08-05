"""Tests for the PyJWT-based auth module.

Regression coverage for python-jose → PyJWT (CVE-2024-33663/-33664) plus
post-audit hardening: iat/nbf/jti/iss/aud required, empty secret refused
in every profile.
"""

from __future__ import annotations

import time

import jwt
import pytest

from forge.webui import auth as auth_mod


_TEST_SECRET = "s" * 64
_TEST_SUBJECT = "operator@example.com"


@pytest.fixture(autouse=True)
def _mock_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth_mod, "_secret", lambda: _TEST_SECRET)


def test_mint_verify_roundtrip() -> None:
    token = auth_mod.mint_token(_TEST_SUBJECT, ttl_seconds=60)
    assert auth_mod.verify_token(token) == _TEST_SUBJECT


def test_mint_includes_required_claims() -> None:
    token = auth_mod.mint_token(_TEST_SUBJECT, ttl_seconds=60)
    payload = jwt.decode(
        token,
        _TEST_SECRET,
        algorithms=["HS256"],
        audience="forge-webui",
        issuer="forge-webui",
    )
    for required in ("sub", "iat", "nbf", "exp", "jti", "iss", "aud"):
        assert required in payload, f"minted token missing {required}"
    assert payload["iss"] == "forge-webui"
    assert payload["aud"] == "forge-webui"
    assert len(payload["jti"]) >= 16


def test_verify_rejects_missing_jti() -> None:
    now = int(time.time())
    payload = {
        "sub": _TEST_SUBJECT,
        "iat": now,
        "nbf": now,
        "exp": now + 60,
        "iss": "forge-webui",
        "aud": "forge-webui",
    }
    token = jwt.encode(payload, _TEST_SECRET, algorithm="HS256")
    assert auth_mod.verify_token(token) is None


def test_verify_rejects_wrong_issuer() -> None:
    now = int(time.time())
    payload = {
        "sub": _TEST_SUBJECT,
        "iat": now, "nbf": now, "exp": now + 60,
        "jti": "abcdef" * 4,
        "iss": "someone-else",
        "aud": "forge-webui",
    }
    token = jwt.encode(payload, _TEST_SECRET, algorithm="HS256")
    assert auth_mod.verify_token(token) is None


def test_verify_rejects_wrong_audience() -> None:
    now = int(time.time())
    payload = {
        "sub": _TEST_SUBJECT,
        "iat": now, "nbf": now, "exp": now + 60,
        "jti": "abcdef" * 4,
        "iss": "forge-webui",
        "aud": "someone-else",
    }
    token = jwt.encode(payload, _TEST_SECRET, algorithm="HS256")
    assert auth_mod.verify_token(token) is None


def test_verify_rejects_expired_token() -> None:
    now = int(time.time())
    payload = {
        "sub": _TEST_SUBJECT, "iat": now - 300, "nbf": now - 300,
        "exp": now - 60, "jti": "a" * 32,
        "iss": "forge-webui", "aud": "forge-webui",
    }
    stale = jwt.encode(payload, _TEST_SECRET, algorithm="HS256")
    assert auth_mod.verify_token(stale) is None


def test_verify_rejects_nbf_future() -> None:
    now = int(time.time())
    payload = {
        "sub": _TEST_SUBJECT, "iat": now, "nbf": now + 300,
        "exp": now + 600, "jti": "b" * 32,
        "iss": "forge-webui", "aud": "forge-webui",
    }
    token = jwt.encode(payload, _TEST_SECRET, algorithm="HS256")
    assert auth_mod.verify_token(token) is None


def test_verify_rejects_algorithm_none() -> None:
    import base64
    import json

    now = int(time.time())
    payload = {
        "sub": _TEST_SUBJECT, "iat": now, "nbf": now, "exp": now + 60,
        "jti": "c" * 32, "iss": "forge-webui", "aud": "forge-webui",
    }

    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload).encode())
    unsigned = f"{header}.{body}."
    assert auth_mod.verify_token(unsigned) is None


def test_verify_rejects_rs256_shaped_token() -> None:
    """Algorithm-confusion: HS256-signed token with claimed alg=RS256 in header must fail."""
    import base64
    import json

    now = int(time.time())
    payload = {
        "sub": _TEST_SUBJECT, "iat": now, "nbf": now, "exp": now + 60,
        "jti": "d" * 32, "iss": "forge-webui", "aud": "forge-webui",
    }
    signed = jwt.encode(payload, _TEST_SECRET, algorithm="HS256")
    _, body, sig = signed.split(".")

    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    rs256_header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    forged = f"{rs256_header}.{body}.{sig}"
    assert auth_mod.verify_token(forged) is None


def test_verify_rejects_tampered_signature() -> None:
    token = auth_mod.mint_token(_TEST_SUBJECT, ttl_seconds=60)
    head, body, sig = token.split(".")
    tampered = f"{head}.{body}.{sig[:-1]}{'A' if sig[-1] != 'A' else 'B'}"
    assert auth_mod.verify_token(tampered) is None


def test_verify_rejects_garbage_input() -> None:
    assert auth_mod.verify_token("") is None
    assert auth_mod.verify_token("not-a-jwt") is None
    assert auth_mod.verify_token("....") is None


def test_verify_returns_none_on_missing_sub_claim() -> None:
    now = int(time.time())
    payload = {
        "iat": now, "nbf": now, "exp": now + 60, "jti": "e" * 32,
        "iss": "forge-webui", "aud": "forge-webui",
    }
    token = jwt.encode(payload, _TEST_SECRET, algorithm="HS256")
    assert auth_mod.verify_token(token) is None


def test_secret_refuses_empty_in_dev_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    """P2-B09: empty secret must be refused even under FORGE_ENV=dev."""
    # Restore the real _secret function by re-importing after the autouse fixture
    # patches it — we want to actually invoke the guarded code path.
    import importlib
    from forge.webui import auth as _real_auth_mod
    importlib.reload(_real_auth_mod)

    import forge.config

    class _FakeConfig:
        web_secret_key = ""

    monkeypatch.setattr(
        forge.config.ForgeConfig, "load",
        staticmethod(lambda: _FakeConfig()),
    )
    monkeypatch.setenv("FORGE_ENV", "dev")
    with pytest.raises(RuntimeError, match="non-empty value"):
        _real_auth_mod._secret()


def test_auth_module_does_not_import_jose() -> None:
    import ast
    import inspect

    source = inspect.getsource(auth_mod)
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("jose")
        elif isinstance(node, ast.ImportFrom):
            assert node.module != "jose"
            assert node.module is None or not node.module.startswith("jose.")
