"""Tests for the PyJWT-based auth module.

Regression coverage for the python-jose → PyJWT migration that mitigates
CVE-2024-33663 (algorithm confusion) and CVE-2024-33664 (JWT bomb DoS).

Key invariants:
* Round-trip: mint → verify returns the same subject.
* Only HS256 is accepted on decode; ``alg=none`` and RS256-shaped tokens are
  rejected.
* Tampered tokens are rejected.
* Expired tokens are rejected.
* Missing/malformed ``sub`` claim yields ``None`` (never raises).
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
    subject = auth_mod.verify_token(token)
    assert subject == _TEST_SUBJECT


def test_verify_rejects_expired_token() -> None:
    payload = {"sub": _TEST_SUBJECT, "exp": int(time.time()) - 60}
    stale = jwt.encode(payload, _TEST_SECRET, algorithm="HS256")
    assert auth_mod.verify_token(stale) is None


def test_verify_rejects_algorithm_none() -> None:
    """CVE-2024-33663 mitigation: verifier must ignore ``alg=none`` tokens."""
    payload = {"sub": _TEST_SUBJECT, "exp": int(time.time()) + 60}
    # PyJWT refuses to encode with alg=none against a real secret; craft the
    # unsigned token manually.
    import base64
    import json

    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload).encode())
    unsigned = f"{header}.{body}."
    assert auth_mod.verify_token(unsigned) is None


def test_verify_rejects_rs256_token() -> None:
    """Algorithm-confusion guard: an RS256-shaped token must not decode.

    Sign the token with HS256, then rewrite the header to claim
    ``alg=RS256``. PyJWT with an explicit ``algorithms=['HS256']`` must
    refuse to decode this because the header algorithm is not in the
    allowed list.
    """
    import base64
    import json

    payload = {"sub": _TEST_SUBJECT, "exp": int(time.time()) + 60}
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
    # flip a bit in the signature
    tampered = f"{head}.{body}.{sig[:-1]}{'A' if sig[-1] != 'A' else 'B'}"
    assert auth_mod.verify_token(tampered) is None


def test_verify_rejects_garbage_input() -> None:
    assert auth_mod.verify_token("") is None
    assert auth_mod.verify_token("not-a-jwt") is None
    assert auth_mod.verify_token("....") is None


def test_verify_returns_none_on_missing_sub_claim() -> None:
    payload = {"exp": int(time.time()) + 60}
    token = jwt.encode(payload, _TEST_SECRET, algorithm="HS256")
    assert auth_mod.verify_token(token) is None


def test_verify_returns_none_on_empty_sub_claim() -> None:
    payload = {"sub": "", "exp": int(time.time()) + 60}
    token = jwt.encode(payload, _TEST_SECRET, algorithm="HS256")
    assert auth_mod.verify_token(token) is None


def test_verify_returns_none_on_non_string_sub() -> None:
    payload = {"sub": 12345, "exp": int(time.time()) + 60}
    token = jwt.encode(payload, _TEST_SECRET, algorithm="HS256")
    assert auth_mod.verify_token(token) is None


def test_auth_module_does_not_import_jose() -> None:
    """Regression: no jose import should sneak back in via merge conflicts.

    Checks the module's AST rather than raw source, so mentions of the
    string ``python-jose`` in docstrings (explaining the migration) don't
    trip the guard.
    """
    import ast
    import inspect

    source = inspect.getsource(auth_mod)
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("jose"), (
                    f"forbidden import found: {alias.name}"
                )
        elif isinstance(node, ast.ImportFrom):
            assert node.module != "jose", "forbidden import: from jose"
            assert node.module is None or not node.module.startswith("jose."), (
                f"forbidden import: from {node.module}"
            )
