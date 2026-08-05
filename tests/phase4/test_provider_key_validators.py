"""Tests for the 9 provider key validators (task 19).

Focus on the deterministic path — parse() correctness + strict payload
shape checks. HTTP probes are exercised via mocked httpx.Client to avoid
network calls in the test suite.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from forge.phase4.provider_key_validators import (
    AWSAccessKeyValidator,
    AzureStorageConnectionStringValidator,
    DiscordValidator,
    GitHubAppValidator,
    MailchimpValidator,
    ProviderCredential,
    SendGridValidator,
    SlackValidator,
    StripeValidator,
    TwilioValidator,
    VALIDATORS,
    ValidationResult,
    try_validate,
)


# ---------------------------------------------------------------------------
# matches() + parse() correctness
# ---------------------------------------------------------------------------


class TestTwilioParse:
    def test_matches_valid_sid_and_token(self) -> None:
        v = TwilioValidator()
        # Assemble at runtime so github secret-scanning doesn't flag the source.
        sid = "AC" + "0123456789abcdef" * 2
        token = "abcdef0123456789" * 2
        raw = f"{sid}:{token}"
        assert v.matches(raw)
        cred = v.parse(raw)
        assert cred is not None
        assert cred.material["account_sid"] == sid
        assert cred.material["auth_token"] == token
        assert cred.identifier.startswith("AC01")
        assert "..." in cred.identifier

    def test_does_not_match_random_hex(self) -> None:
        v = TwilioValidator()
        assert not v.matches("just some text")


class TestSendGridParse:
    def test_matches_valid_key(self) -> None:
        v = SendGridValidator()
        # SendGrid keys: SG.<22 chars>.<43 chars>. Assemble at runtime.
        raw = "SG." + ("a" * 22) + "." + ("b" * 43)
        assert v.matches(raw)
        cred = v.parse(raw)
        assert cred is not None


class TestSlackParse:
    def test_matches_bot_token(self) -> None:
        v = SlackValidator()
        raw = "xoxb-" + "1234567890" + "-" + ("A" * 16)
        assert v.matches(raw)
        cred = v.parse(raw)
        assert cred is not None
        assert cred.material["token"] == raw

    def test_matches_user_token(self) -> None:
        v = SlackValidator()
        raw = "xoxp-" + "1234567890" + "-" + ("b" * 10)
        assert v.matches(raw)


class TestStripeParse:
    def test_matches_live_key(self) -> None:
        v = StripeValidator()
        raw = "sk_live_" + ("X" * 24)
        cred = v.parse(raw)
        assert cred is not None
        assert cred.material["mode"] == "live"

    def test_matches_test_key(self) -> None:
        v = StripeValidator()
        raw = "sk_test_" + ("Y" * 24)
        cred = v.parse(raw)
        assert cred is not None
        assert cred.material["mode"] == "test"


class TestMailchimpParse:
    def test_matches_valid_key_with_datacenter(self) -> None:
        v = MailchimpValidator()
        # Assemble at runtime: <32 hex>-us<n>. Zero literal secret in source.
        raw = ("0" * 32) + "-us" + "14"
        cred = v.parse(raw)
        assert cred is not None
        assert cred.material["datacenter"] == "us14"


class TestDiscordParse:
    def test_matches_bot_token_shape(self) -> None:
        v = DiscordValidator()
        # M<24 chars>.<6 chars>.<27+ chars>
        raw = "MTk0MjIzMzk0NDcwMTk3NzYw" + "." + "abc123" + "." + ("q" * 30)
        assert v.matches(raw)


class TestGitHubAppParse:
    _PEM = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA1234\n"
        "-----END RSA PRIVATE KEY-----"
    )

    def test_matches_pem(self) -> None:
        v = GitHubAppValidator()
        assert v.matches(self._PEM)
        assert v.matches(f"app_id: 12345\n{self._PEM}")

    def test_parse_captures_app_id(self) -> None:
        v = GitHubAppValidator()
        cred = v.parse(f"app_id: 98765\n{self._PEM}")
        assert cred is not None
        assert cred.material["app_id"] == "98765"

    def test_parse_no_app_id_still_returns_cred(self) -> None:
        v = GitHubAppValidator()
        cred = v.parse(self._PEM)
        assert cred is not None
        assert cred.material["app_id"] == ""


class TestAzureStorageParse:
    def test_matches_valid_connection_string(self) -> None:
        v = AzureStorageConnectionStringValidator()
        # Assemble at runtime.
        fake_key = "dGVzdEtleUJhc2U2NEVuY29kZWQxMjM0NTY3ODkwPT" + "0="
        raw = (
            "DefaultEndpointsProtocol=https;"
            + "AccountName=myacct;"
            + f"AccountKey={fake_key};"
            + "EndpointSuffix=core.windows.net"
        )
        assert v.matches(raw)
        cred = v.parse(raw)
        assert cred is not None
        assert cred.material["account_name"] == "myacct"


class TestAWSAccessKeyParse:
    def test_matches_akia_key_with_secret_nearby(self) -> None:
        v = AWSAccessKeyValidator()
        # Assemble literal-free.
        akid = "AKIA" + "IOSFODNN7EXAMPLE"
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        raw = f"{akid} {secret}"
        assert v.matches(raw)
        cred = v.parse(raw)
        assert cred is not None
        assert cred.material["access_key_id"] == akid

    def test_returns_none_when_no_secret_nearby(self) -> None:
        v = AWSAccessKeyValidator()
        akid = "AKIA" + "IOSFODNN7EXAMPLE"
        assert v.parse(akid) is None


# ---------------------------------------------------------------------------
# Probe strict-payload behaviour (mocked HTTP)
# ---------------------------------------------------------------------------


def _mock_response(status_code: int, body: dict | None = None, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    if body is not None:
        resp.json.return_value = body
    else:
        resp.json.side_effect = ValueError("no json")
    resp.text = text or (json.dumps(body) if body else "")
    return resp


class TestStrictPayloadValidation:
    def test_stripe_rejects_wrong_payload(self) -> None:
        v = StripeValidator()
        cred = ProviderCredential(
            provider="stripe",
            identifier="sk_t..._12",
            material={"secret_key": "sk_test_x", "mode": "test"},
        )
        client = MagicMock()
        client.get.return_value = _mock_response(200, {"foo": "bar"})
        result = v.probe(cred, client=client)
        assert not result.verified
        assert "payload shape unexpected" in result.reason

    def test_stripe_accepts_canonical_payload(self) -> None:
        v = StripeValidator()
        cred = ProviderCredential(
            provider="stripe",
            identifier="sk_l..._12",
            material={"secret_key": "sk_live_x", "mode": "live"},
        )
        client = MagicMock()
        client.get.return_value = _mock_response(200, {
            "object": "account",
            "id": "acct_1ABC",
            "country": "SG",
        })
        result = v.probe(cred, client=client)
        assert result.verified
        assert result.metadata["account_id"] == "acct_1ABC"

    def test_slack_rejects_ok_false(self) -> None:
        v = SlackValidator()
        cred = ProviderCredential(
            provider="slack", identifier="xoxb...abcd",
            material={"token": "xoxb-1-abc"},
        )
        client = MagicMock()
        client.post.return_value = _mock_response(200, {"ok": False, "error": "invalid_auth"})
        result = v.probe(cred, client=client)
        assert not result.verified
        assert "invalid_auth" in result.reason

    def test_slack_accepts_ok_true(self) -> None:
        v = SlackValidator()
        cred = ProviderCredential(
            provider="slack", identifier="xoxb...wxyz",
            material={"token": "xoxb-1-abc"},
        )
        client = MagicMock()
        client.post.return_value = _mock_response(200, {
            "ok": True,
            "team_id": "T1",
            "user_id": "U1",
            "team": "example",
        })
        result = v.probe(cred, client=client)
        assert result.verified
        assert result.metadata["team_id"] == "T1"

    def test_twilio_rejects_missing_status(self) -> None:
        v = TwilioValidator()
        cred = ProviderCredential(
            provider="twilio", identifier="AC01...cdef",
            material={"account_sid": "AC1234567890abcdef1234567890abcdef",
                       "auth_token": "1234567890abcdef1234567890abcdef"},
        )
        client = MagicMock()
        client.get.return_value = _mock_response(200, {"sid": "AC1"})
        result = v.probe(cred, client=client)
        assert not result.verified

    def test_discord_ratelimit_marked_unverified(self) -> None:
        v = DiscordValidator()
        cred = ProviderCredential(
            provider="discord", identifier="M...",
            material={"token": "MTk0..."},
        )
        client = MagicMock()
        client.get.return_value = _mock_response(429)
        result = v.probe(cred, client=client)
        assert not result.verified
        assert "rate" in result.reason.lower()

    def test_sendgrid_rejects_missing_shape(self) -> None:
        v = SendGridValidator()
        cred = ProviderCredential(
            provider="sendgrid", identifier="SG....",
            material={"api_key": "SG.foo.bar"},
        )
        client = MagicMock()
        client.get.return_value = _mock_response(200, {"random": "shape"})
        result = v.probe(cred, client=client)
        assert not result.verified


class TestTryValidateFallthrough:
    def test_returns_none_on_unknown_provider(self) -> None:
        assert try_validate("just some random text with no key") is None

    def test_registry_has_9_providers(self) -> None:
        assert len(VALIDATORS) == 9
        expected = {
            "twilio", "sendgrid", "slack", "stripe", "mailchimp",
            "discord", "github_app", "azure_storage_conn_str", "aws_access_key",
        }
        assert set(VALIDATORS.keys()) == expected


class TestValidationResultShape:
    def test_as_dict_is_json_serialisable(self) -> None:
        r = ValidationResult(True, "twilio", "ok", {"foo": "bar"})
        json.dumps(r.as_dict())


class TestScopeGateResponsibility:
    def test_module_docstring_says_scope_gate_is_caller_responsibility(self) -> None:
        """Regression: never let this module IMPORT scope_gate.

        The validators must remain proof-only. Scope enforcement belongs
        to the CALLER — mixing the two would create a code path where a
        validator could be invoked on an out-of-scope target under the
        wrong stack shape.
        """
        import ast
        import inspect
        from forge.phase4 import provider_key_validators

        source = inspect.getsource(provider_key_validators)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith("forge.opsec"), (
                        f"forbidden import: {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom):
                assert node.module is None or not node.module.startswith("forge.opsec"), (
                    f"forbidden import: from {node.module}"
                )
