"""Tests for forge.collection.cloud.aws_credentials."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from forge.collection.cloud import aws_credentials as aws
from forge.collection.cloud.aws_credentials import (
    AWSCredential,
    harvest_aws_credentials,
)

_AWS_ENV_VARS = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
)


def _sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _AWS_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


# --------------------------------------------------------------------------- #
# Fake urlopen response                                                       #
# --------------------------------------------------------------------------- #

class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


# --------------------------------------------------------------------------- #
# Source 1: env vars                                                          #
# --------------------------------------------------------------------------- #

def test_env_harvest_finds_all_three_vars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_env(monkeypatch)
    access = "AKIAIOSFODNN7EXAMPLE"
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    session = "FQoGZXIvYXdzEXAMPLESESSIONTOKEN"
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", access)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", secret)
    monkeypatch.setenv("AWS_SESSION_TOKEN", session)

    creds = harvest_aws_credentials(
        home=tmp_path, include_ec2_metadata=False, include_ecs_metadata=False
    )

    env_creds = [c for c in creds if c.type == "env"]
    assert len(env_creds) == 1
    c = env_creds[0]
    assert c.source == "env:AWS_ACCESS_KEY_ID"
    assert c.access_key_hash == _sha256(access)
    assert c.secret_hash == _sha256(secret)
    assert c.session_token_hash == _sha256(session)
    # No raw material must appear in the serialized dict.
    dumped = json.dumps(c.to_dict())
    for raw in (access, secret, session):
        assert raw not in dumped


def test_env_harvest_omits_empty_session_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_env(monkeypatch)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE1234567890")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    # AWS_SESSION_TOKEN intentionally absent.

    creds = harvest_aws_credentials(
        home=tmp_path, include_ec2_metadata=False, include_ecs_metadata=False
    )
    env_creds = [c for c in creds if c.type == "env"]
    assert len(env_creds) == 1
    assert env_creds[0].session_token_hash is None


def test_env_harvest_missing_returns_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_env(monkeypatch)
    assert harvest_aws_credentials(
        home=tmp_path, include_ec2_metadata=False, include_ecs_metadata=False
    ) == []


# --------------------------------------------------------------------------- #
# Source 2: ~/.aws/credentials                                                #
# --------------------------------------------------------------------------- #

def _write_credentials_file(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def test_credentials_file_parsed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_env(monkeypatch)
    access_default = "AKIAIOSFODNN7EXAMPLE"
    secret_default = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    session_dev = "FQoGZXIvSESSIONDEV"
    body = (
        "[default]\n"
        f"aws_access_key_id = {access_default}\n"
        f"aws_secret_access_key = {secret_default}\n"
        "\n"
        "[dev]\n"
        "aws_access_key_id = AKIADEVEXAMPLE123456\n"
        "aws_secret_access_key = devsecret\n"
        f"aws_session_token = {session_dev}\n"
    )
    _write_credentials_file(tmp_path / ".aws" / "credentials", body)

    creds = harvest_aws_credentials(
        home=tmp_path, include_ec2_metadata=False, include_ecs_metadata=False
    )
    shared = [c for c in creds if c.type == "shared_credentials"]
    assert len(shared) == 2
    profiles = {c.extra["profile"]: c for c in shared}
    assert set(profiles) == {"default", "dev"}
    assert profiles["default"].access_key_hash == _sha256(access_default)
    assert profiles["default"].secret_hash == _sha256(secret_default)
    assert profiles["default"].session_token_hash is None  # empty -> None
    assert profiles["dev"].session_token_hash == _sha256(session_dev)

    dumped = json.dumps([c.to_dict() for c in shared])
    for raw in (access_default, secret_default, session_dev, "devsecret"):
        assert raw not in dumped


def test_credentials_file_skips_malformed_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_env(monkeypatch)
    # Includes a duplicate option (raises DuplicateOptionError in strict
    # mode) plus a bare token line, forcing the fallback line-by-line
    # parser. The `[good]` section must still be recovered.
    body = (
        "malformed line without section\n"
        "[bad\n"  # invalid section header
        "aws_access_key_id = AKIABADEXAMPLE1234\n"
        "\n"
        "[good]\n"
        "not_a_kv_pair_line\n"
        "aws_access_key_id = AKIAGOODEXAMPLE12345\n"
        "aws_access_key_id = AKIAGOODEXAMPLE12345\n"  # duplicate
        "aws_secret_access_key = goodsecret\n"
        "= value_without_key\n"
    )
    _write_credentials_file(tmp_path / ".aws" / "credentials", body)

    creds = harvest_aws_credentials(
        home=tmp_path, include_ec2_metadata=False, include_ecs_metadata=False
    )
    shared = [c for c in creds if c.type == "shared_credentials"]
    profiles = {c.extra["profile"] for c in shared}
    assert "good" in profiles
    good = next(c for c in shared if c.extra["profile"] == "good")
    assert good.access_key_hash == _sha256("AKIAGOODEXAMPLE12345")
    assert good.secret_hash == _sha256("goodsecret")


def test_credentials_file_missing_graceful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_env(monkeypatch)
    # No ~/.aws directory at all.
    assert harvest_aws_credentials(
        home=tmp_path, include_ec2_metadata=False, include_ecs_metadata=False
    ) == []


# --------------------------------------------------------------------------- #
# Source 3: ~/.aws/config (assume-role profiles)                              #
# --------------------------------------------------------------------------- #

def test_config_file_assume_role_profile_parsed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_env(monkeypatch)
    body = (
        "[default]\n"
        "region = us-east-1\n"
        "\n"
        "[profile prod]\n"
        "role_arn = arn:aws:iam::123456789012:role/ProdAdmin\n"
        "source_profile = default\n"
        "mfa_serial = arn:aws:iam::123456789012:mfa/alice\n"
        "role_session_name = alice-prod\n"
        "\n"
        "[profile ec2role]\n"
        "role_arn = arn:aws:iam::999988887777:role/EC2Role\n"
        "credential_source = Ec2InstanceMetadata\n"
    )
    _write_credentials_file(tmp_path / ".aws" / "config", body)

    creds = harvest_aws_credentials(
        home=tmp_path, include_ec2_metadata=False, include_ecs_metadata=False
    )
    roles = [c for c in creds if c.type == "assume_role_profile"]
    by_profile = {c.extra["profile"]: c for c in roles}
    assert set(by_profile) == {"prod", "ec2role"}

    prod = by_profile["prod"]
    assert prod.account_id == "123456789012"
    assert prod.extra["role_arn"] == "arn:aws:iam::123456789012:role/ProdAdmin"
    assert prod.extra["source_profile"] == "default"
    assert prod.extra["mfa_serial"].startswith("arn:aws:iam::")
    assert prod.access_key_hash is None
    assert prod.secret_hash is None
    assert prod.session_token_hash is None

    ec2 = by_profile["ec2role"]
    assert ec2.account_id == "999988887777"
    assert ec2.extra["credential_source"] == "Ec2InstanceMetadata"

    # region-only [default] section is not emitted as a credential.
    assert "default" not in by_profile


def test_config_file_missing_graceful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_env(monkeypatch)
    (tmp_path / ".aws").mkdir()
    (tmp_path / ".aws" / "credentials").write_text("", encoding="utf-8")
    # No config file at all: still fine.
    assert harvest_aws_credentials(
        home=tmp_path, include_ec2_metadata=False, include_ecs_metadata=False
    ) == []


# --------------------------------------------------------------------------- #
# Source 4: EC2 IMDS                                                          #
# --------------------------------------------------------------------------- #

def test_ec2_metadata_harvest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_env(monkeypatch)
    access = "ASIAIOSFODNN7EXAMPLE"
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    token = "IQoJb3JpZ2luX2VjEXAMPLE"

    def fake_urlopen(req: Any, timeout: float = 0) -> _FakeResponse:
        assert timeout <= 2.0
        method = getattr(req, "method", None) or req.get_method()
        # Token endpoint (IMDSv2)
        if req.full_url.endswith("/api/token") and method == "PUT":
            assert req.get_header("X-aws-ec2-metadata-token-ttl-seconds")
            return _FakeResponse(b"IMDS-TOKEN-XYZ")
        # Role listing
        if req.full_url.endswith("/security-credentials/"):
            assert req.get_header("X-aws-ec2-metadata-token") == "IMDS-TOKEN-XYZ"
            return _FakeResponse(b"WebAppRole\n")
        # Role detail
        if req.full_url.endswith("/security-credentials/WebAppRole"):
            assert req.get_header("X-aws-ec2-metadata-token") == "IMDS-TOKEN-XYZ"
            return _FakeResponse(
                json.dumps(
                    {
                        "Code": "Success",
                        "AccessKeyId": access,
                        "SecretAccessKey": secret,
                        "Token": token,
                        "Expiration": "2026-09-01T12:00:00Z",
                    }
                ).encode()
            )
        raise AssertionError(f"unexpected URL: {req.full_url}")

    with mock.patch.object(aws.urlrequest, "urlopen", side_effect=fake_urlopen):
        creds = harvest_aws_credentials(
            home=tmp_path, include_ec2_metadata=True, include_ecs_metadata=False
        )

    imds = [c for c in creds if c.type == "ec2_instance_metadata"]
    assert len(imds) == 1
    c = imds[0]
    assert c.source == "imds:WebAppRole"
    assert c.extra["role"] == "WebAppRole"
    assert c.extra["expiration"] == "2026-09-01T12:00:00Z"
    assert c.access_key_hash == _sha256(access)
    assert c.secret_hash == _sha256(secret)
    assert c.session_token_hash == _sha256(token)
    dumped = json.dumps(c.to_dict())
    for raw in (access, secret, token):
        assert raw not in dumped


def test_ec2_metadata_timeout_returns_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_env(monkeypatch)

    def raiser(*_a: Any, **_kw: Any) -> Any:
        raise TimeoutError("network timeout")

    with mock.patch.object(aws.urlrequest, "urlopen", side_effect=raiser):
        creds = harvest_aws_credentials(
            home=tmp_path,
            include_ec2_metadata=True,
            include_ecs_metadata=False,
            metadata_timeout=0.01,
        )
    assert [c for c in creds if c.type == "ec2_instance_metadata"] == []


def test_ec2_metadata_urlerror_returns_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_env(monkeypatch)
    from urllib.error import URLError

    with mock.patch.object(
        aws.urlrequest, "urlopen", side_effect=URLError("no route")
    ):
        creds = harvest_aws_credentials(
            home=tmp_path,
            include_ec2_metadata=True,
            include_ecs_metadata=False,
        )
    assert creds == []


def test_ec2_metadata_imdsv1_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Token endpoint denied (IMDSv1 host): harvest still succeeds unauthed."""
    _clean_env(monkeypatch)
    from urllib.error import HTTPError

    def fake_urlopen(req: Any, timeout: float = 0) -> _FakeResponse:
        method = getattr(req, "method", None) or req.get_method()
        if req.full_url.endswith("/api/token") and method == "PUT":
            raise HTTPError(req.full_url, 405, "Method Not Allowed", {}, None)  # type: ignore[arg-type]
        if req.full_url.endswith("/security-credentials/"):
            # IMDSv1: unauthenticated request works.
            assert req.get_header("X-aws-ec2-metadata-token") is None
            return _FakeResponse(b"LegacyRole\n")
        if req.full_url.endswith("/security-credentials/LegacyRole"):
            return _FakeResponse(
                json.dumps(
                    {
                        "AccessKeyId": "ASIALEGACYEXAMPLE",
                        "SecretAccessKey": "legacysecret",
                        "Token": "legacytoken",
                    }
                ).encode()
            )
        raise AssertionError(f"unexpected URL: {req.full_url}")

    with mock.patch.object(aws.urlrequest, "urlopen", side_effect=fake_urlopen):
        creds = harvest_aws_credentials(
            home=tmp_path, include_ec2_metadata=True, include_ecs_metadata=False
        )
    imds = [c for c in creds if c.type == "ec2_instance_metadata"]
    assert len(imds) == 1
    assert imds[0].extra["role"] == "LegacyRole"


# --------------------------------------------------------------------------- #
# Source 5: ECS credential endpoint                                           #
# --------------------------------------------------------------------------- #

def test_ecs_relative_uri_harvest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_env(monkeypatch)
    monkeypatch.setenv(
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/abc123"
    )
    access = "ASIAECSEXAMPLE1234567"
    secret = "ecs-secret-key"
    token = "ecs-session-token"

    def fake_urlopen(req: Any, timeout: float = 0) -> _FakeResponse:
        assert timeout <= 2.0
        assert req.full_url == "http://169.254.170.2/v2/credentials/abc123"
        return _FakeResponse(
            json.dumps(
                {
                    "AccessKeyId": access,
                    "SecretAccessKey": secret,
                    "Token": token,
                    "RoleArn": "arn:aws:iam::555566667777:role/EcsTaskRole",
                    "Expiration": "2026-09-01T13:00:00Z",
                }
            ).encode()
        )

    with mock.patch.object(aws.urlrequest, "urlopen", side_effect=fake_urlopen):
        creds = harvest_aws_credentials(
            home=tmp_path, include_ec2_metadata=False, include_ecs_metadata=True
        )
    ecs = [c for c in creds if c.type == "ecs_container_credentials"]
    assert len(ecs) == 1
    c = ecs[0]
    assert c.source == "ecs:/v2/credentials/abc123"
    assert c.account_id == "555566667777"
    assert c.access_key_hash == _sha256(access)
    assert c.secret_hash == _sha256(secret)
    assert c.session_token_hash == _sha256(token)
    dumped = json.dumps(c.to_dict())
    for raw in (access, secret, token):
        assert raw not in dumped


def test_ecs_full_uri_and_auth_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_env(monkeypatch)
    full = "http://internal.svc.local:8080/creds"
    monkeypatch.setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", full)
    monkeypatch.setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "bearer-abc")

    def fake_urlopen(req: Any, timeout: float = 0) -> _FakeResponse:
        assert req.full_url == full
        assert req.get_header("Authorization") == "bearer-abc"
        return _FakeResponse(
            json.dumps(
                {
                    "AccessKeyId": "ASIAFULLURI",
                    "SecretAccessKey": "s",
                    "Token": "t",
                }
            ).encode()
        )

    with mock.patch.object(aws.urlrequest, "urlopen", side_effect=fake_urlopen):
        creds = harvest_aws_credentials(
            home=tmp_path, include_ec2_metadata=False, include_ecs_metadata=True
        )
    ecs = [c for c in creds if c.type == "ecs_container_credentials"]
    assert len(ecs) == 1
    assert ecs[0].source == f"ecs:{full}"


def test_ecs_no_env_returns_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_env(monkeypatch)
    with mock.patch.object(
        aws.urlrequest, "urlopen", side_effect=AssertionError("no call")
    ):
        creds = harvest_aws_credentials(
            home=tmp_path, include_ec2_metadata=False, include_ecs_metadata=True
        )
    assert creds == []


def test_ecs_timeout_returns_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_env(monkeypatch)
    monkeypatch.setenv(
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/x"
    )

    def raiser(*_a: Any, **_kw: Any) -> Any:
        raise TimeoutError("boom")

    with mock.patch.object(aws.urlrequest, "urlopen", side_effect=raiser):
        creds = harvest_aws_credentials(
            home=tmp_path,
            include_ec2_metadata=False,
            include_ecs_metadata=True,
            metadata_timeout=0.01,
        )
    assert creds == []


# --------------------------------------------------------------------------- #
# Structural / contract                                                       #
# --------------------------------------------------------------------------- #

def test_credential_object_required_fields() -> None:
    c = AWSCredential(type="t", source="s")
    d = c.to_dict()
    for key in (
        "type",
        "source",
        "account_id",
        "access_key_hash",
        "secret_hash",
        "session_token_hash",
    ):
        assert key in d, f"missing required field: {key}"


def test_all_hashes_use_sha256_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_env(monkeypatch)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE1234567890")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "sekret")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "sess")

    creds = harvest_aws_credentials(
        home=tmp_path, include_ec2_metadata=False, include_ecs_metadata=False
    )
    assert creds
    for c in creds:
        for hashed in (c.access_key_hash, c.secret_hash, c.session_token_hash):
            if hashed is None:
                continue
            assert hashed.startswith("sha256:"), hashed
            # 7-char prefix + 64 hex chars.
            assert len(hashed) == 7 + 64


def test_all_five_sources_checked_in_one_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_env(monkeypatch)

    # 1. env
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAENV0000000000000")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "envsecret")

    # 2. credentials file
    _write_credentials_file(
        tmp_path / ".aws" / "credentials",
        (
            "[default]\n"
            "aws_access_key_id = AKIAFILE000000000000\n"
            "aws_secret_access_key = filesecret\n"
        ),
    )

    # 3. config file
    _write_credentials_file(
        tmp_path / ".aws" / "config",
        (
            "[profile assumed]\n"
            "role_arn = arn:aws:iam::111122223333:role/Assumed\n"
            "source_profile = default\n"
        ),
    )

    # 4. ECS
    monkeypatch.setenv(
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/creds/task"
    )

    # 5. EC2 IMDS
    def fake_urlopen(req: Any, timeout: float = 0) -> _FakeResponse:
        method = getattr(req, "method", None) or req.get_method()
        if req.full_url.endswith("/api/token") and method == "PUT":
            return _FakeResponse(b"TOK")
        if req.full_url.endswith("/security-credentials/"):
            return _FakeResponse(b"MyRole\n")
        if req.full_url.endswith("/security-credentials/MyRole"):
            return _FakeResponse(
                json.dumps(
                    {
                        "AccessKeyId": "ASIAIMDS000000000000",
                        "SecretAccessKey": "imdssecret",
                        "Token": "imdstoken",
                    }
                ).encode()
            )
        if req.full_url.endswith("/v2/creds/task"):
            return _FakeResponse(
                json.dumps(
                    {
                        "AccessKeyId": "ASIAECS0000000000000",
                        "SecretAccessKey": "ecssecret",
                        "Token": "ecstoken",
                    }
                ).encode()
            )
        raise AssertionError(f"unexpected URL: {req.full_url}")

    with mock.patch.object(aws.urlrequest, "urlopen", side_effect=fake_urlopen):
        creds = harvest_aws_credentials(
            home=tmp_path, include_ec2_metadata=True, include_ecs_metadata=True
        )

    types = {c.type for c in creds}
    assert types == {
        "env",
        "shared_credentials",
        "assume_role_profile",
        "ec2_instance_metadata",
        "ecs_container_credentials",
    }


def test_one_source_failure_does_not_break_others(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Even if EC2 metadata blows up, env/file/ECS results still surface."""
    _clean_env(monkeypatch)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAOK00000000000000")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "oksecret")

    from urllib.error import URLError

    with mock.patch.object(
        aws.urlrequest, "urlopen", side_effect=URLError("dead")
    ):
        creds = harvest_aws_credentials(
            home=tmp_path, include_ec2_metadata=True, include_ecs_metadata=False
        )
    types = {c.type for c in creds}
    assert "env" in types
    assert "ec2_instance_metadata" not in types


def test_raw_secrets_never_appear_across_all_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_env(monkeypatch)
    secrets = {
        "env_access": "AKIALEAK000000000000",
        "env_secret": "leakedenvsecret",
        "env_session": "leakedenvsession",
        "file_secret": "leakedfilesecret",
        "imds_secret": "leakedimdssecret",
        "imds_token": "leakedimdstoken",
        "ecs_secret": "leakedecssecret",
        "ecs_token": "leakedecstoken",
    }
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", secrets["env_access"])
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", secrets["env_secret"])
    monkeypatch.setenv("AWS_SESSION_TOKEN", secrets["env_session"])
    _write_credentials_file(
        tmp_path / ".aws" / "credentials",
        (
            "[default]\n"
            "aws_access_key_id = AKIAFILE000000000000\n"
            f"aws_secret_access_key = {secrets['file_secret']}\n"
        ),
    )
    monkeypatch.setenv(
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/creds/leak"
    )

    def fake_urlopen(req: Any, timeout: float = 0) -> _FakeResponse:
        method = getattr(req, "method", None) or req.get_method()
        if req.full_url.endswith("/api/token") and method == "PUT":
            return _FakeResponse(b"T")
        if req.full_url.endswith("/security-credentials/"):
            return _FakeResponse(b"R\n")
        if req.full_url.endswith("/security-credentials/R"):
            return _FakeResponse(
                json.dumps(
                    {
                        "AccessKeyId": "ASIAIMDS000000000000",
                        "SecretAccessKey": secrets["imds_secret"],
                        "Token": secrets["imds_token"],
                    }
                ).encode()
            )
        if req.full_url.endswith("/v2/creds/leak"):
            return _FakeResponse(
                json.dumps(
                    {
                        "AccessKeyId": "ASIAECS0000000000000",
                        "SecretAccessKey": secrets["ecs_secret"],
                        "Token": secrets["ecs_token"],
                    }
                ).encode()
            )
        raise AssertionError(req.full_url)

    with mock.patch.object(aws.urlrequest, "urlopen", side_effect=fake_urlopen):
        creds = harvest_aws_credentials(
            home=tmp_path, include_ec2_metadata=True, include_ecs_metadata=True
        )

    dumped = json.dumps([c.to_dict() for c in creds])
    for name, raw in secrets.items():
        assert raw not in dumped, f"raw secret leaked ({name})"
