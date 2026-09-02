"""Unit tests for :mod:`forge.ingestion.schemas.bloodhound`.

Coverage:
* SharpHoundSession -- valid + timestamp forms + bad SID rejection.
* AzureHoundObject   -- raw AzureHound envelope + kind/GUID rejection.
* BloodHoundContainer -- valid entry + child validation + bad OID.
* BloodHoundFile     -- meta.count invariant.
* BloodHoundZipManifest -- accepted layouts + unsafe/unknown member reject.
* Roundtrip: parse -> model_dump -> re-parse produces an equivalent model.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from forge.ingestion.schemas import (
    AzureHoundObject,
    BloodHoundContainer,
    BloodHoundFile,
    BloodHoundZipManifest,
    SharpHoundSession,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_VALID_SID = "S-1-5-21-1111111111-2222222222-3333333333-1105"
_VALID_COMPUTER_SID = "S-1-5-21-1111111111-2222222222-3333333333-1002"
_VALID_AZURE_ID = "11111111-2222-3333-4444-555555555555"
_VALID_TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_VALID_APP_ID = "99999999-8888-7777-6666-555555555555"
_VALID_GUID_CONTAINER = "{fedcba98-7654-3210-fedc-ba9876543210}"


@pytest.fixture
def sharphound_session_raw() -> dict[str, object]:
    return {
        "UserName": "alice@CONTOSO.LOCAL",
        "UserSID": _VALID_SID,
        "ComputerSID": _VALID_COMPUTER_SID,
        "LogonType": 3,
        "Timestamp": 1_700_000_000,
    }


@pytest.fixture
def azurehound_user_raw() -> dict[str, object]:
    return {
        "kind": "AZUser",
        "data": {
            "id": _VALID_AZURE_ID,
            "displayName": "Alice Example",
            "tenantId": _VALID_TENANT_ID,
            "userPrincipalName": "alice@contoso.onmicrosoft.com",
            "createdDateTime": "2026-06-01T12:34:56Z",
        },
    }


@pytest.fixture
def container_raw() -> dict[str, object]:
    return {
        "ObjectIdentifier": _VALID_GUID_CONTAINER,
        "Properties": {
            "name": "USERS",
            "domain": "CONTOSO.LOCAL",
            "distinguishedname": "CN=Users,DC=contoso,DC=local",
            "highvalue": False,
        },
        "ChildObjects": [
            {"ObjectIdentifier": _VALID_SID, "ObjectType": "User"},
            {"ObjectIdentifier": _VALID_COMPUTER_SID, "ObjectType": "Computer"},
        ],
        "Aces": [],
        "IsDeleted": False,
        "IsACLProtected": True,
    }


# ---------------------------------------------------------------------------
# SharpHoundSession
# ---------------------------------------------------------------------------


class TestSharpHoundSession:
    def test_parses_valid_entry(self, sharphound_session_raw: dict[str, object]) -> None:
        session = SharpHoundSession.model_validate(sharphound_session_raw)
        assert session.user_name == "alice@CONTOSO.LOCAL"
        assert session.user_sid == _VALID_SID
        assert session.computer_sid == _VALID_COMPUTER_SID
        assert session.logon_type == 3
        assert session.timestamp == datetime.fromtimestamp(
            1_700_000_000, tz=timezone.utc,
        )
        assert session.timestamp.tzinfo is timezone.utc

    def test_accepts_iso_timestamp(self, sharphound_session_raw: dict[str, object]) -> None:
        sharphound_session_raw["Timestamp"] = "2026-06-01T00:00:00Z"
        session = SharpHoundSession.model_validate(sharphound_session_raw)
        assert session.timestamp.tzinfo is timezone.utc
        assert session.timestamp.year == 2026

    def test_rejects_bad_sid(self, sharphound_session_raw: dict[str, object]) -> None:
        sharphound_session_raw["ComputerSID"] = "not-a-sid"
        with pytest.raises(ValidationError) as exc:
            SharpHoundSession.model_validate(sharphound_session_raw)
        assert "invalid SID" in str(exc.value)

    def test_rejects_zero_timestamp(self, sharphound_session_raw: dict[str, object]) -> None:
        sharphound_session_raw["Timestamp"] = 0
        with pytest.raises(ValidationError):
            SharpHoundSession.model_validate(sharphound_session_raw)

    def test_rejects_negative_logon_type(self, sharphound_session_raw: dict[str, object]) -> None:
        sharphound_session_raw["LogonType"] = -1
        with pytest.raises(ValidationError):
            SharpHoundSession.model_validate(sharphound_session_raw)


# ---------------------------------------------------------------------------
# AzureHoundObject
# ---------------------------------------------------------------------------


class TestAzureHoundObject:
    def test_parses_raw_envelope(self, azurehound_user_raw: dict[str, object]) -> None:
        obj = AzureHoundObject.model_validate(azurehound_user_raw)
        assert obj.kind == "AZUser"
        assert obj.object_id == _VALID_AZURE_ID
        assert obj.tenant_id == _VALID_TENANT_ID
        assert obj.display_name == "Alice Example"
        assert obj.created_at is not None
        assert obj.created_at.tzinfo is timezone.utc
        assert obj.data["userPrincipalName"] == "alice@contoso.onmicrosoft.com"

    def test_service_principal_lifts_app_id(self) -> None:
        raw = {
            "kind": "AZServicePrincipal",
            "data": {
                "id": _VALID_AZURE_ID,
                "appId": _VALID_APP_ID,
                "displayName": "svc-app",
                "tenantId": _VALID_TENANT_ID,
            },
        }
        obj = AzureHoundObject.model_validate(raw)
        assert obj.app_id == _VALID_APP_ID

    def test_rejects_unknown_kind(self, azurehound_user_raw: dict[str, object]) -> None:
        azurehound_user_raw["kind"] = "AZFakeThing"
        with pytest.raises(ValidationError) as exc:
            AzureHoundObject.model_validate(azurehound_user_raw)
        assert "unsupported AzureHound kind" in str(exc.value)

    def test_rejects_bad_guid(self, azurehound_user_raw: dict[str, object]) -> None:
        raw = dict(azurehound_user_raw)
        payload = dict(raw["data"])  # type: ignore[arg-type]
        payload["id"] = "not-a-guid"
        raw["data"] = payload
        with pytest.raises(ValidationError) as exc:
            AzureHoundObject.model_validate(raw)
        assert "invalid Azure GUID" in str(exc.value)

    def test_missing_data_block_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc:
            AzureHoundObject.model_validate({"kind": "AZUser"})
        assert "missing ``data``" in str(exc.value)


# ---------------------------------------------------------------------------
# BloodHoundContainer
# ---------------------------------------------------------------------------


class TestBloodHoundContainer:
    def test_parses_valid_container(self, container_raw: dict[str, object]) -> None:
        container = BloodHoundContainer.model_validate(container_raw)
        assert container.object_identifier == _VALID_GUID_CONTAINER
        assert container.properties.name == "USERS"
        assert container.properties.domain == "CONTOSO.LOCAL"
        assert len(container.child_objects) == 2
        assert container.child_objects[0].object_type == "User"
        assert container.is_acl_protected is True

    def test_rejects_bad_child_object_type(self, container_raw: dict[str, object]) -> None:
        children = list(container_raw["ChildObjects"])  # type: ignore[arg-type]
        children.append({"ObjectIdentifier": _VALID_SID, "ObjectType": "Bogus"})
        container_raw["ChildObjects"] = children
        with pytest.raises(ValidationError) as exc:
            BloodHoundContainer.model_validate(container_raw)
        assert "unknown ObjectType" in str(exc.value)

    def test_rejects_bad_object_identifier(self, container_raw: dict[str, object]) -> None:
        container_raw["ObjectIdentifier"] = "definitely not a sid"
        with pytest.raises(ValidationError) as exc:
            BloodHoundContainer.model_validate(container_raw)
        assert "invalid AD ObjectIdentifier" in str(exc.value)


# ---------------------------------------------------------------------------
# BloodHoundFile envelope
# ---------------------------------------------------------------------------


class TestBloodHoundFile:
    def test_meta_count_matches_data_length(self) -> None:
        env = BloodHoundFile.model_validate(
            {
                "meta": {"type": "sessions", "count": 2, "version": 5},
                "data": [{"x": 1}, {"x": 2}],
            },
        )
        assert env.meta.count == 2

    def test_meta_count_mismatch_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc:
            BloodHoundFile.model_validate(
                {
                    "meta": {"type": "sessions", "count": 5, "version": 5},
                    "data": [{"x": 1}],
                },
            )
        assert "does not match" in str(exc.value)


# ---------------------------------------------------------------------------
# BloodHoundZipManifest
# ---------------------------------------------------------------------------


class TestBloodHoundZipManifest:
    def test_valid_bloodhound_layout(self) -> None:
        manifest = BloodHoundZipManifest.model_validate(
            {"members": ["users.json", "groups.json", "sessions.json"]},
        )
        assert manifest.export_kind == "bloodhound"

    def test_azurehound_only_layout(self) -> None:
        manifest = BloodHoundZipManifest.model_validate(
            {"members": ["azureusers.json", "azuregroups.json"]},
        )
        assert manifest.export_kind == "azurehound"

    def test_mixed_layout(self) -> None:
        manifest = BloodHoundZipManifest.model_validate(
            {"members": ["users.json", "azureusers.json"]},
        )
        assert manifest.export_kind == "mixed"

    def test_rejects_path_traversal(self) -> None:
        with pytest.raises(ValidationError) as exc:
            BloodHoundZipManifest.model_validate(
                {"members": ["../etc/passwd"]},
            )
        assert "unsafe zip member" in str(exc.value)

    def test_rejects_unknown_file(self) -> None:
        with pytest.raises(ValidationError) as exc:
            BloodHoundZipManifest.model_validate(
                {"members": ["random.json"]},
            )
        assert "unrecognised BloodHound file" in str(exc.value)

    def test_rejects_empty_zip(self) -> None:
        with pytest.raises(ValidationError):
            BloodHoundZipManifest.model_validate({"members": []})


# ---------------------------------------------------------------------------
# Roundtrip
# ---------------------------------------------------------------------------


class TestRoundtrip:
    def test_session_roundtrip(self, sharphound_session_raw: dict[str, object]) -> None:
        original = SharpHoundSession.model_validate(sharphound_session_raw)
        exported = original.model_dump(by_alias=True, mode="json")
        again = SharpHoundSession.model_validate(exported)
        assert again == original

    def test_azurehound_roundtrip(self, azurehound_user_raw: dict[str, object]) -> None:
        original = AzureHoundObject.model_validate(azurehound_user_raw)
        exported = original.model_dump(mode="json")
        # Exported form is already flattened, so re-parse must accept it.
        again = AzureHoundObject.model_validate(exported)
        assert again.object_id == original.object_id
        assert again.kind == original.kind
        assert again.tenant_id == original.tenant_id
        assert again.created_at == original.created_at

    def test_container_roundtrip(self, container_raw: dict[str, object]) -> None:
        original = BloodHoundContainer.model_validate(container_raw)
        exported = original.model_dump(by_alias=True, mode="json")
        again = BloodHoundContainer.model_validate(exported)
        assert again == original
