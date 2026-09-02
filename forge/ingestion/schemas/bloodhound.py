"""Pydantic v2 schemas for BloodHound / SharpHound / AzureHound imports.

BloodHound exports arrive as a ``.zip`` containing several JSON files:

    users.json, groups.json, computers.json, ous.json, domains.json,
    gpos.json, containers.json, sessions.json, azure*.json

Every JSON has the same shape::

    {
      "meta": {"type": "<collection>", "count": N, "version": M,
                "methods": <int>},
      "data": [ ... ]
    }

The classes in this module cover only U1.1's required entries:

* :class:`SharpHoundSession`   -- one row of ``sessions.json``.
* :class:`AzureHoundObject`    -- one row from an ``azure*.json`` file.
* :class:`BloodHoundContainer` -- one row of ``containers.json``.

Companion helpers:

* :class:`BloodHoundMeta`         -- validates the shared ``meta`` block.
* :class:`BloodHoundFile`         -- validates the ``{meta, data}`` envelope.
* :class:`BloodHoundZipManifest`  -- validates that a zip's file set is
  the one a BloodHound export is supposed to contain.

Edge-model classes (``ACE``, ``GroupMember``, ``LocalGroup`` etc.) are
intentionally out of scope for U1.1 and will land in Phase 2.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Annotated, Any, ClassVar, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

# Windows / AD SID.  RID-relative forms like ``S-1-5-21-...-1105`` are the
# common ones we care about, but SharpHound also emits well-known short SIDs
# (``S-1-5-11``) for authenticated users and similar built-ins.
_SID_RE = re.compile(r"^S-1-\d+(?:-\d+)*$")

# Azure directory object ID -- always a lowercase-hex UUID.
_AZURE_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# ``ObjectIdentifier`` for AD containers is either a SID or a stable
# GUID-in-braces form emitted for OUs/containers without a resolvable SID.
_GUID_RE = re.compile(
    r"^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$"
)

# ObjectType values BloodHound emits for child references inside a container.
_AD_OBJECT_TYPES: frozenset[str] = frozenset({
    "User", "Group", "Computer", "OU", "GPO", "Domain", "Container", "Base",
})

# AzureHound "kind" tags accepted by U1.1.
_AZURE_KINDS: frozenset[str] = frozenset({
    "AZUser",
    "AZGroup",
    "AZServicePrincipal",
    "AZApp",
    "AZDevice",
    "AZTenant",
    "AZSubscription",
    "AZResourceGroup",
    "AZManagementGroup",
})

# Files a well-formed BloodHound zip export MAY contain.  The zip is
# considered valid if it contains at least one recognised file and every
# member is on this list.
_BH_ZIP_MEMBERS: frozenset[str] = frozenset({
    "users.json",
    "groups.json",
    "computers.json",
    "ous.json",
    "domains.json",
    "gpos.json",
    "containers.json",
    "sessions.json",
    "azure.json",
    "azuregroups.json",
    "azureusers.json",
    "azuredevices.json",
    "azureapps.json",
    "azureserviceprincipals.json",
    "azuretenants.json",
    "azuresubscriptions.json",
    "azureresourcegroups.json",
    "azuremanagementgroups.json",
})

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_bh_timestamp(value: Any) -> datetime:
    """Parse a BloodHound timestamp into an aware UTC ``datetime``.

    BloodHound tools serialise timestamps in three shapes:

    * Unix seconds as ``int`` (SharpHound sessions),
    * Unix seconds as a numeric ``str`` (older ADCS collectors),
    * ISO-8601 string with optional ``Z`` suffix (AzureHound).

    An unset field is signalled by the sentinel ``-1`` or ``0`` -- we
    reject both, forcing callers to use ``Optional`` fields with an
    explicit ``None`` when a value is genuinely missing.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, bool):  # bool is an int subclass -- exclude first
        raise ValueError("timestamp must not be a bool")
    if isinstance(value, (int, float)):
        if value <= 0:
            raise ValueError(f"non-positive timestamp: {value!r}")
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise ValueError("empty timestamp string")
        if raw.lstrip("-").isdigit() or _looks_numeric(raw):
            secs = float(raw)
            if secs <= 0:
                raise ValueError(f"non-positive timestamp: {value!r}")
            return datetime.fromtimestamp(secs, tz=timezone.utc)
        iso = raw.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(iso)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    raise ValueError(f"unsupported timestamp type: {type(value).__name__}")


def _looks_numeric(raw: str) -> bool:
    try:
        float(raw)
    except ValueError:
        return False
    return True


def _validate_ad_object_id(value: str) -> str:
    """Accept a SID or a ``{GUID}`` container ID; reject anything else."""
    stripped = value.strip()
    if not stripped:
        raise ValueError("empty ObjectIdentifier")
    if _SID_RE.match(stripped) or _GUID_RE.match(stripped):
        return stripped
    raise ValueError(
        f"invalid AD ObjectIdentifier {stripped!r}: expected SID (S-1-...) "
        "or {GUID}",
    )


# ---------------------------------------------------------------------------
# Shared envelope
# ---------------------------------------------------------------------------


class BloodHoundMeta(BaseModel):
    """Meta block shared by every BloodHound JSON file.

    Field mapping:
        * ``type``    -> BloodHound collection name (``sessions``,
          ``containers``, ``azureusers`` ...).
        * ``count``   -> length of the paired ``data`` array.
        * ``version`` -> SharpHound / AzureHound schema version integer.
        * ``methods`` -> bitmask of collection methods; optional (only
          present in SharpHound v5+).
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    type: str = Field(min_length=1)
    count: int = Field(ge=0)
    version: int = Field(ge=1)
    methods: int | None = Field(default=None, ge=0)


class BloodHoundFile(BaseModel):
    """Generic ``{meta, data}`` envelope produced by every BloodHound file.

    U1.1 validates only the envelope shape and the ``meta.count`` <->
    ``len(data)`` invariant.  Per-row parsing is done by the caller with
    the type-specific model (``SharpHoundSession`` etc.), which lets the
    ingest pipeline stream large arrays without loading every row through
    Pydantic when the operator has explicitly opted into fast-path mode.
    """

    model_config = ConfigDict(extra="forbid")

    meta: BloodHoundMeta
    data: list[dict[str, Any]]

    @model_validator(mode="after")
    def _count_matches(self) -> BloodHoundFile:
        if self.meta.count != len(self.data):
            raise ValueError(
                f"meta.count={self.meta.count} does not match "
                f"len(data)={len(self.data)}",
            )
        return self


# ---------------------------------------------------------------------------
# SharpHound sessions.json
# ---------------------------------------------------------------------------


class SharpHoundSession(BaseModel):
    """One entry from a SharpHound ``sessions.json`` payload.

    Field mapping (SharpHound source field -> model field):

        UserName / User        -> :attr:`user_name`
        UserSID / UserId       -> :attr:`user_sid`
        ComputerSID / ComputerId -> :attr:`computer_sid`
        LogonType              -> :attr:`logon_type`
        Timestamp              -> :attr:`timestamp` (Unix seconds -> UTC)

    ``LogonType`` uses the Windows logon-type integer (2=interactive,
    3=network, 10=RemoteInteractive, ...).  ``0`` is a valid SharpHound
    value meaning "not reported".
    """

    model_config = ConfigDict(
        extra="ignore",
        populate_by_name=True,
        str_strip_whitespace=True,
    )

    user_name: str | None = Field(
        default=None,
        alias="UserName",
        description="UPN-style user name (``user@DOMAIN``); optional pre-v4.",
    )
    user_sid: str | None = Field(
        default=None,
        alias="UserSID",
        description="Security identifier of the interactive user.",
    )
    computer_sid: str = Field(
        alias="ComputerSID",
        description="Security identifier of the source computer.",
    )
    logon_type: int = Field(
        alias="LogonType",
        ge=0,
        description="Windows logon-type integer.",
    )
    timestamp: datetime = Field(
        alias="Timestamp",
        description="UTC datetime the session was observed.",
    )

    @field_validator("user_sid", "computer_sid")
    @classmethod
    def _validate_sid(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            return None
        if not _SID_RE.match(stripped):
            raise ValueError(f"invalid SID: {value!r}")
        return stripped

    @field_validator("timestamp", mode="before")
    @classmethod
    def _validate_timestamp(cls, value: Any) -> datetime:
        return _parse_bh_timestamp(value)


# ---------------------------------------------------------------------------
# AzureHound objects
# ---------------------------------------------------------------------------


class AzureHoundObject(BaseModel):
    """One Azure AD object emitted by AzureHound.

    AzureHound writes each entry as::

        {"kind": "AZUser", "data": {"id": "...", "displayName": "...", ...}}

    Field mapping (AzureHound source -> model field):

        kind             -> :attr:`kind`
        data.id          -> :attr:`object_id`
        data.appId       -> :attr:`app_id`         (service principals / apps)
        data.displayName -> :attr:`display_name`
        data.tenantId    -> :attr:`tenant_id`
        data.createdDateTime | data.whenCreated
                         -> :attr:`created_at`     (optional, UTC)
        data (whole)     -> :attr:`data`           (raw payload preserved)
    """

    model_config = ConfigDict(
        extra="ignore",
        str_strip_whitespace=True,
    )

    kind: str = Field(description="AzureHound object kind (``AZUser`` ...).")
    object_id: str = Field(description="Azure directory object GUID.")
    tenant_id: str | None = Field(
        default=None, description="Azure tenant GUID (optional pre-v2).",
    )
    app_id: str | None = Field(
        default=None,
        description="Application (client) GUID for AZApp / AZServicePrincipal.",
    )
    display_name: str | None = Field(default=None)
    created_at: datetime | None = Field(default=None)
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Raw AzureHound ``data`` payload (kept for enrichment).",
    )

    _AZURE_KINDS: ClassVar[frozenset[str]] = _AZURE_KINDS

    @field_validator("kind")
    @classmethod
    def _validate_kind(cls, value: str) -> str:
        if value not in _AZURE_KINDS:
            raise ValueError(
                f"unsupported AzureHound kind {value!r}; expected one of "
                f"{sorted(_AZURE_KINDS)}",
            )
        return value

    @field_validator("object_id", "tenant_id", "app_id")
    @classmethod
    def _validate_guid(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            return None
        if not _AZURE_ID_RE.match(stripped):
            raise ValueError(f"invalid Azure GUID: {value!r}")
        return stripped.lower()

    @field_validator("created_at", mode="before")
    @classmethod
    def _validate_created_at(cls, value: Any) -> datetime | None:
        if value is None or value == "":
            return None
        return _parse_bh_timestamp(value)

    @model_validator(mode="before")
    @classmethod
    def _lift_nested_payload(cls, value: Any) -> Any:
        """Accept the raw ``{"kind": ..., "data": {...}}`` AzureHound shape.

        Pydantic gets the top-level object; we hoist ``data.id``,
        ``data.appId``, ``data.displayName``, ``data.tenantId``, and
        ``data.createdDateTime`` into the model's own fields so callers do
        not have to reshape upstream JSON.
        """
        if not isinstance(value, dict):
            return value
        # If the caller already flattened the payload, do nothing.
        if "object_id" in value:
            return value
        payload = value.get("data")
        if not isinstance(payload, dict):
            raise ValueError("AzureHound entry missing ``data`` object")
        object_id = payload.get("id") or payload.get("objectId")
        if object_id is None:
            raise ValueError("AzureHound entry missing ``data.id``")
        created = (
            payload.get("createdDateTime")
            or payload.get("whenCreated")
            or payload.get("CreatedDateTime")
        )
        return {
            "kind": value.get("kind"),
            "object_id": object_id,
            "tenant_id": payload.get("tenantId") or payload.get("TenantId"),
            "app_id": payload.get("appId") or payload.get("AppId"),
            "display_name": (
                payload.get("displayName") or payload.get("DisplayName")
            ),
            "created_at": created,
            "data": payload,
        }


# ---------------------------------------------------------------------------
# containers.json
# ---------------------------------------------------------------------------


class BloodHoundContainerChild(BaseModel):
    """Reference to a child object inside a container.

    Mirrors SharpHound's ``ChildObjects[i]`` shape: an ``ObjectIdentifier``
    (SID or ``{GUID}``) plus a coarse ``ObjectType`` tag.
    """

    model_config = ConfigDict(
        extra="ignore",
        populate_by_name=True,
        frozen=True,
    )

    object_identifier: str = Field(alias="ObjectIdentifier")
    object_type: str = Field(alias="ObjectType")

    @field_validator("object_identifier")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        return _validate_ad_object_id(value)

    @field_validator("object_type")
    @classmethod
    def _validate_type(cls, value: str) -> str:
        if value not in _AD_OBJECT_TYPES:
            raise ValueError(
                f"unknown ObjectType {value!r}; expected one of "
                f"{sorted(_AD_OBJECT_TYPES)}",
            )
        return value


class BloodHoundContainerProperties(BaseModel):
    """Properties block inside a container entry."""

    model_config = ConfigDict(
        extra="allow",
        str_strip_whitespace=True,
    )

    name: str = Field(min_length=1)
    domain: str = Field(min_length=1)
    distinguishedname: str | None = Field(default=None)
    highvalue: bool = Field(default=False)


class BloodHoundContainer(BaseModel):
    """One entry from a BloodHound ``containers.json`` payload.

    Field mapping:

        ObjectIdentifier -> :attr:`object_identifier`
        Properties       -> :attr:`properties`
        ChildObjects     -> :attr:`child_objects` (may be ``[]``)
        Aces             -> :attr:`aces`  (opaque list; edge parsing in Phase 2)
        IsDeleted        -> :attr:`is_deleted`
        IsACLProtected   -> :attr:`is_acl_protected`
    """

    model_config = ConfigDict(
        extra="ignore",
        populate_by_name=True,
    )

    object_identifier: str = Field(alias="ObjectIdentifier")
    properties: BloodHoundContainerProperties = Field(alias="Properties")
    child_objects: list[BloodHoundContainerChild] = Field(
        default_factory=list, alias="ChildObjects",
    )
    aces: list[dict[str, Any]] = Field(default_factory=list, alias="Aces")
    is_deleted: bool = Field(default=False, alias="IsDeleted")
    is_acl_protected: bool = Field(default=False, alias="IsACLProtected")

    @field_validator("object_identifier")
    @classmethod
    def _validate_object_id(cls, value: str) -> str:
        return _validate_ad_object_id(value)


# ---------------------------------------------------------------------------
# Zip-level manifest
# ---------------------------------------------------------------------------


class BloodHoundZipManifest(BaseModel):
    """Validated view of a BloodHound export zip's file set.

    Callers pass the list of member filenames (basename, lowercase) from a
    ``zipfile.ZipFile`` instance; the model checks that:

    * the zip is non-empty,
    * every entry is one of the recognised BloodHound files, and
    * at least one recognised file is present.

    The validator refuses path traversal, absolute paths, and any nested
    directory components -- BloodHound zips are always flat.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    members: Annotated[list[str], Field(min_length=1)]
    export_kind: Literal["bloodhound", "azurehound", "mixed"] = "bloodhound"

    @field_validator("members")
    @classmethod
    def _validate_members(cls, value: list[str]) -> list[str]:
        normalised: list[str] = []
        for raw in value:
            if not isinstance(raw, str) or not raw:
                raise ValueError(f"invalid zip member: {raw!r}")
            if "/" in raw or "\\" in raw or raw.startswith("."):
                raise ValueError(f"unsafe zip member path: {raw!r}")
            lowered = raw.lower()
            if lowered not in _BH_ZIP_MEMBERS:
                raise ValueError(
                    f"unrecognised BloodHound file {raw!r}; expected one of "
                    f"{sorted(_BH_ZIP_MEMBERS)}",
                )
            normalised.append(lowered)
        if not normalised:
            raise ValueError("BloodHound zip contains no recognised files")
        return normalised

    @model_validator(mode="after")
    def _classify(self) -> BloodHoundZipManifest:
        has_ad = any(not m.startswith("azure") for m in self.members)
        has_az = any(m.startswith("azure") for m in self.members)
        object.__setattr__(
            self,
            "export_kind",
            "mixed" if has_ad and has_az else ("azurehound" if has_az else "bloodhound"),
        )
        return self


__all__ = [
    "AzureHoundObject",
    "BloodHoundContainer",
    "BloodHoundContainerChild",
    "BloodHoundContainerProperties",
    "BloodHoundFile",
    "BloodHoundMeta",
    "BloodHoundZipManifest",
    "SharpHoundSession",
]
