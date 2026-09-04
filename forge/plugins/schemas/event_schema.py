"""JSON Schema definitions for plugin event bus events (E2.3).

Four event types map to the boundary contract from E2.1:

    - ArtifactDiscoveredSchema: emitted when a plugin discovers an artifact
    - GraphUpdatedSchema: emitted when the knowledge graph is mutated
    - ReportGeneratedSchema: emitted when a report artifact is produced
    - CollectionProgressSchema: emitted when collection progress changes

Every event on the bus must include an "event_type" discriminator and a
"payload" object matching the schema for that type. Forbidden fields
(secrets) must never appear anywhere in the payload; payload size is
capped at 10 KiB.
"""

from __future__ import annotations

from typing import Any, Final

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_PAYLOAD_BYTES: Final[int] = 10240
"""Hard upper bound on serialized payload size in bytes (10 KiB)."""

MAX_PAYLOAD_KEYS: Final[int] = 50
"""Hard upper bound on keys across the complete payload tree."""

MAX_NESTING_DEPTH: Final[int] = 5
"""Hard upper bound on payload container nesting, including the payload root."""

FORBIDDEN_FIELD_PATTERNS: Final[frozenset[str]] = frozenset(
    {
        # Spec §4 (docs/specs/plugin_boundary_v1.md:166): case-insensitive
        # substring match on any key at any depth. Catches 'access_token',
        # 'database_password', 'MY_API_KEY', 'x-private-cert', etc.
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "api-key",
        "credential",
        "private",
        "auth",
    }
)
"""Substring patterns that must never appear in any payload key.

Matching is case-insensitive substring at every nesting depth per spec §4.
A key like 'my_access_token_value' is rejected because it contains 'token'.
'access_token' -> 'token'; 'database_password' -> 'password'; 'auth_header'
-> 'auth'; 'private_key_pem' -> 'private'/'private_key'.
"""

# Backward-compatible alias for callers that still import the old name.
FORBIDDEN_FIELDS: Final[frozenset[str]] = FORBIDDEN_FIELD_PATTERNS


# ---------------------------------------------------------------------------
# JSON Schema fragments
# ---------------------------------------------------------------------------

_TIMESTAMP_SCHEMA: Final[dict[str, Any]] = {
    "type": "string",
    "format": "date-time",
    "description": "ISO 8601 timestamp (UTC) marking when the event was emitted.",
    "minLength": 1,
}

_ID_SCHEMA: Final[dict[str, Any]] = {
    "type": "string",
    "minLength": 1,
    "maxLength": 256,
}


# ---------------------------------------------------------------------------
# ArtifactDiscoveredSchema
# ---------------------------------------------------------------------------

ArtifactDiscoveredSchema: Final[dict[str, Any]] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "ArtifactDiscovered",
    "type": "object",
    "additionalProperties": False,
    "maxProperties": MAX_PAYLOAD_KEYS,
    "required": ["artifact_id", "artifact_type", "source", "discovered_at"],
    "properties": {
        "artifact_id": {
            "type": "integer",
            "minimum": 1,
            "description": "Stable identifier for the discovered artifact.",
        },
        "artifact_type": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "description": "Canonical artifact type (e.g., 'host', 'url', 'email').",
        },
        "source": {
            "type": "string",
            "minLength": 1,
            "maxLength": 256,
            "description": "Plugin or module that discovered the artifact.",
        },
        "discovered_at": _TIMESTAMP_SCHEMA,
    },
}


# ---------------------------------------------------------------------------
# GraphUpdatedSchema
# ---------------------------------------------------------------------------

GraphUpdatedSchema: Final[dict[str, Any]] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "GraphUpdated",
    "type": "object",
    "additionalProperties": False,
    "maxProperties": MAX_PAYLOAD_KEYS,
    "required": ["node_id", "node_type", "operation"],
    "properties": {
        "node_id": {
            **_ID_SCHEMA,
            "description": "Identifier of the affected graph node.",
        },
        "node_type": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "description": "Node type (e.g., 'asset', 'finding', 'owner').",
        },
        "operation": {
            "type": "string",
            "enum": ["created", "updated", "removed"],
            "description": "Mutation applied to the node.",
        },
    },
}


# ---------------------------------------------------------------------------
# ReportGeneratedSchema
# ---------------------------------------------------------------------------

ReportGeneratedSchema: Final[dict[str, Any]] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "ReportGenerated",
    "type": "object",
    "additionalProperties": False,
    "maxProperties": MAX_PAYLOAD_KEYS,
    "required": ["report_type", "engagement_id", "path"],
    "properties": {
        "report_type": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "description": "Report family or template identifier.",
        },
        "engagement_id": {
            "type": "integer",
            "minimum": 1,
            "description": "Engagement the report belongs to.",
        },
        "path": {
            "type": "string",
            "minLength": 1,
            "maxLength": 1024,
            "description": "Relative path to the report artifact in the engagement workspace.",
        },
    },
}


# ---------------------------------------------------------------------------
# CollectionProgressSchema
# ---------------------------------------------------------------------------

CollectionProgressSchema: Final[dict[str, Any]] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "CollectionProgress",
    "type": "object",
    "additionalProperties": False,
    "maxProperties": MAX_PAYLOAD_KEYS,
    "required": ["collection_id", "progress", "state", "message"],
    "properties": {
        "collection_id": {
            **_ID_SCHEMA,
            "description": "Stable identifier for the collection or scan.",
        },
        "progress": {
            "type": "integer",
            "minimum": 0,
            "maximum": 100,
        },
        "state": {
            "type": "string",
            "enum": ["pending", "running", "completed", "failed"],
        },
        "message": {
            "type": "string",
            "maxLength": 280,
        },
    },
}


# ---------------------------------------------------------------------------
# Event type registry
# ---------------------------------------------------------------------------

EVENT_SCHEMAS: Final[dict[str, dict[str, Any]]] = {
    "artifact:discovered": ArtifactDiscoveredSchema,
    "graph:updated": GraphUpdatedSchema,
    "report:generated": ReportGeneratedSchema,
    "collection:progress": CollectionProgressSchema,
}
"""Mapping of event_type discriminator -> JSON Schema for its payload."""


__all__ = [
    "ArtifactDiscoveredSchema",
    "CollectionProgressSchema",
    "GraphUpdatedSchema",
    "ReportGeneratedSchema",
    "EVENT_SCHEMAS",
    "FORBIDDEN_FIELDS",
    "FORBIDDEN_FIELD_PATTERNS",
    "MAX_NESTING_DEPTH",
    "MAX_PAYLOAD_BYTES",
    "MAX_PAYLOAD_KEYS",
]
