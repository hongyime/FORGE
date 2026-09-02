"""JSON Schema definitions for plugin event bus events (E2.3).

Three event types map to the boundary contract from E2.1:

    - ArtifactDiscoveredSchema: emitted when a plugin discovers an artifact
    - GraphUpdatedSchema: emitted when the knowledge graph is mutated
    - ReportGeneratedSchema: emitted when a report artifact is produced

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

FORBIDDEN_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "api_key",
        "apikey",
        "api-key",
        "access_token",
        "refresh_token",
        "auth_token",
        "bearer_token",
        "private_key",
        "privatekey",
        "credentials",
        "authorization",
        "session_token",
        "client_secret",
    }
)
"""Field names that must never appear on any event payload.

Matching is case-insensitive and applies at every nesting depth.
Presence of any listed name (top-level or nested) rejects the event.
"""


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
    "required": ["artifact_id", "artifact_type", "source", "timestamp"],
    "properties": {
        "artifact_id": {
            **_ID_SCHEMA,
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
        "timestamp": _TIMESTAMP_SCHEMA,
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
    "required": ["node_id", "node_type", "operation", "timestamp"],
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
            "enum": ["create", "update", "delete"],
            "description": "Mutation applied to the node.",
        },
        "timestamp": _TIMESTAMP_SCHEMA,
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
    "required": ["report_type", "engagement_id", "output_path"],
    "properties": {
        "report_type": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "description": "Report family or template identifier.",
        },
        "engagement_id": {
            "type": ["integer", "string"],
            "description": "Engagement the report belongs to.",
        },
        "output_path": {
            "type": "string",
            "minLength": 1,
            "maxLength": 1024,
            "description": "Filesystem path (relative or absolute) to the report artifact.",
        },
        "timestamp": _TIMESTAMP_SCHEMA,
    },
}


# ---------------------------------------------------------------------------
# Event type registry
# ---------------------------------------------------------------------------

EVENT_SCHEMAS: Final[dict[str, dict[str, Any]]] = {
    "artifact_discovered": ArtifactDiscoveredSchema,
    "graph_updated": GraphUpdatedSchema,
    "report_generated": ReportGeneratedSchema,
}
"""Mapping of event_type discriminator -> JSON Schema for its payload."""


__all__ = [
    "ArtifactDiscoveredSchema",
    "GraphUpdatedSchema",
    "ReportGeneratedSchema",
    "EVENT_SCHEMAS",
    "FORBIDDEN_FIELDS",
    "MAX_PAYLOAD_BYTES",
]
