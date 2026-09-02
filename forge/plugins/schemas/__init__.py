"""Event schema validation for the plugin event bus (E2.3).

Enforces the boundary contract from E2.1 by validating every event
published on the plugin event bus against a JSON Schema, rejecting
forbidden fields (secrets), and capping payload size.

Public API:
    - ArtifactDiscoveredSchema, GraphUpdatedSchema, ReportGeneratedSchema
    - EVENT_SCHEMAS: mapping of event type -> JSON Schema
    - FORBIDDEN_FIELDS: set of field names that must never appear
    - MAX_PAYLOAD_BYTES: hard payload size ceiling (10240)
    - ValidationResult: outcome of validate_event
    - validate_event(event) -> ValidationResult
    - check_forbidden_fields(payload) -> list[str]
    - validate_payload_size(payload, max_bytes=10240) -> bool
    - SchemaValidationError: raised in strict mode
    - EventValidatorMiddleware: strict/lenient middleware for the bus
"""

from forge.plugins.schemas.event_schema import (
    EVENT_SCHEMAS,
    FORBIDDEN_FIELDS,
    MAX_PAYLOAD_BYTES,
    ArtifactDiscoveredSchema,
    GraphUpdatedSchema,
    ReportGeneratedSchema,
)
from forge.plugins.schemas.validators import (
    EventValidatorMiddleware,
    SchemaValidationError,
    ValidationResult,
    check_forbidden_fields,
    validate_event,
    validate_payload_size,
)

__all__ = [
    "EVENT_SCHEMAS",
    "FORBIDDEN_FIELDS",
    "MAX_PAYLOAD_BYTES",
    "ArtifactDiscoveredSchema",
    "GraphUpdatedSchema",
    "ReportGeneratedSchema",
    "EventValidatorMiddleware",
    "SchemaValidationError",
    "ValidationResult",
    "check_forbidden_fields",
    "validate_event",
    "validate_payload_size",
]
