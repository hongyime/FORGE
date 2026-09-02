"""Collector-specific parsers. Each parser owns one vendor JSON shape."""

from forge.ingestion.parsers.azurehound_parser import (
    AzureEntityType,
    GraphEntity,
    Relationship,
    parse_azurehound_json,
)

__all__ = [
    "AzureEntityType",
    "GraphEntity",
    "Relationship",
    "parse_azurehound_json",
]
