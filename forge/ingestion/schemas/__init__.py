"""Pydantic schemas for external-tool ingestion.

Public exports:
    SharpHoundSession   -- one entry from a SharpHound ``sessions.json`` file
    AzureHoundObject    -- one Azure AD object emitted by AzureHound
    BloodHoundContainer -- one container entry from ``containers.json``
    BloodHoundMeta      -- ``meta`` block shared by every BloodHound JSON
    BloodHoundFile      -- top-level ``{meta, data}`` envelope for any file
    BloodHoundZipManifest -- validated view of a BloodHound export zip's file
                             set (schema for the zip layout)
"""

from forge.ingestion.schemas.bloodhound import (
    AzureHoundObject,
    BloodHoundContainer,
    BloodHoundFile,
    BloodHoundMeta,
    BloodHoundZipManifest,
    SharpHoundSession,
)

__all__ = [
    "AzureHoundObject",
    "BloodHoundContainer",
    "BloodHoundFile",
    "BloodHoundMeta",
    "BloodHoundZipManifest",
    "SharpHoundSession",
]
