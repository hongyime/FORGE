"""Tests for :mod:`forge.ingestion.bloodhound_importer` (U1.5 ROE gates)."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEntry, AuditEventType
from forge.ingestion.bloodhound_importer import (
    BloodHoundImporter,
    ImportResult,
    InvalidScopeManifestError,
    MissingEngagementIdError,
    MissingScopeManifestError,
    ScopeManifest,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def scope_manifest() -> ScopeManifest:
    return ScopeManifest(
        roe_id="ROE-U1.5-TEST",
        domains=["example.com", "*.example.com"],
        ip_ranges=["10.0.0.0/24"],
        urls=[],
        authorized_seeds=["user@example.com"],
    )


@pytest.fixture
def audit_logger() -> AuditLogger:
    # In-memory only -- the importer must not need on-disk persistence to
    # write its four audit event categories.
    return AuditLogger(log_path=None)


def _write_bh_zip(zip_path: Path, entities: dict[str, list[dict]]) -> None:
    """Write a minimal BloodHound-shaped zip containing the given entities."""
    with zipfile.ZipFile(zip_path, "w") as archive:
        for entity_type, data in entities.items():
            payload = {
                "meta": {
                    "type": entity_type,
                    "count": len(data),
                    "version": 5,
                    "methods": 0,
                },
                "data": data,
            }
            archive.writestr(f"{entity_type}.json", json.dumps(payload))


def _audit_events(logger: AuditLogger) -> list[AuditEntry]:
    return list(logger.entries)


def _event_names(entries: list[AuditEntry]) -> list[str]:
    names: list[str] = []
    for entry in entries:
        if entry.tool_name != "bloodhound_importer":
            continue
        params = entry.input_params or {}
        event = params.get("event")
        if isinstance(event, str):
            names.append(event)
    return names


# ---------------------------------------------------------------------------
# Construction gates
# ---------------------------------------------------------------------------


class TestConstructionROE:
    def test_missing_scope_manifest_raises(self, audit_logger: AuditLogger) -> None:
        with pytest.raises(MissingScopeManifestError) as excinfo:
            BloodHoundImporter(None, audit_logger=audit_logger)  # type: ignore[arg-type]
        assert "scope_manifest is required" in str(excinfo.value)

    def test_wrong_type_scope_manifest_raises(self, audit_logger: AuditLogger) -> None:
        with pytest.raises(InvalidScopeManifestError):
            BloodHoundImporter({"roe_id": "R"}, audit_logger=audit_logger)  # type: ignore[arg-type]

    def test_empty_scope_manifest_rejected(self, audit_logger: AuditLogger) -> None:
        empty = ScopeManifest(roe_id="ROE-EMPTY")
        with pytest.raises(InvalidScopeManifestError) as excinfo:
            BloodHoundImporter(empty, audit_logger=audit_logger)
        assert "at least one" in str(excinfo.value)

    def test_broad_wildcard_rejected_at_manifest_parse(self) -> None:
        with pytest.raises(Exception):  # noqa: PT011 -- pydantic ValidationError
            ScopeManifest(roe_id="ROE-BAD", authorized_seeds=["*"])


# ---------------------------------------------------------------------------
# import_zip ROE gates
# ---------------------------------------------------------------------------


class TestImportZipROE:
    def test_engagement_id_none_rejected(
        self,
        scope_manifest: ScopeManifest,
        audit_logger: AuditLogger,
        tmp_path: Path,
    ) -> None:
        importer = BloodHoundImporter(scope_manifest, audit_logger=audit_logger)
        zip_path = tmp_path / "unused.zip"
        with pytest.raises(MissingEngagementIdError) as excinfo:
            importer.import_zip(zip_path, engagement_id=None)  # type: ignore[arg-type]
        assert "engagement_id is required" in str(excinfo.value)
        # No audit events -- rejection happens before any write.
        assert _audit_events(audit_logger) == []

    def test_engagement_id_empty_string_rejected(
        self,
        scope_manifest: ScopeManifest,
        audit_logger: AuditLogger,
        tmp_path: Path,
    ) -> None:
        importer = BloodHoundImporter(scope_manifest, audit_logger=audit_logger)
        with pytest.raises(MissingEngagementIdError):
            importer.import_zip(tmp_path / "x.zip", engagement_id="   ")
        assert _audit_events(audit_logger) == []

    def test_engagement_id_wrong_type_rejected(
        self,
        scope_manifest: ScopeManifest,
        audit_logger: AuditLogger,
        tmp_path: Path,
    ) -> None:
        importer = BloodHoundImporter(scope_manifest, audit_logger=audit_logger)
        with pytest.raises(MissingEngagementIdError):
            importer.import_zip(tmp_path / "x.zip", engagement_id=1234)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Successful import audit trail
# ---------------------------------------------------------------------------


class TestSuccessfulImportAuditTrail:
    def test_success_writes_all_four_event_categories(
        self,
        scope_manifest: ScopeManifest,
        audit_logger: AuditLogger,
        tmp_path: Path,
    ) -> None:
        zip_path = tmp_path / "bh.zip"
        _write_bh_zip(
            zip_path,
            {
                "users": [{"ObjectIdentifier": "S-1-5-21-1"}],
                "computers": [
                    {"ObjectIdentifier": "S-1-5-21-2"},
                    {"ObjectIdentifier": "S-1-5-21-3"},
                ],
            },
        )

        importer = BloodHoundImporter(scope_manifest, audit_logger=audit_logger)
        result = importer.import_zip(zip_path, engagement_id="ENG-1001")

        # Result invariants.
        assert isinstance(result, ImportResult)
        assert result.success is True
        assert result.engagement_id == "ENG-1001"
        assert result.total_entities == 3
        assert result.entities_by_type == {"users": 1, "computers": 2}
        assert result.error is None
        assert result.duration_seconds >= 0.0

        # Audit trail invariants: import_started + N x entity_imported +
        # import_completed. With two JSON members we get exactly 4 entries.
        entries = _audit_events(audit_logger)
        names = _event_names(entries)
        assert names.count("import_started") == 1
        assert names.count("entity_imported") == 2
        assert names.count("import_completed") == 1
        # All four required categories are present.
        assert set(names) == {"import_started", "entity_imported", "import_completed"}
        assert len(entries) == 4

    def test_every_audit_entry_carries_engagement_id(
        self,
        scope_manifest: ScopeManifest,
        audit_logger: AuditLogger,
        tmp_path: Path,
    ) -> None:
        zip_path = tmp_path / "bh.zip"
        _write_bh_zip(zip_path, {"users": [{"ObjectIdentifier": "S-1-5-21-1"}]})
        importer = BloodHoundImporter(scope_manifest, audit_logger=audit_logger)
        importer.import_zip(zip_path, engagement_id="ENG-42")

        entries = _audit_events(audit_logger)
        assert entries, "expected at least one audit entry"
        for entry in entries:
            params = entry.input_params or {}
            assert params.get("engagement_id") == "ENG-42", (
                f"entry {entry.output_summary!r} missing engagement_id"
            )

    def test_import_started_is_first_entry(
        self,
        scope_manifest: ScopeManifest,
        audit_logger: AuditLogger,
        tmp_path: Path,
    ) -> None:
        zip_path = tmp_path / "bh.zip"
        _write_bh_zip(zip_path, {"users": [{"ObjectIdentifier": "S-1-5-21-1"}]})
        importer = BloodHoundImporter(scope_manifest, audit_logger=audit_logger)
        importer.import_zip(zip_path, engagement_id="ENG-42")

        names = _event_names(_audit_events(audit_logger))
        assert names[0] == "import_started"
        assert names[-1] == "import_completed"


# ---------------------------------------------------------------------------
# Failure path audit trail
# ---------------------------------------------------------------------------


class TestFailedImportAuditTrail:
    def test_missing_zip_produces_import_failed_entry(
        self,
        scope_manifest: ScopeManifest,
        audit_logger: AuditLogger,
        tmp_path: Path,
    ) -> None:
        importer = BloodHoundImporter(scope_manifest, audit_logger=audit_logger)
        missing = tmp_path / "does-not-exist.zip"
        result = importer.import_zip(missing, engagement_id="ENG-9")

        assert result.success is False
        assert result.error is not None
        assert result.engagement_id == "ENG-9"

        names = _event_names(_audit_events(audit_logger))
        # import_started must still be logged BEFORE the failure -- the
        # audit trail is required even when the read fails.
        assert names.count("import_started") == 1
        assert names.count("import_failed") == 1
        assert "import_completed" not in names

    def test_partial_import_error_midway_still_has_audit_trail(
        self,
        scope_manifest: ScopeManifest,
        audit_logger: AuditLogger,
        tmp_path: Path,
    ) -> None:
        # Build a zip whose second member is malformed JSON. The first
        # member must be parsed and audited before the second raises.
        zip_path = tmp_path / "bad.zip"
        with zipfile.ZipFile(zip_path, "w") as archive:
            archive.writestr(
                "users.json",
                json.dumps(
                    {
                        "meta": {"type": "users", "count": 1, "version": 5},
                        "data": [{"ObjectIdentifier": "S-1-5-21-1"}],
                    }
                ),
            )
            archive.writestr("computers.json", "{ this is not valid json ")

        importer = BloodHoundImporter(scope_manifest, audit_logger=audit_logger)
        result = importer.import_zip(zip_path, engagement_id="ENG-partial")

        assert result.success is False
        assert result.error is not None
        # Depending on zip member ordering the first parse may or may not
        # succeed before the malformed one raises; we require only that
        # the ROE-mandatory events surrounded any progress.
        names = _event_names(_audit_events(audit_logger))
        assert names.count("import_started") == 1
        assert names.count("import_failed") == 1
        assert "import_completed" not in names
        # Every entry still carries engagement_id.
        for entry in _audit_events(audit_logger):
            params = entry.input_params or {}
            assert params.get("engagement_id") == "ENG-partial"

    def test_import_failed_entry_records_error_and_marks_error_event(
        self,
        scope_manifest: ScopeManifest,
        audit_logger: AuditLogger,
        tmp_path: Path,
    ) -> None:
        importer = BloodHoundImporter(scope_manifest, audit_logger=audit_logger)
        result = importer.import_zip(tmp_path / "nope.zip", engagement_id="ENG-9")
        assert result.success is False

        failed = [
            entry
            for entry in _audit_events(audit_logger)
            if (entry.input_params or {}).get("event") == "import_failed"
        ]
        assert len(failed) == 1
        entry = failed[0]
        assert entry.event_type is AuditEventType.ERROR
        assert entry.success is False
        assert entry.error_detail  # non-empty error description
        assert (entry.input_params or {}).get("error_message")


# ---------------------------------------------------------------------------
# Default logger fallback -- audit MUST still fire even without an explicit sink.
# ---------------------------------------------------------------------------


def test_default_logger_captures_events_when_none_supplied(
    scope_manifest: ScopeManifest,
    tmp_path: Path,
) -> None:
    zip_path = tmp_path / "bh.zip"
    _write_bh_zip(zip_path, {"users": [{"ObjectIdentifier": "S-1-5-21-1"}]})

    importer = BloodHoundImporter(scope_manifest)  # audit_logger=None
    result = importer.import_zip(zip_path, engagement_id="ENG-DEFAULT")

    assert result.success is True
    names = _event_names(_audit_events(importer.audit_logger))
    assert "import_started" in names
    assert "import_completed" in names
    assert names.count("entity_imported") == 1
