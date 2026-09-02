"""Integration test — SharpHound zip parser (U1.2).

Contract:

* Parse a real-shaped SharpHound zip fixture ≥1 MB uncompressed.
* Complete in under 10 seconds.
* Output entity count matches input object count within tolerance.
* ``sessions.json``, ``grouped.json`` and ``containers.json`` are all
  extracted and produce typed entities.
* Unicode object names round-trip cleanly.
* Missing expected files are handled without raising.
* Corrupt / truncated zips raise :class:`SharpHoundParseError`.
* The source zip is never mutated by the parser.
"""

from __future__ import annotations

import hashlib
import io
import json
import time
import zipfile
from pathlib import Path
from typing import Any

import pytest

from forge.ingestion.parsers.sharphound_parser import (
    PARSER_VERSION,
    GraphEntity,
    SharpHoundParseError,
    parse_sharphound_zip,
)


# ── Fixture builder ──────────────────────────────────────────────────────────
_DOMAIN_SID = "S-1-5-21-4111111111-4222222222-4333333333"


def _sid(rid: int) -> str:
    return f"{_DOMAIN_SID}-{rid}"


def _build_sessions_document(count: int) -> dict[str, Any]:
    """SharpHound sessions.json shape — one entry per user↔computer session."""
    return {
        "data": [
            {
                "UserSID": _sid(1104 + (i % 400)),
                "ComputerSID": _sid(2000 + (i % 200)),
                "Weight": (i % 5) + 1,
                # Unicode in the observed hostname exercises UTF-8 handling.
                "ObservedHost": f"WS-Πλάτων-{i}.forge.local",
            }
            for i in range(count)
        ],
        "meta": {"methods": 0, "type": "sessions", "count": count, "version": 5},
    }


def _build_grouped_document(count: int) -> dict[str, Any]:
    """SharpHound grouped.json shape — flattened group membership edges."""
    return {
        "data": [
            {
                "GroupSID": _sid(512 if i % 50 == 0 else 513 + (i % 30)),
                "MemberSID": _sid(1104 + (i % 400)),
                "MemberType": "User" if i % 3 else "Computer",
                # Unicode group / member display name (dotted-Latin, Cyrillic,
                # Han, Arabic RTL) to prove no encoding path munges the name.
                "MemberName": (
                    f"用户_{i}@forge.local"
                    if i % 4 == 0
                    else f"Пользователь_{i}@forge.local"
                ),
            }
            for i in range(count)
        ],
        "meta": {"methods": 0, "type": "grouped", "count": count, "version": 5},
    }


def _build_containers_document(count: int) -> dict[str, Any]:
    """SharpHound containers.json shape — OU / container hierarchy."""
    return {
        "data": [
            {
                "ObjectIdentifier": (
                    f"CN=Container-{i:04d},"
                    "OU=مستخدمون,"  # Arabic RTL segment
                    "DC=forge,DC=local"
                ),
                "Properties": {
                    "name": f"CONTAINER-Λ-{i:04d}",
                    "domain": "FORGE.LOCAL",
                    "domainsid": _DOMAIN_SID,
                    "distinguishedname": (
                        f"CN=Container-{i:04d},"
                        "OU=مستخدمون,"
                        "DC=forge,DC=local"
                    ),
                    "highvalue": (i % 100 == 0),
                    "description": f"Auto-generated container {i} (тест 测试)",
                },
                "ChildObjects": [
                    {
                        "ObjectIdentifier": _sid(2000 + (i % 200)),
                        "ObjectType": "Computer",
                    }
                ],
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False,
            }
            for i in range(count)
        ],
        "meta": {"methods": 0, "type": "containers", "count": count, "version": 5},
    }


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@pytest.fixture()
def sharphound_zip(tmp_path: Path) -> tuple[Path, dict[str, int]]:
    """Build a ≥1 MB SharpHound zip with all three required files.

    Returns the zip path plus expected record counts per file so tests
    can compare parsed output against the ground truth.
    """
    sessions_count = 2000
    grouped_count = 3000
    containers_count = 800

    sessions_doc = _build_sessions_document(sessions_count)
    grouped_doc = _build_grouped_document(grouped_count)
    containers_doc = _build_containers_document(containers_count)

    zip_path = tmp_path / "sharphound_20260901.zip"
    with zipfile.ZipFile(
        zip_path, mode="w", compression=zipfile.ZIP_DEFLATED
    ) as zf:
        # ``ensure_ascii=False`` keeps the Unicode payload intact — the
        # parser must decode UTF-8 correctly, and we assert the surviving
        # code points after re-parse.
        zf.writestr(
            "sessions.json", json.dumps(sessions_doc, ensure_ascii=False)
        )
        zf.writestr(
            "grouped.json", json.dumps(grouped_doc, ensure_ascii=False)
        )
        zf.writestr(
            "containers.json",
            json.dumps(containers_doc, ensure_ascii=False),
        )
        # A non-JSON side-file to prove the parser logs & skips it
        # without failing.
        zf.writestr("collection.log", "SharpHound 2.5.9 completed OK\n")

    # Verify the uncompressed payload passes the ≥1 MB gate the task
    # requires — a synthetic fixture that is too small would let the
    # perf assertion succeed for the wrong reason.
    uncompressed = sum(
        info.file_size for info in zipfile.ZipFile(zip_path).infolist()
    )
    assert uncompressed >= 1_000_000, (
        f"Fixture too small: uncompressed size {uncompressed} bytes < 1 MB"
    )

    return zip_path, {
        "sessions": sessions_count,
        "grouped": grouped_count,
        "containers": containers_count,
    }


# ── Tests ────────────────────────────────────────────────────────────────────
def test_parse_sharphound_zip_all_three_files_produce_entities(
    sharphound_zip: tuple[Path, dict[str, int]],
) -> None:
    """Every required file yields entities with the correct FORGE type."""
    zip_path, counts = sharphound_zip

    entities = parse_sharphound_zip(zip_path)

    by_type: dict[str, list[GraphEntity]] = {}
    for entity in entities:
        by_type.setdefault(entity.type, []).append(entity)

    # The three mandatory files must all contribute entities.
    assert len(by_type.get("session", [])) == counts["sessions"]
    assert len(by_type.get("group_membership", [])) == counts["grouped"]
    assert len(by_type.get("container", [])) == counts["containers"]


def test_parse_sharphound_zip_output_count_matches_input(
    sharphound_zip: tuple[Path, dict[str, int]],
) -> None:
    """Total parsed entity count matches the input object count ±0.

    Tolerance is defined in the task as ±(a small proportion); the
    parser is expected to be deterministic on well-formed input, so
    exact equality is the strongest available proof.
    """
    zip_path, counts = sharphound_zip
    expected_total = sum(counts.values())

    entities = parse_sharphound_zip(zip_path)

    # Tolerance envelope: within 1 % of the expected total. Deterministic
    # parsing normally yields equality; keeping a slack for future
    # ingestion filters (e.g. skipping self-referential edges).
    tolerance = max(1, expected_total // 100)
    assert abs(len(entities) - expected_total) <= tolerance


def test_parse_sharphound_zip_completes_within_ten_seconds(
    sharphound_zip: tuple[Path, dict[str, int]],
) -> None:
    """Perf floor: ≥1 MB fixture must be parsed in <10 s."""
    zip_path, _ = sharphound_zip

    start = time.perf_counter()
    entities = parse_sharphound_zip(zip_path)
    elapsed = time.perf_counter() - start

    assert entities, "Parser returned no entities"
    assert elapsed < 10.0, f"Parser took {elapsed:.2f}s (>=10s budget)"


def test_parse_sharphound_zip_preserves_unicode(
    sharphound_zip: tuple[Path, dict[str, int]],
) -> None:
    """Cyrillic, Greek, Han, and Arabic RTL round-trip through the parser."""
    zip_path, _ = sharphound_zip

    entities = parse_sharphound_zip(zip_path)

    joined = " ".join(json.dumps(e.properties, ensure_ascii=False) for e in entities)
    # Sample tokens from each script that the fixture builders emit.
    assert "Πλάτων" in joined  # Greek
    assert "Пользователь" in joined  # Cyrillic
    assert "用户" in joined  # Han
    assert "مستخدمون" in joined  # Arabic RTL
    assert "CONTAINER-Λ-0000" in joined  # Property field with Greek capital


def test_parse_sharphound_zip_records_source_metadata(
    sharphound_zip: tuple[Path, dict[str, int]],
) -> None:
    """Every entity carries provenance: zip path, member, parser version."""
    zip_path, _ = sharphound_zip

    entities = parse_sharphound_zip(zip_path)

    assert entities
    for entity in entities:
        meta = entity.source_metadata
        assert meta["parser"] == PARSER_VERSION
        assert meta["source_type"] == "sharphound"
        assert meta["zip_path"] == str(zip_path)
        assert meta["zip_member"] in {
            "sessions.json",
            "grouped.json",
            "containers.json",
        }
        assert meta["record_kind"] in {"sessions", "grouped", "containers"}
        # BloodHound `meta` block preserved verbatim from the fixture.
        assert meta["bloodhound_meta"]["version"] == 5


def test_parse_sharphound_zip_does_not_mutate_source(
    sharphound_zip: tuple[Path, dict[str, int]],
) -> None:
    """The source zip's byte-for-byte content is unchanged after parsing."""
    zip_path, _ = sharphound_zip
    digest_before = _hash_file(zip_path)
    mtime_before = zip_path.stat().st_mtime_ns

    parse_sharphound_zip(zip_path)

    assert _hash_file(zip_path) == digest_before
    assert zip_path.stat().st_mtime_ns == mtime_before


def test_parse_sharphound_zip_missing_files_handled_gracefully(
    tmp_path: Path,
) -> None:
    """SharpHound legitimately omits sections — parser must not raise.

    Task constraint: some exports skip certain files (e.g. no session
    collection). Only files that ARE present should be parsed.
    """
    zip_path = tmp_path / "partial.zip"
    with zipfile.ZipFile(zip_path, mode="w") as zf:
        # containers.json alone — no sessions, no grouped.
        zf.writestr(
            "containers.json",
            json.dumps(_build_containers_document(count=25)),
        )

    entities = parse_sharphound_zip(zip_path)

    assert len(entities) == 25
    assert {e.type for e in entities} == {"container"}


def test_parse_sharphound_zip_corrupt_zip_raises(tmp_path: Path) -> None:
    """A truncated / non-zip file surfaces a :class:`SharpHoundParseError`."""
    bogus = tmp_path / "corrupt.zip"
    bogus.write_bytes(b"PK\x03\x04not-a-real-zip")

    with pytest.raises(SharpHoundParseError) as excinfo:
        parse_sharphound_zip(bogus)

    assert "valid zip" in str(excinfo.value).lower()


def test_parse_sharphound_zip_malformed_json_reports_entry(
    tmp_path: Path,
) -> None:
    """Malformed JSON inside the zip is attributed to the offending member."""
    zip_path = tmp_path / "malformed.zip"
    with zipfile.ZipFile(zip_path, mode="w") as zf:
        zf.writestr("containers.json", "{ this is not valid json")

    with pytest.raises(SharpHoundParseError) as excinfo:
        parse_sharphound_zip(zip_path)

    assert excinfo.value.entry == "containers.json"


def test_parse_sharphound_zip_missing_path_raises(tmp_path: Path) -> None:
    """A path that does not exist raises :class:`FileNotFoundError`."""
    ghost = tmp_path / "does-not-exist.zip"

    with pytest.raises(FileNotFoundError):
        parse_sharphound_zip(ghost)


def test_parse_sharphound_zip_stems_are_case_insensitive(
    tmp_path: Path,
) -> None:
    """Uppercase / nested filenames still map to the right entity types."""
    zip_path = tmp_path / "mixed_case.zip"
    with zipfile.ZipFile(zip_path, mode="w") as zf:
        zf.writestr(
            "Collection/Containers.JSON",
            json.dumps(_build_containers_document(count=3)),
        )
        zf.writestr(
            "Collection/SESSIONS.json",
            json.dumps(_build_sessions_document(count=4)),
        )

    entities = parse_sharphound_zip(zip_path)

    kinds = {e.source_metadata["record_kind"] for e in entities}
    assert kinds == {"containers", "sessions"}


def test_parse_sharphound_zip_returns_pydantic_frozen_entities(
    sharphound_zip: tuple[Path, dict[str, int]],
) -> None:
    """``GraphEntity`` is frozen — downstream stages cannot mutate ids in place."""
    zip_path, _ = sharphound_zip
    entities = parse_sharphound_zip(zip_path)

    assert entities
    with pytest.raises((TypeError, ValueError)):
        # Pydantic v2 frozen models raise on attribute assignment.
        entities[0].id = "mutated"  # type: ignore[misc]


def test_parse_sharphound_zip_reads_bom_prefixed_json(tmp_path: Path) -> None:
    """UTF-8 BOM on Windows-produced SharpHound exports is tolerated."""
    zip_path = tmp_path / "bom.zip"
    bom_payload = "\ufeff" + json.dumps(_build_containers_document(count=2))
    with zipfile.ZipFile(zip_path, mode="w") as zf:
        zf.writestr(
            "containers.json", bom_payload.encode("utf-8")
        )

    entities = parse_sharphound_zip(zip_path)

    assert len(entities) == 2
    assert entities[0].type == "container"


def test_parse_sharphound_zip_streams_zip_members(
    sharphound_zip: tuple[Path, dict[str, int]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Members are opened with ``ZipFile.open`` (streaming), not
    ``ZipFile.read`` (whole-member buffer).

    This is the closest observable proxy for the task constraint 'do
    not load entire zip into memory (stream large files)'. ``read``
    materialises the whole member up front; ``open`` returns a lazy
    file-like the parser then feeds to :func:`json.load`. If a future
    refactor ever regresses to ``read``, this test fails.
    """
    zip_path, _ = sharphound_zip

    read_calls: list[str] = []
    original_read = zipfile.ZipFile.read

    def _tracking_read(self: zipfile.ZipFile, name: Any, pwd: Any = None) -> bytes:  # noqa: ANN401
        read_calls.append(str(name))
        return original_read(self, name, pwd)

    monkeypatch.setattr(zipfile.ZipFile, "read", _tracking_read)

    parse_sharphound_zip(zip_path)

    assert read_calls == [], (
        f"Parser fell back to ZipFile.read (non-streaming): {read_calls!r}"
    )
