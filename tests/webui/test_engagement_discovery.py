import sqlite3
from pathlib import Path
from typing import Any

from forge.db.control import (
    connect_control_db,
    lookup_engagement_index,
    upsert_engagement_index,
    upsert_membership,
)
from forge.db.direct_connect import direct_connect
from forge.webui.engagement_discovery import (
    EngagementDiscoveryContext,
    build_engagement_discovery_context_provider,
    control_tombstone_retention_seconds,
    find_engagement_artifact,
    find_engagement_detail,
    indexed_db_path,
    iter_engagement_payloads,
    resolve_engagement_db,
)


def _slug(name: str, engagement_id: int = 1001) -> str:
    return f"engagement-{engagement_id}-{name.lower().replace(' ', '-')}"


def _create_engagement_db(
    db_path: Path,
    *,
    engagement_id: int = 1001,
    name: str = "Acme Example",
    workspace_id: str = "default",
    member_subject: str = "architect",
) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = direct_connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                workspace_id TEXT NOT NULL DEFAULT 'default',
                scope_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                operator TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT '2026-08-13 10:00:00',
                updated_at TEXT NOT NULL DEFAULT '2026-08-13 10:00:00'
            );

            CREATE TABLE workspace_memberships (
                workspace_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'operator',
                permissions_json TEXT NOT NULL DEFAULT '[]',
                PRIMARY KEY (workspace_id, subject)
            );
            """
        )
        con.execute(
            """
            INSERT INTO engagements
                (id, name, workspace_id, scope_json, status, operator)
            VALUES (?, ?, ?, '["acme.example"]', 'ACTIVE', ?)
            """,
            (engagement_id, name, workspace_id, member_subject),
        )
        con.execute(
            """
            INSERT INTO workspace_memberships
                (workspace_id, subject, role, permissions_json)
            VALUES (?, ?, 'owner', '["*"]')
            """,
            (workspace_id, member_subject),
        )
        con.commit()
    finally:
        con.close()


def _engagement_rows(con: sqlite3.Connection) -> list[sqlite3.Row]:
    return con.execute(
        """
        SELECT id, name, workspace_id, scope_json, status, operator, created_at, updated_at
        FROM engagements
        ORDER BY id
        """
    ).fetchall()


def _engagement_row(con: sqlite3.Connection, engagement_id: int) -> sqlite3.Row | None:
    return con.execute(
        """
        SELECT id, name, workspace_id, scope_json, status, operator, created_at, updated_at
        FROM engagements
        WHERE id=?
        """,
        (engagement_id,),
    ).fetchone()


def _summary_payload(db_path: Path, _con: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    engagement_id = int(row["id"])
    return {
        "db": db_path.name,
        "id": engagement_id,
        "slug": _slug(str(row["name"]), engagement_id),
        "name": str(row["name"]),
        "workspace_id": str(row["workspace_id"] or "default"),
        "status": str(row["status"] or ""),
        "operator": str(row["operator"] or ""),
        "created_at": str(row["created_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
        "seeds": ["acme.example"],
        "counts": {},
    }


def _detail_payload(db_path: Path, con: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    return {**_summary_payload(db_path, con, row), "detail": True}


def _principal(subject: str = "architect", workspace_id: str = "default") -> dict[str, str]:
    return {"subject": subject, "workspace_id": workspace_id}


def _can_access_workspace(
    principal: dict[str, str] | None,
    workspace_id: str,
    con: sqlite3.Connection | None,
) -> bool:
    if principal is None:
        return True
    if principal["workspace_id"] != workspace_id:
        return False
    if con is None:
        return False
    row = con.execute(
        """
        SELECT 1
        FROM workspace_memberships
        WHERE workspace_id=? AND subject=?
        LIMIT 1
        """,
        (workspace_id, principal["subject"]),
    ).fetchone()
    return row is not None


def _can_access_engagement_row(
    con: sqlite3.Connection,
    principal: dict[str, str] | None,
    row: sqlite3.Row,
) -> bool:
    workspace_id = str(row["workspace_id"] or "default")
    return _can_access_workspace(principal, workspace_id, con)


def _context(data_dir: Path, artifact_files: list[Path] | None = None) -> EngagementDiscoveryContext:
    return EngagementDiscoveryContext(
        data_dir=data_dir,
        ensure_workspace_rbac_foundation=lambda _con: None,
        engagement_rows=_engagement_rows,
        engagement_row=_engagement_row,
        summary_payload=_summary_payload,
        detail_payload=_detail_payload,
        can_access_workspace=_can_access_workspace,
        can_access_engagement_row=_can_access_engagement_row,
        artifact_files=lambda _con, _db, _engagement_id, _summary: list(artifact_files or []),
        tombstone_retention_days="30",
    )


def test_build_engagement_discovery_context_provider_binds_dependencies(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "report.md"
    provider = build_engagement_discovery_context_provider(
        data_dir=tmp_path / ".forge_data",
        ensure_workspace_rbac_foundation=lambda _con: None,
        engagement_rows=_engagement_rows,
        engagement_row=_engagement_row,
        summary_payload=_summary_payload,
        detail_payload=_detail_payload,
        can_access_workspace=_can_access_workspace,
        can_access_engagement_row=_can_access_engagement_row,
        artifact_files=lambda _con, _db, _engagement_id, _summary: [artifact],
        tombstone_retention_days="7",
    )

    ctx = provider()

    assert ctx.data_dir == tmp_path / ".forge_data"
    assert ctx.engagement_rows is _engagement_rows
    assert ctx.engagement_row is _engagement_row
    assert ctx.summary_payload is _summary_payload
    assert ctx.detail_payload is _detail_payload
    assert ctx.can_access_workspace is _can_access_workspace
    assert ctx.can_access_engagement_row is _can_access_engagement_row
    assert ctx.artifact_files(None, artifact, 1001, {}) == [artifact]
    assert ctx.tombstone_retention_days == "7"


def test_control_tombstone_retention_seconds_parses_operational_values() -> None:
    assert control_tombstone_retention_seconds("30") == 30 * 86400
    assert control_tombstone_retention_seconds("0.5") == 43200
    assert control_tombstone_retention_seconds("off") is None
    assert control_tombstone_retention_seconds("-1") is None
    assert control_tombstone_retention_seconds("invalid") == 30 * 86400


def test_indexed_db_path_rejects_missing_and_outside_paths(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    inside_db = db_root / "1001.db"
    inside_db.write_bytes(b"sqlite")
    outside_db = tmp_path / "outside.db"
    outside_db.write_bytes(b"sqlite")
    control_con = connect_control_db(data_dir)
    try:
        upsert_engagement_index(
            control_con,
            engagement_id=1001,
            workspace_id="default",
            db_path=inside_db,
            slug="engagement-1001-acme-example",
            name="Acme Example",
            status="ACTIVE",
            operator="architect",
            summary={"id": 1001},
        )
        upsert_engagement_index(
            control_con,
            engagement_id=1002,
            workspace_id="default",
            db_path=outside_db,
            slug="engagement-1002-outside",
            name="Outside",
            status="ACTIVE",
            operator="architect",
            summary={"id": 1002},
        )
        control_con.commit()
        inside_row = lookup_engagement_index(control_con, "1001")
        outside_row = lookup_engagement_index(control_con, "1002")

        assert indexed_db_path(inside_row, data_dir) == inside_db.resolve()
        assert indexed_db_path(outside_row, data_dir) is None
    finally:
        control_con.close()


def test_iter_engagement_payloads_uses_fresh_control_index_without_opening_db(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = data_dir / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True)
    db_path.write_bytes(b"sqlite")
    summary = {
        "id": 1001,
        "slug": "engagement-1001-cached",
        "name": "Cached",
        "workspace_id": "default",
        "status": "ACTIVE",
        "operator": "architect",
        "created_at": "2026-08-13 10:00:00",
        "updated_at": "2026-08-13 10:00:00",
        "seeds": ["cached.example"],
    }
    control_con = connect_control_db(data_dir)
    try:
        upsert_engagement_index(
            control_con,
            engagement_id=1001,
            workspace_id="default",
            db_path=db_path,
            slug="engagement-1001-cached",
            name="Cached",
            status="ACTIVE",
            operator="architect",
            summary=summary,
        )
        upsert_membership(
            control_con,
            workspace_id="default",
            subject="architect",
            role="owner",
            permissions_json='["*"]',
        )
        control_con.commit()
    finally:
        control_con.close()

    ctx = EngagementDiscoveryContext(
        data_dir=data_dir,
        ensure_workspace_rbac_foundation=lambda _con: None,
        engagement_rows=lambda _con: (_ for _ in ()).throw(AssertionError("unexpected scan")),
        engagement_row=lambda _con, _engagement_id: (_ for _ in ()).throw(AssertionError("unexpected read")),
        summary_payload=lambda _db, _con, _row: {},
        detail_payload=lambda _db, _con, _row: {},
        can_access_workspace=_can_access_workspace,
        can_access_engagement_row=_can_access_engagement_row,
        artifact_files=lambda _con, _db, _engagement_id, _summary: [],
    )

    assert iter_engagement_payloads(ctx, _principal()) == [summary]


def test_iter_engagement_payloads_scans_unindexed_dbs_when_index_has_items(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    indexed_db = data_dir / "engagements" / "1003.db"
    unindexed_db = data_dir / "engagements" / "1001.db"
    _create_engagement_db(
        indexed_db,
        engagement_id=1003,
        name="Indexed Example",
    )
    _create_engagement_db(unindexed_db)
    indexed_summary = {
        "id": 1003,
        "slug": "engagement-1003-indexed-example",
        "name": "Indexed Example",
        "workspace_id": "default",
        "status": "ACTIVE",
        "operator": "architect",
        "created_at": "2026-08-13 10:00:00",
        "updated_at": "2026-08-13 10:00:00",
        "seeds": ["indexed.example"],
    }
    control_con = connect_control_db(data_dir)
    try:
        upsert_engagement_index(
            control_con,
            engagement_id=1003,
            workspace_id="default",
            db_path=indexed_db,
            slug="engagement-1003-indexed-example",
            name="Indexed Example",
            status="ACTIVE",
            operator="architect",
            summary=indexed_summary,
        )
        upsert_membership(
            control_con,
            workspace_id="default",
            subject="architect",
            role="owner",
            permissions_json='["*"]',
        )
        control_con.commit()
    finally:
        control_con.close()

    items = iter_engagement_payloads(_context(data_dir), _principal())

    assert {int(item["id"]) for item in items} == {1001, 1003}
    control_con = connect_control_db(data_dir)
    try:
        assert lookup_engagement_index(control_con, "engagement-1001-acme-example") is not None
    finally:
        control_con.close()


def test_resolve_engagement_db_marks_missing_cached_paths_as_tombstones(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    missing_db = data_dir / "engagements" / "1001.db"
    missing_db.parent.mkdir(parents=True)
    control_con = connect_control_db(data_dir)
    try:
        upsert_engagement_index(
            control_con,
            engagement_id=1001,
            workspace_id="default",
            db_path=missing_db,
            slug="engagement-1001-missing",
            name="Missing",
            status="ACTIVE",
            operator="architect",
            summary={"id": 1001, "slug": "engagement-1001-missing"},
        )
        upsert_membership(
            control_con,
            workspace_id="default",
            subject="architect",
            role="owner",
            permissions_json='["*"]',
        )
        control_con.commit()
    finally:
        control_con.close()

    assert resolve_engagement_db(_context(data_dir), "engagement-1001-missing", _principal()) is None

    control_con = connect_control_db(data_dir)
    try:
        row = lookup_engagement_index(control_con, "1001")
        assert row is not None
        assert str(row["missing_since"] or "")
    finally:
        control_con.close()


def test_resolve_detail_and_artifact_fallback_scan_numeric_engagement_dbs(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = data_dir / "engagements" / "1001.db"
    _create_engagement_db(db_path)
    report_path = tmp_path / "1001_report.json"
    report_path.write_text("{}", encoding="utf-8")
    ctx = _context(data_dir, artifact_files=[report_path])

    assert resolve_engagement_db(ctx, "engagement-1001-acme-example", _principal()) == (
        db_path.resolve(),
        1001,
    )
    detail = find_engagement_detail(ctx, "1001", _principal())
    assert detail is not None
    assert detail["detail"] is True
    assert detail["slug"] == "engagement-1001-acme-example"
    assert find_engagement_artifact(
        ctx,
        "engagement-1001-acme-example",
        "../1001_report.json",
        _principal(),
    ) == report_path

    control_con = connect_control_db(data_dir)
    try:
        assert lookup_engagement_index(control_con, "engagement-1001-acme-example") is not None
    finally:
        control_con.close()
