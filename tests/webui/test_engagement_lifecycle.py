import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from forge.db.control import connect_control_db, lookup_engagement_index
from forge.db.direct_connect import direct_connect
from forge.webui.engagement_lifecycle import (
    create_engagement_record,
    create_engagement_route_payload,
    index_webui_engagement_summary,
    normalize_create_engagement_request,
    normalize_engagement_tags,
    update_engagement_record,
    update_engagement_route_payload,
)


def _detail_payload(db_path: Path, con: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    seeds = con.execute(
        """
        SELECT seed_value, seed_type, source
        FROM engagement_seeds
        WHERE engagement_id=?
        ORDER BY id
        """,
        (int(row["id"]),),
    ).fetchall()
    return {
        "id": int(row["id"]),
        "slug": f"engagement-{int(row['id'])}-{str(row['name']).lower().replace(' ', '-')}",
        "name": str(row["name"]),
        "workspace_id": str(row["workspace_id"]),
        "status": str(row["status"]),
        "operator": str(row["operator"]),
        "created_at": str(row["created_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
        "scope": json.loads(str(row["scope_json"] or "[]")),
        "seeds": [
            {
                "seed_value": str(seed["seed_value"]),
                "seed_type": str(seed["seed_type"]),
                "source": str(seed["source"]),
            }
            for seed in seeds
        ],
        "path": db_path.as_posix(),
    }


def test_normalize_create_engagement_request_parses_tags_and_seeds() -> None:
    request = normalize_create_engagement_request(
        {
            "name": " Beta Example ",
            "status": "prep",
            "tags": "External, external\nPriority",
            "workspace_id": "",
            "seeds": [
                "HTTPS://BETA.EXAMPLE:443/login#top",
                "https://beta.example/login",
                {"seed_value": "security@beta.example", "source": "scope"},
            ],
        },
        principal_subject="architect",
        principal_workspace_id="default",
        default_operator="fallback",
    )

    assert request.name == "Beta Example"
    assert request.status == "PREP"
    assert request.operator == "architect"
    assert request.workspace_id == "default"
    assert request.metadata == {"tags": ["External", "Priority"]}
    assert request.seeds == [
        {
            "seed_value": "https://beta.example/login",
            "seed_type": "url",
            "source": "operator",
        },
        {
            "seed_value": "security@beta.example",
            "seed_type": "email",
            "source": "scope",
        },
    ]


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({"seeds": ["beta.example"]}, "name is required"),
        ({"name": "Beta", "status": "UNKNOWN", "seeds": ["beta.example"]}, "Invalid engagement status"),
        ({"name": "Beta", "seeds": []}, "seeds must be a non-empty list"),
    ],
)
def test_normalize_create_engagement_request_rejects_invalid_input(
    body: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        normalize_create_engagement_request(
            body,
            principal_subject="architect",
            principal_workspace_id="default",
            default_operator="fallback",
        )


def test_create_engagement_record_bootstraps_workspace_and_seeds(tmp_path: Path) -> None:
    db_path = tmp_path / "1001.db"
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    request = normalize_create_engagement_request(
        {
            "name": "Beta Example",
            "status": "PREP",
            "metadata": {"tags": ["external", "beta"]},
            "seeds": ["beta.example", {"seed_value": "security@beta.example", "source": "scope"}],
        },
        principal_subject="architect",
        principal_workspace_id="default",
        default_operator="fallback",
    )

    detail = create_engagement_record(
        con,
        db_path=db_path,
        engagement_id=1001,
        request=request,
        member_subject="architect",
        detail_payload_builder=_detail_payload,
    )

    assert detail["scope"] == ["beta.example", "*.beta.example", "security@beta.example"]
    assert detail["seeds"] == [
        {"seed_value": "beta.example", "seed_type": "domain", "source": "operator"},
        {"seed_value": "security@beta.example", "seed_type": "email", "source": "scope"},
    ]
    workspace_row = con.execute(
        "SELECT workspace_id, name FROM workspaces WHERE workspace_id='default'"
    ).fetchone()
    assert tuple(workspace_row) == ("default", "Default Workspace")
    membership_row = con.execute(
        """
        SELECT workspace_id, subject, role, permissions_json
        FROM workspace_memberships
        WHERE workspace_id='default' AND subject='architect'
        """
    ).fetchone()
    assert tuple(membership_row) == ("default", "architect", "owner", '["*"]')
    metadata = json.loads(
        con.execute("SELECT metadata_json FROM engagements WHERE id=1001").fetchone()[0]
    )
    assert metadata == {"tags": ["external", "beta"]}


def test_create_engagement_route_payload_indexes_control_summary(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = data_dir / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True)
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    request = normalize_create_engagement_request(
        {"name": "Beta Example", "seeds": ["beta.example"]},
        principal_subject="architect",
        principal_workspace_id="alpha",
        default_operator="fallback",
    )
    try:
        detail = create_engagement_route_payload(
            con,
            data_dir=data_dir,
            db_path=db_path,
            engagement_id=1001,
            request=request,
            member_subject="architect",
            detail_payload_builder=_detail_payload,
        )
    finally:
        con.close()

    assert detail["workspace_id"] == "alpha"
    control_con = connect_control_db(data_dir)
    try:
        index_row = lookup_engagement_index(control_con, "engagement-1001-beta-example")
        assert index_row is not None
        assert int(index_row["engagement_id"]) == 1001
        assert str(index_row["workspace_id"]) == "alpha"
    finally:
        control_con.close()


def test_update_engagement_record_merges_metadata_and_reindexes_payload(tmp_path: Path) -> None:
    db_path = tmp_path / "1001.db"
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    request = normalize_create_engagement_request(
        {"name": "Beta Example", "seeds": ["beta.example"], "metadata": {"keep": True}},
        principal_subject="architect",
        principal_workspace_id="default",
        default_operator="fallback",
    )
    create_engagement_record(
        con,
        db_path=db_path,
        engagement_id=1001,
        request=request,
        member_subject="architect",
        detail_payload_builder=_detail_payload,
    )

    detail = update_engagement_record(
        con,
        db_path=db_path,
        engagement_id=1001,
        body={
            "name": "Beta Example Updated",
            "status": "COMPLETE",
            "operator": "architect-two",
            "metadata": {"extra": "value"},
            "tags": ["priority-high", "priority-high", "beta-expanded"],
        },
        detail_payload_builder=_detail_payload,
    )

    assert detail["name"] == "Beta Example Updated"
    assert detail["status"] == "COMPLETE"
    assert detail["operator"] == "architect-two"
    metadata = json.loads(
        con.execute("SELECT metadata_json FROM engagements WHERE id=1001").fetchone()[0]
    )
    assert metadata == {
        "extra": "value",
        "keep": True,
        "tags": ["priority-high", "beta-expanded"],
    }


def test_update_engagement_route_payload_refreshes_control_summary(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = data_dir / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True)
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    request = normalize_create_engagement_request(
        {"name": "Beta Example", "seeds": ["beta.example"]},
        principal_subject="architect",
        principal_workspace_id="default",
        default_operator="fallback",
    )
    create_engagement_route_payload(
        con,
        data_dir=data_dir,
        db_path=db_path,
        engagement_id=1001,
        request=request,
        member_subject="architect",
        detail_payload_builder=_detail_payload,
    )

    try:
        detail = update_engagement_route_payload(
            con,
            data_dir=data_dir,
            db_path=db_path,
            engagement_id=1001,
            body={"name": "Beta Example Updated", "status": "COMPLETE"},
            detail_payload_builder=_detail_payload,
        )
    finally:
        con.close()

    assert detail["name"] == "Beta Example Updated"
    control_con = connect_control_db(data_dir)
    try:
        index_row = lookup_engagement_index(control_con, "engagement-1001-beta-example-updated")
        assert index_row is not None
        assert str(index_row["status"]) == "COMPLETE"
    finally:
        control_con.close()


def test_index_webui_engagement_summary_writes_control_index_and_optional_owner(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = data_dir / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True)
    db_path.write_bytes(b"sqlite")
    summary = {
        "id": 1001,
        "workspace_id": "alpha",
        "slug": "engagement-1001-alpha",
        "name": "Alpha",
        "status": "ACTIVE",
        "operator": "architect",
        "created_at": "2026-08-13 10:00:00",
        "updated_at": "2026-08-13 10:00:00",
    }

    index_webui_engagement_summary(
        data_dir,
        db_path,
        summary,
        member_subject="architect",
    )

    control_con = connect_control_db(data_dir)
    try:
        index_row = lookup_engagement_index(control_con, "engagement-1001-alpha")
        assert index_row is not None
        assert int(index_row["engagement_id"]) == 1001
        assert str(index_row["workspace_id"]) == "alpha"
        membership_row = control_con.execute(
            """
            SELECT workspace_id, subject, role, permissions_json
            FROM workspace_memberships
            WHERE workspace_id='alpha' AND subject='architect'
            """
        ).fetchone()
        assert tuple(membership_row) == ("alpha", "architect", "owner", '["*"]')
    finally:
        control_con.close()


def test_normalize_engagement_tags_caps_count_and_length() -> None:
    raw = [f" tag {idx} " for idx in range(20)]
    raw[1] = "TAG 0"
    raw[2] = "x" * 80

    tags = normalize_engagement_tags(raw)

    assert tags[0] == "tag 0"
    assert tags[1] == "x" * 48
    assert len(tags) == 12
