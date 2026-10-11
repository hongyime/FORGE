"""Tests for the Wave 2 #20 recursion_intents table and ``forge recursion`` CLI."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from forge.db.migrations import TARGET_VERSION, run_migrations
from forge.db.schema import apply_schema
from forge.db.validation import validate_canonical_schema
from forge.recursion.cli import register_recursion_commands
from forge.recursion.store import (
    ALLOWED_STATUSES,
    IntentStoreError,
    add_intent,
    count_intents,
    list_intents,
)


def _build_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    apply_schema(con)
    run_migrations(con)
    validate_canonical_schema(con)
    con.execute(
        """
        INSERT INTO engagements (id, name, scope_json, status, operator)
        VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'tester')
        """
    )
    con.commit()
    return con


# ---------------------------------------------------------------------------
# Migration + schema
# ---------------------------------------------------------------------------


def test_schema_includes_recursion_intents_table(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "schema.db")
    try:
        row = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='recursion_intents'"
        ).fetchone()
        assert row is not None
        columns = {str(r[1]) for r in con.execute("PRAGMA table_info(recursion_intents)")}
        assert columns == {
            "intent_id",
            "source_fact_id",
            "target_seed",
            "seed_type",
            "rationale",
            "created_at",
            "claimed_by",
            "claimed_at",
            "completed_fact_id",
            "status",
            "engagement_id",
        }
    finally:
        con.close()


def test_recursion_intents_check_rejects_invalid_status(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "check.db")
    try:
        with pytest.raises(sqlite3.IntegrityError):
            con.execute(
                """
                INSERT INTO recursion_intents (intent_id, target_seed, status)
                VALUES ('x', 'acme.example', 'bogus')
                """
            )
    finally:
        con.close()


def test_target_version_covers_recursion_intents(tmp_path: Path) -> None:
    """Database should land at the current TARGET_VERSION (>= 51)."""
    con = _build_db(tmp_path / "ver.db")
    try:
        row = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()
        assert int(row[0]) == TARGET_VERSION
        assert TARGET_VERSION >= 51
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


def test_store_add_intent_persists_defaults(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "add.db")
    try:
        created = add_intent(
            con,
            target_seed="acme.example",
            rationale="follow-up on validated cloud ref",
            source_fact_id="cloud_ref:1234",
            seed_type="domain",
            engagement_id="1001",
        )
        con.commit()

        assert created["target_seed"] == "acme.example"
        assert created["status"] == "open"
        assert created["engagement_id"] == "1001"
        assert created["source_fact_id"] == "cloud_ref:1234"
        assert created["seed_type"] == "domain"
        assert created["intent_id"]
        assert created["created_at"]
        assert created["claimed_by"] is None
        assert created["completed_fact_id"] is None
    finally:
        con.close()


def test_store_add_intent_rejects_blank_target_seed(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "blank.db")
    try:
        with pytest.raises(IntentStoreError):
            add_intent(con, target_seed="  ", engagement_id="1001")
    finally:
        con.close()


def test_store_add_intent_rejects_unknown_status(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "status.db")
    try:
        with pytest.raises(IntentStoreError):
            add_intent(
                con,
                target_seed="acme.example",
                status="not-a-real-status",
                engagement_id="1001",
            )
    finally:
        con.close()


def test_store_add_intent_rejects_duplicate_intent_id(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "dupe.db")
    try:
        add_intent(con, target_seed="a.example", intent_id="dupe-1", engagement_id="1001")
        con.commit()
        with pytest.raises(IntentStoreError):
            add_intent(
                con,
                target_seed="b.example",
                intent_id="dupe-1",
                engagement_id="1001",
            )
    finally:
        con.close()


def test_store_list_intents_filters_by_engagement_and_status(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "list.db")
    try:
        add_intent(con, target_seed="a.example", engagement_id="1001")
        add_intent(con, target_seed="b.example", engagement_id="1001", status="claimed")
        add_intent(con, target_seed="c.example", engagement_id="2002")
        con.commit()

        all_1001 = list_intents(con, engagement_id="1001")
        assert [row["target_seed"] for row in all_1001] == ["b.example", "a.example"] or len(
            all_1001
        ) == 2
        assert {row["target_seed"] for row in all_1001} == {"a.example", "b.example"}

        only_claimed = list_intents(con, engagement_id="1001", status="claimed")
        assert [row["target_seed"] for row in only_claimed] == ["b.example"]

        across = list_intents(con)
        assert len(across) == 3

        assert count_intents(con, engagement_id="1001") == 2
        assert count_intents(con, engagement_id="1001", status="open") == 1
    finally:
        con.close()


def test_store_list_intents_bounds_limit(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "limit.db")
    try:
        for n in range(5):
            add_intent(
                con,
                target_seed=f"seed-{n}.example",
                engagement_id="1001",
            )
        con.commit()
        rows = list_intents(con, engagement_id="1001", limit=2)
        assert len(rows) == 2
        assert count_intents(con, engagement_id="1001") == 5
    finally:
        con.close()


def test_store_allowed_statuses_are_canonical() -> None:
    assert ALLOWED_STATUSES == ("open", "claimed", "completed", "abandoned")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_cli_app() -> typer.Typer:
    app = typer.Typer()
    recursion = typer.Typer(name="recursion", no_args_is_help=True)
    register_recursion_commands(recursion)
    app.add_typer(recursion, name="recursion")
    return app


def _patch_engagement_db(monkeypatch, db_path: Path) -> None:
    """Point ForgeConfig.engagement_db_path at the test SQLite file."""
    from forge.config import ForgeConfig

    def _resolve(_self, _engagement_id: str) -> Path:
        return db_path

    monkeypatch.setattr(ForgeConfig, "engagement_db_path", _resolve)


def test_cli_intents_add_and_list_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "cli.db"
    con = _build_db(db_path)
    con.close()
    _patch_engagement_db(monkeypatch, db_path)

    runner = CliRunner()
    app = _build_cli_app()

    add_result = runner.invoke(
        app,
        [
            "recursion",
            "intents",
            "add",
            "--engagement",
            "1001",
            "--target-seed",
            "cloud.example",
            "--rationale",
            "operator follow-up",
            "--seed-type",
            "domain",
            "--json",
        ],
    )
    assert add_result.exit_code == 0, add_result.stdout
    add_payload = json.loads(add_result.stdout)
    assert add_payload["engagement_id"] == "1001"
    assert add_payload["intent"]["target_seed"] == "cloud.example"
    assert add_payload["intent"]["status"] == "open"

    list_result = runner.invoke(
        app,
        [
            "recursion",
            "intents",
            "list",
            "--engagement",
            "1001",
            "--json",
        ],
    )
    assert list_result.exit_code == 0, list_result.stdout
    list_payload = json.loads(list_result.stdout)
    assert list_payload["engagement_id"] == "1001"
    assert list_payload["total_count"] == 1
    assert list_payload["selected_count"] == 1
    assert list_payload["intents"][0]["target_seed"] == "cloud.example"


def test_cli_intents_list_status_filter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "filter.db"
    con = _build_db(db_path)
    try:
        add_intent(con, target_seed="a.example", engagement_id="1001")
        add_intent(con, target_seed="b.example", engagement_id="1001", status="claimed")
        con.commit()
    finally:
        con.close()
    _patch_engagement_db(monkeypatch, db_path)

    runner = CliRunner()
    app = _build_cli_app()

    all_result = runner.invoke(
        app,
        ["recursion", "intents", "list", "--engagement", "1001", "--json"],
    )
    assert all_result.exit_code == 0
    assert json.loads(all_result.stdout)["total_count"] == 2

    claimed_result = runner.invoke(
        app,
        [
            "recursion",
            "intents",
            "list",
            "--engagement",
            "1001",
            "--status",
            "claimed",
            "--json",
        ],
    )
    assert claimed_result.exit_code == 0
    payload = json.loads(claimed_result.stdout)
    assert payload["total_count"] == 1
    assert payload["intents"][0]["target_seed"] == "b.example"


def test_cli_intents_add_rejects_blank_target_seed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "blank_cli.db"
    con = _build_db(db_path)
    con.close()
    _patch_engagement_db(monkeypatch, db_path)

    runner = CliRunner()
    app = _build_cli_app()

    result = runner.invoke(
        app,
        [
            "recursion",
            "intents",
            "add",
            "--engagement",
            "1001",
            "--target-seed",
            "   ",
            "--json",
        ],
    )
    assert result.exit_code != 0


def test_cli_intents_list_bad_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "bad_status.db"
    con = _build_db(db_path)
    con.close()
    _patch_engagement_db(monkeypatch, db_path)

    runner = CliRunner()
    app = _build_cli_app()

    result = runner.invoke(
        app,
        [
            "recursion",
            "intents",
            "list",
            "--engagement",
            "1001",
            "--status",
            "not-real",
            "--json",
        ],
    )
    assert result.exit_code != 0
