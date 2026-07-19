"""
tests/phase2/test_data_connector.py
Canonical: tests/phase2/test_breach_db.py

Unit tests for Module 2-A: data_connector.py
"""

from __future__ import annotations

import gzip
import sqlite3
import tempfile
from pathlib import Path

import pytest

from forge.utils.intel.data_connector import (
    BaseQueryAdapter,
    BreachFormat,
    SQLiteBreachAdapter,
    TextBreachAdapter,
    _classify_password,
    _detect_adapter,
    run_breach_query,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _set_engagement_key_env(monkeypatch):
    monkeypatch.setenv(
        "FORGE_ENGAGEMENT_KEY",
        "AGE-SECRET-KEY-1TESTTESTTESTTESTTESTTESTTESTTEST",
    )


@pytest.fixture
def sqlite_breach_db(tmp_path: Path) -> Path:
    db = tmp_path / "breach.db"
    con = sqlite3.connect(db)
    con.execute(
        "CREATE TABLE breaches (id INTEGER PRIMARY KEY, email TEXT, password TEXT, "
        "hash_type TEXT, breach_name TEXT)"
    )
    con.execute("CREATE INDEX idx_email ON breaches(email)")
    con.executemany(
        "INSERT INTO breaches (email, password, hash_type, breach_name) VALUES (?,?,?,?)",
        [
            ("alice@example.com", "P@ssw0rd!", None, "TestBreach2023"),
            ("alice@example.com", "aad3b435b51404eeaad3b435b51404ee", "ntlm", "TestBreach2023"),
            ("bob@example.com", "hunter2", None, "OtherBreach"),
        ],
    )
    con.commit()
    con.close()
    return db


@pytest.fixture
def basequery_db(tmp_path: Path) -> Path:
    db = tmp_path / "bq.db"
    con = sqlite3.connect(db)
    con.execute(
        "CREATE TABLE data (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, password TEXT)"
    )
    con.execute("CREATE INDEX idx_email ON data(email)")
    con.executemany(
        "INSERT INTO data (email, password) VALUES (?,?)",
        [
            ("victim@target.com", "ClearP@ss"),
            ("victim@target.com", "5f4dcc3b5aa765d61d8327deb882cf99"),  # md5("password")
            ("other@target.com", "$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"),
        ],
    )
    con.commit()
    con.close()
    return db


@pytest.fixture
def invalid_bq_db(tmp_path: Path) -> Path:
    db = tmp_path / "bad.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE wrong_table (id INTEGER PRIMARY KEY, user TEXT)")
    con.commit()
    con.close()
    return db


@pytest.fixture
def text_breach_file(tmp_path: Path) -> Path:
    f = tmp_path / "breach.txt"
    f.write_text(
        "alice@example.com:P@ssw0rd!\n"
        "bob@example.com:hunter2\n"
        "invalid_line_no_at\n"
        "charlie@example.com:abc123\n"
    )
    return f


@pytest.fixture
def gz_breach_file(tmp_path: Path) -> Path:
    f = tmp_path / "breach.txt.gz"
    with gzip.open(f, "wt") as fh:
        fh.write("alice@example.com:gzP@ss!\n")
        fh.write("bob@example.com:another\n")
    return f


@pytest.fixture
def engagement_db(tmp_path: Path) -> Path:
    db = tmp_path / "engagement.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE engagements (
            id INTEGER PRIMARY KEY, name TEXT, scope_json TEXT
        );
        CREATE TABLE emails (
            id INTEGER PRIMARY KEY, engagement_id INTEGER, address TEXT,
            source TEXT, discovered_at TEXT
        );
        CREATE TABLE credentials (
            id INTEGER PRIMARY KEY, engagement_id INTEGER, email TEXT,
            password_plaintext_enc TEXT, password_hash TEXT,
            hash_type TEXT, breach_name TEXT, source TEXT, discovered_at TEXT
        );
        CREATE TABLE query_audit (
            id INTEGER PRIMARY KEY, engagement_id INTEGER, source TEXT,
            email_queried TEXT, queried_at TEXT, matched INTEGER,
            records_found INTEGER, operator TEXT
        );
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            phase TEXT, module TEXT, action TEXT, target TEXT,
            result TEXT, operator TEXT, logged_at TEXT
        );
        INSERT INTO engagements (id, name, scope_json)
        VALUES (1, 'test-eng', '["example.com"]');
        INSERT INTO emails (engagement_id, address, source, discovered_at)
        VALUES (1, 'alice@example.com', 'test', '2024-01-01');
    """)
    con.commit()
    con.close()
    return db


# ---------------------------------------------------------------------------
# _classify_password
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected_plain,expected_hash",
    [
        ("P@ssw0rd!", "P@ssw0rd!", None),
        ("aad3b435b51404eeaad3b435b51404ee", None, "ntlm"),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", None, "sha1"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", None, "sha256"),
        ("$2b$12$abcdefghijklmnop", None, "bcrypt"),
        ("$1$salt$hash", None, "md5crypt"),
        ("$6$salt$hash", None, "sha512crypt"),
        ("", None, None),
    ],
)
def test_classify_password(raw, expected_plain, expected_hash):
    plain, hash_type = _classify_password(raw)
    assert plain == expected_plain
    assert hash_type == expected_hash


# ---------------------------------------------------------------------------
# SQLiteBreachAdapter
# ---------------------------------------------------------------------------


def test_sqlite_adapter_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        SQLiteBreachAdapter(tmp_path / "nonexistent.db")


def test_sqlite_adapter_finds_records(sqlite_breach_db):
    adapter = SQLiteBreachAdapter(sqlite_breach_db)
    records = list(adapter.records({"alice@example.com"}))
    assert len(records) == 2


def test_sqlite_adapter_case_insensitive(sqlite_breach_db):
    adapter = SQLiteBreachAdapter(sqlite_breach_db)
    records = list(adapter.records({"ALICE@EXAMPLE.COM"}))
    assert len(records) == 2


def test_sqlite_adapter_plaintext_classified(sqlite_breach_db):
    adapter = SQLiteBreachAdapter(sqlite_breach_db)
    records = list(adapter.records({"alice@example.com"}))
    plaintexts = [r for r in records if r.plaintext == "P@ssw0rd!"]
    assert len(plaintexts) == 1


def test_sqlite_adapter_hash_classified(sqlite_breach_db):
    adapter = SQLiteBreachAdapter(sqlite_breach_db)
    records = list(adapter.records({"alice@example.com"}))
    hashes = [r for r in records if r.hash_type == "ntlm"]
    assert len(hashes) == 1


def test_sqlite_adapter_miss_returns_empty(sqlite_breach_db):
    adapter = SQLiteBreachAdapter(sqlite_breach_db)
    records = list(adapter.records({"nobody@nowhere.com"}))
    assert records == []


# ---------------------------------------------------------------------------
# BaseQueryAdapter
# ---------------------------------------------------------------------------


def test_basequery_adapter_valid_schema(basequery_db):
    adapter = BaseQueryAdapter(basequery_db)
    records = list(adapter.records({"victim@target.com"}))
    assert len(records) == 2


def test_basequery_adapter_invalid_schema_raises(invalid_bq_db):
    with pytest.raises(ValueError, match="not found"):
        BaseQueryAdapter(invalid_bq_db)


def test_basequery_adapter_plaintext_detection(basequery_db):
    adapter = BaseQueryAdapter(basequery_db)
    records = list(adapter.records({"victim@target.com"}))
    pt_recs = [r for r in records if r.plaintext == "ClearP@ss"]
    assert len(pt_recs) == 1


def test_basequery_adapter_bcrypt_marked(basequery_db):
    adapter = BaseQueryAdapter(basequery_db)
    records = list(adapter.records({"other@target.com"}))
    bcrypt = [r for r in records if r.hash_type == "bcrypt"]
    assert len(bcrypt) == 1
    assert bcrypt[0].plaintext is None


def test_basequery_adapter_case_insensitive(basequery_db):
    adapter = BaseQueryAdapter(basequery_db)
    records = list(adapter.records({"VICTIM@TARGET.COM"}))
    assert len(records) == 2


# ---------------------------------------------------------------------------
# TextBreachAdapter
# ---------------------------------------------------------------------------


def test_text_adapter_finds_records(text_breach_file):
    adapter = TextBreachAdapter(text_breach_file)
    records = list(adapter.records({"alice@example.com"}))
    assert len(records) == 1
    assert records[0].plaintext == "P@ssw0rd!"


def test_text_adapter_skips_no_at_sign(text_breach_file):
    adapter = TextBreachAdapter(text_breach_file)
    records = list(adapter.records({"invalid_line_no_at"}))
    assert records == []


def test_text_adapter_gz(gz_breach_file):
    adapter = TextBreachAdapter(gz_breach_file, compressed=True)
    records = list(adapter.records({"alice@example.com"}))
    assert len(records) == 1
    assert records[0].plaintext == "gzP@ss!"


def test_text_adapter_pass_email_order(tmp_path):
    f = tmp_path / "reversed.txt"
    f.write_text("hunter2:bob@example.com\n")
    adapter = TextBreachAdapter(f, column_order="pass:email")
    records = list(adapter.records({"bob@example.com"}))
    assert records[0].plaintext == "hunter2"


def test_text_adapter_multi_target(text_breach_file):
    adapter = TextBreachAdapter(text_breach_file)
    records = list(adapter.records({"alice@example.com", "bob@example.com"}))
    assert len(records) == 2


# ---------------------------------------------------------------------------
# _detect_adapter
# ---------------------------------------------------------------------------


def test_detect_adapter_db_extension(sqlite_breach_db):
    adapter = _detect_adapter(sqlite_breach_db)
    assert isinstance(adapter, SQLiteBreachAdapter)


def test_detect_adapter_txt_extension(text_breach_file):
    adapter = _detect_adapter(text_breach_file)
    assert isinstance(adapter, TextBreachAdapter)


def test_detect_adapter_gz_extension(gz_breach_file):
    adapter = _detect_adapter(gz_breach_file)
    assert isinstance(adapter, TextBreachAdapter)
    assert adapter._compressed is True


def test_detect_adapter_basequery_flag(basequery_db):
    adapter = _detect_adapter(basequery_db, basequery=True)
    assert isinstance(adapter, BaseQueryAdapter)


def test_detect_adapter_explicit_format_overrides_extension(text_breach_file):
    adapter = _detect_adapter(text_breach_file, fmt=BreachFormat.TEXT)
    assert isinstance(adapter, TextBreachAdapter)


# ---------------------------------------------------------------------------
# run_breach_query
# ---------------------------------------------------------------------------


def test_run_breach_query_inserts_credential(engagement_db, sqlite_breach_db):
    con = sqlite3.connect(engagement_db)
    inserted = run_breach_query(
        db_path=sqlite_breach_db,
        engagement_id=1,
        conn=con,
        target_emails=["alice@example.com"],
    )
    con.close()
    assert inserted >= 1


def test_run_breach_query_dedup(engagement_db, sqlite_breach_db):
    con = sqlite3.connect(engagement_db)
    run_breach_query(sqlite_breach_db, 1, con, ["alice@example.com"])
    count1 = con.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
    run_breach_query(sqlite_breach_db, 1, con, ["alice@example.com"])
    count2 = con.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
    con.close()
    assert count1 == count2  # dedup: no duplicates on second run


def test_run_breach_query_dry_run_no_insert(engagement_db, sqlite_breach_db):
    con = sqlite3.connect(engagement_db)
    run_breach_query(sqlite_breach_db, 1, con, ["alice@example.com"], dry_run=True)
    count = con.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
    con.close()
    assert count == 0


def test_run_breach_query_no_plaintext_in_log(engagement_db, sqlite_breach_db):
    """Passwords must never appear in query_audit rows."""
    con = sqlite3.connect(engagement_db)
    run_breach_query(sqlite_breach_db, 1, con, ["alice@example.com"])
    logs = con.execute("SELECT * FROM query_audit").fetchall()
    con.close()
    log_str = str(logs).lower()
    assert "p@ssw0rd" not in log_str


def test_run_breach_query_encrypted_storage(engagement_db, sqlite_breach_db):
    """Stored password_plaintext_enc must not equal the raw plaintext."""
    con = sqlite3.connect(engagement_db)
    run_breach_query(sqlite_breach_db, 1, con, ["alice@example.com"])
    rows = con.execute(
        "SELECT password_plaintext_enc FROM credentials WHERE email='alice@example.com'"
    ).fetchall()
    con.close()
    for row in rows:
        if row[0]:
            assert row[0] != "P@ssw0rd!", "Plaintext stored unencrypted in credentials table"


def test_run_breach_query_no_targets_returns_zero(engagement_db, sqlite_breach_db):
    con = sqlite3.connect(engagement_db)
    # Remove all emails.
    con.execute("DELETE FROM emails WHERE engagement_id=1")
    con.commit()
    result = run_breach_query(sqlite_breach_db, 1, con)
    con.close()
    assert result == 0


def test_run_breach_query_writes_query_audit_on_v72_schema(tmp_path: Path, sqlite_breach_db: Path):
    db = tmp_path / "eng-v72.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE engagements (id INTEGER PRIMARY KEY, name TEXT, scope_json TEXT);
        CREATE TABLE emails (id INTEGER PRIMARY KEY, engagement_id INTEGER, address TEXT, source TEXT, discovered_at TEXT);
        CREATE TABLE credentials (
            id INTEGER PRIMARY KEY, engagement_id INTEGER, email TEXT,
            password_plaintext_enc TEXT, password_hash TEXT,
            hash_type TEXT, breach_name TEXT, source TEXT, discovered_at TEXT
        );
        CREATE TABLE query_audit (
            id INTEGER PRIMARY KEY, engagement_id INTEGER, source TEXT,
            email_queried TEXT, queried_at TEXT, matched INTEGER,
            records_found INTEGER, operator TEXT
        );
        INSERT INTO engagements VALUES (1, 'eng', '["example.com"]');
        INSERT INTO emails VALUES (1, 1, 'alice@example.com', 'seed', '2026-01-01');
    """)
    con.commit()

    run_breach_query(sqlite_breach_db, 1, con, ["alice@example.com"])
    count = con.execute("SELECT COUNT(*) FROM query_audit").fetchone()[0]
    con.close()
    assert count >= 1


def test_run_breach_query_supports_canonical_email_schema(tmp_path: Path, sqlite_breach_db: Path):
    db = tmp_path / "eng-canonical.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE engagements (id INTEGER PRIMARY KEY, name TEXT, scope_json TEXT);
        CREATE TABLE emails (
            id INTEGER PRIMARY KEY, engagement_id INTEGER, email TEXT,
            source TEXT, first_seen_at TEXT
        );
        CREATE TABLE credentials (
            id INTEGER PRIMARY KEY, engagement_id INTEGER, email TEXT,
            password_plaintext_enc TEXT, password_hash TEXT,
            hash_type TEXT, breach_name TEXT, source TEXT, discovered_at TEXT
        );
        CREATE TABLE query_audit (
            id INTEGER PRIMARY KEY, engagement_id INTEGER, source TEXT,
            email_queried TEXT, queried_at TEXT, matched INTEGER,
            records_found INTEGER, operator TEXT
        );
        INSERT INTO engagements VALUES (1, 'eng', '["example.com"]');
        INSERT INTO emails VALUES (1, 1, 'alice@example.com', 'seed', '2026-01-01');
    """)
    con.commit()

    inserted = run_breach_query(sqlite_breach_db, 1, con)
    con.close()
    assert inserted >= 1
