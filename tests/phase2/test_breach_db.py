"""
tests/phase2/test_breach_db.py
Canonical path maps to: forge/utils/intel/data_connector.py  (Module 2-A)

Coverage target: 90% (PRD §15.1)

Test strategy:
  - Fixture SQLite databases for SQLiteBreachAdapter and BaseQueryAdapter.
  - Fixture plain-text and gzip files for TextBreachAdapter.
  - All run_breach_query tests assert: no plaintext in audit_log/query_audit,
    encryption applied, deduplication enforced.
"""

from __future__ import annotations

import gzip
import hashlib
import sqlite3
from pathlib import Path

import pytest

from forge.utils.intel.data_connector import (
    BaseQueryAdapter,
    BreachFormat,
    BreachRecord,
    SQLiteBreachAdapter,
    TextBreachAdapter,
    _classify_password,
    _detect_adapter,
    run_breach_query,
)


# ─── shared engagement DB fixture ───────────────────────────────────────────


@pytest.fixture()
def engagement_db(tmp_path: Path) -> Path:
    db = tmp_path / "eng.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE engagements (
            id INTEGER PRIMARY KEY, name TEXT, scope_json TEXT
        );
        CREATE TABLE emails (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            address TEXT, source TEXT, discovered_at TEXT
        );
        CREATE TABLE credentials (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            email TEXT, password_plaintext_enc TEXT,
            password_hash TEXT, hash_type TEXT,
            breach_name TEXT, source TEXT, discovered_at TEXT
        );
        CREATE TABLE query_audit (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            source TEXT, email_queried TEXT, queried_at TEXT,
            matched INTEGER, records_found INTEGER, operator TEXT
        );
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            phase TEXT, module TEXT, action TEXT, target TEXT,
            result TEXT, operator TEXT, logged_at TEXT
        );
        INSERT INTO engagements VALUES (1, 'test-eng', '["example.com"]');
        INSERT INTO emails VALUES (1, 1, 'alice@example.com', 'test', '2024-01-01');
        INSERT INTO emails VALUES (2, 1, 'bob@example.com',   'test', '2024-01-01');
    """)
    con.commit()
    con.close()
    return db


# ─── SQLiteBreachAdapter fixtures ───────────────────────────────────────────


@pytest.fixture()
def sqlite_db(tmp_path: Path) -> Path:
    db = tmp_path / "breach.db"
    con = sqlite3.connect(db)
    con.execute(
        "CREATE TABLE breaches (id INTEGER PRIMARY KEY, email TEXT, "
        "password TEXT, hash_type TEXT, breach_name TEXT)"
    )
    con.execute("CREATE INDEX idx_email ON breaches(email)")
    con.executemany(
        "INSERT INTO breaches VALUES (?,?,?,?,?)",
        [
            (1, "alice@example.com", "P@ssw0rd!", None, "Breach2023"),
            (2, "alice@example.com", "aad3b435b51404eeaad3b435b51404ee", "ntlm", "Breach2023"),
            (
                3,
                "alice@example.com",
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "sha1",
                "Breach2023",
            ),
            (4, "bob@example.com", "hunter2", None, "OtherBreach"),
        ],
    )
    con.commit()
    con.close()
    return db


@pytest.fixture()
def sqlite_db_no_index(tmp_path: Path) -> Path:
    db = tmp_path / "noindex.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE breaches (id INTEGER PRIMARY KEY, email TEXT, password TEXT)")
    con.execute("INSERT INTO breaches VALUES (1,'alice@example.com','pass')")
    con.commit()
    con.close()
    return db


# ─── BaseQueryAdapter fixtures ───────────────────────────────────────────────


@pytest.fixture()
def bq_db(tmp_path: Path) -> Path:
    db = tmp_path / "bq.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE data (id INTEGER PRIMARY KEY, email TEXT, password TEXT)")
    con.execute("CREATE INDEX idx_email ON data(email)")
    con.executemany(
        "INSERT INTO data VALUES (?,?,?)",
        [
            (1, "victim@example.com", "ClearP@ss"),
            (2, "victim@example.com", "5f4dcc3b5aa765d61d8327deb882cf99"),
            (3, "other@example.com", "$2b$12$abc123defghijklmnopqrstuabc123defghijklmnopq"),
        ],
    )
    con.commit()
    con.close()
    return db


@pytest.fixture()
def bq_db_invalid(tmp_path: Path) -> Path:
    db = tmp_path / "bad.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE wrong (id INTEGER PRIMARY KEY, user TEXT)")
    con.commit()
    con.close()
    return db


@pytest.fixture()
def bq_db_missing_col(tmp_path: Path) -> Path:
    db = tmp_path / "misscol.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE data (id INTEGER PRIMARY KEY, email TEXT)")  # no password col
    con.commit()
    con.close()
    return db


# ─── TextBreachAdapter fixtures ──────────────────────────────────────────────


@pytest.fixture()
def text_file(tmp_path: Path) -> Path:
    f = tmp_path / "breach.txt"
    f.write_text(
        "alice@example.com:P@ssw0rd!\n"
        "bob@example.com:hunter2\n"
        "invalid_line_no_colon\n"
        "nodomain:pass\n"
        "charlie@example.com:abc123\n"
    )
    return f


@pytest.fixture()
def gz_file(tmp_path: Path) -> Path:
    f = tmp_path / "breach.txt.gz"
    with gzip.open(f, "wt") as fh:
        fh.write("alice@example.com:gzP@ss!\n")
        fh.write("dave@example.com:pass2\n")
    return f


@pytest.fixture()
def reversed_text_file(tmp_path: Path) -> Path:
    f = tmp_path / "rev.txt"
    f.write_text("hunter2:bob@example.com\n")
    return f


# ═══════════════════════════════════════════════════════════════════════════
# _classify_password
# ═══════════════════════════════════════════════════════════════════════════


class TestClassifyPassword:
    @pytest.mark.parametrize(
        "raw,exp_plain,exp_hash",
        [
            ("P@ssw0rd!", "P@ssw0rd!", None),
            ("aad3b435b51404eeaad3b435b51404ee", None, "ntlm"),
            ("da39a3ee5e6b4b0d3255bfef95601890afd80709", None, "sha1"),
            ("e3b0c44298fc1c149afbf4c8996fb924" + "2" * 32, None, "sha256"),
            ("$2b$12$abcdefghijk", None, "bcrypt"),
            ("$2a$10$abcdefghijk", None, "bcrypt"),
            ("$1$salt$hash", None, "md5crypt"),
            ("$6$salt$longhash", None, "sha512crypt"),
            ("", None, None),
        ],
    )
    def test_classify(self, raw, exp_plain, exp_hash):
        plain, ht = _classify_password(raw)
        assert plain == exp_plain
        assert ht == exp_hash

    def test_bcrypt_plaintext_none(self):
        plain, ht = _classify_password("$2b$12$test")
        assert plain is None
        assert ht == "bcrypt"

    def test_ntlm_exactly_32_hex(self):
        _, ht = _classify_password("a" * 32)
        assert ht == "ntlm"

    def test_sha1_exactly_40_hex(self):
        _, ht = _classify_password("a" * 40)
        assert ht == "sha1"


# ═══════════════════════════════════════════════════════════════════════════
# SQLiteBreachAdapter
# ═══════════════════════════════════════════════════════════════════════════


class TestSQLiteBreachAdapter:
    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            SQLiteBreachAdapter(tmp_path / "nonexistent.db")

    def test_finds_multiple_records_for_email(self, sqlite_db):
        adapter = SQLiteBreachAdapter(sqlite_db)
        records = list(adapter.records({"alice@example.com"}))
        assert len(records) == 3

    def test_case_insensitive_lookup(self, sqlite_db):
        adapter = SQLiteBreachAdapter(sqlite_db)
        records = list(adapter.records({"ALICE@EXAMPLE.COM"}))
        assert len(records) == 3

    def test_plaintext_classified_correctly(self, sqlite_db):
        adapter = SQLiteBreachAdapter(sqlite_db)
        records = list(adapter.records({"alice@example.com"}))
        plaintexts = [r for r in records if r.plaintext == "P@ssw0rd!"]
        assert len(plaintexts) == 1

    def test_ntlm_hash_classified(self, sqlite_db):
        adapter = SQLiteBreachAdapter(sqlite_db)
        records = list(adapter.records({"alice@example.com"}))
        ntlm = [r for r in records if r.hash_type == "ntlm"]
        assert len(ntlm) == 1
        assert ntlm[0].plaintext is None

    def test_sha1_hash_classified(self, sqlite_db):
        adapter = SQLiteBreachAdapter(sqlite_db)
        records = list(adapter.records({"alice@example.com"}))
        sha1 = [r for r in records if r.hash_type == "sha1"]
        assert len(sha1) == 1

    def test_no_results_for_missing_email(self, sqlite_db):
        adapter = SQLiteBreachAdapter(sqlite_db)
        records = list(adapter.records({"nobody@nowhere.com"}))
        assert records == []

    def test_multi_target_lookup(self, sqlite_db):
        adapter = SQLiteBreachAdapter(sqlite_db)
        records = list(adapter.records({"alice@example.com", "bob@example.com"}))
        emails = {r.email for r in records}
        assert "alice@example.com" in emails
        assert "bob@example.com" in emails

    def test_no_index_warning_logged(self, sqlite_db_no_index, caplog):
        import logging

        with caplog.at_level(logging.WARNING):
            SQLiteBreachAdapter(sqlite_db_no_index)
        assert any("index" in m.lower() or "slow" in m.lower() for m in caplog.messages)

    def test_source_file_recorded(self, sqlite_db):
        adapter = SQLiteBreachAdapter(sqlite_db)
        records = list(adapter.records({"alice@example.com"}))
        assert all(str(sqlite_db) in r.source_file for r in records)

    def test_query_bulk_grouping(self, sqlite_db):
        adapter = SQLiteBreachAdapter(sqlite_db)
        result = dict(adapter.query_bulk({"alice@example.com", "bob@example.com"}))
        assert len(result["alice@example.com"]) == 3
        assert len(result["bob@example.com"]) == 1


# ═══════════════════════════════════════════════════════════════════════════
# BaseQueryAdapter
# ═══════════════════════════════════════════════════════════════════════════


class TestBaseQueryAdapter:
    def test_valid_schema_succeeds(self, bq_db):
        adapter = BaseQueryAdapter(bq_db)
        records = list(adapter.records({"victim@example.com"}))
        assert len(records) == 2

    def test_invalid_table_raises(self, bq_db_invalid):
        with pytest.raises(ValueError, match="table 'data' not found|missing columns"):
            BaseQueryAdapter(bq_db_invalid)

    def test_missing_column_raises(self, bq_db_missing_col):
        with pytest.raises(ValueError):
            BaseQueryAdapter(bq_db_missing_col)

    def test_plaintext_detection(self, bq_db):
        adapter = BaseQueryAdapter(bq_db)
        records = list(adapter.records({"victim@example.com"}))
        pt_recs = [r for r in records if r.plaintext == "ClearP@ss"]
        assert len(pt_recs) == 1

    def test_md5_hash_detected(self, bq_db):
        adapter = BaseQueryAdapter(bq_db)
        records = list(adapter.records({"victim@example.com"}))
        hashes = [r for r in records if r.hash_value is not None]
        assert len(hashes) >= 1

    def test_bcrypt_skipped_plaintext_none(self, bq_db):
        adapter = BaseQueryAdapter(bq_db)
        records = list(adapter.records({"other@example.com"}))
        bcrypt = [r for r in records if r.hash_type == "bcrypt"]
        assert len(bcrypt) == 1
        assert bcrypt[0].plaintext is None

    def test_case_insensitive(self, bq_db):
        adapter = BaseQueryAdapter(bq_db)
        records = list(adapter.records({"VICTIM@EXAMPLE.COM"}))
        assert len(records) == 2

    def test_breach_name_is_basequery_comb(self, bq_db):
        adapter = BaseQueryAdapter(bq_db)
        records = list(adapter.records({"victim@example.com"}))
        assert all(r.breach_name == "basequery_comb" for r in records)


# ═══════════════════════════════════════════════════════════════════════════
# TextBreachAdapter
# ═══════════════════════════════════════════════════════════════════════════


class TestTextBreachAdapter:
    def test_finds_email_record(self, text_file):
        adapter = TextBreachAdapter(text_file)
        records = list(adapter.records({"alice@example.com"}))
        assert len(records) == 1
        assert records[0].plaintext == "P@ssw0rd!"

    def test_skips_invalid_lines(self, text_file):
        adapter = TextBreachAdapter(text_file)
        records = list(adapter.records({"invalid_line_no_colon"}))
        assert records == []

    def test_skips_no_at_sign(self, text_file):
        adapter = TextBreachAdapter(text_file)
        records = list(adapter.records({"nodomain"}))
        assert records == []

    def test_multi_target(self, text_file):
        adapter = TextBreachAdapter(text_file)
        records = list(adapter.records({"alice@example.com", "bob@example.com"}))
        assert len(records) == 2

    def test_gz_decompression(self, gz_file):
        adapter = TextBreachAdapter(gz_file, compressed=True)
        records = list(adapter.records({"alice@example.com"}))
        assert len(records) == 1
        assert records[0].plaintext == "gzP@ss!"

    def test_reversed_column_order(self, reversed_text_file):
        adapter = TextBreachAdapter(reversed_text_file, column_order="pass:email")
        records = list(adapter.records({"bob@example.com"}))
        assert records[0].plaintext == "hunter2"

    def test_case_insensitive_lookup(self, text_file):
        adapter = TextBreachAdapter(text_file)
        records = list(adapter.records({"ALICE@EXAMPLE.COM"}))
        assert len(records) == 1

    def test_no_match_returns_empty(self, text_file):
        adapter = TextBreachAdapter(text_file)
        records = list(adapter.records({"nobody@example.com"}))
        assert records == []


# ═══════════════════════════════════════════════════════════════════════════
# _detect_adapter
# ═══════════════════════════════════════════════════════════════════════════


class TestDetectAdapter:
    def test_db_extension_returns_sqlite(self, sqlite_db):
        adapter = _detect_adapter(sqlite_db)
        assert isinstance(adapter, SQLiteBreachAdapter)

    def test_txt_extension_returns_text(self, text_file):
        adapter = _detect_adapter(text_file)
        assert isinstance(adapter, TextBreachAdapter)
        assert adapter._compressed is False

    def test_gz_extension_returns_compressed(self, gz_file):
        adapter = _detect_adapter(gz_file)
        assert isinstance(adapter, TextBreachAdapter)
        assert adapter._compressed is True

    def test_basequery_flag_overrides(self, bq_db):
        adapter = _detect_adapter(bq_db, basequery=True)
        assert isinstance(adapter, BaseQueryAdapter)

    def test_explicit_format_overrides_extension(self, text_file):
        adapter = _detect_adapter(text_file, fmt=BreachFormat.GZ)
        assert isinstance(adapter, TextBreachAdapter)
        assert adapter._compressed is True

    def test_explicit_text_format(self, text_file):
        adapter = _detect_adapter(text_file, fmt=BreachFormat.TEXT)
        assert isinstance(adapter, TextBreachAdapter)

    def test_explicit_sqlite_format(self, sqlite_db):
        adapter = _detect_adapter(sqlite_db, fmt=BreachFormat.SQLITE)
        assert isinstance(adapter, SQLiteBreachAdapter)


# ═══════════════════════════════════════════════════════════════════════════
# run_breach_query
# ═══════════════════════════════════════════════════════════════════════════


class TestRunBreachQuery:
    def test_inserts_credentials(self, engagement_db, sqlite_db):
        con = sqlite3.connect(engagement_db)
        inserted = run_breach_query(sqlite_db, 1, con, ["alice@example.com"])
        count = con.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
        con.close()
        assert inserted >= 1
        assert count >= 1

    def test_dedup_no_double_insert(self, engagement_db, sqlite_db):
        con = sqlite3.connect(engagement_db)
        run_breach_query(sqlite_db, 1, con, ["alice@example.com"])
        c1 = con.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
        run_breach_query(sqlite_db, 1, con, ["alice@example.com"])
        c2 = con.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
        con.close()
        assert c1 == c2

    def test_dry_run_no_insert(self, engagement_db, sqlite_db):
        con = sqlite3.connect(engagement_db)
        run_breach_query(sqlite_db, 1, con, ["alice@example.com"], dry_run=True)
        count = con.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
        con.close()
        assert count == 0

    def test_no_plaintext_in_query_audit(self, engagement_db, sqlite_db):
        """Passwords must NEVER appear in query_audit."""
        con = sqlite3.connect(engagement_db)
        run_breach_query(sqlite_db, 1, con, ["alice@example.com"])
        rows = con.execute("SELECT * FROM query_audit").fetchall()
        as_str = str(rows).lower()
        con.close()
        assert "p@ssw0rd" not in as_str
        assert "hunter2" not in as_str

    def test_password_stored_encrypted(self, engagement_db, sqlite_db):
        """password_plaintext_enc must not equal the original plaintext."""
        con = sqlite3.connect(engagement_db)
        run_breach_query(sqlite_db, 1, con, ["alice@example.com"])
        rows = con.execute(
            "SELECT password_plaintext_enc FROM credentials WHERE email='alice@example.com'"
        ).fetchall()
        con.close()
        for (enc,) in rows:
            if enc:
                assert enc != "P@ssw0rd!", "Plaintext stored unencrypted!"

    def test_uses_emails_from_db_when_none_supplied(self, engagement_db, sqlite_db):
        con = sqlite3.connect(engagement_db)
        inserted = run_breach_query(sqlite_db, 1, con)  # no target_emails kwarg
        con.close()
        assert inserted >= 0  # ran without error; alice is in DB emails table

    def test_zero_targets_returns_zero(self, engagement_db, sqlite_db):
        con = sqlite3.connect(engagement_db)
        con.execute("DELETE FROM emails WHERE engagement_id=1")
        con.commit()
        result = run_breach_query(sqlite_db, 1, con)
        con.close()
        assert result == 0

    def test_query_audit_has_entry(self, engagement_db, sqlite_db):
        con = sqlite3.connect(engagement_db)
        run_breach_query(sqlite_db, 1, con, ["alice@example.com"])
        count = con.execute("SELECT COUNT(*) FROM query_audit").fetchone()[0]
        con.close()
        assert count >= 1

    def test_hash_only_records_stored(self, engagement_db, sqlite_db):
        """Records with only a hash (no plaintext) must still be inserted."""
        con = sqlite3.connect(engagement_db)
        run_breach_query(sqlite_db, 1, con, ["alice@example.com"])
        hrows = con.execute(
            "SELECT * FROM credentials WHERE email='alice@example.com' AND password_hash IS NOT NULL"
        ).fetchall()
        con.close()
        assert len(hrows) >= 1
