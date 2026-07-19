"""
tests/phase4/test_hash_credential_bridge.py
Unit tests for hash_credential_bridge.py (Module 4-C).
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from forge.phase4.hash_credential_bridge import (
    HashAttackClass,
    HashCredential,
    HashCredentialBridge,
    HashCredentialSet,
    classify_hash_attack_from_exploit,
)


# ══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def db_with_hashes(tmp_path: Path) -> Path:
    db = tmp_path / "eng.db"
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    con.executescript("""
        CREATE TABLE credentials (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            email TEXT, validated INTEGER DEFAULT 0,
            password_hash TEXT, hash_type TEXT,
            hash_plaintext TEXT, hash_crack_source TEXT
        );
        -- Uncracked NTLM hash
        INSERT INTO credentials VALUES
            (1, 1, 'alice@corp.com', 0,
             'aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4',
             'NTLM', NULL, NULL);
        -- Cracked hash
        INSERT INTO credentials VALUES
            (2, 1, 'bob@corp.com', 0,
             '$2a$10$abc123', 'BCRYPT',
             'AGE1ENCRYPTED_PLAINTEXT', 'hashcat_offline');
        -- Engagement 2 — different engagement
        INSERT INTO credentials VALUES
            (3, 2, 'other@corp.com', 0, 'hash999', 'MD5', NULL, NULL);
    """)
    con.commit(); con.close()
    return db


@pytest.fixture
def bridge(db_with_hashes: Path) -> HashCredentialBridge:
    return HashCredentialBridge(db_path=db_with_hashes, engagement_id=1)


# ══════════════════════════════════════════════════════════════════════════════
# HashAttackClass taxonomy
# ══════════════════════════════════════════════════════════════════════════════

class TestHashAttackClassEnum:
    def test_all_four_classes_exist(self):
        for name in ("NTLM_RELAY", "PASS_THE_HASH", "KERBEROAST", "HASH_INJECTION"):
            assert hasattr(HashAttackClass, name)

    def test_str_value_matches_name(self):
        assert HashAttackClass.NTLM_RELAY.value == "NTLM_RELAY"
        assert HashAttackClass.PASS_THE_HASH.value == "PASS_THE_HASH"


# ══════════════════════════════════════════════════════════════════════════════
# classify_hash_attack_from_exploit
# ══════════════════════════════════════════════════════════════════════════════

class TestClassifyHashAttack:

    def _exploit(self, title="", description="", type_="remote", platform="windows"):
        con = sqlite3.connect(":memory:")
        con.row_factory = sqlite3.Row
        con.execute("""CREATE TABLE e
            (edb_id INT, title TEXT, type TEXT, platform TEXT,
             path TEXT, cvss_score REAL, description TEXT)""")
        con.execute("INSERT INTO e VALUES (1,?,?,?,?,?,?)",
                    [title, type_, platform, "", 5.0, description])
        return con.execute("SELECT * FROM e").fetchone()

    def test_ntlm_relay_keyword(self):
        e = self._exploit(title="Responder NTLM relay attack Windows SMB")
        assert classify_hash_attack_from_exploit(e) == HashAttackClass.NTLM_RELAY.value

    def test_pth_keyword(self):
        e = self._exploit(title="Impacket psexec pass-the-hash exploit")
        assert classify_hash_attack_from_exploit(e) == HashAttackClass.PASS_THE_HASH.value

    def test_kerberoast_keyword(self):
        e = self._exploit(description="Kerberoast TGS-REP hash offline crack hashcat 13100")
        assert classify_hash_attack_from_exploit(e) == HashAttackClass.KERBEROAST.value

    def test_hash_injection_local_only(self):
        e = self._exploit(title="Token impersonation sekurlsa mimikatz", type_="local")
        assert classify_hash_attack_from_exploit(e) == HashAttackClass.HASH_INJECTION.value

    def test_hash_injection_not_remote(self):
        e = self._exploit(title="token impersonation sekurlsa", type_="remote")
        # HASH_INJECTION requires type='local'
        result = classify_hash_attack_from_exploit(e)
        assert result != HashAttackClass.HASH_INJECTION.value

    def test_ntlm_port_context(self):
        e = self._exploit(title="SMB Windows remote exploit", platform="windows")
        # Port 445 + windows platform → NTLM_RELAY
        assert classify_hash_attack_from_exploit(e, port=445) == HashAttackClass.NTLM_RELAY.value

    def test_non_ntlm_port_no_bonus(self):
        e = self._exploit(title="HTTP exploit", platform="linux", type_="remote")
        # Port 80 not in NTLM_PORTS
        result = classify_hash_attack_from_exploit(e, port=80)
        assert result != HashAttackClass.NTLM_RELAY.value

    def test_none_for_generic_exploit(self):
        e = self._exploit(title="Some web exploit", type_="webapps", platform="linux")
        assert classify_hash_attack_from_exploit(e) is None

    def test_priority_ntlm_relay_over_pth(self):
        e = self._exploit(title="ntlm relay pass-the-hash psexec impacket smb")
        result = classify_hash_attack_from_exploit(e)
        # NTLM_RELAY takes priority over PASS_THE_HASH
        assert result == HashAttackClass.NTLM_RELAY.value


# ══════════════════════════════════════════════════════════════════════════════
# HashCredentialSet
# ══════════════════════════════════════════════════════════════════════════════

class TestHashCredentialSet:

    def _make_cred(self, cid, plaintext=None):
        return HashCredential(
            credential_id=cid, email="u@c.com", hash_type="NTLM",
            password_hash="aabbcc", hash_plaintext=plaintext,
        )

    def test_empty_set_has_no_hash(self):
        s = HashCredentialSet()
        assert not s.has_any_hash

    def test_has_any_hash_when_populated(self):
        s = HashCredentialSet([self._make_cred(1)])
        assert s.has_any_hash

    def test_has_cracked_false_when_none(self):
        s = HashCredentialSet([self._make_cred(1, plaintext=None)])
        assert not s.has_cracked

    def test_has_cracked_true_when_one_cracked(self):
        s = HashCredentialSet([
            self._make_cred(1, plaintext=None),
            self._make_cred(2, plaintext="P@ssw0rd"),
        ])
        assert s.has_cracked

    def test_crack_pending_true_when_uncracked_exists(self):
        s = HashCredentialSet([self._make_cred(1, plaintext=None)])
        assert s.crack_pending

    def test_crack_pending_false_when_all_cracked(self):
        s = HashCredentialSet([self._make_cred(1, plaintext="secret")])
        assert not s.crack_pending

    def test_all_hash_ids(self):
        s = HashCredentialSet([self._make_cred(5), self._make_cred(7)])
        assert set(s.all_hash_ids) == {5, 7}

    def test_cracked_ids_subset(self):
        s = HashCredentialSet([
            self._make_cred(1, plaintext="cracked"),
            self._make_cred(2, plaintext=None),
        ])
        assert s.cracked_ids == [1]

    def test_summary_counts(self):
        s = HashCredentialSet([
            self._make_cred(1, plaintext="p"),
            self._make_cred(2, plaintext=None),
        ])
        summary = s.summary()
        assert summary["total_hashes"] == 2
        assert summary["cracked"] == 1
        assert summary["pending"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# HashCredentialBridge
# ══════════════════════════════════════════════════════════════════════════════

class TestHashCredentialBridge:

    def test_get_hash_credentials_returns_set(self, bridge: HashCredentialBridge):
        s = bridge.get_hash_credentials("10.0.0.1")
        assert isinstance(s, HashCredentialSet)

    def test_only_engagement_1_returned(self, bridge: HashCredentialBridge):
        s = bridge.get_hash_credentials("10.0.0.1")
        assert all(c.credential_id in (1, 2) for c in s.credentials)

    def test_uncracked_credential_present(self, bridge: HashCredentialBridge):
        s = bridge.get_hash_credentials("")
        assert any(c.email == "alice@corp.com" for c in s.credentials)

    def test_plaintext_never_logged(self, bridge: HashCredentialBridge, caplog):
        import logging
        with caplog.at_level(logging.DEBUG):
            bridge.get_hash_credentials("")
        for record in caplog.records:
            assert "P@ssw0rd" not in record.message
            assert "AGE1ENCRYPTED" not in record.message

    def test_get_summary_structure(self, bridge: HashCredentialBridge):
        summary = bridge.get_summary()
        assert "total_hashes" in summary
        assert "cracked" in summary
        assert "pending" in summary
        assert summary["total_hashes"] == 2

    def test_get_pending_for_crack(self, bridge: HashCredentialBridge):
        pending = bridge.get_pending_for_crack()
        assert all(c.hash_plaintext is None for c in pending)
        assert any(c.email == "alice@corp.com" for c in pending)

    def test_missing_hash_columns_returns_empty(self, tmp_path: Path):
        db = tmp_path / "nohash.db"
        con = sqlite3.connect(db)
        con.execute("""CREATE TABLE credentials
            (id INTEGER PRIMARY KEY, engagement_id INTEGER, email TEXT, validated INTEGER)""")
        con.execute("INSERT INTO credentials VALUES (1, 1, 'x@y.com', 1)")
        con.commit(); con.close()
        bridge = HashCredentialBridge(db, engagement_id=1)
        s = bridge.get_hash_credentials("")
        assert not s.has_any_hash
