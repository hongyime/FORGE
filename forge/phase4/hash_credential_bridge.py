"""
forge/phase4/hash_credential_bridge.py
Hash-Aware Exploit Correlator — Module 4-C.

Provides:
  HashAttackClass    — enum of four hash-exploitable attack paths
  HashCredential     — frozen dataclass for a single hash-bearing credential
  HashCredentialSet  — aggregated hash context for one host (consumed by 4-B scorer)
  HashCredentialBridge — read-only Phase 2 → Phase 4 interface
  classify_hash_attack_from_exploit() — standalone classifier (used by ExploitCorrelator)

Design constraints:
  - Read-only. Phase 4 NEVER writes to the credentials table.
  - hash_plaintext values are in-memory only; never logged, never written to any
    unencrypted output path.
  - Returns typed dataclasses; callers must not access sqlite3.Row directly.
"""
from __future__ import annotations

import logging
import re
import sqlite3
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

_LOG = logging.getLogger(__name__)


# ── Hash attack class taxonomy ─────────────────────────────────────────────────

class HashAttackClass(str, Enum):
    NTLM_RELAY     = "NTLM_RELAY"
    PASS_THE_HASH  = "PASS_THE_HASH"
    KERBEROAST     = "KERBEROAST"
    HASH_INJECTION = "HASH_INJECTION"


_NTLM_RELAY_KW: frozenset[str] = frozenset({
    "ntlm relay", "ntlmrelayx", "smb relay", "responder",
    "llmnr", "nbt-ns", "mdns poisoning",
})
_PTH_KW: frozenset[str] = frozenset({
    "pass-the-hash", "pass the hash", "pth", "psexec",
    "wmiexec", "smbexec", "atexec", "impacket",
    "overpass-the-hash", "opth",
})
_KERBEROAST_KW: frozenset[str] = frozenset({
    "kerberoast", "kerberos tgs", "spn", "rc4 ticket",
    "hashcat 13100", "tgs-rep", "service ticket",
})
_HASH_INJ_KW: frozenset[str] = frozenset({
    "token impersonation", "hash injection", "lsa secrets",
    "sekurlsa", "mimikatz logonpasswords",
})

# SMB/WMI/RPC ports that elevate NTLM attack likelihood
_NTLM_PORTS: frozenset[int] = frozenset({139, 445, 135, 593})


def classify_hash_attack_from_exploit(
    exploit:  sqlite3.Row,
    port:     Optional[int] = None,
) -> Optional[str]:
    """
    Classify an exploit row as a hash-based attack type, or return None.
    Returns the string value of HashAttackClass (or None) so callers need
    not import the enum directly.

    Priority: NTLM_RELAY > PASS_THE_HASH > KERBEROAST > HASH_INJECTION
    """
    description = exploit["description"] if "description" in exploit.keys() else ""
    title_desc = (
        (exploit["title"] or "") + " " + (description or "")
    ).lower()

    def _matches(kws: frozenset[str]) -> bool:
        return any(kw in title_desc for kw in kws)

    port_is_ntlm = port is not None and port in _NTLM_PORTS
    is_windows   = "windows" in (exploit["platform"] or "").lower()

    if _matches(_NTLM_RELAY_KW) or (port_is_ntlm and is_windows):
        return HashAttackClass.NTLM_RELAY.value
    if _matches(_PTH_KW):
        return HashAttackClass.PASS_THE_HASH.value
    if _matches(_KERBEROAST_KW):
        return HashAttackClass.KERBEROAST.value
    if _matches(_HASH_INJ_KW) and exploit["type"] == "local":
        return HashAttackClass.HASH_INJECTION.value
    return None


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class HashCredential:
    credential_id:     int
    email:             str
    hash_type:         str                    # 'NTLM' | 'MD5' | 'SHA1' | 'KRB5TGS' ...
    password_hash:     str                    # raw hash — in-memory only; never log
    hash_plaintext:    Optional[str] = None   # populated if cracked
    hash_crack_source: Optional[str] = None   # 'hashbuster_online' | 'hashcat_offline'


@dataclass
class HashCredentialSet:
    """
    Aggregated hash credential context for a single host.
    Consumed by ExploitCorrelator._score() as an optional bonus signal.
    """
    credentials: list[HashCredential] = field(default_factory=list)

    @property
    def has_any_hash(self) -> bool:
        return len(self.credentials) > 0

    @property
    def has_cracked(self) -> bool:
        return any(c.hash_plaintext is not None for c in self.credentials)

    @property
    def crack_pending(self) -> bool:
        return any(
            c.hash_plaintext is None for c in self.credentials
        )

    @property
    def all_hash_ids(self) -> list[int]:
        return [c.credential_id for c in self.credentials]

    @property
    def cracked_ids(self) -> list[int]:
        return [c.credential_id for c in self.credentials if c.hash_plaintext is not None]

    @property
    def pending_ids(self) -> list[int]:
        return [c.credential_id for c in self.credentials if c.hash_plaintext is None]

    def summary(self) -> dict:
        return {
            "total_hashes": len(self.credentials),
            "cracked":      len(self.cracked_ids),
            "pending":      len(self.pending_ids),
        }


# ── Bridge ─────────────────────────────────────────────────────────────────────

class HashCredentialBridge:
    """
    Read-only Phase 2 → Phase 4 interface for hash-bearing credentials.

    Queries the engagement credential store. Never modifies any table.
    hash_plaintext values are decrypted in-memory only.
    """

    def __init__(self, db_path: Path, engagement_id: int) -> None:
        self._db_path       = db_path
        self._engagement_id = engagement_id
        self._con           = sqlite3.connect(
            f"file:{db_path}?mode=ro", uri=True
        )
        self._con.row_factory = sqlite3.Row

    # ── Public API ─────────────────────────────────────────────────────────────

    def get_hash_credentials(self, host_ip: str) -> HashCredentialSet:
        """
        Return all hash-bearing credentials associated with host_ip.
        Falls back to engagement-wide hashes if no host-specific match.
        Plaintext decryption attempted via forge.opsec.crypto if available.
        """
        try:
            rows = self._con.execute(
                """
                SELECT c.id, c.email, c.hash_type, c.password_hash,
                       c.hash_plaintext, c.hash_crack_source
                FROM credentials c
                WHERE c.engagement_id = ?
                  AND c.password_hash IS NOT NULL
                """,
                (self._engagement_id,),
            ).fetchall()
        except sqlite3.OperationalError:
            # hash columns may not exist if migration hasn't run
            _LOG.debug("hash columns missing from credentials table; returning empty set")
            return HashCredentialSet()

        creds = []
        for row in rows:
            plaintext = self._safe_decrypt(row["hash_plaintext"])
            creds.append(HashCredential(
                credential_id     = row["id"],
                email             = row["email"] or "",
                hash_type         = row["hash_type"] or "UNKNOWN",
                password_hash     = row["password_hash"],
                hash_plaintext    = plaintext,
                hash_crack_source = row["hash_crack_source"],
            ))

        return HashCredentialSet(credentials=creds)

    def get_summary(self) -> dict:
        """Return aggregate hash stats for the engagement (for CLI display)."""
        try:
            row = self._con.execute(
                """
                SELECT
                    COUNT(*)                                        AS total_hashes,
                    SUM(CASE WHEN hash_plaintext IS NOT NULL THEN 1 ELSE 0 END) AS cracked,
                    SUM(CASE WHEN hash_plaintext IS NULL     THEN 1 ELSE 0 END) AS pending
                FROM credentials
                WHERE engagement_id=? AND password_hash IS NOT NULL
                """,
                (self._engagement_id,),
            ).fetchone()
        except sqlite3.OperationalError:
            return {"total_hashes": 0, "cracked": 0, "pending": 0}
        return {
            "total_hashes": row["total_hashes"] or 0,
            "cracked":      row["cracked"]       or 0,
            "pending":      row["pending"]        or 0,
        }

    def get_pending_for_crack(self) -> list[HashCredential]:
        """Return credentials with hashes that have not yet been cracked."""
        full_set = self.get_hash_credentials("")
        return [c for c in full_set.credentials if c.hash_plaintext is None]

    def close(self) -> None:
        self._con.close()

    # ── Internal ───────────────────────────────────────────────────────────────

    @staticmethod
    def _safe_decrypt(ciphertext: Optional[str]) -> Optional[str]:
        """
        Attempt age-decryption of hash_plaintext. Returns None on failure
        or if ciphertext is None. NEVER logs the plaintext value.
        """
        if not ciphertext:
            return None
        try:
            from forge.opsec.crypto import decrypt_string
            return decrypt_string(ciphertext)
        except Exception:
            return None
