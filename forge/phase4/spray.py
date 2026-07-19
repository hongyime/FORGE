from __future__ import annotations

from pathlib import Path


def run_spray(credential_id: int, wordlist_path: str, usernames_path: str, db_path: Path) -> dict:
    raise NotImplementedError(
        "spray.run_spray is not implemented. "
        "Implement via forge.utils.intel.auth_adapters (SSH/SMB/HTTP adapters) before use."
    )
