from __future__ import annotations

import json
import subprocess
from pathlib import Path

from forge.utils.intel import google_account


def test_lookup_google_account_uses_configured_ghunt_command(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        captured["command"] = command
        json_path = Path(command[command.index("--json") + 1])
        json_path.write_text(
            json.dumps(
                {
                    "PROFILE_CONTAINER": {
                        "profile": {
                            "personId": "1234567890",
                            "names": {"PROFILE": {"fullname": "Alice Example"}},
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setenv(
        "FORGE_GHUNT_COMMAND",
        r"C:\Tools\ghunt-env\Scripts\python.exe -m ghunt",
    )
    monkeypatch.setattr(google_account, "_ghunt_creds_available", lambda: True)
    monkeypatch.setattr(google_account.subprocess, "run", fake_run)

    result = google_account.lookup_google_account(
        "Alice@Example.com",
        engagement_id=1001,
        db_path=tmp_path / "engagement.db",
    )

    assert result["available"] is True
    assert result["found"] is True
    assert result["profile"]["gaia_id"] == "1234567890"
    assert result["profile"]["display_name"] == "Alice Example"
    assert captured["command"][:3] == [
        r"C:\Tools\ghunt-env\Scripts\python.exe",
        "-m",
        "ghunt",
    ]
    assert captured["command"][3] == "email"
    assert captured["command"][4] == "--json"
    assert captured["command"][5].endswith(".json")
    assert captured["command"][6] == "Alice@Example.com"


def test_ghunt_binary_env_override_is_command_prefix(monkeypatch) -> None:
    monkeypatch.delenv("FORGE_GHUNT_COMMAND", raising=False)
    monkeypatch.setenv("FORGE_GHUNT_BINARY", r"C:\Tools\ghunt-env\Scripts\ghunt.exe")

    assert google_account._ghunt_command() == [r"C:\Tools\ghunt-env\Scripts\ghunt.exe"]
