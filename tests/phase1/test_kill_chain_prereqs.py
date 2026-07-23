from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.kill_chain_prereqs import detect_kill_chain_prerequisites


def test_detect_kill_chain_prerequisites_collects_safe_runnable_inputs(tmp_path: Path) -> None:
    breach_dir = tmp_path / ".forge_data" / "breach"
    breach_dir.mkdir(parents=True)
    breach_file = breach_dir / "sample.sqlite"
    breach_file.write_text("placeholder", encoding="utf-8")

    artifact_dir = tmp_path / "data" / "artifacts"
    artifact_dir.mkdir(parents=True)
    mobile_bundle = artifact_dir / "client.xapk"
    mobile_bundle.write_text("placeholder", encoding="utf-8")

    detected = detect_kill_chain_prerequisites(
        db_path=tmp_path / "missing.db",
        engagement_id=1001,
        engagement="1001",
        domain="acme.example",
        include_offensive_prereqs=False,
        cwd=tmp_path,
        env={
            "FORGE_DEHASHED_API_KEY": "key",
            "FORGE_DEHASHED_EMAIL": "operator@acme.example",
            "AWS_PROFILE": "default",
            "FORGE_AZURE_SUBSCRIPTION_ID": "sub-123",
        },
    )

    labels = [str(item["label"]) for item in detected]
    assert labels == [
        "osint dehashed (Module 2-C)",
        "osint breach (Module 2-A)",
        "cloud aws (Module 4)",
        "cloud azure (Module 4)",
        "cloud firebase-extract (Module 4-F)",
    ]
    assert all(item["runnable"] is True for item in detected)
    firebase_argv = detected[-1]["argv"]
    assert isinstance(firebase_argv, list)
    assert firebase_argv[-2:] == ["--apk", str(mobile_bundle)]


def test_detect_kill_chain_prerequisites_requires_opt_in_for_offensive_hints(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE hosts (id INTEGER PRIMARY KEY, engagement_id INTEGER);
            CREATE TABLE services (id INTEGER PRIMARY KEY, host_id INTEGER);
            CREATE TABLE credentials (engagement_id INTEGER, validated INTEGER);
            INSERT INTO hosts (id, engagement_id) VALUES (1, 1001);
            INSERT INTO services (id, host_id) VALUES (1, 1);
            INSERT INTO credentials (engagement_id, validated) VALUES (1001, 1);
            """
        )
        con.commit()
    finally:
        con.close()

    default_detected = detect_kill_chain_prerequisites(
        db_path=db_path,
        engagement_id=1001,
        engagement="1001",
        domain="acme.example",
        include_offensive_prereqs=False,
        cwd=tmp_path,
        env={"FORGE_SAFE_MODE": "0"},
    )
    assert default_detected == []

    opt_in_detected = detect_kill_chain_prerequisites(
        db_path=db_path,
        engagement_id=1001,
        engagement="1001",
        domain="acme.example",
        include_offensive_prereqs=True,
        cwd=tmp_path,
        env={"FORGE_SAFE_MODE": "0"},
    )

    labels = [str(item["label"]) for item in opt_in_detected]
    assert labels == [
        "evasion generate (Phase 3)",
        "vuln idor (Module 4-D)",
        "auth brute (Phase 4)",
        "auth bypass (Phase 4)",
        "post {shell,beacon,lateral} (Phase 5)",
    ]
    assert all(item["runnable"] is False for item in opt_in_detected)
    assert all(item["argv"] is None for item in opt_in_detected)
