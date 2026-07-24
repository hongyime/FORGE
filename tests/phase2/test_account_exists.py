from __future__ import annotations

import sqlite3
import subprocess
import threading
import time
from pathlib import Path

import pytest

from forge.utils.intel import account_exists
from forge.utils.intel.account_exists import _holehe_command, _in_scope, run_holehe


@pytest.fixture(autouse=True)
def clean_holehe_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FORGE_HOLEHE_COMMAND", raising=False)
    monkeypatch.delenv("FORGE_HOLEHE_BINARY", raising=False)


def test_holehe_command_env_takes_precedence_over_path(monkeypatch) -> None:
    monkeypatch.setenv(
        "FORGE_HOLEHE_COMMAND",
        r"C:\Tools\holehe\.venv\Scripts\python.exe -m holehe",
    )
    monkeypatch.setenv("FORGE_HOLEHE_BINARY", r"C:\Ignored\holehe.exe")
    monkeypatch.setattr(
        "forge.utils.intel.account_exists._find_tool",
        lambda _: (_ for _ in ()).throw(AssertionError("_find_tool should not be called")),
    )

    assert _holehe_command() == [
        r"C:\Tools\holehe\.venv\Scripts\python.exe",
        "-m",
        "holehe",
    ]


def test_holehe_binary_env_used_when_command_absent(monkeypatch) -> None:
    monkeypatch.delenv("FORGE_HOLEHE_COMMAND", raising=False)
    monkeypatch.setenv("FORGE_HOLEHE_BINARY", r"C:\Tools\holehe\.venv\Scripts\holehe.exe")
    monkeypatch.setattr(
        "forge.utils.intel.account_exists._find_tool",
        lambda _: (_ for _ in ()).throw(AssertionError("_find_tool should not be called")),
    )

    assert _holehe_command() == [r"C:\Tools\holehe\.venv\Scripts\holehe.exe"]


def test_holehe_scope_accepts_exact_email_and_wildcard_subdomain() -> None:
    scope = ["security@acme.example", "*.corp.acme.example"]

    assert _in_scope("security@acme.example", scope)
    assert _in_scope("analyst@ops.corp.acme.example", scope)
    assert not _in_scope("analyst@corp.acme.example", scope)


def _build_db(path: Path) -> Path:
    con = sqlite3.connect(path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY,
                name TEXT,
                scope_json TEXT
            );
            CREATE TABLE emails (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER,
                email TEXT,
                source TEXT,
                first_seen_at TEXT
            );
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER,
                phase TEXT,
                module TEXT,
                action TEXT,
                target TEXT,
                result TEXT,
                operator TEXT,
                logged_at TEXT
            );
            INSERT INTO engagements VALUES (1001, 'Acme', '["acme.example"]');
            INSERT INTO emails VALUES (1, 1001, 'alpha@acme.example', 'seed', '2026-01-01');
            INSERT INTO emails VALUES (2, 1001, 'bravo@acme.example', 'seed', '2026-01-01');
            INSERT INTO emails VALUES (3, 1001, 'charlie@acme.example', 'seed', '2026-01-01');
            """
        )
        con.commit()
    finally:
        con.close()
    return path


def test_run_holehe_parallelizes_subprocess_stage_but_persists_in_email_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = _build_db(tmp_path / "eng.db")
    monkeypatch.setattr("forge.utils.intel.account_exists._find_tool", lambda _: "holehe")

    delays = {
        "alpha@acme.example": 0.05,
        "bravo@acme.example": 0.01,
        "charlie@acme.example": 0.03,
    }
    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_run(cmd, capture_output, text, timeout):  # noqa: ANN001
        del capture_output, text, timeout
        email = str(cmd[-1])
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(delays[email])
            local = email.split("@", 1)[0]
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=f"[+] github-{local}.com\n[x] twitter-{local}.com\n",
                stderr="",
            )
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr("forge.utils.intel.account_exists.subprocess.run", fake_run)

    written = run_holehe(
        db_path=db_path,
        engagement_id=1001,
        emails=list(delays.keys()),
        max_workers=2,
        timeout_per_email=30,
    )

    assert written == 3
    assert peak == 2

    con = sqlite3.connect(db_path)
    try:
        account_rows = con.execute(
            """
            SELECT email, service, exists_flag, rate_limited
            FROM account_existence
            WHERE engagement_id=1001
            ORDER BY email, service
            """
        ).fetchall()
        assert account_rows == [
            ("alpha@acme.example", "github-alpha.com", 1, 0),
            ("alpha@acme.example", "twitter-alpha.com", 0, 1),
            ("bravo@acme.example", "github-bravo.com", 1, 0),
            ("bravo@acme.example", "twitter-bravo.com", 0, 1),
            ("charlie@acme.example", "github-charlie.com", 1, 0),
            ("charlie@acme.example", "twitter-charlie.com", 0, 1),
        ]

        audit_rows = [
            row[0]
            for row in con.execute(
                """
                SELECT result
                FROM audit_log
                WHERE engagement_id=1001 AND action='holehe_query'
                ORDER BY id ASC
                """
            ).fetchall()
        ]
        assert audit_rows == [
            "email=alpha@acme.example found=1 rate_limited=1",
            "email=bravo@acme.example found=1 rate_limited=1",
            "email=charlie@acme.example found=1 rate_limited=1",
        ]
    finally:
        con.close()


def test_run_holehe_uses_configured_command_prefix(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = _build_db(tmp_path / "eng-command.db")
    monkeypatch.setenv("FORGE_HOLEHE_COMMAND", "python -m holehe")
    observed_commands: list[list[str]] = []

    def fake_run(cmd, capture_output, text, timeout):  # noqa: ANN001
        del capture_output, text, timeout
        observed_commands.append(list(cmd))
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout="[+] github.com\n",
            stderr="",
        )

    monkeypatch.setattr("forge.utils.intel.account_exists.subprocess.run", fake_run)

    written = run_holehe(
        db_path=db_path,
        engagement_id=1001,
        emails=["alpha@acme.example"],
        timeout_per_email=30,
    )

    assert written == 1
    assert observed_commands == [
        [
            "python",
            "-m",
            "holehe",
            "--no-color",
            "--no-clear",
            "--only-used",
            "alpha@acme.example",
        ]
    ]


def test_run_holehe_passes_proxy_env_to_configured_command(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = _build_db(tmp_path / "eng-proxy.db")
    monkeypatch.setenv("FORGE_HOLEHE_COMMAND", "python -m holehe")
    observed_commands: list[list[str]] = []
    observed_envs: list[dict[str, str]] = []

    def fake_run(cmd, capture_output, text, timeout, env=None):  # noqa: ANN001
        del capture_output, text, timeout
        observed_commands.append(list(cmd))
        observed_envs.append(dict(env or {}))
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout="[+] github.com\n[x] instagram.com\n",
            stderr="",
        )

    monkeypatch.setattr("forge.utils.intel.account_exists.subprocess.run", fake_run)

    written = run_holehe(
        db_path=db_path,
        engagement_id=1001,
        emails=["alpha@acme.example"],
        timeout_per_email=30,
        proxy="socks5://127.0.0.1:9050",
    )

    assert written == 1
    assert observed_commands == [
        [
            "python",
            "-m",
            "holehe",
            "--no-color",
            "--no-clear",
            "--only-used",
            "alpha@acme.example",
        ]
    ]
    assert observed_envs[0]["HTTP_PROXY"] == "socks5://127.0.0.1:9050"
    assert observed_envs[0]["HTTPS_PROXY"] == "socks5://127.0.0.1:9050"
    assert observed_envs[0]["ALL_PROXY"] == "socks5://127.0.0.1:9050"

    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            """
            SELECT service, exists_flag, rate_limited
            FROM account_existence
            WHERE engagement_id=1001
            ORDER BY service
            """
        ).fetchall()
        assert rows == [
            ("github.com", 1, 0),
            ("instagram.com", 0, 1),
        ]
    finally:
        con.close()


def test_run_holehe_defaults_to_sequential_outer_email_workers(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = _build_db(tmp_path / "eng-default.db")
    monkeypatch.delenv("FORGE_HOLEHE_MAX_WORKERS", raising=False)
    monkeypatch.setattr("forge.utils.intel.account_exists._find_tool", lambda _: "holehe")
    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_run(cmd, capture_output, text, timeout):  # noqa: ANN001
        del capture_output, text, timeout
        email = str(cmd[-1])
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.01)
            local = email.split("@", 1)[0]
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=f"[+] github-{local}.com\n",
                stderr="",
            )
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr("forge.utils.intel.account_exists.subprocess.run", fake_run)

    written = run_holehe(
        db_path=db_path,
        engagement_id=1001,
        emails=[
            "alpha@acme.example",
            "bravo@acme.example",
            "charlie@acme.example",
        ],
        timeout_per_email=30,
    )

    assert written == 3
    assert peak == 1

    con = sqlite3.connect(db_path)
    try:
        audit_rows = [
            row[0]
            for row in con.execute(
                """
                SELECT result
                FROM audit_log
                WHERE engagement_id=1001 AND action='holehe_query'
                ORDER BY id ASC
                """
            ).fetchall()
        ]
    finally:
        con.close()
    assert audit_rows == [
        "email=alpha@acme.example found=1 rate_limited=0",
        "email=bravo@acme.example found=1 rate_limited=0",
        "email=charlie@acme.example found=1 rate_limited=0",
    ]


def test_holehe_default_workers_can_be_raised_by_env(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_HOLEHE_MAX_WORKERS", "4")

    assert account_exists._holehe_max_workers_default() == 4


def test_run_holehe_keeps_timeout_audit_semantics_under_parallel_execution(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = _build_db(tmp_path / "eng-timeout.db")
    monkeypatch.setattr("forge.utils.intel.account_exists._find_tool", lambda _: "holehe")

    def fake_run(cmd, capture_output, text, timeout):  # noqa: ANN001
        del capture_output, text, timeout
        email = str(cmd[-1])
        if email == "bravo@acme.example":
            raise subprocess.TimeoutExpired(cmd, 30)
        local = email.split("@", 1)[0]
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=f"[+] github-{local}.com\n",
            stderr="",
        )

    monkeypatch.setattr("forge.utils.intel.account_exists.subprocess.run", fake_run)

    written = run_holehe(
        db_path=db_path,
        engagement_id=1001,
        emails=[
            "alpha@acme.example",
            "bravo@acme.example",
            "charlie@acme.example",
        ],
        max_workers=2,
        timeout_per_email=30,
    )

    assert written == 2

    con = sqlite3.connect(db_path)
    try:
        timeout_rows = con.execute(
            """
            SELECT action, result
            FROM audit_log
            WHERE engagement_id=1001 AND action='holehe_timeout'
            ORDER BY id ASC
            """
        ).fetchall()
        assert timeout_rows == [
            ("holehe_timeout", "email=bravo@acme.example timeout_s=30"),
        ]
    finally:
        con.close()
