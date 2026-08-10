from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.kill_chain_prereqs import (
    detect_kill_chain_prerequisites,
    handle_kill_chain_prerequisite_flow,
)


def _capture_flow(
    detected: list[dict[str, object]],
    *,
    auto_run_detected: bool = False,
    is_tty: bool = False,
    inputs: list[str] | None = None,
    batch_results: list[int] | None = None,
) -> dict[str, object]:
    messages: list[str] = []
    logs: list[tuple[str, str]] = []
    completed: list[dict[str, object]] = []
    auto_audits: list[str] = []
    prompt_audits: list[str] = []
    run_calls: list[tuple[list[str], str]] = []
    hardened: list[list[str]] = []

    def run_inprocess_batch(items, worker, **kwargs):  # noqa: ANN001
        del kwargs
        return [worker(item) for item in items]

    def run_module_batch(specs, run_module, **kwargs):  # noqa: ANN001
        del specs, run_module, kwargs
        return list(batch_results if batch_results is not None else [0])

    def run_module(argv: list[str], label: str) -> int:
        run_calls.append((argv, label))
        return 0

    input_iter = iter(inputs or [])

    handle_kill_chain_prerequisite_flow(
        detected,
        auto_run_detected=auto_run_detected,
        parallel_workers=2,
        console_print=messages.append,
        log=lambda label, message: logs.append((label, message)),
        complete_run=completed.append,
        audit_auto_run=auto_audits.append,
        audit_prompted=prompt_audits.append,
        run_inprocess_batch=run_inprocess_batch,
        run_module_batch=run_module_batch,
        run_module=run_module,
        make_dispatch_spec=lambda argv, label: {"cmd_argv": argv, "label": label},
        harden_child_argv=lambda argv: (
            hardened.append([str(item) for item in argv]) or [*argv, "--hardened"]
        ),
        progress_callback=None,
        is_tty=is_tty,
        input_func=lambda _prompt: next(input_iter),
    )
    return {
        "messages": messages,
        "logs": logs,
        "completed": completed,
        "auto_audits": auto_audits,
        "prompt_audits": prompt_audits,
        "run_calls": run_calls,
        "hardened": hardened,
    }


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


def test_handle_kill_chain_prerequisite_flow_completion_modes() -> None:
    empty_result = _capture_flow([])
    assert empty_result["completed"] == [
        {
            "prereq_detected_count": 0,
            "prereq_runnable_count": 0,
            "prereq_execution_mode": "none",
            "prereq_auto_run_enabled": False,
        }
    ]

    manual_result = _capture_flow(
        [
            {
                "label": "manual-only",
                "reason": "needs target",
                "argv": None,
                "manual_hint": "forge thing --target-url <url>",
                "runnable": False,
            }
        ]
    )
    assert manual_result["completed"][-1]["prereq_execution_mode"] == "manual_only"

    non_tty_result = _capture_flow(
        [
            {
                "label": "safe runnable",
                "reason": "ready",
                "argv": ["cloud", "aws", "--engagement", "1001"],
                "manual_hint": None,
                "runnable": True,
            }
        ]
    )
    assert non_tty_result["completed"][-1]["prereq_execution_mode"] == "non_tty_skipped"


def test_handle_kill_chain_prerequisite_flow_prompt_mode_runs_selected_entries() -> None:
    result = _capture_flow(
        [
            {
                "label": "safe runnable",
                "reason": "ready",
                "argv": ["cloud", "aws", "--engagement", "1001"],
                "manual_hint": None,
                "runnable": True,
            }
        ],
        is_tty=True,
        inputs=["y"],
    )

    assert result["run_calls"] == [
        (["cloud", "aws", "--engagement", "1001"], "prereq: safe runnable")
    ]
    assert result["prompt_audits"] == ["offered=1 ran=1"]
    assert result["completed"][-1]["prereq_execution_mode"] == "prompted"
    assert result["completed"][-1]["prereq_prompted_ran"] == 1


def test_handle_kill_chain_prerequisite_flow_auto_run_mode_hardens_and_audits() -> None:
    result = _capture_flow(
        [
            {
                "label": "aws",
                "reason": "ready",
                "argv": ["cloud", "aws", "--engagement", "1001"],
                "manual_hint": None,
                "runnable": True,
            },
            {
                "label": "azure",
                "reason": "ready",
                "argv": ["cloud", "azure", "--engagement", "1001"],
                "manual_hint": None,
                "runnable": True,
            },
        ],
        auto_run_detected=True,
        batch_results=[0, 1],
    )

    assert result["hardened"] == [
        ["cloud", "aws", "--engagement", "1001"],
        ["cloud", "azure", "--engagement", "1001"],
    ]
    assert result["auto_audits"] == ["ran=2 failed=1 workers=2"]
    assert result["completed"][-1]["prereq_execution_mode"] == "auto_run"
    assert result["completed"][-1]["prereq_auto_run_count"] == 2
    assert result["completed"][-1]["prereq_auto_run_failures"] == 1
