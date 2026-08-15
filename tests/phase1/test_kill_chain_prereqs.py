from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from forge.kill_chain_prereqs import (
    KillChainPrereqAuditCallbacks,
    KillChainPrereqFlowRuntime,
    detect_and_audit_kill_chain_prerequisites,
    detect_kill_chain_prerequisites,
    emit_kill_chain_prereq_detection_audit,
    handle_kill_chain_prerequisite_flow,
    handle_kill_chain_prerequisite_flow_with_runtime,
    kill_chain_prereq_audit_callback,
    kill_chain_prereq_audit_callbacks,
    kill_chain_prereq_child_argv_hardener,
    kill_chain_prereq_detection_audit_result,
    kill_chain_prereq_dispatch_spec_factory,
    kill_chain_prereq_flow_runtime,
    kill_chain_prereq_is_interactive,
    run_kill_chain_prerequisites_with_cli_hooks,
    run_kill_chain_prerequisites_with_runtime,
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


def test_kill_chain_prereq_detection_audit_result_preserves_payload() -> None:
    detected = [
        {"label": "aws", "runnable": True},
        {"label": "manual", "runnable": False},
    ]

    assert kill_chain_prereq_detection_audit_result(
        detected,
        auto_run_detected=True,
        include_offensive_prereqs=False,
    ) == "detected=2 auto_run=True offensive_prereqs=False"


def test_emit_kill_chain_prereq_detection_audit_invokes_cli_audit_shape(
    tmp_path: Path,
) -> None:
    audit_events: list[tuple[tuple[object, ...], dict[str, object]]] = []
    detected = [{"label": "aws", "runnable": True}]

    result = emit_kill_chain_prereq_detection_audit(
        audit_callback=lambda *args, **kwargs: audit_events.append((args, kwargs)),
        db_path=tmp_path / "engagement.db",
        engagement_id=1001,
        target="acme.example",
        detected=detected,
        auto_run_detected=False,
        include_offensive_prereqs=True,
    )

    assert result == "detected=1 auto_run=False offensive_prereqs=True"
    assert audit_events == [
        (
            (
                tmp_path / "engagement.db",
                1001,
                "orchestrator",
                "kill_chain",
                "prereq_detection",
            ),
            {
                "target": "acme.example",
                "result": "detected=1 auto_run=False offensive_prereqs=True",
            },
        )
    ]


def test_detect_and_audit_kill_chain_prerequisites_returns_detected_and_audits(
    tmp_path: Path,
) -> None:
    audit_events: list[tuple[tuple[object, ...], dict[str, object]]] = []

    detected = detect_and_audit_kill_chain_prerequisites(
        audit_callback=lambda *args, **kwargs: audit_events.append((args, kwargs)),
        db_path=tmp_path / "missing.db",
        engagement_id=1001,
        engagement="1001",
        domain="acme.example",
        auto_run_detected=True,
        include_offensive_prereqs=False,
        cwd=tmp_path,
        env={"AWS_PROFILE": "default"},
    )

    assert [item["label"] for item in detected] == ["cloud aws (Module 4)"]
    assert audit_events == [
        (
            (
                tmp_path / "missing.db",
                1001,
                "orchestrator",
                "kill_chain",
                "prereq_detection",
            ),
            {
                "target": "acme.example",
                "result": "detected=1 auto_run=True offensive_prereqs=False",
            },
        )
    ]


def test_kill_chain_prereq_audit_callback_binds_action_and_context(
    tmp_path: Path,
) -> None:
    audit_events: list[tuple[tuple[object, ...], dict[str, object]]] = []
    audit_prompted = kill_chain_prereq_audit_callback(
        audit_callback=lambda *args, **kwargs: audit_events.append((args, kwargs)),
        db_path=tmp_path / "engagement.db",
        engagement_id=1001,
        target="acme.example",
        action="prereq_prompted",
    )

    audit_prompted("offered=2 ran=1")

    assert audit_events == [
        (
            (
                tmp_path / "engagement.db",
                1001,
                "orchestrator",
                "kill_chain",
                "prereq_prompted",
            ),
            {"target": "acme.example", "result": "offered=2 ran=1"},
        )
    ]


def test_kill_chain_prereq_audit_callbacks_bind_auto_run_and_prompted_actions(
    tmp_path: Path,
) -> None:
    audit_events: list[tuple[tuple[object, ...], dict[str, object]]] = []
    callbacks = kill_chain_prereq_audit_callbacks(
        audit_callback=lambda *args, **kwargs: audit_events.append((args, kwargs)),
        db_path=tmp_path / "engagement.db",
        engagement_id=1001,
        target="acme.example",
    )

    callbacks.auto_run("ran=2 failed=0 workers=2")
    callbacks.prompted("offered=1 ran=1")

    assert audit_events == [
        (
            (
                tmp_path / "engagement.db",
                1001,
                "orchestrator",
                "kill_chain",
                "prereq_auto_run",
            ),
            {"target": "acme.example", "result": "ran=2 failed=0 workers=2"},
        ),
        (
            (
                tmp_path / "engagement.db",
                1001,
                "orchestrator",
                "kill_chain",
                "prereq_prompted",
            ),
            {"target": "acme.example", "result": "offered=1 ran=1"},
        ),
    ]


def test_kill_chain_prereq_flow_runtime_preserves_cli_callback_wiring() -> None:
    class _Stream:
        def isatty(self) -> bool:
            return True

    def _console_print(_message: str) -> None:
        return None

    def _log(_label: str, _message: str) -> None:
        return None

    def _complete(_metadata: dict[str, object]) -> None:
        return None

    def _run_inprocess_batch(*_args, **_kwargs):  # noqa: ANN202
        return []

    def _run_module_batch(*_args, **_kwargs):  # noqa: ANN202
        return []

    def _run_module(_argv: list[str], _label: str) -> int:
        return 0

    def _dispatch_spec(**_kwargs):  # noqa: ANN202
        return object()

    def _harden(_argv):  # noqa: ANN001, ANN202
        return []

    def _progress(_label: str, _metrics: dict[str, object]) -> None:
        return None

    def _input(_prompt: str) -> str:
        return "n"

    stdin = _Stream()
    stdout = _Stream()

    runtime = kill_chain_prereq_flow_runtime(
        console_print=_console_print,
        log=_log,
        complete_run=_complete,
        run_inprocess_batch=_run_inprocess_batch,
        run_module_batch=_run_module_batch,
        run_module=_run_module,
        dispatch_spec_type=_dispatch_spec,
        harden_child_argv=_harden,
        progress_callback=_progress,
        stdin=stdin,
        stdout=stdout,
        input_func=_input,
    )

    assert runtime == KillChainPrereqFlowRuntime(
        console_print=_console_print,
        log=_log,
        complete_run=_complete,
        run_inprocess_batch=_run_inprocess_batch,
        run_module_batch=_run_module_batch,
        run_module=_run_module,
        dispatch_spec_type=_dispatch_spec,
        harden_child_argv=_harden,
        progress_callback=_progress,
        stdin=stdin,
        stdout=stdout,
        input_func=_input,
    )


def test_kill_chain_prereq_child_argv_hardener_binds_roe_and_scope() -> None:
    calls: list[tuple[tuple[str, ...], str, str]] = []

    def harden_child_argv(argv, *, roe_id: str, scope_manifest: str):  # noqa: ANN001
        calls.append((tuple(argv), roe_id, scope_manifest))
        return [*argv, "--roe-id", roe_id, "--scope-manifest", scope_manifest]

    harden = kill_chain_prereq_child_argv_hardener(
        harden_child_argv=harden_child_argv,
        roe_id="roe-123",
        scope_manifest="scope.json",
    )

    assert harden(("cloud", "aws")) == [
        "cloud",
        "aws",
        "--roe-id",
        "roe-123",
        "--scope-manifest",
        "scope.json",
    ]
    assert calls == [(("cloud", "aws"), "roe-123", "scope.json")]


def test_kill_chain_prereq_dispatch_spec_factory_preserves_cli_shape() -> None:
    @dataclass(frozen=True)
    class DispatchSpec:
        cmd_argv: list[str]
        label: str

    make_dispatch_spec = kill_chain_prereq_dispatch_spec_factory(DispatchSpec)

    assert make_dispatch_spec(["cloud", "aws"], "prereq: cloud aws") == DispatchSpec(
        cmd_argv=["cloud", "aws"],
        label="prereq: cloud aws",
    )


def test_kill_chain_prereq_is_interactive_requires_stdin_and_stdout_tty() -> None:
    class Stream:
        def __init__(self, value: bool) -> None:
            self.value = value

        def isatty(self) -> bool:
            return self.value

    assert kill_chain_prereq_is_interactive(Stream(True), Stream(True)) is True
    assert kill_chain_prereq_is_interactive(Stream(False), Stream(True)) is False
    assert kill_chain_prereq_is_interactive(Stream(True), Stream(False)) is False
    assert kill_chain_prereq_is_interactive(Stream(False), Stream(False)) is False


def test_handle_kill_chain_prerequisite_flow_with_runtime_wires_cli_adapters() -> None:
    @dataclass(frozen=True)
    class DispatchSpec:
        cmd_argv: list[str]
        label: str

    class Stream:
        def isatty(self) -> bool:
            return True

    messages: list[str] = []
    completed: list[dict[str, object]] = []
    audits: list[str] = []
    specs_seen: list[DispatchSpec] = []
    hardened_calls: list[tuple[tuple[str, ...], str, str]] = []

    def run_inprocess_batch(items, worker, **kwargs):  # noqa: ANN001
        del kwargs
        return [worker(item) for item in items]

    def run_module_batch(specs, run_module, **kwargs):  # noqa: ANN001
        del run_module, kwargs
        specs_seen.extend(specs)
        return [0 for _spec in specs]

    def harden_child_argv(argv, *, roe_id: str, scope_manifest: str):  # noqa: ANN001
        hardened_calls.append((tuple(argv), roe_id, scope_manifest))
        return [*argv, "--roe-id", roe_id, "--scope-manifest", scope_manifest]

    handle_kill_chain_prerequisite_flow_with_runtime(
        [
            {
                "label": "cloud aws",
                "reason": "AWS creds detected",
                "argv": ["cloud", "aws"],
                "manual_hint": None,
                "runnable": True,
            }
        ],
        auto_run_detected=True,
        parallel_workers=2,
        audit_callbacks=KillChainPrereqAuditCallbacks(
            auto_run=audits.append,
            prompted=lambda result: audits.append(f"prompted:{result}"),
        ),
        runtime=KillChainPrereqFlowRuntime(
            console_print=messages.append,
            log=lambda _label, _message: None,
            complete_run=completed.append,
            run_inprocess_batch=run_inprocess_batch,
            run_module_batch=run_module_batch,
            run_module=lambda _argv, _label: 0,
            dispatch_spec_type=DispatchSpec,
            harden_child_argv=harden_child_argv,
            progress_callback=None,
            stdin=Stream(),
            stdout=Stream(),
            input_func=lambda _prompt: "n",
        ),
        roe_id="roe-123",
        scope_manifest="scope.json",
    )

    assert specs_seen == [
        DispatchSpec(
            cmd_argv=["cloud", "aws", "--roe-id", "roe-123", "--scope-manifest", "scope.json"],
            label="prereq: cloud aws",
        )
    ]
    assert hardened_calls == [(("cloud", "aws"), "roe-123", "scope.json")]
    assert audits == ["ran=1 failed=0 workers=1"]
    assert completed[-1]["prereq_execution_mode"] == "auto_run"


def test_run_kill_chain_prerequisites_with_runtime_detects_audits_and_runs(
    tmp_path: Path,
) -> None:
    @dataclass(frozen=True)
    class DispatchSpec:
        cmd_argv: list[str]
        label: str

    class Stream:
        def isatty(self) -> bool:
            return True

    audit_events: list[tuple[tuple[object, ...], dict[str, object]]] = []
    completed: list[dict[str, object]] = []
    specs_seen: list[DispatchSpec] = []

    def run_inprocess_batch(items, worker, **kwargs):  # noqa: ANN001
        del kwargs
        return [worker(item) for item in items]

    def run_module_batch(specs, run_module, **kwargs):  # noqa: ANN001
        del run_module, kwargs
        specs_seen.extend(specs)
        return [0 for _spec in specs]

    detected = run_kill_chain_prerequisites_with_runtime(
        audit_callback=lambda *args, **kwargs: audit_events.append((args, kwargs)),
        db_path=tmp_path / "missing.db",
        engagement_id=1001,
        engagement="1001",
        domain="acme.example",
        auto_run_detected=True,
        include_offensive_prereqs=False,
        parallel_workers=2,
        runtime=KillChainPrereqFlowRuntime(
            console_print=lambda _message: None,
            log=lambda _label, _message: None,
            complete_run=completed.append,
            run_inprocess_batch=run_inprocess_batch,
            run_module_batch=run_module_batch,
            run_module=lambda _argv, _label: 0,
            dispatch_spec_type=DispatchSpec,
            harden_child_argv=lambda argv, **_kwargs: list(argv),
            progress_callback=None,
            stdin=Stream(),
            stdout=Stream(),
            input_func=lambda _prompt: "n",
        ),
        roe_id="",
        scope_manifest="",
        cwd=tmp_path,
        env={"AWS_PROFILE": "default"},
    )

    assert [item["label"] for item in detected] == ["cloud aws (Module 4)"]
    assert specs_seen == [
        DispatchSpec(
            cmd_argv=["cloud", "aws", "--engagement", "1001"],
            label="prereq: cloud aws (Module 4)",
        )
    ]
    assert [event[0][4] for event in audit_events] == [
        "prereq_detection",
        "prereq_auto_run",
    ]
    assert audit_events[0][1]["result"] == "detected=1 auto_run=True offensive_prereqs=False"
    assert audit_events[1][1]["result"] == "ran=1 failed=0 workers=1"
    assert completed[-1]["prereq_execution_mode"] == "auto_run"


def test_run_kill_chain_prerequisites_with_cli_hooks_builds_runtime_and_runs(
    tmp_path: Path,
) -> None:
    @dataclass(frozen=True)
    class DispatchSpec:
        cmd_argv: list[str]
        label: str

    class Stream:
        def isatty(self) -> bool:
            return True

    audit_events: list[tuple[tuple[object, ...], dict[str, object]]] = []
    completed: list[dict[str, object]] = []
    specs_seen: list[DispatchSpec] = []
    hardened: list[list[str]] = []

    def run_inprocess_batch(items, worker, **kwargs):  # noqa: ANN001
        del kwargs
        return [worker(item) for item in items]

    def run_module_batch(specs, run_module, **kwargs):  # noqa: ANN001
        del run_module, kwargs
        specs_seen.extend(specs)
        return [0 for _spec in specs]

    detected = run_kill_chain_prerequisites_with_cli_hooks(
        audit_callback=lambda *args, **kwargs: audit_events.append((args, kwargs)),
        db_path=tmp_path / "missing.db",
        engagement_id=1001,
        engagement="1001",
        domain="acme.example",
        auto_run_detected=True,
        include_offensive_prereqs=False,
        parallel_workers=2,
        console_print=lambda _message: None,
        log=lambda _label, _message: None,
        complete_run=completed.append,
        run_inprocess_batch=run_inprocess_batch,
        run_module_batch=run_module_batch,
        run_module=lambda _argv, _label: 0,
        dispatch_spec_type=DispatchSpec,
        harden_child_argv=lambda argv, **_kwargs: hardened.append(list(argv)) or list(argv),
        progress_callback=None,
        stdin=Stream(),
        stdout=Stream(),
        input_func=lambda _prompt: "n",
        roe_id="",
        scope_manifest="",
        cwd=tmp_path,
        env={"AWS_PROFILE": "default"},
    )

    assert [item["label"] for item in detected] == ["cloud aws (Module 4)"]
    assert specs_seen == [
        DispatchSpec(
            cmd_argv=["cloud", "aws", "--engagement", "1001"],
            label="prereq: cloud aws (Module 4)",
        )
    ]
    assert hardened == [["cloud", "aws", "--engagement", "1001"]]
    assert [event[0][4] for event in audit_events] == [
        "prereq_detection",
        "prereq_auto_run",
    ]
    assert completed[-1]["prereq_execution_mode"] == "auto_run"


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
