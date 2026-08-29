import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]


def _read_launcher(name: str) -> str:
    return (REPO_ROOT / name).read_text(encoding="utf-8").lower()


def test_windows_launchers_use_project_virtualenv() -> None:
    launchers = (
        "forge-autopilot.bat",
        "forge-kill-chain.bat",
        "forge-menu.bat",
        "forge-report.bat",
        "forge-status.bat",
        "start_toolkit.bat",
    )
    for launcher in launchers:
        text = _read_launcher(launcher)
        assert ".venv\\scripts\\" in text


def test_report_launcher_uses_windows_native_latest_report_listing() -> None:
    text = _read_launcher("forge-report.bat")
    assert "| head" not in text
    assert ".venv\\scripts\\python.exe -c" in text
    assert "reports[:3]" in text


def test_status_windows_launcher_uses_consolidated_automation_status() -> None:
    text = _read_launcher("forge-status.bat")

    assert ".venv\\scripts\\forge.exe automation status --quick --json" in text
    assert "kb status" not in text
    assert ".forge_data/engagements" not in text


def test_autopilot_launcher_runs_start_resume_monitor_dashboard() -> None:
    text = _read_launcher("forge-autopilot.bat")
    assert "automation feed-build" in text
    assert "--skip-feed-build" in text
    assert "--feed-source" in text
    assert "targets import" in text
    assert "--start-limit" in text
    assert "--min-start-source-count" in text
    assert "targets resume-run" in text
    assert "--max-parallel" in text
    assert "monitoring run-due" in text
    assert "dashboard" in text
    assert "--dry-run" in text
    assert "roe_id_present" in text
    assert "echo   roe_id=%roe_id%" not in text


def test_autopilot_windows_launcher_success_phase_order() -> None:
    text = _read_launcher("forge-autopilot.bat")

    assert text.index("[feed] building target feed") < text.index("[import] importing target feed")
    assert text.index("[import] importing target feed") < text.index("[resume] resuming ready")
    assert text.index("[resume] resuming ready") < text.index("[monitoring] applying due")
    assert text.index("[monitoring] applying due") < text.index("[dashboard] refreshing")


def test_autopilot_windows_launcher_defaults_to_dry_run_and_fails_fast_on_feed_apply() -> None:
    text = _read_launcher("forge-autopilot.bat")

    assert 'set "dry_run=1"' in text
    assert 'if /i "%~1"=="--apply" set "dry_run=0"' in text
    assert "failed in apply mode; stopping before stale feed import/resume/monitoring" in text
    assert "exit /b !exit_code!" in text
    assert 'set "start_limit=2"' in text
    assert 'set "min_start_source_count=1"' in text
    assert 'set "max_runtime_minutes=10"' in text
    assert 'set "resume_limit=10"' in text
    assert 'set "max_parallel=2"' in text
    assert 'set "monitor_limit=10"' in text


def test_autopilot_windows_launcher_can_run_from_packaged_path_runtime() -> None:
    text = _read_launcher("forge-autopilot.bat")

    assert "where python >nul 2>nul" in text
    assert "where forge >nul 2>nul" in text
    assert 'set "python=python"' in text
    assert "use the packaged docker image" in text
    assert re.search(r"(?m)^\s*pause\s*$", text) is None


def test_autopilot_windows_apply_requires_roe_before_python_call(tmp_path: Path) -> None:
    if sys.platform != "win32":
        pytest.skip("cmd launcher behavior is Windows-specific")

    launcher = tmp_path / "forge-autopilot.bat"
    launcher.write_text((REPO_ROOT / "forge-autopilot.bat").read_text(encoding="utf-8"), encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    python_log = tmp_path / "python.log"
    (bin_dir / "python.bat").write_text(
        f"@echo off\r\necho %*>>\"{python_log}\"\r\nexit /b 0\r\n",
        encoding="utf-8",
    )
    (bin_dir / "forge.bat").write_text("@echo off\r\nexit /b 0\r\n", encoding="utf-8")

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
    env.pop("FORGE_ROE_ID", None)
    result = subprocess.run(
        ["cmd", "/c", str(launcher), "--apply", "--skip-dashboard"],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )

    assert result.returncode == 1
    assert "--apply requires --roe-id or FORGE_ROE_ID" in result.stdout
    assert not python_log.exists()


def test_autopilot_windows_apply_stops_after_feed_build_failure(tmp_path: Path) -> None:
    if sys.platform != "win32":
        pytest.skip("cmd launcher behavior is Windows-specific")

    launcher = tmp_path / "forge-autopilot.bat"
    launcher.write_text((REPO_ROOT / "forge-autopilot.bat").read_text(encoding="utf-8"), encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    python_log = tmp_path / "python.log"
    forge_pkg = tmp_path / "forge"
    forge_pkg.mkdir()
    (forge_pkg / "__init__.py").write_text("", encoding="utf-8")
    (forge_pkg / "cli.py").write_text(
        "\n".join(
            [
                "from pathlib import Path",
                "import sys",
                f"Path({str(python_log)!r}).write_text(' '.join(sys.argv[1:]) + '\\n', encoding='utf-8')",
                "if sys.argv[1:3] == ['automation', 'feed-build']:",
                "    raise SystemExit(7)",
                "raise SystemExit(0)",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (bin_dir / "forge.bat").write_text("@echo off\r\nexit /b 0\r\n", encoding="utf-8")

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
    env["PYTHONPATH"] = str(tmp_path)
    env.pop("FORGE_ROE_ID", None)
    result = subprocess.run(
        ["cmd", "/c", str(launcher), "--apply", "--roe-id", "ROE-TEST", "--skip-dashboard"],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )
    calls = python_log.read_text(encoding="utf-8").lower().splitlines()

    assert result.returncode == 7
    assert "failed in apply mode; stopping before stale feed import/resume/monitoring" in result.stdout
    assert len(calls) == 1
    assert "automation feed-build" in calls[0]
    assert "targets import" not in "\n".join(calls)
    assert "targets resume-run" not in "\n".join(calls)
    assert "monitoring run-due" not in "\n".join(calls)


def test_autopilot_windows_dry_run_without_roe_rehearses_order_and_skips_dashboard(
    tmp_path: Path,
) -> None:
    if sys.platform != "win32":
        pytest.skip("cmd launcher behavior is Windows-specific")

    launcher = tmp_path / "forge-autopilot.bat"
    launcher.write_text(
        (REPO_ROOT / "forge-autopilot.bat").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    imports = tmp_path / "imports"
    imports.mkdir()
    (imports / "target-feed.json").write_text(
        json.dumps({"schema_version": "target-feed.v1", "items": []}),
        encoding="utf-8",
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    python_log = tmp_path / "python.log"
    (bin_dir / "python.bat").write_text(
        f"@echo off\r\necho %*>>\"{python_log}\"\r\nexit /b 0\r\n",
        encoding="utf-8",
    )
    (bin_dir / "forge.bat").write_text("@echo off\r\nexit /b 0\r\n", encoding="utf-8")

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
    env.pop("FORGE_ROE_ID", None)
    result = subprocess.run(
        ["cmd", "/c", str(launcher), "--skip-feed-build"],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )

    calls = python_log.read_text(encoding="utf-8").lower().splitlines()
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(calls) == 3
    assert "targets import" in calls[0]
    assert "--start --dry-run" in calls[0]
    assert "--roe-id" not in calls[0]
    assert "targets resume-run" in calls[1]
    assert "--dry-run" in calls[1]
    assert "monitoring run-due" in calls[2]
    assert "--dry-run" in calls[2]
    assert "dashboard" not in "\n".join(calls)
    assert "skipped in dry-run mode" in result.stdout.lower()


def test_powershell_stack_helper_uses_docker_compose_dev_file() -> None:
    text = (REPO_ROOT / "tools" / "forge-stack.ps1").read_text(encoding="utf-8").lower()
    assert "..\\docker\\docker-compose.dev.yml" in text
    assert "..\\docker-compose.dev.yml" not in text


def test_tph_import_task_uses_temp_python_scripts_for_watchdog_helpers() -> None:
    text = (
        REPO_ROOT / "scripts" / "run_tph_target_import_task.ps1"
    ).read_text(encoding="utf-8").lower()
    watchdog_body = text.split("function invoke-watchdogpython", 1)[1].split(
        "function invoke-optionalrecoverystep", 1
    )[0]
    assert "invoke-watchdogpython" in text
    assert "writealltext($tempscript" in text
    assert "$helperargs = @($tempscript) + $scriptarguments" in watchdog_body
    assert "$helperstartinfo.filename = $python" in watchdog_body
    assert "quote-windowsprocessargument" in watchdog_body
    assert "$helperstartinfo.useshellexecute = $false" in text
    assert "$helperstartinfo.createnowindow = $true" in text
    assert "$helperstartinfo.redirectstandardoutput = $true" in text
    assert "$helperstartinfo.redirectstandarderror = $true" in text
    assert "$helperjobhandle = new-killonclosejobobject" in watchdog_body
    assert "add-processtojobobject -jobhandle $helperjobhandle -process $helper" in watchdog_body
    assert "close-jobobject -jobhandle $helperjobhandle" in watchdog_body
    assert "closing helper job root=" in watchdog_body
    assert "& $python -c" not in text
    assert "-c $code" not in text
    assert "<string>" not in text
    assert not re.search(r"(?:\$python|pythonw?(?:\.exe)?)\s+-c(?:\s|$)", text)
    assert 'argumentlist "-c"' not in text
    assert "argumentlist '-c'" not in text
    assert '"-c"' not in watchdog_body
    assert "'-c'" not in watchdog_body
    assert " -c " not in watchdog_body
    assert "-encodedcommand" not in watchdog_body


def test_tph_import_task_has_watchdog_self_test_without_runner_side_effects() -> None:
    text = (
        REPO_ROOT / "scripts" / "run_tph_target_import_task.ps1"
    ).read_text(encoding="utf-8").lower()
    self_test_body = text.split("if ($watchdogselftest)", 1)[1].split(
        "if (-not $nostalecleanup)", 1
    )[0]
    assert "[switch]$watchdogselftest" in text
    assert "function test-watchdogpythonquoting" in text
    assert "scheduled import watchdog self-test; quotes preserved" in text
    assert "argument with spaces and \"quotes\"" in text
    assert "invoke-watchdogpython -python $python" in text
    assert "exit 0" in self_test_body
    assert "stop-stalewatchdoghelperprocesses" not in self_test_body
    assert "mark-stalerunningrunsfailed" not in self_test_body
    assert "starting import" not in self_test_body


def test_tph_import_task_watchdog_self_test_preserves_python_quotes() -> None:
    if sys.platform != "win32":
        pytest.skip("watchdog self-test uses Windows job objects")
    powershell = shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("powershell.exe is required for the scheduled task launcher")

    script = REPO_ROOT / "scripts" / "run_tph_target_import_task.ps1"
    result = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-WatchdogSelfTest",
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    assert "<string>" not in (result.stderr + result.stdout).lower()


def test_tph_import_task_stops_orphaned_import_descendants_after_job_close() -> None:
    text = (
        REPO_ROOT / "scripts" / "run_tph_target_import_task.ps1"
    ).read_text(encoding="utf-8").lower()
    assert "function stop-processids" in text
    assert "$descendantidsbeforejobclose = @(get-childprocessids" in text
    assert "captured import child process ids before watchdog close" in text
    assert "$remainingprocessids = @($descendantidsbeforejobclose) + @(get-childprocessids" in text
    assert "stopping remaining import process ids after watchdog close" in text
    assert "stop-processids -processids $remainingprocessids" in text


def test_tph_import_task_uses_one_wall_clock_budget_for_startup_import_and_cleanup() -> None:
    text = (
        REPO_ROOT / "scripts" / "run_tph_target_import_task.ps1"
    ).read_text(encoding="utf-8").lower()
    assert "$taskdeadline = (get-date).addminutes($taskbudgetminutes)" in text
    assert "function get-remainingtaskbudgetmilliseconds" in text
    assert "function get-remainingtaskbudgetseconds" in text
    assert (
        "$stalecoverytimeoutseconds = get-remainingtaskbudgetseconds"
        not in text
    )
    assert (
        "$stalerecoverytimeoutseconds = get-remainingtaskbudgetseconds "
        "-reserveseconds ([math]::max(30, $stopgraceseconds + 30))"
    ) in text
    assert "[int]$timeoutrecoveryhelperseconds = 10" in text
    assert "$timeoutcleanupreserveseconds = [math]::max(" in text
    assert (
        "[math]::max(1, $stopgraceseconds) + "
        "[math]::max(1, $timeoutrecoveryhelperseconds) + 30"
    ) in text
    assert "$timeout = get-remainingtaskbudgetmilliseconds -reserveseconds $timeoutcleanupreserveseconds" in text
    assert "import skipped: no remaining task budget after startup and cleanup reserve" in text
    assert "task_timeout_minutes=$timeoutminutes import_timeout_seconds=" in text
    assert "$gracemilliseconds = [math]::min" in text
    assert "[math]::max(0, (get-remainingtaskbudgetmilliseconds -reserveseconds 20))" in text
    assert "[math]::max(1, $timeoutrecoveryhelperseconds)" in text
    assert "timed-out run marking skipped: no remaining task budget" in text


def test_tph_import_task_cleans_stale_watchdog_helpers() -> None:
    text = (
        REPO_ROOT / "scripts" / "run_tph_target_import_task.ps1"
    ).read_text(encoding="utf-8").lower()
    assert "[int]$stalehelperfileminutes = 360" in text
    assert "[switch]$stalehelperprocesscleanup" in text
    assert "function test-legacyinlinewatchdoghelpercommandline" in text
    assert '(?:[^"]*[\\\\/])?pythonw?(?:\\.exe)?' in text
    assert "pythonw?(?:\\.exe)?" in text
    assert "\\s-[c]\\s" in text
    assert "scheduled import watchdog timeout" in text
    assert "scheduled import stale-run recovery" in text
    assert "scheduled_import_watchdog" in text
    assert "function stop-stalewatchdoghelperprocesses" in text
    assert "function remove-stalewatchdoghelperfiles" in text
    assert "forge_tph_watchdog_[0-9a-f]+\\.py" in text
    assert "forge_tph_watchdog_*.py" in text
    assert '$kind = "temp-script"' in text
    assert '$kind = "legacy-inline"' in text
    assert "stale $kind watchdog helper process found" in text
    assert "remove-item -literalpath $file.fullname" in text
    assert "stop-processtree -rootprocessid ([int]$proc.processid)" in text
    assert "if ($stalehelperprocesscleanup)" in text
    assert "stop-stalewatchdoghelperprocesses -olderthanminutes $stalehelperfileminutes" in text
    assert (
        "skipping stale watchdog helper process scan; stale temp-file cleanup remains enabled"
        in text
    )
    assert "remove-stalewatchdoghelperfiles -olderthanminutes $stalehelperfileminutes" in text


def test_tph_import_task_launches_import_runner_hidden_and_noninteractive() -> None:
    text = (
        REPO_ROOT / "scripts" / "run_tph_target_import_task.ps1"
    ).read_text(encoding="utf-8").lower()
    assert '"-noprofile"' in text
    assert '"-noninteractive"' in text
    assert '"-windowstyle", "hidden"' in text
    assert '"-executionpolicy", "bypass"' in text
    assert '"-file", (quote-windowsprocessargument $runner)' in text
    assert '"-apiurl", (quote-windowsprocessargument $apiurl)' in text
    assert '"-tphenvpath", (quote-windowsprocessargument $tphenvpath)' in text
    assert "quote-processargument" not in text
    assert '$startinfo.useshellexecute = $false' in text
    assert '$startinfo.createnowindow = $true' in text
    assert '$startinfo.redirectstandardoutput = $true' in text
    assert '$startinfo.redirectstandarderror = $true' in text


def test_tph_import_runner_reports_feed_reachability_diagnostics() -> None:
    text = (
        REPO_ROOT / "scripts" / "import_tph_targets.ps1"
    ).read_text(encoding="utf-8").lower()
    assert "function test-tcpport" in text
    assert "system.net.sockets.tcpclient" in text
    assert "function get-targetfeeddiagnostics" in text
    assert "tcp=$($uri.host):$($uri.port) reachable=$portreachable" in text
    assert "tph_env_exists=$envexists" in text
    assert 'join-path $tphrepopath "docker-compose.yml"' in text
    assert "compose_file=$composepath exists=$(test-path -literalpath $composepath)" in text
    assert "waiting for target feed url=$url timeout_seconds=$timeoutseconds" in text
    assert "target feed reachable attempts=$attempt" in text
    assert "last_error=$lasterror" in text
    assert (
        "wait-targetfeed -url $feedurl -headers $headers -timeoutseconds "
        "$waitseconds -tphenvpath $tphenvpath"
    ) in text
    assert "[int]$maxruntimeminutes = 25" in text
    assert '"--max-runtime-minutes", [string]$maxruntimeminutes' in text


def test_tph_import_task_parallelizes_watchdog_db_scans() -> None:
    text = (
        REPO_ROOT / "scripts" / "run_tph_target_import_task.ps1"
    ).read_text(encoding="utf-8").lower()
    assert text.count("import concurrent.futures") == 3
    assert text.count("def scan_db(db_path):") == 3
    assert text.count("threadpoolexecutor(max_workers=workers)") == 3
    assert text.count("pool.map(scan_db, paths)") == 3
    assert (
        text.count(
            "workers = min(16, max(1, os.cpu_count() or 4), max(1, len(paths)))"
        )
        == 3
    )


def test_tph_task_installer_uses_timeout_as_whole_task_budget() -> None:
    text = (
        REPO_ROOT / "scripts" / "install_tph_target_import_task.ps1"
    ).read_text(encoding="utf-8").lower()
    assert "[int]$everyminutes = 60" in text
    assert "[int]$maxruntimeminutes = 25" in text
    assert "[int]$watchdoghelpertimeoutseconds = 120" in text
    assert "[int]$timeoutrecoveryhelperseconds = 10" in text
    assert "[int]$stalehelperfileminutes = 360" in text
    assert "$childtimeoutgraceseconds = 120" in text
    assert "$effectivestartlimit = if ($start) { [math]::max(1, $startlimit) } else { 0 }" in text
    assert "$budgetedruntimeminutes = [int][math]::floor($runtimeseconds / 60)" in text
    assert "scheduled import budget cannot fit startlimit=$startlimit within timeoutminutes=$timeoutminutes" in text
    assert "-maxruntimeminutes $effectivemaxruntimeminutes" in text
    assert "-watchdoghelpertimeoutseconds $watchdoghelpertimeoutseconds" in text
    assert "-timeoutrecoveryhelperseconds $timeoutrecoveryhelperseconds" in text
    assert "-stalehelperfileminutes $stalehelperfileminutes" in text
    assert "$cleanupminutes" not in text
    assert "$executionlimitminutes = [math]::max($timeoutminutes, 10)" in text
    assert "$interval = [math]::max([math]::max(5, $everyminutes), $executionlimitminutes)" in text
    assert "requested interval $everyminutes minute(s) was raised to $interval minute(s)" in text
    assert "-executiontimelimit (new-timespan -minutes $executionlimitminutes)" in text
    assert "requested max runtime $maxruntimeminutes minute(s) was lowered to $effectivemaxruntimeminutes minute(s)" in text
    assert "max runtime per started target: $effectivemaxruntimeminutes minute(s)" in text
    assert "timeout recovery helper: $timeoutrecoveryhelperseconds second(s)" in text


def test_tph_import_task_runner_fits_child_runtime_to_task_budget() -> None:
    text = (
        REPO_ROOT / "scripts" / "run_tph_target_import_task.ps1"
    ).read_text(encoding="utf-8").lower()
    assert "[int]$maxruntimeminutes = 25" in text
    assert "$childtimeoutgraceseconds = 120" in text
    assert "function get-effectivechildruntimeminutes" in text
    assert "scheduled import budget cannot fit startlimit=$starts within timeoutminutes=$timeoutminutes" in text
    assert '"-maxruntimeminutes", [string]$maxruntimeminutes' in text
    assert "$effectivestartlimit = if ($start) { [math]::max(1, $startlimit) } else { 0 }" in text
    assert "$effectivemaxruntimeminutes = get-effectivechildruntimeminutes `" in text
    assert "$args[$maxruntimeindex + 1] = [string]$effectivemaxruntimeminutes" in text
    assert "requested_max_runtime_minutes=$maxruntimeminutes" in text
    assert "effective_max_runtime_minutes=$effectivemaxruntimeminutes" in text


def test_remediation_ticket_status_import_task_defaults_to_dry_run() -> None:
    text = (
        REPO_ROOT / "scripts" / "run_remediation_ticket_status_import_task.ps1"
    ).read_text(encoding="utf-8").lower()
    assert "[parameter(mandatory = $true)][string]$statusfile" in text
    assert "[switch]$apply" in text
    assert "forge_remediation_ticket_status_import.log" in text
    assert '"remediation"' in text
    assert '"import-ticket-statuses"' in text
    assert '"--data-dir"' in text
    assert '"--file"' in text
    assert '"--close-policy"' in text
    assert "$closepolicy" in text
    assert '"--json"' in text
    assert "if (-not $apply)" in text
    assert '$arguments += "--dry-run"' in text
    assert "-redirectstandardoutput $stdoutpath" in text
    assert "-redirectstandarderror $stderrpath" in text
    assert "exit 124" in text


def test_remediation_ticket_status_import_installer_is_budgeted_and_apply_gated() -> None:
    text = (
        REPO_ROOT / "scripts" / "install_remediation_ticket_status_import_task.ps1"
    ).read_text(encoding="utf-8").lower()
    assert "[string]$taskname = \"forge import remediation ticket statuses\"" in text
    assert "[bool]$apply = $false" in text
    assert '[string]$closepolicy = "trust_external_status"' in text
    assert "[switch]$dryrun" in text
    assert "run_remediation_ticket_status_import_task.ps1" in text
    assert "forge_remediation_ticket_status_import.cmd" in text
    assert '$applyarg = if ($apply -and -not $dryrun) { " -apply" } else { "" }' in text
    assert '-closepolicy `"$closepolicy`"' in text
    assert "$executionlimitminutes = [math]::max($timeoutminutes + 5, 10)" in text
    assert "$interval = [math]::max([math]::max(5, $everyminutes), $executionlimitminutes)" in text
    assert "register-scheduledtask" in text
    assert "-multipleinstances ignorenew" in text
    assert "mode: $(if ($apply -and -not $dryrun) { 'apply' } else { 'dry-run' })" in text
    assert "close policy: $closepolicy" in text


def test_guarded_autostart_task_installer_uses_safe_hidden_apply_runner() -> None:
    installer = (
        REPO_ROOT / "scripts" / "install_guarded_autostart_task.ps1"
    ).read_text(encoding="utf-8").lower()
    runner = (
        REPO_ROOT / "scripts" / "run_guarded_autostart_task.ps1"
    ).read_text(encoding="utf-8").lower()

    assert "register-scheduledtask" in installer
    assert "hkcu:\\software\\microsoft\\windows\\currentversion\\run" in installer
    assert "installed hkcu run startup entry instead" in installer
    assert "$fallbackargument" in installer
    assert "-loop -everyminutes $interval -startupdelayminutes $startupdelayminutes" in installer
    assert "runs a single guarded loop at user logon" in installer
    assert "[int]$timeoutminutes = 150" in installer
    assert "new-scheduledtasktrigger -atlogon" in installer
    assert "repetitioninterval" in installer
    assert "-multipleinstances ignorenew" in installer
    assert "-priority 7" in installer
    assert "new-scheduledtaskprincipal" in installer
    assert "-logontype interactive" in installer
    assert "-runlevel limited" in installer
    assert "run_guarded_autostart_task.ps1" in installer
    assert "windowstyle hidden" in installer
    assert "mode: cycle apply/live" in installer

    assert '"automation"' in runner
    assert '"cycle"' in runner
    assert '"--autostart-config"' in runner
    assert '"--apply"' in runner
    assert '"--live"' in runner
    assert '"--json"' in runner
    assert "function convertto-processargument" in runner
    assert "$argumenttext = join-processarguments $arguments" in runner
    assert "[switch]$loop" in runner
    assert "local\\forge_guarded_autostart_loop" in runner
    assert "loop already running; exiting" in runner
    assert "loop sleeping seconds=$sleepseconds" in runner
    assert "-argumentlist $argumenttext" in runner
    assert "-windowstyle hidden" in runner
    assert "redirectstandardoutput" in runner
    assert "forge_guarded_autostart.stdout.log" in runner
    assert "forge_guarded_autostart.stderr.log" in runner
    assert "function stop-processtree" in runner
    assert "system32\\taskkill.exe" in runner
    assert "/pid $rootprocessid /t /f" in runner
    assert "stop-processtree -rootprocessid $process.id" in runner
    assert "timed out process_tree_root_id=$($process.id)" in runner
    assert "return 124" in runner
    assert "exit (invoke-automationcycle)" in runner
