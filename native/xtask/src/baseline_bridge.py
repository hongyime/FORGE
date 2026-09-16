"""Bounded migration tool bridge. Takes data, never shell command strings."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

# -I avoids ambient Python paths; only our own installed adapter is added.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from baseline_job import Job


def main():
    request = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    root, work = Path(request["root"]).resolve(), Path(request["work"]).resolve()
    files = request["files"]
    if request["action"] not in ("collect", "execute") or not files:
        raise ValueError("invalid_action")
    expected_marker = "" if request["action"] == "collect" else "not network and not slow and not chaos and not cart_readiness and not integration and not e2e"
    if request["marker_expression"] != expected_marker:
        raise ValueError("invalid_marker_expression")
    for name in files:
        path = (root / name).resolve()
        if not path.is_relative_to(root) or path.suffix != ".py" or ":" in name or name.startswith("-"):
            raise ValueError("invalid_file")
    timeout = request["timeout_ms"] / 1000
    if not 0.1 <= timeout <= 120:
        raise ValueError("invalid_timeout")
    # Translate the parent's absolute cutoff once, then retain a monotonic deadline.
    remaining = min(timeout, (request["deadline_epoch_ms"] - time.time_ns() // 1_000_000) / 1000)
    deadline = time.monotonic() + max(0, remaining)
    limit = 8 * 1024 * 1024
    command = [sys.executable, "-B", "-m", "pytest", "-p", "pytest_adapter", "-p", "no:cacheprovider",
               "-o", "addopts=",
               "--rootdir", str(root), "--basetemp", str(work / "tmp"),
               "--import-mode=importlib", "--capture=no", "-m", request["marker_expression"], "-q"]
    if request["action"] == "collect":
        command += ["--collect-only"]
    targets = files
    if request["all_files"] and (root / "tests").is_dir():
        targets = ["tests"] + [name for name in files if not name.startswith("tests/")]
    command += [str(root / name) for name in targets]
    env = {name: os.environ[name] for name in ("PATH", "SystemRoot", "WINDIR", "SYSTEMROOT") if name in os.environ}
    env.update(HOME=str(work), USERPROFILE=str(work), TEMP=str(work), TMP=str(work),
               FORGE_DATA_DIR=str(work / "data"), FORGE_NO_TOR="1", FORGE_OFFLINE_STRICT="1",
               PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=os.pathsep.join((str(Path(__file__).parent), str(root))),
               FORGE_BASELINE_EVENTS=str(work / "events.jsonl"), PYTHONIOENCODING="utf-8",
               PYTHON_DOTENV_DISABLED="1")
    if not (root / "pyproject.toml").exists():
        env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    result = dict(exit_code=None, termination="launch_failed", tree_reaped=False,
                  stdout_bytes=0, stderr_bytes=0, job_processes=0, active_after=None,
                  cleanup_duration_ms=0, child_timeout_ms=None)
    if os.name != "nt":
        result["termination"] = "containment_failed"
        print(json.dumps(result))
        return
    job, child = None, None
    counts = [0, 0]
    threads = []
    try:
        if deadline - time.monotonic() < 0.1:
            result.update(termination="budget_exhausted", tree_reaped=True, active_after=0)
            return
        job = Job()
        remaining_ms = int((deadline - time.monotonic()) * 1000)
        if remaining_ms < 100:
            result["termination"] = "budget_exhausted"
            return
        result["child_timeout_ms"] = remaining_ms
        child = subprocess.Popen(command, cwd=work, env=env, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 creationflags=0x00000004 | 0x08000000)
        job.assign_resume(child)

        def drain(stream, index):
            while data := stream.read(8192):
                counts[index] += len(data)  # Deliberately discard all raw test output.

        for index, stream in enumerate((child.stdout, child.stderr)):
            thread = threading.Thread(target=drain, args=(stream, index), daemon=True)
            thread.start()
            threads.append(thread)
        events = work / "events.jsonl"
        while child.poll() is None:
            if sum(counts) > limit or (events.exists() and events.stat().st_size > limit):
                result["termination"] = "output_limit"
                break
            if time.monotonic() >= deadline:
                result["termination"] = "timeout"
                break
            time.sleep(0.02)
        else:
            result["termination"] = "exited" if child.returncode in range(6) else "crash"
        result["exit_code"] = child.poll()
    except (OSError, ValueError):
        result["termination"] = "containment_failed" if child else "launch_failed"
    finally:
        cleanup_started = time.monotonic()
        if job:
            result["tree_reaped"] = job.terminate()
            result["job_processes"] = job.total_processes
            result["active_after"] = job.active_after
            job.close()
        if child:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            if result["exit_code"] is None:
                result["exit_code"] = child.returncode
        for thread in threads:
            thread.join(timeout=2)
        result["stdout_bytes"], result["stderr_bytes"] = counts
        if sum(counts) > limit:
            result["termination"] = "output_limit"
        result["cleanup_duration_ms"] = int((time.monotonic() - cleanup_started) * 1000)
        print(json.dumps(result))


if __name__ == "__main__":
    main()
