"""Bounded Node/Vitest bridge. Job-contained, secret-minimal, cap-guarded."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baseline_job import Job


def main():
    request = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    root = Path(request["root"]).resolve()
    work = Path(request["work"]).resolve()
    package_dir = Path(request["package_dir"]).resolve()
    node = Path(request["node"]).resolve()
    vitest = Path(request["vitest"]).resolve()
    output_file = Path(request["output_file"]).resolve()
    if not package_dir.is_relative_to(root):
        raise ValueError("invalid_package_dir")
    if not output_file.is_relative_to(work):
        raise ValueError("invalid_output_file")
    for path in (node, vitest):
        if not path.is_file():
            raise ValueError("invalid_tool")
    timeout = request["timeout_ms"] / 1000
    if not 0.1 <= timeout <= 120:
        raise ValueError("invalid_timeout")
    remaining = min(timeout, (request["deadline_epoch_ms"] - time.time_ns() // 1_000_000) / 1000)
    deadline = time.monotonic() + max(0, remaining)
    limit = 8 * 1024 * 1024
    action = request.get("action", "run")
    if action == "collect":
        command = [str(node), str(vitest), "list", "--no-static-parse",
                   f"--json={output_file}"]
        accepted_exits = (0,)
    elif action == "run":
        command = [str(node), str(vitest), "run", "--reporter=json",
                   f"--outputFile={output_file}"]
        accepted_exits = (0, 1)
    else:
        raise ValueError("invalid_action")
    env = {name: os.environ[name] for name in
           ("PATH", "SystemRoot", "WINDIR", "SYSTEMROOT") if name in os.environ}
    env.update(HOME=str(work), USERPROFILE=str(work), TEMP=str(work), TMP=str(work),
               NODE_NO_WARNINGS="1", FORCE_COLOR="0", NO_COLOR="1",
               CI="1", FORGE_NO_TOR="1", FORGE_OFFLINE_STRICT="1")
    result = dict(exit_code=None, termination="launch_failed", tree_reaped=False,
                  stdout_bytes=0, stderr_bytes=0, job_processes=0, active_after=None,
                  cleanup_duration_ms=0, child_timeout_ms=None, report_present=False,
                  report_bytes=0)
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
        child = subprocess.Popen(command, cwd=package_dir, env=env,
                                 stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 creationflags=0x00000004 | 0x08000000)
        job.assign_resume(child)

        def drain(stream, index):
            while data := stream.read(8192):
                counts[index] += len(data)

        for index, stream in enumerate((child.stdout, child.stderr)):
            thread = threading.Thread(target=drain, args=(stream, index), daemon=True)
            thread.start()
            threads.append(thread)
        while child.poll() is None:
            if sum(counts) > limit:
                result["termination"] = "output_limit"
                break
            if output_file.exists() and output_file.stat().st_size > limit:
                result["termination"] = "output_limit"
                break
            if time.monotonic() >= deadline:
                result["termination"] = "timeout"
                break
            time.sleep(0.02)
        else:
            # Runtime accept-set per action: vitest run returns 0/1 (pass/fail);
            # vitest list returns 0 only. Non-accepted exits are crashes.
            result["termination"] = "exited" if child.returncode in accepted_exits else "crash"
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
        if output_file.exists():
            result["report_present"] = True
            try:
                result["report_bytes"] = output_file.stat().st_size
            except OSError:
                result["report_bytes"] = 0
        result["cleanup_duration_ms"] = int((time.monotonic() - cleanup_started) * 1000)
        print(json.dumps(result))


if __name__ == "__main__":
    main()
