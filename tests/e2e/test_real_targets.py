"""Real-target E2E test harness for FORGE kill-chain.

Runs each of Bryan's provided seeds as an independent engagement, asserts
minimum row counts per relevant table, and produces a Markdown report card
at reports/real_target_test_YYYYMMDDTHHMMSS.md.

Seeds tested:
  2001  hong-yi.me                      (domain — should get many subs)
  2002  bryanseah234@gmail.com          (email  — HIBP/xposed/holehe hits)
  2003  shotsbyseah234@gmail.com        (email  — same)
  2004  @bryanseah234                   (username — Sherlock hits)
  2005  @shotsbyseah234                 (username — same)
  2006  +6592348112                     (phone   — Singapore/SingTel/mobile)
  2007  testphp.vulnweb.com             (domain — deliberately vulnerable)

Each engagement runs with --max-iter=2 --dry-run-keyscan (== --dry-run in
new scheme) --report-provider template for reliable, fast execution.

The harness itself:
  - creates each engagement DB fresh
  - runs forge kill-chain <seed> --engagement N --max-iter 2 --skip-keyscan --skip-cloud
    for the *domain* seeds; simpler flags for others
  - captures duration + exit code
  - queries the DB for row counts across hosts, emails, audit_log, etc.
  - writes a Markdown table with PASS/FAIL per criterion
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO))
os.chdir(REPO)
FORGE_EXE = REPO / ".venv" / "Scripts" / "forge.exe"

TEST_MATRIX: list[dict[str, Any]] = [
    {
        "id": 2001,
        "seed": "hong-yi.me",
        "type": "domain",
        "flags": ["--max-iter", "1", "--skip-keyscan"],
        "success": {"hosts": 5, "audit_log": 10},
        "note": "domain — many Vercel-hosted subdomains",
    },
    {
        "id": 2002,
        "seed": "bryanseah234@gmail.com",
        "type": "email",
        "flags": ["--max-iter", "1", "--skip-keyscan", "--skip-cloud"],
        "success": {"emails": 1, "audit_log": 5},
        "note": "email — should get xposed/holehe/social/sherlock",
    },
    {
        "id": 2003,
        "seed": "shotsbyseah234@gmail.com",
        "type": "email",
        "flags": ["--max-iter", "1", "--skip-keyscan", "--skip-cloud"],
        "success": {"emails": 1, "audit_log": 5},
        "note": "second email — comparison",
    },
    {
        "id": 2004,
        "seed": "@bryanseah234",
        "type": "username",
        "flags": ["--max-iter", "1", "--skip-keyscan", "--skip-cloud"],
        "success": {"audit_log": 5},
        "note": "username — Sherlock should hit",
    },
    {
        "id": 2005,
        "seed": "@shotsbyseah234",
        "type": "username",
        "flags": ["--max-iter", "1", "--skip-keyscan", "--skip-cloud"],
        "success": {"audit_log": 5},
        "note": "second username — comparison",
    },
    {
        "id": 2006,
        "seed": "+6592348112",
        "type": "phone",
        "flags": ["--max-iter", "1", "--skip-keyscan", "--skip-cloud"],
        "success": {"audit_log": 5},
        "note": "phone — offline parse via phonenumbers",
    },
    {
        "id": 2007,
        "seed": "testphp.vulnweb.com",
        "type": "domain",
        "flags": ["--max-iter", "1", "--skip-keyscan"],
        "success": {"hosts": 3, "audit_log": 10},
        "note": "deliberately vulnerable — should surface findings",
    },
]


def prep_engagement(eng_id: int, seed: str) -> None:
    """Reset and create a fresh engagement DB."""
    db_path = REPO / ".forge_data" / "engagements" / f"{eng_id}.db"
    if db_path.exists():
        db_path.unlink()
    # Import via subprocess to avoid path issues
    from forge.db.schema import apply_schema
    con = sqlite3.connect(str(db_path))
    apply_schema(con)
    try:
        from forge.db.migrations import run_migrations
        run_migrations(con)
    except Exception:
        pass
    con.execute(
        "INSERT INTO engagements (id,name,scope_json,status,operator) "
        "VALUES (?,?,?,?,?)",
        (eng_id, f"real_target_{eng_id}", json.dumps([seed]), "ACTIVE", "prawn"),
    )
    con.commit()
    con.close()


def run_killchain(eng_id: int, seed: str, flags: list[str],
                  timeout: float = 300.0) -> tuple[int, float, str]:
    """Fire kill-chain and return (exit_code, duration, stderr_tail)."""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["TERM"] = "dumb"
    env["NO_COLOR"] = "1"
    argv = [
        str(FORGE_EXE), "--no-tor", "kill-chain", seed,
        "--engagement", str(eng_id),
        *flags,
    ]
    t0 = time.time()
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True,
            timeout=timeout, env=env,
            encoding="utf-8", errors="replace",
        )
        duration = time.time() - t0
        stderr_tail = (proc.stderr or "")[-300:]
        return proc.returncode, duration, stderr_tail
    except subprocess.TimeoutExpired:
        return 999, time.time() - t0, "TIMEOUT"


def count_rows(eng_id: int) -> dict[str, int]:
    """Read-only row counts for the engagement DB."""
    db_path = REPO / ".forge_data" / "engagements" / f"{eng_id}.db"
    if not db_path.exists():
        return {}
    con = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    counts: dict[str, int] = {}
    for table in ("hosts", "emails", "subdomains", "services",
                  "audit_log", "key_scanner_findings", "crawl_results",
                  "social_profiles"):
        try:
            n = con.execute(
                f"SELECT COUNT(*) FROM {table} WHERE engagement_id=?",
                (eng_id,),
            ).fetchone()[0]
            counts[table] = n
        except sqlite3.OperationalError:
            counts[table] = 0
    con.close()
    return counts


def evaluate(entry: dict[str, Any], counts: dict[str, int]) -> tuple[bool, list[str]]:
    """Check success criteria; return (pass, list_of_details)."""
    details = []
    passed = True
    for table, min_val in entry["success"].items():
        actual = counts.get(table, 0)
        ok = actual >= min_val
        details.append(f"{table}>={min_val}: got {actual} {'PASS' if ok else 'FAIL'}")
        if not ok:
            passed = False
    return passed, details


def main() -> int:
    now = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%S")
    report_path = REPO / "reports" / f"real_target_test_{now}.md"
    report_path.parent.mkdir(exist_ok=True)

    # Support --report-only: score existing engagements without re-running.
    report_only = "--report-only" in sys.argv

    results = []
    for entry in TEST_MATRIX:
        print(f"\n=== [{entry['id']}] {entry['seed']} ({entry['type']}) ===")
        if report_only:
            counts = count_rows(entry["id"])
            passed, details = evaluate(entry, counts)
            summary_ok = "PASS" if passed else "FAIL"
            print(f"  (--report-only)  verdict={summary_ok}")
            for d in details:
                print(f"    {d}")
            results.append({
                "id": entry["id"],
                "seed": entry["seed"],
                "type": entry["type"],
                "note": entry["note"],
                "exit_code": "N/A",
                "duration_s": 0.0,
                "counts": counts,
                "criteria": entry["success"],
                "details": details,
                "verdict": summary_ok,
                "stderr_tail": "",
            })
            continue
        prep_engagement(entry["id"], entry["seed"])
        rc, dur, err = run_killchain(entry["id"], entry["seed"], entry["flags"])
        counts = count_rows(entry["id"])
        passed, details = evaluate(entry, counts)
        # Verdict: PASS if criteria met (data was collected). Exit code
        # tracked separately since kill-chain intermittently exits non-zero
        # due to individual OSINT tools failing (Sherlock rate limit,
        # cloud discovery timeout, etc.) even when data was captured.
        summary_ok = "PASS" if passed else "FAIL"
        print(f"  exit={rc}  duration={dur:.1f}s  verdict={summary_ok}")
        for d in details:
            print(f"    {d}")
        if err and rc != 0:
            print(f"    stderr: {err}")

        results.append({
            "id": entry["id"],
            "seed": entry["seed"],
            "type": entry["type"],
            "note": entry["note"],
            "exit_code": rc,
            "duration_s": round(dur, 1),
            "counts": counts,
            "criteria": entry["success"],
            "details": details,
            "verdict": summary_ok,
            "stderr_tail": err,
        })

    # Write Markdown report
    lines = [
        f"# FORGE real-target test — {now}",
        "",
        f"Ran {len(results)} engagement(s) against real seeds provided by operator.",
        "",
        "## Summary",
        "",
        "| ID | Seed | Type | Duration | Exit | Hosts | Emails | Audit | Verdict |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        c = r["counts"]
        lines.append(
            f"| {r['id']} | `{r['seed']}` | {r['type']} | "
            f"{r['duration_s']}s | {r['exit_code']} | "
            f"{c.get('hosts', 0)} | {c.get('emails', 0)} | "
            f"{c.get('audit_log', 0)} | **{r['verdict']}** |"
        )
    lines.append("")

    passed_ct = sum(1 for r in results if r["verdict"] == "PASS")
    failed_ct = len(results) - passed_ct
    lines.append(f"## Overall: {passed_ct} PASS, {failed_ct} FAIL")
    lines.append("")

    lines.append("## Per-target detail")
    for r in results:
        lines.append(f"### [{r['id']}] `{r['seed']}` — {r['type']}")
        lines.append(f"- **Note:** {r['note']}")
        lines.append(f"- **Duration:** {r['duration_s']}s")
        lines.append(f"- **Exit code:** {r['exit_code']}")
        lines.append(f"- **Verdict:** **{r['verdict']}**")
        lines.append(f"- **Criteria:**")
        for d in r["details"]:
            lines.append(f"  - {d}")
        lines.append(f"- **All row counts:**")
        for table, n in r["counts"].items():
            lines.append(f"  - {table}: {n}")
        if r["stderr_tail"]:
            lines.append(f"- **stderr tail:** `{r['stderr_tail'][:200]}`")
        lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n=== Report: {report_path} ===")
    return 0 if failed_ct == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
