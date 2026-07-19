from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge.phase4.aws_audit import run_aws_audit
from forge.phase4.azure_audit import run_azure_audit
from forge.phase6.llm_validator import validate_report
from forge.phase6.report_synthesizer import MANDATORY_SECTIONS
from forge.utils.post.session_manager import C2Generator


def _timed(name: str, fn):
    start = time.perf_counter()
    result = fn()
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return name, elapsed_ms, result


def _benchmark_c2() -> dict:
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "bench.db"
        gen = C2Generator(db_path=db_path, engagement_id=1)
        http = gen.generate(
            agent_type="python",
            channel="https",
            c2_urls=["https://cdn.example.com"],
            interval=300,
            jitter_pct=25,
        )
        smb = gen.generate(
            agent_type="python",
            channel="smb",
            c2_urls=["https://cdn.example.com"],
            smb_config={"pipe_name": "atsvc", "target": "127.0.0.1"},
        )
        icmp = gen.generate(
            agent_type="python",
            channel="icmp",
            c2_urls=["https://cdn.example.com"],
            icmp_config={"target_ip": "127.0.0.1", "max_payload_size": 64},
        )
        return {
            "https_len": len(http.source),
            "smb_len": len(smb.source),
            "icmp_len": len(icmp.source),
        }


def _benchmark_cloud() -> dict:
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "bench.db"
        aws = run_aws_audit(db_path=db_path, engagement_id=1, dry_run=True)
        azure = run_azure_audit(db_path=db_path, engagement_id=1, dry_run=True)
        return {"aws_findings": len(aws), "azure_findings": len(azure)}


def _benchmark_validator() -> dict:
    body = " ".join(["validated content"] * 80)
    lines: list[str] = []
    for section in MANDATORY_SECTIONS:
        lines.extend([section, "", body, ""])
    text = "\n".join(lines)
    text = text.replace("## 1. Executive Summary\n", "## 1. Executive Summary\nThe overall risk is HIGH.\n", 1)
    result = validate_report(raw_text=text, overall_risk="HIGH")
    return {"errors": len(result.errors), "warnings": len(result.warnings), "passed": result.passed}


def _benchmark_sqlite_insert() -> dict:
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "bench.db"
        with sqlite3.connect(db_path) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS metrics (id INTEGER PRIMARY KEY, name TEXT, value REAL)")
            for i in range(500):
                conn.execute("INSERT INTO metrics (name, value) VALUES (?, ?)", (f"m{i}", i / 10))
        return {"rows": 500}


_BENCHMARKS = {
    "c2_generation": _benchmark_c2,
    "cloud_dry_run": _benchmark_cloud,
    "validator_pass": _benchmark_validator,
    "sqlite_metrics": _benchmark_sqlite_insert,
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="", help="Optional output path for JSON benchmark report.")
    parser.add_argument(
        "--sections",
        default="all",
        help="Comma-separated benchmark sections to run. Options: all,c2_generation,cloud_dry_run,validator_pass,sqlite_metrics.",
    )
    args = parser.parse_args()

    selected_raw = [item.strip() for item in args.sections.split(",") if item.strip()]
    if not selected_raw or selected_raw == ["all"]:
        selected = list(_BENCHMARKS.keys())
    else:
        invalid = [item for item in selected_raw if item not in _BENCHMARKS]
        if invalid:
            raise SystemExit(f"Unknown benchmark sections: {', '.join(invalid)}")
        selected = selected_raw

    report: dict[str, dict] = {}
    for section in selected:
        name, elapsed_ms, payload = _timed(section, _BENCHMARKS[section])
        report[name] = {"elapsed_ms": round(elapsed_ms, 3), "payload": payload}

    text = json.dumps(report, indent=2)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text, encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    main()
