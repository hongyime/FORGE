import os
from pathlib import Path

from forge.webui.logs import (
    engagement_log_files,
    log_api_href,
    log_payload,
    log_tail_api_href,
    log_tail_payload,
    logs_dir,
    resolve_log_file,
    tail_lines,
)


def _write(path: Path, body: str, *, mtime: int = 1_786_529_400) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    os.utime(path, (mtime, mtime))
    return path


def test_logs_dir_creates_data_log_directory(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"

    assert logs_dir(data_dir) == data_dir / "logs"
    assert (data_dir / "logs").is_dir()


def test_engagement_log_files_filters_and_orders_newest_first(tmp_path: Path) -> None:
    logs_root = logs_dir(tmp_path / ".forge_data")
    older = _write(logs_root / "engagement_1001_kill_chain_100.log", "older", mtime=10)
    newest = _write(logs_root / "engagement_1001_kill_chain_200.log", "newer", mtime=20)
    _write(logs_root / "engagement_10010_kill_chain_300.log", "wrong engagement", mtime=30)
    _write(logs_root / "engagement_1001_other_400.log", "wrong kind", mtime=40)

    assert engagement_log_files(logs_root, 1001) == [newest, older]


def test_log_payload_preserves_live_api_contract(tmp_path: Path) -> None:
    log_path = _write(logs_dir(tmp_path / ".forge_data") / "engagement_1001_kill_chain_1 #.log", "abc")
    seen_dates: list[str] = []

    def format_dt(value: str) -> str:
        seen_dates.append(value)
        return "formatted-date"

    assert log_api_href("engagement 1001/acme", log_path.name) == (
        "/api/engagements/engagement%201001%2Facme"
        "/logs/engagement_1001_kill_chain_1%20%23.log"
    )
    assert log_tail_api_href("engagement 1001/acme", log_path.name) == (
        "/api/engagements/engagement%201001%2Facme"
        "/logs/engagement_1001_kill_chain_1%20%23.log/tail"
    )
    assert log_payload(
        "engagement 1001/acme",
        log_path,
        format_size=lambda size: f"{size} bytes",
        format_dt=format_dt,
    ) == {
        "name": "engagement_1001_kill_chain_1 #.log",
        "href": (
            "/api/engagements/engagement%201001%2Facme"
            "/logs/engagement_1001_kill_chain_1%20%23.log"
        ),
        "tail_api": (
            "/api/engagements/engagement%201001%2Facme"
            "/logs/engagement_1001_kill_chain_1%20%23.log/tail"
        ),
        "size_bytes": 3,
        "size_label": "3 bytes",
        "modified_at": "formatted-date",
    }
    assert seen_dates
    assert "T" in seen_dates[0]


def test_resolve_log_file_preserves_basename_and_engagement_prefix_gate(
    tmp_path: Path,
) -> None:
    logs_root = logs_dir(tmp_path / ".forge_data")
    valid = _write(logs_root / "engagement_1001_kill_chain_1.log", "ok")
    _write(logs_root / "engagement_10010_kill_chain_1.log", "wrong engagement")
    outside = _write(tmp_path / "engagement_1001_kill_chain_1.log", "outside")

    assert resolve_log_file(logs_root, 1001, valid.name) == valid.resolve()
    assert resolve_log_file(logs_root, 1001, f"../{valid.name}") == valid.resolve()
    assert resolve_log_file(logs_root, 1001, "engagement_10010_kill_chain_1.log") is None
    assert resolve_log_file(logs_root, 1001, outside.as_posix()) == valid.resolve()
    assert resolve_log_file(logs_root, 1001, "missing.log") is None


def test_tail_lines_and_payload_clamp_requested_lines(tmp_path: Path) -> None:
    log_path = _write(
        logs_dir(tmp_path / ".forge_data") / "engagement_1001_kill_chain_1.log",
        "\n".join(f"line-{index}" for index in range(1, 6)) + "\n",
    )

    assert tail_lines(log_path, 2) == "line-4\nline-5"
    assert log_tail_payload(log_path, 0) == {
        "name": "engagement_1001_kill_chain_1.log",
        "tail": "line-5",
        "requested_lines": 1,
    }
    assert log_tail_payload(log_path, 2000)["requested_lines"] == 1000
