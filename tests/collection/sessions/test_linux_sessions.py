"""Tests for forge.collection.sessions.linux_sessions."""

from __future__ import annotations

from unittest import mock

from forge.collection.sessions import linux_sessions as ls
from forge.collection.sessions.linux_sessions import (
    Session,
    _collect_linux_sessions_direct as collect_linux_sessions,
    parse_last,
    parse_w,
    parse_who,
)


# --------------------------------------------------------------------------- #
# parse_who                                                                   #
# --------------------------------------------------------------------------- #


class TestParseWho:
    def test_parses_local_and_remote_sessions(self) -> None:
        output = (
            "root     tty1         2026-08-04 09:12\n"
            "alice    pts/0        2026-08-04 09:15 (10.0.0.5)\n"
            "bob      pts/1        2026-08-04 09:20 (:0)\n"
        )
        sessions = parse_who(output)

        assert len(sessions) == 3
        assert sessions[0].user == "root"
        assert sessions[0].terminal == "tty1"
        assert sessions[0].host == ""
        assert sessions[0].session_type == "local"
        assert sessions[0].login_time == "2026-08-04T09:12:00"
        assert sessions[0].source == "who"

        assert sessions[1].user == "alice"
        assert sessions[1].host == "10.0.0.5"
        assert sessions[1].session_type == "ssh"

        assert sessions[2].user == "bob"
        assert sessions[2].host == ":0"
        assert sessions[2].session_type == "local"

    def test_parses_rhel_style_date_format(self) -> None:
        output = "carol    pts/2        Aug  4 09:20 (example.com)\n"
        sessions = parse_who(output)

        assert len(sessions) == 1
        assert sessions[0].host == "example.com"
        assert sessions[0].session_type == "ssh"
        # Date parsed (year defaults to 1900 in strptime for %b %d), so ISO string is present.
        assert sessions[0].login_time is not None
        assert "09:20" in sessions[0].login_time

    def test_falls_back_to_raw_time_when_unparseable(self) -> None:
        output = "alice    pts/0        some-weird-date-format\n"
        sessions = parse_who(output)
        assert len(sessions) == 1
        assert sessions[0].login_time == "some-weird-date-format"

    def test_empty_output_returns_empty_list(self) -> None:
        assert parse_who("") == []
        assert parse_who("   \n\n  ") == []

    def test_malformed_lines_are_skipped(self) -> None:
        output = (
            "alice\n"  # too few tokens
            "\n"
            "bob pts/0\n"  # still too few
            "carol    pts/1        2026-08-04 09:20\n"  # valid
        )
        sessions = parse_who(output)
        assert len(sessions) == 1
        assert sessions[0].user == "carol"

    def test_session_has_all_required_fields(self) -> None:
        output = "alice    pts/0        2026-08-04 09:15 (10.0.0.5)\n"
        session = parse_who(output)[0]
        # Dataclass exposes every required attribute.
        for attr in (
            "user",
            "terminal",
            "login_time",
            "logout_time",
            "host",
            "session_type",
            "source",
        ):
            assert hasattr(session, attr)


# --------------------------------------------------------------------------- #
# parse_w                                                                     #
# --------------------------------------------------------------------------- #


class TestParseW:
    def test_parses_header_and_rows(self) -> None:
        output = (
            " 09:12:34 up  3:15,  2 users,  load average: 0.00, 0.00, 0.00\n"
            "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            "alice    pts/0    10.0.0.5         09:00    2:00   0.10s  0.05s -bash\n"
            "bob      pts/1    -                09:05    12:34  0.20s  0.10s vim file.py\n"
        )
        sessions = parse_w(output)

        assert len(sessions) == 2
        assert sessions[0].user == "alice"
        assert sessions[0].terminal == "pts/0"
        assert sessions[0].host == "10.0.0.5"
        assert sessions[0].session_type == "ssh"
        assert sessions[0].idle == "2:00"
        assert sessions[0].what == "-bash"
        assert sessions[0].source == "w"

        assert sessions[1].host == ""
        assert sessions[1].session_type == "local"
        assert sessions[1].what == "vim file.py"

    def test_parses_no_header_output(self) -> None:
        # `w -h` output skips header
        output = "alice    pts/0    10.0.0.5         09:00    2:00   0.10s  0.05s -bash\n"
        sessions = parse_w(output)
        assert len(sessions) == 1
        assert sessions[0].user == "alice"

    def test_empty_output_returns_empty_list(self) -> None:
        assert parse_w("") == []
        assert parse_w("   ") == []

    def test_malformed_lines_are_skipped(self) -> None:
        output = (
            "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            "alice pts/0\n"  # too few columns
            "\n"
            "bob      pts/1    -                09:05    12:34  0.20s  0.10s bash\n"
        )
        sessions = parse_w(output)
        assert len(sessions) == 1
        assert sessions[0].user == "bob"


# --------------------------------------------------------------------------- #
# parse_last                                                                  #
# --------------------------------------------------------------------------- #


class TestParseLast:
    def test_parses_active_ssh_session(self) -> None:
        output = "alice    pts/0        10.0.0.5         Mon Aug  4 09:15   still logged in\n"
        sessions = parse_last(output)

        assert len(sessions) == 1
        session = sessions[0]
        assert session.user == "alice"
        assert session.terminal == "pts/0"
        assert session.host == "10.0.0.5"
        assert session.session_type == "ssh"
        assert session.logout_time == "still_logged_in"
        assert session.source == "last"

    def test_parses_completed_session(self) -> None:
        output = "alice    pts/0        10.0.0.5         Mon Aug  4 09:15 - 09:45  (00:30)\n"
        sessions = parse_last(output)

        assert len(sessions) == 1
        assert sessions[0].logout_time == "09:45"
        assert sessions[0].session_type == "ssh"

    def test_parses_crash_and_down_markers(self) -> None:
        output = (
            "alice    pts/0        10.0.0.5         Mon Aug  4 09:15 - crash (01:30)\n"
            "bob      pts/1        192.168.1.2      Mon Aug  4 08:00 - down  (02:00)\n"
        )
        sessions = parse_last(output)

        assert len(sessions) == 2
        assert sessions[0].logout_time == "crash"
        assert sessions[1].logout_time == "down"

    def test_parses_reboot_pseudo_user(self) -> None:
        output = (
            "reboot   system boot  5.15.0-83-generic Mon Aug  4 08:00   still running\n"
        )
        sessions = parse_last(output)

        assert len(sessions) == 1
        assert sessions[0].user == "reboot"
        assert sessions[0].session_type == "reboot"
        assert sessions[0].host == ""  # kernel version is not a host
        assert sessions[0].logout_time == "still_logged_in"

    def test_parses_shutdown_pseudo_user(self) -> None:
        output = (
            "shutdown system down  5.15.0-83-generic Mon Aug  4 07:59 - 08:00  (00:01)\n"
        )
        sessions = parse_last(output)

        assert len(sessions) == 1
        assert sessions[0].user == "shutdown"
        assert sessions[0].session_type == "shutdown"

    def test_parses_full_year_date_format(self) -> None:
        # `last -F` includes full year and seconds.
        output = (
            "alice    pts/0        10.0.0.5         Mon Aug  4 09:15:00 2026   still logged in\n"
        )
        sessions = parse_last(output)
        assert len(sessions) == 1
        assert sessions[0].login_time is not None
        assert "2026-08-04" in sessions[0].login_time

    def test_ignores_wtmp_footer(self) -> None:
        output = (
            "alice    pts/0        10.0.0.5         Mon Aug  4 09:15   still logged in\n"
            "\n"
            "wtmp begins Mon Aug  4 07:00:00 2026\n"
        )
        sessions = parse_last(output)
        assert len(sessions) == 1
        assert sessions[0].user == "alice"

    def test_empty_output_returns_empty_list(self) -> None:
        assert parse_last("") == []
        assert parse_last("   \n") == []

    def test_malformed_lines_are_skipped(self) -> None:
        output = (
            "gibberish\n"  # too few
            "alice pts/0 host\n"  # no weekday
            "alice    pts/0        10.0.0.5         Mon Aug  4 09:15   still logged in\n"
        )
        sessions = parse_last(output)
        assert len(sessions) == 1
        assert sessions[0].user == "alice"

    def test_local_login_has_local_session_type(self) -> None:
        # No remote host between terminal and weekday -> local.
        # (Uncommon but valid on some `last` builds when host is empty.)
        output = "alice    tty1                          Mon Aug  4 09:15   still logged in\n"
        sessions = parse_last(output)
        assert len(sessions) == 1
        assert sessions[0].session_type == "local"
        assert sessions[0].host == ""


# --------------------------------------------------------------------------- #
# SSH detection                                                               #
# --------------------------------------------------------------------------- #


class TestSSHDetection:
    def test_ipv4_host_is_ssh(self) -> None:
        session = parse_who("alice pts/0 2026-08-04 09:15 (10.0.0.5)\n")[0]
        assert session.session_type == "ssh"

    def test_hostname_is_ssh(self) -> None:
        session = parse_who("alice pts/0 2026-08-04 09:15 (jumpbox.example.com)\n")[0]
        assert session.session_type == "ssh"

    def test_local_x_display_is_local(self) -> None:
        session = parse_who("alice pts/0 2026-08-04 09:15 (:0)\n")[0]
        assert session.session_type == "local"

    def test_no_host_is_local(self) -> None:
        session = parse_who("alice tty1 2026-08-04 09:15\n")[0]
        assert session.session_type == "local"


# --------------------------------------------------------------------------- #
# collect_linux_sessions orchestrator                                         #
# --------------------------------------------------------------------------- #


class TestCollectLinuxSessions:
    def test_merges_all_three_command_outputs(self) -> None:
        who_out = "alice pts/0 2026-08-04 09:15 (10.0.0.5)\n"
        w_out = (
            "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            "alice    pts/0    10.0.0.5         09:15    2:00   0.10s  0.05s -bash\n"
        )
        last_out = "alice    pts/0        10.0.0.5         Mon Aug  4 09:15   still logged in\n"

        def fake_run(argv: list[str], timeout: float = 5.0) -> str:
            binary = argv[0]
            if binary == "who":
                return who_out
            if binary == "w":
                return w_out
            if binary == "last":
                return last_out
            return ""

        with mock.patch.object(ls, "_run_command", side_effect=fake_run):
            sessions = collect_linux_sessions()

        sources = [s.source for s in sessions]
        assert sources == ["who", "w", "last"]
        assert all(s.user == "alice" for s in sessions)

    def test_missing_binaries_return_empty_list(self) -> None:
        with mock.patch.object(ls, "_run_command", return_value=""):
            sessions = collect_linux_sessions()
        assert sessions == []

    def test_never_raises_on_partial_failure(self) -> None:
        def fake_run(argv: list[str], timeout: float = 5.0) -> str:
            if argv[0] == "w":
                return "totally garbage output\n"
            if argv[0] == "who":
                return "alice pts/0 2026-08-04 09:15\n"
            return ""

        with mock.patch.object(ls, "_run_command", side_effect=fake_run):
            sessions = collect_linux_sessions()

        # `who` row survives; `w` garbage is skipped; `last` empty.
        assert len(sessions) == 1
        assert sessions[0].user == "alice"


# --------------------------------------------------------------------------- #
# _run_command                                                                #
# --------------------------------------------------------------------------- #


class TestRunCommand:
    def test_missing_binary_returns_empty_string(self) -> None:
        with mock.patch.object(ls.shutil, "which", return_value=None):
            assert ls._run_command(["definitely-not-a-real-command"]) == ""

    def test_subprocess_error_returns_empty_string(self) -> None:
        with (
            mock.patch.object(ls.shutil, "which", return_value="/usr/bin/who"),
            mock.patch.object(
                ls.subprocess,
                "run",
                side_effect=OSError("boom"),
            ),
        ):
            assert ls._run_command(["who"]) == ""

    def test_timeout_returns_empty_string(self) -> None:
        with (
            mock.patch.object(ls.shutil, "which", return_value="/usr/bin/who"),
            mock.patch.object(
                ls.subprocess,
                "run",
                side_effect=ls.subprocess.TimeoutExpired(cmd="who", timeout=5),
            ),
        ):
            assert ls._run_command(["who"]) == ""

    def test_success_returns_stdout(self) -> None:
        completed = mock.Mock(returncode=0, stdout="alice pts/0 2026-08-04 09:15\n")
        with (
            mock.patch.object(ls.shutil, "which", return_value="/usr/bin/who"),
            mock.patch.object(ls.subprocess, "run", return_value=completed),
        ):
            assert ls._run_command(["who"]) == "alice pts/0 2026-08-04 09:15\n"
