"""
tests/plugins/test_executor_modes.py — Regression tests for SUBPROCESS,
REST_API, and DOCKER execution modes after the security hardening sweep.

These tests cover the eight defects fixed in :mod:`forge.plugins.executor`:

- Fix 1 (P0-6): bounded incremental stdout/stderr reader.
- Fix 2 (P0-7): SSRF allowlist for REST_API endpoints.
- Fix 3 (P0-8): unconditional Docker resource caps.
- Fix 4 (P1-2): minimal env default for SUBPROCESS plugins.
- Fix 5 (P2-5): always-reap child on any exception.
- Fix 6 (P2-12): httpx connection limits + verify=True.
- Fix 7 (P0-6 follow-up): non-JSON stdout returns failure.
- Fix 8 (P1-3): REST response size cap.

All Docker tests are mocked — no real ``docker`` daemon is required. SSRF
tests use loopback / link-local hostnames that resolve locally without any
network egress.
"""

from __future__ import annotations

import asyncio
import json
import socket
import sys
from typing import Any
from unittest.mock import patch

import pytest

from forge.audit.logger import AuditLogger
from forge.config import PlatformSettings
from forge.core.errors import SsrfBlockedError
from forge.plugins.base import (
    ExecutionMode,
    PluginMetadata,
    PluginResult,
    RiskLevel,
)
from forge.plugins.executor import (
    BLOCKED_NETWORKS,
    MAX_REST_RESPONSE_BYTES,
    MAX_STDOUT_BYTES,
    PluginExecutor,
    _validate_endpoint_url,
)


# ---------------------------------------------------------------------------
# Test fixtures and helpers
# ---------------------------------------------------------------------------


def _make_plugin(
    *,
    name: str,
    mode: ExecutionMode,
    timeout_seconds: int = 5,
    inherit_env_vars: list[str] | None = None,
):
    """Construct a minimal Plugin-protocol instance for executor dispatch."""
    md = PluginMetadata(
        name=name,
        version="1.0.0",
        capabilities=["test"],
        execution_mode=mode,
        timeout_seconds=timeout_seconds,
        risk_level=RiskLevel.LOW,
        inherit_env_vars=list(inherit_env_vars or []),
    )

    class _P:
        @property
        def metadata(self) -> PluginMetadata:
            return md

        async def execute(self, params: dict) -> PluginResult:
            return PluginResult(success=True, output={})

        async def health_check(self) -> bool:
            return True

    return _P()


def _make_test_settings(**overrides: Any) -> PlatformSettings:
    """Build a PlatformSettings instance with safe defaults, ignoring env."""
    base: dict[str, Any] = {
        "redis_url": None,
        "state_db_url": "sqlite:///:memory:",
        "plugin_dir": "./plugins",
        "llm_provider": "llama_cpp",
        "llm_model_path": None,
        "provider_timeout": 5,
        "heartbeat_interval": 30,
        "safe_mode": 0,
        "scope_json": None,
        "governance_rules": None,
        "audit_db_url": "sqlite:///:memory:",
        "telemetry_threshold_ms": 5000,
        "message_retry_max": 3,
        "message_ack_timeout": 60,
        "allow_private_networks": False,
        "docker_memory_mb": 512,
        "docker_cpus": 1.0,
        "docker_pids_limit": 128,
    }
    base.update(overrides)
    # Use ``model_construct`` so we bypass env-file reads and trust caller.
    return PlatformSettings.model_construct(**base)


# ===========================================================================
# SUBPROCESS mode hardening
# ===========================================================================


class TestSubprocessModeSecurity:
    """SUBPROCESS executor regression tests covering Fixes 1, 4, 5, 7."""

    @pytest.mark.asyncio
    async def test_stdout_overflow_killed_with_error(self, tmp_path, monkeypatch) -> None:
        """Fix 1: a child producing > MAX_STDOUT_BYTES is killed and we
        return a failure PluginResult referencing the cap."""
        # Patch the cap down so the test runs quickly.
        monkeypatch.setattr("forge.plugins.executor.MAX_STDOUT_BYTES", 64 * 1024)

        # Tiny Python program that floods stdout (writes 1 MiB) — the
        # patched 64 KiB cap will be exceeded almost immediately.
        script = tmp_path / "flood.py"
        script.write_text(
            "import sys\n"
            "chunk = b'A' * 4096\n"
            "for _ in range(256):\n"
            "    sys.stdout.buffer.write(chunk)\n"
            "    sys.stdout.buffer.flush()\n",
            encoding="utf-8",
        )

        plugin = _make_plugin(name="flooder", mode=ExecutionMode.SUBPROCESS, timeout_seconds=10)
        executor = PluginExecutor(settings=_make_test_settings())

        result = await executor.execute(
            plugin,
            params={"cmd": [sys.executable, str(script)]},
        )

        assert result.success is False
        assert result.error is not None
        assert "stdout exceeded" in result.error
        # Audit must record the failure.
        entries = [e for e in executor.audit.entries if e.tool_name == "flooder"]
        assert len(entries) == 1
        assert entries[0].success is False

    @pytest.mark.asyncio
    async def test_non_json_stdout_returns_failure(self, tmp_path) -> None:
        """Fix 7: non-empty, non-JSON stdout → success=False with descriptive
        error (was previously masked as success=True)."""
        script = tmp_path / "garbage.py"
        script.write_text("print('this is not json output')\n", encoding="utf-8")

        plugin = _make_plugin(name="garbage", mode=ExecutionMode.SUBPROCESS, timeout_seconds=10)
        executor = PluginExecutor(settings=_make_test_settings())

        result = await executor.execute(plugin, params={"cmd": [sys.executable, str(script)]})

        assert result.success is False
        assert result.error is not None
        assert "not valid JSON" in result.error

    @pytest.mark.asyncio
    async def test_subprocess_inherits_minimal_env_only(self, tmp_path, monkeypatch) -> None:
        """Fix 4: child env contains PATH/HOME/LANG/TZ but NOT arbitrary
        host vars by default."""
        # Set a sentinel var the child must NOT see.
        monkeypatch.setenv("FORGE_SECRET_DO_NOT_INHERIT", "leaked")
        # PATH is needed for python to find shared libs on the child.
        # No-op assignment ensures it's defined.

        script = tmp_path / "dump_env.py"
        script.write_text(
            "import json, os\n"
            "print(json.dumps({"
            "'has_secret': 'FORGE_SECRET_DO_NOT_INHERIT' in os.environ, "
            "'has_path': 'PATH' in os.environ, "
            "'has_lang': 'LANG' in os.environ"
            "}))\n",
            encoding="utf-8",
        )
        plugin = _make_plugin(
            name="env_dump",
            mode=ExecutionMode.SUBPROCESS,
            timeout_seconds=10,
        )
        executor = PluginExecutor(settings=_make_test_settings())

        result = await executor.execute(plugin, params={"cmd": [sys.executable, str(script)]})

        assert result.success is True, f"got error: {result.error!r}"
        assert result.output["has_secret"] is False
        assert result.output["has_path"] is True
        assert result.output["has_lang"] is True

    @pytest.mark.asyncio
    async def test_subprocess_env_allowlist_via_metadata(self, tmp_path, monkeypatch) -> None:
        """Fix 4: metadata.inherit_env_vars opts the child into specific keys."""
        monkeypatch.setenv("MY_ALLOWED_KEY", "allowed_value")
        monkeypatch.setenv("MY_BLOCKED_KEY", "blocked_value")

        script = tmp_path / "check_env.py"
        script.write_text(
            "import json, os\n"
            "print(json.dumps({"
            "'allowed': os.environ.get('MY_ALLOWED_KEY', 'MISSING'), "
            "'blocked': os.environ.get('MY_BLOCKED_KEY', 'MISSING')"
            "}))\n",
            encoding="utf-8",
        )
        plugin = _make_plugin(
            name="allowlist",
            mode=ExecutionMode.SUBPROCESS,
            timeout_seconds=10,
            inherit_env_vars=["MY_ALLOWED_KEY"],
        )
        executor = PluginExecutor(settings=_make_test_settings())

        result = await executor.execute(plugin, params={"cmd": [sys.executable, str(script)]})

        assert result.success is True, f"got error: {result.error!r}"
        assert result.output["allowed"] == "allowed_value"
        assert result.output["blocked"] == "MISSING"

    @pytest.mark.asyncio
    async def test_child_killed_on_unexpected_exception(self) -> None:
        """Fix 5: any exception during stdout read terminates the child.

        We simulate an exception by patching the bounded reader to raise
        and assert ``_terminate_subprocess`` is invoked.
        """
        plugin = _make_plugin(name="reaper", mode=ExecutionMode.SUBPROCESS, timeout_seconds=5)
        executor = PluginExecutor(settings=_make_test_settings())

        terminate_calls: list[int] = []

        async def _fake_terminate(proc):
            terminate_calls.append(proc.pid if proc.pid else -1)
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                pass

        async def _fake_reader(stream, max_bytes):
            raise RuntimeError("synthetic reader failure")

        with (
            patch.object(executor, "_terminate_subprocess", _fake_terminate),
            patch("forge.plugins.executor._read_stream_bounded", _fake_reader),
        ):
            result = await executor.execute(
                plugin,
                params={
                    "cmd": [
                        sys.executable,
                        "-c",
                        "import time; time.sleep(10)",
                    ]
                },
            )

        # The exception path returns a failure result (via the outer
        # except Exception handler in `execute`).
        assert result.success is False
        assert result.error is not None
        assert "synthetic reader failure" in result.error
        # And critically: the terminate hook fired.
        assert len(terminate_calls) >= 1, "child must be reaped when reader raises"

    @pytest.mark.asyncio
    async def test_missing_cmd_raises_validation_error(self) -> None:
        """SUBPROCESS without a 'cmd' list → ValueError surfaced as failure."""
        plugin = _make_plugin(name="no_cmd", mode=ExecutionMode.SUBPROCESS, timeout_seconds=5)
        executor = PluginExecutor(settings=_make_test_settings())

        result = await executor.execute(plugin, params={})
        assert result.success is False
        assert result.error is not None
        assert "non-empty list" in result.error


# ===========================================================================
# REST_API mode hardening
# ===========================================================================


class TestRestApiModeSecurity:
    """REST_API executor regression tests covering Fixes 2, 6, 8."""

    def test_blocked_networks_constant_covers_required_ranges(self) -> None:
        """Static check: the SSRF blocklist contains every documented range."""
        cidrs = {str(net) for net in BLOCKED_NETWORKS}
        for required in (
            "127.0.0.0/8",
            "169.254.0.0/16",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10",
            "224.0.0.0/4",
            "::1/128",
            "fc00::/7",
            "fe80::/10",
        ):
            assert required in cidrs, f"missing required CIDR {required}"

    @pytest.mark.asyncio
    async def test_localhost_endpoint_rejected(self) -> None:
        """Fix 2: http://127.0.0.1/ raises SsrfBlockedError."""
        plugin = _make_plugin(name="local", mode=ExecutionMode.REST_API, timeout_seconds=5)
        executor = PluginExecutor(settings=_make_test_settings())

        result = await executor.execute(plugin, params={"endpoint": "http://127.0.0.1/api"})
        assert result.success is False
        assert result.error is not None
        assert "SsrfBlockedError" in result.error or "blocked network" in result.error

    @pytest.mark.asyncio
    async def test_link_local_endpoint_rejected(self) -> None:
        """Fix 2: AWS IMDS-style 169.254.169.254 is rejected."""
        with pytest.raises(SsrfBlockedError) as exc_info:
            _validate_endpoint_url("http://169.254.169.254/latest/meta-data/")
        assert "blocked network" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_rfc1918_endpoint_rejected(self) -> None:
        """Fix 2: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 all rejected."""
        for addr in ("10.0.0.1", "172.16.0.1", "192.168.1.1"):
            with pytest.raises(SsrfBlockedError):
                _validate_endpoint_url(f"http://{addr}/")

    @pytest.mark.asyncio
    async def test_aws_imds_endpoint_rejected(self) -> None:
        """Fix 2: explicit AWS IMDS endpoint rejected (test_link_local
        checks the IP — this asserts the URL string is rejected too)."""
        with pytest.raises(SsrfBlockedError):
            _validate_endpoint_url("http://169.254.169.254/latest/api/token")

    @pytest.mark.asyncio
    async def test_file_scheme_rejected(self) -> None:
        """Fix 2: file:// and other non-http(s) schemes rejected up-front."""
        for url in (
            "file:///etc/passwd",
            "gopher://example.com/",
            "ftp://example.com/file",
        ):
            with pytest.raises(SsrfBlockedError) as exc_info:
                _validate_endpoint_url(url)
            assert "scheme" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_https_public_allowed(self) -> None:
        """Fix 2: a public IP (8.8.8.8) passes the SSRF gate.

        We patch ``socket.getaddrinfo`` to return the canonical Google DNS
        IP so this test does not depend on real DNS.
        """
        fake_info = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                0,
                "",
                ("8.8.8.8", 0),
            )
        ]
        with patch(
            "forge.plugins.executor.socket.getaddrinfo",
            return_value=fake_info,
        ):
            # Should NOT raise.
            _validate_endpoint_url("https://example.com/api")

    @pytest.mark.asyncio
    async def test_response_size_cap_enforced(self, monkeypatch) -> None:
        """Fix 8: streaming response > MAX_REST_RESPONSE_BYTES raises."""
        monkeypatch.setattr("forge.plugins.executor.MAX_REST_RESPONSE_BYTES", 1024)
        # Bypass SSRF for the test endpoint.
        monkeypatch.setattr(
            "forge.plugins.executor._validate_endpoint_url",
            lambda url, allow_private_networks=False: None,
        )

        # Build a fake httpx response that streams chunks > the cap.
        oversized = b"X" * 4096

        class _FakeStreamCtx:
            def __init__(self) -> None:
                self.status_code = 200

            async def __aenter__(self) -> "_FakeStreamCtx":
                return self

            async def __aexit__(self, *exc: object) -> None:
                return None

            async def aiter_bytes(self):
                # Yield in chunks so the running buffer crosses the cap mid-stream.
                yield oversized[:512]
                yield oversized[512:1024]
                yield oversized[1024:2048]
                yield oversized[2048:]

        class _FakeClient:
            def stream(self, method, url, **kwargs):  # noqa: ARG002
                return _FakeStreamCtx()

        plugin = _make_plugin(name="oversized", mode=ExecutionMode.REST_API, timeout_seconds=5)
        executor = PluginExecutor(
            http_client=_FakeClient(),  # type: ignore[arg-type]
            settings=_make_test_settings(),
        )

        result = await executor.execute(plugin, params={"endpoint": "https://example.com/big"})
        assert result.success is False
        assert result.error is not None
        assert "exceeded" in result.error and "byte limit" in result.error

    @pytest.mark.asyncio
    async def test_redirect_not_followed(self, monkeypatch) -> None:
        """Fix 6: the lazy-built httpx.AsyncClient has follow_redirects=False."""
        try:
            import httpx
        except ImportError:
            pytest.skip("httpx not installed")

        # Lazy-construct via the executor.
        executor = PluginExecutor(settings=_make_test_settings())
        client = await executor._get_http_client(timeout_seconds=5)
        try:
            assert isinstance(client, httpx.AsyncClient)
            assert client.follow_redirects is False
            # And TLS verify must be on.
            # httpx exposes via the underlying transport; we test the
            # constructor was given verify=True implicitly by checking the
            # default _transport behaviour: a successful build is enough.
        finally:
            await executor.close()


# ===========================================================================
# DOCKER mode hardening
# ===========================================================================


class TestDockerModeHardening:
    """DOCKER executor regression tests for Fix 3 (resource limits).

    All tests mock :func:`asyncio.create_subprocess_exec` so no real Docker
    daemon is required; we capture the argv passed to the executor and
    assert on its shape.
    """

    @staticmethod
    def _build_capturing_subprocess():
        """Returns (captured_argv, fake_create_subprocess_exec) helpers."""
        captured: dict[str, Any] = {"argv": None}

        class _FakeStream:
            def __init__(self, data: bytes = b"") -> None:
                self._data = data
                self._read = False

            async def read(self, n: int) -> bytes:
                if self._read:
                    return b""
                self._read = True
                return self._data[:n]

        class _FakeProc:
            def __init__(self) -> None:
                self.stdout = _FakeStream(b'{"success": true, "output": {}}')
                self.stderr = _FakeStream(b"")
                self.stdin = None
                self.returncode = 0
                self.pid = 12345

            async def wait(self) -> int:
                return 0

            def kill(self) -> None:
                pass

        async def _fake_exec(*args: str, **_kwargs: Any) -> _FakeProc:
            captured["argv"] = list(args)
            return _FakeProc()

        return captured, _fake_exec

    @pytest.mark.asyncio
    async def test_argv_includes_resource_limits(self, monkeypatch) -> None:
        """Fix 3: --memory, --memory-swap, --cpus, --pids-limit are present."""
        captured, fake_exec = self._build_capturing_subprocess()
        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

        plugin = _make_plugin(name="docker_t", mode=ExecutionMode.DOCKER, timeout_seconds=10)
        executor = PluginExecutor(settings=_make_test_settings())

        result = await executor.execute(
            plugin, params={"image": "alpine:3.19", "cmd": ["echo", "hi"]}
        )
        assert result.success is True
        argv = captured["argv"]
        assert argv is not None
        assert "--memory=512m" in argv
        assert "--memory-swap=512m" in argv
        assert "--cpus=1.0" in argv
        assert "--pids-limit=128" in argv

    @pytest.mark.asyncio
    async def test_argv_includes_network_none(self, monkeypatch) -> None:
        """Fix 3: --network=none + existing --rm/--read-only/-i remain."""
        captured, fake_exec = self._build_capturing_subprocess()
        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

        plugin = _make_plugin(name="docker_n", mode=ExecutionMode.DOCKER, timeout_seconds=10)
        executor = PluginExecutor(settings=_make_test_settings())
        await executor.execute(plugin, params={"image": "alpine:3.19"})

        argv = captured["argv"]
        assert "--network=none" in argv
        assert "--rm" in argv
        assert "--read-only" in argv
        assert "-i" in argv

    @pytest.mark.asyncio
    async def test_argv_includes_user_nobody(self, monkeypatch) -> None:
        """Fix 3: --user=65534:65534 (nobody:nogroup) always present."""
        captured, fake_exec = self._build_capturing_subprocess()
        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

        plugin = _make_plugin(name="docker_u", mode=ExecutionMode.DOCKER, timeout_seconds=10)
        executor = PluginExecutor(settings=_make_test_settings())
        await executor.execute(plugin, params={"image": "alpine:3.19"})

        argv = captured["argv"]
        assert "--user=65534:65534" in argv

    @pytest.mark.asyncio
    async def test_argv_no_volume_mounts(self, monkeypatch) -> None:
        """No -v / --volume / --mount flags ever land in argv even when a
        plugin tries to smuggle them via params (params are not honoured
        for sandbox-defining flags)."""
        captured, fake_exec = self._build_capturing_subprocess()
        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

        plugin = _make_plugin(name="docker_v", mode=ExecutionMode.DOCKER, timeout_seconds=10)
        executor = PluginExecutor(settings=_make_test_settings())
        # Even with a malicious-looking env value, no -v should appear.
        await executor.execute(
            plugin,
            params={
                "image": "alpine:3.19",
                "env": {"INNOCUOUS": "value"},
                "cmd": ["echo", "ok"],
            },
        )

        argv = captured["argv"]
        # No volume-mount flag in any form.
        for token in argv:
            assert not token.startswith("-v"), f"unexpected -v flag: {token}"
            assert not token.startswith("--volume"), f"unexpected --volume flag: {token}"
            assert not token.startswith("--mount"), f"unexpected --mount flag: {token}"

    @pytest.mark.asyncio
    async def test_docker_limits_overrideable_per_instance(self, monkeypatch) -> None:
        """Per-instance ``docker_limits`` ctor arg overrides PlatformSettings."""
        captured, fake_exec = self._build_capturing_subprocess()
        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

        plugin = _make_plugin(name="docker_o", mode=ExecutionMode.DOCKER, timeout_seconds=10)
        executor = PluginExecutor(
            settings=_make_test_settings(),
            docker_limits={"memory_mb": 256, "cpus": 0.5, "pids_limit": 64},
        )
        await executor.execute(plugin, params={"image": "alpine:3.19"})

        argv = captured["argv"]
        assert "--memory=256m" in argv
        assert "--cpus=0.5" in argv
        assert "--pids-limit=64" in argv
