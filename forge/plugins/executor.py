"""
forge/plugins/executor.py — Plugin execution dispatcher with timeout enforcement.

The :class:`PluginExecutor` is the single entry point through which the
platform invokes a registered :class:`forge.plugins.base.Plugin`. It reads the
plugin's declared :class:`forge.plugins.base.ExecutionMode` and dispatches the
call to one of four backend handlers, enforcing the per-plugin
``timeout_seconds`` and emitting exactly one
:class:`forge.audit.models.AuditEntry` of type
:class:`forge.audit.models.AuditEventType.TOOL_INVOCATION` per call (success
*or* failure).

Hardening (post-review remediation):

- **SUBPROCESS / DOCKER** stdout and stderr are read incrementally with bounded
  byte caps (``MAX_STDOUT_BYTES`` / ``MAX_STDERR_BYTES``); on overflow the
  child is killed and a failure :class:`PluginResult` is returned. The full
  ``proc.communicate`` path was removed so a runaway child cannot exhaust
  memory in the host process.
- **REST_API** endpoints are validated against an SSRF blocklist
  (``BLOCKED_NETWORKS``) covering loopback, link-local, RFC1918, carrier-grade
  NAT, multicast, IPv6 unique-local, and IPv6 link-local prefixes; the only
  allowed schemes are ``http`` and ``https``. Operators may opt in to private
  networks via :attr:`forge.config.PlatformSettings.allow_private_networks`.
  Responses are streamed with an upper byte cap
  (``MAX_REST_RESPONSE_BYTES``).
- **DOCKER** invocations always include resource caps (``--memory``,
  ``--memory-swap``, ``--cpus``, ``--pids-limit``, ``--user=65534:65534``)
  on top of the existing sandbox flags (``--rm --network=none --read-only
  -i``). Defaults come from :class:`PlatformSettings` and may be overridden
  per :class:`PluginExecutor` instance via the ``docker_limits`` ctor arg.
- **SUBPROCESS** child processes inherit only a minimal allow-list env
  (``PATH`` / ``HOME`` / ``LANG`` / ``TZ``) instead of the full host
  environment. Plugins may opt-in to extra inherited keys via
  :attr:`PluginMetadata.inherit_env_vars`.
- **All exception paths** in SUBPROCESS / DOCKER reap the child via
  :meth:`_terminate_subprocess`, including ``BaseException``-derived
  exceptions (``KeyboardInterrupt`` / ``SystemExit``).
- **httpx.AsyncClient** is constructed with explicit connection limits, TLS
  verification on, and redirect following off.
- **Non-JSON stdout** from a SUBPROCESS plugin is treated as a failure (was
  previously silently wrapped as success), matching plugin authors' intent.

Requirements: 4.4, 4.5
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import socket
import sys
import time
import uuid
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlsplit

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEntry, AuditEventType
from forge.config import PlatformSettings
from forge.core.errors import (
    PluginSubprocessKilledError,
    PluginTimeoutError,
    SsrfBlockedError,
)
from forge.plugins.base import ExecutionMode, Plugin, PluginResult

if TYPE_CHECKING:  # pragma: no cover - import for type hints only
    import httpx

__all__ = ["PluginExecutor"]

_LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hardening constants (Fix 1, 2, 3, 8)
# ---------------------------------------------------------------------------

# Fix 1 (P0-6) — bounded stream caps for SUBPROCESS / DOCKER.
MAX_STDOUT_BYTES: int = 16 * 1024 * 1024  # 16 MiB
MAX_STDERR_BYTES: int = 1 * 1024 * 1024  # 1 MiB
_STREAM_CHUNK: int = 64 * 1024  # 64 KiB read granularity

# Fix 8 (P1-3) — REST response cap.
MAX_REST_RESPONSE_BYTES: int = 10 * 1024 * 1024  # 10 MiB

# Fix 2 (P0-7) — SSRF blocklist. Each entry parsed once into an
# ``ip_network`` object; ``hostname`` resolution is checked against every
# entry. Operators may opt-in to private networks for isolated test
# environments via :attr:`PlatformSettings.allow_private_networks`.
_BLOCKED_NETWORK_STRINGS: tuple[str, ...] = (
    # IPv4
    "127.0.0.0/8",  # loopback
    "169.254.0.0/16",  # link-local / AWS IMDS
    "10.0.0.0/8",  # RFC1918
    "172.16.0.0/12",  # RFC1918
    "192.168.0.0/16",  # RFC1918
    "100.64.0.0/10",  # carrier-grade NAT
    "224.0.0.0/4",  # multicast
    # IPv6
    "::1/128",  # loopback
    "fc00::/7",  # unique-local
    "fe80::/10",  # link-local
)
BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(cidr) for cidr in _BLOCKED_NETWORK_STRINGS
)
ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})


def _validate_endpoint_url(url: str, allow_private_networks: bool = False) -> None:
    """SSRF guard for REST_API endpoints (Fix 2 / P0-7).

    Validates that ``url``:

    1. Has a scheme in :data:`ALLOWED_SCHEMES` (rejects ``file://``,
       ``gopher://``, ``ftp://`` etc.).
    2. Has a non-empty hostname.
    3. Resolves (via ``socket.getaddrinfo``) to at least one address, and
       NONE of the resolved addresses fall inside :data:`BLOCKED_NETWORKS`
       (unless ``allow_private_networks`` is True).

    Raises:
        SsrfBlockedError: When any of the above checks fail.
    """
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SsrfBlockedError(
            f"REST_API endpoint scheme {scheme!r} is not allowed; "
            f"permitted schemes: {sorted(ALLOWED_SCHEMES)}"
        )
    hostname = parsed.hostname
    if not hostname:
        raise SsrfBlockedError(
            f"REST_API endpoint {url!r} has no hostname component"
        )

    # Short-circuit when the operator has explicitly opted-in. We still
    # require a parsable hostname above so config errors surface.
    if allow_private_networks:
        return

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise SsrfBlockedError(
            f"REST_API endpoint {url!r} did not resolve: {exc}"
        ) from exc

    seen: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_text = str(sockaddr[0])
        # Strip IPv6 zone suffix, e.g. ``fe80::1%eth0`` → ``fe80::1``.
        ip_text = ip_text.split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(ip_text)
        except ValueError:
            continue
        seen.append(ip_text)
        for net in BLOCKED_NETWORKS:
            if addr.version != net.version:
                continue
            if addr in net:
                raise SsrfBlockedError(
                    f"REST_API endpoint {url!r} resolves to {ip_text} which "
                    f"is in blocked network {net}"
                )
    if not seen:
        raise SsrfBlockedError(
            f"REST_API endpoint {url!r} produced no usable IP addresses"
        )


async def _read_stream_bounded(
    stream: asyncio.StreamReader | None, max_bytes: int
) -> tuple[bytes, bool]:
    """Read ``stream`` in chunks up to ``max_bytes`` (Fix 1 / P0-6).

    Returns the accumulated bytes plus a ``truncated`` flag set to True when
    the stream produced more data than ``max_bytes``. When ``stream`` is
    None (handler did not request a pipe), returns ``(b"", False)``.
    """
    if stream is None:
        return b"", False
    buf = bytearray()
    truncated = False
    while True:
        chunk = await stream.read(_STREAM_CHUNK)
        if not chunk:
            break
        if len(buf) + len(chunk) > max_bytes:
            # Accept up to the cap so we still surface a useful preview.
            remaining = max_bytes - len(buf)
            if remaining > 0:
                buf.extend(chunk[:remaining])
            truncated = True
            break
        buf.extend(chunk)
    return bytes(buf), truncated


class PluginExecutor:
    """Dispatches plugin invocations to the backend selected by metadata.

    Args:
        audit: Audit sink for ``TOOL_INVOCATION`` entries. When ``None`` a
            fresh :class:`AuditLogger` is constructed.
        http_client: Pre-built ``httpx.AsyncClient`` for REST_API dispatch.
            When ``None`` the client is lazy-constructed on the first
            REST_API call.
        settings: Platform settings used for SSRF / Docker hardening
            defaults. When ``None`` a fresh :class:`PlatformSettings` is
            instantiated (sourced from environment).
        docker_limits: Optional per-instance override for Docker resource
            caps. Recognised keys (all optional): ``memory_mb`` (int),
            ``cpus`` (float), ``pids_limit`` (int).

    Requirements: 4.4 (timeout), 4.5 (audit).
    """

    def __init__(
        self,
        audit: AuditLogger | None = None,
        http_client: "httpx.AsyncClient | None" = None,
        settings: PlatformSettings | None = None,
        docker_limits: dict[str, int | float] | None = None,
    ) -> None:
        self._audit: AuditLogger = audit if audit is not None else AuditLogger()
        self._http_client: "httpx.AsyncClient | None" = http_client
        self._http_client_owned: bool = False
        # PlatformSettings reads from env at construction; if instantiation
        # fails (e.g. invalid env var) we fall back to defaults so the
        # executor remains usable in test environments.
        if settings is not None:
            self._settings = settings
        else:
            try:
                self._settings = PlatformSettings()
            except Exception:  # noqa: BLE001 - defensive default
                self._settings = PlatformSettings.model_construct()
        self._docker_limits: dict[str, int | float] = self._resolve_docker_limits(
            docker_limits
        )

    def _resolve_docker_limits(
        self, override: dict[str, int | float] | None
    ) -> dict[str, int | float]:
        """Merge per-instance ``docker_limits`` with PlatformSettings defaults."""
        merged: dict[str, int | float] = {
            "memory_mb": int(self._settings.docker_memory_mb),
            "cpus": float(self._settings.docker_cpus),
            "pids_limit": int(self._settings.docker_pids_limit),
        }
        if override:
            for key in ("memory_mb", "cpus", "pids_limit"):
                if key in override:
                    merged[key] = override[key]
        return merged

    # ------------------------------------------------------------------
    # Read-only accessors
    # ------------------------------------------------------------------

    @property
    def audit(self) -> AuditLogger:
        """Return the audit logger used by this executor."""
        return self._audit

    # ------------------------------------------------------------------
    # Public operations
    # ------------------------------------------------------------------

    async def execute(
        self,
        plugin: Plugin,
        params: dict[str, object],
        correlation_id: str | None = None,
    ) -> PluginResult:
        """Invoke ``plugin`` with ``params`` under its declared execution mode."""
        cid = correlation_id if correlation_id is not None else uuid.uuid4().hex
        metadata = plugin.metadata
        timeout = float(metadata.timeout_seconds)
        mode = metadata.execution_mode
        start = time.perf_counter()

        _LOG.debug(
            "PluginExecutor: dispatching tool=%s mode=%s timeout=%.1fs cid=%s",
            metadata.name,
            mode.value,
            timeout,
            cid,
        )

        try:
            result = await asyncio.wait_for(
                self._dispatch(mode, plugin, params),
                timeout=timeout,
            )
        except asyncio.TimeoutError as exc:
            duration_ms = (time.perf_counter() - start) * 1000.0
            message = (
                f"Plugin {metadata.name!r} exceeded "
                f"{timeout:.1f}s timeout (mode={mode.value})"
            )
            await self._audit_failure(
                correlation_id=cid,
                tool_name=metadata.name,
                params=params,
                duration_ms=duration_ms,
                error_detail=message,
                error_class="PluginTimeoutError",
            )
            raise PluginTimeoutError(message) from exc
        except PluginTimeoutError as exc:
            duration_ms = (time.perf_counter() - start) * 1000.0
            await self._audit_failure(
                correlation_id=cid,
                tool_name=metadata.name,
                params=params,
                duration_ms=duration_ms,
                error_detail=str(exc),
                error_class="PluginTimeoutError",
            )
            raise
        except Exception as exc:  # noqa: BLE001 - normalise all backend failures
            duration_ms = (time.perf_counter() - start) * 1000.0
            error_detail = f"{exc.__class__.__name__}: {exc}"
            fq_error_class = (
                f"{exc.__class__.__module__}.{exc.__class__.__qualname__}"
            )
            await self._audit_failure(
                correlation_id=cid,
                tool_name=metadata.name,
                params=params,
                duration_ms=duration_ms,
                error_detail=error_detail,
                error_class=exc.__class__.__name__,
            )
            return PluginResult(
                success=False,
                output={},
                error=error_detail,
                error_class=fq_error_class,
                error_exc=exc,
                duration_ms=duration_ms,
            )

        duration_ms = (time.perf_counter() - start) * 1000.0
        if result.duration_ms <= 0.0:
            result = result.model_copy(update={"duration_ms": duration_ms})

        await self._audit_success(
            correlation_id=cid,
            tool_name=metadata.name,
            params=params,
            result=result,
            duration_ms=duration_ms,
        )
        return result

    async def close(self) -> None:
        """Release any lazy resources (currently the HTTP client)."""
        if self._http_client is not None and self._http_client_owned:
            try:
                await self._http_client.aclose()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                _LOG.debug("PluginExecutor: error closing http client", exc_info=True)
            finally:
                self._http_client = None
                self._http_client_owned = False

    # ------------------------------------------------------------------
    # Mode dispatch
    # ------------------------------------------------------------------

    async def _dispatch(
        self,
        mode: ExecutionMode,
        plugin: Plugin,
        params: dict[str, object],
    ) -> PluginResult:
        if mode is ExecutionMode.IN_PROCESS:
            return await self._exec_in_process(plugin, params)
        if mode is ExecutionMode.SUBPROCESS:
            return await self._exec_subprocess(plugin, params)
        if mode is ExecutionMode.REST_API:
            return await self._exec_rest_api(plugin, params)
        if mode is ExecutionMode.DOCKER:
            return await self._exec_docker(plugin, params)
        raise ValueError(f"Unsupported execution mode: {mode!r}")

    async def _exec_in_process(
        self, plugin: Plugin, params: dict[str, object]
    ) -> PluginResult:
        """Invoke ``plugin.execute`` directly in the host event loop."""
        result = await plugin.execute(dict(params))
        if not isinstance(result, PluginResult):
            raise TypeError(
                "In-process plugin returned non-PluginResult "
                f"(got {type(result).__name__})"
            )
        return result

    # ------------------------------------------------------------------
    # SUBPROCESS
    # ------------------------------------------------------------------

    @staticmethod
    def _build_minimal_env(
        inherit_keys: list[str], explicit_env: dict[str, str] | None
    ) -> dict[str, str]:
        """Build the child env for a SUBPROCESS plugin (Fix 4 / P1-2).

        Always seeds ``PATH``, ``HOME`` (or ``USERPROFILE`` on Windows),
        ``LANG`` and ``TZ`` from the host. Plugins may extend the inherited
        set via :attr:`PluginMetadata.inherit_env_vars`. Explicit ``env``
        params are merged last (highest precedence) but, critically, NOT
        merged with the full host ``os.environ``.
        """
        env: dict[str, str] = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get(
                "HOME", os.environ.get("USERPROFILE", "")
            ),
            "LANG": os.environ.get("LANG", "C"),
            "TZ": os.environ.get("TZ", "UTC"),
        }
        for key in inherit_keys:
            if not isinstance(key, str) or not key:
                continue
            if key in os.environ:
                env[key] = os.environ[key]
        if explicit_env:
            for k, v in explicit_env.items():
                env[str(k)] = str(v)
        return env

    async def _exec_subprocess(
        self, plugin: Plugin, params: dict[str, object]
    ) -> PluginResult:
        """Spawn a CLI tool and parse its stdout JSON into a PluginResult."""
        cmd_obj = params.get("cmd")
        if not isinstance(cmd_obj, list) or not cmd_obj:
            raise ValueError(
                "SUBPROCESS plugin requires params['cmd'] to be a non-empty list"
            )
        cmd: list[str] = [str(token) for token in cmd_obj]

        cwd_obj = params.get("cwd")
        cwd: str | None = str(cwd_obj) if cwd_obj is not None else None

        explicit_env: dict[str, str] | None = None
        env_obj = params.get("env")
        if isinstance(env_obj, dict):
            explicit_env = {str(k): str(v) for k, v in env_obj.items()}

        # Fix 4 (P1-2): minimal env by default; metadata allowlist; explicit
        # params['env'] merges on top of the minimal env, NOT os.environ.
        inherit_keys = list(getattr(plugin.metadata, "inherit_env_vars", []) or [])
        env: dict[str, str] = self._build_minimal_env(inherit_keys, explicit_env)

        stdin_obj = params.get("stdin")
        stdin_bytes: bytes | None = None
        if isinstance(stdin_obj, (bytes, bytearray)):
            stdin_bytes = bytes(stdin_obj)
        elif isinstance(stdin_obj, str):
            stdin_bytes = stdin_obj.encode("utf-8")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin_bytes is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
        )
        # Fix 5 (P2-5): always reap on any exception (BaseException-derived
        # included).
        try:
            return await self._read_subprocess_to_result(
                proc=proc,
                tool_name=plugin.metadata.name,
                stdin_bytes=stdin_bytes,
            )
        except BaseException:
            await self._terminate_subprocess(proc)
            raise

    async def _read_subprocess_to_result(
        self,
        *,
        proc: asyncio.subprocess.Process,
        tool_name: str,
        stdin_bytes: bytes | None,
    ) -> PluginResult:
        """Bounded incremental reader for SUBPROCESS / DOCKER children.

        Implements Fix 1 (P0-6): replaces ``proc.communicate`` with a
        chunked reader so a runaway child cannot exhaust host memory. On
        overflow the child is killed and a failure :class:`PluginResult`
        is returned (rather than raising) so upstream audit emission still
        captures the event.
        """
        # Feed stdin first if present. ``communicate`` would have done this
        # for us; here we drive the writer manually to keep the lifecycle
        # explicit.
        if stdin_bytes is not None and proc.stdin is not None:
            try:
                proc.stdin.write(stdin_bytes)
                await proc.stdin.drain()
            finally:
                try:
                    proc.stdin.close()
                except Exception:  # noqa: BLE001 - best-effort
                    pass

        stdout_task = asyncio.create_task(
            _read_stream_bounded(proc.stdout, MAX_STDOUT_BYTES)
        )
        stderr_task = asyncio.create_task(
            _read_stream_bounded(proc.stderr, MAX_STDERR_BYTES)
        )
        # Wait for both bounded readers concurrently. If either overflows
        # the child must be killed BEFORE we drain the other stream — a
        # full pipe would otherwise deadlock the child and stall this
        # coroutine until ``asyncio.wait_for`` cancels us.
        try:
            done, _pending = await asyncio.wait(
                {stdout_task, stderr_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            # Inspect whichever finished first; if it overflowed, kill
            # the child so the second reader can drain to EOF promptly.
            for t in done:
                _data, _trunc = t.result()
                if _trunc:
                    await self._terminate_subprocess(proc)
                    break
            stdout, stdout_truncated = await stdout_task
            stderr, stderr_truncated = await stderr_task
        except BaseException:
            stdout_task.cancel()
            stderr_task.cancel()
            raise
        await proc.wait()

        if stdout_truncated:
            return PluginResult(
                success=False,
                output={"stdout_preview": stdout[:1024].decode("utf-8", errors="replace")},
                error=f"stdout exceeded {MAX_STDOUT_BYTES} byte limit",
            )
        if stderr_truncated:
            return PluginResult(
                success=False,
                output={"stderr_preview": stderr[:1024].decode("utf-8", errors="replace")},
                error=f"stderr exceeded {MAX_STDERR_BYTES} byte limit",
            )

        return self._parse_process_result(
            tool_name=tool_name,
            returncode=proc.returncode if proc.returncode is not None else -1,
            stdout=stdout,
            stderr=stderr,
        )

    # ------------------------------------------------------------------
    # REST_API
    # ------------------------------------------------------------------

    async def _exec_rest_api(
        self, plugin: Plugin, params: dict[str, object]
    ) -> PluginResult:
        """POST ``params`` (minus ``endpoint``) to a remote tool endpoint."""
        endpoint_obj = params.get("endpoint")
        if not isinstance(endpoint_obj, str) or not endpoint_obj:
            raise ValueError(
                "REST_API plugin requires params['endpoint'] to be a non-empty string"
            )
        endpoint: str = endpoint_obj

        # Fix 2 (P0-7): SSRF allowlist BEFORE any I/O.
        _validate_endpoint_url(
            endpoint,
            allow_private_networks=bool(self._settings.allow_private_networks),
        )

        headers_obj = params.get("headers")
        headers: dict[str, str] | None = None
        if isinstance(headers_obj, dict):
            headers = {str(k): str(v) for k, v in headers_obj.items()}

        method_obj = params.get("method", "POST")
        method = str(method_obj).upper() if method_obj is not None else "POST"

        body: dict[str, object] = {
            k: v
            for k, v in params.items()
            if k not in {"endpoint", "headers", "method"}
        }

        client = await self._get_http_client(plugin.metadata.timeout_seconds)
        # Lazy-import httpx for typed exception handling.
        try:
            import httpx as _httpx
        except ImportError:  # pragma: no cover - httpx is in pyproject
            raise

        # Fix 8 (P1-3): stream the response with a hard byte cap. We cannot
        # use response.json() directly because that buffers the full body.
        try:
            async with client.stream(
                method,
                endpoint,
                json=body,
                headers=headers,
                timeout=float(plugin.metadata.timeout_seconds),
            ) as response:
                if response.status_code >= 400:
                    # Read up to 200 bytes of preview without exceeding the
                    # cap; ``aread`` is bounded by the streaming context.
                    preview_buf = bytearray()
                    async for chunk in response.aiter_bytes():
                        preview_buf.extend(chunk)
                        if len(preview_buf) >= 200:
                            break
                    preview = bytes(preview_buf[:200]).decode(
                        "utf-8", errors="replace"
                    )
                    raise RuntimeError(
                        f"REST_API call to {endpoint!r} returned HTTP "
                        f"{response.status_code}: {preview!r}"
                    )

                body_buf = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(body_buf) + len(chunk) > MAX_REST_RESPONSE_BYTES:
                        raise RuntimeError(
                            f"REST_API response from {endpoint!r} exceeded "
                            f"{MAX_REST_RESPONSE_BYTES} byte limit"
                        )
                    body_buf.extend(chunk)
        except _httpx.TimeoutException as exc:
            raise PluginTimeoutError(
                f"REST_API call to {endpoint!r} timed out after "
                f"{plugin.metadata.timeout_seconds}s"
            ) from exc

        if not body_buf:
            return PluginResult(success=True, output={})
        try:
            payload = json.loads(bytes(body_buf).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(
                f"REST_API response from {endpoint!r} is not valid JSON: {exc}"
            ) from exc
        return self._coerce_result(payload)

    # ------------------------------------------------------------------
    # DOCKER
    # ------------------------------------------------------------------

    def _build_docker_argv(
        self,
        *,
        image: str,
        env: dict[str, object] | None,
        cmd: list[str] | None,
        container_name: str,
    ) -> list[str]:
        """Compose ``docker run`` argv with unconditional sandbox flags."""
        memory_mb = int(self._docker_limits["memory_mb"])
        cpus = float(self._docker_limits["cpus"])
        pids = int(self._docker_limits["pids_limit"])

        argv: list[str] = [
            "docker",
            "run",
            "--rm",
            "--name", container_name,
            "--network=none",
            "--read-only",
            "-i",
            # Fix 3 (P0-8): unconditional resource caps.
            f"--memory={memory_mb}m",
            f"--memory-swap={memory_mb}m",
            f"--cpus={cpus}",
            f"--pids-limit={pids}",
            "--user=65534:65534",
        ]

        if env:
            for k, v in env.items():
                argv.extend(["-e", f"{k}={v}"])

        argv.append(image)

        if cmd:
            argv.extend(str(token) for token in cmd)
        return argv

    async def _exec_docker(
        self, plugin: Plugin, params: dict[str, object]
    ) -> PluginResult:
        """Run a tool inside a hardened Docker sandbox."""
        image_obj = params.get("image")
        if not isinstance(image_obj, str) or not image_obj:
            raise ValueError(
                "DOCKER plugin requires params['image'] to be a non-empty string"
            )
        image: str = image_obj

        env_obj = params.get("env")
        env_dict: dict[str, object] | None = (
            {str(k): v for k, v in env_obj.items()}
            if isinstance(env_obj, dict)
            else None
        )

        cmd_obj = params.get("cmd")
        cmd_list: list[str] | None = (
            [str(token) for token in cmd_obj] if isinstance(cmd_obj, list) else None
        )

        # Fix 9 (Win Docker orphan reap): assign a stable forge-prefix name
        # so we can `docker kill` the daemon-side container directly on
        # timeout/cancellation. Killing the CLI alone does not propagate to
        # the container managed by the Docker daemon.
        container_name = f"forge-plugin-{uuid.uuid4().hex[:12]}"

        argv: list[str] = self._build_docker_argv(
            image=image, env=env_dict, cmd=cmd_list,
            container_name=container_name,
        )

        stdin_obj = params.get("stdin")
        stdin_bytes: bytes | None = None
        if isinstance(stdin_obj, (bytes, bytearray)):
            stdin_bytes = bytes(stdin_obj)
        elif isinstance(stdin_obj, str):
            stdin_bytes = stdin_obj.encode("utf-8")

        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin_bytes is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        # Fix 5 (P2-5): always reap on any exception including BaseException.
        try:
            return await self._read_subprocess_to_result(
                proc=proc,
                tool_name=plugin.metadata.name,
                stdin_bytes=stdin_bytes,
            )
        except BaseException:
            # Fix 9: kill the named container BEFORE cleaning the CLI proc.
            await self._docker_kill_container(container_name)
            await self._terminate_subprocess(proc)
            raise

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _get_http_client(self, timeout_seconds: int) -> "httpx.AsyncClient":
        """Return the lazy-constructed shared HTTP client (Fix 6)."""
        if self._http_client is not None:
            return self._http_client
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - httpx is in pyproject
            raise RuntimeError(
                "REST_API execution requires the 'httpx' package to be installed"
            ) from exc
        from forge.utils.ssl_hygiene import restore_default_ssl_context

        restore_default_ssl_context()
        # Fix 6 (P2-12): explicit limits, TLS verify on, no redirects.
        client = httpx.AsyncClient(
            timeout=httpx.Timeout(float(timeout_seconds)),
            limits=httpx.Limits(
                max_connections=20,
                max_keepalive_connections=5,
                keepalive_expiry=30.0,
            ),
            verify=True,
            follow_redirects=False,
        )
        self._http_client = client
        self._http_client_owned = True
        return client

    @staticmethod
    async def _terminate_subprocess(proc: asyncio.subprocess.Process) -> None:
        """Best-effort kill of a child process."""
        if proc.returncode is not None:
            return
        try:
            proc.kill()
        except ProcessLookupError:  # pragma: no cover - already dead
            return
        try:
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        except (asyncio.TimeoutError, Exception):  # noqa: BLE001
            _LOG.debug(
                "PluginExecutor: child %s did not exit after kill", proc.pid
            )

    @staticmethod
    async def _docker_kill_container(container_name: str) -> None:
        """Best-effort `docker kill` of a named container (Fix 9).

        On Windows Docker Desktop, killing the local docker CLI does NOT
        propagate to the daemon-managed container. We therefore have to
        explicitly tell the daemon to kill the named container. Failures
        are swallowed - this is a defence-in-depth cleanup, not a hard
        guarantee that the container existed.
        """
        try:
            kill_proc = await asyncio.create_subprocess_exec(
                "docker", "kill", container_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(kill_proc.wait(), timeout=5.0)
        except (FileNotFoundError, asyncio.TimeoutError, Exception):  # noqa: BLE001
            _LOG.debug(
                "PluginExecutor: docker kill %s failed (probably already gone)",
                container_name,
            )

    def _parse_process_result(
        self,
        *,
        tool_name: str,
        returncode: int,
        stdout: bytes,
        stderr: bytes,
    ) -> PluginResult:
        """Decode a child's stdout JSON into a PluginResult.

        Fix 7 (P0-6 follow-up): when stdout is non-empty but undecodable
        as JSON, return ``success=False`` with a descriptive error rather
        than masking the plugin bug behind ``success=True``.
        """
        stdout_text = stdout.decode("utf-8", errors="replace").strip()
        stderr_text = stderr.decode("utf-8", errors="replace").strip()

        if returncode != 0:
            # Requirement 10 of chaos-harness-hardening: encode the
            # failure class so callers can distinguish signal-driven
            # termination (returncode < 0 on POSIX) from other non-zero
            # exits. Windows does not surface signals via returncode,
            # so every non-zero exit is treated as a subprocess-killed
            # event there. Requirement 3.13 of audit-cleanup-and-chaos:
            # carry an actual exception INSTANCE in ``error_exc`` so
            # callers (the chaos harness's ``scenario_plugin_sigkill``)
            # can do a proper ``isinstance(err, ForgeError)`` check
            # rather than round-tripping through a string class name.
            error_msg = (
                f"{tool_name!r} exited with code {returncode}: "
                f"{stderr_text[:512]}"
            )
            error_exc: BaseException
            if returncode < 0 and sys.platform != "win32":
                fq_error_class = "builtins.ProcessLookupError"
                # ``ProcessLookupError`` is one of the accepted typed
                # sentinels for signal-driven POSIX exits (see the
                # chaos harness's scenario 3 documentation).
                error_exc = ProcessLookupError(error_msg)
            else:
                fq_error_class = (
                    "forge.core.errors.PluginSubprocessKilledError"
                )
                error_exc = PluginSubprocessKilledError(error_msg)
            return PluginResult(
                success=False,
                output={"stdout": stdout_text[:1024]},
                error=error_msg,
                error_class=fq_error_class,
                error_exc=error_exc,
            )

        if not stdout_text:
            # Cleanly-exiting plugins may produce no stdout — preserve the
            # success contract for that case.
            return PluginResult(success=True, output={})

        try:
            payload = json.loads(stdout_text)
        except json.JSONDecodeError as exc:
            preview = stdout_text[:200]
            return PluginResult(
                success=False,
                output={"stdout": stdout_text[:4096]},
                error=f"stdout is not valid JSON: {preview!r}",
                error_class="json.JSONDecodeError",
                error_exc=exc,
            )
        return self._coerce_result(payload)

    @staticmethod
    def _coerce_result(payload: object) -> PluginResult:
        """Convert a JSON payload into a :class:`PluginResult`."""
        if isinstance(payload, dict) and "success" in payload and "output" in payload:
            return PluginResult.model_validate(payload)
        if isinstance(payload, dict):
            return PluginResult(success=True, output=cast(dict[str, Any], payload))
        return PluginResult(success=True, output={"value": payload})

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    async def _audit_success(
        self,
        *,
        correlation_id: str,
        tool_name: str,
        params: dict[str, object],
        result: PluginResult,
        duration_ms: float,
    ) -> None:
        summary = json.dumps(
            {
                "tool_name": tool_name,
                "success": result.success,
                "output_keys": sorted(result.output.keys()),
                "duration_ms": duration_ms,
            },
            sort_keys=True,
        )
        entry = AuditEntry(
            correlation_id=correlation_id,
            event_type=AuditEventType.TOOL_INVOCATION,
            tool_name=tool_name,
            input_params=dict(params),
            output_summary=summary,
            duration_ms=duration_ms,
            success=result.success,
            error_detail=result.error,
        )
        await self._audit.log(entry)

    async def _audit_failure(
        self,
        *,
        correlation_id: str,
        tool_name: str,
        params: dict[str, object],
        duration_ms: float,
        error_detail: str,
        error_class: str,
    ) -> None:
        summary = json.dumps(
            {
                "tool_name": tool_name,
                "success": False,
                "error_class": error_class,
                "duration_ms": duration_ms,
            },
            sort_keys=True,
        )
        entry = AuditEntry(
            correlation_id=correlation_id,
            event_type=AuditEventType.TOOL_INVOCATION,
            tool_name=tool_name,
            input_params=dict(params),
            output_summary=summary,
            duration_ms=duration_ms,
            success=False,
            error_detail=error_detail,
        )
        await self._audit.log(entry)
