"""CLI entry point for ``forge mcp serve``.

Exposes the FORGE evidence surface over MCP (JSON-RPC 2.0). Loopback
only, token-authenticated by default; stdio is an alternative transport
for coding-agent harnesses that spawn MCP servers as subprocesses.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

import typer
from rich.console import Console

from forge.mcp.server import (
    MCP_PROTOCOL_VERSION,
    MCP_SERVER_VERSION,
    ForgeMCPServer,
    _is_loopback,
    build_tool_registry,
)

__all__ = ["register_mcp_commands"]

_console = Console(stderr=True)


def register_mcp_commands(app: typer.Typer) -> None:
    @app.command("serve")
    def serve(
        host: str = typer.Option(
            "127.0.0.1",
            "--host",
            help="Bind host. Loopback addresses only (127.0.0.1, ::1, localhost).",
        ),
        port: int = typer.Option(
            0,
            "--port",
            min=0,
            max=65535,
            help="Bind port. 0 picks a free ephemeral port.",
        ),
        transport: str = typer.Option(
            "http",
            "--transport",
            help="Transport: http (loopback+token) or stdio (one JSON per line).",
            case_sensitive=False,
        ),
        token: str = typer.Option(
            "",
            "--token",
            help="Bearer token for HTTP transport. If empty, one is generated.",
        ),
        token_env: str = typer.Option(
            "FORGE_MCP_TOKEN",
            "--token-env",
            help="Env var holding the bearer token when --token is not supplied.",
        ),
        no_token: bool = typer.Option(
            False,
            "--no-token",
            help="DANGEROUS: run the HTTP transport with no bearer token.",
        ),
        data_dir: str = typer.Option(
            "",
            "--data-dir",
            help="FORGE data directory. Defaults to $FORGE_DATA_DIR.",
        ),
        print_plan: bool = typer.Option(
            False,
            "--print-plan",
            help="Print the server configuration plan and exit without serving.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Emit JSON instead of human-readable output.",
        ),
    ) -> None:
        """Serve the FORGE MCP surface (read-only, loopback+token)."""
        transport_normalized = (transport or "").strip().lower()
        if transport_normalized not in {"http", "stdio"}:
            raise typer.BadParameter("--transport must be 'http' or 'stdio'")

        if not _is_loopback(host):
            raise typer.BadParameter(
                f"--host must be a loopback address (got {host!r})"
            )

        resolved_data_dir = (
            Path(data_dir).expanduser()
            if data_dir
            else Path(os.environ.get("FORGE_DATA_DIR") or (Path.home() / ".forge" / "data"))
        )

        if transport_normalized == "http":
            resolved_token = (
                token.strip()
                or os.environ.get(token_env or "FORGE_MCP_TOKEN", "").strip()
            )
            if no_token:
                resolved_token = ""
            elif not resolved_token:
                resolved_token = secrets.token_urlsafe(32)
        else:
            resolved_token = ""  # stdio does not use HTTP auth

        if print_plan:
            plan = {
                "schema_version": "forge.mcp.serve_plan.v1",
                "transport": transport_normalized,
                "host": host if transport_normalized == "http" else None,
                "port": port if transport_normalized == "http" else None,
                "data_dir": str(resolved_data_dir),
                "token_required": bool(resolved_token) and transport_normalized == "http",
                "token_present": bool(resolved_token),
                "protocol_version": MCP_PROTOCOL_VERSION,
                "server_version": MCP_SERVER_VERSION,
                "tools": sorted(build_tool_registry().keys()),
                "note": "Loopback-only HTTP; bearer-token required by default.",
            }
            if json_output:
                typer.echo(json.dumps(plan, indent=2))
            else:
                _console.print_json(data=plan)
            return

        server = ForgeMCPServer(
            data_dir=resolved_data_dir,
            host=host,
            port=port,
            auth_token=resolved_token or None,
            require_token=transport_normalized == "http" and not no_token,
        )

        if transport_normalized == "stdio":
            if json_output:
                typer.echo(
                    json.dumps(
                        {
                            "schema_version": "forge.mcp.serve_status.v1",
                            "transport": "stdio",
                            "data_dir": str(resolved_data_dir),
                            "tools": sorted(build_tool_registry().keys()),
                        }
                    )
                )
            else:
                _console.print(
                    "[cyan]forge-mcp[/cyan] serving on stdio (one JSON-RPC request per line)."
                )
            server.run_stdio()
            return

        bound_host, bound_port = server.start()
        try:
            status = {
                "schema_version": "forge.mcp.serve_status.v1",
                "transport": "http",
                "host": bound_host,
                "port": bound_port,
                "data_dir": str(resolved_data_dir),
                "token_present": bool(resolved_token),
                "protocol_version": MCP_PROTOCOL_VERSION,
                "server_version": MCP_SERVER_VERSION,
                "tools": sorted(build_tool_registry().keys()),
            }
            if json_output:
                typer.echo(json.dumps(status, indent=2))
            else:
                _console.print(
                    f"[cyan]forge-mcp[/cyan] listening on http://{bound_host}:{bound_port}/mcp"
                )
                if resolved_token and not no_token:
                    _console.print(
                        f"[dim]bearer token: [green]{resolved_token}[/green] (store this out of band)[/dim]"
                    )
                elif no_token:
                    _console.print(
                        "[red]DANGER:[/red] token auth disabled; anyone on loopback can read evidence."
                    )
            # Block until Ctrl+C.
            server.serve_forever()
        finally:
            server.stop()

    @app.command("tools")
    def tools(
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Emit JSON instead of a table.",
        ),
    ) -> None:
        """List the MCP tools exposed by ``forge mcp serve`` (read-only)."""
        registry = build_tool_registry()
        descriptors = [
            {
                "name": tool["name"],
                "description": tool["description"],
                "input_schema": tool["inputSchema"],
            }
            for tool in registry.values()
        ]
        payload = {
            "schema_version": "forge.mcp.tools.v1",
            "server_version": MCP_SERVER_VERSION,
            "protocol_version": MCP_PROTOCOL_VERSION,
            "total_count": len(descriptors),
            "tools": descriptors,
        }
        if json_output:
            typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        else:
            from rich.table import Table

            table = Table(title="FORGE MCP Tools", show_lines=True)
            table.add_column("Tool", style="cyan")
            table.add_column("Description")
            for descriptor in descriptors:
                table.add_row(descriptor["name"], descriptor["description"])
            _console.print(table)
