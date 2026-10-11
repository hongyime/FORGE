"""MCP (Model Context Protocol) server surface for FORGE evidence.

Wave 3, Explore #22. Exposes read-only FORGE engagement evidence
through the Model Context Protocol so coding agents (Strix, Claude Code,
Codex, Gemini, Kiro) can read engagement state the same way they read
other MCP servers.

Design invariants:
* Read-only by default; no write-capable tool is exposed.
* Loopback bind + token-authenticated by default; no public exposure.
* Scope/engagement filtering is enforced by the underlying DB queries.
* No raw secret material is ever returned.

Protocol: JSON-RPC 2.0 (see https://modelcontextprotocol.io/).
"""

from __future__ import annotations

from forge.mcp.server import (
    MCP_SERVER_VERSION,
    MCP_PROTOCOL_VERSION,
    ForgeMCPServer,
    MCPError,
    MCPResponse,
    build_tool_registry,
    dispatch_jsonrpc,
)

__all__ = [
    "MCP_SERVER_VERSION",
    "MCP_PROTOCOL_VERSION",
    "ForgeMCPServer",
    "MCPError",
    "MCPResponse",
    "build_tool_registry",
    "dispatch_jsonrpc",
]
