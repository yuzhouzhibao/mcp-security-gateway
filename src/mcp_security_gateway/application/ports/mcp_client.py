from collections.abc import Mapping
from typing import Any, Protocol


class McpUpstreamError(RuntimeError):
    """Raised when the upstream MCP call fails."""


class McpUpstreamTimeoutError(McpUpstreamError):
    """Raised when the upstream MCP call times out."""


class McpClient(Protocol):
    async def call_tool(
        self,
        *,
        server: Any,
        tool: Any,
        arguments: Mapping[str, Any],
        timeout_seconds: float,
    ) -> Mapping[str, Any]: ...
