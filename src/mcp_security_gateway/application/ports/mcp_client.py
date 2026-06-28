from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol


class McpUpstreamError(RuntimeError):
    """Raised when the upstream MCP call fails."""

    def __init__(
        self,
        code: str = "upstream_failed",
        message: str = "Upstream tool call failed",
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class McpUpstreamTimeoutError(McpUpstreamError):
    """Raised when the upstream MCP call times out."""


class McpToolListError(McpUpstreamError):
    """Raised when MCP tool discovery fails."""


@dataclass(frozen=True, slots=True)
class McpToolMetadata:
    name: str
    description: str | None
    input_schema: dict[str, Any]


class McpClient(Protocol):
    async def list_tools(
        self,
        *,
        server: Any,
        timeout_seconds: float,
    ) -> Sequence[McpToolMetadata]: ...

    async def call_tool(
        self,
        *,
        server: Any,
        tool: Any,
        arguments: Mapping[str, Any],
        timeout_seconds: float,
    ) -> Mapping[str, Any]: ...
