from collections.abc import Mapping
from typing import Any

from mcp_security_gateway.application.ports.mcp_client import (
    McpToolListError,
    McpToolMetadata,
    McpUpstreamError,
    McpUpstreamTimeoutError,
)


class TestOnlyMcpClient:
    __test__ = False

    def __init__(
        self,
        result: Mapping[str, Any] | None = None,
        failure: str | None = None,
        tools: list[McpToolMetadata] | None = None,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self.list_calls: list[dict[str, Any]] = []
        self._result = result or {"ok": True}
        self._failure = failure
        self._tools = tools or []

    def set_tools(self, tools: list[McpToolMetadata]) -> None:
        self._tools = tools

    async def list_tools(
        self,
        *,
        server: Any,
        timeout_seconds: float,
    ) -> list[McpToolMetadata]:
        self.list_calls.append({"server": server, "timeout_seconds": timeout_seconds})
        if self._failure == "timeout":
            raise McpToolListError("mcp_timeout", "MCP tool discovery timed out")
        if self._failure == "failed":
            raise McpToolListError("mcp_tool_list_failed", "MCP tool discovery failed")
        return self._tools

    async def call_tool(
        self,
        *,
        server: Any,
        tool: Any,
        arguments: Mapping[str, Any],
        timeout_seconds: float,
    ) -> Mapping[str, Any]:
        self.calls.append(
            {
                "server": server,
                "tool": tool,
                "arguments": dict(arguments),
                "timeout_seconds": timeout_seconds,
            }
        )
        if self._failure == "timeout":
            raise McpUpstreamTimeoutError("upstream_timeout", "Upstream timed out")
        if self._failure == "failed":
            raise McpUpstreamError("upstream_failed", "Upstream tool call failed")
        if self._failure == "mcp_tool_call_failed":
            raise McpUpstreamError("mcp_tool_call_failed", "MCP tool call failed")
        return self._result
