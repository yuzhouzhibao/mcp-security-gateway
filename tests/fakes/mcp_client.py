from collections.abc import Mapping
from typing import Any

from mcp_security_gateway.application.ports.mcp_client import (
    McpUpstreamError,
    McpUpstreamTimeoutError,
)


class TestOnlyMcpClient:
    __test__ = False

    def __init__(
        self,
        result: Mapping[str, Any] | None = None,
        failure: str | None = None,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self._result = result or {"ok": True}
        self._failure = failure

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
            raise McpUpstreamTimeoutError("test-only timeout")
        if self._failure == "failed":
            raise McpUpstreamError("test-only failure")
        return self._result
