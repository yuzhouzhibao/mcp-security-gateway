import asyncio
from collections.abc import Mapping, Sequence
from datetime import timedelta
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError
from mcp_security_gateway.application.ports.mcp_client import (
    McpClient,
    McpToolListError,
    McpToolMetadata,
    McpUpstreamError,
    McpUpstreamTimeoutError,
)
from mcp_security_gateway.domain.enums import TransportType


class StdioMcpClient:
    async def list_tools(
        self,
        *,
        server: Any,
        timeout_seconds: float,
    ) -> Sequence[McpToolMetadata]:
        if server.transport_type == TransportType.STREAMABLE_HTTP:
            raise McpToolListError(
                "transport_not_supported_yet",
                "Streamable HTTP MCP transport is not supported yet",
            )
        parameters = _stdio_parameters(server)
        try:
            async with (
                stdio_client(parameters) as (read_stream, write_stream),
                ClientSession(read_stream, write_stream) as session,
            ):
                await asyncio.wait_for(session.initialize(), timeout=timeout_seconds)
                result = await asyncio.wait_for(
                    session.list_tools(),
                    timeout=timeout_seconds,
                )
        except TimeoutError as error:
            raise McpToolListError("mcp_timeout", "MCP tool discovery timed out") from error
        except (McpError, OSError, RuntimeError, ValueError) as error:
            raise McpToolListError("mcp_tool_list_failed", "MCP tool discovery failed") from error

        return [
            McpToolMetadata(
                name=tool.name,
                description=tool.description,
                input_schema=dict(tool.inputSchema),
            )
            for tool in result.tools
        ]

    async def call_tool(
        self,
        *,
        server: Any,
        tool: Any,
        arguments: Mapping[str, Any],
        timeout_seconds: float,
    ) -> Mapping[str, Any]:
        if server.transport_type == TransportType.STREAMABLE_HTTP:
            raise McpUpstreamError(
                "transport_not_supported_yet",
                "Streamable HTTP MCP transport is not supported yet",
            )
        parameters = _stdio_parameters(server)
        try:
            async with (
                stdio_client(parameters) as (read_stream, write_stream),
                ClientSession(read_stream, write_stream) as session,
            ):
                await asyncio.wait_for(session.initialize(), timeout=timeout_seconds)
                result = await asyncio.wait_for(
                    session.call_tool(
                        tool.tool_name,
                        dict(arguments),
                        read_timeout_seconds=timedelta(seconds=timeout_seconds),
                    ),
                    timeout=timeout_seconds,
                )
        except TimeoutError as error:
            raise McpUpstreamTimeoutError("mcp_timeout", "MCP tool call timed out") from error
        except (McpError, OSError, RuntimeError, ValueError) as error:
            raise McpUpstreamError("mcp_tool_call_failed", "MCP tool call failed") from error

        ensure_mcp_call_result_ok(result)
        return mcp_result_to_json_safe(result)


def create_mcp_client() -> McpClient:
    return StdioMcpClient()


def _stdio_parameters(server: Any) -> StdioServerParameters:
    command = getattr(server, "command", None)
    if not isinstance(command, str) or command == "":
        raise McpUpstreamError("mcp_connection_failed", "MCP stdio server command is required")
    raw_args = getattr(server, "args", None)
    args = _string_list(raw_args)
    raw_env = getattr(server, "env", None)
    env = _string_map(raw_env) if raw_env is not None else None
    return StdioServerParameters(command=command, args=args, env=env)


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    raise McpUpstreamError("mcp_connection_failed", "MCP stdio server args must be a list")


def _string_map(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(key): str(item) for key, item in value.items()}
    raise McpUpstreamError("mcp_connection_failed", "MCP stdio server env must be an object")


def mcp_result_to_json_safe(result: Any) -> dict[str, Any]:
    structured = getattr(result, "structuredContent", None)
    if structured is None:
        structured = getattr(result, "structured_content", None)
    if structured is not None:
        return {"structured": _json_safe(structured)}

    content = getattr(result, "content", None)
    if isinstance(content, list):
        converted = [_content_item_to_json_safe(item) for item in content]
        if converted:
            return {"content": converted}
    return {"content": []}


def ensure_mcp_call_result_ok(result: Any) -> None:
    if getattr(result, "isError", False):
        raise McpUpstreamError("mcp_tool_call_failed", "MCP tool returned an error")


def _content_item_to_json_safe(item: Any) -> dict[str, Any]:
    item_type = getattr(item, "type", None)
    if item_type == "text":
        return {"type": "text", "text": str(getattr(item, "text", ""))}
    if isinstance(item_type, str) and item_type != "":
        return {"type": item_type}
    return {"type": "unknown"}


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)
