from types import SimpleNamespace

import pytest

from mcp_security_gateway.application.ports.mcp_client import McpUpstreamError
from mcp_security_gateway.domain.enums import TransportType
from mcp_security_gateway.infrastructure.mcp.stdio_client import (
    _stdio_parameters,
    ensure_mcp_call_result_ok,
    mcp_result_to_json_safe,
)


def test_stdio_adapter_requires_command() -> None:
    server = SimpleNamespace(transport_type=TransportType.STDIO, command=None, args=None, env=None)

    with pytest.raises(McpUpstreamError) as captured:
        _stdio_parameters(server)

    assert captured.value.code == "mcp_connection_failed"


@pytest.mark.asyncio
async def test_streamable_http_returns_transport_not_supported_yet() -> None:
    from mcp_security_gateway.infrastructure.mcp.stdio_client import StdioMcpClient

    server = SimpleNamespace(transport_type=TransportType.STREAMABLE_HTTP)
    client = StdioMcpClient()

    with pytest.raises(McpUpstreamError) as captured:
        await client.call_tool(
            server=server,
            tool=SimpleNamespace(tool_name="add"),
            arguments={},
            timeout_seconds=1,
        )

    assert captured.value.code == "transport_not_supported_yet"


@pytest.mark.asyncio
async def test_streamable_http_discovery_returns_transport_not_supported_yet() -> None:
    from mcp_security_gateway.application.ports.mcp_client import McpToolListError
    from mcp_security_gateway.infrastructure.mcp.stdio_client import StdioMcpClient

    server = SimpleNamespace(transport_type=TransportType.STREAMABLE_HTTP)
    client = StdioMcpClient()

    with pytest.raises(McpToolListError) as captured:
        await client.list_tools(server=server, timeout_seconds=1)

    assert captured.value.code == "transport_not_supported_yet"


def test_mcp_call_result_is_error_raises_failed_call_error() -> None:
    result = SimpleNamespace(isError=True, content=[SimpleNamespace(type="text", text="bad")])

    with pytest.raises(McpUpstreamError) as captured:
        ensure_mcp_call_result_ok(result)

    assert captured.value.code == "mcp_tool_call_failed"


def test_mcp_result_conversion_structured_content() -> None:
    result = SimpleNamespace(structuredContent={"answer": 5}, content=[])

    assert mcp_result_to_json_safe(result) == {"structured": {"answer": 5}}


def test_mcp_result_conversion_text_content() -> None:
    result = SimpleNamespace(
        structuredContent=None,
        content=[SimpleNamespace(type="text", text="hello")],
    )

    assert mcp_result_to_json_safe(result) == {"content": [{"type": "text", "text": "hello"}]}


def test_mcp_result_conversion_unknown_content_safe_summary() -> None:
    result = SimpleNamespace(
        structuredContent=None,
        content=[SimpleNamespace(type="image", data=b"not-json")],
    )

    assert mcp_result_to_json_safe(result) == {"content": [{"type": "image"}]}
