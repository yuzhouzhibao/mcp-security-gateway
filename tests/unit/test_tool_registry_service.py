from uuid import UUID

import pytest

from mcp_security_gateway.application.ports.mcp_client import McpToolMetadata
from mcp_security_gateway.application.services.errors import McpToolListFailedError
from mcp_security_gateway.application.services.tool_registry_service import (
    ToolRegistryService,
    ToolServerCreate,
)
from mcp_security_gateway.domain.enums import ActionType, EntityStatus, RiskLevel, TransportType
from mcp_security_gateway.infrastructure.db.models import (
    TenantModel,
    ToolDefinitionModel,
    ToolServerModel,
)
from tests.fakes.mcp_client import TestOnlyMcpClient

TENANT_ID = UUID("00000000-0000-4000-8000-000000000701")


class TenantRepo:
    def get_by_id(self, tenant_id: UUID) -> TenantModel | None:
        if tenant_id == TENANT_ID:
            return TenantModel(id=TENANT_ID, name="tenant", status=EntityStatus.ACTIVE)
        return None


class ToolServerRepo:
    def __init__(self) -> None:
        self.servers: list[ToolServerModel] = []

    def create(self, server: ToolServerModel) -> ToolServerModel:
        self.servers.append(server)
        return server

    def get_by_server_id(self, tenant_id: UUID, server_id: str) -> ToolServerModel | None:
        for server in self.servers:
            if server.tenant_id == tenant_id and server.server_id == server_id:
                return server
        return None

    def list_by_tenant(self, tenant_id: UUID) -> list[ToolServerModel]:
        return [server for server in self.servers if server.tenant_id == tenant_id]


class ToolDefinitionRepo:
    def __init__(self) -> None:
        self.definitions: list[ToolDefinitionModel] = []

    def create(self, definition: ToolDefinitionModel) -> ToolDefinitionModel:
        self.definitions.append(definition)
        return definition

    def get_by_name(
        self,
        tenant_id: UUID,
        server_id: UUID,
        tool_name: str,
    ) -> ToolDefinitionModel | None:
        for definition in self.definitions:
            if (
                definition.tenant_id == tenant_id
                and definition.server_id == server_id
                and definition.tool_name == tool_name
            ):
                return definition
        return None

    def list_by_server(self, tenant_id: UUID, server_id: UUID) -> list[ToolDefinitionModel]:
        return [
            definition
            for definition in self.definitions
            if definition.tenant_id == tenant_id and definition.server_id == server_id
        ]

    def get_by_id(self, definition_id: UUID) -> ToolDefinitionModel | None:
        for definition in self.definitions:
            if definition.id == definition_id:
                return definition
        return None

    def update(self, definition: ToolDefinitionModel) -> ToolDefinitionModel:
        return definition


def service(
    client: TestOnlyMcpClient,
) -> tuple[ToolRegistryService, ToolServerRepo, ToolDefinitionRepo]:
    server_repo = ToolServerRepo()
    definition_repo = ToolDefinitionRepo()
    return (
        ToolRegistryService(
            tenant_repository=TenantRepo(),
            tool_server_repository=server_repo,
            tool_definition_repository=definition_repo,
            mcp_client=client,
            mcp_call_timeout_seconds=5,
        ),
        server_repo,
        definition_repo,
    )


def tool_server_create() -> ToolServerCreate:
    return ToolServerCreate(
        tenant_id=TENANT_ID,
        server_id="calculator-local",
        name="Calculator",
        transport_type=TransportType.STDIO,
        endpoint_url=None,
        command="python",
        args=["server.py"],
        env={"SECRET": "test-only"},
    )


@pytest.mark.asyncio
async def test_discovery_creates_disabled_critical_privileged_tools() -> None:
    client = TestOnlyMcpClient(
        tools=[
            McpToolMetadata(
                name="add",
                description="Add numbers",
                input_schema={"type": "object"},
            )
        ]
    )
    registry, _, definitions = service(client)
    registry.create_tool_server(tool_server_create())

    refreshed = await registry.refresh_tools(tenant_id=TENANT_ID, server_id="calculator-local")

    assert refreshed[0].tool_name == "add"
    assert refreshed[0].risk_level == RiskLevel.CRITICAL
    assert refreshed[0].action_type == ActionType.PRIVILEGED
    assert refreshed[0].status == EntityStatus.DISABLED
    assert definitions.definitions == refreshed


@pytest.mark.asyncio
async def test_discovery_update_does_not_override_manual_classification() -> None:
    client = TestOnlyMcpClient(
        tools=[
            McpToolMetadata(
                name="add",
                description="Add two numbers",
                input_schema={"type": "object", "properties": {"a": {"type": "integer"}}},
            )
        ]
    )
    registry, _, _ = service(client)
    server = registry.create_tool_server(tool_server_create())
    first = (await registry.refresh_tools(tenant_id=TENANT_ID, server_id="calculator-local"))[0]
    first.risk_level = RiskLevel.LOW
    first.action_type = ActionType.READ
    first.status = EntityStatus.ACTIVE
    client.set_tools(
        [
            McpToolMetadata(
                name="add",
                description="Updated",
                input_schema={"type": "object", "properties": {"b": {"type": "integer"}}},
            )
        ]
    )

    refreshed = await registry.refresh_tools(tenant_id=TENANT_ID, server_id=server.server_id)

    assert refreshed[0].description == "Updated"
    assert refreshed[0].risk_level == RiskLevel.LOW
    assert refreshed[0].action_type == ActionType.READ
    assert refreshed[0].status == EntityStatus.ACTIVE


@pytest.mark.asyncio
async def test_discovery_failure_does_not_return_empty_success_or_upsert() -> None:
    client = TestOnlyMcpClient(failure="failed")
    registry, _, definitions = service(client)
    registry.create_tool_server(tool_server_create())

    with pytest.raises(McpToolListFailedError) as captured:
        await registry.refresh_tools(tenant_id=TENANT_ID, server_id="calculator-local")

    assert captured.value.code == "mcp_tool_list_failed"
    assert definitions.definitions == []
