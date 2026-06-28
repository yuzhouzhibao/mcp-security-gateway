import hashlib
import json
from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID

from sqlalchemy.exc import IntegrityError

from mcp_security_gateway.application.ports.mcp_client import (
    McpClient,
    McpToolListError,
)
from mcp_security_gateway.application.services.errors import (
    McpClientNotConfiguredError,
    McpToolListFailedError,
    TenantNotFoundError,
    ToolNotFoundError,
    ToolServerConfigurationError,
    ToolServerConflictError,
    ToolServerNotFoundError,
)
from mcp_security_gateway.domain.enums import ActionType, EntityStatus, RiskLevel, TransportType
from mcp_security_gateway.infrastructure.db.models import ToolDefinitionModel, ToolServerModel


@dataclass(frozen=True, slots=True)
class ToolServerCreate:
    tenant_id: UUID
    server_id: str
    name: str
    transport_type: TransportType
    endpoint_url: str | None
    command: str | None
    args: list[str] | None
    env: dict[str, Any] | None


@dataclass(frozen=True, slots=True)
class ToolDefinitionUpdate:
    risk_level: RiskLevel | None = None
    action_type: ActionType | None = None
    status: EntityStatus | None = None
    description: str | None = None


class ToolRegistryService:
    def __init__(
        self,
        *,
        tenant_repository: Any,
        tool_server_repository: Any,
        tool_definition_repository: Any,
        mcp_client: McpClient | None,
        mcp_call_timeout_seconds: float,
    ) -> None:
        self._tenant_repository = tenant_repository
        self._tool_server_repository = tool_server_repository
        self._tool_definition_repository = tool_definition_repository
        self._mcp_client = mcp_client
        self._mcp_call_timeout_seconds = mcp_call_timeout_seconds

    def create_tool_server(self, request: ToolServerCreate) -> ToolServerModel:
        if self._tenant_repository.get_by_id(request.tenant_id) is None:
            raise TenantNotFoundError()
        if request.transport_type == TransportType.STDIO and not request.command:
            raise ToolServerConfigurationError("stdio tool servers require command")

        server = ToolServerModel(
            tenant_id=request.tenant_id,
            server_id=request.server_id,
            name=request.name,
            transport_type=request.transport_type,
            endpoint_url=request.endpoint_url,
            command=request.command,
            args=request.args,
            env=request.env,
            status=EntityStatus.ACTIVE,
        )
        try:
            return cast(ToolServerModel, self._tool_server_repository.create(server))
        except IntegrityError as error:
            raise ToolServerConflictError() from error

    def list_tool_servers(self, tenant_id: UUID) -> list[ToolServerModel]:
        return list(self._tool_server_repository.list_by_tenant(tenant_id))

    async def refresh_tools(self, *, tenant_id: UUID, server_id: str) -> list[ToolDefinitionModel]:
        server = self._tool_server_repository.get_by_server_id(tenant_id, server_id)
        if server is None:
            raise ToolServerNotFoundError()
        if server.status != EntityStatus.ACTIVE:
            raise ToolServerNotFoundError()
        if self._mcp_client is None:
            raise McpClientNotConfiguredError()

        try:
            discovered_tools = await self._mcp_client.list_tools(
                server=server,
                timeout_seconds=self._mcp_call_timeout_seconds,
            )
        except McpToolListError as error:
            raise McpToolListFailedError(error.code) from error

        definitions: list[ToolDefinitionModel] = []
        for discovered in discovered_tools:
            existing = self._tool_definition_repository.get_by_name(
                tenant_id,
                server.id,
                discovered.name,
            )
            schema_hash = schema_hash_for(discovered.input_schema)
            if existing is None:
                definition = ToolDefinitionModel(
                    tenant_id=tenant_id,
                    server_id=server.id,
                    tool_name=discovered.name,
                    description=discovered.description,
                    input_schema=discovered.input_schema,
                    risk_level=RiskLevel.CRITICAL,
                    action_type=ActionType.PRIVILEGED,
                    resource_patterns=None,
                    status=EntityStatus.DISABLED,
                    schema_hash=schema_hash,
                )
                definitions.append(self._tool_definition_repository.create(definition))
            else:
                existing.description = discovered.description
                existing.input_schema = discovered.input_schema
                existing.schema_hash = schema_hash
                definitions.append(self._tool_definition_repository.update(existing))
        return definitions

    def list_tool_definitions(
        self,
        *,
        tenant_id: UUID,
        server_id: str,
    ) -> list[ToolDefinitionModel]:
        server = self._tool_server_repository.get_by_server_id(tenant_id, server_id)
        if server is None:
            raise ToolServerNotFoundError()
        return list(self._tool_definition_repository.list_by_server(tenant_id, server.id))

    def update_tool_definition(
        self,
        *,
        tool_definition_id: UUID,
        request: ToolDefinitionUpdate,
    ) -> ToolDefinitionModel:
        definition = self._tool_definition_repository.get_by_id(tool_definition_id)
        if definition is None:
            raise ToolNotFoundError()
        if request.risk_level is not None:
            definition.risk_level = request.risk_level
        if request.action_type is not None:
            definition.action_type = request.action_type
        if request.status is not None:
            definition.status = request.status
        if request.description is not None:
            definition.description = request.description
        return cast(ToolDefinitionModel, self._tool_definition_repository.update(definition))


def schema_hash_for(schema: dict[str, Any]) -> str:
    encoded = json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
