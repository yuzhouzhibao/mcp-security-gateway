from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from mcp_security_gateway.api.dependencies import get_db_session, get_settings, require_admin
from mcp_security_gateway.api.schemas import (
    ToolDefinitionListResponse,
    ToolDefinitionResponse,
    ToolDefinitionUpdateRequest,
    ToolServerCreateRequest,
    ToolServerListResponse,
    ToolServerRefreshRequest,
    ToolServerResponse,
)
from mcp_security_gateway.application.ports.mcp_client import McpClient
from mcp_security_gateway.application.services.tool_registry_service import (
    ToolDefinitionUpdate,
    ToolRegistryService,
    ToolServerCreate,
)
from mcp_security_gateway.infrastructure.db.repositories import (
    SQLAlchemyTenantRepository,
    SQLAlchemyToolDefinitionRepository,
    SQLAlchemyToolServerRepository,
)
from mcp_security_gateway.settings import Settings

router = APIRouter(prefix="/v1/admin", dependencies=[Depends(require_admin)])
SessionDep = Annotated[Session, Depends(get_db_session)]


def build_service(
    request: Request,
    session: Session,
) -> ToolRegistryService:
    settings: Settings = get_settings(request)
    mcp_client = getattr(request.app.state, "mcp_client", None)
    return ToolRegistryService(
        tenant_repository=SQLAlchemyTenantRepository(session),
        tool_server_repository=SQLAlchemyToolServerRepository(session),
        tool_definition_repository=SQLAlchemyToolDefinitionRepository(session),
        mcp_client=cast(McpClient | None, mcp_client),
        mcp_call_timeout_seconds=settings.mcp_call_timeout_seconds,
    )


@router.post("/tool-servers", response_model=ToolServerResponse, status_code=201)
async def create_tool_server(
    payload: ToolServerCreateRequest,
    request: Request,
    session: SessionDep,
) -> ToolServerResponse:
    service = build_service(request, session)
    server = service.create_tool_server(
        ToolServerCreate(
            tenant_id=payload.tenant_id,
            server_id=payload.server_id,
            name=payload.name,
            transport_type=payload.transport_type,
            endpoint_url=payload.endpoint_url,
            command=payload.command,
            args=payload.args,
            env=payload.env,
        )
    )
    session.commit()
    return ToolServerResponse.model_validate(server)


@router.get("/tool-servers", response_model=ToolServerListResponse)
async def list_tool_servers(
    tenant_id: UUID,
    request: Request,
    session: SessionDep,
) -> ToolServerListResponse:
    service = build_service(request, session)
    return ToolServerListResponse(
        items=[
            ToolServerResponse.model_validate(server)
            for server in service.list_tool_servers(tenant_id)
        ]
    )


@router.post(
    "/tool-servers/{server_id}/refresh-tools",
    response_model=ToolDefinitionListResponse,
)
async def refresh_tools(
    server_id: str,
    payload: ToolServerRefreshRequest,
    request: Request,
    session: SessionDep,
) -> ToolDefinitionListResponse:
    service = build_service(request, session)
    definitions = await service.refresh_tools(tenant_id=payload.tenant_id, server_id=server_id)
    session.commit()
    return ToolDefinitionListResponse(
        items=[ToolDefinitionResponse.model_validate(definition) for definition in definitions]
    )


@router.get("/tool-definitions", response_model=ToolDefinitionListResponse)
async def list_tool_definitions(
    tenant_id: UUID,
    server_id: str,
    request: Request,
    session: SessionDep,
) -> ToolDefinitionListResponse:
    service = build_service(request, session)
    definitions = service.list_tool_definitions(tenant_id=tenant_id, server_id=server_id)
    return ToolDefinitionListResponse(
        items=[ToolDefinitionResponse.model_validate(definition) for definition in definitions]
    )


@router.patch("/tool-definitions/{tool_definition_id}", response_model=ToolDefinitionResponse)
async def update_tool_definition(
    tool_definition_id: UUID,
    payload: ToolDefinitionUpdateRequest,
    request: Request,
    session: SessionDep,
) -> ToolDefinitionResponse:
    service = build_service(request, session)
    definition = service.update_tool_definition(
        tool_definition_id=tool_definition_id,
        request=ToolDefinitionUpdate(
            risk_level=payload.risk_level,
            action_type=payload.action_type,
            status=payload.status,
            description=payload.description,
        ),
    )
    session.commit()
    return ToolDefinitionResponse.model_validate(definition)
