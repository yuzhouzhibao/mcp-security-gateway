from dataclasses import asdict
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from mcp_security_gateway.api.dependencies import (
    get_agent_service,
    get_db_session,
    get_settings,
    require_admin,
)
from mcp_security_gateway.api.schemas import AgentCreateRequest, AgentCreateResponse, AgentResponse
from mcp_security_gateway.application.services.agent_service import AgentService
from mcp_security_gateway.settings import Settings

router = APIRouter(prefix="/v1/admin/agents", dependencies=[Depends(require_admin)])
SessionDep = Annotated[Session, Depends(get_db_session)]


def build_service(request: Request, session: Session) -> AgentService:
    settings: Settings = get_settings(request)
    return get_agent_service(session, settings)


@router.post("", response_model=AgentCreateResponse, status_code=201)
async def create_agent(
    payload: AgentCreateRequest,
    request: Request,
    session: SessionDep,
) -> AgentCreateResponse:
    service = build_service(request, session)
    created = service.create_agent(payload.tenant_id, payload.name, payload.role)
    session.commit()
    return AgentCreateResponse(**asdict(created.agent), api_key=created.api_key)


@router.get("", response_model=list[AgentResponse])
async def list_agents(
    tenant_id: UUID,
    request: Request,
    session: SessionDep,
) -> list[AgentResponse]:
    service = build_service(request, session)
    agents = service.list_agents(tenant_id)
    return [AgentResponse.model_validate(agent) for agent in agents]


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: UUID,
    request: Request,
    session: SessionDep,
) -> AgentResponse:
    service = build_service(request, session)
    return AgentResponse.model_validate(service.get_agent(agent_id))


@router.post("/{agent_id}/disable", response_model=AgentResponse)
async def disable_agent(
    agent_id: UUID,
    request: Request,
    session: SessionDep,
) -> AgentResponse:
    service = build_service(request, session)
    agent = service.disable_agent(agent_id)
    session.commit()
    return AgentResponse.model_validate(agent)
