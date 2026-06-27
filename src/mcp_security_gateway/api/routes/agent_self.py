from typing import Annotated

from fastapi import APIRouter, Depends

from mcp_security_gateway.api.dependencies import require_agent
from mcp_security_gateway.api.schemas import AgentResponse
from mcp_security_gateway.application.services.agent_service import AgentDTO

router = APIRouter(prefix="/v1/agents")
AgentDep = Annotated[AgentDTO, Depends(require_agent)]


@router.get("/me", response_model=AgentResponse)
async def get_current_agent(
    agent: AgentDep,
) -> AgentResponse:
    return AgentResponse.model_validate(agent)
