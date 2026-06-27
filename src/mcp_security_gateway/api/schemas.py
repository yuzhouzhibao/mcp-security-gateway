from uuid import UUID

from pydantic import BaseModel, ConfigDict

from mcp_security_gateway.domain.enums import AgentRole, EntityStatus


class AgentCreateRequest(BaseModel):
    tenant_id: UUID
    name: str
    role: AgentRole


class AgentResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    name: str
    role: AgentRole
    status: EntityStatus

    model_config = ConfigDict(from_attributes=True)


class AgentCreateResponse(AgentResponse):
    api_key: str
