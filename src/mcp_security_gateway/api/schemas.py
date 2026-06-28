from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from mcp_security_gateway.domain.enums import AgentRole, EntityStatus, PolicyEffect, ToolCallStatus


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


class ToolCallRequestBody(BaseModel):
    target_server: str
    target_tool: str
    arguments: dict[str, Any]
    trace_id: str | None = None
    idempotency_key: str | None = None


class ToolCallErrorBody(BaseModel):
    code: str
    message: str


class ToolCallResponse(BaseModel):
    tool_call_id: UUID
    status: ToolCallStatus
    policy_decision: PolicyEffect | None
    reason: str | None = None
    approval_id: UUID | None = None
    result: dict[str, Any] | None = None
    error: ToolCallErrorBody | None = None

    model_config = ConfigDict(from_attributes=True)
