from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from mcp_security_gateway.domain.enums import (
    ActionType,
    AgentRole,
    ApprovalStatus,
    EntityStatus,
    PolicyEffect,
    RiskLevel,
    ToolCallStatus,
    TransportType,
)

JsonObject = dict[str, Any]


@dataclass(frozen=True, slots=True)
class Tenant:
    id: UUID
    name: str
    status: EntityStatus
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class Agent:
    id: UUID
    tenant_id: UUID
    name: str
    role: AgentRole
    status: EntityStatus
    api_key_hash: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class ToolServer:
    id: UUID
    tenant_id: UUID
    server_id: str
    name: str
    transport_type: TransportType
    endpoint_url: str | None
    command: str | None
    args: JsonObject | None
    env: JsonObject | None
    status: EntityStatus
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    id: UUID
    tenant_id: UUID
    server_id: UUID
    tool_name: str
    description: str | None
    input_schema: JsonObject
    risk_level: RiskLevel
    action_type: ActionType
    resource_patterns: JsonObject | None
    status: EntityStatus
    schema_hash: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class Policy:
    id: UUID
    tenant_id: UUID
    name: str
    priority: int
    effect: PolicyEffect
    conditions: JsonObject
    reason: str
    status: EntityStatus
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class ToolCall:
    id: UUID
    trace_id: str | None
    tenant_id: UUID
    agent_id: UUID
    target_server: str
    target_tool: str
    arguments_redacted: JsonObject
    arguments_hash: str
    tool_schema_hash: str | None
    policy_decision: str | None
    decision_reason: str | None
    approval_id: UUID | None
    status: ToolCallStatus
    error_code: str | None
    error_message: str | None
    idempotency_key: str | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    id: UUID
    tenant_id: UUID
    agent_id: UUID
    tool_call_id: UUID
    target_server: str
    target_tool: str
    arguments_redacted: JsonObject
    arguments_hash: str
    status: ApprovalStatus
    requested_reason: str | None
    reviewer_id: str | None
    review_reason: str | None
    expires_at: datetime
    approved_at: datetime | None
    denied_at: datetime | None
    executed_at: datetime | None
    created_at: datetime
    updated_at: datetime
    version: int


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_id: UUID
    trace_id: str | None
    tenant_id: UUID
    agent_id: UUID | None
    event_type: str
    target_server: str | None
    target_tool: str | None
    arguments_redacted: JsonObject | None
    arguments_hash: str | None
    policy_decision: str | None
    decision_reason: str | None
    approval_id: UUID | None
    status: str
    error_code: str | None
    error_message: str | None
    metadata_json: JsonObject | None
    created_at: datetime
