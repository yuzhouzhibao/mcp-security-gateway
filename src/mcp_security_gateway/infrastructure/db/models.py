from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID
from sqlalchemy.orm import Mapped, mapped_column

from mcp_security_gateway.domain.enums import (
    ActionType,
    ApprovalStatus,
    EntityStatus,
    PolicyEffect,
    RiskLevel,
    ToolCallStatus,
    TransportType,
)
from mcp_security_gateway.infrastructure.db.base import Base


def utc_now() -> datetime:
    return datetime.now(UTC)


class TenantModel(Base):
    __tablename__ = "tenants"
    __table_args__ = (
        UniqueConstraint("name", name="uq_tenants_name"),
        Index("ix_tenants_status", "status"),
    )

    id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[EntityStatus] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


class AgentModel(Base):
    __tablename__ = "agents"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_agents_tenant_id_name"),
        UniqueConstraint("api_key_hash", name="uq_agents_api_key_hash"),
        Index("ix_agents_tenant_id", "tenant_id"),
        Index("ix_agents_status", "status"),
        Index("ix_agents_role", "role"),
    )

    id: Mapped[UUID] = mapped_column(PostgresUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[EntityStatus] = mapped_column(String(32), nullable=False)
    api_key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


class ToolServerModel(Base):
    __tablename__ = "tool_servers"
    __table_args__ = (
        UniqueConstraint("tenant_id", "server_id", name="uq_tool_servers_tenant_id_server_id"),
        Index("ix_tool_servers_tenant_id", "tenant_id"),
        Index("ix_tool_servers_transport_type", "transport_type"),
        Index("ix_tool_servers_status", "status"),
    )

    id: Mapped[UUID] = mapped_column(PostgresUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    server_id: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    transport_type: Mapped[TransportType] = mapped_column(String(32), nullable=False)
    endpoint_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    command: Mapped[str | None] = mapped_column(Text, nullable=True)
    args: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    env: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    status: Mapped[EntityStatus] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


class ToolDefinitionModel(Base):
    __tablename__ = "tool_definitions"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "server_id",
            "tool_name",
            name="uq_tool_definitions_tenant_server_tool",
        ),
        Index("ix_tool_definitions_tenant_id", "tenant_id"),
        Index("ix_tool_definitions_server_id", "server_id"),
        Index("ix_tool_definitions_risk_level", "risk_level"),
        Index("ix_tool_definitions_action_type", "action_type"),
        Index("ix_tool_definitions_status", "status"),
        Index("ix_tool_definitions_schema_hash", "schema_hash"),
    )

    id: Mapped[UUID] = mapped_column(PostgresUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    server_id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("tool_servers.id", ondelete="CASCADE"),
        nullable=False,
    )
    tool_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    input_schema: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    risk_level: Mapped[RiskLevel] = mapped_column(String(32), nullable=False)
    action_type: Mapped[ActionType] = mapped_column(String(32), nullable=False)
    resource_patterns: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    status: Mapped[EntityStatus] = mapped_column(String(32), nullable=False)
    schema_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


class PolicyModel(Base):
    __tablename__ = "policies"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_policies_tenant_id_name"),
        Index("ix_policies_tenant_id", "tenant_id"),
        Index("ix_policies_priority", "priority"),
        Index("ix_policies_effect", "effect"),
        Index("ix_policies_status", "status"),
    )

    id: Mapped[UUID] = mapped_column(PostgresUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False)
    effect: Mapped[PolicyEffect] = mapped_column(String(32), nullable=False)
    conditions: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[EntityStatus] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


class ToolCallModel(Base):
    __tablename__ = "tool_calls"
    __table_args__ = (
        Index("ix_tool_calls_trace_id", "trace_id"),
        Index("ix_tool_calls_tenant_id", "tenant_id"),
        Index("ix_tool_calls_agent_id", "agent_id"),
        Index("ix_tool_calls_target_tool", "target_tool"),
        Index("ix_tool_calls_status", "status"),
        Index("ix_tool_calls_created_at", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    trace_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tenant_id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    agent_id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_server: Mapped[str] = mapped_column(String(255), nullable=False)
    target_tool: Mapped[str] = mapped_column(String(255), nullable=False)
    arguments_redacted: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    arguments_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    tool_schema_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    policy_decision: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    approval_id: Mapped[UUID | None] = mapped_column(PostgresUUID(as_uuid=True), nullable=True)
    status: Mapped[ToolCallStatus] = mapped_column(String(32), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


Index(
    "uq_tool_calls_tenant_agent_idempotency_key",
    ToolCallModel.tenant_id,
    ToolCallModel.agent_id,
    ToolCallModel.idempotency_key,
    unique=True,
    postgresql_where=ToolCallModel.idempotency_key.is_not(None),
)


class ApprovalRequestModel(Base):
    __tablename__ = "approval_requests"
    __table_args__ = (
        UniqueConstraint("tool_call_id", name="uq_approval_requests_tool_call_id"),
        Index("ix_approval_requests_tenant_id", "tenant_id"),
        Index("ix_approval_requests_agent_id", "agent_id"),
        Index("ix_approval_requests_status", "status"),
        Index("ix_approval_requests_expires_at", "expires_at"),
    )

    id: Mapped[UUID] = mapped_column(PostgresUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    agent_id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
    )
    tool_call_id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("tool_calls.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_server: Mapped[str] = mapped_column(String(255), nullable=False)
    target_tool: Mapped[str] = mapped_column(String(255), nullable=False)
    arguments_redacted: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    arguments_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[ApprovalStatus] = mapped_column(String(32), nullable=False)
    requested_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewer_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    review_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    denied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class AuditEventModel(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_tenant_id", "tenant_id"),
        Index("ix_audit_events_agent_id", "agent_id"),
        Index("ix_audit_events_trace_id", "trace_id"),
        Index("ix_audit_events_event_type", "event_type"),
        Index("ix_audit_events_target_tool", "target_tool"),
        Index("ix_audit_events_status", "status"),
        Index("ix_audit_events_created_at", "created_at"),
    )

    event_id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    trace_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tenant_id: Mapped[UUID] = mapped_column(PostgresUUID(as_uuid=True), nullable=False)
    agent_id: Mapped[UUID | None] = mapped_column(PostgresUUID(as_uuid=True), nullable=True)
    event_type: Mapped[str] = mapped_column(String(255), nullable=False)
    target_server: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_tool: Mapped[str | None] = mapped_column(String(255), nullable=True)
    arguments_redacted: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    arguments_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    policy_decision: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    approval_id: Mapped[UUID | None] = mapped_column(PostgresUUID(as_uuid=True), nullable=True)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
