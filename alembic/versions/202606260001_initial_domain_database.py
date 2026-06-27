from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "202606260001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", name="uq_tenants_name"),
    )
    op.create_index("ix_tenants_status", "tenants", ["status"])

    op.create_table(
        "agents",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("api_key_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("api_key_hash", name="uq_agents_api_key_hash"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_agents_tenant_id_name"),
    )
    op.create_index("ix_agents_role", "agents", ["role"])
    op.create_index("ix_agents_status", "agents", ["status"])
    op.create_index("ix_agents_tenant_id", "agents", ["tenant_id"])

    op.create_table(
        "tool_servers",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("server_id", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("transport_type", sa.String(length=32), nullable=False),
        sa.Column("endpoint_url", sa.Text(), nullable=True),
        sa.Column("command", sa.Text(), nullable=True),
        sa.Column("args", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("env", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "server_id", name="uq_tool_servers_tenant_id_server_id"),
    )
    op.create_index("ix_tool_servers_status", "tool_servers", ["status"])
    op.create_index("ix_tool_servers_tenant_id", "tool_servers", ["tenant_id"])
    op.create_index("ix_tool_servers_transport_type", "tool_servers", ["transport_type"])

    op.create_table(
        "policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("effect", sa.String(length=32), nullable=False),
        sa.Column("conditions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_policies_tenant_id_name"),
    )
    op.create_index("ix_policies_effect", "policies", ["effect"])
    op.create_index("ix_policies_priority", "policies", ["priority"])
    op.create_index("ix_policies_status", "policies", ["status"])
    op.create_index("ix_policies_tenant_id", "policies", ["tenant_id"])

    op.create_table(
        "tool_definitions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("server_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tool_name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("input_schema", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("risk_level", sa.String(length=32), nullable=False),
        sa.Column("action_type", sa.String(length=32), nullable=False),
        sa.Column("resource_patterns", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("schema_hash", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["server_id"], ["tool_servers.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "server_id",
            "tool_name",
            name="uq_tool_definitions_tenant_server_tool",
        ),
    )
    op.create_index("ix_tool_definitions_action_type", "tool_definitions", ["action_type"])
    op.create_index("ix_tool_definitions_risk_level", "tool_definitions", ["risk_level"])
    op.create_index("ix_tool_definitions_schema_hash", "tool_definitions", ["schema_hash"])
    op.create_index("ix_tool_definitions_server_id", "tool_definitions", ["server_id"])
    op.create_index("ix_tool_definitions_status", "tool_definitions", ["status"])
    op.create_index("ix_tool_definitions_tenant_id", "tool_definitions", ["tenant_id"])

    op.create_table(
        "tool_calls",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("trace_id", sa.String(length=255), nullable=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_server", sa.String(length=255), nullable=False),
        sa.Column("target_tool", sa.String(length=255), nullable=False),
        sa.Column("arguments_redacted", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("arguments_hash", sa.String(length=128), nullable=False),
        sa.Column("tool_schema_hash", sa.String(length=128), nullable=True),
        sa.Column("policy_decision", sa.String(length=64), nullable=True),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("approval_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("idempotency_key", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_tool_calls_agent_id", "tool_calls", ["agent_id"])
    op.create_index("ix_tool_calls_created_at", "tool_calls", ["created_at"])
    op.create_index("ix_tool_calls_status", "tool_calls", ["status"])
    op.create_index("ix_tool_calls_target_tool", "tool_calls", ["target_tool"])
    op.create_index("ix_tool_calls_tenant_id", "tool_calls", ["tenant_id"])
    op.create_index("ix_tool_calls_trace_id", "tool_calls", ["trace_id"])
    op.create_index(
        "uq_tool_calls_tenant_agent_idempotency_key",
        "tool_calls",
        ["tenant_id", "agent_id", "idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )

    op.create_table(
        "approval_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tool_call_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_server", sa.String(length=255), nullable=False),
        sa.Column("target_tool", sa.String(length=255), nullable=False),
        sa.Column("arguments_redacted", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("arguments_hash", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("requested_reason", sa.Text(), nullable=True),
        sa.Column("reviewer_id", sa.String(length=255), nullable=True),
        sa.Column("review_reason", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("denied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tool_call_id"], ["tool_calls.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tool_call_id", name="uq_approval_requests_tool_call_id"),
    )
    op.create_index("ix_approval_requests_agent_id", "approval_requests", ["agent_id"])
    op.create_index("ix_approval_requests_expires_at", "approval_requests", ["expires_at"])
    op.create_index("ix_approval_requests_status", "approval_requests", ["status"])
    op.create_index("ix_approval_requests_tenant_id", "approval_requests", ["tenant_id"])

    op.create_table(
        "audit_events",
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("trace_id", sa.String(length=255), nullable=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.String(length=255), nullable=False),
        sa.Column("target_server", sa.String(length=255), nullable=True),
        sa.Column("target_tool", sa.String(length=255), nullable=True),
        sa.Column("arguments_redacted", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("arguments_hash", sa.String(length=128), nullable=True),
        sa.Column("policy_decision", sa.String(length=64), nullable=True),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("approval_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("event_id"),
    )
    op.create_index("ix_audit_events_agent_id", "audit_events", ["agent_id"])
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])
    op.create_index("ix_audit_events_event_type", "audit_events", ["event_type"])
    op.create_index("ix_audit_events_status", "audit_events", ["status"])
    op.create_index("ix_audit_events_target_tool", "audit_events", ["target_tool"])
    op.create_index("ix_audit_events_tenant_id", "audit_events", ["tenant_id"])
    op.create_index("ix_audit_events_trace_id", "audit_events", ["trace_id"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_trace_id", table_name="audit_events")
    op.drop_index("ix_audit_events_tenant_id", table_name="audit_events")
    op.drop_index("ix_audit_events_target_tool", table_name="audit_events")
    op.drop_index("ix_audit_events_status", table_name="audit_events")
    op.drop_index("ix_audit_events_event_type", table_name="audit_events")
    op.drop_index("ix_audit_events_created_at", table_name="audit_events")
    op.drop_index("ix_audit_events_agent_id", table_name="audit_events")
    op.drop_table("audit_events")

    op.drop_index("ix_approval_requests_tenant_id", table_name="approval_requests")
    op.drop_index("ix_approval_requests_status", table_name="approval_requests")
    op.drop_index("ix_approval_requests_expires_at", table_name="approval_requests")
    op.drop_index("ix_approval_requests_agent_id", table_name="approval_requests")
    op.drop_table("approval_requests")

    op.drop_index("uq_tool_calls_tenant_agent_idempotency_key", table_name="tool_calls")
    op.drop_index("ix_tool_calls_trace_id", table_name="tool_calls")
    op.drop_index("ix_tool_calls_tenant_id", table_name="tool_calls")
    op.drop_index("ix_tool_calls_target_tool", table_name="tool_calls")
    op.drop_index("ix_tool_calls_status", table_name="tool_calls")
    op.drop_index("ix_tool_calls_created_at", table_name="tool_calls")
    op.drop_index("ix_tool_calls_agent_id", table_name="tool_calls")
    op.drop_table("tool_calls")

    op.drop_index("ix_tool_definitions_tenant_id", table_name="tool_definitions")
    op.drop_index("ix_tool_definitions_status", table_name="tool_definitions")
    op.drop_index("ix_tool_definitions_server_id", table_name="tool_definitions")
    op.drop_index("ix_tool_definitions_schema_hash", table_name="tool_definitions")
    op.drop_index("ix_tool_definitions_risk_level", table_name="tool_definitions")
    op.drop_index("ix_tool_definitions_action_type", table_name="tool_definitions")
    op.drop_table("tool_definitions")

    op.drop_index("ix_policies_tenant_id", table_name="policies")
    op.drop_index("ix_policies_status", table_name="policies")
    op.drop_index("ix_policies_priority", table_name="policies")
    op.drop_index("ix_policies_effect", table_name="policies")
    op.drop_table("policies")

    op.drop_index("ix_tool_servers_transport_type", table_name="tool_servers")
    op.drop_index("ix_tool_servers_tenant_id", table_name="tool_servers")
    op.drop_index("ix_tool_servers_status", table_name="tool_servers")
    op.drop_table("tool_servers")

    op.drop_index("ix_agents_tenant_id", table_name="agents")
    op.drop_index("ix_agents_status", table_name="agents")
    op.drop_index("ix_agents_role", table_name="agents")
    op.drop_table("agents")

    op.drop_index("ix_tenants_status", table_name="tenants")
    op.drop_table("tenants")
