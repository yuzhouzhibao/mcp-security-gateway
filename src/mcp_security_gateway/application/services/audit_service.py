from typing import Any, cast
from uuid import UUID

from mcp_security_gateway.infrastructure.db.models import AuditEventModel


class AuditService:
    def __init__(self, audit_repository: Any) -> None:
        self._audit_repository = audit_repository

    def append_tool_call_event(
        self,
        *,
        trace_id: str | None,
        tenant_id: UUID,
        agent_id: UUID | None,
        target_server: str | None,
        target_tool: str | None,
        arguments_redacted: dict[str, Any] | None,
        arguments_hash: str | None,
        policy_decision: str | None,
        decision_reason: str | None,
        approval_id: UUID | None,
        status: str,
        error_code: str | None,
        error_message: str | None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEventModel:
        return cast(
            AuditEventModel,
            self._audit_repository.append(
                AuditEventModel(
                    trace_id=trace_id,
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    event_type="tool_call",
                    target_server=target_server,
                    target_tool=target_tool,
                    arguments_redacted=arguments_redacted,
                    arguments_hash=arguments_hash,
                    policy_decision=policy_decision,
                    decision_reason=decision_reason,
                    approval_id=approval_id,
                    status=status,
                    error_code=error_code,
                    error_message=error_message,
                    metadata_json=metadata,
                )
            ),
        )
