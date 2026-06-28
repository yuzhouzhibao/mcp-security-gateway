from datetime import timedelta
from typing import Any, cast
from uuid import UUID

from mcp_security_gateway.domain.enums import ApprovalStatus
from mcp_security_gateway.infrastructure.db.models import ApprovalRequestModel, utc_now


class ApprovalService:
    def __init__(
        self,
        approval_repository: Any,
        request_ttl_seconds: int,
    ) -> None:
        self._approval_repository = approval_repository
        self._request_ttl_seconds = request_ttl_seconds

    def create_pending_approval(
        self,
        *,
        tenant_id: UUID,
        agent_id: UUID,
        tool_call_id: UUID,
        target_server: str,
        target_tool: str,
        arguments_redacted: dict[str, Any],
        arguments_hash: str,
        requested_reason: str,
    ) -> ApprovalRequestModel:
        return cast(
            ApprovalRequestModel,
            self._approval_repository.create(
                ApprovalRequestModel(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    tool_call_id=tool_call_id,
                    target_server=target_server,
                    target_tool=target_tool,
                    arguments_redacted=arguments_redacted,
                    arguments_hash=arguments_hash,
                    status=ApprovalStatus.PENDING,
                    requested_reason=requested_reason,
                    reviewer_id=None,
                    review_reason=None,
                    expires_at=utc_now() + timedelta(seconds=self._request_ttl_seconds),
                    approved_at=None,
                    denied_at=None,
                    executed_at=None,
                )
            ),
        )
