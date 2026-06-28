from dataclasses import dataclass
from datetime import timedelta
from typing import Any, cast
from uuid import UUID

from mcp_security_gateway.application.services.audit_service import AuditService
from mcp_security_gateway.application.services.errors import (
    ApprovalAlreadyProcessedError,
    ApprovalDeniedError,
    ApprovalNotFoundError,
    ApprovalNotPendingError,
)
from mcp_security_gateway.domain.enums import ApprovalStatus, ToolCallStatus
from mcp_security_gateway.infrastructure.db.models import (
    ApprovalRequestModel,
    ToolCallModel,
    utc_now,
)


@dataclass(frozen=True, slots=True)
class ApprovalActionError:
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class ApprovalActionResult:
    approval_id: UUID
    tool_call_id: UUID
    status: ApprovalStatus
    tool_call_status: ToolCallStatus
    result: dict[str, Any] | None = None
    error: ApprovalActionError | None = None


class ApprovalService:
    def __init__(
        self,
        approval_repository: Any,
        request_ttl_seconds: int,
        tool_call_repository: Any | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        self._approval_repository = approval_repository
        self._request_ttl_seconds = request_ttl_seconds
        self._tool_call_repository = tool_call_repository
        self._audit_service = audit_service

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

    def list_approvals(
        self,
        *,
        status: ApprovalStatus | None,
        tenant_id: UUID | None,
        limit: int | None,
    ) -> list[ApprovalRequestModel]:
        return list(self._approval_repository.list_filtered(status, tenant_id, limit))

    async def approve_approval(
        self,
        *,
        approval_id: UUID,
        review_reason: str,
        tool_call_service: Any,
    ) -> ApprovalActionResult:
        approval = self._get_approval_or_raise(approval_id)
        if approval.status != ApprovalStatus.PENDING:
            self._raise_for_non_pending(approval)

        if utc_now() > approval.expires_at:
            expired = self._approval_repository.transition_status(
                approval_id,
                ApprovalStatus.PENDING,
                ApprovalStatus.EXPIRED,
            )
            if expired is None:
                raise ApprovalNotPendingError()
            tool_call = self._mark_tool_call_denied(expired.tool_call_id, "approval_expired")
            self._append_approval_audit(expired, tool_call, "expired", "approval_expired")
            return ApprovalActionResult(
                approval_id=expired.id,
                tool_call_id=expired.tool_call_id,
                status=ApprovalStatus.EXPIRED,
                tool_call_status=ToolCallStatus(tool_call.status),
                error=ApprovalActionError("approval_expired", "Approval request has expired"),
            )

        approved = self._approval_repository.transition_status(
            approval_id,
            ApprovalStatus.PENDING,
            ApprovalStatus.APPROVED,
            review_reason=review_reason,
        )
        if approved is None:
            raise ApprovalNotPendingError()

        self._append_approval_audit(approved, None, "approved", None)
        return cast(
            ApprovalActionResult,
            await tool_call_service.execute_approved_tool_call(approved),
        )

    def deny_approval(
        self,
        *,
        approval_id: UUID,
        review_reason: str,
    ) -> ApprovalActionResult:
        approval = self._get_approval_or_raise(approval_id)
        if approval.status != ApprovalStatus.PENDING:
            self._raise_for_non_pending(approval)

        if utc_now() > approval.expires_at:
            expired = self._approval_repository.transition_status(
                approval_id,
                ApprovalStatus.PENDING,
                ApprovalStatus.EXPIRED,
            )
            if expired is None:
                raise ApprovalNotPendingError()
            tool_call = self._mark_tool_call_denied(expired.tool_call_id, "approval_expired")
            self._append_approval_audit(expired, tool_call, "expired", "approval_expired")
            return ApprovalActionResult(
                approval_id=expired.id,
                tool_call_id=expired.tool_call_id,
                status=ApprovalStatus.EXPIRED,
                tool_call_status=ToolCallStatus(tool_call.status),
                error=ApprovalActionError("approval_expired", "Approval request has expired"),
            )

        denied = self._approval_repository.transition_status(
            approval_id,
            ApprovalStatus.PENDING,
            ApprovalStatus.DENIED,
            review_reason=review_reason,
        )
        if denied is None:
            raise ApprovalNotPendingError()
        tool_call = self._mark_tool_call_denied(denied.tool_call_id, "approval_denied")
        self._append_approval_audit(denied, tool_call, "denied", "approval_denied")
        return ApprovalActionResult(
            approval_id=denied.id,
            tool_call_id=denied.tool_call_id,
            status=ApprovalStatus.DENIED,
            tool_call_status=ToolCallStatus(tool_call.status),
        )

    def _get_approval_or_raise(self, approval_id: UUID) -> ApprovalRequestModel:
        approval = self._approval_repository.get_by_id(approval_id)
        if approval is None:
            raise ApprovalNotFoundError()
        return cast(ApprovalRequestModel, approval)

    @staticmethod
    def _raise_for_non_pending(approval: ApprovalRequestModel) -> None:
        if approval.status == ApprovalStatus.DENIED:
            raise ApprovalDeniedError()
        if approval.status in {
            ApprovalStatus.EXPIRED,
            ApprovalStatus.EXECUTED,
            ApprovalStatus.FAILED,
        }:
            raise ApprovalAlreadyProcessedError()
        raise ApprovalNotPendingError()

    def _mark_tool_call_denied(self, tool_call_id: UUID, error_code: str) -> ToolCallModel:
        tool_call_repository = self._require_tool_call_repository()
        tool_call = tool_call_repository.get_by_id(tool_call_id)
        if tool_call is None:
            raise ApprovalNotFoundError()
        tool_call.status = ToolCallStatus.DENIED
        tool_call.error_code = error_code
        tool_call.error_message = "Approval request did not permit execution"
        tool_call_repository.update(tool_call)
        cleared = tool_call_repository.clear_arguments_payload(tool_call.id)
        return cast(ToolCallModel, cleared if cleared is not None else tool_call)

    def _append_approval_audit(
        self,
        approval: ApprovalRequestModel,
        tool_call: ToolCallModel | None,
        status: str,
        error_code: str | None,
    ) -> None:
        audit_service = self._require_audit_service()
        audit_service.append_tool_call_event(
            trace_id=tool_call.trace_id if tool_call is not None else None,
            tenant_id=approval.tenant_id,
            agent_id=approval.agent_id,
            target_server=approval.target_server,
            target_tool=approval.target_tool,
            arguments_redacted=approval.arguments_redacted,
            arguments_hash=approval.arguments_hash,
            policy_decision=None,
            decision_reason=approval.requested_reason,
            approval_id=approval.id,
            status=status,
            error_code=error_code,
            error_message=None,
            metadata={"tool_call_id": str(approval.tool_call_id)},
        )

    def _require_tool_call_repository(self) -> Any:
        if self._tool_call_repository is None:
            raise ApprovalNotFoundError()
        return self._tool_call_repository

    def _require_audit_service(self) -> AuditService:
        if self._audit_service is None:
            raise ApprovalNotFoundError()
        return self._audit_service
