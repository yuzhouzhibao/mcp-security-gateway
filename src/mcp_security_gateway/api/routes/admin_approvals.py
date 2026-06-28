from dataclasses import asdict
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from mcp_security_gateway.api.dependencies import get_db_session, get_settings, require_admin
from mcp_security_gateway.api.schemas import (
    ApprovalActionErrorBody,
    ApprovalActionResponse,
    ApprovalListItem,
    ApprovalListResponse,
    ApprovalReviewRequest,
)
from mcp_security_gateway.application.services.approval_service import ApprovalService
from mcp_security_gateway.application.services.audit_service import AuditService
from mcp_security_gateway.application.services.tool_call_service import ToolCallService
from mcp_security_gateway.domain.enums import ApprovalStatus
from mcp_security_gateway.infrastructure.db.repositories import (
    SQLAlchemyApprovalRequestRepository,
    SQLAlchemyAuditEventRepository,
    SQLAlchemyPolicyRepository,
    SQLAlchemyToolCallRepository,
    SQLAlchemyToolDefinitionRepository,
    SQLAlchemyToolServerRepository,
)
from mcp_security_gateway.settings import Settings

router = APIRouter(prefix="/v1/admin/approvals", dependencies=[Depends(require_admin)])
SessionDep = Annotated[Session, Depends(get_db_session)]


def build_services(
    request: Request,
    session: Session,
    settings: Settings,
) -> tuple[ApprovalService, ToolCallService]:
    approval_repository = SQLAlchemyApprovalRequestRepository(session)
    tool_call_repository = SQLAlchemyToolCallRepository(session)
    audit_service = AuditService(SQLAlchemyAuditEventRepository(session))
    approval_service = ApprovalService(
        approval_repository,
        settings.approval_request_ttl_seconds,
        tool_call_repository=tool_call_repository,
        audit_service=audit_service,
    )
    mcp_client = getattr(request.app.state, "mcp_client", None)
    tool_call_service = ToolCallService(
        tool_server_repository=SQLAlchemyToolServerRepository(session),
        tool_definition_repository=SQLAlchemyToolDefinitionRepository(session),
        tool_call_repository=tool_call_repository,
        approval_repository=approval_repository,
        policy_repository=SQLAlchemyPolicyRepository(session),
        audit_service=audit_service,
        approval_service=approval_service,
        mcp_client=mcp_client,
        mcp_call_timeout_seconds=settings.mcp_call_timeout_seconds,
    )
    return approval_service, tool_call_service


@router.get("", response_model=ApprovalListResponse)
async def list_approvals(
    request: Request,
    session: SessionDep,
    status: ApprovalStatus = ApprovalStatus.PENDING,
    tenant_id: UUID | None = None,
    limit: int | None = None,
) -> ApprovalListResponse:
    settings = get_settings(request)
    approval_service, _ = build_services(request, session, settings)
    approvals = approval_service.list_approvals(status=status, tenant_id=tenant_id, limit=limit)
    return ApprovalListResponse(
        items=[ApprovalListItem.model_validate(approval) for approval in approvals]
    )


@router.post("/{approval_id}/approve", response_model=ApprovalActionResponse)
async def approve_approval(
    approval_id: UUID,
    payload: ApprovalReviewRequest,
    request: Request,
    session: SessionDep,
) -> ApprovalActionResponse:
    settings = get_settings(request)
    approval_service, tool_call_service = build_services(request, session, settings)
    result = await approval_service.approve_approval(
        approval_id=approval_id,
        review_reason=payload.review_reason,
        tool_call_service=tool_call_service,
    )
    session.commit()
    error = ApprovalActionErrorBody(**asdict(result.error)) if result.error is not None else None
    return ApprovalActionResponse(
        approval_id=result.approval_id,
        tool_call_id=result.tool_call_id,
        status=result.status,
        tool_call_status=result.tool_call_status,
        result=result.result,
        error=error,
    )


@router.post("/{approval_id}/deny", response_model=ApprovalActionResponse)
async def deny_approval(
    approval_id: UUID,
    payload: ApprovalReviewRequest,
    request: Request,
    session: SessionDep,
) -> ApprovalActionResponse:
    settings = get_settings(request)
    approval_service, _ = build_services(request, session, settings)
    result = approval_service.deny_approval(
        approval_id=approval_id,
        review_reason=payload.review_reason,
    )
    session.commit()
    error = ApprovalActionErrorBody(**asdict(result.error)) if result.error is not None else None
    return ApprovalActionResponse(
        approval_id=result.approval_id,
        tool_call_id=result.tool_call_id,
        status=result.status,
        tool_call_status=result.tool_call_status,
        result=result.result,
        error=error,
    )
