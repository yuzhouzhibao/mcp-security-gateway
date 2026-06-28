from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from mcp_security_gateway.api.dependencies import (
    get_db_session,
    get_settings,
    require_agent,
)
from mcp_security_gateway.api.schemas import (
    ToolCallErrorBody,
    ToolCallRequestBody,
    ToolCallResponse,
)
from mcp_security_gateway.application.ports.mcp_client import McpClient
from mcp_security_gateway.application.services.agent_service import AgentDTO
from mcp_security_gateway.application.services.approval_service import ApprovalService
from mcp_security_gateway.application.services.audit_service import AuditService
from mcp_security_gateway.application.services.tool_call_service import (
    ToolCallRequest,
    ToolCallService,
)
from mcp_security_gateway.infrastructure.db.repositories import (
    SQLAlchemyApprovalRequestRepository,
    SQLAlchemyAuditEventRepository,
    SQLAlchemyPolicyRepository,
    SQLAlchemyToolCallRepository,
    SQLAlchemyToolDefinitionRepository,
    SQLAlchemyToolServerRepository,
)
from mcp_security_gateway.settings import Settings

router = APIRouter(prefix="/v1/tool-calls")
SessionDep = Annotated[Session, Depends(get_db_session)]
AgentDep = Annotated[AgentDTO, Depends(require_agent)]


def build_service(
    session: Session,
    settings: Settings,
    mcp_client: McpClient | None,
) -> ToolCallService:
    approval_repository = SQLAlchemyApprovalRequestRepository(session)
    return ToolCallService(
        tool_server_repository=SQLAlchemyToolServerRepository(session),
        tool_definition_repository=SQLAlchemyToolDefinitionRepository(session),
        tool_call_repository=SQLAlchemyToolCallRepository(session),
        approval_repository=approval_repository,
        policy_repository=SQLAlchemyPolicyRepository(session),
        audit_service=AuditService(SQLAlchemyAuditEventRepository(session)),
        approval_service=ApprovalService(
            approval_repository,
            settings.approval_request_ttl_seconds,
        ),
        mcp_client=mcp_client,
        mcp_call_timeout_seconds=settings.mcp_call_timeout_seconds,
    )


@router.post("", response_model=ToolCallResponse)
async def call_tool(
    payload: ToolCallRequestBody,
    request: Request,
    session: SessionDep,
    agent: AgentDep,
) -> ToolCallResponse:
    settings = get_settings(request)
    mcp_client = getattr(request.app.state, "mcp_client", None)
    service = build_service(session, settings, mcp_client)
    result = await service.call_tool(
        agent,
        ToolCallRequest(
            target_server=payload.target_server,
            target_tool=payload.target_tool,
            arguments=payload.arguments,
            trace_id=payload.trace_id,
            idempotency_key=payload.idempotency_key,
        ),
    )
    session.commit()
    error = ToolCallErrorBody(**asdict(result.error)) if result.error is not None else None
    response_result = dict(result.result) if result.result is not None else None
    return ToolCallResponse(
        tool_call_id=result.tool_call_id,
        status=result.status,
        policy_decision=result.policy_decision,
        reason=result.reason,
        approval_id=result.approval_id,
        result=response_result,
        error=error,
    )
