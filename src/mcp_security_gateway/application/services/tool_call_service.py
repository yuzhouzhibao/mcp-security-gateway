from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

from jsonschema import SchemaError, ValidationError
from jsonschema.validators import validator_for

from mcp_security_gateway.application.ports.mcp_client import (
    McpClient,
    McpUpstreamError,
    McpUpstreamTimeoutError,
)
from mcp_security_gateway.application.services.agent_service import AgentDTO
from mcp_security_gateway.application.services.approval_service import (
    ApprovalActionError,
    ApprovalActionResult,
    ApprovalService,
)
from mcp_security_gateway.application.services.audit_service import AuditService
from mcp_security_gateway.application.services.errors import (
    ArgumentSchemaInvalidError,
    IdempotencyConflictError,
    ToolDisabledError,
    ToolNotFoundError,
    ToolServerNotFoundError,
)
from mcp_security_gateway.application.services.policy_engine import (
    canonical_arguments_hash,
    redact_arguments,
)
from mcp_security_gateway.domain.enums import (
    ActionType,
    ApprovalStatus,
    EntityStatus,
    PolicyEffect,
    RiskLevel,
    ToolCallStatus,
)
from mcp_security_gateway.domain.policy import PolicyContext
from mcp_security_gateway.infrastructure.db.models import ToolCallModel


@dataclass(frozen=True, slots=True)
class ToolCallRequest:
    target_server: str
    target_tool: str
    arguments: dict[str, Any]
    trace_id: str | None
    idempotency_key: str | None


@dataclass(frozen=True, slots=True)
class ToolCallError:
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class ToolCallResult:
    tool_call_id: UUID
    status: ToolCallStatus
    policy_decision: PolicyEffect | None
    reason: str | None = None
    approval_id: UUID | None = None
    result: Mapping[str, Any] | None = None
    error: ToolCallError | None = None


class ToolCallService:
    def __init__(
        self,
        *,
        tool_server_repository: Any,
        tool_definition_repository: Any,
        tool_call_repository: Any,
        approval_repository: Any,
        policy_repository: Any,
        audit_service: AuditService,
        approval_service: ApprovalService,
        mcp_client: McpClient | None,
        mcp_call_timeout_seconds: float,
    ) -> None:
        self._tool_server_repository = tool_server_repository
        self._tool_definition_repository = tool_definition_repository
        self._tool_call_repository = tool_call_repository
        self._approval_repository = approval_repository
        self._policy_repository = policy_repository
        self._audit_service = audit_service
        self._approval_service = approval_service
        self._mcp_client = mcp_client
        self._mcp_call_timeout_seconds = mcp_call_timeout_seconds

    async def call_tool(self, agent: AgentDTO, request: ToolCallRequest) -> ToolCallResult:
        trace_id = request.trace_id or f"trace_{uuid4().hex}"
        redacted_arguments = self._redacted_arguments(request.arguments)
        arguments_hash = canonical_arguments_hash(request.arguments)

        if request.idempotency_key is not None:
            existing = self._tool_call_repository.get_by_idempotency_key(
                agent.tenant_id,
                agent.id,
                request.idempotency_key,
            )
            if existing is not None:
                return self._idempotent_result(existing, request, arguments_hash, trace_id)

        server = self._tool_server_repository.get_by_server_id(
            agent.tenant_id,
            request.target_server,
        )
        if server is None:
            self._append_failure_audit(
                agent=agent,
                request=request,
                trace_id=trace_id,
                redacted_arguments=redacted_arguments,
                arguments_hash=arguments_hash,
                status="failed",
                error_code="tool_server_not_found",
                error_message="Tool server not found",
            )
            raise ToolServerNotFoundError(trace_id)
        if server.status != EntityStatus.ACTIVE:
            self._append_failure_audit(
                agent=agent,
                request=request,
                trace_id=trace_id,
                redacted_arguments=redacted_arguments,
                arguments_hash=arguments_hash,
                status="failed",
                error_code="tool_disabled",
                error_message="Tool server is disabled",
            )
            raise ToolDisabledError(trace_id)

        tool = self._tool_definition_repository.get_by_name(
            agent.tenant_id,
            server.id,
            request.target_tool,
        )
        if tool is None:
            self._append_failure_audit(
                agent=agent,
                request=request,
                trace_id=trace_id,
                redacted_arguments=redacted_arguments,
                arguments_hash=arguments_hash,
                status="failed",
                error_code="tool_not_found",
                error_message="Tool not found",
            )
            raise ToolNotFoundError(trace_id)
        if tool.status != EntityStatus.ACTIVE:
            self._append_failure_audit(
                agent=agent,
                request=request,
                trace_id=trace_id,
                redacted_arguments=redacted_arguments,
                arguments_hash=arguments_hash,
                status="failed",
                error_code="tool_disabled",
                error_message="Tool is disabled",
            )
            raise ToolDisabledError(trace_id)

        if not self._arguments_match_schema(tool.input_schema, request.arguments):
            self._append_failure_audit(
                agent=agent,
                request=request,
                trace_id=trace_id,
                redacted_arguments=redacted_arguments,
                arguments_hash=arguments_hash,
                status="failed",
                error_code="argument_schema_invalid",
                error_message="Tool arguments do not match input schema",
            )
            raise ArgumentSchemaInvalidError(trace_id)

        policy_result = self._policy_repository_evaluate(
            agent=agent,
            request=request,
            tool_risk=RiskLevel(tool.risk_level),
            tool_action=ActionType(tool.action_type),
        )
        tool_call = self._create_tool_call(
            agent=agent,
            request=request,
            trace_id=trace_id,
            arguments_redacted=policy_result.arguments_redacted,
            arguments_hash=policy_result.arguments_hash,
            arguments_payload=(
                request.arguments
                if policy_result.decision == PolicyEffect.REQUIRE_APPROVAL
                else None
            ),
            tool_schema_hash=tool.schema_hash,
            policy_decision=policy_result.decision.value,
            decision_reason=policy_result.reason,
            status=self._initial_status(policy_result.decision),
        )

        if policy_result.decision == PolicyEffect.DENY:
            self._append_tool_call_audit(tool_call)
            return ToolCallResult(
                tool_call_id=tool_call.id,
                status=ToolCallStatus.DENIED,
                policy_decision=PolicyEffect.DENY,
                reason=policy_result.reason,
            )

        if policy_result.decision == PolicyEffect.REQUIRE_APPROVAL:
            approval = self._approval_service.create_pending_approval(
                tenant_id=agent.tenant_id,
                agent_id=agent.id,
                tool_call_id=tool_call.id,
                target_server=request.target_server,
                target_tool=request.target_tool,
                arguments_redacted=policy_result.arguments_redacted,
                arguments_hash=policy_result.arguments_hash,
                requested_reason=policy_result.reason,
            )
            tool_call.approval_id = approval.id
            self._tool_call_repository.update(tool_call)
            self._append_tool_call_audit(tool_call)
            return ToolCallResult(
                tool_call_id=tool_call.id,
                status=ToolCallStatus.PENDING_APPROVAL,
                policy_decision=PolicyEffect.REQUIRE_APPROVAL,
                reason=policy_result.reason,
                approval_id=approval.id,
            )

        if self._mcp_client is None:
            return self._mark_upstream_failed(
                tool_call,
                "mcp_client_not_configured",
                "MCP client is not configured",
            )

        try:
            upstream_result = await self._mcp_client.call_tool(
                server=server,
                tool=tool,
                arguments=request.arguments,
                timeout_seconds=self._mcp_call_timeout_seconds,
            )
        except McpUpstreamTimeoutError as error:
            return self._mark_upstream_failed(tool_call, error.code, error.message)
        except McpUpstreamError as error:
            return self._mark_upstream_failed(
                tool_call,
                error.code,
                error.message,
            )

        tool_call.status = ToolCallStatus.SUCCEEDED
        self._tool_call_repository.update(tool_call)
        self._append_tool_call_audit(tool_call)
        return ToolCallResult(
            tool_call_id=tool_call.id,
            status=ToolCallStatus.SUCCEEDED,
            policy_decision=PolicyEffect.ALLOW,
            result=upstream_result,
        )

    async def execute_approved_tool_call(self, approval: Any) -> ApprovalActionResult:
        tool_call = self._tool_call_repository.get_by_id(approval.tool_call_id)
        if tool_call is None:
            return self._approval_execution_failed(
                approval,
                None,
                "approval_execution_failed",
                "Approved tool call was not found",
            )
        arguments = tool_call.arguments_payload
        if arguments is None:
            return self._approval_execution_failed(
                approval,
                tool_call,
                "approval_execution_failed",
                "Execution payload is not available",
            )

        server = self._tool_server_repository.get_by_server_id(
            approval.tenant_id,
            approval.target_server,
        )
        if server is None or server.status != EntityStatus.ACTIVE:
            return self._approval_execution_failed(
                approval,
                tool_call,
                "tool_disabled",
                "Tool server is not active",
            )

        tool = self._tool_definition_repository.get_by_name(
            approval.tenant_id,
            server.id,
            approval.target_tool,
        )
        if tool is None or tool.status != EntityStatus.ACTIVE:
            return self._approval_execution_failed(
                approval,
                tool_call,
                "tool_disabled",
                "Tool is not active",
            )

        if self._mcp_client is None:
            return self._approval_execution_failed(
                approval,
                tool_call,
                "mcp_client_not_configured",
                "MCP client is not configured",
            )

        try:
            upstream_result = await self._mcp_client.call_tool(
                server=server,
                tool=tool,
                arguments=arguments,
                timeout_seconds=self._mcp_call_timeout_seconds,
            )
        except McpUpstreamTimeoutError as error:
            return self._approval_execution_failed(
                approval,
                tool_call,
                error.code,
                error.message,
            )
        except McpUpstreamError as error:
            return self._approval_execution_failed(
                approval,
                tool_call,
                error.code,
                error.message,
            )

        tool_call.status = ToolCallStatus.SUCCEEDED
        tool_call.error_code = None
        tool_call.error_message = None
        self._tool_call_repository.update(tool_call)
        self._tool_call_repository.clear_arguments_payload(tool_call.id)
        executed = self._approval_repository.transition_status(
            approval.id,
            ApprovalStatus.APPROVED,
            ApprovalStatus.EXECUTED,
        )
        if executed is None:
            return self._approval_execution_failed(
                approval,
                tool_call,
                "approval_already_processed",
                "Approval request was already processed",
            )
        self._append_tool_call_audit(tool_call, status="executed")
        return ApprovalActionResult(
            approval_id=approval.id,
            tool_call_id=approval.tool_call_id,
            status=ApprovalStatus.EXECUTED,
            tool_call_status=ToolCallStatus.SUCCEEDED,
            result=dict(upstream_result),
        )

    def _policy_repository_evaluate(
        self,
        *,
        agent: AgentDTO,
        request: ToolCallRequest,
        tool_risk: RiskLevel,
        tool_action: ActionType,
    ) -> Any:
        from mcp_security_gateway.application.services.policy_engine import PolicyService

        return PolicyService(self._policy_repository).evaluate(
            PolicyContext(
                tenant_id=agent.tenant_id,
                agent_id=agent.id,
                role=agent.role,
                target_server=request.target_server,
                target_tool=request.target_tool,
                risk_level=tool_risk,
                action_type=tool_action,
                arguments=request.arguments,
                resource=self._resource_from_arguments(request.arguments),
                current_time=datetime.now(UTC),
            )
        )

    @staticmethod
    def _resource_from_arguments(arguments: dict[str, Any]) -> str | None:
        resource = arguments.get("resource")
        if isinstance(resource, str):
            return resource
        repo = arguments.get("repo")
        if isinstance(repo, str):
            return f"repo:{repo}"
        return None

    @staticmethod
    def _redacted_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
        redacted = redact_arguments(arguments)
        if not isinstance(redacted, dict):
            return {}
        return redacted

    @staticmethod
    def _arguments_match_schema(schema: dict[str, Any], arguments: dict[str, Any]) -> bool:
        try:
            validator_class = validator_for(schema)
            validator_class.check_schema(schema)
            validator_class(schema).validate(arguments)
        except (SchemaError, ValidationError):
            return False
        return True

    def _create_tool_call(
        self,
        *,
        agent: AgentDTO,
        request: ToolCallRequest,
        trace_id: str,
        arguments_redacted: dict[str, Any],
        arguments_hash: str,
        arguments_payload: dict[str, Any] | None,
        tool_schema_hash: str | None,
        policy_decision: str | None,
        decision_reason: str | None,
        status: ToolCallStatus,
    ) -> ToolCallModel:
        return cast(
            ToolCallModel,
            self._tool_call_repository.create(
                ToolCallModel(
                    trace_id=trace_id,
                    tenant_id=agent.tenant_id,
                    agent_id=agent.id,
                    target_server=request.target_server,
                    target_tool=request.target_tool,
                    arguments_redacted=arguments_redacted,
                    arguments_hash=arguments_hash,
                    arguments_payload=arguments_payload,
                    tool_schema_hash=tool_schema_hash,
                    policy_decision=policy_decision,
                    decision_reason=decision_reason,
                    approval_id=None,
                    status=status,
                    error_code=None,
                    error_message=None,
                    idempotency_key=request.idempotency_key,
                )
            ),
        )

    @staticmethod
    def _initial_status(decision: PolicyEffect) -> ToolCallStatus:
        if decision == PolicyEffect.DENY:
            return ToolCallStatus.DENIED
        if decision == PolicyEffect.REQUIRE_APPROVAL:
            return ToolCallStatus.PENDING_APPROVAL
        return ToolCallStatus.EXECUTING

    def _idempotent_result(
        self,
        existing: ToolCallModel,
        request: ToolCallRequest,
        arguments_hash: str,
        trace_id: str,
    ) -> ToolCallResult:
        if (
            existing.target_server != request.target_server
            or existing.target_tool != request.target_tool
            or existing.arguments_hash != arguments_hash
        ):
            raise IdempotencyConflictError(trace_id)
        if existing.status == ToolCallStatus.EXECUTING:
            raise IdempotencyConflictError(trace_id)
        approval_id = existing.approval_id
        if existing.status == ToolCallStatus.PENDING_APPROVAL and approval_id is None:
            approval = self._approval_repository.get_by_tool_call_id(existing.id)
            approval_id = approval.id if approval is not None else None
        return ToolCallResult(
            tool_call_id=existing.id,
            status=ToolCallStatus(existing.status),
            policy_decision=(
                PolicyEffect(existing.policy_decision)
                if existing.policy_decision is not None
                else None
            ),
            reason=existing.decision_reason,
            approval_id=approval_id,
            error=(
                ToolCallError(
                    code=existing.error_code,
                    message=existing.error_message or "Tool call failed",
                )
                if existing.error_code is not None
                else None
            ),
        )

    def _mark_upstream_failed(
        self,
        tool_call: ToolCallModel,
        error_code: str,
        error_message: str,
    ) -> ToolCallResult:
        tool_call.status = ToolCallStatus.FAILED
        tool_call.error_code = error_code
        tool_call.error_message = error_message
        self._tool_call_repository.update(tool_call)
        self._append_tool_call_audit(tool_call)
        return ToolCallResult(
            tool_call_id=tool_call.id,
            status=ToolCallStatus.FAILED,
            policy_decision=PolicyEffect.ALLOW,
            error=ToolCallError(code=error_code, message=error_message),
        )

    def _approval_execution_failed(
        self,
        approval: Any,
        tool_call: ToolCallModel | None,
        error_code: str,
        error_message: str,
    ) -> ApprovalActionResult:
        if tool_call is not None:
            tool_call.status = ToolCallStatus.FAILED
            tool_call.error_code = error_code
            tool_call.error_message = error_message
            self._tool_call_repository.update(tool_call)
            self._tool_call_repository.clear_arguments_payload(tool_call.id)
        failed = self._approval_repository.transition_status(
            approval.id,
            ApprovalStatus.APPROVED,
            ApprovalStatus.FAILED,
        )
        self._audit_service.append_tool_call_event(
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
            status="failed",
            error_code=error_code,
            error_message=error_message,
            metadata={"tool_call_id": str(approval.tool_call_id)},
        )
        return ApprovalActionResult(
            approval_id=approval.id,
            tool_call_id=approval.tool_call_id,
            status=ApprovalStatus.FAILED if failed is not None else ApprovalStatus(approval.status),
            tool_call_status=(
                ToolCallStatus(tool_call.status) if tool_call is not None else ToolCallStatus.FAILED
            ),
            error=ApprovalActionError(error_code, error_message),
        )

    def _append_tool_call_audit(
        self,
        tool_call: ToolCallModel,
        status: str | None = None,
    ) -> None:
        self._audit_service.append_tool_call_event(
            trace_id=tool_call.trace_id,
            tenant_id=tool_call.tenant_id,
            agent_id=tool_call.agent_id,
            target_server=tool_call.target_server,
            target_tool=tool_call.target_tool,
            arguments_redacted=tool_call.arguments_redacted,
            arguments_hash=tool_call.arguments_hash,
            policy_decision=tool_call.policy_decision,
            decision_reason=tool_call.decision_reason,
            approval_id=tool_call.approval_id,
            status=status or ToolCallStatus(tool_call.status).value,
            error_code=tool_call.error_code,
            error_message=tool_call.error_message,
            metadata={"tool_call_id": str(tool_call.id)},
        )

    def _append_failure_audit(
        self,
        *,
        agent: AgentDTO,
        request: ToolCallRequest,
        trace_id: str,
        redacted_arguments: dict[str, Any],
        arguments_hash: str,
        status: str,
        error_code: str,
        error_message: str,
    ) -> None:
        self._audit_service.append_tool_call_event(
            trace_id=trace_id,
            tenant_id=agent.tenant_id,
            agent_id=agent.id,
            target_server=request.target_server,
            target_tool=request.target_tool,
            arguments_redacted=redacted_arguments,
            arguments_hash=arguments_hash,
            policy_decision=None,
            decision_reason=None,
            approval_id=None,
            status=status,
            error_code=error_code,
            error_message=error_message,
        )
