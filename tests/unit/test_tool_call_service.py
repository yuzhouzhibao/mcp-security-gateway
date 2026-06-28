from collections.abc import Sequence
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest

from mcp_security_gateway.application.services.agent_service import AgentDTO
from mcp_security_gateway.application.services.approval_service import ApprovalService
from mcp_security_gateway.application.services.audit_service import AuditService
from mcp_security_gateway.application.services.errors import (
    ApprovalAlreadyProcessedError,
    ApprovalDeniedError,
    ArgumentSchemaInvalidError,
    IdempotencyConflictError,
    ToolDisabledError,
    ToolNotFoundError,
    ToolServerNotFoundError,
)
from mcp_security_gateway.application.services.tool_call_service import (
    ToolCallRequest,
    ToolCallService,
)
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
from mcp_security_gateway.infrastructure.db.models import (
    ApprovalRequestModel,
    AuditEventModel,
    PolicyModel,
    ToolCallModel,
    ToolDefinitionModel,
    ToolServerModel,
    utc_now,
)
from mcp_security_gateway.main import create_app
from mcp_security_gateway.settings import Settings
from tests.fakes.mcp_client import TestOnlyMcpClient

TENANT_ID = UUID("00000000-0000-4000-8000-000000000201")
AGENT_ID = UUID("00000000-0000-4000-8000-000000000202")


class ToolServerRepo:
    def __init__(self, server: ToolServerModel | None) -> None:
        self.server = server

    def get_by_server_id(self, tenant_id: UUID, server_id: str) -> ToolServerModel | None:
        if self.server is None:
            return None
        if self.server.tenant_id == tenant_id and self.server.server_id == server_id:
            return self.server
        return None


class ToolDefinitionRepo:
    def __init__(self, definition: ToolDefinitionModel | None) -> None:
        self.definition = definition

    def get_by_name(
        self,
        tenant_id: UUID,
        server_id: UUID,
        tool_name: str,
    ) -> ToolDefinitionModel | None:
        if self.definition is None:
            return None
        if (
            self.definition.tenant_id == tenant_id
            and self.definition.server_id == server_id
            and self.definition.tool_name == tool_name
        ):
            return self.definition
        return None


class ToolCallRepo:
    def __init__(self, existing: ToolCallModel | None = None) -> None:
        self.created: list[ToolCallModel] = []
        self.existing = existing

    def create(self, tool_call: ToolCallModel) -> ToolCallModel:
        tool_call.id = tool_call.id or uuid4()
        self.created.append(tool_call)
        self.existing = tool_call
        return tool_call

    def update(self, tool_call: ToolCallModel) -> ToolCallModel:
        return tool_call

    def clear_arguments_payload(self, tool_call_id: UUID) -> ToolCallModel | None:
        tool_call = self.get_by_id(tool_call_id)
        if tool_call is None:
            return None
        tool_call.arguments_payload = None
        return tool_call

    def get_by_id(self, tool_call_id: UUID) -> ToolCallModel | None:
        if self.existing is not None and self.existing.id == tool_call_id:
            return self.existing
        for tool_call in self.created:
            if tool_call.id == tool_call_id:
                return tool_call
        return None

    def get_by_idempotency_key(
        self,
        tenant_id: UUID,
        agent_id: UUID,
        idempotency_key: str,
    ) -> ToolCallModel | None:
        if self.existing is None:
            return None
        if (
            self.existing.tenant_id == tenant_id
            and self.existing.agent_id == agent_id
            and self.existing.idempotency_key == idempotency_key
        ):
            return self.existing
        return None


class ApprovalRepo:
    def __init__(self) -> None:
        self.created: list[ApprovalRequestModel] = []

    def create(self, approval: ApprovalRequestModel) -> ApprovalRequestModel:
        approval.id = approval.id or uuid4()
        self.created.append(approval)
        return approval

    def get_by_tool_call_id(self, tool_call_id: UUID) -> ApprovalRequestModel | None:
        for approval in self.created:
            if approval.tool_call_id == tool_call_id:
                return approval
        return None

    def get_by_id(self, approval_id: UUID) -> ApprovalRequestModel | None:
        for approval in self.created:
            if approval.id == approval_id:
                return approval
        return None

    def list_filtered(
        self,
        status: ApprovalStatus | None,
        tenant_id: UUID | None,
        limit: int | None,
    ) -> list[ApprovalRequestModel]:
        approvals = [
            approval
            for approval in self.created
            if (status is None or approval.status == status)
            and (tenant_id is None or approval.tenant_id == tenant_id)
        ]
        return approvals[:limit] if limit is not None else approvals

    def transition_status(
        self,
        approval_id: UUID,
        expected_status: ApprovalStatus,
        next_status: ApprovalStatus,
        review_reason: str | None = None,
    ) -> ApprovalRequestModel | None:
        approval = self.get_by_id(approval_id)
        if approval is None or approval.status != expected_status:
            return None
        approval.status = next_status
        if review_reason is not None:
            approval.review_reason = review_reason
        return approval


class AuditRepo:
    def __init__(self) -> None:
        self.events: list[AuditEventModel] = []

    def append(self, event: AuditEventModel) -> AuditEventModel:
        event.event_id = event.event_id or uuid4()
        self.events.append(event)
        return event


class PolicyRepo:
    def __init__(self, policies: Sequence[PolicyModel] = ()) -> None:
        self.policies = list(policies)

    def list_active_by_tenant_ordered(self, tenant_id: UUID) -> list[PolicyModel]:
        return sorted(
            [
                policy
                for policy in self.policies
                if policy.tenant_id == tenant_id and policy.status == EntityStatus.ACTIVE
            ],
            key=lambda policy: policy.priority,
        )


def agent() -> AgentDTO:
    return AgentDTO(
        id=AGENT_ID,
        tenant_id=TENANT_ID,
        name="github-agent",
        role=AgentRole.AGENT,
        status=EntityStatus.ACTIVE,
    )


def server() -> ToolServerModel:
    return ToolServerModel(
        id=UUID("00000000-0000-4000-8000-000000000203"),
        tenant_id=TENANT_ID,
        server_id="github-main",
        name="GitHub",
        transport_type=TransportType.STREAMABLE_HTTP,
        endpoint_url="https://example.invalid",
        command=None,
        args=None,
        env=None,
        status=EntityStatus.ACTIVE,
    )


def disabled_server() -> ToolServerModel:
    model = server()
    model.status = EntityStatus.DISABLED
    return model


def definition(
    risk_level: RiskLevel = RiskLevel.LOW,
    action_type: ActionType = ActionType.READ,
    schema: dict[str, Any] | None = None,
) -> ToolDefinitionModel:
    return ToolDefinitionModel(
        id=UUID("00000000-0000-4000-8000-000000000204"),
        tenant_id=TENANT_ID,
        server_id=server().id,
        tool_name="github.get_issue",
        description=None,
        input_schema=schema
        or {
            "type": "object",
            "required": ["repo", "issue_number"],
            "properties": {
                "repo": {"type": "string"},
                "issue_number": {"type": "integer"},
            },
            "additionalProperties": False,
        },
        risk_level=risk_level,
        action_type=action_type,
        resource_patterns=None,
        status=EntityStatus.ACTIVE,
        schema_hash="schema-hash",
    )


def disabled_definition() -> ToolDefinitionModel:
    model = definition()
    model.status = EntityStatus.DISABLED
    return model


def request(
    arguments: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> ToolCallRequest:
    return ToolCallRequest(
        target_server="github-main",
        target_tool="github.get_issue",
        arguments=arguments or {"repo": "acme/api", "issue_number": 123},
        trace_id="trace-unit",
        idempotency_key=idempotency_key,
    )


def policy(effect: PolicyEffect, conditions: dict[str, object]) -> PolicyModel:
    return PolicyModel(
        id=uuid4(),
        tenant_id=TENANT_ID,
        name=f"policy-{effect.value}",
        priority=10,
        effect=effect,
        conditions=conditions,
        reason=f"{effect.value} reason",
        status=EntityStatus.ACTIVE,
    )


def service(
    *,
    tool: ToolDefinitionModel | None = None,
    include_tool: bool = True,
    tool_server: ToolServerModel | None = None,
    include_server: bool = True,
    policies: Sequence[PolicyModel] = (),
    mcp_client: TestOnlyMcpClient | None = None,
    configured_mcp_client: bool = True,
    existing_call: ToolCallModel | None = None,
) -> tuple[ToolCallService, ToolCallRepo, ApprovalRepo, AuditRepo, TestOnlyMcpClient]:
    tool_call_repo = ToolCallRepo(existing_call)
    approval_repo = ApprovalRepo()
    audit_repo = AuditRepo()
    resolved_client = mcp_client or TestOnlyMcpClient()
    return (
        ToolCallService(
            tool_server_repository=ToolServerRepo(
                (tool_server if tool_server is not None else server()) if include_server else None
            ),
            tool_definition_repository=ToolDefinitionRepo(
                (tool if tool is not None else definition()) if include_tool else None
            ),
            tool_call_repository=tool_call_repo,
            approval_repository=approval_repo,
            policy_repository=PolicyRepo(policies),
            audit_service=AuditService(audit_repo),
            approval_service=ApprovalService(approval_repo, 900),
            mcp_client=resolved_client if configured_mcp_client else None,
            mcp_call_timeout_seconds=5,
        ),
        tool_call_repo,
        approval_repo,
        audit_repo,
        resolved_client,
    )


@pytest.mark.asyncio
async def test_tool_lookup_uses_registry_risk_and_action_not_request() -> None:
    svc, _, approvals, _, client = service(tool=definition(RiskLevel.HIGH, ActionType.READ))

    result = await svc.call_tool(agent(), request())

    assert result.status == ToolCallStatus.PENDING_APPROVAL
    assert len(approvals.created) == 1
    assert client.calls == []


@pytest.mark.asyncio
async def test_arguments_schema_valid_continues_and_allow_calls_mcp() -> None:
    svc, _, _, _, client = service()

    result = await svc.call_tool(agent(), request())

    assert result.status == ToolCallStatus.SUCCEEDED
    assert result.result == {"ok": True}
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_arguments_schema_invalid_does_not_call_mcp_and_writes_audit() -> None:
    svc, tool_calls, _, audit, client = service()

    with pytest.raises(ArgumentSchemaInvalidError):
        await svc.call_tool(agent(), request({"repo": "acme/api", "issue_number": "bad"}))

    assert client.calls == []
    assert tool_calls.created == []
    assert audit.events[-1].error_code == "argument_schema_invalid"


@pytest.mark.asyncio
async def test_policy_deny_does_not_call_mcp_and_writes_audit() -> None:
    svc, tool_calls, _, audit, client = service(
        policies=[policy(PolicyEffect.DENY, {"tool_names": ["github.get_issue"]})]
    )

    result = await svc.call_tool(agent(), request())

    assert result.status == ToolCallStatus.DENIED
    assert client.calls == []
    assert tool_calls.created[-1].arguments_payload is None
    assert audit.events[-1].status == "denied"


@pytest.mark.asyncio
async def test_policy_require_approval_creates_approval_without_mcp_and_writes_audit() -> None:
    svc, tool_calls, approvals, audit, client = service(
        tool=definition(RiskLevel.HIGH, ActionType.READ)
    )

    result = await svc.call_tool(agent(), request())

    assert result.status == ToolCallStatus.PENDING_APPROVAL
    assert result.approval_id == approvals.created[0].id
    assert approvals.created[0].status == ApprovalStatus.PENDING
    assert tool_calls.created[-1].arguments_payload == {"repo": "acme/api", "issue_number": 123}
    assert client.calls == []
    assert audit.events[-1].status == "pending_approval"


@pytest.mark.asyncio
async def test_upstream_failure_and_timeout_are_failed_not_success() -> None:
    failed_service, _, _, failed_audit, failed_client = service(
        mcp_client=TestOnlyMcpClient(failure="failed")
    )
    timeout_service, _, _, timeout_audit, timeout_client = service(
        mcp_client=TestOnlyMcpClient(failure="timeout")
    )

    failed = await failed_service.call_tool(agent(), request())
    timeout = await timeout_service.call_tool(agent(), request())

    assert failed.status == ToolCallStatus.FAILED
    assert failed.error is not None
    assert failed.error.code == "upstream_failed"
    assert timeout.status == ToolCallStatus.FAILED
    assert timeout.error is not None
    assert timeout.error.code == "upstream_timeout"
    assert len(failed_client.calls) == 1
    assert len(timeout_client.calls) == 1
    assert failed_audit.events[-1].error_code == "upstream_failed"
    assert timeout_audit.events[-1].error_code == "upstream_timeout"


@pytest.mark.asyncio
async def test_mcp_call_result_is_error_maps_to_failed_tool_call() -> None:
    svc, tool_calls, _, audit, client = service(
        mcp_client=TestOnlyMcpClient(failure="mcp_tool_call_failed")
    )

    result = await svc.call_tool(agent(), request())

    assert result.status == ToolCallStatus.FAILED
    assert result.error is not None
    assert result.error.code == "mcp_tool_call_failed"
    assert tool_calls.created[-1].status == ToolCallStatus.FAILED
    assert audit.events[-1].status == "failed"
    assert audit.events[-1].error_code == "mcp_tool_call_failed"
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_missing_mcp_client_writes_failed_tool_call_and_audit_without_success() -> None:
    svc, tool_calls, _, audit, client = service(configured_mcp_client=False)

    result = await svc.call_tool(agent(), request())

    assert result.status == ToolCallStatus.FAILED
    assert result.error is not None
    assert result.error.code == "mcp_client_not_configured"
    assert tool_calls.created[-1].status == ToolCallStatus.FAILED
    assert tool_calls.created[-1].error_code == "mcp_client_not_configured"
    assert tool_calls.created[-1].arguments_payload is None
    assert audit.events[-1].error_code == "mcp_client_not_configured"
    assert client.calls == []


@pytest.mark.asyncio
async def test_audit_written_for_tool_not_found() -> None:
    svc, tool_calls, _, audit, client = service(include_tool=False)

    with pytest.raises(ToolNotFoundError):
        await svc.call_tool(agent(), request())

    assert client.calls == []
    assert tool_calls.created == []
    assert audit.events[-1].error_code == "tool_not_found"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scenario", "expected_error", "expected_code"),
    [
        ("missing_server", ToolServerNotFoundError, "tool_server_not_found"),
        ("disabled_server", ToolDisabledError, "tool_disabled"),
        ("missing_tool", ToolNotFoundError, "tool_not_found"),
        ("disabled_tool", ToolDisabledError, "tool_disabled"),
        ("schema_invalid", ArgumentSchemaInvalidError, "argument_schema_invalid"),
    ],
)
async def test_pre_policy_failures_audit_redacted_arguments_without_raw_secret(
    scenario: str,
    expected_error: type[Exception],
    expected_code: str,
) -> None:
    secret_value = "sk-test-secret"
    if scenario == "missing_server":
        svc, tool_calls, _, audit, client = service(include_server=False)
    elif scenario == "disabled_server":
        svc, tool_calls, _, audit, client = service(tool_server=disabled_server())
    elif scenario == "missing_tool":
        svc, tool_calls, _, audit, client = service(include_tool=False)
    elif scenario == "disabled_tool":
        svc, tool_calls, _, audit, client = service(tool=disabled_definition())
    else:
        svc, tool_calls, _, audit, client = service()
    failing_request = request({"token": secret_value})

    with pytest.raises(expected_error):
        await svc.call_tool(agent(), failing_request)

    assert tool_calls.created == []
    assert client.calls == []
    assert audit.events[-1].error_code == expected_code
    assert secret_value not in repr(audit.events[-1].arguments_redacted)
    assert audit.events[-1].arguments_hash is not None


@pytest.mark.asyncio
async def test_idempotency_repeated_success_does_not_call_mcp_twice() -> None:
    svc, tool_calls, _, _, client = service()
    first = await svc.call_tool(agent(), request(idempotency_key="idem-1"))
    second = await svc.call_tool(agent(), request(idempotency_key="idem-1"))

    assert first.tool_call_id == second.tool_call_id
    assert second.status == ToolCallStatus.SUCCEEDED
    assert tool_calls.existing is not None
    assert tool_calls.existing.arguments_payload is None
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_idempotency_repeated_pending_approval_returns_same_approval() -> None:
    svc, _, approvals, _, client = service(tool=definition(RiskLevel.HIGH, ActionType.READ))
    first = await svc.call_tool(agent(), request(idempotency_key="idem-approval"))
    second = await svc.call_tool(agent(), request(idempotency_key="idem-approval"))

    assert first.approval_id == second.approval_id
    assert len(approvals.created) == 1
    assert client.calls == []


@pytest.mark.asyncio
async def test_idempotency_same_key_different_arguments_conflicts() -> None:
    svc, _, _, _, _ = service()
    await svc.call_tool(agent(), request(idempotency_key="idem-conflict"))

    with pytest.raises(IdempotencyConflictError):
        await svc.call_tool(
            agent(),
            request({"repo": "acme/api", "issue_number": 456}, "idem-conflict"),
        )


@pytest.mark.asyncio
async def test_idempotency_repeated_failed_result_is_reused_without_retry() -> None:
    svc, _, _, _, client = service(mcp_client=TestOnlyMcpClient(failure="failed"))
    first = await svc.call_tool(agent(), request(idempotency_key="idem-failed"))
    second = await svc.call_tool(agent(), request(idempotency_key="idem-failed"))

    assert first.tool_call_id == second.tool_call_id
    assert second.status == ToolCallStatus.FAILED
    assert second.error is not None
    assert second.error.code == "upstream_failed"
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_executing_duplicate_conflicts() -> None:
    existing = ToolCallModel(
        id=uuid4(),
        trace_id="trace-existing",
        tenant_id=TENANT_ID,
        agent_id=AGENT_ID,
        target_server="github-main",
        target_tool="github.get_issue",
        arguments_redacted={"repo": "acme/api", "issue_number": 123},
        arguments_hash="eb4a82c7ff802b0b36d52e56ec27bb3f440f2c2dc708e4bc3a495cc36f986b18",
        tool_schema_hash="schema-hash",
        policy_decision="allow",
        decision_reason=None,
        approval_id=None,
        status=ToolCallStatus.EXECUTING,
        error_code=None,
        error_message=None,
        idempotency_key="idem-executing",
    )
    svc, _, _, _, _ = service(existing_call=existing)

    with pytest.raises(IdempotencyConflictError):
        await svc.call_tool(agent(), request(idempotency_key="idem-executing"))


def test_test_only_mcp_client_is_not_selected_by_production_settings(
    test_settings: Settings,
) -> None:
    app = create_app(test_settings)

    assert type(app.state.mcp_client).__name__ == "StdioMcpClient"


@pytest.mark.asyncio
async def test_raw_secret_not_written_to_audit_for_secret_policy_deny() -> None:
    secret_value = "Bearer unit-sensitive-value"
    svc, tool_calls, _, audit, client = service(
        tool=definition(
            schema={
                "type": "object",
                "required": ["authorization"],
                "properties": {"authorization": {"type": "string"}},
            }
        ),
        policies=[policy(PolicyEffect.ALLOW, {"tool_names": ["github.get_issue"]})],
    )

    result = await svc.call_tool(agent(), request({"authorization": secret_value}))

    assert result.status == ToolCallStatus.DENIED
    assert client.calls == []
    assert repr(audit.events[-1].arguments_redacted).find(secret_value) == -1
    assert repr(tool_calls.created[-1].arguments_redacted).find(secret_value) == -1


def pending_tool_call(
    arguments_payload: dict[str, Any] | None = None,
    status: ToolCallStatus = ToolCallStatus.PENDING_APPROVAL,
) -> ToolCallModel:
    return ToolCallModel(
        id=uuid4(),
        trace_id="trace-approval",
        tenant_id=TENANT_ID,
        agent_id=AGENT_ID,
        target_server="github-main",
        target_tool="github.get_issue",
        arguments_redacted={"repo": "acme/api", "token": "[REDACTED]"},
        arguments_hash="approval-arguments-hash",
        arguments_payload=arguments_payload or {"repo": "acme/api", "issue_number": 123},
        tool_schema_hash="schema-hash",
        policy_decision="require_approval",
        decision_reason="high risk tools require approval",
        approval_id=None,
        status=status,
        error_code=None,
        error_message=None,
        idempotency_key=None,
    )


def pending_approval(
    tool_call: ToolCallModel,
    status: ApprovalStatus = ApprovalStatus.PENDING,
    expires_in_seconds: int = 900,
) -> ApprovalRequestModel:
    return ApprovalRequestModel(
        id=uuid4(),
        tenant_id=TENANT_ID,
        agent_id=AGENT_ID,
        tool_call_id=tool_call.id,
        target_server="github-main",
        target_tool="github.get_issue",
        arguments_redacted=tool_call.arguments_redacted,
        arguments_hash=tool_call.arguments_hash,
        status=status,
        requested_reason="high risk tools require approval",
        reviewer_id=None,
        review_reason=None,
        expires_at=utc_now() + timedelta(seconds=expires_in_seconds),
        approved_at=None,
        denied_at=None,
        executed_at=None,
    )


def approval_flow(
    *,
    tool_call: ToolCallModel | None = None,
    approval_status: ApprovalStatus = ApprovalStatus.PENDING,
    expires_in_seconds: int = 900,
    tool: ToolDefinitionModel | None = None,
    tool_server: ToolServerModel | None = None,
    mcp_client: TestOnlyMcpClient | None = None,
    configured_mcp_client: bool = True,
) -> tuple[
    ApprovalService,
    ToolCallService,
    ToolCallRepo,
    ApprovalRepo,
    AuditRepo,
    TestOnlyMcpClient,
]:
    resolved_tool_call = tool_call or pending_tool_call()
    tool_call_repo = ToolCallRepo(resolved_tool_call)
    approval_repo = ApprovalRepo()
    approval = pending_approval(
        resolved_tool_call,
        status=approval_status,
        expires_in_seconds=expires_in_seconds,
    )
    approval_repo.create(approval)
    audit_repo = AuditRepo()
    audit_service = AuditService(audit_repo)
    approval_service = ApprovalService(
        approval_repo,
        900,
        tool_call_repository=tool_call_repo,
        audit_service=audit_service,
    )
    resolved_client = mcp_client or TestOnlyMcpClient(result={"ok": True})
    tool_call_service = ToolCallService(
        tool_server_repository=ToolServerRepo(tool_server if tool_server is not None else server()),
        tool_definition_repository=ToolDefinitionRepo(tool if tool is not None else definition()),
        tool_call_repository=tool_call_repo,
        approval_repository=approval_repo,
        policy_repository=PolicyRepo(),
        audit_service=audit_service,
        approval_service=approval_service,
        mcp_client=resolved_client if configured_mcp_client else None,
        mcp_call_timeout_seconds=5,
    )
    return (
        approval_service,
        tool_call_service,
        tool_call_repo,
        approval_repo,
        audit_repo,
        resolved_client,
    )


@pytest.mark.asyncio
async def test_pending_approval_approve_transitions_to_executed() -> None:
    approval_service, tool_call_service, tool_calls, approvals, audit, client = approval_flow()
    approval = approvals.created[0]

    result = await approval_service.approve_approval(
        approval_id=approval.id,
        review_reason="Looks safe",
        tool_call_service=tool_call_service,
    )

    assert result.status == ApprovalStatus.EXECUTED
    assert result.tool_call_status == ToolCallStatus.SUCCEEDED
    assert tool_calls.existing is not None
    assert tool_calls.existing.status == ToolCallStatus.SUCCEEDED
    assert tool_calls.existing.arguments_payload is None
    assert approvals.created[0].status == ApprovalStatus.EXECUTED
    assert len(client.calls) == 1
    assert [event.status for event in audit.events] == ["approved", "executed"]


@pytest.mark.asyncio
async def test_pending_approval_approve_upstream_failed_transitions_to_failed() -> None:
    approval_service, tool_call_service, tool_calls, approvals, audit, client = approval_flow(
        mcp_client=TestOnlyMcpClient(failure="failed")
    )
    approval = approvals.created[0]

    result = await approval_service.approve_approval(
        approval_id=approval.id,
        review_reason="Looks safe",
        tool_call_service=tool_call_service,
    )

    assert result.status == ApprovalStatus.FAILED
    assert result.tool_call_status == ToolCallStatus.FAILED
    assert result.error is not None
    assert result.error.code == "upstream_failed"
    assert tool_calls.existing is not None
    assert tool_calls.existing.status == ToolCallStatus.FAILED
    assert tool_calls.existing.arguments_payload is None
    assert approvals.created[0].status == ApprovalStatus.FAILED
    assert len(client.calls) == 1
    assert audit.events[-1].error_code == "upstream_failed"


def test_pending_approval_deny_transitions_to_denied() -> None:
    approval_service, _, tool_calls, approvals, audit, client = approval_flow()
    approval = approvals.created[0]

    result = approval_service.deny_approval(
        approval_id=approval.id,
        review_reason="Too risky",
    )

    assert result.status == ApprovalStatus.DENIED
    assert result.tool_call_status == ToolCallStatus.DENIED
    assert tool_calls.existing is not None
    assert tool_calls.existing.status == ToolCallStatus.DENIED
    assert tool_calls.existing.arguments_payload is None
    assert approvals.created[0].status == ApprovalStatus.DENIED
    assert client.calls == []
    assert audit.events[-1].status == "denied"


@pytest.mark.asyncio
async def test_expired_approval_approve_expires_without_mcp_call() -> None:
    approval_service, tool_call_service, tool_calls, approvals, audit, client = approval_flow(
        expires_in_seconds=-1
    )
    approval = approvals.created[0]

    result = await approval_service.approve_approval(
        approval_id=approval.id,
        review_reason="Looks safe",
        tool_call_service=tool_call_service,
    )

    assert result.status == ApprovalStatus.EXPIRED
    assert result.tool_call_status == ToolCallStatus.DENIED
    assert result.error is not None
    assert result.error.code == "approval_expired"
    assert tool_calls.existing is not None
    assert tool_calls.existing.status == ToolCallStatus.DENIED
    assert tool_calls.existing.arguments_payload is None
    assert client.calls == []
    assert audit.events[-1].status == "expired"


@pytest.mark.asyncio
async def test_approve_already_executed_or_denied_does_not_call_mcp() -> None:
    executed_service, executed_tool_service, _, executed_approvals, _, executed_client = (
        approval_flow(approval_status=ApprovalStatus.EXECUTED)
    )
    denied_service, denied_tool_service, _, denied_approvals, _, denied_client = approval_flow(
        approval_status=ApprovalStatus.DENIED
    )

    with pytest.raises(ApprovalAlreadyProcessedError):
        await executed_service.approve_approval(
            approval_id=executed_approvals.created[0].id,
            review_reason="Again",
            tool_call_service=executed_tool_service,
        )
    with pytest.raises(ApprovalDeniedError):
        await denied_service.approve_approval(
            approval_id=denied_approvals.created[0].id,
            review_reason="Again",
            tool_call_service=denied_tool_service,
        )

    assert executed_client.calls == []
    assert denied_client.calls == []


def test_deny_executed_approval_does_not_change_state() -> None:
    approval_service, _, _, approvals, _, client = approval_flow(
        approval_status=ApprovalStatus.EXECUTED
    )

    with pytest.raises(ApprovalAlreadyProcessedError):
        approval_service.deny_approval(
            approval_id=approvals.created[0].id,
            review_reason="Too late",
        )

    assert approvals.created[0].status == ApprovalStatus.EXECUTED
    assert client.calls == []


@pytest.mark.asyncio
async def test_double_approve_only_calls_mcp_once() -> None:
    approval_service, tool_call_service, _, approvals, _, client = approval_flow()
    approval = approvals.created[0]
    first = await approval_service.approve_approval(
        approval_id=approval.id,
        review_reason="Looks safe",
        tool_call_service=tool_call_service,
    )

    with pytest.raises(ApprovalAlreadyProcessedError):
        await approval_service.approve_approval(
            approval_id=approval.id,
            review_reason="Again",
            tool_call_service=tool_call_service,
        )

    assert first.status == ApprovalStatus.EXECUTED
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_approve_uses_execution_payload_not_redacted_arguments() -> None:
    payload = {"repo": "acme/api", "issue_number": 123, "token": "payload-token"}
    tool_call = pending_tool_call(arguments_payload=payload)
    approval_service, tool_call_service, _, approvals, audit, client = approval_flow(
        tool_call=tool_call,
        tool=definition(
            schema={
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "issue_number": {"type": "integer"},
                    "token": {"type": "string"},
                },
            }
        ),
    )

    result = await approval_service.approve_approval(
        approval_id=approvals.created[0].id,
        review_reason="Looks safe",
        tool_call_service=tool_call_service,
    )

    assert result.status == ApprovalStatus.EXECUTED
    assert client.calls[0]["arguments"] == payload
    assert client.calls[0]["arguments"] != tool_call.arguments_redacted
    assert "payload-token" not in repr(audit.events)


@pytest.mark.asyncio
async def test_missing_mcp_client_during_approve_fails_without_test_client_call() -> None:
    approval_service, tool_call_service, tool_calls, approvals, audit, client = approval_flow(
        configured_mcp_client=False
    )

    result = await approval_service.approve_approval(
        approval_id=approvals.created[0].id,
        review_reason="Looks safe",
        tool_call_service=tool_call_service,
    )

    assert result.status == ApprovalStatus.FAILED
    assert result.error is not None
    assert result.error.code == "mcp_client_not_configured"
    assert tool_calls.existing is not None
    assert tool_calls.existing.status == ToolCallStatus.FAILED
    assert tool_calls.existing.arguments_payload is None
    assert client.calls == []
    assert audit.events[-1].error_code == "mcp_client_not_configured"


@pytest.mark.asyncio
async def test_tool_or_server_disabled_before_approval_execution_fails_without_mcp() -> None:
    server_service, server_tool_service, _, server_approvals, _, server_client = approval_flow(
        tool_server=disabled_server()
    )
    tool_service, tool_tool_service, _, tool_approvals, _, tool_client = approval_flow(
        tool=disabled_definition()
    )

    server_result = await server_service.approve_approval(
        approval_id=server_approvals.created[0].id,
        review_reason="Looks safe",
        tool_call_service=server_tool_service,
    )
    tool_result = await tool_service.approve_approval(
        approval_id=tool_approvals.created[0].id,
        review_reason="Looks safe",
        tool_call_service=tool_tool_service,
    )

    assert server_result.status == ApprovalStatus.FAILED
    assert tool_result.status == ApprovalStatus.FAILED
    assert server_result.error is not None
    assert tool_result.error is not None
    assert server_result.error.code == "tool_disabled"
    assert tool_result.error.code == "tool_disabled"
    assert server_client.calls == []
    assert tool_client.calls == []
