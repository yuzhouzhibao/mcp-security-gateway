from collections.abc import Sequence
from typing import Any
from uuid import UUID, uuid4

import pytest

from mcp_security_gateway.application.services.agent_service import AgentDTO
from mcp_security_gateway.application.services.approval_service import ApprovalService
from mcp_security_gateway.application.services.audit_service import AuditService
from mcp_security_gateway.application.services.errors import (
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
    svc, _, _, audit, client = service(
        policies=[policy(PolicyEffect.DENY, {"tool_names": ["github.get_issue"]})]
    )

    result = await svc.call_tool(agent(), request())

    assert result.status == ToolCallStatus.DENIED
    assert client.calls == []
    assert audit.events[-1].status == "denied"


@pytest.mark.asyncio
async def test_policy_require_approval_creates_approval_without_mcp_and_writes_audit() -> None:
    svc, _, approvals, audit, client = service(tool=definition(RiskLevel.HIGH, ActionType.READ))

    result = await svc.call_tool(agent(), request())

    assert result.status == ToolCallStatus.PENDING_APPROVAL
    assert result.approval_id == approvals.created[0].id
    assert approvals.created[0].status == ApprovalStatus.PENDING
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
async def test_missing_mcp_client_writes_failed_tool_call_and_audit_without_success() -> None:
    svc, tool_calls, _, audit, client = service(configured_mcp_client=False)

    result = await svc.call_tool(agent(), request())

    assert result.status == ToolCallStatus.FAILED
    assert result.error is not None
    assert result.error.code == "mcp_client_not_configured"
    assert tool_calls.created[-1].status == ToolCallStatus.FAILED
    assert tool_calls.created[-1].error_code == "mcp_client_not_configured"
    assert audit.events[-1].error_code == "mcp_client_not_configured"
    assert client.calls == []


@pytest.mark.asyncio
async def test_audit_written_for_tool_not_found() -> None:
    svc, _, _, audit, client = service(include_tool=False)

    with pytest.raises(ToolNotFoundError):
        await svc.call_tool(agent(), request())

    assert client.calls == []
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
    svc, _, _, _, client = service()
    first = await svc.call_tool(agent(), request(idempotency_key="idem-1"))
    second = await svc.call_tool(agent(), request(idempotency_key="idem-1"))

    assert first.tool_call_id == second.tool_call_id
    assert second.status == ToolCallStatus.SUCCEEDED
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

    assert not hasattr(app.state, "mcp_client")


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
