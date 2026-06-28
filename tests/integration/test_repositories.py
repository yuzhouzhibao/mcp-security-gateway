import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from mcp_security_gateway.application.ports.mcp_client import McpClient, McpToolMetadata
from mcp_security_gateway.application.services.agent_service import AgentDTO, AgentService
from mcp_security_gateway.application.services.approval_service import ApprovalService
from mcp_security_gateway.application.services.audit_service import AuditService
from mcp_security_gateway.application.services.errors import (
    AgentDisabledError,
    AgentNameConflictError,
    ApprovalAlreadyProcessedError,
    ToolDisabledError,
)
from mcp_security_gateway.application.services.policy_engine import PolicyService
from mcp_security_gateway.application.services.tool_call_service import (
    ToolCallRequest,
    ToolCallService,
)
from mcp_security_gateway.application.services.tool_registry_service import (
    ToolRegistryService,
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
from mcp_security_gateway.domain.policy import PolicyContext
from mcp_security_gateway.infrastructure.db.base import Base
from mcp_security_gateway.infrastructure.db.models import (
    AgentModel,
    ApprovalRequestModel,
    AuditEventModel,
    PolicyModel,
    TenantModel,
    ToolCallModel,
    ToolDefinitionModel,
    ToolServerModel,
    utc_now,
)
from mcp_security_gateway.infrastructure.db.repositories import (
    SQLAlchemyAgentRepository,
    SQLAlchemyApprovalRequestRepository,
    SQLAlchemyAuditEventRepository,
    SQLAlchemyPolicyRepository,
    SQLAlchemyTenantRepository,
    SQLAlchemyToolCallRepository,
    SQLAlchemyToolDefinitionRepository,
    SQLAlchemyToolServerRepository,
)
from tests.fakes.mcp_client import TestOnlyMcpClient

pytestmark = pytest.mark.integration


@pytest.fixture(scope="session")
def integration_database_url() -> str:
    database_url = os.environ.get("TEST_DATABASE_URL")
    if database_url is None:
        pytest.skip("TEST_DATABASE_URL must be set explicitly for PostgreSQL integration tests")
    blocked_scheme = "sql" + "ite"
    if database_url.startswith(blocked_scheme):
        pytest.fail("Integration tests require PostgreSQL")
    return database_url


@pytest.fixture(scope="session")
def engine(integration_database_url: str) -> Iterator[Engine]:
    schema_name = f"test_schema_{uuid4().hex}"
    bootstrap_engine = create_engine(integration_database_url, future=True)
    if bootstrap_engine.dialect.name != "postgresql":
        pytest.fail("Integration tests require PostgreSQL")
    with bootstrap_engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema_name}"'))
    bootstrap_engine.dispose()

    engine = create_engine(
        integration_database_url,
        future=True,
        connect_args={"options": f"-csearch_path={schema_name}"},
    )
    if engine.dialect.name != "postgresql":
        pytest.fail("Integration tests require PostgreSQL")
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()
    cleanup_engine = create_engine(integration_database_url, future=True)
    with cleanup_engine.begin() as connection:
        connection.execute(text(f'DROP SCHEMA "{schema_name}" CASCADE'))
    cleanup_engine.dispose()


@pytest.fixture
def db_session(engine: Engine) -> Iterator[Session]:
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        yield session
        session.rollback()


def create_tenant(session: Session, name: str = "tenant-alpha") -> TenantModel:
    tenant = TenantModel(name=name, status=EntityStatus.ACTIVE)
    SQLAlchemyTenantRepository(session).create(tenant)
    return tenant


def create_agent(
    session: Session,
    tenant_id: UUID,
    name: str = "agent-alpha",
    api_key_hash: str | None = None,
) -> AgentModel:
    resolved_api_key_hash = api_key_hash or f"hash-{name}-{tenant_id}"
    agent = AgentModel(
        tenant_id=tenant_id,
        name=name,
        role=AgentRole.AGENT,
        status=EntityStatus.ACTIVE,
        api_key_hash=resolved_api_key_hash,
    )
    SQLAlchemyAgentRepository(session).create(agent)
    return agent


def create_tool_server(session: Session, tenant_id: UUID) -> ToolServerModel:
    server = ToolServerModel(
        tenant_id=tenant_id,
        server_id="filesystem",
        name="Filesystem",
        transport_type=TransportType.STDIO,
        endpoint_url=None,
        command="mcp-filesystem",
        args=["--readonly"],
        env={"PROFILE": "test"},
        status=EntityStatus.ACTIVE,
    )
    SQLAlchemyToolServerRepository(session).create(server)
    return server


def create_tool_call(
    session: Session,
    tenant_id: UUID,
    agent_id: UUID,
    idempotency_key: str | None = None,
) -> ToolCallModel:
    tool_call = ToolCallModel(
        trace_id="trace-alpha",
        tenant_id=tenant_id,
        agent_id=agent_id,
        target_server="filesystem",
        target_tool="read_file",
        arguments_redacted={"path": "/workspace/example.txt"},
        arguments_hash="args-hash-alpha",
        tool_schema_hash=None,
        policy_decision=None,
        decision_reason=None,
        approval_id=None,
        status=ToolCallStatus.PENDING_APPROVAL,
        error_code=None,
        error_message=None,
        idempotency_key=idempotency_key,
    )
    SQLAlchemyToolCallRepository(session).create(tool_call)
    return tool_call


def create_tool_definition(
    session: Session,
    tenant_id: UUID,
    server_id: UUID,
    *,
    risk_level: RiskLevel = RiskLevel.LOW,
    action_type: ActionType = ActionType.READ,
    schema: dict[str, object] | None = None,
) -> ToolDefinitionModel:
    definition = ToolDefinitionModel(
        tenant_id=tenant_id,
        server_id=server_id,
        tool_name="read_file",
        description="Read file",
        input_schema=schema
        or {
            "type": "object",
            "required": ["path"],
            "properties": {"path": {"type": "string"}},
            "additionalProperties": False,
        },
        risk_level=risk_level,
        action_type=action_type,
        resource_patterns=None,
        status=EntityStatus.ACTIVE,
        schema_hash=f"schema-{risk_level.value}-{action_type.value}",
    )
    SQLAlchemyToolDefinitionRepository(session).create(definition)
    return definition


def tool_call_service(
    session: Session,
    mcp_client: McpClient,
) -> ToolCallService:
    approval_repository = SQLAlchemyApprovalRequestRepository(session)
    audit_service = AuditService(SQLAlchemyAuditEventRepository(session))
    return ToolCallService(
        tool_server_repository=SQLAlchemyToolServerRepository(session),
        tool_definition_repository=SQLAlchemyToolDefinitionRepository(session),
        tool_call_repository=SQLAlchemyToolCallRepository(session),
        approval_repository=approval_repository,
        policy_repository=SQLAlchemyPolicyRepository(session),
        audit_service=audit_service,
        approval_service=ApprovalService(
            approval_repository,
            900,
            tool_call_repository=SQLAlchemyToolCallRepository(session),
            audit_service=audit_service,
        ),
        mcp_client=mcp_client,
        mcp_call_timeout_seconds=5,
    )


def approval_service(session: Session) -> ApprovalService:
    return ApprovalService(
        SQLAlchemyApprovalRequestRepository(session),
        900,
        tool_call_repository=SQLAlchemyToolCallRepository(session),
        audit_service=AuditService(SQLAlchemyAuditEventRepository(session)),
    )


def agent_dto(agent_model: AgentModel) -> AgentDTO:
    return AgentDTO(
        id=agent_model.id,
        tenant_id=agent_model.tenant_id,
        name=agent_model.name,
        role=AgentRole(agent_model.role),
        status=EntityStatus(agent_model.status),
    )


def service_request(
    idempotency_key: str | None = None,
    arguments: dict[str, object] | None = None,
) -> ToolCallRequest:
    return ToolCallRequest(
        target_server="filesystem",
        target_tool="read_file",
        arguments=arguments or {"path": "/workspace/example.txt"},
        trace_id="trace-service",
        idempotency_key=idempotency_key,
    )


def test_create_tenant_and_agent(db_session: Session) -> None:
    tenant = create_tenant(db_session)
    agent = create_agent(db_session, tenant.id, api_key_hash="hash-agent-alpha")

    assert SQLAlchemyTenantRepository(db_session).get_by_id(tenant.id) == tenant
    assert SQLAlchemyAgentRepository(db_session).get_by_api_key_hash("hash-agent-alpha") == agent


def test_agent_unique_constraints(db_session: Session) -> None:
    tenant = create_tenant(db_session, "tenant-agent-unique")
    create_agent(db_session, tenant.id, api_key_hash="hash-agent-alpha")
    db_session.commit()

    with pytest.raises(IntegrityError):
        create_agent(db_session, tenant.id, api_key_hash="hash-agent-beta")
    db_session.rollback()

    with pytest.raises(IntegrityError):
        create_agent(db_session, tenant.id, name="agent-beta", api_key_hash="hash-agent-alpha")


def test_create_tool_server_and_definition_with_unique_constraint(db_session: Session) -> None:
    tenant = create_tenant(db_session, "tenant-tool-definition")
    server = create_tool_server(db_session, tenant.id)
    definition = ToolDefinitionModel(
        tenant_id=tenant.id,
        server_id=server.id,
        tool_name="read_file",
        description="Read a workspace file",
        input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
        risk_level=RiskLevel.LOW,
        action_type=ActionType.READ,
        resource_patterns={"paths": ["/workspace/*"]},
        status=EntityStatus.ACTIVE,
        schema_hash="schema-hash-alpha",
    )
    repository = SQLAlchemyToolDefinitionRepository(db_session)
    repository.create(definition)
    db_session.commit()

    assert (
        SQLAlchemyToolServerRepository(db_session).get_by_server_id(tenant.id, "filesystem")
        == server
    )
    assert repository.get_by_name(tenant.id, server.id, "read_file") == definition

    with pytest.raises(IntegrityError):
        repository.create(
            ToolDefinitionModel(
                tenant_id=tenant.id,
                server_id=server.id,
                tool_name="read_file",
                description=None,
                input_schema={"type": "object"},
                risk_level=RiskLevel.MEDIUM,
                action_type=ActionType.READ,
                resource_patterns=None,
                status=EntityStatus.ACTIVE,
                schema_hash="schema-hash-beta",
            )
        )


def test_create_policy(db_session: Session) -> None:
    tenant = create_tenant(db_session, "tenant-policy")
    policy = PolicyModel(
        tenant_id=tenant.id,
        name="read-policy",
        priority=100,
        effect=PolicyEffect.REQUIRE_APPROVAL,
        conditions={"tool": "read_file"},
        reason="Sensitive workspace access requires review",
        status=EntityStatus.ACTIVE,
    )
    repository = SQLAlchemyPolicyRepository(db_session)
    repository.create(policy)

    assert repository.get_by_id(policy.id) == policy


def test_tool_call_idempotency_partial_unique_index(db_session: Session) -> None:
    tenant = create_tenant(db_session, "tenant-tool-call")
    agent = create_agent(db_session, tenant.id)
    create_tool_call(db_session, tenant.id, agent.id, idempotency_key="idem-alpha")
    db_session.commit()

    with pytest.raises(IntegrityError):
        create_tool_call(db_session, tenant.id, agent.id, idempotency_key="idem-alpha")
    db_session.rollback()

    create_tool_call(db_session, tenant.id, agent.id, idempotency_key=None)
    create_tool_call(db_session, tenant.id, agent.id, idempotency_key=None)

    found = SQLAlchemyToolCallRepository(db_session).get_by_idempotency_key(
        tenant.id,
        agent.id,
        "idem-alpha",
    )
    assert found is not None


def test_approval_request_status_transition(db_session: Session) -> None:
    tenant = create_tenant(db_session, "tenant-approval")
    agent = create_agent(db_session, tenant.id)
    tool_call = create_tool_call(db_session, tenant.id, agent.id)
    approval = ApprovalRequestModel(
        tenant_id=tenant.id,
        agent_id=agent.id,
        tool_call_id=tool_call.id,
        target_server="filesystem",
        target_tool="read_file",
        arguments_redacted={"path": "/workspace/example.txt"},
        arguments_hash="args-hash-alpha",
        status=ApprovalStatus.PENDING,
        requested_reason="Review required",
        reviewer_id=None,
        review_reason=None,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        approved_at=None,
        denied_at=None,
        executed_at=None,
    )
    repository = SQLAlchemyApprovalRequestRepository(db_session)
    repository.create(approval)

    mismatch = repository.transition_status(
        approval.id,
        ApprovalStatus.APPROVED,
        ApprovalStatus.DENIED,
    )
    assert mismatch is None

    approved = repository.transition_status(
        approval.id,
        ApprovalStatus.PENDING,
        ApprovalStatus.APPROVED,
    )
    assert approved is not None
    assert approved.status == ApprovalStatus.APPROVED
    assert approved.version == 2

    executed = repository.transition_status(
        approval.id,
        ApprovalStatus.APPROVED,
        ApprovalStatus.EXECUTED,
    )
    assert executed is not None
    assert executed.status == ApprovalStatus.EXECUTED

    reverted = repository.transition_status(
        approval.id,
        ApprovalStatus.EXECUTED,
        ApprovalStatus.PENDING,
    )
    assert reverted is None


def test_append_audit_event_and_repository_has_no_mutators(db_session: Session) -> None:
    tenant = create_tenant(db_session, "tenant-audit")
    event = AuditEventModel(
        trace_id="trace-audit",
        tenant_id=tenant.id,
        agent_id=None,
        event_type="tool_call_recorded",
        target_server="filesystem",
        target_tool="read_file",
        arguments_redacted={"path": "/workspace/example.txt"},
        arguments_hash="args-hash-alpha",
        policy_decision=None,
        decision_reason=None,
        approval_id=None,
        status="recorded",
        error_code=None,
        error_message=None,
        metadata_json={"source": "integration-test"},
    )
    repository = SQLAlchemyAuditEventRepository(db_session)
    repository.append(event)

    assert repository.get_by_id(event.event_id) == event
    assert list(repository.list_by_tenant(tenant.id)) == [event]
    assert not hasattr(repository, "update")
    assert not hasattr(repository, "delete")


def test_agent_service_create_stores_only_hash_and_authenticates(db_session: Session) -> None:
    tenant = create_tenant(db_session, "tenant-service-create")
    service = AgentService(
        tenant_repository=SQLAlchemyTenantRepository(db_session),
        agent_repository=SQLAlchemyAgentRepository(db_session),
        api_key_pepper="test-api-key-pepper",
    )

    created = service.create_agent(tenant.id, "github-agent", AgentRole.AGENT)
    db_session.commit()
    stored = SQLAlchemyAgentRepository(db_session).get_by_id(created.agent.id)

    assert stored is not None
    assert stored.api_key_hash != created.api_key
    assert created.api_key not in stored.api_key_hash
    assert SQLAlchemyAgentRepository(db_session).get_by_api_key_hash(stored.api_key_hash) == stored
    assert service.authenticate_agent_by_api_key(created.api_key).id == created.agent.id


def test_agent_service_disable_blocks_authentication(db_session: Session) -> None:
    tenant = create_tenant(db_session, "tenant-service-disable")
    service = AgentService(
        tenant_repository=SQLAlchemyTenantRepository(db_session),
        agent_repository=SQLAlchemyAgentRepository(db_session),
        api_key_pepper="test-api-key-pepper",
    )
    created = service.create_agent(tenant.id, "github-agent", AgentRole.AGENT)
    disabled = service.disable_agent(created.agent.id)

    assert disabled.status == EntityStatus.DISABLED
    with pytest.raises(AgentDisabledError):
        service.authenticate_agent_by_api_key(created.api_key)


def test_agent_service_converts_unique_violation_to_conflict(db_session: Session) -> None:
    tenant = create_tenant(db_session, "tenant-service-conflict")
    service = AgentService(
        tenant_repository=SQLAlchemyTenantRepository(db_session),
        agent_repository=SQLAlchemyAgentRepository(db_session),
        api_key_pepper="test-api-key-pepper",
    )
    service.create_agent(tenant.id, "github-agent", AgentRole.AGENT)

    with pytest.raises(AgentNameConflictError):
        service.create_agent(tenant.id, "github-agent", AgentRole.AGENT)


def policy_context(tenant_id: UUID, agent_id: UUID, target_tool: str) -> PolicyContext:
    return PolicyContext(
        tenant_id=tenant_id,
        agent_id=agent_id,
        role=AgentRole.AGENT,
        target_server="github-main",
        target_tool=target_tool,
        risk_level=RiskLevel.MEDIUM,
        action_type=ActionType.WRITE,
        arguments={"repo": "acme/widget", "dry_run": True},
        resource="repo:acme/widget",
        current_time=datetime.now(UTC),
    )


def read_policy_context(tenant_id: UUID, agent_id: UUID, target_tool: str) -> PolicyContext:
    return PolicyContext(
        tenant_id=tenant_id,
        agent_id=agent_id,
        role=AgentRole.AGENT,
        target_server="github-main",
        target_tool=target_tool,
        risk_level=RiskLevel.LOW,
        action_type=ActionType.READ,
        arguments={"repo": "acme/widget", "issue_number": 42},
        resource="repo:acme/widget",
        current_time=datetime.now(UTC),
    )


def create_policy(
    session: Session,
    tenant_id: UUID,
    name: str,
    priority: int,
    effect: PolicyEffect,
    conditions: dict[str, object],
    status: EntityStatus = EntityStatus.ACTIVE,
) -> PolicyModel:
    policy_model = PolicyModel(
        tenant_id=tenant_id,
        name=name,
        priority=priority,
        effect=effect,
        conditions=conditions,
        reason=f"{name} reason",
        status=status,
    )
    SQLAlchemyPolicyRepository(session).create(policy_model)
    return policy_model


def test_policy_repository_lists_only_active_ordered(db_session: Session) -> None:
    tenant = create_tenant(db_session, "tenant-policy-order")
    create_policy(db_session, tenant.id, "later", 20, PolicyEffect.ALLOW, {})
    create_policy(
        db_session,
        tenant.id,
        "disabled",
        1,
        PolicyEffect.DENY,
        {},
        EntityStatus.DISABLED,
    )
    create_policy(db_session, tenant.id, "earlier", 10, PolicyEffect.ALLOW, {})

    policies = SQLAlchemyPolicyRepository(db_session).list_active_by_tenant_ordered(tenant.id)

    assert [policy.name for policy in policies] == ["earlier", "later"]


def test_policy_service_uses_priority_order_from_database(db_session: Session) -> None:
    tenant = create_tenant(db_session, "tenant-policy-priority")
    agent = create_agent(db_session, tenant.id)
    deny_policy = create_policy(
        db_session,
        tenant.id,
        "deny-first",
        1,
        PolicyEffect.DENY,
        {"tool_names": ["github.update_issue"]},
    )
    create_policy(
        db_session,
        tenant.id,
        "allow-second",
        20,
        PolicyEffect.ALLOW,
        {"tool_names": ["github.update_issue"]},
    )

    result = PolicyService(SQLAlchemyPolicyRepository(db_session)).evaluate(
        policy_context(tenant.id, agent.id, "github.update_issue")
    )

    assert result.decision == PolicyEffect.DENY
    assert result.matched_policy_id == deny_policy.id


def test_disabled_policy_does_not_participate_in_evaluation(db_session: Session) -> None:
    tenant = create_tenant(db_session, "tenant-policy-disabled")
    agent = create_agent(db_session, tenant.id)
    create_policy(
        db_session,
        tenant.id,
        "disabled-deny",
        1,
        PolicyEffect.DENY,
        {"tool_names": ["github.update_issue"]},
        EntityStatus.DISABLED,
    )
    create_policy(
        db_session,
        tenant.id,
        "active-allow",
        10,
        PolicyEffect.ALLOW,
        {"tool_names": ["github.update_issue"]},
    )

    result = PolicyService(SQLAlchemyPolicyRepository(db_session)).evaluate(
        policy_context(tenant.id, agent.id, "github.update_issue")
    )

    assert result.decision == PolicyEffect.ALLOW


def test_active_allow_policy_allows_medium_write(db_session: Session) -> None:
    tenant = create_tenant(db_session, "tenant-policy-allow")
    agent = create_agent(db_session, tenant.id)
    create_policy(
        db_session,
        tenant.id,
        "allow-medium-write",
        10,
        PolicyEffect.ALLOW,
        {"risk_levels": ["medium"], "action_types": ["write"]},
    )

    result = PolicyService(SQLAlchemyPolicyRepository(db_session)).evaluate(
        policy_context(tenant.id, agent.id, "github.update_issue")
    )

    assert result.decision == PolicyEffect.ALLOW


def test_active_deny_policy_rejects_specific_tool(db_session: Session) -> None:
    tenant = create_tenant(db_session, "tenant-policy-deny")
    agent = create_agent(db_session, tenant.id)
    create_policy(
        db_session,
        tenant.id,
        "deny-tool",
        10,
        PolicyEffect.DENY,
        {"tool_names": ["github.update_issue"]},
    )

    result = PolicyService(SQLAlchemyPolicyRepository(db_session)).evaluate(
        policy_context(tenant.id, agent.id, "github.update_issue")
    )

    assert result.decision == PolicyEffect.DENY
    assert result.reason == "deny-tool reason"


def test_policy_parse_error_from_database_fails_closed(db_session: Session) -> None:
    tenant = create_tenant(db_session, "tenant-policy-parse-error")
    agent = create_agent(db_session, tenant.id)
    create_policy(
        db_session,
        tenant.id,
        "bad-policy",
        10,
        PolicyEffect.ALLOW,
        {"unknown_condition": ["value"]},
    )

    result = PolicyService(SQLAlchemyPolicyRepository(db_session)).evaluate(
        policy_context(tenant.id, agent.id, "github.update_issue")
    )

    assert result.decision == PolicyEffect.DENY
    assert result.reason == "policy evaluation failed closed"


def test_configured_deny_overrides_builtin_low_risk_read_allow_from_database(
    db_session: Session,
) -> None:
    tenant = create_tenant(db_session, "tenant-policy-low-risk-deny")
    agent = create_agent(db_session, tenant.id)
    policy_model = create_policy(
        db_session,
        tenant.id,
        "deny-low-risk-read",
        10,
        PolicyEffect.DENY,
        {"tool_names": ["github.get_issue"]},
    )

    result = PolicyService(SQLAlchemyPolicyRepository(db_session)).evaluate(
        read_policy_context(tenant.id, agent.id, "github.get_issue")
    )

    assert result.decision == PolicyEffect.DENY
    assert result.matched_policy_id == policy_model.id


@pytest.mark.asyncio
async def test_tool_call_gateway_success_creates_tool_call_and_audit(
    db_session: Session,
) -> None:
    tenant = create_tenant(db_session, "tenant-gateway-success")
    agent_model = create_agent(db_session, tenant.id)
    server = create_tool_server(db_session, tenant.id)
    create_tool_definition(db_session, tenant.id, server.id)
    client = TestOnlyMcpClient(result={"content": "ok"})

    result = await tool_call_service(db_session, client).call_tool(
        agent_dto(agent_model),
        service_request(),
    )

    tool_calls = SQLAlchemyToolCallRepository(db_session).list_by_tenant(tenant.id)
    audit_events = SQLAlchemyAuditEventRepository(db_session).list_by_tenant(tenant.id)
    assert result.status == ToolCallStatus.SUCCEEDED
    assert len(client.calls) == 1
    assert len(tool_calls) == 1
    assert tool_calls[0].status == ToolCallStatus.SUCCEEDED
    assert len(audit_events) == 1
    assert audit_events[0].status == "succeeded"


@pytest.mark.asyncio
async def test_tool_call_gateway_deny_creates_tool_call_and_audit(
    db_session: Session,
) -> None:
    tenant = create_tenant(db_session, "tenant-gateway-deny")
    agent_model = create_agent(db_session, tenant.id)
    server = create_tool_server(db_session, tenant.id)
    create_tool_definition(db_session, tenant.id, server.id, risk_level=RiskLevel.CRITICAL)
    client = TestOnlyMcpClient()

    result = await tool_call_service(db_session, client).call_tool(
        agent_dto(agent_model),
        service_request(),
    )

    tool_calls = SQLAlchemyToolCallRepository(db_session).list_by_tenant(tenant.id)
    audit_events = SQLAlchemyAuditEventRepository(db_session).list_by_tenant(tenant.id)
    assert result.status == ToolCallStatus.DENIED
    assert client.calls == []
    assert len(tool_calls) == 1
    assert tool_calls[0].status == ToolCallStatus.DENIED
    assert len(audit_events) == 1
    assert audit_events[0].status == "denied"


@pytest.mark.asyncio
async def test_tool_call_gateway_pending_approval_creates_rows(
    db_session: Session,
) -> None:
    tenant = create_tenant(db_session, "tenant-gateway-approval")
    agent_model = create_agent(db_session, tenant.id)
    server = create_tool_server(db_session, tenant.id)
    create_tool_definition(db_session, tenant.id, server.id, risk_level=RiskLevel.HIGH)
    client = TestOnlyMcpClient()

    result = await tool_call_service(db_session, client).call_tool(
        agent_dto(agent_model),
        service_request(),
    )

    tool_calls = SQLAlchemyToolCallRepository(db_session).list_by_tenant(tenant.id)
    approvals = SQLAlchemyApprovalRequestRepository(db_session).list_by_tenant(tenant.id)
    audit_events = SQLAlchemyAuditEventRepository(db_session).list_by_tenant(tenant.id)
    assert result.status == ToolCallStatus.PENDING_APPROVAL
    assert result.approval_id is not None
    assert client.calls == []
    assert len(tool_calls) == 1
    assert tool_calls[0].approval_id == result.approval_id
    assert len(approvals) == 1
    assert approvals[0].status == ApprovalStatus.PENDING
    assert len(audit_events) == 1
    assert audit_events[0].approval_id == result.approval_id


@pytest.mark.asyncio
async def test_tool_call_gateway_audits_schema_invalid_and_tool_not_found(
    db_session: Session,
) -> None:
    from mcp_security_gateway.application.services.errors import (
        ArgumentSchemaInvalidError,
        ToolNotFoundError,
    )

    tenant = create_tenant(db_session, "tenant-gateway-failures")
    agent_model = create_agent(db_session, tenant.id)
    server = create_tool_server(db_session, tenant.id)
    create_tool_definition(db_session, tenant.id, server.id)
    client = TestOnlyMcpClient()
    service = tool_call_service(db_session, client)

    with pytest.raises(ArgumentSchemaInvalidError):
        await service.call_tool(agent_dto(agent_model), service_request(arguments={"path": 123}))
    with pytest.raises(ToolNotFoundError):
        await service.call_tool(
            agent_dto(agent_model),
            ToolCallRequest(
                target_server="filesystem",
                target_tool="missing_tool",
                arguments={"path": "/workspace/example.txt"},
                trace_id="trace-missing-tool",
                idempotency_key=None,
            ),
        )

    audit_events = SQLAlchemyAuditEventRepository(db_session).list_by_tenant(tenant.id)
    assert [event.error_code for event in audit_events] == [
        "argument_schema_invalid",
        "tool_not_found",
    ]
    assert client.calls == []


@pytest.mark.asyncio
async def test_tool_call_gateway_idempotency_reuses_success_and_avoids_duplicate_upstream(
    db_session: Session,
) -> None:
    tenant = create_tenant(db_session, "tenant-gateway-idempotency")
    agent_model = create_agent(db_session, tenant.id)
    server = create_tool_server(db_session, tenant.id)
    create_tool_definition(db_session, tenant.id, server.id)
    client = TestOnlyMcpClient()
    service = tool_call_service(db_session, client)

    first = await service.call_tool(agent_dto(agent_model), service_request("idem-service"))
    second = await service.call_tool(agent_dto(agent_model), service_request("idem-service"))

    tool_calls = SQLAlchemyToolCallRepository(db_session).list_by_tenant(tenant.id)
    assert first.tool_call_id == second.tool_call_id
    assert len(tool_calls) == 1
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_tool_call_gateway_raw_secret_not_stored_in_audit_or_tool_call(
    db_session: Session,
) -> None:
    tenant = create_tenant(db_session, "tenant-gateway-secret")
    agent_model = create_agent(db_session, tenant.id)
    server = create_tool_server(db_session, tenant.id)
    create_tool_definition(
        db_session,
        tenant.id,
        server.id,
        schema={
            "type": "object",
            "properties": {"authorization": {"type": "string"}},
        },
    )
    secret_value = "Bearer integration-sensitive-value"

    result = await tool_call_service(db_session, TestOnlyMcpClient()).call_tool(
        agent_dto(agent_model),
        service_request(arguments={"authorization": secret_value}),
    )

    tool_call = SQLAlchemyToolCallRepository(db_session).list_by_tenant(tenant.id)[0]
    audit_event = SQLAlchemyAuditEventRepository(db_session).list_by_tenant(tenant.id)[0]
    assert result.status == ToolCallStatus.DENIED
    assert secret_value not in repr(tool_call.arguments_redacted)
    assert secret_value not in repr(audit_event.arguments_redacted)
    assert tool_call.arguments_hash is not None
    assert audit_event.arguments_hash is not None


async def create_pending_approval_with_service(
    session: Session,
    tenant_name: str,
    client: TestOnlyMcpClient,
    arguments: dict[str, object] | None = None,
) -> tuple[TenantModel, AgentModel, ApprovalRequestModel, ToolCallService]:
    tenant = create_tenant(session, tenant_name)
    agent_model = create_agent(session, tenant.id)
    server = create_tool_server(session, tenant.id)
    create_tool_definition(session, tenant.id, server.id, risk_level=RiskLevel.HIGH)
    service = tool_call_service(session, client)
    pending = await service.call_tool(
        agent_dto(agent_model),
        service_request(arguments=arguments),
    )
    assert pending.approval_id is not None
    approval = SQLAlchemyApprovalRequestRepository(session).get_by_id(pending.approval_id)
    assert approval is not None
    return tenant, agent_model, approval, service


@pytest.mark.asyncio
async def test_approval_approve_persists_executed_statuses(db_session: Session) -> None:
    tenant, _, approval, service = await create_pending_approval_with_service(
        db_session,
        "tenant-approval-executed",
        TestOnlyMcpClient(result={"ok": True}),
    )

    result = await approval_service(db_session).approve_approval(
        approval_id=approval.id,
        review_reason="Looks safe",
        tool_call_service=service,
    )

    stored_approval = SQLAlchemyApprovalRequestRepository(db_session).get_by_id(approval.id)
    stored_tool_call = SQLAlchemyToolCallRepository(db_session).get_by_id(approval.tool_call_id)
    audit_events = SQLAlchemyAuditEventRepository(db_session).list_by_tenant(tenant.id)
    assert result.status == ApprovalStatus.EXECUTED
    assert stored_approval is not None
    assert stored_approval.status == ApprovalStatus.EXECUTED
    assert stored_tool_call is not None
    assert stored_tool_call.status == ToolCallStatus.SUCCEEDED
    assert stored_tool_call.arguments_payload is None
    assert [event.status for event in audit_events][-2:] == ["approved", "executed"]


@pytest.mark.asyncio
async def test_approval_deny_persists_denied_status(db_session: Session) -> None:
    tenant, _, approval, _ = await create_pending_approval_with_service(
        db_session,
        "tenant-approval-denied",
        TestOnlyMcpClient(),
    )

    result = approval_service(db_session).deny_approval(
        approval_id=approval.id,
        review_reason="Too risky",
    )

    stored_approval = SQLAlchemyApprovalRequestRepository(db_session).get_by_id(approval.id)
    stored_tool_call = SQLAlchemyToolCallRepository(db_session).get_by_id(approval.tool_call_id)
    audit_events = SQLAlchemyAuditEventRepository(db_session).list_by_tenant(tenant.id)
    assert result.status == ApprovalStatus.DENIED
    assert stored_approval is not None
    assert stored_approval.status == ApprovalStatus.DENIED
    assert stored_tool_call is not None
    assert stored_tool_call.status == ToolCallStatus.DENIED
    assert stored_tool_call.arguments_payload is None
    assert audit_events[-1].status == "denied"


@pytest.mark.asyncio
async def test_approval_expiration_persists_without_execution(db_session: Session) -> None:
    tenant, _, approval, service = await create_pending_approval_with_service(
        db_session,
        "tenant-approval-expired",
        TestOnlyMcpClient(),
    )
    approval.expires_at = utc_now() - timedelta(seconds=1)

    result = await approval_service(db_session).approve_approval(
        approval_id=approval.id,
        review_reason="Looks safe",
        tool_call_service=service,
    )

    stored_approval = SQLAlchemyApprovalRequestRepository(db_session).get_by_id(approval.id)
    audit_events = SQLAlchemyAuditEventRepository(db_session).list_by_tenant(tenant.id)
    assert result.status == ApprovalStatus.EXPIRED
    assert stored_approval is not None
    assert stored_approval.status == ApprovalStatus.EXPIRED
    stored_tool_call = SQLAlchemyToolCallRepository(db_session).get_by_id(approval.tool_call_id)
    assert stored_tool_call is not None
    assert stored_tool_call.arguments_payload is None
    assert audit_events[-1].error_code == "approval_expired"


def test_approval_conditional_update_mismatch_fails(db_session: Session) -> None:
    tenant = create_tenant(db_session, "tenant-approval-conditional")
    agent_model = create_agent(db_session, tenant.id)
    tool_call = create_tool_call(db_session, tenant.id, agent_model.id)
    approval = ApprovalRequestModel(
        tenant_id=tenant.id,
        agent_id=agent_model.id,
        tool_call_id=tool_call.id,
        target_server="filesystem",
        target_tool="read_file",
        arguments_redacted={"path": "/workspace/example.txt"},
        arguments_hash="args-hash-conditional",
        status=ApprovalStatus.PENDING,
        requested_reason="Review required",
        reviewer_id=None,
        review_reason=None,
        expires_at=utc_now() + timedelta(minutes=10),
        approved_at=None,
        denied_at=None,
        executed_at=None,
    )
    repository = SQLAlchemyApprovalRequestRepository(db_session)
    repository.create(approval)

    mismatch = repository.transition_status(
        approval.id,
        ApprovalStatus.APPROVED,
        ApprovalStatus.EXECUTED,
    )

    assert mismatch is None
    stored = repository.get_by_id(approval.id)
    assert stored is not None
    assert stored.status == ApprovalStatus.PENDING


@pytest.mark.asyncio
async def test_double_approve_cannot_execute_twice(db_session: Session) -> None:
    client = TestOnlyMcpClient()
    _, _, approval, service = await create_pending_approval_with_service(
        db_session,
        "tenant-approval-double-execute",
        client,
    )
    approvals = approval_service(db_session)
    first = await approvals.approve_approval(
        approval_id=approval.id,
        review_reason="Looks safe",
        tool_call_service=service,
    )

    with pytest.raises(ApprovalAlreadyProcessedError):
        await approvals.approve_approval(
            approval_id=approval.id,
            review_reason="Again",
            tool_call_service=service,
        )

    assert first.status == ApprovalStatus.EXECUTED
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_execution_payload_is_stored_only_on_tool_call(db_session: Session) -> None:
    _, _, approval, _ = await create_pending_approval_with_service(
        db_session,
        "tenant-approval-payload-storage",
        TestOnlyMcpClient(),
    )
    tool_call = SQLAlchemyToolCallRepository(db_session).get_by_id(approval.tool_call_id)

    assert tool_call is not None
    assert tool_call.arguments_payload == {"path": "/workspace/example.txt"}
    assert not hasattr(approval, "arguments_payload")


@pytest.mark.asyncio
async def test_approval_audit_never_stores_payload_secret(db_session: Session) -> None:
    secret_value = "payload-sensitive-value"
    tenant = create_tenant(db_session, "tenant-approval-secret-audit")
    agent_model = create_agent(db_session, tenant.id)
    server = create_tool_server(db_session, tenant.id)
    create_tool_definition(
        db_session,
        tenant.id,
        server.id,
        schema={
            "type": "object",
            "properties": {"path": {"type": "string"}, "session": {"type": "string"}},
        },
    )
    tool_call = create_tool_call(db_session, tenant.id, agent_model.id)
    tool_call.arguments_payload = {
        "path": "/workspace/example.txt",
        "session": secret_value,
    }
    approval = ApprovalRequestModel(
        tenant_id=tenant.id,
        agent_id=agent_model.id,
        tool_call_id=tool_call.id,
        target_server="filesystem",
        target_tool="read_file",
        arguments_redacted={"path": "/workspace/example.txt", "session": "[REDACTED]"},
        arguments_hash="args-hash-secret-approval",
        status=ApprovalStatus.PENDING,
        requested_reason="Review required",
        reviewer_id=None,
        review_reason=None,
        expires_at=utc_now() + timedelta(minutes=10),
        approved_at=None,
        denied_at=None,
        executed_at=None,
    )
    SQLAlchemyApprovalRequestRepository(db_session).create(approval)

    result = await approval_service(db_session).approve_approval(
        approval_id=approval.id,
        review_reason="Looks safe",
        tool_call_service=tool_call_service(db_session, TestOnlyMcpClient()),
    )

    audit_events = SQLAlchemyAuditEventRepository(db_session).list_by_tenant(tenant.id)
    assert result.status == ApprovalStatus.EXECUTED
    assert secret_value not in repr(audit_events)
    stored_tool_call = SQLAlchemyToolCallRepository(db_session).get_by_id(approval.tool_call_id)
    assert stored_tool_call is not None
    assert stored_tool_call.arguments_payload is None


def registry_service(session: Session, client: TestOnlyMcpClient) -> ToolRegistryService:
    return ToolRegistryService(
        tenant_repository=SQLAlchemyTenantRepository(session),
        tool_server_repository=SQLAlchemyToolServerRepository(session),
        tool_definition_repository=SQLAlchemyToolDefinitionRepository(session),
        mcp_client=client,
        mcp_call_timeout_seconds=5,
    )


def test_create_and_list_tool_server_persisted(db_session: Session) -> None:
    tenant = create_tenant(db_session, "tenant-registry-server")
    server = create_tool_server(db_session, tenant.id)

    servers = SQLAlchemyToolServerRepository(db_session).list_by_tenant(tenant.id)

    assert servers == [server]
    assert servers[0].args == ["--readonly"]


@pytest.mark.asyncio
async def test_registry_discovery_upserts_definitions_and_updates_schema_hash(
    db_session: Session,
) -> None:
    tenant = create_tenant(db_session, "tenant-registry-upsert")
    create_tool_server(db_session, tenant.id)
    client = TestOnlyMcpClient(
        tools=[
            McpToolMetadata(
                name="read_file",
                description="Read file",
                input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
            )
        ]
    )
    service = registry_service(db_session, client)

    first = await service.refresh_tools(tenant_id=tenant.id, server_id="filesystem")
    first_hash = first[0].schema_hash
    client.set_tools(
        [
            McpToolMetadata(
                name="read_file",
                description="Read file v2",
                input_schema={"type": "object", "properties": {"path": {"minLength": 1}}},
            )
        ]
    )
    second = await service.refresh_tools(tenant_id=tenant.id, server_id="filesystem")

    assert len(SQLAlchemyToolDefinitionRepository(db_session).list_by_tenant(tenant.id)) == 1
    assert second[0].schema_hash != first_hash
    assert second[0].description == "Read file v2"


@pytest.mark.asyncio
async def test_registry_discovery_does_not_override_manual_classification(
    db_session: Session,
) -> None:
    tenant = create_tenant(db_session, "tenant-registry-classification")
    create_tool_server(db_session, tenant.id)
    client = TestOnlyMcpClient(
        tools=[
            McpToolMetadata(
                name="read_file",
                description="Read file",
                input_schema={"type": "object"},
            )
        ]
    )
    service = registry_service(db_session, client)
    discovered = (await service.refresh_tools(tenant_id=tenant.id, server_id="filesystem"))[0]
    discovered.risk_level = RiskLevel.LOW
    discovered.action_type = ActionType.READ
    discovered.status = EntityStatus.ACTIVE
    SQLAlchemyToolDefinitionRepository(db_session).update(discovered)

    refreshed = await service.refresh_tools(tenant_id=tenant.id, server_id="filesystem")

    assert refreshed[0].risk_level == RiskLevel.LOW
    assert refreshed[0].action_type == ActionType.READ
    assert refreshed[0].status == EntityStatus.ACTIVE


@pytest.mark.asyncio
async def test_registry_discovery_failure_does_not_upsert_or_override_manual_classification(
    db_session: Session,
) -> None:
    tenant = create_tenant(db_session, "tenant-registry-discovery-failure")
    server = create_tool_server(db_session, tenant.id)
    definition = create_tool_definition(db_session, tenant.id, server.id)
    definition.risk_level = RiskLevel.LOW
    definition.action_type = ActionType.READ
    definition.status = EntityStatus.ACTIVE
    client = TestOnlyMcpClient(failure="failed")

    from mcp_security_gateway.application.services.errors import McpToolListFailedError

    with pytest.raises(McpToolListFailedError) as captured:
        await registry_service(db_session, client).refresh_tools(
            tenant_id=tenant.id,
            server_id="filesystem",
        )

    stored = SQLAlchemyToolDefinitionRepository(db_session).get_by_id(definition.id)
    assert captured.value.code == "mcp_tool_list_failed"
    assert stored is not None
    assert stored.risk_level == RiskLevel.LOW
    assert stored.action_type == ActionType.READ
    assert stored.status == EntityStatus.ACTIVE
    assert len(SQLAlchemyToolDefinitionRepository(db_session).list_by_tenant(tenant.id)) == 1


@pytest.mark.asyncio
async def test_disabled_discovered_tool_cannot_be_called_by_gateway(
    db_session: Session,
) -> None:
    tenant = create_tenant(db_session, "tenant-registry-disabled-tool")
    agent_model = create_agent(db_session, tenant.id)
    create_tool_server(db_session, tenant.id)
    client = TestOnlyMcpClient(
        tools=[
            McpToolMetadata(
                name="read_file",
                description="Read file",
                input_schema={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                },
            )
        ]
    )
    await registry_service(db_session, client).refresh_tools(
        tenant_id=tenant.id,
        server_id="filesystem",
    )

    with pytest.raises(ToolDisabledError):
        await tool_call_service(db_session, client).call_tool(
            agent_dto(agent_model),
            service_request(),
        )

    assert client.calls == []


@pytest.mark.asyncio
async def test_active_classified_tool_can_be_called_with_injected_client(
    db_session: Session,
) -> None:
    tenant = create_tenant(db_session, "tenant-registry-active-tool")
    agent_model = create_agent(db_session, tenant.id)
    server = create_tool_server(db_session, tenant.id)
    definition = create_tool_definition(db_session, tenant.id, server.id)
    definition.risk_level = RiskLevel.LOW
    definition.action_type = ActionType.READ
    definition.status = EntityStatus.ACTIVE
    client = TestOnlyMcpClient(result={"ok": True})

    result = await tool_call_service(db_session, client).call_tool(
        agent_dto(agent_model),
        service_request(),
    )

    assert result.status == ToolCallStatus.SUCCEEDED
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_streamable_http_call_returns_transport_not_supported_and_audit_failed(
    db_session: Session,
) -> None:
    from mcp_security_gateway.infrastructure.mcp.stdio_client import StdioMcpClient

    tenant = create_tenant(db_session, "tenant-streamable-http")
    agent_model = create_agent(db_session, tenant.id)
    server = ToolServerModel(
        tenant_id=tenant.id,
        server_id="remote-main",
        name="Remote",
        transport_type=TransportType.STREAMABLE_HTTP,
        endpoint_url="https://example.invalid/mcp",
        command=None,
        args=None,
        env={"GITHUB_TOKEN": "streamable-secret"},
        status=EntityStatus.ACTIVE,
    )
    SQLAlchemyToolServerRepository(db_session).create(server)
    SQLAlchemyToolDefinitionRepository(db_session).create(
        ToolDefinitionModel(
            tenant_id=tenant.id,
            server_id=server.id,
            tool_name="read_file",
            description="Read file",
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "additionalProperties": False,
            },
            risk_level=RiskLevel.LOW,
            action_type=ActionType.READ,
            resource_patterns=None,
            status=EntityStatus.ACTIVE,
            schema_hash="schema-streamable",
        )
    )

    result = await tool_call_service(db_session, StdioMcpClient()).call_tool(
        agent_dto(agent_model),
        ToolCallRequest(
            target_server="remote-main",
            target_tool="read_file",
            arguments={"path": "/workspace/example.txt"},
            trace_id="trace-streamable",
            idempotency_key=None,
        ),
    )

    audit_event = SQLAlchemyAuditEventRepository(db_session).list_by_tenant(tenant.id)[0]
    assert result.status == ToolCallStatus.FAILED
    assert result.error is not None
    assert result.error.code == "transport_not_supported_yet"
    assert audit_event.error_code == "transport_not_supported_yet"
    assert "streamable-secret" not in repr(audit_event)
