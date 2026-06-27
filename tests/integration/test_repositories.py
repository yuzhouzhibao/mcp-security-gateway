import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from mcp_security_gateway.application.services.agent_service import AgentService
from mcp_security_gateway.application.services.errors import (
    AgentDisabledError,
    AgentNameConflictError,
)
from mcp_security_gateway.application.services.policy_engine import PolicyService
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
        args={"mode": "readonly"},
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
