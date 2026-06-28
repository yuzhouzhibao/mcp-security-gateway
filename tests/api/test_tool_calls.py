import os
from collections.abc import Iterator
from datetime import timedelta
from typing import cast
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, select, text
from sqlalchemy.orm import Session, sessionmaker

from mcp_security_gateway.api.dependencies import get_db_session
from mcp_security_gateway.domain.enums import (
    ActionType,
    EntityStatus,
    RiskLevel,
    TransportType,
)
from mcp_security_gateway.infrastructure.db.base import Base
from mcp_security_gateway.infrastructure.db.models import (
    ApprovalRequestModel,
    TenantModel,
    ToolDefinitionModel,
    ToolServerModel,
    utc_now,
)
from mcp_security_gateway.infrastructure.db.repositories import (
    SQLAlchemyTenantRepository,
    SQLAlchemyToolDefinitionRepository,
    SQLAlchemyToolServerRepository,
)
from mcp_security_gateway.main import create_app
from mcp_security_gateway.settings import Settings
from tests.fakes.mcp_client import TestOnlyMcpClient

pytestmark = pytest.mark.integration


@pytest.fixture(scope="session")
def tool_call_api_database_url() -> str:
    database_url = os.environ.get("TEST_DATABASE_URL")
    if database_url is None:
        pytest.skip("TEST_DATABASE_URL must be set explicitly for PostgreSQL API tests")
    blocked_scheme = "sql" + "ite"
    if database_url.startswith(blocked_scheme):
        pytest.fail("API tests require PostgreSQL")
    return database_url


@pytest.fixture(scope="session")
def tool_call_api_engine(tool_call_api_database_url: str) -> Iterator[Engine]:
    schema_name = f"api_tool_call_schema_{uuid4().hex}"
    bootstrap_engine = create_engine(tool_call_api_database_url, future=True)
    if bootstrap_engine.dialect.name != "postgresql":
        pytest.fail("API tests require PostgreSQL")
    with bootstrap_engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema_name}"'))
    bootstrap_engine.dispose()

    engine = create_engine(
        tool_call_api_database_url,
        future=True,
        connect_args={"options": f"-csearch_path={schema_name}"},
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()
    cleanup_engine = create_engine(tool_call_api_database_url, future=True)
    with cleanup_engine.begin() as connection:
        connection.execute(text(f'DROP SCHEMA "{schema_name}" CASCADE'))
    cleanup_engine.dispose()


@pytest.fixture
def tool_call_api_session(tool_call_api_engine: Engine) -> Iterator[Session]:
    factory = sessionmaker(bind=tool_call_api_engine, expire_on_commit=False)
    with factory() as session:
        yield session
        session.rollback()


@pytest.fixture
def mcp_client() -> TestOnlyMcpClient:
    return TestOnlyMcpClient(result={"ok": True})


@pytest.fixture
def client(
    test_settings: Settings,
    tool_call_api_session: Session,
    mcp_client: TestOnlyMcpClient,
) -> TestClient:
    app = create_app(test_settings)
    app.state.mcp_client = mcp_client

    def override_session() -> Iterator[Session]:
        yield tool_call_api_session

    app.dependency_overrides[get_db_session] = override_session
    return TestClient(app)


def admin_headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-admin-key"}


def create_tenant(session: Session, name: str) -> TenantModel:
    tenant = TenantModel(name=name, status=EntityStatus.ACTIVE)
    SQLAlchemyTenantRepository(session).create(tenant)
    session.commit()
    return tenant


def create_agent(
    client: TestClient,
    tenant: TenantModel,
    name: str = "github-agent",
) -> dict[str, str]:
    response = client.post(
        "/v1/admin/agents",
        json={"tenant_id": str(tenant.id), "name": name, "role": "agent"},
        headers=admin_headers(),
    )
    assert response.status_code == 201
    return cast(dict[str, str], response.json())


def create_tool(
    session: Session,
    tenant: TenantModel,
    *,
    risk_level: RiskLevel = RiskLevel.LOW,
    action_type: ActionType = ActionType.READ,
    tool_name: str = "github.get_issue",
) -> ToolDefinitionModel:
    server = ToolServerModel(
        tenant_id=tenant.id,
        server_id="github-main",
        name="GitHub",
        transport_type=TransportType.STREAMABLE_HTTP,
        endpoint_url="https://example.invalid",
        command=None,
        args=None,
        env=None,
        status=EntityStatus.ACTIVE,
    )
    SQLAlchemyToolServerRepository(session).create(server)
    definition = ToolDefinitionModel(
        tenant_id=tenant.id,
        server_id=server.id,
        tool_name=tool_name,
        description=None,
        input_schema={
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
        schema_hash=f"schema-{tool_name}",
    )
    SQLAlchemyToolDefinitionRepository(session).create(definition)
    session.commit()
    return definition


def call_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


def payload(idempotency_key: str | None = None, issue_number: int | str = 123) -> dict[str, object]:
    data: dict[str, object] = {
        "target_server": "github-main",
        "target_tool": "github.get_issue",
        "arguments": {"repo": "acme/api", "issue_number": issue_number},
        "trace_id": "trace-api",
    }
    if idempotency_key is not None:
        data["idempotency_key"] = idempotency_key
    return data


def test_tool_calls_require_agent_auth(client: TestClient) -> None:
    response = client.post("/v1/tool-calls", json=payload())

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"


def test_disabled_agent_is_forbidden(
    client: TestClient,
    tool_call_api_session: Session,
) -> None:
    tenant = create_tenant(tool_call_api_session, "tenant-disabled-api")
    agent = create_agent(client, tenant)
    create_tool(tool_call_api_session, tenant)
    client.post(f"/v1/admin/agents/{agent['id']}/disable", headers=admin_headers())

    response = client.post(
        "/v1/tool-calls",
        json=payload(),
        headers=call_headers(agent["api_key"]),
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "agent_disabled"


def test_missing_tool_server_and_tool_return_clear_errors(
    client: TestClient,
    tool_call_api_session: Session,
) -> None:
    tenant = create_tenant(tool_call_api_session, "tenant-missing-api")
    agent = create_agent(client, tenant)
    missing_server = client.post(
        "/v1/tool-calls",
        json=payload(),
        headers=call_headers(agent["api_key"]),
    )
    server = ToolServerModel(
        tenant_id=tenant.id,
        server_id="github-main",
        name="GitHub",
        transport_type=TransportType.STREAMABLE_HTTP,
        endpoint_url="https://example.invalid",
        command=None,
        args=None,
        env=None,
        status=EntityStatus.ACTIVE,
    )
    SQLAlchemyToolServerRepository(tool_call_api_session).create(server)
    tool_call_api_session.commit()
    missing_tool = client.post(
        "/v1/tool-calls",
        json=payload(),
        headers=call_headers(agent["api_key"]),
    )

    assert missing_server.status_code == 404
    assert missing_server.json()["error"]["code"] == "tool_server_not_found"
    assert missing_tool.status_code == 404
    assert missing_tool.json()["error"]["code"] == "tool_not_found"


def test_schema_invalid_returns_clear_error_without_mcp_call(
    client: TestClient,
    tool_call_api_session: Session,
    mcp_client: TestOnlyMcpClient,
) -> None:
    tenant = create_tenant(tool_call_api_session, "tenant-schema-api")
    agent = create_agent(client, tenant)
    create_tool(tool_call_api_session, tenant)

    response = client.post(
        "/v1/tool-calls",
        json=payload(issue_number="bad"),
        headers=call_headers(agent["api_key"]),
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "argument_schema_invalid"
    assert mcp_client.calls == []


def test_low_risk_read_allow_succeeds(
    client: TestClient,
    tool_call_api_session: Session,
    mcp_client: TestOnlyMcpClient,
) -> None:
    tenant = create_tenant(tool_call_api_session, "tenant-success-api")
    agent = create_agent(client, tenant)
    create_tool(tool_call_api_session, tenant)

    response = client.post(
        "/v1/tool-calls",
        json=payload(),
        headers=call_headers(agent["api_key"]),
    )

    body = response.json()
    assert response.status_code == 200
    assert body["status"] == "succeeded"
    assert body["policy_decision"] == "allow"
    assert body["result"] == {"ok": True}
    assert len(mcp_client.calls) == 1


def test_critical_deny_and_high_risk_approval_do_not_call_mcp(
    client: TestClient,
    tool_call_api_session: Session,
    mcp_client: TestOnlyMcpClient,
) -> None:
    critical_tenant = create_tenant(tool_call_api_session, "tenant-critical-api")
    critical_agent = create_agent(client, critical_tenant, "critical-agent")
    create_tool(tool_call_api_session, critical_tenant, risk_level=RiskLevel.CRITICAL)
    critical = client.post(
        "/v1/tool-calls",
        json=payload(),
        headers=call_headers(critical_agent["api_key"]),
    )
    high_tenant = create_tenant(tool_call_api_session, "tenant-high-api")
    high_agent = create_agent(client, high_tenant, "high-agent")
    create_tool(tool_call_api_session, high_tenant, risk_level=RiskLevel.HIGH)
    high = client.post(
        "/v1/tool-calls",
        json=payload(),
        headers=call_headers(high_agent["api_key"]),
    )

    assert critical.status_code == 200
    assert critical.json()["status"] == "denied"
    assert high.status_code == 200
    assert high.json()["status"] == "pending_approval"
    assert high.json()["approval_id"] is not None
    assert mcp_client.calls == []


def test_upstream_failure_returns_failed_status(
    test_settings: Settings,
    tool_call_api_session: Session,
) -> None:
    failing_client = TestOnlyMcpClient(failure="failed")
    app = create_app(test_settings)
    app.state.mcp_client = failing_client

    def override_session() -> Iterator[Session]:
        yield tool_call_api_session

    app.dependency_overrides[get_db_session] = override_session
    client = TestClient(app)
    tenant = create_tenant(tool_call_api_session, "tenant-upstream-api")
    agent = create_agent(client, tenant)
    create_tool(tool_call_api_session, tenant)

    response = client.post(
        "/v1/tool-calls",
        json=payload(),
        headers=call_headers(agent["api_key"]),
    )

    body = response.json()
    assert response.status_code == 200
    assert body["status"] == "failed"
    assert body["error"]["code"] == "upstream_failed"


def test_production_default_missing_mcp_client_returns_failed_not_succeeded(
    test_settings: Settings,
    tool_call_api_session: Session,
) -> None:
    app = create_app(test_settings)

    def override_session() -> Iterator[Session]:
        yield tool_call_api_session

    app.dependency_overrides[get_db_session] = override_session
    client = TestClient(app)
    tenant = create_tenant(tool_call_api_session, "tenant-no-mcp-api")
    agent = create_agent(client, tenant)
    create_tool(tool_call_api_session, tenant)

    response = client.post(
        "/v1/tool-calls",
        json=payload(),
        headers=call_headers(agent["api_key"]),
    )

    body = response.json()
    assert response.status_code == 200
    assert body["status"] == "failed"
    assert body["error"]["code"] == "mcp_client_not_configured"


def test_idempotency_repeat_success_and_argument_mismatch_conflict(
    client: TestClient,
    tool_call_api_session: Session,
    mcp_client: TestOnlyMcpClient,
) -> None:
    tenant = create_tenant(tool_call_api_session, "tenant-idem-api")
    agent = create_agent(client, tenant)
    create_tool(tool_call_api_session, tenant)
    first = client.post(
        "/v1/tool-calls",
        json=payload("idem-api"),
        headers=call_headers(agent["api_key"]),
    )
    repeat = client.post(
        "/v1/tool-calls",
        json=payload("idem-api"),
        headers=call_headers(agent["api_key"]),
    )
    mismatch = client.post(
        "/v1/tool-calls",
        json=payload("idem-api", issue_number=456),
        headers=call_headers(agent["api_key"]),
    )

    assert first.status_code == 200
    assert repeat.status_code == 200
    assert first.json()["tool_call_id"] == repeat.json()["tool_call_id"]
    assert mismatch.status_code == 409
    assert mismatch.json()["error"]["code"] == "idempotency_conflict"
    assert len(mcp_client.calls) == 1


def test_response_does_not_contain_sensitive_fields_or_raw_secret(
    client: TestClient,
    tool_call_api_session: Session,
) -> None:
    tenant = create_tenant(tool_call_api_session, "tenant-secret-response-api")
    agent = create_agent(client, tenant)
    server = ToolServerModel(
        tenant_id=tenant.id,
        server_id="github-main",
        name="GitHub",
        transport_type=TransportType.STREAMABLE_HTTP,
        endpoint_url="https://example.invalid",
        command=None,
        args=None,
        env=None,
        status=EntityStatus.ACTIVE,
    )
    SQLAlchemyToolServerRepository(tool_call_api_session).create(server)
    SQLAlchemyToolDefinitionRepository(tool_call_api_session).create(
        ToolDefinitionModel(
            tenant_id=tenant.id,
            server_id=server.id,
            tool_name="github.get_issue",
            description=None,
            input_schema={
                "type": "object",
                "properties": {"authorization": {"type": "string"}},
            },
            risk_level=RiskLevel.LOW,
            action_type=ActionType.READ,
            resource_patterns=None,
            status=EntityStatus.ACTIVE,
            schema_hash="schema-secret",
        )
    )
    tool_call_api_session.commit()
    secret_value = "Bearer api-response-sensitive"

    response = client.post(
        "/v1/tool-calls",
        json={
            "target_server": "github-main",
            "target_tool": "github.get_issue",
            "arguments": {"authorization": secret_value},
        },
        headers=call_headers(agent["api_key"]),
    )
    body_text = response.text

    assert response.status_code == 200
    assert "api_key" not in body_text
    assert "api_key_hash" not in body_text
    assert secret_value not in body_text


def test_approval_admin_endpoints_require_admin_auth(
    client: TestClient,
    tool_call_api_session: Session,
) -> None:
    tenant = create_tenant(tool_call_api_session, "tenant-approval-auth-api")
    agent = create_agent(client, tenant)
    create_tool(tool_call_api_session, tenant, risk_level=RiskLevel.HIGH)
    pending = client.post(
        "/v1/tool-calls",
        json=payload(),
        headers=call_headers(agent["api_key"]),
    ).json()
    approval_id = pending["approval_id"]

    listed = client.get("/v1/admin/approvals")
    approved = client.post(
        f"/v1/admin/approvals/{approval_id}/approve",
        json={"review_reason": "Looks safe"},
    )
    denied = client.post(
        f"/v1/admin/approvals/{approval_id}/deny",
        json={"review_reason": "Too risky"},
    )

    assert listed.status_code == 401
    assert approved.status_code == 401
    assert denied.status_code == 401


def test_list_pending_and_approve_executes_approved_tool_call(
    client: TestClient,
    tool_call_api_session: Session,
    mcp_client: TestOnlyMcpClient,
) -> None:
    tenant = create_tenant(tool_call_api_session, "tenant-approval-execute-api")
    agent = create_agent(client, tenant)
    create_tool(tool_call_api_session, tenant, risk_level=RiskLevel.HIGH)
    pending = client.post(
        "/v1/tool-calls",
        json=payload("approval-execute"),
        headers=call_headers(agent["api_key"]),
    ).json()

    listed = client.get(
        f"/v1/admin/approvals?tenant_id={tenant.id}",
        headers=admin_headers(),
    )
    approved = client.post(
        f"/v1/admin/approvals/{pending['approval_id']}/approve",
        json={"review_reason": "Looks safe"},
        headers=admin_headers(),
    )

    body = approved.json()
    assert listed.status_code == 200
    assert listed.json()["items"][0]["id"] == pending["approval_id"]
    assert approved.status_code == 200
    assert body["status"] == "executed"
    assert body["tool_call_status"] == "succeeded"
    assert body["result"] == {"ok": True}
    assert len(mcp_client.calls) == 1


def test_deny_pending_approval_does_not_call_mcp(
    client: TestClient,
    tool_call_api_session: Session,
    mcp_client: TestOnlyMcpClient,
) -> None:
    tenant = create_tenant(tool_call_api_session, "tenant-approval-deny-api")
    agent = create_agent(client, tenant)
    create_tool(tool_call_api_session, tenant, risk_level=RiskLevel.HIGH)
    pending = client.post(
        "/v1/tool-calls",
        json=payload("approval-deny"),
        headers=call_headers(agent["api_key"]),
    ).json()

    denied = client.post(
        f"/v1/admin/approvals/{pending['approval_id']}/deny",
        json={"review_reason": "Too risky"},
        headers=admin_headers(),
    )

    assert denied.status_code == 200
    assert denied.json()["status"] == "denied"
    assert denied.json()["tool_call_status"] == "denied"
    assert mcp_client.calls == []


def test_approve_same_approval_twice_does_not_execute_twice(
    client: TestClient,
    tool_call_api_session: Session,
    mcp_client: TestOnlyMcpClient,
) -> None:
    tenant = create_tenant(tool_call_api_session, "tenant-approval-double-api")
    agent = create_agent(client, tenant)
    create_tool(tool_call_api_session, tenant, risk_level=RiskLevel.HIGH)
    pending = client.post(
        "/v1/tool-calls",
        json=payload("approval-double"),
        headers=call_headers(agent["api_key"]),
    ).json()

    first = client.post(
        f"/v1/admin/approvals/{pending['approval_id']}/approve",
        json={"review_reason": "Looks safe"},
        headers=admin_headers(),
    )
    second = client.post(
        f"/v1/admin/approvals/{pending['approval_id']}/approve",
        json={"review_reason": "Again"},
        headers=admin_headers(),
    )

    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "approval_already_processed"
    assert len(mcp_client.calls) == 1


def test_approve_expired_approval_does_not_call_mcp(
    client: TestClient,
    tool_call_api_session: Session,
    mcp_client: TestOnlyMcpClient,
) -> None:
    tenant = create_tenant(tool_call_api_session, "tenant-approval-expired-api")
    agent = create_agent(client, tenant)
    create_tool(tool_call_api_session, tenant, risk_level=RiskLevel.HIGH)
    pending = client.post(
        "/v1/tool-calls",
        json=payload("approval-expired"),
        headers=call_headers(agent["api_key"]),
    ).json()
    approval = tool_call_api_session.scalar(
        select(ApprovalRequestModel).where(
            ApprovalRequestModel.id == pending["approval_id"],
        )
    )
    assert approval is not None
    approval.expires_at = utc_now() - timedelta(seconds=1)
    tool_call_api_session.commit()

    approved = client.post(
        f"/v1/admin/approvals/{pending['approval_id']}/approve",
        json={"review_reason": "Looks safe"},
        headers=admin_headers(),
    )

    body = approved.json()
    assert approved.status_code == 200
    assert body["status"] == "expired"
    assert body["error"]["code"] == "approval_expired"
    assert mcp_client.calls == []


def test_approval_response_does_not_include_execution_payload(
    client: TestClient,
    tool_call_api_session: Session,
) -> None:
    tenant = create_tenant(tool_call_api_session, "tenant-approval-payload-api")
    agent = create_agent(client, tenant)
    create_tool(tool_call_api_session, tenant, risk_level=RiskLevel.HIGH)
    pending = client.post(
        "/v1/tool-calls",
        json=payload("approval-payload"),
        headers=call_headers(agent["api_key"]),
    ).json()

    listed = client.get("/v1/admin/approvals", headers=admin_headers()).text
    approved = client.post(
        f"/v1/admin/approvals/{pending['approval_id']}/approve",
        json={"review_reason": "Looks safe"},
        headers=admin_headers(),
    ).text

    assert "arguments_payload" not in listed
    assert "arguments_payload" not in approved
