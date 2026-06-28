import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, select, text
from sqlalchemy.orm import Session, sessionmaker

from mcp_security_gateway.api.dependencies import get_db_session
from mcp_security_gateway.domain.enums import EntityStatus
from mcp_security_gateway.infrastructure.db.base import Base
from mcp_security_gateway.infrastructure.db.models import (
    AuditEventModel,
    TenantModel,
    ToolCallModel,
)
from mcp_security_gateway.infrastructure.db.repositories import SQLAlchemyTenantRepository
from mcp_security_gateway.main import create_app
from mcp_security_gateway.settings import Settings

pytestmark = [pytest.mark.e2e]


@pytest.fixture(scope="session")
def e2e_database_url() -> str:
    database_url = os.environ.get("TEST_DATABASE_URL")
    if database_url is None:
        pytest.skip("TEST_DATABASE_URL must be set explicitly for PostgreSQL e2e tests")
    blocked_scheme = "sql" + "ite"
    if database_url.startswith(blocked_scheme):
        pytest.fail("e2e tests require PostgreSQL")
    return database_url


@pytest.fixture(scope="session")
def e2e_engine(e2e_database_url: str) -> Iterator[Engine]:
    schema_name = f"e2e_schema_{uuid4().hex}"
    bootstrap_engine = create_engine(e2e_database_url, future=True)
    if bootstrap_engine.dialect.name != "postgresql":
        pytest.fail("e2e tests require PostgreSQL")
    with bootstrap_engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema_name}"'))
    bootstrap_engine.dispose()

    engine = create_engine(
        e2e_database_url,
        future=True,
        connect_args={"options": f"-csearch_path={schema_name}"},
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()
    cleanup_engine = create_engine(e2e_database_url, future=True)
    with cleanup_engine.begin() as connection:
        connection.execute(text(f'DROP SCHEMA "{schema_name}" CASCADE'))
    cleanup_engine.dispose()


@pytest.fixture
def e2e_session(e2e_engine: Engine) -> Iterator[Session]:
    factory = sessionmaker(bind=e2e_engine, expire_on_commit=False)
    with factory() as session:
        yield session
        session.rollback()


@pytest.fixture
def e2e_client(test_settings: Settings, e2e_session: Session) -> TestClient:
    app = create_app(test_settings)

    def override_session() -> Iterator[Session]:
        yield e2e_session

    app.dependency_overrides[get_db_session] = override_session
    assert type(app.state.mcp_client).__name__ == "StdioMcpClient"
    return TestClient(app)


def admin_headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-admin-key"}


def create_tenant(session: Session) -> TenantModel:
    tenant = TenantModel(name="tenant-e2e", status=EntityStatus.ACTIVE)
    SQLAlchemyTenantRepository(session).create(tenant)
    session.commit()
    return tenant


def create_agent(client: TestClient, tenant: TenantModel) -> dict[str, str]:
    response = client.post(
        "/v1/admin/agents",
        json={"tenant_id": str(tenant.id), "name": "calculator-agent", "role": "agent"},
        headers=admin_headers(),
    )
    assert response.status_code == 201
    return cast(dict[str, str], response.json())


def call_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


def test_agent_calls_real_stdio_calculator_through_gateway(
    e2e_client: TestClient,
    e2e_session: Session,
) -> None:
    tenant = create_tenant(e2e_session)
    agent = create_agent(e2e_client, tenant)
    server_path = Path("examples/mcp_servers/calculator_server.py").resolve()

    created_server = e2e_client.post(
        "/v1/admin/tool-servers",
        json={
            "tenant_id": str(tenant.id),
            "server_id": "calculator-local",
            "name": "Local Calculator MCP",
            "transport_type": "stdio",
            "command": sys.executable,
            "args": [str(server_path)],
            "env": {},
        },
        headers=admin_headers(),
    )
    refreshed = e2e_client.post(
        "/v1/admin/tool-servers/calculator-local/refresh-tools",
        json={"tenant_id": str(tenant.id)},
        headers=admin_headers(),
    )
    discovered = {item["tool_name"]: item for item in refreshed.json()["items"]}
    classified = e2e_client.patch(
        f"/v1/admin/tool-definitions/{discovered['add']['id']}",
        json={"risk_level": "low", "action_type": "read", "status": "active"},
        headers=admin_headers(),
    )
    called = e2e_client.post(
        "/v1/tool-calls",
        json={
            "target_server": "calculator-local",
            "target_tool": "add",
            "arguments": {"a": 2, "b": 3},
            "trace_id": "trace-e2e-calculator",
        },
        headers=call_headers(agent["api_key"]),
    )

    assert created_server.status_code == 201
    assert refreshed.status_code == 200
    assert discovered["add"]["risk_level"] == "critical"
    assert discovered["add"]["action_type"] == "privileged"
    assert discovered["add"]["status"] == "disabled"
    assert "echo" in discovered
    assert classified.status_code == 200
    assert called.status_code == 200
    assert called.json()["status"] == "succeeded"
    assert "5" in called.text
    tool_calls = list(e2e_session.scalars(select(ToolCallModel)).all())
    audit_events = list(e2e_session.scalars(select(AuditEventModel)).all())
    assert len(tool_calls) == 1
    assert tool_calls[0].status == "succeeded"
    assert len(audit_events) >= 1
    assert audit_events[-1].status == "succeeded"
