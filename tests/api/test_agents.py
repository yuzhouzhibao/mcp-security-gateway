import os
from collections.abc import Iterator
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from mcp_security_gateway.api.dependencies import get_db_session
from mcp_security_gateway.domain.enums import EntityStatus
from mcp_security_gateway.infrastructure.db.base import Base
from mcp_security_gateway.infrastructure.db.models import TenantModel
from mcp_security_gateway.infrastructure.db.repositories import SQLAlchemyTenantRepository
from mcp_security_gateway.main import create_app
from mcp_security_gateway.settings import Settings

pytestmark = pytest.mark.integration


@pytest.fixture(scope="session")
def api_database_url() -> str:
    database_url = os.environ.get("TEST_DATABASE_URL")
    if database_url is None:
        pytest.skip("TEST_DATABASE_URL must be set explicitly for PostgreSQL API tests")
    blocked_scheme = "sql" + "ite"
    if database_url.startswith(blocked_scheme):
        pytest.fail("API tests require PostgreSQL")
    return database_url


@pytest.fixture(scope="session")
def api_engine(api_database_url: str) -> Iterator[Engine]:
    schema_name = f"api_test_schema_{uuid4().hex}"
    bootstrap_engine = create_engine(api_database_url, future=True)
    if bootstrap_engine.dialect.name != "postgresql":
        pytest.fail("API tests require PostgreSQL")
    with bootstrap_engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema_name}"'))
    bootstrap_engine.dispose()

    engine = create_engine(
        api_database_url,
        future=True,
        connect_args={"options": f"-csearch_path={schema_name}"},
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()
    cleanup_engine = create_engine(api_database_url, future=True)
    with cleanup_engine.begin() as connection:
        connection.execute(text(f'DROP SCHEMA "{schema_name}" CASCADE'))
    cleanup_engine.dispose()


@pytest.fixture
def api_session(api_engine: Engine) -> Iterator[Session]:
    factory = sessionmaker(bind=api_engine, expire_on_commit=False)
    with factory() as session:
        yield session
        session.rollback()


@pytest.fixture
def client(test_settings: Settings, api_session: Session) -> TestClient:
    app = create_app(test_settings)

    def override_session() -> Iterator[Session]:
        yield api_session

    app.dependency_overrides[get_db_session] = override_session
    return TestClient(app)


def create_tenant(session: Session, name: str = "tenant-api") -> TenantModel:
    tenant = TenantModel(name=name, status=EntityStatus.ACTIVE)
    SQLAlchemyTenantRepository(session).create(tenant)
    session.commit()
    return tenant


def admin_headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-admin-key"}


def test_create_agent_requires_admin_key(client: TestClient, api_session: Session) -> None:
    tenant = create_tenant(api_session, "tenant-create-auth")
    payload = {"tenant_id": str(tenant.id), "name": "github-agent", "role": "agent"}

    missing = client.post("/v1/admin/agents", json=payload)
    wrong = client.post(
        "/v1/admin/agents",
        json=payload,
        headers={"Authorization": "Bearer wrong-admin-key"},
    )

    assert missing.status_code == 401
    assert missing.json()["error"]["code"] == "unauthenticated"
    assert wrong.status_code == 401
    assert wrong.json()["error"]["code"] == "unauthenticated"


def test_create_agent_returns_plaintext_key_once_without_hash(
    client: TestClient,
    api_session: Session,
) -> None:
    tenant = create_tenant(api_session, "tenant-create-success")

    response = client.post(
        "/v1/admin/agents",
        json={"tenant_id": str(tenant.id), "name": "github-agent", "role": "agent"},
        headers=admin_headers(),
    )

    body = response.json()
    assert response.status_code == 201
    assert body["api_key"].startswith("msgw_")
    assert body["status"] == "active"
    assert "api_key_hash" not in body


def test_admin_agent_read_and_disable_endpoints_require_admin(
    client: TestClient,
    api_session: Session,
) -> None:
    tenant = create_tenant(api_session, "tenant-admin-required")
    created = client.post(
        "/v1/admin/agents",
        json={"tenant_id": str(tenant.id), "name": "github-agent", "role": "agent"},
        headers=admin_headers(),
    ).json()
    agent_id = created["id"]

    assert client.get(f"/v1/admin/agents?tenant_id={tenant.id}").status_code == 401
    assert client.get(f"/v1/admin/agents/{agent_id}").status_code == 401
    assert client.post(f"/v1/admin/agents/{agent_id}/disable").status_code == 401


def test_admin_list_and_get_do_not_return_sensitive_fields(
    client: TestClient,
    api_session: Session,
) -> None:
    tenant = create_tenant(api_session, "tenant-list-get")
    created = client.post(
        "/v1/admin/agents",
        json={"tenant_id": str(tenant.id), "name": "github-agent", "role": "agent"},
        headers=admin_headers(),
    ).json()

    listed = client.get(
        f"/v1/admin/agents?tenant_id={tenant.id}",
        headers=admin_headers(),
    )
    fetched = client.get(f"/v1/admin/agents/{created['id']}", headers=admin_headers())

    assert listed.status_code == 200
    assert fetched.status_code == 200
    assert "api_key" not in listed.json()[0]
    assert "api_key_hash" not in listed.json()[0]
    assert "api_key" not in fetched.json()
    assert "api_key_hash" not in fetched.json()


def test_agent_self_authentication_and_disabled_rejection(
    client: TestClient,
    api_session: Session,
) -> None:
    tenant = create_tenant(api_session, "tenant-agent-self")
    created = client.post(
        "/v1/admin/agents",
        json={"tenant_id": str(tenant.id), "name": "github-agent", "role": "agent"},
        headers=admin_headers(),
    ).json()

    missing = client.get("/v1/agents/me")
    wrong = client.get("/v1/agents/me", headers={"Authorization": "Bearer wrong-agent-key"})
    valid = client.get("/v1/agents/me", headers={"Authorization": f"Bearer {created['api_key']}"})
    disabled = client.post(
        f"/v1/admin/agents/{created['id']}/disable",
        headers=admin_headers(),
    )
    after_disable = client.get(
        "/v1/agents/me",
        headers={"Authorization": f"Bearer {created['api_key']}"},
    )

    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert valid.status_code == 200
    assert "api_key" not in valid.json()
    assert "api_key_hash" not in valid.json()
    assert disabled.status_code == 200
    assert disabled.json()["status"] == "disabled"
    assert after_disable.status_code == 403
    assert after_disable.json()["error"]["code"] == "agent_disabled"


def test_create_agent_errors_are_explicit(client: TestClient, api_session: Session) -> None:
    missing_tenant_id = UUID("00000000-0000-4000-8000-000000000099")
    missing_tenant = client.post(
        "/v1/admin/agents",
        json={"tenant_id": str(missing_tenant_id), "name": "github-agent", "role": "agent"},
        headers=admin_headers(),
    )
    tenant = create_tenant(api_session, "tenant-conflict")
    first = client.post(
        "/v1/admin/agents",
        json={"tenant_id": str(tenant.id), "name": "github-agent", "role": "agent"},
        headers=admin_headers(),
    )
    conflict = client.post(
        "/v1/admin/agents",
        json={"tenant_id": str(tenant.id), "name": "github-agent", "role": "agent"},
        headers=admin_headers(),
    )

    assert missing_tenant.status_code == 404
    assert missing_tenant.json()["error"]["code"] == "tenant_not_found"
    assert first.status_code == 201
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "agent_name_conflict"
