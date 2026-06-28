"""Demo-only bootstrap helper for local development."""

from __future__ import annotations

import argparse
from uuid import uuid4

from mcp_security_gateway.application.services.agent_service import AgentService
from mcp_security_gateway.domain.enums import AgentRole, EntityStatus
from mcp_security_gateway.infrastructure.db.models import TenantModel
from mcp_security_gateway.infrastructure.db.repositories import (
    SQLAlchemyAgentRepository,
    SQLAlchemyTenantRepository,
)
from mcp_security_gateway.infrastructure.db.session import (
    create_database_engine,
    create_session_factory,
)
from mcp_security_gateway.settings import Settings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create demo-only tenant and agent bootstrap data."
    )
    parser.add_argument("--tenant-name", default=f"demo-tenant-{uuid4().hex[:8]}")
    parser.add_argument("--agent-name", default="demo-agent")
    args = parser.parse_args()

    settings = Settings()
    engine = create_database_engine(settings.database_url)
    session_factory = create_session_factory(engine)
    with session_factory() as session:
        tenant = TenantModel(name=args.tenant_name, status=EntityStatus.ACTIVE)
        tenant_repository = SQLAlchemyTenantRepository(session)
        agent_repository = SQLAlchemyAgentRepository(session)
        tenant_repository.create(tenant)
        created = AgentService(
            tenant_repository=tenant_repository,
            agent_repository=agent_repository,
            api_key_pepper=settings.api_key_pepper,
        ).create_agent(tenant.id, args.agent_name, AgentRole.AGENT)
        session.commit()

    print("Demo seed created:")
    print(f"TENANT_ID={tenant.id}")
    print(f"AGENT_ID={created.agent.id}")
    print(f"AGENT_API_KEY={created.api_key}")
    print("Store the agent API key securely; it is shown only by this demo helper.")


if __name__ == "__main__":
    main()
