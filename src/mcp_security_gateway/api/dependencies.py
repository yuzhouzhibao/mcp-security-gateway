from collections.abc import Iterator
from typing import Annotated, cast

from fastapi import Depends, Header, Request
from sqlalchemy.orm import Session, sessionmaker

from mcp_security_gateway.api.errors import APIError
from mcp_security_gateway.application.ports.mcp_client import McpClient
from mcp_security_gateway.application.services.agent_service import AgentDTO, AgentService
from mcp_security_gateway.application.services.errors import McpClientNotConfiguredError
from mcp_security_gateway.infrastructure.auth.api_keys import verify_api_key_hash
from mcp_security_gateway.infrastructure.db.repositories import (
    SQLAlchemyAgentRepository,
    SQLAlchemyTenantRepository,
)
from mcp_security_gateway.settings import Settings


def get_settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def get_db_session(request: Request) -> Iterator[Session]:
    session_factory: sessionmaker[Session] = request.app.state.session_factory
    with session_factory() as session:
        yield session


def get_agent_service(session: Session, settings: Settings) -> AgentService:
    return AgentService(
        tenant_repository=SQLAlchemyTenantRepository(session),
        agent_repository=SQLAlchemyAgentRepository(session),
        api_key_pepper=settings.api_key_pepper,
    )


def extract_bearer_token(authorization: str | None) -> str:
    if authorization is None:
        raise APIError("unauthenticated", "Authentication is required", 401)
    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0] != "Bearer" or parts[1] == "":
        raise APIError("unauthenticated", "Authentication is required", 401)
    return parts[1]


def require_admin(
    request: Request,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> None:
    settings = get_settings(request)
    token = extract_bearer_token(authorization)
    if not verify_api_key_hash(token, settings.admin_api_key_hash, settings.api_key_pepper):
        raise APIError("unauthenticated", "Authentication is required", 401)


def require_agent(
    request: Request,
    session: Annotated[Session, Depends(get_db_session)],
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> AgentDTO:
    settings = get_settings(request)
    token = extract_bearer_token(authorization)
    service = get_agent_service(session, settings)
    return service.authenticate_agent_by_api_key(token)


def get_mcp_client(request: Request) -> McpClient:
    client = getattr(request.app.state, "mcp_client", None)
    if client is None:
        raise McpClientNotConfiguredError()
    return cast(McpClient, client)
