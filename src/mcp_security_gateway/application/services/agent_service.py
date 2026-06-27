from dataclasses import dataclass
from uuid import UUID

from sqlalchemy.exc import IntegrityError

from mcp_security_gateway.application.services.errors import (
    AgentDisabledError,
    AgentNameConflictError,
    AgentNotFoundError,
    TenantNotFoundError,
    UnauthenticatedError,
)
from mcp_security_gateway.domain.enums import AgentRole, EntityStatus
from mcp_security_gateway.infrastructure.auth.api_keys import generate_api_key, hash_api_key
from mcp_security_gateway.infrastructure.db.models import AgentModel
from mcp_security_gateway.infrastructure.db.repositories import (
    SQLAlchemyAgentRepository,
    SQLAlchemyTenantRepository,
)


@dataclass(frozen=True, slots=True)
class AgentDTO:
    id: UUID
    tenant_id: UUID
    name: str
    role: AgentRole
    status: EntityStatus


@dataclass(frozen=True, slots=True)
class CreatedAgentDTO:
    agent: AgentDTO
    api_key: str


class AgentService:
    def __init__(
        self,
        tenant_repository: SQLAlchemyTenantRepository,
        agent_repository: SQLAlchemyAgentRepository,
        api_key_pepper: str,
    ) -> None:
        self._tenant_repository = tenant_repository
        self._agent_repository = agent_repository
        self._api_key_pepper = api_key_pepper

    def create_agent(self, tenant_id: UUID, name: str, role: AgentRole) -> CreatedAgentDTO:
        tenant = self._tenant_repository.get_by_id(tenant_id)
        if tenant is None:
            raise TenantNotFoundError()

        api_key = generate_api_key()
        agent = AgentModel(
            tenant_id=tenant_id,
            name=name,
            role=role,
            status=EntityStatus.ACTIVE,
            api_key_hash=hash_api_key(api_key, self._api_key_pepper),
        )
        try:
            self._agent_repository.create(agent)
        except IntegrityError as error:
            raise AgentNameConflictError from error

        return CreatedAgentDTO(agent=self._to_dto(agent), api_key=api_key)

    def list_agents(self, tenant_id: UUID) -> list[AgentDTO]:
        tenant = self._tenant_repository.get_by_id(tenant_id)
        if tenant is None:
            raise TenantNotFoundError
        return [self._to_dto(agent) for agent in self._agent_repository.list_by_tenant(tenant_id)]

    def get_agent(self, agent_id: UUID) -> AgentDTO:
        agent = self._agent_repository.get_by_id(agent_id)
        if agent is None:
            raise AgentNotFoundError
        return self._to_dto(agent)

    def disable_agent(self, agent_id: UUID) -> AgentDTO:
        agent = self._agent_repository.disable(agent_id)
        if agent is None:
            raise AgentNotFoundError
        return self._to_dto(agent)

    def authenticate_agent_by_api_key(self, api_key: str) -> AgentDTO:
        api_key_hash = hash_api_key(api_key, self._api_key_pepper)
        agent = self._agent_repository.get_by_api_key_hash(api_key_hash)
        if agent is None:
            raise UnauthenticatedError
        if agent.status == EntityStatus.DISABLED:
            raise AgentDisabledError
        return self._to_dto(agent)

    @staticmethod
    def _to_dto(agent: AgentModel) -> AgentDTO:
        return AgentDTO(
            id=agent.id,
            tenant_id=agent.tenant_id,
            name=agent.name,
            role=AgentRole(agent.role),
            status=EntityStatus(agent.status),
        )
