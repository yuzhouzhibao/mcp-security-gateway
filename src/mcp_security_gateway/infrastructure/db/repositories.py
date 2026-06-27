from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from mcp_security_gateway.domain.enums import ApprovalStatus, EntityStatus
from mcp_security_gateway.domain.policy import PolicyRepositoryError
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


class SQLAlchemyTenantRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, tenant: TenantModel) -> TenantModel:
        self._session.add(tenant)
        self._session.flush()
        return tenant

    def get_by_id(self, tenant_id: UUID) -> TenantModel | None:
        return self._session.get(TenantModel, tenant_id)

    def list(self) -> Sequence[TenantModel]:
        return list(self._session.scalars(select(TenantModel)).all())


class SQLAlchemyAgentRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, agent: AgentModel) -> AgentModel:
        self._session.add(agent)
        self._session.flush()
        return agent

    def get_by_id(self, agent_id: UUID) -> AgentModel | None:
        return self._session.get(AgentModel, agent_id)

    def list_by_tenant(self, tenant_id: UUID) -> Sequence[AgentModel]:
        return list(
            self._session.scalars(select(AgentModel).where(AgentModel.tenant_id == tenant_id)).all()
        )

    def get_by_api_key_hash(self, api_key_hash: str) -> AgentModel | None:
        return self._session.scalar(
            select(AgentModel).where(AgentModel.api_key_hash == api_key_hash)
        )

    def disable(self, agent_id: UUID) -> AgentModel | None:
        agent = self.get_by_id(agent_id)
        if agent is None:
            return None
        agent.status = EntityStatus.DISABLED
        self._session.flush()
        return agent


class SQLAlchemyToolServerRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, server: ToolServerModel) -> ToolServerModel:
        self._session.add(server)
        self._session.flush()
        return server

    def get_by_id(self, server_id: UUID) -> ToolServerModel | None:
        return self._session.get(ToolServerModel, server_id)

    def list_by_tenant(self, tenant_id: UUID) -> Sequence[ToolServerModel]:
        return list(
            self._session.scalars(
                select(ToolServerModel).where(ToolServerModel.tenant_id == tenant_id)
            ).all()
        )

    def get_by_server_id(self, tenant_id: UUID, server_id: str) -> ToolServerModel | None:
        return self._session.scalar(
            select(ToolServerModel).where(
                ToolServerModel.tenant_id == tenant_id,
                ToolServerModel.server_id == server_id,
            )
        )


class SQLAlchemyToolDefinitionRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, definition: ToolDefinitionModel) -> ToolDefinitionModel:
        self._session.add(definition)
        self._session.flush()
        return definition

    def get_by_id(self, definition_id: UUID) -> ToolDefinitionModel | None:
        return self._session.get(ToolDefinitionModel, definition_id)

    def list_by_tenant(self, tenant_id: UUID) -> Sequence[ToolDefinitionModel]:
        return list(
            self._session.scalars(
                select(ToolDefinitionModel).where(ToolDefinitionModel.tenant_id == tenant_id)
            ).all()
        )

    def get_by_name(
        self,
        tenant_id: UUID,
        server_id: UUID,
        tool_name: str,
    ) -> ToolDefinitionModel | None:
        return self._session.scalar(
            select(ToolDefinitionModel).where(
                ToolDefinitionModel.tenant_id == tenant_id,
                ToolDefinitionModel.server_id == server_id,
                ToolDefinitionModel.tool_name == tool_name,
            )
        )


class SQLAlchemyPolicyRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, policy: PolicyModel) -> PolicyModel:
        self._session.add(policy)
        self._session.flush()
        return policy

    def get_by_id(self, policy_id: UUID) -> PolicyModel | None:
        return self._session.get(PolicyModel, policy_id)

    def list_by_tenant(self, tenant_id: UUID) -> Sequence[PolicyModel]:
        return list(
            self._session.scalars(
                select(PolicyModel).where(PolicyModel.tenant_id == tenant_id)
            ).all()
        )

    def list_active_by_tenant_ordered(self, tenant_id: UUID) -> Sequence[PolicyModel]:
        try:
            return list(
                self._session.scalars(
                    select(PolicyModel)
                    .where(
                        PolicyModel.tenant_id == tenant_id,
                        PolicyModel.status == EntityStatus.ACTIVE,
                    )
                    .order_by(PolicyModel.priority.asc())
                ).all()
            )
        except SQLAlchemyError as error:
            raise PolicyRepositoryError("policy repository read failed") from error


class SQLAlchemyToolCallRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, tool_call: ToolCallModel) -> ToolCallModel:
        self._session.add(tool_call)
        self._session.flush()
        return tool_call

    def get_by_id(self, tool_call_id: UUID) -> ToolCallModel | None:
        return self._session.get(ToolCallModel, tool_call_id)

    def list_by_tenant(self, tenant_id: UUID) -> Sequence[ToolCallModel]:
        return list(
            self._session.scalars(
                select(ToolCallModel).where(ToolCallModel.tenant_id == tenant_id)
            ).all()
        )

    def get_by_idempotency_key(
        self,
        tenant_id: UUID,
        agent_id: UUID,
        idempotency_key: str,
    ) -> ToolCallModel | None:
        return self._session.scalar(
            select(ToolCallModel).where(
                ToolCallModel.tenant_id == tenant_id,
                ToolCallModel.agent_id == agent_id,
                ToolCallModel.idempotency_key == idempotency_key,
            )
        )


class SQLAlchemyApprovalRequestRepository:
    _terminal_statuses = frozenset(
        {
            ApprovalStatus.DENIED,
            ApprovalStatus.EXPIRED,
            ApprovalStatus.EXECUTED,
            ApprovalStatus.FAILED,
        }
    )

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, approval: ApprovalRequestModel) -> ApprovalRequestModel:
        self._session.add(approval)
        self._session.flush()
        return approval

    def get_by_id(self, approval_id: UUID) -> ApprovalRequestModel | None:
        return self._session.get(ApprovalRequestModel, approval_id)

    def list_by_tenant(self, tenant_id: UUID) -> Sequence[ApprovalRequestModel]:
        return list(
            self._session.scalars(
                select(ApprovalRequestModel).where(ApprovalRequestModel.tenant_id == tenant_id)
            ).all()
        )

    def transition_status(
        self,
        approval_id: UUID,
        expected_status: ApprovalStatus,
        next_status: ApprovalStatus,
    ) -> ApprovalRequestModel | None:
        if expected_status in self._terminal_statuses:
            return None

        now = utc_now()
        values: dict[str, object] = {
            "status": next_status,
            "updated_at": now,
            "version": ApprovalRequestModel.version + 1,
        }
        if next_status == ApprovalStatus.APPROVED:
            values["approved_at"] = now
        if next_status == ApprovalStatus.DENIED:
            values["denied_at"] = now
        if next_status == ApprovalStatus.EXECUTED:
            values["executed_at"] = now

        statement = (
            update(ApprovalRequestModel)
            .where(
                ApprovalRequestModel.id == approval_id,
                ApprovalRequestModel.status == expected_status,
            )
            .values(**values)
            .returning(ApprovalRequestModel)
        )
        return self._session.scalar(statement)


class SQLAlchemyAuditEventRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def append(self, event: AuditEventModel) -> AuditEventModel:
        self._session.add(event)
        self._session.flush()
        return event

    def get_by_id(self, event_id: UUID) -> AuditEventModel | None:
        return self._session.get(AuditEventModel, event_id)

    def list_by_tenant(self, tenant_id: UUID) -> Sequence[AuditEventModel]:
        return list(
            self._session.scalars(
                select(AuditEventModel).where(AuditEventModel.tenant_id == tenant_id)
            ).all()
        )
