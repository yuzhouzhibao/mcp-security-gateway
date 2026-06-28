from collections.abc import Sequence
from typing import Protocol, TypeVar
from uuid import UUID

from mcp_security_gateway.domain.enums import ApprovalStatus, ToolCallStatus

TenantT = TypeVar("TenantT")
AgentT = TypeVar("AgentT")
ToolServerT = TypeVar("ToolServerT")
ToolDefinitionT = TypeVar("ToolDefinitionT")
PolicyT = TypeVar("PolicyT")
ToolCallT = TypeVar("ToolCallT")
ApprovalRequestT = TypeVar("ApprovalRequestT")
AuditEventT = TypeVar("AuditEventT")


class TenantRepository(Protocol[TenantT]):
    def create(self, tenant: TenantT) -> TenantT: ...

    def get_by_id(self, tenant_id: UUID) -> TenantT | None: ...

    def list(self) -> Sequence[TenantT]: ...


class AgentRepository(Protocol[AgentT]):
    def create(self, agent: AgentT) -> AgentT: ...

    def get_by_id(self, agent_id: UUID) -> AgentT | None: ...

    def list_by_tenant(self, tenant_id: UUID) -> Sequence[AgentT]: ...

    def get_by_api_key_hash(self, api_key_hash: str) -> AgentT | None: ...

    def disable(self, agent_id: UUID) -> AgentT | None: ...


class ToolServerRepository(Protocol[ToolServerT]):
    def create(self, server: ToolServerT) -> ToolServerT: ...

    def get_by_id(self, server_id: UUID) -> ToolServerT | None: ...

    def list_by_tenant(self, tenant_id: UUID) -> Sequence[ToolServerT]: ...

    def get_by_server_id(self, tenant_id: UUID, server_id: str) -> ToolServerT | None: ...


class ToolDefinitionRepository(Protocol[ToolDefinitionT]):
    def create(self, definition: ToolDefinitionT) -> ToolDefinitionT: ...

    def get_by_id(self, definition_id: UUID) -> ToolDefinitionT | None: ...

    def list_by_tenant(self, tenant_id: UUID) -> Sequence[ToolDefinitionT]: ...

    def get_by_name(
        self,
        tenant_id: UUID,
        server_id: UUID,
        tool_name: str,
    ) -> ToolDefinitionT | None: ...


class PolicyRepository(Protocol[PolicyT]):
    def create(self, policy: PolicyT) -> PolicyT: ...

    def get_by_id(self, policy_id: UUID) -> PolicyT | None: ...

    def list_by_tenant(self, tenant_id: UUID) -> Sequence[PolicyT]: ...

    def list_active_by_tenant_ordered(self, tenant_id: UUID) -> Sequence[PolicyT]: ...


class ToolCallRepository(Protocol[ToolCallT]):
    def create(self, tool_call: ToolCallT) -> ToolCallT: ...

    def get_by_id(self, tool_call_id: UUID) -> ToolCallT | None: ...

    def list_by_tenant(self, tenant_id: UUID) -> Sequence[ToolCallT]: ...

    def get_by_idempotency_key(
        self,
        tenant_id: UUID,
        agent_id: UUID,
        idempotency_key: str,
    ) -> ToolCallT | None: ...

    def update(self, tool_call: ToolCallT) -> ToolCallT: ...

    def transition_status(
        self,
        tool_call_id: UUID,
        expected_status: ToolCallStatus,
        next_status: ToolCallStatus,
    ) -> ToolCallT | None: ...

    def clear_arguments_payload(self, tool_call_id: UUID) -> ToolCallT | None: ...


class ApprovalRequestRepository(Protocol[ApprovalRequestT]):
    def create(self, approval: ApprovalRequestT) -> ApprovalRequestT: ...

    def get_by_id(self, approval_id: UUID) -> ApprovalRequestT | None: ...

    def list_by_tenant(self, tenant_id: UUID) -> Sequence[ApprovalRequestT]: ...

    def list_filtered(
        self,
        status: ApprovalStatus | None,
        tenant_id: UUID | None,
        limit: int | None,
    ) -> Sequence[ApprovalRequestT]: ...

    def get_by_tool_call_id(self, tool_call_id: UUID) -> ApprovalRequestT | None: ...

    def transition_status(
        self,
        approval_id: UUID,
        expected_status: ApprovalStatus,
        next_status: ApprovalStatus,
        review_reason: str | None = None,
    ) -> ApprovalRequestT | None: ...


class AuditEventRepository(Protocol[AuditEventT]):
    def append(self, event: AuditEventT) -> AuditEventT: ...

    def get_by_id(self, event_id: UUID) -> AuditEventT | None: ...

    def list_by_tenant(self, tenant_id: UUID) -> Sequence[AuditEventT]: ...
