from typing import Any


class ApplicationError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


class TenantNotFoundError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("tenant_not_found", "Tenant was not found")


class AgentNotFoundError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("agent_not_found", "Agent was not found")


class AgentNameConflictError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("agent_name_conflict", "Agent name already exists for tenant")


class AgentDisabledError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("agent_disabled", "Agent is disabled")


class UnauthenticatedError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("unauthenticated", "Authentication is required")
