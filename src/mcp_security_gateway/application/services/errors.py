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


class ToolServerNotFoundError(ApplicationError):
    def __init__(self, trace_id: str | None = None) -> None:
        super().__init__(
            "tool_server_not_found",
            "Tool server not found",
            {"trace_id": trace_id} if trace_id is not None else None,
        )


class ToolNotFoundError(ApplicationError):
    def __init__(self, trace_id: str | None = None) -> None:
        super().__init__(
            "tool_not_found",
            "Tool not found",
            {"trace_id": trace_id} if trace_id is not None else None,
        )


class ToolDisabledError(ApplicationError):
    def __init__(self, trace_id: str | None = None) -> None:
        super().__init__(
            "tool_disabled",
            "Tool is disabled",
            {"trace_id": trace_id} if trace_id is not None else None,
        )


class ArgumentSchemaInvalidError(ApplicationError):
    def __init__(self, trace_id: str | None = None) -> None:
        super().__init__(
            "argument_schema_invalid",
            "Tool arguments do not match input schema",
            {"trace_id": trace_id} if trace_id is not None else None,
        )


class IdempotencyConflictError(ApplicationError):
    def __init__(self, trace_id: str | None = None) -> None:
        super().__init__(
            "idempotency_conflict",
            "Idempotency key conflicts with an in-flight or different request",
            {"trace_id": trace_id} if trace_id is not None else None,
        )


class McpClientNotConfiguredError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("mcp_client_not_configured", "MCP client is not configured")


class ApprovalNotFoundError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("approval_not_found", "Approval request was not found")


class ApprovalNotPendingError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("approval_not_pending", "Approval request is not pending")


class ApprovalAlreadyProcessedError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("approval_already_processed", "Approval request was already processed")


class ApprovalExpiredError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("approval_expired", "Approval request has expired")


class ApprovalExecutionFailedError(ApplicationError):
    def __init__(self, details: dict[str, Any] | None = None) -> None:
        super().__init__("approval_execution_failed", "Approval execution failed", details)


class ApprovalDeniedError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("approval_denied", "Approval request was denied")
