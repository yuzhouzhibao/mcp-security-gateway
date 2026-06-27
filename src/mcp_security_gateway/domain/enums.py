from enum import StrEnum


class EntityStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class AgentRole(StrEnum):
    AGENT = "agent"
    ADMIN = "admin"


class TransportType(StrEnum):
    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable_http"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionType(StrEnum):
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"
    EXTERNAL_SEND = "external_send"
    PRIVILEGED = "privileged"


class PolicyEffect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ToolCallStatus(StrEnum):
    DENIED = "denied"
    PENDING_APPROVAL = "pending_approval"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    EXECUTED = "executed"
    FAILED = "failed"
