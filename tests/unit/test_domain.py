from mcp_security_gateway.application.ports.repositories import AuditEventRepository
from mcp_security_gateway.domain.enums import (
    ActionType,
    AgentRole,
    ApprovalStatus,
    EntityStatus,
    PolicyEffect,
    RiskLevel,
    ToolCallStatus,
    TransportType,
)


def test_domain_enum_values_are_stable() -> None:
    assert [status.value for status in EntityStatus] == ["active", "disabled"]
    assert [role.value for role in AgentRole] == ["agent", "admin"]
    assert [transport.value for transport in TransportType] == ["stdio", "streamable_http"]
    assert [level.value for level in RiskLevel] == ["low", "medium", "high", "critical"]
    assert [action.value for action in ActionType] == [
        "read",
        "write",
        "destructive",
        "external_send",
        "privileged",
    ]
    assert [effect.value for effect in PolicyEffect] == [
        "allow",
        "deny",
        "require_approval",
    ]
    assert [status.value for status in ToolCallStatus] == [
        "denied",
        "pending_approval",
        "executing",
        "succeeded",
        "failed",
    ]


def test_approval_status_contains_required_values() -> None:
    assert {status.value for status in ApprovalStatus} == {
        "pending",
        "approved",
        "denied",
        "expired",
        "executed",
        "failed",
    }


def test_audit_event_repository_protocol_is_append_only() -> None:
    assert hasattr(AuditEventRepository, "append")
    assert hasattr(AuditEventRepository, "list_by_tenant")
    assert not hasattr(AuditEventRepository, "update")
    assert not hasattr(AuditEventRepository, "delete")
