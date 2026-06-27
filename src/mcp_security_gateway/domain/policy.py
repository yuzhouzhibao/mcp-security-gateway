from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from mcp_security_gateway.domain.enums import ActionType, AgentRole, PolicyEffect, RiskLevel

JsonObject = dict[str, Any]
FindingKind = Literal["key_name", "value_pattern"]


@dataclass(frozen=True, slots=True)
class PolicyContext:
    tenant_id: UUID
    agent_id: UUID
    role: AgentRole
    target_server: str
    target_tool: str
    risk_level: RiskLevel
    action_type: ActionType
    arguments: JsonObject
    resource: str | None
    current_time: datetime


@dataclass(frozen=True, slots=True)
class SecretFinding:
    path: str
    kind: FindingKind
    reason: str


@dataclass(frozen=True, slots=True)
class PolicyEvaluationResult:
    decision: PolicyEffect
    reason: str
    matched_policy_id: UUID | None
    arguments_redacted: JsonObject
    arguments_hash: str
    secret_findings: tuple[SecretFinding, ...]


class PolicyEvaluationError(ValueError):
    """Raised for explicit policy evaluation failures that must fail closed."""


class PolicyRepositoryError(PolicyEvaluationError):
    """Raised when policy repository access fails."""
