from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from mcp_security_gateway.application.services.policy_engine import (
    REDACTED_VALUE,
    PolicyService,
    SecretScanner,
    SecretScanningError,
    canonical_arguments_hash,
    redact_arguments,
)
from mcp_security_gateway.domain.enums import (
    ActionType,
    AgentRole,
    EntityStatus,
    PolicyEffect,
    RiskLevel,
)
from mcp_security_gateway.domain.policy import PolicyContext, PolicyRepositoryError
from mcp_security_gateway.infrastructure.db.models import PolicyModel

TENANT_ID = UUID("00000000-0000-4000-8000-000000000101")
AGENT_ID = UUID("00000000-0000-4000-8000-000000000102")


class InMemoryPolicyRepository:
    def __init__(self, policies: list[PolicyModel] | None = None) -> None:
        self._policies = policies or []

    def list_active_by_tenant_ordered(self, tenant_id: UUID) -> list[PolicyModel]:
        return sorted(
            [
                policy
                for policy in self._policies
                if policy.tenant_id == tenant_id and policy.status == EntityStatus.ACTIVE
            ],
            key=lambda policy: policy.priority,
        )


class FailingPolicyRepository:
    def list_active_by_tenant_ordered(self, tenant_id: UUID) -> list[PolicyModel]:
        raise PolicyRepositoryError("policy repository read failed")


class FailingSecretScanner:
    def scan(self, value: Any) -> tuple[Any, ...]:
        raise SecretScanningError("scanner unavailable")


def context(
    *,
    role: AgentRole = AgentRole.AGENT,
    risk_level: RiskLevel = RiskLevel.MEDIUM,
    action_type: ActionType = ActionType.WRITE,
    arguments: dict[str, Any] | None = None,
    resource: str | None = "repo:acme/widget",
    target_tool: str = "github.update_issue",
) -> PolicyContext:
    return PolicyContext(
        tenant_id=TENANT_ID,
        agent_id=AGENT_ID,
        role=role,
        target_server="github-main",
        target_tool=target_tool,
        risk_level=risk_level,
        action_type=action_type,
        arguments=arguments or {"repo": "acme/widget", "dry_run": True, "issue_number": 42},
        resource=resource,
        current_time=datetime.now(UTC),
    )


def policy(
    effect: PolicyEffect,
    conditions: Any,
    *,
    priority: int = 100,
    reason: str = "matched configured policy",
) -> PolicyModel:
    return PolicyModel(
        id=uuid4(),
        tenant_id=TENANT_ID,
        name=f"policy-{uuid4()}",
        priority=priority,
        effect=effect,
        conditions=conditions,
        reason=reason,
        status=EntityStatus.ACTIVE,
    )


def evaluate(
    policy_context: PolicyContext,
    policies: list[PolicyModel] | None = None,
) -> Any:
    return PolicyService(InMemoryPolicyRepository(policies)).evaluate(policy_context)


def test_builtin_low_risk_read_allow_applies_without_configured_override() -> None:
    result = evaluate(context(risk_level=RiskLevel.LOW, action_type=ActionType.READ))

    assert result.decision == PolicyEffect.ALLOW
    assert result.reason == "low risk read-only tool allowed"


def test_configured_deny_overrides_builtin_low_risk_read_allow() -> None:
    result = evaluate(
        context(risk_level=RiskLevel.LOW, action_type=ActionType.READ),
        [policy(PolicyEffect.DENY, {"tool_names": ["github.update_issue"]})],
    )

    assert result.decision == PolicyEffect.DENY
    assert result.reason == "matched configured policy"


def test_configured_require_approval_overrides_builtin_low_risk_read_allow() -> None:
    result = evaluate(
        context(risk_level=RiskLevel.LOW, action_type=ActionType.READ),
        [policy(PolicyEffect.REQUIRE_APPROVAL, {"tool_names": ["github.update_issue"]})],
    )

    assert result.decision == PolicyEffect.REQUIRE_APPROVAL
    assert result.reason == "matched configured policy"


def test_critical_is_denied() -> None:
    result = evaluate(context(risk_level=RiskLevel.CRITICAL))

    assert result.decision == PolicyEffect.DENY
    assert result.reason == "critical tools are denied by default"


def test_high_risk_requires_approval() -> None:
    result = evaluate(context(risk_level=RiskLevel.HIGH))

    assert result.decision == PolicyEffect.REQUIRE_APPROVAL


def test_destructive_non_admin_is_denied() -> None:
    result = evaluate(context(action_type=ActionType.DESTRUCTIVE))

    assert result.decision == PolicyEffect.DENY
    assert result.reason == "destructive tools require admin role"


def test_destructive_admin_still_needs_explicit_allow() -> None:
    result = evaluate(context(role=AgentRole.ADMIN, action_type=ActionType.DESTRUCTIVE))

    assert result.decision == PolicyEffect.DENY
    assert result.reason == "no matching allow policy"


def test_no_matching_policy_denies_by_default() -> None:
    result = evaluate(context())

    assert result.decision == PolicyEffect.DENY
    assert result.reason == "no matching allow policy"


@pytest.mark.parametrize(
    ("arguments", "reason"),
    [
        ({"api_key": "test-sensitive-value"}, "sensitive key name"),
        ({"header": "Bearer test-sensitive-value"}, "bearer token pattern"),
        ({"value": "sk-testsecretvalue"}, "secret token pattern"),
        ({"value": "-----BEGIN PRIVATE KEY-----\nbody"}, "private key pattern"),
    ],
)
def test_secret_detection_denies(arguments: dict[str, Any], reason: str) -> None:
    result = evaluate(context(arguments=arguments))

    assert result.decision == PolicyEffect.DENY
    assert result.reason == "arguments contain suspected secret"
    assert result.secret_findings[0].reason == reason


def test_findings_and_redacted_arguments_do_not_contain_sensitive_value() -> None:
    sensitive_value = "Bearer test-sensitive-value"
    result = evaluate(context(arguments={"headers": {"authorization": sensitive_value}}))

    assert result.decision == PolicyEffect.DENY
    assert result.arguments_redacted == {"headers": {"authorization": REDACTED_VALUE}}
    assert repr(result.secret_findings).find(sensitive_value) == -1
    assert repr(result.arguments_redacted).find(sensitive_value) == -1


def test_arguments_hash_is_stable_and_uses_original_arguments() -> None:
    original = {"api_key": "test-sensitive-value", "dry_run": True}
    redacted = redact_arguments(original)

    first = canonical_arguments_hash(original)
    second = canonical_arguments_hash({"dry_run": True, "api_key": "test-sensitive-value"})

    assert first == second
    assert first != canonical_arguments_hash(redacted)


def test_scanner_does_not_modify_original_arguments() -> None:
    arguments = {"nested": {"token": "test-sensitive-value"}}
    original = {"nested": {"token": "test-sensitive-value"}}

    SecretScanner().scan(arguments)

    assert arguments == original


@pytest.mark.parametrize(
    "conditions",
    [
        {"unknown": ["value"]},
        {"risk_levels": ["invalid"]},
        ["not-object"],
    ],
)
def test_policy_parse_errors_fail_closed(conditions: Any) -> None:
    result = evaluate(context(), [policy(PolicyEffect.ALLOW, conditions)])

    assert result.decision == PolicyEffect.DENY
    assert result.reason == "policy evaluation failed closed"


def test_repository_error_fails_closed() -> None:
    result = PolicyService(FailingPolicyRepository()).evaluate(context())

    assert result.decision == PolicyEffect.DENY
    assert result.reason == "policy evaluation failed closed"


def test_secret_scanner_failure_fails_closed() -> None:
    result = PolicyService(
        InMemoryPolicyRepository(),
        secret_scanner=FailingSecretScanner(),
    ).evaluate(context())

    assert result.decision == PolicyEffect.DENY
    assert result.reason == "secret scanning failed"


def test_argument_hash_failure_fails_closed() -> None:
    result = evaluate(context(arguments={"bad": {1, 2, 3}}))

    assert result.decision == PolicyEffect.DENY
    assert result.reason == "argument hashing failed"


def test_matching_deny_policy_beats_allow() -> None:
    result = evaluate(
        context(),
        [
            policy(PolicyEffect.ALLOW, {"tool_names": ["github.update_issue"]}, priority=10),
            policy(PolicyEffect.DENY, {"tool_names": ["github.update_issue"]}, priority=20),
        ],
    )

    assert result.decision == PolicyEffect.DENY


def test_matching_require_approval_returns_require_approval() -> None:
    result = evaluate(
        context(),
        [policy(PolicyEffect.REQUIRE_APPROVAL, {"tool_names": ["github.update_issue"]})],
    )

    assert result.decision == PolicyEffect.REQUIRE_APPROVAL


def test_configured_allow_policy_can_allow_medium_write() -> None:
    result = evaluate(
        context(),
        [policy(PolicyEffect.ALLOW, {"risk_levels": ["medium"], "action_types": ["write"]})],
    )

    assert result.decision == PolicyEffect.ALLOW


def test_builtin_critical_deny_cannot_be_overridden_by_configured_allow() -> None:
    result = evaluate(
        context(risk_level=RiskLevel.CRITICAL),
        [policy(PolicyEffect.ALLOW, {"risk_levels": ["critical"]})],
    )

    assert result.decision == PolicyEffect.DENY
    assert result.reason == "critical tools are denied by default"


def test_builtin_secret_deny_cannot_be_overridden_by_configured_allow() -> None:
    result = evaluate(
        context(arguments={"token": "test-sensitive-value"}),
        [policy(PolicyEffect.ALLOW, {"tool_names": ["github.update_issue"]})],
    )

    assert result.decision == PolicyEffect.DENY
    assert result.reason == "arguments contain suspected secret"


def test_argument_equals_works() -> None:
    result = evaluate(
        context(arguments={"dry_run": True}),
        [policy(PolicyEffect.ALLOW, {"argument_equals": {"dry_run": True}})],
    )

    assert result.decision == PolicyEffect.ALLOW


def test_argument_contains_keys_works() -> None:
    result = evaluate(
        context(arguments={"repo": "acme/widget", "issue_number": 42}),
        [policy(PolicyEffect.ALLOW, {"argument_contains_keys": ["repo", "issue_number"]})],
    )

    assert result.decision == PolicyEffect.ALLOW


def test_resource_patterns_support_simple_wildcards() -> None:
    result = evaluate(
        context(resource="repo:acme/widget"),
        [policy(PolicyEffect.ALLOW, {"resource_patterns": ["repo:acme/*"]})],
    )

    assert result.decision == PolicyEffect.ALLOW
