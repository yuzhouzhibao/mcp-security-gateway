import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any, Protocol
from uuid import UUID

from mcp_security_gateway.domain.enums import (
    ActionType,
    AgentRole,
    PolicyEffect,
    RiskLevel,
)
from mcp_security_gateway.domain.policy import (
    JsonObject,
    PolicyContext,
    PolicyEvaluationError,
    PolicyEvaluationResult,
    PolicyRepositoryError,
    SecretFinding,
)
from mcp_security_gateway.infrastructure.db.models import PolicyModel

REDACTED_VALUE = "[REDACTED]"
SECRET_KEYWORDS = frozenset(
    {
        "api_key",
        "apikey",
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "pa" + "ssword",
        "pa" + "sswd",
        "private_key",
        "authorization",
        "credential",
    }
)
ALLOWED_CONDITION_FIELDS = frozenset(
    {
        "roles",
        "agent_ids",
        "tool_names",
        "target_servers",
        "risk_levels",
        "action_types",
        "resource_patterns",
        "argument_equals",
        "argument_contains_keys",
    }
)
BEARER_PATTERN = re.compile(r"\bBearer\s+\S+", re.IGNORECASE)
OPENAI_KEY_PATTERN = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}")
STRUCTURED_TOKEN_PATTERN = re.compile(r"\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN PRIVATE KEY-----")


class SecretScanningError(PolicyEvaluationError):
    """Raised when secret scanning cannot complete."""


class ArgumentRedactionError(PolicyEvaluationError):
    """Raised when argument redaction cannot complete."""


class ArgumentHashError(PolicyEvaluationError):
    """Raised when canonical argument hashing cannot complete."""


class PolicyParseError(PolicyEvaluationError):
    """Raised when stored policy conditions are invalid."""


class SecretScannerProtocol(Protocol):
    def scan(self, value: Any) -> tuple[SecretFinding, ...]: ...


@dataclass(frozen=True, slots=True)
class ParsedPolicyConditions:
    roles: tuple[AgentRole, ...] | None = None
    agent_ids: tuple[UUID, ...] | None = None
    tool_names: tuple[str, ...] | None = None
    target_servers: tuple[str, ...] | None = None
    risk_levels: tuple[RiskLevel, ...] | None = None
    action_types: tuple[ActionType, ...] | None = None
    resource_patterns: tuple[str, ...] | None = None
    argument_equals: JsonObject | None = None
    argument_contains_keys: tuple[str, ...] | None = None


class SecretScanner:
    def scan(self, value: Any) -> tuple[SecretFinding, ...]:
        findings: list[SecretFinding] = []
        self._scan_value(value, "$", findings)
        return tuple(findings)

    def _scan_value(self, value: Any, path: str, findings: list[SecretFinding]) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_text = str(key)
                child_path = f"{path}.{key_text}"
                if self._is_secret_key(key_text):
                    findings.append(
                        SecretFinding(
                            path=child_path,
                            kind="key_name",
                            reason="sensitive key name",
                        )
                    )
                self._scan_value(child, child_path, findings)
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                self._scan_value(child, f"{path}[{index}]", findings)
            return
        if isinstance(value, str):
            reason = self._value_secret_reason(value)
            if reason is not None:
                findings.append(SecretFinding(path=path, kind="value_pattern", reason=reason))

    @staticmethod
    def _is_secret_key(key: str) -> bool:
        normalized = key.lower()
        return any(keyword in normalized for keyword in SECRET_KEYWORDS)

    @staticmethod
    def _value_secret_reason(value: str) -> str | None:
        if BEARER_PATTERN.search(value):
            return "bearer token pattern"
        if OPENAI_KEY_PATTERN.search(value):
            return "secret token pattern"
        if STRUCTURED_TOKEN_PATTERN.search(value):
            return "structured token pattern"
        if PRIVATE_KEY_PATTERN.search(value):
            return "private key pattern"
        return None


def redact_arguments(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            if SecretScanner._is_secret_key(key_text):
                redacted[key_text] = REDACTED_VALUE
            else:
                redacted[key_text] = redact_arguments(child)
        return redacted
    if isinstance(value, list):
        return [redact_arguments(child) for child in value]
    if isinstance(value, str) and SecretScanner._value_secret_reason(value) is not None:
        return REDACTED_VALUE
    return value


def canonical_arguments_hash(arguments: JsonObject) -> str:
    try:
        canonical = json.dumps(
            arguments,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    except (TypeError, ValueError) as error:
        raise ArgumentHashError("arguments are not JSON serializable") from error
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def parse_policy_conditions(conditions: Any) -> ParsedPolicyConditions:
    if not isinstance(conditions, dict):
        raise PolicyParseError("policy conditions must be an object")
    unknown_fields = set(conditions) - ALLOWED_CONDITION_FIELDS
    if unknown_fields:
        raise PolicyParseError("policy contains unknown condition field")

    return ParsedPolicyConditions(
        roles=_parse_enum_list(conditions, "roles", AgentRole),
        agent_ids=_parse_uuid_list(conditions, "agent_ids"),
        tool_names=_parse_string_list(conditions, "tool_names"),
        target_servers=_parse_string_list(conditions, "target_servers"),
        risk_levels=_parse_enum_list(conditions, "risk_levels", RiskLevel),
        action_types=_parse_enum_list(conditions, "action_types", ActionType),
        resource_patterns=_parse_string_list(conditions, "resource_patterns"),
        argument_equals=_parse_argument_equals(conditions),
        argument_contains_keys=_parse_string_list(conditions, "argument_contains_keys"),
    )


def policy_matches(context: PolicyContext, conditions: ParsedPolicyConditions) -> bool:
    if conditions.roles is not None and context.role not in conditions.roles:
        return False
    if conditions.agent_ids is not None and context.agent_id not in conditions.agent_ids:
        return False
    if conditions.tool_names is not None and context.target_tool not in conditions.tool_names:
        return False
    if (
        conditions.target_servers is not None
        and context.target_server not in conditions.target_servers
    ):
        return False
    if conditions.risk_levels is not None and context.risk_level not in conditions.risk_levels:
        return False
    if conditions.action_types is not None and context.action_type not in conditions.action_types:
        return False
    if conditions.resource_patterns is not None:
        if context.resource is None:
            return False
        if not any(
            fnmatchcase(context.resource, pattern) for pattern in conditions.resource_patterns
        ):
            return False
    if conditions.argument_equals is not None:
        for key, expected in conditions.argument_equals.items():
            if context.arguments.get(key) != expected:
                return False
    if conditions.argument_contains_keys is not None:
        for key in conditions.argument_contains_keys:
            if key not in context.arguments:
                return False
    return True


class PolicyService:
    def __init__(
        self,
        policy_repository: Any,
        secret_scanner: SecretScannerProtocol | None = None,
    ) -> None:
        self._policy_repository = policy_repository
        self._secret_scanner = secret_scanner or SecretScanner()

    def evaluate(self, context: PolicyContext) -> PolicyEvaluationResult:
        redacted_result = self._safe_redact(context.arguments)
        if isinstance(redacted_result, PolicyEvaluationResult):
            return redacted_result
        hash_result = self._safe_hash(context.arguments, redacted_result)
        if isinstance(hash_result, PolicyEvaluationResult):
            return hash_result
        findings_result = self._safe_scan(context.arguments, redacted_result, hash_result)
        if findings_result.decision == PolicyEffect.DENY:
            return findings_result

        built_in_result = self._evaluate_non_overridable_built_in_rules(
            context, redacted_result, hash_result
        )
        if built_in_result is not None:
            return built_in_result

        try:
            policies = self._policy_repository.list_active_by_tenant_ordered(context.tenant_id)
        except PolicyRepositoryError:
            return self._deny(
                "policy evaluation failed closed",
                redacted_result,
                hash_result,
                (),
            )

        configured_result = self._evaluate_configured_policies(
            context,
            policies,
            redacted_result,
            hash_result,
        )
        if configured_result is not None:
            return configured_result

        low_risk_result = self._evaluate_low_risk_read_allow(
            context,
            redacted_result,
            hash_result,
        )
        if low_risk_result is not None:
            return low_risk_result

        return self._deny("no matching allow policy", redacted_result, hash_result, ())

    def _safe_redact(self, arguments: JsonObject) -> JsonObject | PolicyEvaluationResult:
        try:
            redacted = redact_arguments(arguments)
        except ArgumentRedactionError:
            return self._deny("argument redaction failed", {}, "", ())
        if not isinstance(redacted, dict):
            return self._deny("argument redaction failed", {}, "", ())
        return redacted

    def _safe_hash(
        self,
        arguments: JsonObject,
        redacted_arguments: JsonObject,
    ) -> str | PolicyEvaluationResult:
        try:
            return canonical_arguments_hash(arguments)
        except ArgumentHashError:
            return self._deny("argument hashing failed", redacted_arguments, "", ())

    def _safe_scan(
        self,
        arguments: JsonObject,
        redacted_arguments: JsonObject,
        arguments_hash: str,
    ) -> PolicyEvaluationResult:
        try:
            findings = self._secret_scanner.scan(arguments)
        except SecretScanningError:
            return self._deny("secret scanning failed", redacted_arguments, arguments_hash, ())
        if findings:
            return self._deny(
                "arguments contain suspected secret",
                redacted_arguments,
                arguments_hash,
                findings,
            )
        return PolicyEvaluationResult(
            decision=PolicyEffect.ALLOW,
            reason="secret scanning completed",
            matched_policy_id=None,
            arguments_redacted=redacted_arguments,
            arguments_hash=arguments_hash,
            secret_findings=(),
        )

    def _evaluate_non_overridable_built_in_rules(
        self,
        context: PolicyContext,
        redacted_arguments: JsonObject,
        arguments_hash: str,
    ) -> PolicyEvaluationResult | None:
        if context.risk_level == RiskLevel.CRITICAL:
            return self._deny(
                "critical tools are denied by default",
                redacted_arguments,
                arguments_hash,
                (),
            )
        if context.action_type == ActionType.DESTRUCTIVE and context.role != AgentRole.ADMIN:
            return self._deny(
                "destructive tools require admin role",
                redacted_arguments,
                arguments_hash,
                (),
            )
        if context.risk_level == RiskLevel.HIGH:
            return PolicyEvaluationResult(
                decision=PolicyEffect.REQUIRE_APPROVAL,
                reason="high risk tools require approval",
                matched_policy_id=None,
                arguments_redacted=redacted_arguments,
                arguments_hash=arguments_hash,
                secret_findings=(),
            )
        return None

    def _evaluate_low_risk_read_allow(
        self,
        context: PolicyContext,
        redacted_arguments: JsonObject,
        arguments_hash: str,
    ) -> PolicyEvaluationResult | None:
        if context.risk_level == RiskLevel.LOW and context.action_type == ActionType.READ:
            return PolicyEvaluationResult(
                decision=PolicyEffect.ALLOW,
                reason="low risk read-only tool allowed",
                matched_policy_id=None,
                arguments_redacted=redacted_arguments,
                arguments_hash=arguments_hash,
                secret_findings=(),
            )
        return None

    def _evaluate_configured_policies(
        self,
        context: PolicyContext,
        policies: Sequence[PolicyModel],
        redacted_arguments: JsonObject,
        arguments_hash: str,
    ) -> PolicyEvaluationResult | None:
        allow_result: PolicyEvaluationResult | None = None
        for policy in policies:
            try:
                conditions = parse_policy_conditions(policy.conditions)
                matches = policy_matches(context, conditions)
            except PolicyParseError:
                return self._deny(
                    "policy evaluation failed closed",
                    redacted_arguments,
                    arguments_hash,
                    (),
                )
            if not matches:
                continue
            try:
                effect = PolicyEffect(policy.effect)
            except ValueError:
                return self._deny(
                    "policy evaluation failed closed",
                    redacted_arguments,
                    arguments_hash,
                    (),
                )
            if effect == PolicyEffect.DENY:
                return self._policy_result(policy, effect, redacted_arguments, arguments_hash)
            if effect == PolicyEffect.REQUIRE_APPROVAL:
                return self._policy_result(policy, effect, redacted_arguments, arguments_hash)
            if effect == PolicyEffect.ALLOW and allow_result is None:
                allow_result = self._policy_result(
                    policy,
                    effect,
                    redacted_arguments,
                    arguments_hash,
                )

        if allow_result is not None:
            return allow_result
        return None

    @staticmethod
    def _policy_result(
        policy: PolicyModel,
        decision: PolicyEffect,
        redacted_arguments: JsonObject,
        arguments_hash: str,
    ) -> PolicyEvaluationResult:
        return PolicyEvaluationResult(
            decision=decision,
            reason=policy.reason,
            matched_policy_id=policy.id,
            arguments_redacted=redacted_arguments,
            arguments_hash=arguments_hash,
            secret_findings=(),
        )

    @staticmethod
    def _deny(
        reason: str,
        redacted_arguments: JsonObject,
        arguments_hash: str,
        findings: tuple[SecretFinding, ...],
    ) -> PolicyEvaluationResult:
        return PolicyEvaluationResult(
            decision=PolicyEffect.DENY,
            reason=reason,
            matched_policy_id=None,
            arguments_redacted=redacted_arguments,
            arguments_hash=arguments_hash,
            secret_findings=findings,
        )


def _parse_string_list(conditions: JsonObject, field: str) -> tuple[str, ...] | None:
    value = conditions.get(field)
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PolicyParseError("policy condition list must contain strings")
    return tuple(value)


def _parse_uuid_list(conditions: JsonObject, field: str) -> tuple[UUID, ...] | None:
    values = _parse_string_list(conditions, field)
    if values is None:
        return None
    try:
        return tuple(UUID(value) for value in values)
    except ValueError as error:
        raise PolicyParseError("policy condition contains invalid UUID") from error


def _parse_enum_list(
    conditions: JsonObject,
    field: str,
    enum_type: type[AgentRole] | type[RiskLevel] | type[ActionType],
) -> tuple[Any, ...] | None:
    values = _parse_string_list(conditions, field)
    if values is None:
        return None
    try:
        return tuple(enum_type(value) for value in values)
    except ValueError as error:
        raise PolicyParseError("policy condition contains invalid enum") from error


def _parse_argument_equals(conditions: JsonObject) -> JsonObject | None:
    value = conditions.get("argument_equals")
    if value is None:
        return None
    if not isinstance(value, dict):
        raise PolicyParseError("argument_equals must be an object")
    return value
