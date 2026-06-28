# Security Model

MCP Security Gateway is designed around explicit authorization, conservative defaults, and durable audit records.

## Trust Boundaries

- Agent boundary: agents authenticate with Agent API keys and can call only agent endpoints.
- Admin boundary: operators authenticate with the deployment-level Admin API key and can manage agents, tool registry entries, and approvals.
- MCP boundary: MCP servers are external processes reached through the MCP client port.
- Database boundary: PostgreSQL stores identities, tool registry metadata, policy configuration, tool calls, approvals, and audit events.
- Audit boundary: AuditEvent rows are append-only through repository interfaces.

## Authentication Model

Agent API keys are generated from high-entropy random material and returned once during agent creation. The database stores only HMAC-SHA256 hashes derived with `API_KEY_PEPPER`.

Admin API access uses `ADMIN_API_KEY_HASH` and `API_KEY_PEPPER`. The admin credential is deployment-level bootstrap authentication, not a user management system.

Disabled agents cannot authenticate. Admin and agent credentials are separate and are not interchangeable.

## Policy Evaluation Order

PolicyService evaluates in this order:

1. Secret detection deny.
2. Critical risk deny.
3. Destructive non-admin deny.
4. High risk require approval.
5. Configured policies by priority.
6. Built-in low-risk read allow.
7. Default deny.

Configured deny and require-approval policies can override built-in low-risk read allow. Critical and secret denies cannot be overridden by configured allow policies.

## Secret Detection And Redaction

Arguments are recursively scanned for secret-like key names and value patterns. Findings include path, detector kind, and reason, but not the raw secret value.

AuditEvent rows and ToolCall redacted fields store redacted arguments and canonical argument hashes. Raw arguments are not written to audit events.

## Audit Log Rules

Audit events are written for:

- Tool lookup failures.
- Schema validation failures.
- Policy deny.
- Approval required.
- MCP success.
- MCP failure.
- Approval approved, denied, expired, executed, and failed.

Audit events must not contain API keys, peppers, ToolServer env values, or execution payloads.

## Approval Execution Payload Retention

Approval execution requires original tool arguments. The MVP stores those arguments in `tool_calls.arguments_payload` only while approval execution is pending.

The payload is cleared after:

- executed
- failed
- denied
- expired

The payload is not returned by APIs and is not written to audit events or logs. Production hardening should encrypt this field with a managed key service.

## MCP Discovery Safety

Newly discovered tools default to:

- `risk_level = critical`
- `action_type = privileged`
- `status = disabled`

Admins must explicitly classify and enable tools before agents can call them. Refresh updates description, input schema, and schema hash, but does not overwrite manual risk/action/status choices.

ToolServer `env` values are used only for server execution and are not returned by API responses.

## Failure Modes

The system fails closed for:

- Policy repository errors.
- Policy parse errors.
- Secret scanning errors.
- Argument hash/redaction failures.
- Argument schema validation failures.
- Tool registry misses.
- Disabled tools or servers.
- MCP discovery failures.
- MCP call failures.
- Unsupported MCP transports.

MCP tool call failures produce failed ToolCall and AuditEvent records. They are not reported as success.

## Known Limitations

- Streamable HTTP MCP transport is not implemented.
- OAuth / SSO is not implemented.
- UI dashboard is not implemented.
- Redis-backed rate limiting is not implemented.
- OpenTelemetry tracing is not implemented.
- Audit Query API is not implemented.
- Admin Policy API is not implemented.
