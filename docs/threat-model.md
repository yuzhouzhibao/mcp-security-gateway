# Threat Model

This document describes the current MVP threat model. It focuses on risks around AI agents calling MCP tools.

## Assets

- Agent API keys.
- Admin API key hash and API key pepper.
- Tool arguments.
- Temporary approval execution payload.
- MCP server environment variables.
- AuditEvent records.
- Policy configuration.
- Tool registry metadata.
- Approval state.

## Adversaries

- Prompt injection attacker: influences an agent prompt to cause unsafe tool calls.
- Compromised agent: has a valid Agent API key.
- Malicious MCP server: returns misleading metadata, errors, or tool output.
- Careless admin: enables a dangerous tool with low-risk classification.
- Database reader: can inspect persisted records but should not find raw API keys or audit secrets.

## Threats And Mitigations

### Unauthorized Tool Call

Threat: an unauthenticated caller or disabled agent tries to call tools.

Mitigations:

- Bearer token authentication for agent endpoints.
- Disabled agents are rejected.
- Tool calls require registered active ToolServer and ToolDefinition rows.

### Secret Exfiltration

Threat: tool arguments contain tokens, passwords, private keys, or authorization headers.

Mitigations:

- Secret detection runs before configured policy allow.
- Secret findings do not include raw values.
- Redacted arguments are stored for audit.
- Canonical hashes preserve correlation without revealing raw input.

### Destructive Tool Execution

Threat: a prompt injection attack triggers high-risk or destructive tools.

Mitigations:

- Critical tools are denied by built-in rule.
- High-risk tools require approval.
- Destructive tools require admin role.
- Discovered tools default to disabled, critical, and privileged.

### Audit Tampering

Threat: a caller modifies or deletes audit events.

Mitigations:

- Audit repository exposes append/list/get only.
- No update/delete audit API exists.
- AuditEvent rows include trace, tenant, agent, target, status, error, and approval references.

### Approval Replay Or Double Execution

Threat: the same approval is approved twice and executes upstream twice.

Mitigations:

- Approval state transitions use conditional updates.
- Only `pending -> approved` winner can execute.
- Terminal approvals cannot execute again.
- Failed approvals are not automatically retried.

### Discovery Enabling Dangerous Tools

Threat: a malicious MCP server exposes dangerous tools that become callable.

Mitigations:

- Discovery never defaults tools to active.
- New tools default to critical, privileged, and disabled.
- Refresh does not overwrite manual classification.
- Admin must explicitly classify and enable each tool.

### Malicious MCP Server Output

Threat: an MCP server returns unexpected result objects or error results.

Mitigations:

- SDK result objects are converted to JSON-safe responses.
- `isError=True` is treated as MCP tool call failure.
- Unknown content types are summarized safely.

## Limitations And Future Mitigations

- Encrypt approval execution payloads with KMS.
- Add OAuth / SSO and per-admin identities.
- Add Audit Query API with admin authorization.
- Add Admin Policy API with validation and review controls.
- Add Streamable HTTP MCP adapter with the same fail-closed behavior.
- Add OpenTelemetry tracing without recording secrets.
- Add Redis-backed rate limiting and distributed idempotency.
