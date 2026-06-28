# Security Model

The security model for future phases is based on these principles:

- Deny by default.
- Fail closed when policy, identity, approval, or audit checks cannot be completed.
- Do not write plaintext secrets to logs.
- Admin APIs must be authenticated in a later phase before any privileged operation exists.

Phase 3 adds API key authentication and admin-protected agent management. It does not implement policy evaluation, approval APIs, audit APIs, MCP calls, or tool execution.

Repository code stores only redacted arguments and hashes for tool-call and audit-related records. API key material is represented only as `api_key_hash`; plaintext API keys are not modeled.

- Agent keys are generated from high-entropy random material and returned only in the create response.
- Agent keys are stored only as HMAC-SHA256 hashes derived with `API_KEY_PEPPER`.
- Admin API access uses `ADMIN_API_KEY_HASH` with the same pepper and is a deployment-level bootstrap credential.
- Disabled agents are rejected before any agent endpoint response is returned.
- Error responses must not include API keys, hashes, or peppers.

Phase 4 adds Policy Engine evaluation:

- Deny by default when no explicit built-in or configured allow applies.
- Fail closed for repository, parse, scanning, redaction, and hashing failures.
- Non-overridable built-in rules for suspected secrets, critical tools, destructive non-admin calls, and high-risk approval run before configured policies.
- Configured deny and require-approval policies are evaluated before configured allow policies.
- Low-risk read-only tools are allowed only after configured deny and require-approval policies have had a chance to match.
- Secret findings include only path, detector kind, and reason; they do not contain raw sensitive values.
- Redacted arguments are recursive and use a fixed redaction marker.
- Argument hashes are SHA-256 over canonical JSON from the original arguments.

Phase 5 connects Policy Engine to `POST /v1/tool-calls`:

- The route requires Agent API key authentication.
- The service uses stored ToolDefinition risk level and action type, never request-supplied risk metadata.
- Tool arguments are validated against the stored JSON Schema before policy evaluation can call upstream.
- Deny and require-approval decisions do not call upstream.
- Require-approval creates only a pending ApprovalRequest; review and execution APIs are not implemented.
- Allowed calls use the MCP client port. A real MCP adapter is not implemented.
- ToolCall and AuditEvent rows store redacted arguments and canonical hashes, not raw arguments.
- Tool lookup failure, schema validation failure, deny, require-approval, success, and upstream failure append audit events.
- Idempotency keys reuse existing failed results rather than automatically retrying them in the MVP.

Phase 6 adds approval execution:

- Approval APIs require admin authentication.
- ApprovalService uses conditional status updates so only a pending approval can become approved or denied.
- Approve performs pending to approved, then ToolCallService executes the stored server-side execution payload and records executed or failed.
- Deny performs pending to denied and never calls upstream.
- Expired approvals become expired and do not call upstream; their ToolCall is marked denied with `approval_expired`.
- Executed, denied, expired, and failed approvals are terminal. Failed approvals are not automatically retried.
- Approved execution uses `tool_calls.arguments_payload`, never redacted arguments.
- `arguments_payload` exists only while an approval is pending execution. It is cleared after executed, failed, denied, or expired approval outcomes.
- `arguments_payload` is not returned by APIs and is not written to audit events or logs. The MVP stores this server-side payload as JSONB; production hardening should encrypt it with a managed key service.
