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

The Policy Engine is not yet connected to a Tool Call Gateway, approval execution, audit API, or MCP call path.
