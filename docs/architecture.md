# Architecture

MCP Security Gateway is intended to use a layered architecture:

- API layer: HTTP entry points and request/response contracts.
- Application layer: use cases and orchestration.
- Domain layer: policy, approval, and audit concepts.
- Infrastructure layer: database, MCP adapters, and external integrations.

Phase 7A adds the first real MCP integration through stdio and an admin Tool Registry API. The domain layer does not import FastAPI, SQLAlchemy, Alembic, request schemas, or the MCP SDK.

The application layer contains repository ports, AgentService, PolicyService, ToolCallService, AuditService, ApprovalService, ToolRegistryService, and the MCP client port. AgentService owns agent creation, disabling, and API key authentication decisions. PolicyService owns policy evaluation, non-overridable built-in safety rules, configured policy precedence, condition matching, secret detection, argument redaction, and canonical argument hashing. ToolCallService coordinates tool lookup, JSON Schema validation, policy evaluation, idempotency, approval creation, approved execution, audit appends, and calls through the MCP client port. ApprovalService owns approval listing and the pending to approved, denied, expired, executed, or failed state machine. ToolRegistryService owns ToolServer creation, MCP discovery, ToolDefinition upsert, and classification updates. These services do not depend on FastAPI.

The infrastructure database layer contains SQLAlchemy models, session helpers, and repository implementations. The real stdio MCP adapter lives in `infrastructure/mcp` and is the production app default. Test-only MCP clients live under tests and are injected by tests; production app startup does not select a test client.

Approval admin routes parse requests and call ApprovalService. They do not evaluate policy, look up tools, run MCP calls, or write audit events directly.

Tool Registry admin routes parse requests and call ToolRegistryService. They do not perform discovery, upsert definitions, or classify tools directly.

Audit query APIs, admin policy APIs, real Streamable HTTP MCP transport, and MCP discovery beyond stdio remain outside the current phase.
