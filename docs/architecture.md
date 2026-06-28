# Architecture

MCP Security Gateway is intended to use a layered architecture:

- API layer: HTTP entry points and request/response contracts.
- Application layer: use cases and orchestration.
- Domain layer: policy, approval, and audit concepts.
- Infrastructure layer: database, MCP adapters, and external integrations.

Phase 5 adds the Tool Call Gateway API and application orchestration for the core call path. The domain layer does not import FastAPI, SQLAlchemy, Alembic, or request schemas.

The application layer contains repository ports, AgentService, PolicyService, ToolCallService, AuditService, ApprovalService, and the MCP client port. AgentService owns agent creation, disabling, and API key authentication decisions. PolicyService owns policy evaluation, non-overridable built-in safety rules, configured policy precedence, condition matching, secret detection, argument redaction, and canonical argument hashing. ToolCallService coordinates tool lookup, JSON Schema validation, policy evaluation, idempotency, minimal approval creation, audit appends, and calls through the MCP client port. These services do not depend on FastAPI.

The infrastructure database layer contains SQLAlchemy models, session helpers, and repository implementations. Test-only MCP clients live under tests and are injected by tests; production app startup does not select a test client.

Approval review APIs, audit query APIs, admin policy APIs, tool registry APIs, real tool execution adapters, and MCP discovery remain outside the current phase.
