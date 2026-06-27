# Architecture

MCP Security Gateway is intended to use a layered architecture:

- API layer: HTTP entry points and request/response contracts.
- Application layer: use cases and orchestration.
- Domain layer: policy, approval, and audit concepts.
- Infrastructure layer: database, MCP adapters, and external integrations.

Phase 4 adds Policy Engine domain objects and an application-level PolicyService. The domain layer does not import FastAPI, SQLAlchemy, Alembic, or request schemas.

The application layer contains repository ports, AgentService, and PolicyService. AgentService owns agent creation, disabling, and API key authentication decisions. PolicyService owns policy evaluation, non-overridable built-in safety rules, configured policy precedence, condition matching, secret detection, argument redaction, and canonical argument hashing. Neither service depends on FastAPI.

The infrastructure database layer contains SQLAlchemy models, session helpers, and repository implementations. Future phases should keep business decisions outside route handlers and keep infrastructure details outside the domain model.

Tool Call Gateway, approval APIs, audit APIs, tool execution, and MCP adapters remain outside the current phase. The Policy Engine exists for later use by the Tool Call Gateway, but no tool-call API has been added.
