# Architecture

MCP Security Gateway uses a layered architecture. The main rule is that HTTP routes parse requests and call application services; business decisions live below the API layer.

```text
HTTP clients
  |
  v
API layer
  - FastAPI routes
  - request and response schemas
  - authentication dependencies
  |
  v
Application layer
  - AgentService
  - PolicyService
  - ToolRegistryService
  - ToolCallService
  - ApprovalService
  - AuditService
  - repository and MCP client ports
  |
  v
Domain layer
  - enums
  - policy context/result
  - domain exceptions and value objects
  |
  v
Infrastructure layer
  - SQLAlchemy repositories
  - Alembic migrations
  - real MCP stdio adapter
  - PostgreSQL
```

## Layer Boundaries

The domain layer does not import FastAPI, SQLAlchemy, Alembic, request schemas, or the MCP SDK.

The application layer coordinates use cases and depends on ports. It does not depend on FastAPI. `ToolCallService` calls MCP only through the `McpClient` protocol.

The infrastructure layer implements repository ports and the real MCP stdio adapter. Only `infrastructure/mcp` imports the official MCP Python SDK.

Test-only MCP clients live under `tests/fakes`. They are injected by tests and are not selected by production app startup.

## Tool Call Flow

1. Agent authenticates with `Authorization: Bearer <agent_api_key>`.
2. API route validates the request schema and calls `ToolCallService`.
3. Service looks up active ToolServer and ToolDefinition from the registry.
4. Service validates arguments against ToolDefinition `input_schema`.
5. PolicyService evaluates built-in rules and active configured policies.
6. Deny writes ToolCall and AuditEvent, then returns denied.
7. Require approval writes ToolCall, ApprovalRequest, and AuditEvent.
8. Allow calls the MCP client port.
9. Success or failure updates ToolCall and writes AuditEvent.
10. Idempotency keys reuse existing terminal results and do not re-execute upstream.

## Approval Flow

1. A high-risk tool call creates a pending ApprovalRequest.
2. Admin lists pending approvals.
3. Admin approves or denies.
4. Approve performs conditional `pending -> approved`.
5. Only the request that wins that transition can execute upstream.
6. Execution uses the temporary server-side `arguments_payload`, never redacted arguments.
7. Execution completion transitions `approved -> executed` or `approved -> failed`.
8. Terminal outcomes clear `arguments_payload`.

## MCP Adapter Boundary

The `McpClient` port supports:

- `list_tools`
- `call_tool`

The real adapter supports stdio only. Streamable HTTP is represented in the domain and database but returns `transport_not_supported_yet` in this phase. A later phase can add a dedicated adapter without changing ToolCallService.

## Repository / DB Boundary

SQLAlchemy models and repositories are in `infrastructure/db`. Application services receive repositories through constructor arguments. Repository implementations do database access only; they do not evaluate policies, generate API keys, redact secrets, or call MCP servers.

## Current Non-Goals

- Streamable HTTP adapter.
- Admin Policy API.
- Audit Query API.
- UI dashboard.
- OAuth / SSO.
- Redis rate limiting.
