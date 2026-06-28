# MCP Security Gateway

MCP Security Gateway is an open source Python service intended to become a security gateway for controlled access to MCP tools and servers.

## MVP Goal

The MVP target is a gateway that applies explicit security policy before tool calls reach MCP servers.

## Current Phase

The project currently provides:

- FastAPI application startup.
- `GET /health`.
- `GET /version`.
- Pydantic settings.
- Domain enums and data structures.
- Agent API key authentication and deployment-level admin API key authentication.
- Admin Agent management endpoints for creating, listing, fetching, and disabling agents.
- Agent self-check endpoint at `GET /v1/agents/me`.
- Policy Engine application service with deny by default and fail closed behavior.
- Configured policy precedence where deny and require-approval can override built-in low-risk read allow.
- Secret detection, recursive argument redaction, and canonical argument hashing.
- Tool Call Gateway endpoint at `POST /v1/tool-calls`.
- Tool call orchestration that authenticates agents, validates tool registry metadata and JSON Schema arguments, evaluates policy, records ToolCall rows, creates pending ApprovalRequest rows when required, and appends AuditEvent rows.
- MCP calls through an application port only.
- Idempotency reuses prior completed results, including failed results; the MVP does not automatically retry failed idempotent calls.
- Admin approval endpoints for listing approvals, approving pending approvals, and denying pending approvals.
- Approved requests execute the original server-side execution payload through the MCP client port.
- Approval state transitions are guarded by conditional updates so repeated approval attempts do not execute upstream twice.
- SQLAlchemy ORM models and repository implementations.
- Alembic initial migration.
- Test, lint, type-check, Docker Compose, and CI infrastructure.

Audit query APIs, federated identity, real MCP adapters, and MCP discovery are not implemented. Test-only MCP clients are used only in tests and are not production adapters.

## Local Development

Install dependencies:

```powershell
uv sync
```

Run the API locally:

```powershell
$env:APP_NAME = "MCP Security Gateway"
$env:APP_ENV = "local"
$env:LOG_LEVEL = "INFO"
$env:DATABASE_URL = "postgresql+psycopg://mcp_gateway:mcp_gateway_secret@localhost:5432/mcp_security_gateway"
$env:TEST_DATABASE_URL = "postgresql+psycopg://mcp_gateway:mcp_gateway_secret@localhost:5432/mcp_security_gateway_test"
$env:API_KEY_PEPPER = "replace-with-local-development-pepper"
$env:ADMIN_API_KEY_HASH = "replace-with-hmac-sha256-admin-key-hash"
$env:APPROVAL_REQUEST_TTL_SECONDS = "900"
$env:MCP_CALL_TIMEOUT_SECONDS = "10"
uv run uvicorn mcp_security_gateway.main:app --reload
```

Run tests:

```powershell
uv run pytest
uv run pytest -m integration
```

Run lint and formatting checks:

```powershell
uv run ruff check .
uv run ruff format --check .
```

Run type checks:

```powershell
uv run mypy src tests
```

Validate Docker Compose:

```powershell
docker compose config
```

Start local services:

```powershell
docker compose up --build
```

Start PostgreSQL for database work:

```powershell
docker compose up -d postgres
```

Run migrations:

```powershell
$env:DATABASE_URL = "postgresql+psycopg://mcp_gateway:mcp_gateway_secret@localhost:5432/mcp_security_gateway"
$env:API_KEY_PEPPER = "replace-with-local-development-pepper"
$env:ADMIN_API_KEY_HASH = "replace-with-hmac-sha256-admin-key-hash"
$env:APPROVAL_REQUEST_TTL_SECONDS = "900"
$env:MCP_CALL_TIMEOUT_SECONDS = "10"
uv run alembic upgrade head
```

Approval execution payload:

The MVP stores original tool arguments in `tool_calls.arguments_payload` only while an approval is pending execution. The payload is cleared after executed, failed, denied, or expired approval outcomes. It is not returned by APIs and is not written to audit events. Production hardening should encrypt this payload with a managed key service.

Run integration tests with an explicit PostgreSQL test database URL:

```powershell
$env:TEST_DATABASE_URL = "postgresql+psycopg://mcp_gateway:mcp_gateway_secret@localhost:5432/mcp_security_gateway_test"
uv run pytest -m integration
```

Integration tests create isolated PostgreSQL schemas per test session so separate test processes do not share tables.
