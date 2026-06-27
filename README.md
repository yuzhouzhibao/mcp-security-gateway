# MCP Security Gateway

MCP Security Gateway is an open source Python service intended to become a security gateway for controlled access to MCP tools and servers.

## MVP Goal

The MVP target is a gateway that can enforce explicit security policy before tool calls reach MCP servers. That business functionality is not implemented yet.

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
- SQLAlchemy ORM models and repository implementations.
- Alembic initial migration.
- Test, lint, type-check, Docker Compose, and CI infrastructure.

Tool Call Gateway, approval APIs, audit APIs, tool execution, federated identity, and MCP adapters are not implemented. The Policy Engine is not yet wired to a tool-call API.

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
uv run alembic upgrade head
```

Run integration tests with an explicit PostgreSQL test database URL:

```powershell
$env:TEST_DATABASE_URL = "postgresql+psycopg://mcp_gateway:mcp_gateway_secret@localhost:5432/mcp_security_gateway_test"
uv run pytest -m integration
```

Integration tests create isolated PostgreSQL schemas per test session so separate test processes do not share tables.
