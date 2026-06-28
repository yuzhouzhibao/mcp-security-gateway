# Development

Install dependencies with uv:

```powershell
uv sync
```

Run tests:

```powershell
uv run pytest
uv run pytest -m integration
```

Run lint:

```powershell
uv run ruff check .
```

Check formatting:

```powershell
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

Start the app and PostgreSQL:

```powershell
docker compose up --build
```

Start only PostgreSQL for migration and integration testing:

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

Run PostgreSQL integration tests:

```powershell
$env:TEST_DATABASE_URL = "postgresql+psycopg://mcp_gateway:mcp_gateway_secret@localhost:5432/mcp_security_gateway_test"
uv run pytest -m integration
```

`TEST_DATABASE_URL` must be explicit. Integration tests create isolated PostgreSQL schemas per test session and do not use a local file database substitute.

Approval flow tests use the MCP client port with a test-only client under `tests/fakes`. The production app does not select that client by default.
