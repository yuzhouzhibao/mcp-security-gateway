# Demo

This demo shows the core path:

Agent -> Gateway -> Policy Engine -> real MCP stdio server -> ToolCall and AuditEvent persistence.

## 1. Prepare Environment

```powershell
uv sync
cp .env.example .env
```

Edit `.env`:

```text
DATABASE_URL=postgresql+psycopg://mcp_gateway:mcp_gateway_secret@localhost:5432/mcp_security_gateway
API_KEY_PEPPER=replace-with-local-development-pepper
ADMIN_API_KEY_HASH=replace-with-hmac-sha256-admin-key-hash
APPROVAL_REQUEST_TTL_SECONDS=900
MCP_CALL_TIMEOUT_SECONDS=10
```

Use an HMAC-SHA256 hash for your local admin key. Keep the plaintext admin key outside the repository.

Start PostgreSQL:

```powershell
docker compose up -d postgres
```

If Docker is not available, run PostgreSQL yourself and set `DATABASE_URL`.

The demo starts the API with `uvicorn`, not the compose app service. If you choose to run the app through compose, set `ENV_FILE=.env` so the app reads your edited local environment file instead of `.env.example`.

Run migrations:

```powershell
uv run alembic upgrade head
```

Start the API:

```powershell
uv run uvicorn mcp_security_gateway.main:app --reload
```

## 2. Seed Tenant And Agent

There is no Tenant Admin API yet, so the demo uses a small seed helper for bootstrap data only.

```powershell
uv run python examples/demo_seed.py
```

Save the printed values:

```text
TENANT_ID=<TENANT_ID>
AGENT_API_KEY=<AGENT_API_KEY>
```

The seed helper does not print `API_KEY_PEPPER` or `ADMIN_API_KEY_HASH`.

## 3. Register Calculator MCP Server

```powershell
curl -X POST http://127.0.0.1:8000/v1/admin/tool-servers `
  -H "Authorization: Bearer <ADMIN_API_KEY>" `
  -H "Content-Type: application/json" `
  -d '{
    "tenant_id": "<TENANT_ID>",
    "server_id": "calculator-local",
    "name": "Local Calculator MCP",
    "transport_type": "stdio",
    "command": "uv",
    "args": ["run", "python", "examples/mcp_servers/calculator_server.py"],
    "env": {}
  }'
```

This stores server metadata only. It does not call the MCP server until refresh or tool call time.

## 4. Refresh Tools

```powershell
curl -X POST http://127.0.0.1:8000/v1/admin/tool-servers/calculator-local/refresh-tools `
  -H "Authorization: Bearer <ADMIN_API_KEY>" `
  -H "Content-Type: application/json" `
  -d '{
    "tenant_id": "<TENANT_ID>"
  }'
```

You should see `add` and `echo`. Both are discovered as:

```text
risk_level=critical
action_type=privileged
status=disabled
```

This is intentional. Discovery does not make tools callable.

## 5. Classify `add`

Use the `id` from the discovered `add` ToolDefinition:

```powershell
curl -X PATCH http://127.0.0.1:8000/v1/admin/tool-definitions/<ADD_TOOL_DEFINITION_ID> `
  -H "Authorization: Bearer <ADMIN_API_KEY>" `
  -H "Content-Type: application/json" `
  -d '{
    "risk_level": "low",
    "action_type": "read",
    "status": "active"
  }'
```

## 6. Call `add`

```powershell
curl -X POST http://127.0.0.1:8000/v1/tool-calls `
  -H "Authorization: Bearer <AGENT_API_KEY>" `
  -H "Content-Type: application/json" `
  -d '{
    "target_server": "calculator-local",
    "target_tool": "add",
    "arguments": {
      "a": 2,
      "b": 3
    },
    "trace_id": "trace-demo-add",
    "idempotency_key": "demo-add-1"
  }'
```

The response should be succeeded and include a result containing `5`.

## 7. Approval Example

Classify `echo` as high risk:

```powershell
curl -X PATCH http://127.0.0.1:8000/v1/admin/tool-definitions/<ECHO_TOOL_DEFINITION_ID> `
  -H "Authorization: Bearer <ADMIN_API_KEY>" `
  -H "Content-Type: application/json" `
  -d '{
    "risk_level": "high",
    "action_type": "write",
    "status": "active"
  }'
```

Call it:

```powershell
curl -X POST http://127.0.0.1:8000/v1/tool-calls `
  -H "Authorization: Bearer <AGENT_API_KEY>" `
  -H "Content-Type: application/json" `
  -d '{
    "target_server": "calculator-local",
    "target_tool": "echo",
    "arguments": {
      "text": "approval demo"
    },
    "trace_id": "trace-demo-approval",
    "idempotency_key": "demo-approval-1"
  }'
```

The response should be `pending_approval`.

Approve it:

```powershell
curl -X POST http://127.0.0.1:8000/v1/admin/approvals/<APPROVAL_ID>/approve `
  -H "Authorization: Bearer <ADMIN_API_KEY>" `
  -H "Content-Type: application/json" `
  -d '{
    "review_reason": "Reviewed for demo"
  }'
```

The approved call executes through the same real MCP stdio adapter.

## 8. Audit Behavior

The gateway writes AuditEvent rows for:

- allow success
- policy deny
- approval required
- approval approved
- approval executed
- MCP failure
- validation failure

There is no Audit Query API yet. Inspect PostgreSQL directly during the demo if needed.

## Troubleshooting

### `docker` command not found

Install Docker Desktop or run PostgreSQL yourself and set `DATABASE_URL`.

### `tool_disabled`

Discovered tools are disabled by default. Classify and activate the ToolDefinition before calling it.

### `transport_not_supported_yet`

Only stdio MCP servers are supported in this phase. Streamable HTTP is planned for a later phase.

### `argument_schema_invalid`

The request arguments must match the MCP tool input schema discovered from the server.
