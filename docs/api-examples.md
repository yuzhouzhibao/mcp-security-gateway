# API Examples

These examples assume the API is running at `http://127.0.0.1:8000`.

Use placeholders:

- `<ADMIN_API_KEY>`
- `<AGENT_API_KEY>`
- `<TENANT_ID>`
- `<AGENT_ID>`
- `<TOOL_DEFINITION_ID>`
- `<APPROVAL_ID>`

Create `<TENANT_ID>` and `<AGENT_API_KEY>` with:

```powershell
uv run python examples/demo_seed.py
```

## Health And Version

```powershell
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/version
```

## Create Agent

```powershell
curl -X POST http://127.0.0.1:8000/v1/admin/agents `
  -H "Authorization: Bearer <ADMIN_API_KEY>" `
  -H "Content-Type: application/json" `
  -d '{
    "tenant_id": "<TENANT_ID>",
    "name": "calculator-agent",
    "role": "agent"
  }'
```

The create response returns the plaintext agent API key once.

## Agent Self Check

```powershell
curl http://127.0.0.1:8000/v1/agents/me `
  -H "Authorization: Bearer <AGENT_API_KEY>"
```

## Create Tool Server

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

ToolServer `env` is not returned in responses.

## Refresh Tools

```powershell
curl -X POST http://127.0.0.1:8000/v1/admin/tool-servers/calculator-local/refresh-tools `
  -H "Authorization: Bearer <ADMIN_API_KEY>" `
  -H "Content-Type: application/json" `
  -d '{
    "tenant_id": "<TENANT_ID>"
  }'
```

Discovered tools default to disabled, critical, and privileged.

## List Tool Definitions

```powershell
curl "http://127.0.0.1:8000/v1/admin/tool-definitions?tenant_id=<TENANT_ID>&server_id=calculator-local" `
  -H "Authorization: Bearer <ADMIN_API_KEY>"
```

## Classify Tool

```powershell
curl -X PATCH http://127.0.0.1:8000/v1/admin/tool-definitions/<TOOL_DEFINITION_ID> `
  -H "Authorization: Bearer <ADMIN_API_KEY>" `
  -H "Content-Type: application/json" `
  -d '{
    "risk_level": "low",
    "action_type": "read",
    "status": "active"
  }'
```

## Call Allowed Tool

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

## Call High-Risk Tool

Classify a tool as high risk and active:

```powershell
curl -X PATCH http://127.0.0.1:8000/v1/admin/tool-definitions/<TOOL_DEFINITION_ID> `
  -H "Authorization: Bearer <ADMIN_API_KEY>" `
  -H "Content-Type: application/json" `
  -d '{
    "risk_level": "high",
    "action_type": "write",
    "status": "active"
  }'
```

Call it as the agent:

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

The response status is `pending_approval` and contains `approval_id`.

## List Approvals

```powershell
curl "http://127.0.0.1:8000/v1/admin/approvals?tenant_id=<TENANT_ID>&status=pending" `
  -H "Authorization: Bearer <ADMIN_API_KEY>"
```

## Approve Approval

```powershell
curl -X POST http://127.0.0.1:8000/v1/admin/approvals/<APPROVAL_ID>/approve `
  -H "Authorization: Bearer <ADMIN_API_KEY>" `
  -H "Content-Type: application/json" `
  -d '{
    "review_reason": "Reviewed for demo"
  }'
```

## Deny Approval

```powershell
curl -X POST http://127.0.0.1:8000/v1/admin/approvals/<APPROVAL_ID>/deny `
  -H "Authorization: Bearer <ADMIN_API_KEY>" `
  -H "Content-Type: application/json" `
  -d '{
    "review_reason": "Not approved"
  }'
```

## Common Error Response

```json
{
  "error": {
    "code": "unauthenticated",
    "message": "Authentication is required",
    "details": {},
    "trace_id": null
  }
}
```
