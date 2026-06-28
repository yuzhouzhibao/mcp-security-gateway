# MCP Security Gateway

[![CI](https://github.com/yuzhouzhibao/mcp-security-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/yuzhouzhibao/mcp-security-gateway/actions/workflows/ci.yml)

MCP Security Gateway is a policy, approval, and audit gateway between AI agents and MCP tools.

It is built for teams that want AI agents to use tools without giving those agents unchecked access to sensitive systems.

## Why This Exists

AI agents can call tools quickly, repeatedly, and under prompt pressure. That creates real operational risk:

- Agent tool calls can be hard to control once a key is issued.
- Prompt injection can steer agents toward dangerous or unintended tool calls.
- Tool arguments may contain secrets that should never enter audit logs or responses.
- High-risk actions need human approval before execution.
- After an incident, teams need durable records of what was requested, decided, approved, denied, and executed.

## Implemented Today

- Agent API key authentication.
- Admin API key authentication.
- Tool registry for MCP ToolServers and ToolDefinitions.
- Policy Engine with deny by default and fail closed behavior.
- Secret detection, recursive redaction, and canonical argument hashing.
- Tool Call Gateway at `POST /v1/tool-calls`.
- Approval flow for pending approvals, approve, deny, expiry, and approved execution.
- AuditEvent persistence for gateway and approval paths.
- Real MCP stdio adapter using the official MCP Python SDK.
- Example MCP calculator server.
- PostgreSQL persistence with SQLAlchemy 2.x.
- Alembic migrations.
- Pytest, Ruff, mypy, Docker Compose, Makefile, and GitHub Actions CI.

## Not Implemented Yet

- Streamable HTTP MCP adapter.
- OAuth / SSO.
- UI dashboard.
- Redis rate limiting.
- OpenTelemetry tracing.
- Admin Policy API.
- Audit Query API.

## Quickstart

```powershell
git clone https://github.com/yuzhouzhibao/mcp-security-gateway.git
cd mcp-security-gateway
uv sync
cp .env.example .env
```

Edit `.env` before running the service. Use local-only placeholder values for development and do not commit `.env`.

Start PostgreSQL with Docker:

```powershell
docker compose up -d postgres
```

If Docker is not available, run PostgreSQL yourself and set `DATABASE_URL` in `.env`.

Run migrations and start the API:

```powershell
uv run alembic upgrade head
uv run uvicorn mcp_security_gateway.main:app --reload
```

Health checks:

```powershell
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/version
```

## Demo Flow

There is no Tenant Admin API yet. Use the demo seed helper to create a tenant and an agent:

```powershell
uv run python examples/demo_seed.py
```

The helper prints `TENANT_ID`, `AGENT_ID`, and a one-time `AGENT_API_KEY`. It does not print `API_KEY_PEPPER` or `ADMIN_API_KEY_HASH`.

Then use the real API path:

1. Register the calculator MCP stdio server with `POST /v1/admin/tool-servers`.
2. Refresh discovered tools with `POST /v1/admin/tool-servers/{server_id}/refresh-tools`.
3. Confirm discovered tools default to `critical`, `privileged`, and `disabled`.
4. Classify `add` as `low`, `read`, and `active`.
5. Call `POST /v1/tool-calls` as the agent.
6. Classify another tool as high risk to see `pending_approval`.
7. Approve it through `POST /v1/admin/approvals/{approval_id}/approve`.
8. Inspect database AuditEvent rows if you want to verify recorded decisions. There is no Audit Query API yet.

Full commands are in [docs/demo.md](docs/demo.md). API examples are in [docs/api-examples.md](docs/api-examples.md).

## Security Posture

- Deny by default.
- Fail closed on policy, discovery, validation, and MCP adapter failures.
- Newly discovered tools are disabled, critical, and privileged until an admin classifies them.
- ToolServer `env` values are not returned in API responses.
- Raw tool arguments are not written to AuditEvent rows.
- Approval execution payloads are stored only while approval execution is pending, then cleared.
- Failed idempotent calls are not retried automatically in the MVP.
- The test-only MCP client lives under `tests/` and is not selected by production app startup.

Read more in [docs/security-model.md](docs/security-model.md) and [docs/threat-model.md](docs/threat-model.md).

## Developer Commands

```powershell
make install
make lint
make format-check
make typecheck
make test
make test-integration
make test-e2e
make compose-config
make migrate
make check
```

Without `make`, use:

```powershell
uv sync
uv run pytest
uv run pytest -m integration
uv run pytest -m e2e
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
docker compose config
uv run alembic upgrade head
```

Integration and e2e tests require an explicit PostgreSQL `TEST_DATABASE_URL`.

## Documentation

- [Architecture](docs/architecture.md)
- [Security Model](docs/security-model.md)
- [Threat Model](docs/threat-model.md)
- [API Examples](docs/api-examples.md)
- [Demo](docs/demo.md)
- [Development](docs/development.md)
- [Roadmap](docs/roadmap.md)
