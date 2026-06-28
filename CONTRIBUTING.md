# Contributing

Thanks for your interest in MCP Security Gateway.

## Requirements

- Python 3.12+
- uv
- PostgreSQL for integration and e2e tests
- Docker CLI for compose validation

## Setup

```powershell
uv sync
cp .env.example .env
uv run alembic upgrade head
```

## Checks

Run before opening a pull request:

```powershell
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

## Code Quality Rules

- Keep API routes thin.
- Keep domain code independent from FastAPI, SQLAlchemy, Alembic, and the MCP SDK.
- Keep MCP SDK usage inside infrastructure adapters.
- Prefer explicit application errors over leaking database or SDK internals.
- Add focused tests for security-sensitive behavior.

## Security Principles

- No fake success.
- No broad exception swallowing.
- Fail closed.
- No raw secrets in logs, responses, or audit events.
- No production path that selects a test fake.
- Newly discovered tools must not become active by default.
- Approval execution must not use redacted arguments.

## Pull Request Checklist

- Tests pass locally or skipped tests are explained.
- Ruff and mypy pass.
- Docker Compose config is valid.
- No real secrets are committed.
- Documentation reflects only implemented behavior.
- New security-sensitive paths have tests.
- Database schema changes include Alembic migrations.
