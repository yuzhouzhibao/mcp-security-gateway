# Development

## Requirements

- Python 3.12+
- uv
- PostgreSQL for integration and e2e tests
- Docker CLI for `docker compose config` and local PostgreSQL convenience

## Install

```powershell
uv sync
```

Or:

```powershell
make install
```

## Run The API

```powershell
cp .env.example .env
uv run alembic upgrade head
uv run uvicorn mcp_security_gateway.main:app --reload
```

If Docker is available:

```powershell
docker compose up -d postgres
```

If Docker is not available, run PostgreSQL yourself and set `DATABASE_URL`.

## Tests

Unit and API tests:

```powershell
uv run pytest tests/unit
uv run pytest tests/api
```

Full suite:

```powershell
uv run pytest
```

PostgreSQL integration tests require explicit `TEST_DATABASE_URL`:

```powershell
$env:TEST_DATABASE_URL = "postgresql+psycopg://mcp_gateway:mcp_gateway_secret@localhost:5432/mcp_security_gateway"
uv run pytest -m integration
```

E2E tests also require PostgreSQL:

```powershell
$env:TEST_DATABASE_URL = "postgresql+psycopg://mcp_gateway:mcp_gateway_secret@localhost:5432/mcp_security_gateway"
uv run pytest -m e2e
```

Integration and e2e tests create isolated PostgreSQL schemas per test session.

## Code Quality

```powershell
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
```

Or:

```powershell
make lint
make format-check
make typecheck
```

## Docker Compose

```powershell
docker compose config
```

This validates the compose file and does not require the Docker daemon to be running. It does require the Docker CLI.

## CI

GitHub Actions runs:

- `uv sync`
- `uv run pytest`
- `uv run ruff check .`
- `uv run ruff format --check .`
- `uv run mypy src tests`
- `docker compose config`

Integration and e2e tests require an explicit PostgreSQL `TEST_DATABASE_URL`. The current CI workflow does not configure a PostgreSQL service, so those database-backed tests are intended for local or review runs until CI database services are added.

## Alembic

Run migrations:

```powershell
uv run alembic upgrade head
```

Create migrations only when the database schema changes:

```powershell
uv run alembic revision --autogenerate -m "describe change"
```

Review generated migrations before committing them.

## Makefile

```powershell
make install
make test
make test-integration
make test-e2e
make lint
make format-check
make typecheck
make compose-config
make migrate
make check
```

## Git Workflow

- Keep each phase in a separate commit.
- Run the required checks before committing.
- Push only after review approval.
- Do not hide failures by deleting tests, lowering type checks, or returning fake success.
