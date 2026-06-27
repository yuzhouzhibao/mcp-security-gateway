.PHONY: sync test test-integration lint format-check type-check compose-config migrate check

sync:
	uv sync

test:
	uv run pytest

test-integration:
	uv run pytest -m integration

lint:
	uv run ruff check .

format-check:
	uv run ruff format --check .

type-check:
	uv run mypy src tests

compose-config:
	docker compose config

migrate:
	uv run alembic upgrade head

check: test test-integration lint format-check type-check compose-config migrate
