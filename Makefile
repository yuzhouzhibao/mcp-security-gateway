.PHONY: install sync test test-integration test-e2e lint format-check typecheck type-check compose-config migrate check

install:
	uv sync

sync:
	uv sync

test:
	uv run pytest

test-integration:
	uv run pytest -m integration

test-e2e:
	uv run pytest -m e2e

lint:
	uv run ruff check .

format-check:
	uv run ruff format --check .

typecheck:
	uv run mypy src tests

type-check:
	uv run mypy src tests

compose-config:
	docker compose config

migrate:
	uv run alembic upgrade head

check: install lint format-check typecheck test test-integration test-e2e compose-config migrate
