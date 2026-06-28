import os
from uuid import UUID

import pytest
from fastapi import FastAPI

os.environ["APP_NAME"] = "MCP Security Gateway"
os.environ["APP_ENV"] = "test"
os.environ["LOG_LEVEL"] = "DEBUG"
os.environ["DATABASE_URL"] = (
    "postgresql+psycopg://test_user:test_secret@localhost:5432/test_gateway"
)
os.environ["API_KEY_PEPPER"] = "test-api-key-pepper"
os.environ["ADMIN_API_KEY_HASH"] = (
    "56126e97dc552ee7817798aeb5ea4926cc4d09cffdfcf8797f144255a638381c"
)
os.environ["APPROVAL_REQUEST_TTL_SECONDS"] = "900"
os.environ["MCP_CALL_TIMEOUT_SECONDS"] = "5"

from mcp_security_gateway.main import create_app
from mcp_security_gateway.settings import Settings


@pytest.fixture
def test_settings() -> Settings:
    return Settings.model_validate(
        {
            "APP_NAME": "MCP Security Gateway",
            "APP_ENV": "test",
            "LOG_LEVEL": "DEBUG",
            "DATABASE_URL": "postgresql+psycopg://test_user:test_secret@localhost:5432/test_gateway",
            "API_KEY_PEPPER": "test-api-key-pepper",
            "ADMIN_API_KEY_HASH": (
                "56126e97dc552ee7817798aeb5ea4926cc4d09cffdfcf8797f144255a638381c"
            ),
            "APPROVAL_REQUEST_TTL_SECONDS": 900,
            "MCP_CALL_TIMEOUT_SECONDS": 5,
        }
    )


@pytest.fixture
def app(test_settings: Settings) -> FastAPI:
    return create_app(test_settings)


@pytest.fixture
def sample_uuid() -> UUID:
    return UUID("00000000-0000-4000-8000-000000000001")
