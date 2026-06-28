import pytest
from pydantic import ValidationError

from mcp_security_gateway.settings import Settings


def test_settings_load_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_NAME", "Gateway From Env")
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("LOG_LEVEL", "WARNING")
    monkeypatch.setenv("API_KEY_PEPPER", "test-api-key-pepper")
    monkeypatch.setenv(
        "ADMIN_API_KEY_HASH",
        "56126e97dc552ee7817798aeb5ea4926cc4d09cffdfcf8797f144255a638381c",
    )
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://env_user:env_secret@localhost:5432/env_gateway",
    )
    monkeypatch.setenv("APPROVAL_REQUEST_TTL_SECONDS", "900")
    monkeypatch.setenv("MCP_CALL_TIMEOUT_SECONDS", "5")

    settings = Settings()

    assert settings.app_name == "Gateway From Env"
    assert settings.app_env == "test"
    assert settings.log_level == "WARNING"
    assert (
        settings.database_url
        == "postgresql+psycopg://env_user:env_secret@localhost:5432/env_gateway"
    )
    assert settings.api_key_pepper == "test-api-key-pepper"
    assert settings.approval_request_ttl_seconds == 900
    assert settings.mcp_call_timeout_seconds == 5


def test_test_settings_do_not_depend_on_real_secret(test_settings: Settings) -> None:
    assert test_settings.app_env == "test"
    assert "test_secret" in test_settings.database_url
    assert "mcp_gateway_secret" not in test_settings.database_url


def test_settings_missing_api_key_pepper_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_NAME", "Gateway From Env")
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("LOG_LEVEL", "WARNING")
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg://env_user:env_secret@localhost:5432/env"
    )
    monkeypatch.setenv(
        "ADMIN_API_KEY_HASH",
        "56126e97dc552ee7817798aeb5ea4926cc4d09cffdfcf8797f144255a638381c",
    )
    monkeypatch.setenv("APPROVAL_REQUEST_TTL_SECONDS", "900")
    monkeypatch.setenv("MCP_CALL_TIMEOUT_SECONDS", "5")
    monkeypatch.delenv("API_KEY_PEPPER", raising=False)

    with pytest.raises(ValidationError):
        Settings()


def test_settings_missing_admin_api_key_hash_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_NAME", "Gateway From Env")
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("LOG_LEVEL", "WARNING")
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg://env_user:env_secret@localhost:5432/env"
    )
    monkeypatch.setenv("API_KEY_PEPPER", "test-api-key-pepper")
    monkeypatch.setenv("APPROVAL_REQUEST_TTL_SECONDS", "900")
    monkeypatch.setenv("MCP_CALL_TIMEOUT_SECONDS", "5")
    monkeypatch.delenv("ADMIN_API_KEY_HASH", raising=False)

    with pytest.raises(ValidationError):
        Settings()
