from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = Field(alias="APP_NAME")
    app_env: str = Field(alias="APP_ENV")
    log_level: str = Field(alias="LOG_LEVEL")
    database_url: str = Field(alias="DATABASE_URL")
    api_key_pepper: str = Field(alias="API_KEY_PEPPER")
    admin_api_key_hash: str = Field(alias="ADMIN_API_KEY_HASH")
    test_database_url: str | None = Field(default=None, alias="TEST_DATABASE_URL")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="forbid",
        populate_by_name=True,
    )
