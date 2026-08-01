from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "LoonInspect"
    debug: bool = False

    database_url: str = "sqlite+aiosqlite:///./looninspect.db"

    cors_origins: list[str] = ["http://localhost:5173"]

    jamf_base_url: str | None = None
    jamf_client_id: str | None = None
    jamf_client_secret: str | None = None
    jamf_webhook_secret: str | None = None

    simplemdm_api_key: str | None = None

    siem_webhook_url: str | None = None
    loonvd_gateway_url: str | None = None

    scheduler_enabled: bool = True
    sync_hour: int = 1
    sync_minute: int = 0
    sync_timezone: str = "America/Chicago"


settings = Settings()
